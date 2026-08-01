//! Cross-platform file watcher with per-browser debouncing.
//!
//! The daemon watches each detected browser's install path so it can
//! re-patch as soon as the browser updates itself. We use the
//! [`notify`](https://crates.io/crates/notify) crate, which abstracts
//! `inotify` on Linux and `FSEvents` on macOS into a unified `Watcher`
//! trait.
//!
//! ## Debouncing
//!
//! A single browser update touches dozens of files within milliseconds.
//! We debounce per-browser on the **trailing edge**: every event resets
//! a timer to `now + DEFAULT_DEBOUNCE_MS`, and the user callback only
//! fires once that timer elapses with no new events. This keeps the
//! patch flow from (a) running 30 times during a single update, and
//! (b) running on top of an in-flight update — the leading-edge
//! variant we used to have fired on the very first event of the storm,
//! before the browser bundle finished writing.
//!
//! ## Browser-running deferral
//!
//! Per spec, before invoking the user callback we check
//! [`crate::browsers::discovery::is_running`]. If the browser is running,
//! we don't fire the callback yet — we register a one-shot follow-up
//! poll on the bundle, waiting until the modification time has been
//! stable for [`POST_QUIT_STABLE_S`] seconds (the heuristic the spec
//! uses to detect "browser has quit"), then fire.
//!
//! ## Public API
//!
//! ```ignore
//! pub struct Watcher;
//! impl Watcher {
//!     pub fn new(callback: WatcherCallback) -> Result<Self>;
//!     pub fn watch(&self, browser: Browser) -> Result<()>;
//!     pub fn unwatch(&self, browser: &Browser) -> Result<()>;
//!     pub fn close(self);
//! }
//! pub type WatcherCallback = Arc<dyn Fn(&Browser) + Send + Sync>;
//! ```
//!
//! `watch(browser)` registers the browser's install path with the
//! underlying `notify::Watcher`. `close()` joins the dispatch thread and
//! tears down the watcher cleanly. `Drop` calls `close` if the user
//! didn't.
//!
//! ## Test mode
//!
//! Tests use synthesized browser paths and drive the debounce state machine
//! directly, avoiding timing assumptions from platform watcher backends. They
//! pass explicit running predicates so no real processes are inspected.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use notify::{EventKind, RecursiveMode};
use parking_lot::Mutex;

use crate::browsers::{discovery::ProcessSnapshot, Browser};
use crate::error::{Error, Result};

/// Default debounce window in milliseconds. Matches the existing Swift
/// app's behavior (verified during V1 design).
pub const DEFAULT_DEBOUNCE_MS: u64 = 2_000;

/// How long the bundle's mtime must stay constant before we consider the
/// browser "quit" (after a deferred-because-running event).
pub const POST_QUIT_STABLE_S: u64 = 30;

/// User callback signature. The watcher passes the affected [`Browser`].
///
/// Wrapped in an `Arc` so the dispatch thread can hold a reference; the
/// callback is `Send + Sync` so it can run on any thread the watcher
/// chooses.
pub type WatcherCallback = Arc<dyn Fn(&Browser) + Send + Sync + 'static>;

/// Predicate that returns `true` when the given browser is currently
/// running. Defaults to [`crate::browsers::discovery::is_running`]; tests
/// inject a stub.
pub type RunningPredicate = Arc<dyn Fn(&Browser) -> bool + Send + Sync + 'static>;

#[derive(Clone)]
enum RunningSource {
    Host,
    Custom(RunningPredicate),
}

enum RunningSnapshot<'a> {
    Host(ProcessSnapshot),
    Custom(&'a RunningPredicate),
}

impl RunningSource {
    fn snapshot(&self) -> RunningSnapshot<'_> {
        match self {
            Self::Host => RunningSnapshot::Host(ProcessSnapshot::capture()),
            Self::Custom(predicate) => RunningSnapshot::Custom(predicate),
        }
    }
}

impl RunningSnapshot<'_> {
    fn is_running(&self, browser: &Browser) -> bool {
        match self {
            Self::Host(snapshot) => snapshot.is_running(browser),
            Self::Custom(predicate) => predicate(browser),
        }
    }
}

/// Public watcher handle. Drops gracefully (joins thread + tears down
/// the inner `notify::Watcher`).
#[allow(clippy::struct_field_names)]
pub struct Watcher {
    inner: Arc<Mutex<WatcherState>>,
    debounce: Duration,
    callback: WatcherCallback,
    is_running: RunningPredicate,
    fs_watcher: Option<notify::RecommendedWatcher>,
    event_tx: Sender<WatcherEvent>,
    dispatch_thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

/// Inner mutable state, behind a mutex so the dispatch thread can read
/// it (timestamp lookups, debounce decisions) and the public API can
/// mutate it (register/unregister).
#[derive(Default)]
struct WatcherState {
    /// Watched browsers and all per-browser scheduling state, keyed by the
    /// configured install path. Keeping one entry prevents parallel maps from
    /// drifting apart during watch/unwatch and debounce transitions.
    entries: HashMap<PathBuf, WatchedEntry>,
}

struct WatchedEntry {
    browser: Browser,
    canonical_root: Option<PathBuf>,
    dispatch_at: Option<Instant>,
    deferred: Option<DeferredState>,
}

impl WatchedEntry {
    fn new(browser: Browser) -> Self {
        let canonical_root = std::fs::canonicalize(browser.install_path()).ok();
        Self {
            browser,
            canonical_root,
            dispatch_at: None,
            deferred: None,
        }
    }

    fn owns_event(&self, event_path: &Path) -> bool {
        event_path.starts_with(self.browser.install_path())
            || self
                .canonical_root
                .as_deref()
                .is_some_and(|root| event_path.starts_with(root))
    }
}

/// State for a deferred (because-running) callback dispatch.
struct DeferredState {
    /// Last observed mtime of the install dir.
    last_mtime: Option<SystemTime>,
    /// When `last_mtime` was last updated.
    last_check: Instant,
    /// First time we noticed this deferred path.
    first_seen: Instant,
}

/// Internal events passed to the dispatch thread.
enum WatcherEvent {
    /// A filesystem event arrived for a path below a watched browser.
    FsEvent(PathBuf),
    /// Wake the receiver during shutdown so it can observe `stop`.
    Wake,
}

impl Watcher {
    /// Build a new watcher with the default running-predicate
    /// (`browsers::discovery::is_running`) and the default debounce.
    ///
    /// # Errors
    ///
    /// * [`crate::ErrorCategory::Other`] if the underlying `notify::Watcher`
    ///   fails to initialize (rare — typically a kernel resource limit).
    pub fn new(callback: WatcherCallback) -> Result<Self> {
        Self::with_running_source(
            callback,
            RunningSource::Host,
            Duration::from_millis(DEFAULT_DEBOUNCE_MS),
        )
    }

    /// Test-friendly variant: caller supplies the running predicate and
    /// debounce duration.
    ///
    /// # Errors
    ///
    /// See [`Watcher::new`].
    pub fn with_options(
        callback: WatcherCallback,
        is_running: RunningPredicate,
        debounce: Duration,
    ) -> Result<Self> {
        Self::with_running_source(callback, RunningSource::Custom(is_running), debounce)
    }

    fn with_running_source(
        callback: WatcherCallback,
        running_source: RunningSource,
        debounce: Duration,
    ) -> Result<Self> {
        let (event_tx, event_rx) = channel::<WatcherEvent>();
        let stop = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(Mutex::new(WatcherState::default()));
        let is_running: RunningPredicate = match &running_source {
            RunningSource::Host => Arc::new(crate::browsers::discovery::is_running),
            RunningSource::Custom(predicate) => Arc::clone(predicate),
        };

        // The fs watcher's event handler forwards every fs event into our
        // dispatch channel. We use the recommended watcher (inotify on
        // Linux, FSEvents on macOS) for cross-platform coverage.
        let event_tx_for_fs = event_tx.clone();
        let fs_watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            match res {
                Ok(event) => {
                    if interesting_event(event.kind) {
                        for path in event.paths {
                            // We don't care about errors here — if the
                            // dispatch thread is shutting down the channel
                            // is closed and there's nothing to do.
                            let _ = event_tx_for_fs.send(WatcherEvent::FsEvent(path));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        target: "silvervine::watcher",
                        error = %e,
                        "fs watcher delivered error event"
                    );
                }
            }
        })
        .map_err(|e| Error::other(format!("notify watcher init failed: {e}")).with_source(e))?;

        // Spawn the dispatch thread. It owns the receiver, the inner
        // state mutex, and the user callback.
        let inner_for_thread = Arc::clone(&inner);
        let stop_for_thread = Arc::clone(&stop);
        let callback_for_thread = Arc::clone(&callback);
        let running_source_for_thread = running_source;

        let dispatch_thread = std::thread::Builder::new()
            .name("silvervine-watcher".to_string())
            .spawn(move || {
                run_dispatch(
                    &event_rx,
                    &inner_for_thread,
                    &stop_for_thread,
                    &callback_for_thread,
                    &running_source_for_thread,
                    debounce,
                );
            })
            .map_err(|e| Error::other(format!("watcher dispatch thread spawn: {e}")))?;

        Ok(Self {
            inner,
            debounce,
            callback,
            is_running,
            fs_watcher: Some(fs_watcher),
            event_tx,
            dispatch_thread: Some(dispatch_thread),
            stop,
        })
    }

    /// Register a browser's install path with the watcher.
    ///
    /// Idempotent: re-watching an already-watched path is a no-op.
    ///
    /// # Errors
    ///
    /// * [`crate::ErrorCategory::Other`] if `notify` fails to add the
    ///   watch (e.g. the path doesn't exist).
    ///
    /// # Panics
    ///
    /// Panics if the internal state mutex is poisoned (only possible if
    /// another thread panicked while holding it).
    pub fn watch(&mut self, browser: Browser) -> Result<()> {
        let install = browser.install_path().to_path_buf();
        // Add the path to notify; recursive = "watch the whole bundle tree."
        if let Some(w) = self.fs_watcher.as_mut() {
            use notify::Watcher as _;
            w.watch(&install, RecursiveMode::Recursive).map_err(|e| {
                Error::other(format!("watch {} failed: {e}", install.display())).with_source(e)
            })?;
        }
        self.inner
            .lock()
            .entries
            .insert(install, WatchedEntry::new(browser));
        Ok(())
    }

    /// Stop watching a browser's install path.
    ///
    /// # Errors
    ///
    /// * [`crate::ErrorCategory::Other`] if `notify` fails to remove the
    ///   watch (rare — typically only if the path is already unwatched).
    ///
    /// # Panics
    ///
    /// Panics if the internal state mutex is poisoned.
    pub fn unwatch(&mut self, browser: &Browser) -> Result<()> {
        if let Some(w) = self.fs_watcher.as_mut() {
            use notify::Watcher as _;
            // Best-effort: ignore unwatch-already-unwatched errors.
            let _ = w.unwatch(browser.install_path());
        }
        self.inner.lock().entries.remove(browser.install_path());
        Ok(())
    }

    /// Stop the watcher cleanly.
    ///
    /// Drops the inner `notify::Watcher`, signals the dispatch thread to
    /// exit, and joins it. Calling `close` more than once is a no-op.
    /// `Drop` calls `close` automatically.
    pub fn close(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if !self.stop.swap(true, Ordering::SeqCst) {
            self.fs_watcher.take();
            let _ = self.event_tx.send(WatcherEvent::Wake);
        }
        if let Some(handle) = self.dispatch_thread.take() {
            let _ = handle.join();
        }
    }

    /// Return the configured debounce duration.
    #[must_use]
    pub fn debounce(&self) -> Duration {
        self.debounce
    }

    /// Number of currently-watched browsers.
    #[must_use]
    pub fn watched_count(&self) -> usize {
        self.inner.lock().entries.len()
    }

    /// `true` if the given install path is currently watched.
    #[must_use]
    pub fn is_watching(&self, install_path: &Path) -> bool {
        self.inner.lock().entries.contains_key(install_path)
    }

    /// Expose the configured running predicate for callers.
    #[must_use]
    pub fn running_predicate(&self) -> &RunningPredicate {
        &self.is_running
    }

    /// Re-emit the user callback for the supplied browser as if a
    /// filesystem event arrived. Mostly useful for tests + smoke-tests
    /// of the daemon's callback path.
    pub fn fire_for_test(&self, browser: &Browser) {
        (self.callback)(browser);
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// `true` if the event kind warrants a re-patch consideration.
///
/// We're interested in any **content** change inside the install path —
/// metadata-only events (atime touches, etc.) are ignored to avoid
/// firing on user-driven access.
fn interesting_event(kind: EventKind) -> bool {
    match kind {
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => true,
        EventKind::Access(_) | EventKind::Other | EventKind::Any => false,
    }
}

/// Dispatch loop body. Runs on the watcher's dedicated thread. A fixed
/// receive deadline drives periodic work without a second ticker thread, and
/// filesystem-event traffic cannot postpone that deadline.
fn run_dispatch(
    event_rx: &Receiver<WatcherEvent>,
    inner: &Arc<Mutex<WatcherState>>,
    stop: &Arc<AtomicBool>,
    callback: &WatcherCallback,
    running_source: &RunningSource,
    debounce: Duration,
) {
    const TICK_INTERVAL: Duration = Duration::from_millis(500);
    let mut next_tick = Instant::now() + TICK_INTERVAL;

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let timeout = next_tick.saturating_duration_since(Instant::now());
        match event_rx.recv_timeout(timeout) {
            Ok(WatcherEvent::FsEvent(path)) => handle_fs_event(&path, inner, debounce),
            Ok(WatcherEvent::Wake) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        let now = Instant::now();
        if now >= next_tick {
            let running = running_source.snapshot();
            handle_tick_with_snapshot(inner, callback, &running);
            while next_tick <= now {
                next_tick += TICK_INTERVAL;
            }
        }
    }
}

/// Process one filesystem event: resolve which browser it's for and
/// (re-)arm the trailing-edge debounce timer for that install path.
///
/// The callback is *not* fired here. The tick loop drains
/// [`WatcherState::next_dispatch_at`] once a path has been quiet for the
/// full debounce window. This avoids patching on top of an in-flight
/// browser update (the prior leading-edge behavior fired on the very
/// first event of a 30-event update storm, before the browser bundle
/// finished writing).
fn handle_fs_event(path: &Path, inner: &Arc<Mutex<WatcherState>>, debounce: Duration) {
    let now = Instant::now();
    let mut state = inner.lock();
    let Some(entry) = state
        .entries
        .values_mut()
        .find(|entry| entry.owns_event(path))
    else {
        return;
    };
    // Every event resets the timer — the path needs `debounce` of quiet
    // before the tick loop will fire the callback.
    entry.dispatch_at = Some(now + debounce);
}

/// Periodic tick: walk deferred entries, fire any whose bundle's mtime
/// has been stable for [`POST_QUIT_STABLE_S`] seconds and the browser is
/// no longer running.
fn handle_tick_with_snapshot(
    inner: &Arc<Mutex<WatcherState>>,
    callback: &WatcherCallback,
    running: &RunningSnapshot<'_>,
) {
    let stable_for = Duration::from_secs(POST_QUIT_STABLE_S);
    let now = Instant::now();
    let mut to_fire: Vec<Browser> = Vec::new();
    {
        let mut state = inner.lock();

        // Promote quiet debounce entries to either a callback or deferred
        // state. Iterating entries directly avoids cloning every path key.
        for entry in state.entries.values_mut() {
            if entry.dispatch_at.is_none_or(|deadline| now < deadline) {
                continue;
            }
            entry.dispatch_at = None;
            if running.is_running(&entry.browser) {
                tracing::info!(
                    target: "silvervine::watcher",
                    browser = %entry.browser.name(),
                    "debounce window elapsed but browser is running; deferring until quit"
                );
                entry.deferred = Some(DeferredState {
                    last_mtime: mtime_of(entry.browser.install_path()),
                    last_check: now,
                    first_seen: now,
                });
            } else {
                to_fire.push(entry.browser.clone());
            }
        }

        // Fire deferred entries once their installation has stayed unchanged
        // for the stability window and their browser has exited.
        for (install, entry) in &mut state.entries {
            let Some(deferred) = entry.deferred.as_mut() else {
                continue;
            };
            let current_mtime = mtime_of(install);
            if deferred.last_mtime != current_mtime {
                deferred.last_mtime = current_mtime;
                deferred.last_check = now;
                continue;
            }

            let stable = now.duration_since(deferred.last_check) >= stable_for;
            let expired = now.duration_since(deferred.first_seen) > Duration::from_secs(60 * 60);
            if stable && !running.is_running(&entry.browser) {
                entry.deferred = None;
                to_fire.push(entry.browser.clone());
            } else if expired {
                let deferred_for = deferred.first_seen.elapsed();
                entry.deferred = None;
                tracing::warn!(
                    target: "silvervine::watcher",
                    install = %install.display(),
                    deferred_for_s = ?deferred_for,
                    "giving up on deferred state and firing anyway"
                );
                to_fire.push(entry.browser.clone());
            }
        }
    }
    for browser in to_fire {
        callback(&browser);
    }
}

#[cfg(test)]
fn handle_tick(
    inner: &Arc<Mutex<WatcherState>>,
    callback: &WatcherCallback,
    is_running: &RunningPredicate,
) {
    handle_tick_with_snapshot(inner, callback, &RunningSnapshot::Custom(is_running));
}

/// Read the install dir's mtime; returns `None` on stat failure.
fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Search the watched entries for the browser whose configured or canonical
/// install path prefixes `event_path`.
#[cfg(test)]
fn find_owning_browser<'a>(
    entries: &'a HashMap<PathBuf, WatchedEntry>,
    event_path: &Path,
) -> Option<(&'a PathBuf, &'a Browser)> {
    entries
        .iter()
        .find(|(_, entry)| entry.owns_event(event_path))
        .map(|(install, entry)| (install, &entry.browser))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::AtomicUsize;
    use tempfile::TempDir;

    use crate::browsers::BrowserKind;

    /// Build a fake browser pointing at `path`, with a simple display name.
    fn fake_browser(name: &str, path: PathBuf) -> Browser {
        Browser {
            name: name.into(),
            install_path: path,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    /// Build isolated watcher state for direct debounce tests.
    fn state_with(browser: Browser) -> Arc<Mutex<WatcherState>> {
        let install = browser.install_path().to_path_buf();
        let mut state = WatcherState::default();
        state.entries.insert(install, WatchedEntry::new(browser));
        Arc::new(Mutex::new(state))
    }

    /// Force all armed debounce timers to be eligible for the next tick.
    fn expire_debounce(inner: &Arc<Mutex<WatcherState>>) {
        for entry in inner.lock().entries.values_mut() {
            if entry.dispatch_at.is_some() {
                entry.dispatch_at = Some(Instant::now());
            }
        }
    }

    /// An event inside a watched directory fires only after its debounce
    /// deadline expires.
    #[test]
    fn touch_fires_callback_after_debounce() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).unwrap();
        let browser = fake_browser("Test", install.clone());
        let inner = state_with(browser);

        let count = Arc::new(AtomicUsize::new(0));
        let count_for_cb = Arc::clone(&count);
        let cb: WatcherCallback = Arc::new(move |_b: &Browser| {
            count_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let not_running: RunningPredicate = Arc::new(|_| false);

        handle_fs_event(&install.join("touch"), &inner, Duration::from_millis(100));
        handle_tick(&inner, &cb, &not_running);
        assert_eq!(count.load(Ordering::SeqCst), 0);

        expire_debounce(&inner);
        handle_tick(&inner, &cb, &not_running);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// Multiple events within the debounce window produce one callback.
    #[test]
    fn debounce_collapses_burst() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).unwrap();
        let browser = fake_browser("Test", install.clone());
        let inner = state_with(browser);

        let count = Arc::new(AtomicUsize::new(0));
        let count_for_cb = Arc::clone(&count);
        let cb: WatcherCallback = Arc::new(move |_b: &Browser| {
            count_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let not_running: RunningPredicate = Arc::new(|_| false);

        for i in 0..10 {
            handle_fs_event(
                &install.join(format!("touch_{i}")),
                &inner,
                Duration::from_millis(200),
            );
        }
        assert_eq!(
            inner
                .lock()
                .entries
                .values()
                .filter(|entry| entry.dispatch_at.is_some())
                .count(),
            1
        );

        expire_debounce(&inner);
        handle_tick(&inner, &cb, &not_running);
        handle_tick(&inner, &cb, &not_running);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// Trailing-edge debounce never fires during a burst; it fires once after
    /// the final event's quiet window expires.
    #[test]
    fn burst_does_not_fire_during_window() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).unwrap();
        let browser = fake_browser("Test", install.clone());
        let inner = state_with(browser);

        let count = Arc::new(AtomicUsize::new(0));
        let count_for_cb = Arc::clone(&count);
        let cb: WatcherCallback = Arc::new(move |_b: &Browser| {
            count_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let not_running: RunningPredicate = Arc::new(|_| false);

        for i in 0..6 {
            handle_fs_event(
                &install.join(format!("touch_{i}")),
                &inner,
                Duration::from_millis(500),
            );
            handle_tick(&inner, &cb, &not_running);
            assert_eq!(count.load(Ordering::SeqCst), 0);
        }

        expire_debounce(&inner);
        handle_tick(&inner, &cb, &not_running);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    /// When the running predicate returns true, we don't fire — we defer.
    #[test]
    fn deferred_when_running() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).unwrap();
        let browser = fake_browser("Test", install.clone());

        let count = Arc::new(AtomicUsize::new(0));
        let count_for_cb = Arc::clone(&count);
        let cb: WatcherCallback = Arc::new(move |_b: &Browser| {
            count_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let always_running: RunningPredicate = Arc::new(|_| true);
        let mut watcher =
            Watcher::with_options(cb, always_running, Duration::from_millis(100)).unwrap();
        watcher.watch(browser).unwrap();

        // Trigger an event — should NOT fire.
        fs::write(install.join("touch"), b"x").unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "callback must not fire while browser appears running"
        );
        watcher.close();
    }

    /// Watch + unwatch removes the browser from internal state.
    #[test]
    fn watch_unwatch_round_trip() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).unwrap();
        let browser = fake_browser("Test", install.clone());

        let cb: WatcherCallback = Arc::new(|_b: &Browser| {});
        let not_running: RunningPredicate = Arc::new(|_| false);
        let mut watcher =
            Watcher::with_options(cb, not_running, Duration::from_millis(50)).unwrap();
        watcher.watch(browser.clone()).unwrap();
        assert!(watcher.is_watching(&install));
        assert_eq!(watcher.watched_count(), 1);
        watcher.unwatch(&browser).unwrap();
        assert!(!watcher.is_watching(&install));
        assert_eq!(watcher.watched_count(), 0);
        watcher.close();
    }

    /// `Drop` closes the watcher cleanly without panicking.
    #[test]
    fn drop_shuts_down_cleanly() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).unwrap();
        {
            let cb: WatcherCallback = Arc::new(|_b: &Browser| {});
            let not_running: RunningPredicate = Arc::new(|_| false);
            let mut w = Watcher::with_options(cb, not_running, Duration::from_millis(50)).unwrap();
            w.watch(fake_browser("Test", install.clone())).unwrap();
        } // dropped here
    }

    /// `interesting_event` filters access events but accepts create / modify.
    #[test]
    fn interesting_event_filters_correctly() {
        use notify::event::{AccessKind, CreateKind, ModifyKind, RemoveKind};
        assert!(interesting_event(EventKind::Create(CreateKind::File)));
        assert!(interesting_event(EventKind::Modify(ModifyKind::Any)));
        assert!(interesting_event(EventKind::Remove(RemoveKind::File)));
        assert!(!interesting_event(EventKind::Access(AccessKind::Read)));
        assert!(!interesting_event(EventKind::Any));
        assert!(!interesting_event(EventKind::Other));
    }

    /// `find_owning_browser` resolves an event path to its browser entry
    /// when the path is inside a registered install root.
    #[test]
    fn find_owning_browser_matches_prefix() {
        let mut map: HashMap<PathBuf, WatchedEntry> = HashMap::new();
        map.insert(
            PathBuf::from("/opt/helium-browser-bin"),
            WatchedEntry::new(fake_browser(
                "Helium",
                PathBuf::from("/opt/helium-browser-bin"),
            )),
        );
        map.insert(
            PathBuf::from("/opt/thorium"),
            WatchedEntry::new(fake_browser("Thorium", PathBuf::from("/opt/thorium"))),
        );
        let resolved =
            find_owning_browser(&map, Path::new("/opt/helium-browser-bin/chrome/VERSION")).unwrap();
        assert_eq!(resolved.1.name(), "Helium");
    }

    /// `find_owning_browser` also matches events reported through the
    /// canonical form of a configured path alias.
    #[cfg(unix)]
    #[test]
    fn find_owning_browser_matches_canonical_path_alias() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real-install");
        let alias = tmp.path().join("install-alias");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        let browser = fake_browser("Alias", alias.clone());
        let mut map = HashMap::new();
        map.insert(alias.clone(), WatchedEntry::new(browser));
        let event = fs::canonicalize(&real)
            .unwrap()
            .join("chrome")
            .join("VERSION");

        let (root, owner) = find_owning_browser(&map, &event).expect("canonical alias matches");
        assert_eq!(root, &alias);
        assert_eq!(owner.name(), "Alias");
    }

    #[cfg(unix)]
    #[test]
    fn watched_entry_keeps_canonical_alias_after_alias_disappears() {
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real-install");
        let alias = tmp.path().join("install-alias");
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let entry = WatchedEntry::new(fake_browser("Alias", alias.clone()));
        let event = fs::canonicalize(&real)
            .unwrap()
            .join("chrome")
            .join("VERSION");

        fs::remove_file(alias).unwrap();

        assert!(entry.owns_event(&event));
    }

    /// `find_owning_browser` returns `None` when no install root prefixes
    /// the event path.
    #[test]
    fn find_owning_browser_returns_none_for_unrelated_path() {
        let mut map: HashMap<PathBuf, WatchedEntry> = HashMap::new();
        map.insert(
            PathBuf::from("/opt/helium-browser-bin"),
            WatchedEntry::new(fake_browser(
                "Helium",
                PathBuf::from("/opt/helium-browser-bin"),
            )),
        );
        assert!(find_owning_browser(&map, Path::new("/etc/passwd")).is_none());
    }

    /// `mtime_of` returns `Some(_)` for an existing file, `None` for a
    /// missing one.
    #[test]
    fn mtime_of_returns_none_for_missing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("noexist");
        assert!(mtime_of(&path).is_none());
    }

    #[test]
    fn mtime_of_returns_some_for_existing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("file");
        fs::write(&path, b"x").unwrap();
        assert!(mtime_of(&path).is_some());
    }

    /// A host running source captures a process snapshot that can answer
    /// multiple browser queries without another process-table refresh.
    #[test]
    fn host_running_source_is_reusable() {
        let source = RunningSource::Host;
        let running = source.snapshot();
        let first = fake_browser("X", PathBuf::from("/no/such/path"));
        let second = fake_browser("Y", PathBuf::from("/also/missing"));
        assert!(!running.is_running(&first));
        assert!(!running.is_running(&second));
    }

    /// `Watcher::new` (production constructor) builds a watcher with the
    /// default predicate + debounce.
    #[test]
    fn new_uses_defaults() {
        let cb: WatcherCallback = Arc::new(|_| {});
        let watcher = Watcher::new(cb).expect("default constructor ok");
        assert_eq!(
            watcher.debounce(),
            Duration::from_millis(DEFAULT_DEBOUNCE_MS)
        );
        watcher.close();
    }

    #[test]
    fn running_predicate_preserves_configured_public_accessor() {
        let callback: WatcherCallback = Arc::new(|_| {});
        let predicate: RunningPredicate = Arc::new(|_| true);
        let watcher =
            Watcher::with_options(callback, predicate, Duration::from_millis(100)).unwrap();

        assert!((watcher.running_predicate())(&fake_browser(
            "Test",
            PathBuf::from("/missing")
        )));
        watcher.close();
    }

    /// `fire_for_test` invokes the user callback directly (not gated by
    /// debounce or running checks) — useful for daemon orchestration tests.
    #[test]
    fn fire_for_test_invokes_callback() {
        let count = Arc::new(AtomicUsize::new(0));
        let count_for_cb = Arc::clone(&count);
        let cb: WatcherCallback = Arc::new(move |_| {
            count_for_cb.fetch_add(1, Ordering::SeqCst);
        });
        let watcher =
            Watcher::with_options(cb, Arc::new(|_| false), Duration::from_millis(100)).unwrap();
        watcher.fire_for_test(&fake_browser("Test", PathBuf::from("/x")));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        watcher.close();
    }
}
