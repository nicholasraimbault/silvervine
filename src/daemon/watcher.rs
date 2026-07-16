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
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use notify::{EventKind, RecursiveMode};

use crate::browsers::Browser;
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
    /// Browsers we're watching, keyed by install path.
    /// Multiple browsers can share an install root; we store the first.
    browsers: HashMap<PathBuf, Browser>,
    /// Per-install-path debounce timers: when the next callback dispatch
    /// is allowed.
    next_dispatch_at: HashMap<PathBuf, Instant>,
    /// Browsers whose initial event came in while the browser was running.
    /// We track them so the polling thread can fire the callback once
    /// the bundle stabilizes.
    deferred: HashMap<PathBuf, DeferredState>,
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

/// Internal event types passed to the dispatch thread.
enum WatcherEvent {
    /// A filesystem event arrived for some path. We resolve which
    /// browser it affects and apply the debounce / deferred logic in
    /// the dispatch thread.
    FsEvent(PathBuf),
    /// Periodic tick — drives the deferred-state polling.
    Tick,
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
        Self::with_options(
            callback,
            default_running_predicate(),
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
        let (event_tx, event_rx) = channel::<WatcherEvent>();
        let stop = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(Mutex::new(WatcherState::default()));

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
                        target: "neon::watcher",
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
        let predicate_for_thread = Arc::clone(&is_running);
        let event_tx_for_tick = event_tx.clone();

        let dispatch_thread = std::thread::Builder::new()
            .name("neon-watcher".to_string())
            .spawn(move || {
                run_dispatch(
                    event_rx,
                    inner_for_thread,
                    stop_for_thread,
                    callback_for_thread,
                    predicate_for_thread,
                    debounce,
                    event_tx_for_tick,
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
        self.inner.lock().unwrap().browsers.insert(install, browser);
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
        let mut state = self.inner.lock().unwrap();
        state.browsers.remove(browser.install_path());
        state.next_dispatch_at.remove(browser.install_path());
        state.deferred.remove(browser.install_path());
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
            // Drop the fs watcher first so it stops emitting events.
            self.fs_watcher.take();
            // Send a final tick so the dispatch loop wakes up and observes
            // the stop flag.
            let _ = self.event_tx.send(WatcherEvent::Tick);
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
    ///
    /// # Panics
    ///
    /// Panics if the internal state mutex is poisoned.
    #[must_use]
    pub fn watched_count(&self) -> usize {
        self.inner.lock().unwrap().browsers.len()
    }

    /// `true` if the given install path is currently watched.
    ///
    /// # Panics
    ///
    /// Panics if the internal state mutex is poisoned.
    #[must_use]
    pub fn is_watching(&self, install_path: &Path) -> bool {
        self.inner
            .lock()
            .unwrap()
            .browsers
            .contains_key(install_path)
    }

    /// Expose the running predicate for callers (read-only). Used by the
    /// daemon orchestrator's tests.
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

/// Dispatch loop body. Runs on the watcher's dedicated thread. All
/// arguments are intentionally moved by value: the function owns them
/// for the lifetime of the loop, and the spawned tick thread captures
/// `tick_tx` + a clone of `stop`.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn run_dispatch(
    event_rx: Receiver<WatcherEvent>,
    inner: Arc<Mutex<WatcherState>>,
    stop: Arc<AtomicBool>,
    callback: WatcherCallback,
    is_running: RunningPredicate,
    debounce: Duration,
    tick_tx: Sender<WatcherEvent>,
) {
    // Periodic tick generator — drives the deferred-state polling.
    // We use a separate thread so the main dispatch thread can block on
    // `event_rx.recv` without polling.
    let tick_stop = Arc::clone(&stop);
    let tick_handle = std::thread::Builder::new()
        .name("neon-watcher-tick".to_string())
        .spawn(move || loop {
            if tick_stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
            if tick_tx.send(WatcherEvent::Tick).is_err() {
                return;
            }
        })
        .ok();

    while let Ok(event) = event_rx.recv() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match event {
            WatcherEvent::FsEvent(path) => {
                handle_fs_event(&path, &inner, &callback, &is_running, debounce);
            }
            WatcherEvent::Tick => {
                handle_tick(&inner, &callback, &is_running);
            }
        }
    }
    if let Some(h) = tick_handle {
        let _ = h.join();
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
fn handle_fs_event(
    path: &Path,
    inner: &Arc<Mutex<WatcherState>>,
    _callback: &WatcherCallback,
    _is_running: &RunningPredicate,
    debounce: Duration,
) {
    let now = Instant::now();
    let mut state = inner.lock().unwrap();
    let Some((install_root, _)) = find_owning_browser(&state.browsers, path) else {
        return;
    };
    let install_root = install_root.clone();
    // Every event resets the timer — the path needs `debounce` of quiet
    // before the tick loop will fire the callback.
    state.next_dispatch_at.insert(install_root, now + debounce);
}

/// Periodic tick: walk deferred entries, fire any whose bundle's mtime
/// has been stable for [`POST_QUIT_STABLE_S`] seconds and the browser is
/// no longer running.
fn handle_tick(
    inner: &Arc<Mutex<WatcherState>>,
    callback: &WatcherCallback,
    is_running: &RunningPredicate,
) {
    let stable_for = Duration::from_secs(POST_QUIT_STABLE_S);
    let now = Instant::now();
    let mut to_fire: Vec<Browser> = Vec::new();
    {
        let mut state = inner.lock().unwrap();

        // Step 1: drain expired debounce timers from `next_dispatch_at`.
        // An entry whose dispatch instant has been reached means the
        // install path has been quiet for `debounce`. Promote it: fire
        // the callback now if the browser isn't running, or move it to
        // `deferred` to wait out the running browser.
        let expired: Vec<PathBuf> = state
            .next_dispatch_at
            .iter()
            .filter(|(_, t)| now >= **t)
            .map(|(p, _)| p.clone())
            .collect();
        for install in expired {
            state.next_dispatch_at.remove(&install);
            let Some(browser) = state.browsers.get(&install).cloned() else {
                continue;
            };
            if is_running(&browser) {
                tracing::info!(
                    target: "neon::watcher",
                    browser = %browser.name(),
                    "debounce window elapsed but browser is running; deferring until quit"
                );
                state.deferred.insert(
                    install,
                    DeferredState {
                        last_mtime: mtime_of(browser.install_path()),
                        last_check: now,
                        first_seen: now,
                    },
                );
            } else {
                to_fire.push(browser);
            }
        }

        // Step 2: walk deferred entries (browsers that were running when
        // their debounce timer expired). Fire when mtime has stabilized
        // for [`POST_QUIT_STABLE_S`] and the browser has quit.
        let install_paths: Vec<PathBuf> = state.deferred.keys().cloned().collect();
        for install in install_paths {
            let Some(browser) = state.browsers.get(&install).cloned() else {
                state.deferred.remove(&install);
                continue;
            };
            let current_mtime = mtime_of(&install);
            let Some(entry) = state.deferred.get_mut(&install) else {
                continue;
            };
            // If mtime changed, reset the stable-since timer.
            if entry.last_mtime != current_mtime {
                entry.last_mtime = current_mtime;
                entry.last_check = now;
                continue;
            }
            // mtime stable. If long enough AND browser no longer running,
            // fire the callback.
            if now.duration_since(entry.last_check) >= stable_for && !is_running(&browser) {
                to_fire.push(browser);
                state.deferred.remove(&install);
            } else if now.duration_since(entry.first_seen) > Duration::from_secs(60 * 60) {
                // Hard cap: don't keep deferring forever. After an hour,
                // give up — log it and fire anyway. The patch flow's own
                // running-detection will refuse if the browser truly is
                // still running, which is a more actionable error than an
                // indefinitely-deferred state.
                let entry = state.deferred.remove(&install);
                tracing::warn!(
                    target: "neon::watcher",
                    install = %install.display(),
                    deferred_for_s = ?entry.map(|e| e.first_seen.elapsed()),
                    "giving up on deferred state and firing anyway"
                );
                to_fire.push(browser);
            }
        }
    }
    for b in to_fire {
        callback(&b);
    }
}

/// Read the install dir's mtime; returns `None` on stat failure.
fn mtime_of(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Search `browsers` for the entry whose install path is a prefix of
/// `event_path`. Returns `(install_path, &Browser)` of the matching entry.
///
/// macOS FSEvents reports canonical paths (for example, `/private/var/...`)
/// even when the registered path used an alias (`/var/...`). Compare both the
/// configured path and its canonical form so those events still resolve to
/// the browser that owns them. The original key remains unchanged so unwatch
/// and deletion handling keep working when the target later disappears.
fn find_owning_browser<'a>(
    browsers: &'a HashMap<PathBuf, Browser>,
    event_path: &Path,
) -> Option<(&'a PathBuf, &'a Browser)> {
    browsers.iter().find(|(install, _)| {
        event_path.starts_with(install)
            || std::fs::canonicalize(install)
                .is_ok_and(|canonical| event_path.starts_with(canonical))
    })
}

/// Default running predicate: delegates to
/// [`crate::browsers::discovery::is_running`].
fn default_running_predicate() -> RunningPredicate {
    Arc::new(|browser: &Browser| crate::browsers::discovery::is_running(browser))
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
        state.browsers.insert(install, browser);
        Arc::new(Mutex::new(state))
    }

    /// Force all armed debounce timers to be eligible for the next tick.
    fn expire_debounce(inner: &Arc<Mutex<WatcherState>>) {
        for deadline in inner.lock().unwrap().next_dispatch_at.values_mut() {
            *deadline = Instant::now();
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

        handle_fs_event(
            &install.join("touch"),
            &inner,
            &cb,
            &not_running,
            Duration::from_millis(100),
        );
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
                &cb,
                &not_running,
                Duration::from_millis(200),
            );
        }
        assert_eq!(inner.lock().unwrap().next_dispatch_at.len(), 1);

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
                &cb,
                &not_running,
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
        let mut map: HashMap<PathBuf, Browser> = HashMap::new();
        map.insert(
            PathBuf::from("/opt/helium-browser-bin"),
            fake_browser("Helium", PathBuf::from("/opt/helium-browser-bin")),
        );
        map.insert(
            PathBuf::from("/opt/thorium"),
            fake_browser("Thorium", PathBuf::from("/opt/thorium")),
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
        map.insert(alias.clone(), browser);
        let event = fs::canonicalize(&real)
            .unwrap()
            .join("chrome")
            .join("VERSION");

        let (root, owner) = find_owning_browser(&map, &event).expect("canonical alias matches");
        assert_eq!(root, &alias);
        assert_eq!(owner.name(), "Alias");
    }

    /// `find_owning_browser` returns `None` when no install root prefixes
    /// the event path.
    #[test]
    fn find_owning_browser_returns_none_for_unrelated_path() {
        let mut map: HashMap<PathBuf, Browser> = HashMap::new();
        map.insert(
            PathBuf::from("/opt/helium-browser-bin"),
            fake_browser("Helium", PathBuf::from("/opt/helium-browser-bin")),
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

    /// `default_running_predicate()` produces a callable predicate.
    #[test]
    fn default_running_predicate_callable() {
        let p = default_running_predicate();
        let b = fake_browser("X", PathBuf::from("/no/such/path"));
        // The default predicate scans real processes; we don't assert
        // its return value, only that it doesn't panic.
        let _ = p(&b);
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
