//! Long-running tray daemon: orchestrates tray + watcher + IPC + power +
//! periodic background tasks.
//!
//! ## Module layout
//!
//! Phase 3 platform team's submodules:
//!   * [`lifecycle`] — `LaunchAgent` / systemd-user registration
//!   * [`power`] — sleep/wake hook subscription
//!
//! Phase 3 daemon team's submodules:
//!   * [`tray`] — tray icon UI + click-event channel
//!   * [`watcher`] — file watcher with per-browser debouncing
//!   * [`ipc`] — Unix-socket JSON IPC server
//!
//! ## Public surface
//!
//! ```ignore
//! pub mod lifecycle;
//! pub mod power;
//! pub mod tray;
//! pub mod watcher;
//! pub mod ipc;
//! pub fn run() -> Result<()>;
//! pub fn run_with(options: RunOptions) -> Result<()>;
//! ```
//!
//! `run()` is the entry point invoked by `silvervine` with no arguments
//! (Phase 4 wires this from `main.rs`). It:
//!
//! 1. Installs a `tracing-subscriber`.
//! 2. Loads the user config.
//! 3. Detects browsers.
//! 4. Builds the tray (or falls back to `--no-tray` if the tray library
//!    isn't available at runtime).
//! 5. Spawns the file watcher with a callback that triggers re-patch.
//! 6. Spawns the IPC server with a request handler.
//! 7. Registers a wake-event callback that re-checks all browsers.
//! 8. Spawns the heartbeat thread (writes timestamp every 60s).
//! 9. Spawns the CDM-integrity-check thread (weekly tick).
//! 10. Runs the main event loop.
//! 11. On SIGTERM / `Quit` tray command: tears down everything, writes
//!     a shutdown timestamp, returns.
//!
//! ## Test mode
//!
//! `RunOptions::test_mode = true` short-circuits all the production paths:
//!
//! * No tray UI (uses `Tray::headless`).
//! * No real watcher (skips `notify::recommended_watcher`).
//! * IPC binds to a `tempfile::TempDir`-supplied path.
//! * No `lifecycle::register` / `power::subscribe_wake_events` (relies on
//!   the existing `SILVERVINE_TEST_LIFECYCLE_NOOP` / `SILVERVINE_TEST_POWER_NOOP`
//!   gates).
//! * No `tracing_subscriber::fmt` install — tests can install their own.

pub mod ipc;
pub mod lifecycle;
pub mod power;
pub mod tray;
pub mod watcher;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::browsers::{self, Browser};
use crate::config::{load_config, Config};
use crate::error::Result;
use crate::notify as notify_user;
use crate::platform;

use ipc::{IpcRequest, IpcResponse, IpcResult, IpcServer};
use tray::{BrowserMenuEntry, MenuState, Tray, TrayCommand};
use watcher::{Watcher, WatcherCallback};

/// Heartbeat interval in seconds. Daemon writes the timestamp every
/// `HEARTBEAT_INTERVAL_SECS` seconds.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 60;

/// Weekly tick interval for the CDM integrity check. The daemon recomputes
/// the cached CDM's hash against the manifest and notifies on mismatch.
pub const INTEGRITY_INTERVAL_SECS: u64 = 60 * 60 * 24 * 7;

/// Filename of the heartbeat artifact under `cache_dir/silvervine/`.
pub const HEARTBEAT_FILENAME: &str = "heartbeat";

/// Filename of the shutdown timestamp written when `run()` returns.
pub const SHUTDOWN_FILENAME: &str = "shutdown";

/// Options driving [`run_with`]. The default values produce a real
/// production run; tests construct one with `test_mode = true` and
/// explicit paths.
#[derive(Clone, Default)]
pub struct RunOptions {
    /// If true, skip tray UI and use a headless tray. Skip
    /// lifecycle/power side-effects (those env-gate themselves).
    pub test_mode: bool,
    /// Override the heartbeat path. `None` resolves to
    /// `cache_dir/silvervine/heartbeat`.
    pub heartbeat_path: Option<PathBuf>,
    /// Override the IPC socket path. `None` resolves to
    /// `cache_dir/silvervine/daemon.sock`.
    pub ipc_socket_path: Option<PathBuf>,
    /// Override the heartbeat interval. `None` uses [`HEARTBEAT_INTERVAL_SECS`].
    pub heartbeat_interval: Option<Duration>,
    /// Override the integrity-check interval. `None` uses [`INTEGRITY_INTERVAL_SECS`].
    pub integrity_interval: Option<Duration>,
    /// Inject a fixed list of browsers for tests. When absent, detection uses
    /// the selected [`Config`].
    pub browsers_override: Option<Vec<Browser>>,
    /// Inject a config for tests. `None` calls [`load_config`] at runtime.
    pub config_override: Option<Config>,
    /// Run the main loop once and return `Ok(())` (test mode). When
    /// `false` (production), the loop runs until a `Quit` command or
    /// SIGTERM is received.
    pub single_iteration: bool,
}

/// Entry point for the daemon. Production callers in
/// [`crate::main`] invoke this when `silvervine` is run with no arguments.
///
/// Returns once the user / system requests shutdown.
///
/// # Errors
///
/// Surfaces the first irrecoverable error from any subsystem
/// (IPC bind, config load, etc.). Recoverable per-subsystem failures are
/// logged via `tracing` and don't abort the daemon — for example, if the
/// tray fails to initialize, we run in `--no-tray` mode and log a
/// warning.
pub fn run() -> Result<()> {
    install_tracing_subscriber();
    run_with(&RunOptions::default())
}

/// Test-and-injection-friendly variant of [`run`].
///
/// Exposed as `pub` so tests can drive the daemon with synthesized
/// browsers / config / paths without invoking real platform side-effects.
///
/// # Errors
///
/// See [`run`].
pub fn run_with(options: &RunOptions) -> Result<()> {
    tracing::info!(target: "silvervine::daemon", "silvervine daemon starting");

    let config = match options.config_override.clone() {
        Some(c) => c,
        None => load_config()?,
    };

    let browsers = match options.browsers_override.clone() {
        Some(browsers) => browsers,
        None => match browsers::Os::current() {
            Some(os) => browsers::detect_browsers_with(
                os,
                &browsers::FilesystemRoots::default_for(os),
                &config,
            ),
            None => Vec::new(),
        },
    };

    let stop = Arc::new(AtomicBool::new(false));

    // Build the initial menu from current on-disk patch state.
    let initial_state = MenuState {
        browsers: browsers
            .iter()
            .map(|b| BrowserMenuEntry::from_browser(b, b.is_patched()))
            .collect(),
        launch_at_login: lifecycle_is_registered(),
    };

    // Build tray. Failures fall through to a headless tray — daemon
    // continues in notifications-only mode.
    let tray = build_tray_with_fallback(initial_state.clone(), options.test_mode);

    // Build watcher. Failures here are likewise non-fatal — we log and
    // keep going (the daemon still serves IPC).
    let watcher_callback: WatcherCallback = Arc::new(|browser: &Browser| {
        tracing::info!(
            target: "silvervine::daemon",
            browser = %browser.name(),
            "watcher fired callback; running patch flow"
        );
        let results = drive_patch_flow(std::slice::from_ref(browser), None, false);
        let succeeded = results.iter().any(|(_, ok)| *ok);
        if succeeded {
            // CDM version is recorded in the per-browser report; we don't
            // have it at this layer (the report is consumed inside
            // drive_patch_flow). For the notification, use a placeholder.
            notify_user::notify_info(&format!(
                "Re-patched {} after detected change",
                browser.name()
            ));
        } else {
            notify_user::notify_info(&format!(
                "Patch attempt for {} did not succeed",
                browser.name()
            ));
        }
    });
    let watcher = build_watcher_with_fallback(watcher_callback, &browsers, options.test_mode);

    // Build IPC server. We keep a snapshot of the browser list here so
    // the handler can answer Status without re-detection.
    let ipc_state = Arc::new(IpcSharedState {
        browsers: std::sync::Mutex::new(browsers.clone()),
    });
    let ipc = build_ipc_server(options, &ipc_state)?;

    // Register the wake-event callback. Drop unsubscribes — keep the
    // subscription bound for the duration of run().
    let _wake_subscription = subscribe_wake_for_recheck(Arc::clone(&stop));

    // Heartbeat thread.
    let heartbeat_path = resolve_heartbeat_path(options);
    let heartbeat_interval = options
        .heartbeat_interval
        .unwrap_or_else(|| Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    let heartbeat_handle = spawn_heartbeat(
        heartbeat_path.clone(),
        heartbeat_interval,
        Arc::clone(&stop),
    );

    // Integrity-check thread.
    let integrity_interval = options
        .integrity_interval
        .unwrap_or_else(|| Duration::from_secs(INTEGRITY_INTERVAL_SECS));
    let integrity_handle = spawn_integrity_check(integrity_interval, Arc::clone(&stop));

    // Run the main event loop. In production this blocks until the user
    // clicks Quit / sends SIGTERM. In test mode (`single_iteration`) we run
    // one iteration then return.
    let result = run_event_loop(&tray, &stop, options.single_iteration, Some(&ipc_state));

    // Tear down: writes shutdown stamp + joins threads.
    tracing::info!(target: "silvervine::daemon", "silvervine daemon shutting down");
    stop.store(true, Ordering::SeqCst);
    drop(watcher); // close fs watcher + dispatch thread
    drop(ipc); // close IPC server + remove socket file
    if let Some(h) = heartbeat_handle {
        let _ = h.join();
    }
    if let Some(h) = integrity_handle {
        let _ = h.join();
    }
    write_shutdown_timestamp(heartbeat_path.parent().unwrap_or_else(|| Path::new("/tmp")));
    result
}

/// Internal IPC-handler shared state. Both the IPC handler closure (any
/// thread) and the daemon's main loop hold a reference; mutexes guard
/// the few mutable fields.
struct IpcSharedState {
    browsers: std::sync::Mutex<Vec<Browser>>,
}

/// Build the tray, falling back to headless if the platform backend cannot
/// initialize (for example, when Linux session D-Bus is unavailable).
fn build_tray_with_fallback(initial: MenuState, test_mode: bool) -> Tray {
    if test_mode {
        return Tray::headless(initial);
    }
    match Tray::new(initial.clone()) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(
                target: "silvervine::daemon",
                error = %e,
                "tray initialization failed; running in --no-tray mode (notifications only)"
            );
            Tray::headless(initial)
        }
    }
}

/// Build the watcher, falling back to a no-op closure if `notify` fails
/// to initialize.
fn build_watcher_with_fallback(
    callback: WatcherCallback,
    browsers: &[Browser],
    test_mode: bool,
) -> Option<Watcher> {
    if test_mode {
        return None;
    }
    let mut watcher = match Watcher::new(callback) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!(
                target: "silvervine::daemon",
                error = %e,
                "watcher initialization failed; daemon will not auto-detect browser updates"
            );
            return None;
        }
    };
    for browser in browsers {
        if let Err(e) = watcher.watch(browser.clone()) {
            tracing::warn!(
                target: "silvervine::daemon",
                browser = %browser.name(),
                error = %e,
                "failed to add browser to watcher"
            );
        }
    }
    Some(watcher)
}

/// Build the IPC server.
fn build_ipc_server(options: &RunOptions, state: &Arc<IpcSharedState>) -> Result<IpcServer> {
    let socket_path = resolve_socket_path(options);
    let state_for_handler = Arc::clone(state);
    ipc::start_at(&socket_path, move |req| {
        dispatch_ipc(&req, &state_for_handler)
    })
}

/// IPC handler: routes [`IpcRequest`] → [`IpcResponse`] using the shared
/// daemon state.
fn dispatch_ipc(req: &IpcRequest, state: &IpcSharedState) -> IpcResponse {
    match req {
        IpcRequest::Status => {
            let browsers = state.browsers.lock().unwrap();
            IpcResponse::ok(IpcResult::Status {
                browser_count: browsers.len(),
                last_patch_at: None, // wired in Phase 4 once state file is plumbed
                heartbeat_at: read_heartbeat_now(),
            })
        }
        IpcRequest::Patch { browser, force } => {
            // Phase 4: drive the real patch flow via cli::patch::run_patch_flow.
            // Tests of the IPC dispatcher use the path that doesn't touch
            // the network or filesystem (the Patch handler is exercised
            // through dispatch_ipc directly with a fake browser list); the
            // actual patch shell-out only happens in production.
            let browsers_snapshot = state.browsers.lock().unwrap().clone();
            let results = drive_patch_flow(&browsers_snapshot, browser.as_deref(), *force);
            IpcResponse::ok(IpcResult::Patch { results })
        }
        IpcRequest::TriggerCheck => {
            let browsers = state.browsers.lock().unwrap();
            IpcResponse::ok(IpcResult::TriggerCheck {
                rechecked: browsers.len(),
            })
        }
        IpcRequest::GetState => {
            // Phase 4 fills this in with the real state file contents.
            // For Phase 3 we return an empty JSON object so callers can
            // detect "daemon ran but state is empty" vs. "daemon down".
            IpcResponse::ok(IpcResult::GetState {
                state_json: "{}".into(),
            })
        }
    }
}

/// Subscribe to wake events. The callback flips a flag that the main
/// event loop checks; on wake we re-check every browser. Falls back to
/// a no-op subscription if the platform integration fails.
fn subscribe_wake_for_recheck(stop: Arc<AtomicBool>) -> Option<power::WakeSubscription> {
    let cb = Box::new(move || {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        tracing::info!(target: "silvervine::daemon", "wake event received; re-checking browsers");
        // Phase 4 wires the actual re-check flow; for now we just trace.
    });
    match power::subscribe_wake_events(cb) {
        Ok(sub) => Some(sub),
        Err(e) => {
            tracing::warn!(
                target: "silvervine::daemon",
                error = %e,
                "wake subscription failed; daemon will not re-check after sleep"
            );
            None
        }
    }
}

/// Spawn the heartbeat thread. Returns `Some(handle)` so callers can
/// join on shutdown.
fn spawn_heartbeat(
    path: PathBuf,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> Option<JoinHandle<()>> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::thread::Builder::new()
        .name("silvervine-heartbeat".to_string())
        .spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if let Err(e) = write_heartbeat(&path) {
                    tracing::warn!(
                        target: "silvervine::daemon",
                        error = %e,
                        path = %path.display(),
                        "heartbeat write failed"
                    );
                }
                // Sleep in small increments so the stop flag is observed
                // promptly on shutdown.
                let mut slept = Duration::ZERO;
                let granularity = Duration::from_millis(200);
                while slept < interval && !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(granularity);
                    slept += granularity;
                }
            }
        })
        .ok()
}

/// Spawn the weekly CDM integrity-check thread.
fn spawn_integrity_check(interval: Duration, stop: Arc<AtomicBool>) -> Option<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("silvervine-integrity".to_string())
        .spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let mut slept = Duration::ZERO;
                let granularity = Duration::from_millis(500);
                while slept < interval && !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(granularity);
                    slept += granularity;
                }
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                check_cdm_integrity();
            }
        })
        .ok()
}

/// Run the integrity check once. Best-effort: failures are logged but
/// don't abort the daemon.
fn check_cdm_integrity() {
    // Resolve the manifest from on-disk cache (no network — we don't want
    // to hammer Mozilla weekly). If the manifest cache is empty or
    // unparseable, we skip the check.
    use crate::widevine::cache::verify_integrity;
    use crate::widevine::manifest::{cached_manifest_path, parse_manifest};
    let Some(cache_path) = cached_manifest_path() else {
        tracing::info!(
            target: "silvervine::daemon",
            "integrity check: no resolvable manifest cache path; skipping"
        );
        return;
    };
    let bytes = match std::fs::read(&cache_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                target: "silvervine::daemon",
                "integrity check: no cached manifest at {}; skipping",
                cache_path.display()
            );
            return;
        }
        Err(e) => {
            tracing::warn!(
                target: "silvervine::daemon",
                error = %e,
                path = %cache_path.display(),
                "integrity check: failed to read cached manifest"
            );
            return;
        }
    };
    let manifest = match parse_manifest(&bytes) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                target: "silvervine::daemon",
                error = %e,
                "integrity check: failed to parse cached manifest"
            );
            return;
        }
    };
    match verify_integrity(&manifest) {
        Ok(()) => {
            tracing::debug!(target: "silvervine::daemon", "integrity check passed");
        }
        Err(e) => {
            tracing::warn!(
                target: "silvervine::daemon",
                error = %e,
                "integrity check failed; CDM may need redownload"
            );
            notify_user::notify_failure(e.category, &e.message);
        }
    }
}

/// Write the current Unix timestamp to the heartbeat file.
fn write_heartbeat(path: &Path) -> std::io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    std::fs::write(path, now.to_string())
}

/// Read the current heartbeat timestamp (if any) for IPC `Status`
/// responses. Returns `None` if the file is missing or unreadable.
fn read_heartbeat_now() -> Option<u64> {
    let path = default_heartbeat_path()?;
    let s = std::fs::read_to_string(&path).ok()?;
    s.trim().parse::<u64>().ok()
}

/// Write the current Unix timestamp to a `shutdown` file in `dir`.
fn write_shutdown_timestamp(dir: &Path) {
    let path = dir.join(SHUTDOWN_FILENAME);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let _ = std::fs::write(path, now.to_string());
}

/// Resolve the heartbeat file path from options (or the default).
fn resolve_heartbeat_path(options: &RunOptions) -> PathBuf {
    options.heartbeat_path.clone().unwrap_or_else(|| {
        default_heartbeat_path()
            .unwrap_or_else(|| std::env::temp_dir().join("silvervine-heartbeat"))
    })
}

/// Default heartbeat path: `<cache_dir>/silvervine/heartbeat`.
#[must_use]
pub fn default_heartbeat_path() -> Option<PathBuf> {
    Some(platform::cache_dir().join(HEARTBEAT_FILENAME))
}

/// Resolve the IPC socket path from options (or the default).
fn resolve_socket_path(options: &RunOptions) -> PathBuf {
    options.ipc_socket_path.clone().unwrap_or_else(|| {
        ipc::default_socket_path()
            .unwrap_or_else(|| std::env::temp_dir().join("silvervine-daemon.sock"))
    })
}

/// Run the main event loop. Reads tray commands; dispatches to the
/// patch / update / lifecycle / quit handlers. Returns `Ok(())` on
/// graceful shutdown.
fn run_event_loop(
    tray: &Tray,
    stop: &Arc<AtomicBool>,
    single_iteration: bool,
    state: Option<&Arc<IpcSharedState>>,
) -> Result<()> {
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        // Try to receive a command without blocking forever — we want
        // to observe the stop flag periodically.
        let cmd = tray.try_recv();
        match cmd {
            Some(TrayCommand::Quit) => {
                tracing::info!(target: "silvervine::daemon", "tray Quit; exiting");
                stop.store(true, Ordering::SeqCst);
                return Ok(());
            }
            Some(TrayCommand::PatchAll) => {
                tracing::info!(target: "silvervine::daemon", "tray PatchAll");
                if !daemon_patch_noop() {
                    let detected = detected_browsers_from(state);
                    let results = drive_patch_flow(&detected, None, false);
                    notify_user::notify_info(&summarize_patch_results(&results));
                }
            }
            Some(TrayCommand::PatchOne(name)) => {
                tracing::info!(target: "silvervine::daemon", browser = %name, "tray PatchOne");
                if !daemon_patch_noop() {
                    let detected = detected_browsers_from(state);
                    let results = drive_patch_flow(&detected, Some(&name), false);
                    notify_user::notify_info(&summarize_patch_results(&results));
                }
            }
            Some(TrayCommand::UpdateWidevine) => {
                tracing::info!(target: "silvervine::daemon", "tray UpdateWidevine");
                handle_update_widevine();
            }
            Some(TrayCommand::ToggleLaunchAtLogin(target)) => {
                tracing::info!(
                    target: "silvervine::daemon",
                    target_state = target,
                    "tray ToggleLaunchAtLogin"
                );
                handle_toggle_launch_at_login(target);
            }
            None => {
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        if single_iteration {
            return Ok(());
        }
    }
}

/// Best-effort: returns `true` if the daemon is registered for auto-start.
/// Lifecycle's `is_registered` is short-circuited to `false` under
/// `SILVERVINE_TEST_LIFECYCLE_NOOP`, so test runs never observe stale daemon
/// state.
fn lifecycle_is_registered() -> bool {
    lifecycle::is_registered()
}

/// Env-var name that, when set, makes the daemon's tray + IPC patch
/// handlers short-circuit without invoking the real patch flow. Used by
/// daemon tests + by the IPC dispatch tests that want to exercise the
/// JSON shape without spawning a network fetch.
pub const DAEMON_PATCH_NOOP_ENV: &str = "SILVERVINE_TEST_DAEMON_PATCH_NOOP";

/// Returns `true` when [`DAEMON_PATCH_NOOP_ENV`] is set in the
/// environment.
fn daemon_patch_noop() -> bool {
    std::env::var_os(DAEMON_PATCH_NOOP_ENV).is_some()
}

/// Drive the actual patch flow (in production) or short-circuit to a
/// per-browser `false` result (under `SILVERVINE_TEST_DAEMON_PATCH_NOOP=1`).
///
/// `name_filter` constrains which browser to patch; `force` toggles
/// the `force_while_running` patch option.
///
/// This is the function the tray's `PatchAll` / `PatchOne` and the IPC
/// `Patch` handler share — keeping them in lockstep guarantees the two
/// surfaces produce the same outcome shape.
///
/// Browsers whose installed CDM already matches the cached CDM are
/// reported as success without invoking the patcher — that avoids
/// pointless root escalation (and breaks the watcher→patch→watcher loop
/// where re-writing a bundle re-fires the watcher that just patched it).
#[must_use]
pub fn drive_patch_flow(
    browsers: &[Browser],
    name_filter: Option<&str>,
    force: bool,
) -> Vec<(String, bool)> {
    drive_patch_flow_with_cdm(browsers, name_filter, force, None)
}

fn drive_patch_flow_with_cdm(
    browsers: &[Browser],
    name_filter: Option<&str>,
    force: bool,
    fresh_cdm: Option<crate::widevine::CachedCdm>,
) -> Vec<(String, bool)> {
    if daemon_patch_noop() {
        return browsers
            .iter()
            .filter(|b| name_filter.is_none_or(|n| n == b.name()))
            .map(|b| (b.name().to_string(), false))
            .collect();
    }
    let Ok(patcher) = crate::patch::host_patcher() else {
        return browsers
            .iter()
            .filter(|b| name_filter.is_none_or(|n| n == b.name()))
            .map(|b| (b.name().to_string(), false))
            .collect();
    };
    // Retain the selected CDM so repair does not fetch a manifest when the
    // verified current cache is already usable.
    let cached_cdm =
        fresh_cdm.or_else(|| crate::widevine::cache::validated_current().ok().flatten());
    let cached_version = cached_cdm.as_ref().map(|cdm| cdm.version().to_string());
    let candidates: Vec<&Browser> = browsers
        .iter()
        .filter(|b| name_filter.is_none_or(|n| n == b.name()))
        .collect();
    let (needs, skip): (Vec<&Browser>, Vec<&Browser>) = candidates
        .into_iter()
        .partition(|b| needs_patch(b, cached_version.as_deref(), force));
    let mut results: Vec<(String, bool)> =
        skip.iter().map(|b| (b.name().to_string(), true)).collect();
    if needs.is_empty() {
        return results;
    }
    let cdm_resolver = move || {
        if let Some(cdm) = cached_cdm {
            return Ok(cdm);
        }
        let manifest = crate::widevine::fetch_manifest()?;
        crate::widevine::cache::ensure_cdm_for(&manifest)
    };
    let opts = crate::patch::PatchOptions {
        force_while_running: force,
        dry_run: false,
        ..Default::default()
    };
    let needs_owned: Vec<Browser> = needs.into_iter().cloned().collect();
    let reports = crate::cli::patch::run_patch_flow(
        &needs_owned,
        None,
        cdm_resolver,
        patcher.as_ref(),
        &opts,
    );
    results.extend(reports.into_iter().map(|r| (r.browser, r.success)));
    results
}

/// Decide whether a browser needs a patch. Returns `true` when forced,
/// when the browser has no installed CDM, when the on-disk version
/// differs from the cached one, or when the cached version is unknown
/// (we can't prove the on-disk one is current, so we err toward
/// patching).
#[must_use]
pub fn needs_patch(browser: &Browser, cached_version: Option<&str>, force: bool) -> bool {
    if force {
        return true;
    }
    let Some(installed) = browser.installed_cdm_version() else {
        return true;
    };
    match cached_version {
        Some(c) => installed != c,
        None => true,
    }
}

/// Resolve the current detected-browser list. Prefers the shared daemon
/// state (a snapshot taken at daemon start, behind a Mutex) over a fresh
/// `detect_browsers` walk so tray clicks don't trigger a full filesystem
/// scan on the event-loop thread. Falls back to `detect_browsers` when
/// state isn't available — that happens in tests that drive the loop
/// directly without spinning up `run_with`.
fn detected_browsers_from(state: Option<&Arc<IpcSharedState>>) -> Vec<Browser> {
    match state {
        Some(s) => s
            .browsers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
        None => match browsers::detect_browsers() {
            Ok(browsers) => browsers,
            Err(error) => {
                tracing::warn!(
                    target: "silvervine::daemon",
                    error = %error,
                    "browser detection failed"
                );
                Vec::new()
            }
        },
    }
}

/// Handler for the tray "Update Widevine" command: refresh the CDM cache,
/// then re-patch every detected browser, then surface a single toast.
/// Skips the entire flow under [`daemon_patch_noop`] so tests don't reach
/// the network or attempt root-escalated writes.
fn handle_update_widevine() {
    if daemon_patch_noop() {
        return;
    }
    let update = crate::widevine::fetch_manifest()
        .and_then(|manifest| crate::widevine::cache::ensure_cdm_for(&manifest));
    let cdm = match update {
        Ok(cdm) => cdm,
        Err(error) => {
            crate::hooks::emit_post_update(None, false);
            tracing::warn!(
                target: "silvervine::daemon",
                error = %error,
                "Widevine update failed"
            );
            notify_user::notify_failure(error.category, &error.message);
            return;
        }
    };
    let version = cdm.version().to_string();
    let detected = match browsers::detect_browsers() {
        Ok(browsers) => browsers,
        Err(error) => {
            crate::hooks::emit_post_update(Some(&version), false);
            tracing::warn!(
                target: "silvervine::daemon",
                error = %error,
                "Widevine refreshed, but browser detection failed"
            );
            notify_user::notify_failure(error.category, &error.message);
            return;
        }
    };
    let results = drive_patch_flow_with_cdm(&detected, None, false, Some(cdm));
    crate::hooks::emit_post_update(Some(&version), true);
    notify_user::notify_info(&format!(
        "Widevine refreshed; {}",
        summarize_patch_results(&results)
    ));
}

/// Handler for the tray "Launch at login" toggle: register/unregister via
/// [`lifecycle`] and emit a toast confirming the new state.
fn handle_toggle_launch_at_login(target: bool) {
    let result = if target {
        lifecycle::register()
    } else {
        lifecycle::unregister()
    };
    match result {
        Ok(()) => notify_user::notify_info(if target {
            "Launch at login enabled"
        } else {
            "Launch at login disabled"
        }),
        Err(e) => {
            tracing::warn!(
                target: "silvervine::daemon",
                error = %e,
                "lifecycle toggle failed"
            );
            notify_user::notify_failure(e.category, &e.message);
        }
    }
}

/// Produce a one-line user-facing summary of patch results for a toast
/// notification. Pure — no side effects — so tests can pin every branch.
///
/// Cases:
/// * `[]` → `"No browsers detected"` (no patch could even be tried).
/// * all succeeded, single → `"<name> patched"`.
/// * all succeeded, many → `"Patched <N> browsers"`.
/// * all failed, single → `"Patch failed for <name>"`.
/// * all failed, many → `"Patch failed for: <a>, <b>"`.
/// * mixed → `"Patched <X> of <N>; failed: <a>, <b>"`.
#[must_use]
pub fn summarize_patch_results(results: &[(String, bool)]) -> String {
    if results.is_empty() {
        return "No browsers detected".to_string();
    }
    let (ok, failed): (Vec<_>, Vec<_>) = results.iter().partition(|(_, s)| *s);
    let total = results.len();
    match (ok.len(), failed.len()) {
        (1, 0) => format!("{} patched", ok[0].0),
        (n, 0) => format!("Patched {n} browsers"),
        (0, 1) => format!("Patch failed for {}", failed[0].0),
        (0, _) => {
            let names: Vec<&str> = failed.iter().map(|(n, _)| n.as_str()).collect();
            format!("Patch failed for: {}", names.join(", "))
        }
        (ok_n, _) => {
            let names: Vec<&str> = failed.iter().map(|(n, _)| n.as_str()).collect();
            format!("Patched {ok_n} of {total}; failed: {}", names.join(", "))
        }
    }
}

/// Install the global `tracing` subscriber (production only). Called from
/// [`run`]. Tests don't call this — they install their own via
/// `tracing_subscriber::fmt::Subscriber::builder()` if needed.
fn install_tracing_subscriber() {
    use tracing_subscriber::fmt;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::Mutex;
    use tempfile::TempDir;

    use crate::browsers::BrowserKind;

    struct ScopedEnv {
        key: &'static str,
        prev: Option<OsString>,
    }
    impl ScopedEnv {
        fn set(key: &'static str, value: &Path) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }
    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn fake_browser(name: &str, install: PathBuf) -> Browser {
        Browser {
            name: name.into(),
            install_path: install,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    /// Build a minimal `RunOptions` that uses the supplied tempdir for all
    /// paths and runs in single-iteration test mode. Caller MUST set the
    /// `SILVERVINE_TEST_*_NOOP` env vars before invoking `run_with`.
    fn test_options(tmp: &TempDir, browsers: Vec<Browser>) -> RunOptions {
        RunOptions {
            test_mode: true,
            heartbeat_path: Some(tmp.path().join("heartbeat")),
            ipc_socket_path: Some(tmp.path().join("daemon.sock")),
            heartbeat_interval: Some(Duration::from_millis(50)),
            integrity_interval: Some(Duration::from_secs(60 * 60)),
            browsers_override: Some(browsers),
            config_override: Some(Config::default()),
            single_iteration: true,
        }
    }

    /// `run_with` returns `Ok(())` in test mode with `single_iteration=true`.
    #[test]
    fn run_with_test_mode_returns_ok() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _life = ScopedEnv::set(lifecycle::NOOP_ENV, Path::new("1"));
        let _power = ScopedEnv::set(power::NOOP_ENV, Path::new("1"));
        let _notify = ScopedEnv::set(notify_user::NOOP_ENV, Path::new("1"));

        let options = test_options(&tmp, vec![]);
        run_with(&options).expect("test-mode run returns Ok");
    }

    /// IPC socket gets created during `run_with`.
    #[test]
    fn run_with_creates_ipc_socket() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _life = ScopedEnv::set(lifecycle::NOOP_ENV, Path::new("1"));
        let _power = ScopedEnv::set(power::NOOP_ENV, Path::new("1"));
        let _notify = ScopedEnv::set(notify_user::NOOP_ENV, Path::new("1"));
        let socket = tmp.path().join("daemon.sock");

        let options = RunOptions {
            ipc_socket_path: Some(socket.clone()),
            ..test_options(&tmp, vec![])
        };
        run_with(&options).unwrap();
        // After shutdown the socket file is removed (per ipc::shutdown).
        assert!(!socket.exists(), "ipc shutdown should remove socket file");
    }

    /// Shutdown timestamp is written.
    #[test]
    fn run_with_writes_shutdown_timestamp() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _life = ScopedEnv::set(lifecycle::NOOP_ENV, Path::new("1"));
        let _power = ScopedEnv::set(power::NOOP_ENV, Path::new("1"));
        let _notify = ScopedEnv::set(notify_user::NOOP_ENV, Path::new("1"));

        let options = test_options(&tmp, vec![]);
        run_with(&options).unwrap();
        // Heartbeat path's parent is the tempdir; the SHUTDOWN_FILENAME
        // lives next to it.
        let shutdown_path = tmp.path().join(SHUTDOWN_FILENAME);
        assert!(
            shutdown_path.exists(),
            "shutdown timestamp file must exist at {}",
            shutdown_path.display()
        );
    }

    /// IPC handler responds to Status with the configured browser count.
    #[test]
    fn ipc_status_reflects_browser_count() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _life = ScopedEnv::set(lifecycle::NOOP_ENV, Path::new("1"));
        let _power = ScopedEnv::set(power::NOOP_ENV, Path::new("1"));
        let _notify = ScopedEnv::set(notify_user::NOOP_ENV, Path::new("1"));

        // We can't run the full daemon and also send IPC to it (single
        // iteration loop terminates before the IPC server has clients).
        // Instead, dispatch the IPC handler directly.
        let state = IpcSharedState {
            browsers: Mutex::new(vec![
                fake_browser("Helium", tmp.path().join("h")),
                fake_browser("Thorium", tmp.path().join("t")),
            ]),
        };
        let resp = dispatch_ipc(&IpcRequest::Status, &state);
        match resp {
            IpcResponse::Ok {
                result: IpcResult::Status { browser_count, .. },
            } => assert_eq!(browser_count, 2),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// IPC `Patch` request without browser filter returns one entry per
    /// known browser.
    #[test]
    fn ipc_patch_with_all_browsers_returns_per_browser_results() {
        let _g = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(DAEMON_PATCH_NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let state = IpcSharedState {
            browsers: Mutex::new(vec![
                fake_browser("Helium", tmp.path().join("h")),
                fake_browser("Thorium", tmp.path().join("t")),
            ]),
        };
        let resp = dispatch_ipc(
            &IpcRequest::Patch {
                browser: None,
                force: false,
            },
            &state,
        );
        match resp {
            IpcResponse::Ok {
                result: IpcResult::Patch { results },
            } => {
                assert_eq!(results.len(), 2);
                let names: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
                assert!(names.contains(&"Helium"));
                assert!(names.contains(&"Thorium"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// IPC `Patch` filtered by browser returns only that one.
    #[test]
    fn ipc_patch_filter_by_browser_name() {
        let _g = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(DAEMON_PATCH_NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let state = IpcSharedState {
            browsers: Mutex::new(vec![
                fake_browser("Helium", tmp.path().join("h")),
                fake_browser("Thorium", tmp.path().join("t")),
            ]),
        };
        let resp = dispatch_ipc(
            &IpcRequest::Patch {
                browser: Some("Thorium".into()),
                force: false,
            },
            &state,
        );
        match resp {
            IpcResponse::Ok {
                result: IpcResult::Patch { results },
            } => {
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].0, "Thorium");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// IPC `TriggerCheck` returns the count of browsers it would re-check.
    #[test]
    fn ipc_trigger_check_returns_count() {
        let tmp = TempDir::new().unwrap();
        let state = IpcSharedState {
            browsers: Mutex::new(vec![fake_browser("Helium", tmp.path().join("h"))]),
        };
        let resp = dispatch_ipc(&IpcRequest::TriggerCheck, &state);
        match resp {
            IpcResponse::Ok {
                result: IpcResult::TriggerCheck { rechecked },
            } => assert_eq!(rechecked, 1),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// IPC `GetState` returns a JSON-shaped result.
    #[test]
    fn ipc_get_state_returns_json() {
        let state = IpcSharedState {
            browsers: Mutex::new(vec![]),
        };
        let resp = dispatch_ipc(&IpcRequest::GetState, &state);
        match resp {
            IpcResponse::Ok {
                result: IpcResult::GetState { state_json },
            } => {
                // Must parse as JSON.
                let _: serde_json::Value = serde_json::from_str(&state_json).expect("valid JSON");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// `RunOptions::default` produces a non-test-mode config.
    #[test]
    fn run_options_default_is_production() {
        let opts = RunOptions::default();
        assert!(!opts.test_mode);
        assert!(opts.heartbeat_path.is_none());
        assert!(opts.ipc_socket_path.is_none());
        assert!(!opts.single_iteration);
    }

    /// Heartbeat write puts a parseable Unix timestamp into the file.
    #[test]
    fn write_heartbeat_writes_unix_timestamp() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("heartbeat");
        write_heartbeat(&path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let ts: u64 = body.trim().parse().unwrap();
        // Sanity: greater than 1.7e9 (2023+).
        assert!(ts > 1_700_000_000);
    }

    /// Shutdown timestamp lands at `<dir>/shutdown`.
    #[test]
    fn write_shutdown_timestamp_lands_at_dir_shutdown() {
        let tmp = TempDir::new().unwrap();
        write_shutdown_timestamp(tmp.path());
        let p = tmp.path().join(SHUTDOWN_FILENAME);
        assert!(p.exists());
        let body = std::fs::read_to_string(&p).unwrap();
        let ts: u64 = body.trim().parse().unwrap();
        assert!(ts > 1_700_000_000);
    }

    /// `default_heartbeat_path` ends in `silvervine/heartbeat`.
    #[test]
    fn default_heartbeat_path_ends_with_silvervine_heartbeat() {
        if let Some(p) = default_heartbeat_path() {
            assert!(p.ends_with(HEARTBEAT_FILENAME), "{}", p.display());
            assert!(p.parent().is_some_and(|d| d.ends_with("silvervine")));
        }
    }

    /// `resolve_heartbeat_path` honors the override.
    #[test]
    fn resolve_heartbeat_path_honors_override() {
        let opts = RunOptions {
            heartbeat_path: Some(PathBuf::from("/tmp/silvervine-test/hb")),
            ..RunOptions::default()
        };
        assert_eq!(
            resolve_heartbeat_path(&opts),
            PathBuf::from("/tmp/silvervine-test/hb")
        );
    }

    /// `resolve_socket_path` honors the override.
    #[test]
    fn resolve_socket_path_honors_override() {
        let opts = RunOptions {
            ipc_socket_path: Some(PathBuf::from("/tmp/silvervine-test/sock")),
            ..RunOptions::default()
        };
        assert_eq!(
            resolve_socket_path(&opts),
            PathBuf::from("/tmp/silvervine-test/sock")
        );
    }

    /// `build_tray_with_fallback` returns a headless tray when `test_mode`
    /// is on.
    #[test]
    fn build_tray_with_fallback_test_mode_uses_headless() {
        let initial = MenuState {
            browsers: vec![],
            launch_at_login: false,
        };
        let t = build_tray_with_fallback(initial, true);
        assert!(!t.has_ui());
    }

    /// `build_watcher_with_fallback` skips entirely in test mode.
    #[test]
    fn build_watcher_with_fallback_test_mode_returns_none() {
        let cb: WatcherCallback = Arc::new(|_| {});
        let opt = build_watcher_with_fallback(cb, &[], true);
        assert!(opt.is_none());
    }

    /// Heartbeat thread writes the file at least once before shutdown.
    #[test]
    fn heartbeat_thread_writes_at_least_once() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("hb");
        let stop = Arc::new(AtomicBool::new(false));
        let h = spawn_heartbeat(path.clone(), Duration::from_millis(20), Arc::clone(&stop))
            .expect("spawn ok");
        // Wait briefly for the thread to write.
        std::thread::sleep(Duration::from_millis(150));
        stop.store(true, Ordering::SeqCst);
        h.join().unwrap();
        assert!(path.exists(), "heartbeat file should exist");
    }

    /// Integrity-check thread shuts down promptly.
    #[test]
    fn integrity_check_thread_shuts_down_promptly() {
        let stop = Arc::new(AtomicBool::new(false));
        let h = spawn_integrity_check(Duration::from_secs(60), Arc::clone(&stop)).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        stop.store(true, Ordering::SeqCst);
        h.join().unwrap();
    }

    /// `run_event_loop` returns Ok on a Quit command.
    #[test]
    fn run_event_loop_returns_on_quit() {
        let tray = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
        });
        let stop = Arc::new(AtomicBool::new(false));
        // Synthesize a Quit before calling the loop.
        tray.synthesize(TrayCommand::Quit);
        run_event_loop(&tray, &stop, false, None).unwrap();
        assert!(stop.load(Ordering::SeqCst));
    }

    /// `run_event_loop` returns Ok when `single_iteration` is true and no
    /// command is pending.
    #[test]
    fn run_event_loop_single_iteration_returns_immediately() {
        let tray = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
        });
        let stop = Arc::new(AtomicBool::new(false));
        run_event_loop(&tray, &stop, true, None).unwrap();
    }

    /// `run_event_loop` exits when the stop flag is pre-set.
    #[test]
    fn run_event_loop_observes_stop_flag() {
        let tray = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
        });
        let stop = Arc::new(AtomicBool::new(true));
        run_event_loop(&tray, &stop, false, None).unwrap();
    }

    /// `read_heartbeat_now` returns None when no file exists.
    #[test]
    fn read_heartbeat_now_none_when_missing() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CACHE_HOME", tmp.path());
        let _home = ScopedEnv::set("HOME", tmp.path());
        // No heartbeat file in the redirected cache dir → None.
        assert!(read_heartbeat_now().is_none());
    }

    /// `read_heartbeat_now` reads the file when it exists.
    #[test]
    fn read_heartbeat_now_some_when_present() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CACHE_HOME", tmp.path());
        let _home = ScopedEnv::set("HOME", tmp.path());
        let path = default_heartbeat_path().unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "1700000123").unwrap();
        assert_eq!(read_heartbeat_now(), Some(1_700_000_123));
    }

    /// Tray `ToggleLaunchAtLogin` command honors NOOP — no actual lifecycle
    /// shell-out happens.
    #[test]
    fn tray_toggle_launch_at_login_under_noop() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(lifecycle::NOOP_ENV, Path::new("1"));
        let _notify = ScopedEnv::set(notify_user::NOOP_ENV, Path::new("1"));

        let tray = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
        });
        let stop = Arc::new(AtomicBool::new(false));
        tray.synthesize(TrayCommand::ToggleLaunchAtLogin(true));
        // Loop will run the toggle handler — it must not panic.
        run_event_loop(&tray, &stop, true, None).unwrap();
    }

    /// Tray `PatchAll` command is logged but doesn't crash the loop.
    #[test]
    fn tray_patch_all_acknowledged() {
        let _g = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(DAEMON_PATCH_NOOP_ENV, Path::new("1"));
        let tray = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
        });
        let stop = Arc::new(AtomicBool::new(false));
        tray.synthesize(TrayCommand::PatchAll);
        run_event_loop(&tray, &stop, true, None).unwrap();
    }

    /// Tray `PatchOne` command carries through to the loop.
    #[test]
    fn tray_patch_one_acknowledged() {
        let _g = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(DAEMON_PATCH_NOOP_ENV, Path::new("1"));
        let tray = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
        });
        let stop = Arc::new(AtomicBool::new(false));
        tray.synthesize(TrayCommand::PatchOne("Helium".into()));
        run_event_loop(&tray, &stop, true, None).unwrap();
    }

    /// Tray `UpdateWidevine` command runs.
    #[test]
    fn tray_update_widevine_acknowledged() {
        let _g = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(DAEMON_PATCH_NOOP_ENV, Path::new("1"));
        let tray = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
        });
        let stop = Arc::new(AtomicBool::new(false));
        tray.synthesize(TrayCommand::UpdateWidevine);
        run_event_loop(&tray, &stop, true, None).unwrap();
    }

    /// Build a fake browser whose `WidevineCdm/manifest.json` reports
    /// the given CDM version. Useful for exercising `needs_patch`.
    fn fake_patched_browser(name: &str, install: &Path, cdm_version: &str) -> Browser {
        let cdm = install.join("WidevineCdm");
        std::fs::create_dir_all(&cdm).unwrap();
        std::fs::write(
            cdm.join("manifest.json"),
            format!(r#"{{"version":"{cdm_version}"}}"#),
        )
        .unwrap();
        Browser {
            name: name.into(),
            install_path: install.to_path_buf(),
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    #[test]
    fn needs_patch_when_no_cdm_installed() {
        let tmp = TempDir::new().unwrap();
        let b = fake_browser("Helium", tmp.path().join("h"));
        assert!(needs_patch(&b, Some("4.10.2934.0"), false));
    }

    #[test]
    fn needs_patch_when_version_differs() {
        let tmp = TempDir::new().unwrap();
        let b = fake_patched_browser("Helium", &tmp.path().join("h"), "4.10.2891.0");
        assert!(needs_patch(&b, Some("4.10.2934.0"), false));
    }

    #[test]
    fn skips_patch_when_versions_match() {
        let tmp = TempDir::new().unwrap();
        let b = fake_patched_browser("Helium", &tmp.path().join("h"), "4.10.2934.0");
        assert!(!needs_patch(&b, Some("4.10.2934.0"), false));
    }

    #[test]
    fn force_overrides_version_match() {
        let tmp = TempDir::new().unwrap();
        let b = fake_patched_browser("Helium", &tmp.path().join("h"), "4.10.2934.0");
        assert!(needs_patch(&b, Some("4.10.2934.0"), true));
    }

    #[test]
    fn needs_patch_when_cache_unknown() {
        let tmp = TempDir::new().unwrap();
        let b = fake_patched_browser("Helium", &tmp.path().join("h"), "4.10.2891.0");
        assert!(needs_patch(&b, None, false));
    }

    #[test]
    fn summarize_patch_results_empty_says_no_browsers() {
        let s = summarize_patch_results(&[]);
        assert_eq!(s, "No browsers detected");
    }

    #[test]
    fn summarize_patch_results_single_success() {
        let s = summarize_patch_results(&[("Helium".into(), true)]);
        assert_eq!(s, "Helium patched");
    }

    #[test]
    fn summarize_patch_results_all_success() {
        let s = summarize_patch_results(&[
            ("Helium".into(), true),
            ("Thorium".into(), true),
            ("Chromium".into(), true),
        ]);
        assert_eq!(s, "Patched 3 browsers");
    }

    #[test]
    fn summarize_patch_results_single_failure() {
        let s = summarize_patch_results(&[("Helium".into(), false)]);
        assert_eq!(s, "Patch failed for Helium");
    }

    #[test]
    fn summarize_patch_results_all_failure() {
        let s = summarize_patch_results(&[("Helium".into(), false), ("Thorium".into(), false)]);
        assert_eq!(s, "Patch failed for: Helium, Thorium");
    }

    #[test]
    fn summarize_patch_results_mixed() {
        let s = summarize_patch_results(&[
            ("Helium".into(), true),
            ("Thorium".into(), false),
            ("Chromium".into(), true),
        ]);
        assert_eq!(s, "Patched 2 of 3; failed: Thorium");
    }

    /// `drive_patch_flow` honors `DAEMON_PATCH_NOOP_ENV` — short-circuits
    /// to per-browser `false` results without invoking the host patcher.
    #[test]
    fn drive_patch_flow_under_noop_returns_false_results() {
        let _g = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(DAEMON_PATCH_NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let browsers = vec![
            fake_browser("Helium", tmp.path().join("h")),
            fake_browser("Thorium", tmp.path().join("t")),
        ];
        let results = drive_patch_flow(&browsers, None, false);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|(_, ok)| !ok));
    }

    /// `drive_patch_flow` filter constrains the result list.
    #[test]
    fn drive_patch_flow_filter_by_name_returns_one_entry() {
        let _g = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(DAEMON_PATCH_NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let browsers = vec![
            fake_browser("Helium", tmp.path().join("h")),
            fake_browser("Thorium", tmp.path().join("t")),
        ];
        let results = drive_patch_flow(&browsers, Some("Helium"), false);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "Helium");
    }

    /// `IpcSharedState::browsers` mutex round-trip.
    #[test]
    fn ipc_shared_state_browsers_mutex_round_trip() {
        let tmp = TempDir::new().unwrap();
        let s = IpcSharedState {
            browsers: Mutex::new(vec![fake_browser("X", tmp.path().to_path_buf())]),
        };
        assert_eq!(s.browsers.lock().unwrap().len(), 1);
    }
}
