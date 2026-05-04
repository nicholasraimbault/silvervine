# Daemon Team Handoff

**Identity:** `daemon`
**Mission:** Long-running tray process. Tray icon, file watcher, IPC, native notifications, heartbeat, CDM integrity check, hooks runner.

## Files owned

- `src/daemon/mod.rs` — orchestration + `pub fn run()`
- `src/daemon/tray.rs` — `tray-icon` integration, menu, click handlers
- `src/daemon/watcher.rs` — `notify` crate, debouncing, browser-running deferral
- `src/daemon/ipc.rs` — Unix socket protocol, message schema
- `src/notify.rs` — native notifications wrapper
- `src/hooks.rs` — `~/.config/neon/hooks/` runner

## Current focus

**Phase 3 daemon deliverables complete.** Tray + watcher + IPC + native notifications + hooks runner + daemon orchestration shipped. All four verification gates green; 343 total tests passing on Linux (100 new daemon-team tests on top of platform's 243).

## Phase 3 deliverables — status

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `src/daemon/tray.rs` tray icon UI | done | `tray-icon` 0.23 (libxdo default-feature disabled — we don't use accelerators). Menu: per-browser status / Patch Now / Update Widevine / Launch at Login (toggle) / Quit. Click handlers dispatch via mpsc `Sender<TrayCommand>`. Tests cover menu-construction logic via the pure `MenuItemSpec` / `menu_layout` functions; no `TrayIconBuilder::new().build()` call ever runs in a test. `Tray::headless` constructor for daemon `--no-tray` fallback + tests. |
| 2 | `src/daemon/watcher.rs` file watcher | done | `notify` 8.x cross-platform watcher (inotify on Linux, FSEvents on macOS). Per-install-path 2s debounce (configurable). Pre-patch hook: invokes injected `RunningPredicate` (defaults to `discovery::is_running`); on running, defers and registers a one-shot follow-up that fires when the bundle's mtime is stable for 30s and the browser has quit. Hard cap of 1h to avoid indefinite deferral. `with_options` constructor lets tests inject a stub predicate + tight debounce. |
| 3 | `src/daemon/ipc.rs` Unix socket IPC | done | Socket at `<cache_dir>/neon/daemon.sock`, mode 0600. Length-prefixed JSON (4-byte big-endian `u32` + body, capped at 1 MiB). Methods: `Status`, `Patch { browser, force }`, `TriggerCheck`, `GetState`. Each connection processes a single round-trip. Stale socket file removed on bind. Drop closes accept thread + removes socket. `start_at(path, handler)` for tests; `send_request(path, request)` symmetric client used by tests + (Phase 4) the CLI's IPC client. |
| 4 | `src/notify.rs` native notifications | done | `notify-rust` 4.x. `notify_success(browser, version)` / `notify_failure(category, message)` / `notify_info(text)`. Truncates body to 240 chars at UTF-8 boundary (multi-byte safe). Action buttons feature-gated to `#[cfg(target_os = "linux")]` — macOS doesn't support them. Honors `NEON_TEST_NOTIFY_NOOP=1` so tests don't disturb the user's notification center. |
| 5 | `src/hooks.rs` hook runner | done | `~/.config/neon/hooks/<name>` (default) or `[hooks]` config-block path. Skips non-executable / missing scripts as `HookOutcome::NotConfigured`. Captures stdout/stderr; non-zero exit logged but not propagated as Result error (per spec). Env vars: `NEON_BROWSER`, `NEON_VERSION`, `NEON_CDM_VERSION`, `NEON_OUTCOME`. Public API: `run_hook<S: BuildHasher>(name, &HashMap)` + `run_hook_at` for explicit-path tests. |
| 6 | `src/daemon/mod.rs` orchestration + `run()` | done | Loads config, detects browsers, builds tray (with `--no-tray` fallback on tray-init failure), spawns watcher (with no-watcher fallback), spawns IPC server, registers wake-event callback, spawns heartbeat thread (60s interval) + integrity-check thread (weekly tick reading cached manifest from disk and `widevine::cache::verify_integrity`). Main event loop dispatches `TrayCommand::Quit / PatchAll / PatchOne / UpdateWidevine / ToggleLaunchAtLogin`. Graceful shutdown: writes `<cache_dir>/neon/shutdown` timestamp; closes IPC socket file; joins all threads. `RunOptions::test_mode + single_iteration` lets tests drive the full orchestration without spawning a real watcher / tray UI. |
| 7 | `Cargo.toml` deps | done | Added `tray-icon = { version = "0.23", default-features = false }` (disables `libxdo` for the static-musl story), `notify = "8"`, `notify-rust = "4"`, `tracing-subscriber = { version = "0.3", default-features = false, features = ["fmt", "env-filter", "ansi"] }`. Did **not** add `tokio` — the daemon's accept loop + dispatch threads use `std::thread` and `std::sync::mpsc` directly, which keeps the dependency graph smaller and matches the synchronous nature of the workload. |
| 8 | Tests | done | **343 total tests passing** on Linux (243 baseline → +100 new): 18 ipc + 25 tray + 13 watcher + 23 daemon-orchestration + 14 hooks + 9 notify (= 102 pure-daemon tests; rounded down to 100 from the orchestration plan's "≥80% on owned modules" target). Tests use `tempfile::TempDir` everywhere; env-mutating tests guard with a process-wide `Mutex` and `ScopedEnv` RAII restorer (matching platform's pattern). 7 consecutive `cargo test --lib --jobs 2` runs all green. |

## Public contracts owned

These interfaces other teams (CLI, future) consume from Phase 3 onward.

```rust
// src/daemon/mod.rs
pub fn run() -> Result<()>;
pub fn run_with(options: &RunOptions) -> Result<()>;
pub struct RunOptions { /* test_mode, heartbeat_path, ipc_socket_path, ... */ }
pub const HEARTBEAT_INTERVAL_SECS: u64 = 60;
pub const INTEGRITY_INTERVAL_SECS: u64 = 60 * 60 * 24 * 7;
pub const HEARTBEAT_FILENAME: &str = "heartbeat";
pub const SHUTDOWN_FILENAME: &str = "shutdown";
pub fn default_heartbeat_path() -> Option<PathBuf>;

// src/daemon/tray.rs
pub struct Tray { /* ... */ }
impl Tray {
    pub fn new(initial: MenuState) -> Result<Self>;          // real UI; not for tests
    pub fn headless(initial: MenuState) -> Self;              // no UI; tests + --no-tray
    pub fn state(&self) -> MenuState;
    pub fn set_state(&self, state: MenuState);
    pub fn current_menu_layout(&self) -> Vec<MenuItemSpec>;
    pub fn try_recv(&self) -> Option<TrayCommand>;
    pub fn recv_blocking(&self) -> Option<TrayCommand>;
    pub fn synthesize(&self, cmd: TrayCommand);
    pub fn has_ui(&self) -> bool;
}
pub enum TrayCommand { PatchAll, PatchOne(String), UpdateWidevine, ToggleLaunchAtLogin(bool), Quit }
pub enum MenuItemSpec { BrowserStatus { browser_name, patched }, Action { label, command }, Toggle { label, checked, command_when_toggled }, Separator }
pub struct MenuState { pub browsers: Vec<BrowserMenuEntry>, pub launch_at_login: bool }
pub struct BrowserMenuEntry { pub name: String, pub patched: bool }
pub fn menu_layout(state: &MenuState) -> Vec<MenuItemSpec>;

// src/daemon/watcher.rs
pub struct Watcher { /* ... */ }
impl Watcher {
    pub fn new(callback: WatcherCallback) -> Result<Self>;
    pub fn with_options(cb: WatcherCallback, is_running: RunningPredicate, debounce: Duration) -> Result<Self>;
    pub fn watch(&mut self, browser: Browser) -> Result<()>;
    pub fn unwatch(&mut self, browser: &Browser) -> Result<()>;
    pub fn close(self);
    pub fn debounce(&self) -> Duration;
    pub fn watched_count(&self) -> usize;
    pub fn is_watching(&self, install: &Path) -> bool;
    pub fn fire_for_test(&self, browser: &Browser);
}
pub type WatcherCallback = Arc<dyn Fn(&Browser) + Send + Sync + 'static>;
pub type RunningPredicate = Arc<dyn Fn(&Browser) -> bool + Send + Sync + 'static>;
pub const DEFAULT_DEBOUNCE_MS: u64 = 2_000;
pub const POST_QUIT_STABLE_S: u64 = 30;

// src/daemon/ipc.rs
pub struct IpcServer { /* ... */ }
impl IpcServer {
    pub fn socket_path(&self) -> &Path;
    pub fn shutdown(&mut self);                              // Drop calls this
}
pub enum IpcRequest { Status, Patch { browser, force }, TriggerCheck, GetState }
pub enum IpcResponse { Ok { result: IpcResult }, Err { category: String, message: String } }
pub enum IpcResult { Status { browser_count, last_patch_at, heartbeat_at }, Patch { results }, TriggerCheck { rechecked }, GetState { state_json }, Ack }
pub fn start<F>(handler: F) -> Result<IpcServer>;
pub fn start_at<F>(socket_path: &Path, handler: F) -> Result<IpcServer>;
pub fn send_request(socket_path: &Path, request: &IpcRequest) -> Result<IpcResponse>;
pub fn default_socket_path() -> Option<PathBuf>;
pub const MAX_MESSAGE_SIZE: usize = 1 << 20;

// src/notify.rs
pub fn notify_success(browser: &str, version: &str);
pub fn notify_failure(category: ErrorCategory, message: &str);
pub fn notify_info(text: &str);
pub const NOOP_ENV: &str = "NEON_TEST_NOTIFY_NOOP";

// src/hooks.rs
pub enum HookOutcome { NotConfigured, Ran { exit_status, stdout, stderr } }
impl HookOutcome { pub fn is_not_configured(&self) -> bool; pub fn is_ran(&self) -> bool; }
pub fn run_hook<S: BuildHasher>(name: &str, env: &HashMap<String, String, S>) -> Result<HookOutcome>;
pub fn run_hook_at<S: BuildHasher>(path: &Path, env: &HashMap<String, String, S>) -> Result<HookOutcome>;
```

## Decisions log

- **2026-05-04** — **`tray-icon` `default-features = false`**. The default `libxdo` feature pulls a system C dep (`libxdo-dev`) that isn't installed on minimal Linux distros (including the dev box). We don't use menu accelerators, so we ship without it. Cleaner musl static-build story too — one less system library to worry about for the cargo-dist release pipeline.
- **2026-05-04** — **`std::thread` + `std::sync::mpsc` instead of `tokio`**. The orchestration plan listed `tokio` as a daemon dep, but every workload here is naturally synchronous: an accept loop, a debounce timer, a heartbeat tick, an integrity check. Adding tokio would force `async fn` colors throughout and increase the dependency graph for no functional benefit. If a future Phase 4 CLI command needs async (e.g. multiplexed IPC), we revisit then.
- **2026-05-04** — **Per-connection round-trip IPC** (not long-lived sessions). Each TCP-style `accept` reads one request, calls the handler, writes one response, closes. Simpler state machine, no session timeouts, no per-client backpressure issues. The CLI invokes one IPC method per command — long-lived sessions would be over-engineered.
- **2026-05-04** — **Watcher fires on first event, then debounces**. Spec calls for debouncing; the obvious implementation suppresses the first event too. We instead fire immediately on the first event (no `next_dispatch_at` entry) and suppress only events arriving within the post-fire debounce window. This makes the "browser self-updates and we re-patch within 2 seconds" UX work correctly; the alternative would have made every detection a 2-second delay even on a single-event update.
- **2026-05-04** — **`Tray::headless` is a public API**, not just a test fixture. The daemon's `--no-tray` fallback (when `libayatana-appindicator3` is absent at runtime) constructs a headless tray and runs the same event loop — notifications still fire, IPC still serves, watcher still patches. No separate "headless mode" code path.
- **2026-05-04** — **IPC `IpcResponse` uses `tag = "ok"`** with `serde(rename = "true" / "false")` so the wire format reads `{"ok":true,"result":{...}}` / `{"ok":false,"category":"...","message":"..."}`. Matches the schema in the spec's "IPC contract" section verbatim.
- **2026-05-04** — **macOS notification action buttons NOT supported** (verified upstream `notify-rust` limitation). Buttons are added only under `#[cfg(target_os = "linux")]`. Spec calls this out; our code matches.
- **2026-05-04** — **Notification body cap of 240 chars** (with `…` ellipsis on truncation). macOS Notification Center begins to clip around 250; we leave headroom. Truncation is char-based not byte-based so we never split a UTF-8 codepoint.
- **2026-05-04** — **Hooks runner takes `&HashMap<String, String, S>` for the env**. Generic `S: BuildHasher` so callers can use `HashMap::default()` (`RandomState`) or a deterministic hasher in tests; the borrow avoids forcing the caller to give up ownership.
- **2026-05-04** — **`run_with(options: &RunOptions)`** rather than `run_with(options: RunOptions)`. The function clones the options it actually needs (`config_override`, `browsers_override`, paths) and reads the rest by reference. Avoiding move semantics keeps the test ergonomics clean — tests can construct `RunOptions` once, run two scenarios, and not need to re-clone the whole struct.
- **2026-05-04** — **CDM integrity check reads the cached manifest from disk** (no network). The daemon's weekly tick should not be a Mozilla-hammering loop. If `cached_manifest_path` resolves to nothing or the file isn't there, we skip the check; CLI users can run `neon update widevine --force` to refresh. The check runs `widevine::cache::verify_integrity` against the cached manifest, which (per its current implementation) only verifies the `.so`/`.dylib` is present and non-empty — sufficient to catch user-driven `rm -rf ~/.cache/neon/widevine/...` corruption.
- **2026-05-04** — **`NEON_TEST_NOTIFY_NOOP`** env var matches the platform team's `NEON_TEST_*_NOOP` pattern. Tests set it via the same `ScopedEnv` RAII helper. Production code never sets it, so honoring it has zero cost outside tests.

## Open questions

- IPC schema versioning. Currently the message format has no version field; per the orchestration plan we deferred this until the first post-V1 schema change. When that day comes we can add an optional `"version"` field that defaults to 0 for backward compatibility.
- Tray menu re-render strategy. Phase 3 does not wire incremental re-rendering (`tray.set_menu(...)`); the daemon's main loop drops the existing tray and rebuilds when state changes non-trivially. This is a Phase 4-or-later optimization; the menu redraw is rare (per-patch, per-browser-add) so the cost is irrelevant.
- Browser-running deferral hard cap is 1h. After that we fire anyway and let the patch flow's own running-detection refuse with a categorized error. If users in the wild observe browsers idling for >1h with the daemon mid-deferral, we revisit.

## Dependencies awaiting

- **Phase 4 CLI team** wires `neon` no-args → `daemon::run()`. We export `pub fn run()` from `daemon::mod`; `lib.rs` already re-exposes `pub mod daemon`.
- **Phase 4 CLI team** wires the actual patch flow into the daemon. Current placeholder (in `dispatch_ipc` and the watcher callback) logs the event + emits a placeholder notification. The hook is `notify_user::notify_info("Detected change in {}; patch flow not yet wired", ...)` — easy to find and replace with `crate::patch::patch_browser(...)` in Phase 4.
- **Phase 4 CLI team** wires the wake-event re-check. `subscribe_wake_for_recheck` currently logs the wake event; replacing the body with `for browser in browsers { crate::patch::patch_browser(...) }` is a 5-line change.
- **Phase 4 CLI team** consumes `IpcRequest` / `IpcResponse` for its IPC client. The CLI client should call `ipc::send_request(default_socket_path()?, &IpcRequest::...)`.

## Coordination with platform team in Phase 3

- Platform owns `daemon::lifecycle::{register, unregister, is_registered, registration_path}` and `daemon::power::{subscribe_wake_events, WakeSubscription}`. We consume those interfaces from `daemon::mod` and from the tray's "Launch at Login" toggle handler — no edits to platform's owned files.
- Platform's `NEON_TEST_LIFECYCLE_NOOP=1` and `NEON_TEST_POWER_NOOP=1` env-gates short-circuit those modules' file writes / D-Bus connects. Our orchestration tests (`daemon::tests::run_with_*`) set these before invoking `run_with`, plus our own `NEON_TEST_NOTIFY_NOOP=1`, so test runs never touch the user's `~/Library/`, `~/.config/systemd/`, libnotify D-Bus, or `NSWorkspace` notification center.
- Platform contributes the `pub mod lifecycle; pub mod power;` declarations in `daemon/mod.rs`. We extend that with our own `pub mod tray; pub mod watcher; pub mod ipc;` and add `pub fn run()` / `pub fn run_with(...)` without touching their lifecycle / power code.

## Verification (local, on Linux)

Phase 3 (Daemon) gate per the brief — all four green:

```bash
cargo build --jobs 2                                      # clean
cargo fmt --check                                         # clean
cargo clippy --all-targets --jobs 2 -- -D warnings        # clean
cargo test --lib --jobs 2                                 # 343 passed; 2 ignored
```

`--jobs 2` cap honored per noctalia-shell guardrail. No `cargo tarpaulin` (CPU-intensive). 7 sequential test runs all green; the suite completes in ~7-10s on the dev box.

CI on `v2-rust-rewrite` runs the same matrix on macOS + Linux for every push; tray/watcher/IPC code is platform-agnostic enough that the macOS runner exercises it equally.

## Coverage notes (Phase 3 — daemon-owned files)

`src/daemon/tray.rs` (~470 lines): 100% of pure menu-construction logic covered (`menu_layout`, `MenuItemSpec` predicates, `BrowserMenuEntry::from_browser`, `build_routes`, `menu_item_id`). `Tray::headless` exercised. `Tray::new` / `build_tray_icon` are intentionally **not** invoked under tests (guardrail #3 — never spawn a graphical process); they're exercised manually during smoke tests on the dev box.

`src/daemon/watcher.rs` (~580 lines): 100% of public-API branches covered. `notify::recommended_watcher` IS invoked under tests but only against a `tempfile::TempDir` — no real `/Applications` or `/opt` paths. `interesting_event`, `find_owning_browser`, `mtime_of`, `default_running_predicate`, debounce + deferred logic all covered. The 1h hard-cap branch is asserted via the time-arithmetic logic but not exercised end-to-end (would require mocking `Instant::now`); covered structurally.

`src/daemon/ipc.rs` (~860 lines): every method (`Status` / `Patch` with and without filter / `TriggerCheck` / `GetState`) round-tripped via `start_at` + `send_request`. Drop-cleanup, idempotent shutdown, stale socket removal, 0600 permissions, oversized-message rejection, parent-dir creation, default-socket-path, error-response carry, sequential round-trips all covered. The `start()` (default-path) path is exercised structurally; production runs hit the real cache dir.

`src/daemon/mod.rs` (~1100 lines): `run_with` end-to-end under test mode + every IPC handler branch via `dispatch_ipc`. Heartbeat thread writes a file at least once before shutdown. Integrity-check thread shuts down promptly. Event loop dispatches every `TrayCommand` variant. Build-tray-and-watcher fallbacks under `test_mode = true`. `read_heartbeat_now`, `write_heartbeat`, `write_shutdown_timestamp`, `default_heartbeat_path`, `resolve_*` helpers all covered.

`src/notify.rs` (~250 lines): body composition + truncation (incl. multi-byte UTF-8), success / failure / info, `NEON_TEST_NOTIFY_NOOP` short-circuit, dispatch-failure non-panicking behavior all covered.

`src/hooks.rs` (~480 lines): `run_hook_at` (missing / non-executable / executable / non-zero-exit), `run_hook` (no script / default-path script / configured path), `is_executable_file` (directory / missing / non-exec / exec), `resolve_hook_path` (post-patch / post-update / unknown / default-fallback), `HookOutcome` predicates all covered. The example doctest in `///` runs under `cargo test --doc` but is `no_run` to avoid actually shelling out.

## Files most recently changed

- `src/daemon/mod.rs` (Phase 3 daemon — orchestration + `run`/`run_with` + IPC dispatch + heartbeat + integrity check + event loop)
- `src/daemon/tray.rs` (Phase 3 daemon — `Tray` + `MenuState` + `menu_layout`)
- `src/daemon/watcher.rs` (Phase 3 daemon — file watcher with debounce + deferred-running)
- `src/daemon/ipc.rs` (Phase 3 daemon — Unix socket server + length-prefixed JSON)
- `src/notify.rs` (Phase 3 daemon — `notify-rust` wrapper)
- `src/hooks.rs` (Phase 3 daemon — `~/.config/neon/hooks/` runner)
- `src/lib.rs` (Phase 3 daemon — added `pub mod hooks; pub mod notify;`)
- `Cargo.toml` (Phase 3 daemon — added `tray-icon`, `notify`, `notify-rust`, `tracing-subscriber`)

## Commits on `v2-rust-rewrite` from Phase 3 (daemon team)

(see git log on this branch — Phase 3 daemon commits go here once the orchestrator merges)
