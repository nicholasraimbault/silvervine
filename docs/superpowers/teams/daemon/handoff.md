# Daemon Team Handoff

**Identity:** `daemon`
**Mission:** Long-running tray process. Tray icon, file watcher, IPC, native notifications, heartbeat, CDM integrity check.

## Files owned

- `src/daemon/mod.rs` — orchestration
- `src/daemon/tray.rs` — `tray-icon` integration, menu, click handlers
- `src/daemon/watcher.rs` — `notify` crate, debouncing, browser-running detection
- `src/daemon/ipc.rs` — Unix socket protocol, message schema
- `src/notify.rs` — native notifications wrapper
- `src/hooks.rs` — `~/.config/neon/hooks/` runner

## Current focus

Pending. Activates in Phase 3 (tray, watcher, IPC, notifications, hooks).

## Public contracts owned (planned)

```rust
// daemon/mod.rs
pub fn run() -> Result<()>;          // entry from `neon` no-args
pub fn shutdown() -> Result<()>;

// daemon/ipc.rs
pub struct IpcServer { /* ... */ }
pub enum IpcRequest { Status, Patch { browser: Option<String>, force: bool }, TriggerCheck, ... }
pub enum IpcResponse { Ok(IpcResult), Err(ErrorCategory, String) }

// notify.rs
pub fn notify_success(browser: &str, version: &str);
pub fn notify_failure(category: ErrorCategory, message: &str);
```

## Decisions log

- **macOS notification action buttons not supported** (verified `notify-rust` limitation). Buttons feature-flagged via `#[cfg(target_os = "linux")]`.
- **Linux tray requires GTK + libayatana-appindicator3 runtime** — documented in README install section; `--no-tray` fallback for headless / minimal environments.

## Open questions

- IPC schema versioning strategy. Probably `serde_json` with version field; defer until first post-V1 schema change.
- Watcher debounce timing: 2s matches existing Swift app; verify still appropriate during Phase 3 testing.

## Dependencies awaiting

- Core Engine team's `patch::patch_browser` API (called from watcher)
- Platform team's `lifecycle` (daemon-registration) and `power` (sleep/wake) modules
- CLI team's IPC client implementation (consumes `IpcRequest`/`IpcResponse`)

## Files most recently changed

(empty)
