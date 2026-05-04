# Platform Team Handoff

**Identity:** `platform`
**Mission:** All platform-specific code: bundle write semantics, codesign, xattr, privilege escalation, daemon registration (LaunchAgent / systemd-user), sleep/wake hooks. Cross-platform abstractions live here.

## Files owned

- `src/platform/` — paths trait, Linux + macOS impls
- `src/patch/linux.rs` — Linux-specific patch (cp + chmod, no codesign)
- `src/patch/macos.rs` — macOS-specific patch (xattr -cr, codesign, atomic-rename APFS)
- `src/daemon/lifecycle.rs` — LaunchAgent / systemd-user unit registration
- `src/daemon/power.rs` — sleep/wake hooks (NSWorkspaceDidWakeNotification, logind D-Bus)
- `src/migration.rs` — detect + remove old bash-installed Neon

## Current focus

Pending. Activates in Phase 2 (Linux + macOS patch impls, migration logic) and Phase 3 (daemon lifecycle + sleep/wake).

## Public contracts owned (planned)

```rust
// patch/linux.rs
pub fn patch(target: &Path, cdm_source: &Path) -> Result<()>;

// patch/macos.rs
pub fn patch(target: &Path, cdm_source: &Path) -> Result<()>;

// platform/mod.rs
pub trait PlatformPaths {
    fn cache_dir() -> PathBuf;
    fn config_dir() -> PathBuf;
    fn applications_dirs() -> Vec<PathBuf>;
}
pub fn escalate_for_patch(target: &Path) -> Result<()>;
pub fn run_as_root(command: &[&str]) -> Result<Output>;

// migration.rs
pub fn detect_legacy_install() -> Option<LegacyInstall>;
pub fn remove_legacy(install: LegacyInstall) -> Result<()>;
```

## Decisions log

- **xattr `-r` flag confirmed exists on macOS** (verified during design phase). Rust impl preserves recursive clearing semantics; do not regress to `xattr -c` only.

## Open questions

- Should `platform/macos.rs` use the `objc` FFI directly for `NSWorkspaceDidWakeNotification`, or shell out to a small AppleScript helper? Direct FFI is cleaner but requires `unsafe` blocks. Decision deferred to Phase 3.

## Dependencies awaiting

- Core Engine team's `patch::PatchOutcome` / `Result` / error types (defines the contract `patch::linux::patch` and `patch::macos::patch` must conform to)

## Files most recently changed

(empty)
