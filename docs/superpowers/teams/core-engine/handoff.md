# Core Engine Team Handoff

**Identity:** `core-engine`
**Mission:** Widevine acquisition + browser detection + atomic patching. Pure Rust logic, no platform-specific syscalls (those live in the Platform team's modules).

## Files owned

- `src/widevine/` — manifest, download, extract, cache management
- `src/browsers/` — known list, auto-discovery, custom-paths config
- `src/patch/mod.rs` — atomic patch protocol (calls into platform impls)
- `src/patch/backup.rs` — snapshot, rollback, atomic rename helpers
- `src/lockfile.rs` — flock-based concurrent-patch protection
- `src/error.rs` — categorized error type

## Current focus

Pending. Activates in Phase 1 (core skeleton — manifest parsing, browser detection, error type, lockfile) and Phase 2 (widevine download/extract, atomic patch, backup).

## Public contracts owned (planned)

```rust
// patch/mod.rs
pub fn patch_browser(browser: &Browser, options: PatchOptions) -> Result<PatchOutcome>;

// widevine/manifest.rs
pub fn fetch_manifest(urls: &[Url]) -> Result<Manifest>;

// browsers/mod.rs
pub fn detect_browsers() -> Vec<Browser>;
pub trait Browser { fn name(&self) -> &str; fn install_path(&self) -> &Path; fn is_patched(&self) -> bool; }

// error.rs
pub enum ErrorCategory { /* per spec */ }
```

## Decisions log

(empty)

## Open questions

(empty)

## Dependencies awaiting

- Platform team's `patch/linux.rs` and `patch/macos.rs` impls (interface defined here in Phase 2)

## Files most recently changed

(empty)
