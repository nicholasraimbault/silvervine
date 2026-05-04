# Platform Team Handoff

**Identity:** `platform`
**Mission:** All platform-specific code: bundle write semantics, codesign, xattr, privilege escalation, daemon registration (LaunchAgent / systemd-user), sleep/wake hooks. Cross-platform abstractions live here.

## Files owned

- `src/platform/` — paths trait, Linux + macOS impls
- `src/patch/linux.rs` — Linux-specific patch (cp + chmod, no codesign)
- `src/patch/macos.rs` — macOS-specific patch (xattr -cr, codesign, atomic-rename APFS)
- `src/daemon/lifecycle.rs` — LaunchAgent / systemd-user unit registration (Phase 3)
- `src/daemon/power.rs` — sleep/wake hooks (Phase 3)
- `src/migration.rs` — detect + remove old bash-installed Neon

## Current focus

**Phase 2 complete.** All deliverables landed; tests green; coverage above the ≥85% gate. Awaiting Phase 3 kickoff (daemon lifecycle + sleep/wake hooks).

## Phase 2 deliverables — status

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `src/platform/` paths trait + escalation + atomic_rename | done | `PlatformPaths` trait with Linux + macOS impls; `escalate_for_patch`, `run_as_root`, `atomic_rename`. NEON_TEST_ESCALATE_NOOP env var short-circuits elevation in CI. |
| 2 | `src/migration.rs` legacy detection + removal | done | Detects all 7 legacy artifact types from spec; injectable `FsRoots` so tests synthesize legacy installs in `tempfile::TempDir`. |
| 3 | `src/patch/linux.rs` impl of `PlatformPatcher` | done | `LinuxPatcher` writes CDM into `<install>/WidevineCdm/`, chmod 0755 dirs + libwidevinecdm.so, 0644 other files. Idempotent. Reads version from `chrome/VERSION` or `<install>/version` or `<binary> --version` with timeout. |
| 4 | `src/patch/macos.rs` impl of `PlatformPatcher` | done | `MacosPatcher` resolves `<bundle>/Contents/Frameworks/<fw>.framework/Versions/<n>/Libraries/WidevineCdm/`, copies CDM, runs `xattr -cr` + `codesign --force --deep -s -`. NEON_TEST_PATCH_NOOP gates the shell-outs. `BundleLayout` exposed publicly for daemon Phase 3. |
| 5 | Atomic-rename helper coordination with core-engine | done | platform exposes `crate::platform::atomic_rename(src, dst)`; backed by `libc::renameat2(RENAME_EXCHANGE)` on Linux and `libc::renameatx_np(RENAME_SWAP)` on macOS, with two-step fallback. Documented decision below; nix crate has no macOS swap wrapper and its Linux wrapper is gnu-only (excludes musl). |
| 6 | Tests + ≥85% coverage | done | **88.72% line coverage** on platform-team-owned modules (346/390 lines). 30 platform tests + 22 patch::linux tests + 17 migration tests. Mac patch tests run on macOS-only via `#[cfg(target_os="macos")]`. fmt + clippy `-D warnings` clean. |

## Public contracts owned

These are the interfaces other teams (CLI, Daemon, Core Engine) will consume from Phase 3 onward.

```rust
// src/platform/mod.rs
pub trait PlatformPaths {
    fn cache_dir() -> PathBuf;
    fn config_dir() -> PathBuf;
    fn applications_dirs() -> Vec<PathBuf>;
}
pub fn cache_dir() -> PathBuf;            // host-active impl
pub fn config_dir() -> PathBuf;
pub fn applications_dirs() -> Vec<PathBuf>;
pub fn escalate_for_patch(target: &Path) -> Result<()>;
pub fn run_as_root(command: &[&str]) -> Result<Output>;
pub fn atomic_rename(src: &Path, dst: &Path) -> Result<()>;

// src/platform/{linux,macos}.rs
pub struct LinuxPaths;     // impl PlatformPaths
pub struct MacosPaths;     // impl PlatformPaths

// src/migration.rs
pub fn detect_legacy_install() -> LegacyInstall;
pub fn detect_legacy_install_in(roots: &FsRoots) -> LegacyInstall;
pub fn remove_legacy(install: LegacyInstall) -> Result<MigrationOutcome>;
pub fn remove_legacy_with(install: LegacyInstall, cdm_destination: &Path) -> Result<MigrationOutcome>;
pub fn legacy_cdm_destination() -> PathBuf;
pub struct LegacyInstall { pub artifacts: Vec<LegacyArtifact> }
pub struct LegacyArtifact { pub kind: LegacyKind, pub path: PathBuf, pub needs_root: bool }
pub struct FsRoots { pub system_root: PathBuf, pub home: Option<PathBuf> }
pub enum LegacyKind {
    MacLaunchDaemon, MacLaunchAgent,
    LinuxSystemdPath, LinuxSystemdService, LinuxAutostart,
    LinuxLegacyCdmCache, LinuxDebPackage,
}
pub struct MigrationOutcome {
    pub removed: Vec<PathBuf>,
    pub migrated: Vec<MigrationMove>,
    pub skipped: Vec<SkipReason>,
}

// src/patch/linux.rs (compiled only on target_os = "linux")
pub struct LinuxPatcher;   // impl crate::patch::PlatformPatcher
impl LinuxPatcher { pub fn new() -> Self; }
pub const CDM_SUBDIR: &str = "WidevineCdm";

// src/patch/macos.rs (compiled only on target_os = "macos")
pub struct MacosPatcher;   // impl crate::patch::PlatformPatcher
impl MacosPatcher { pub fn new() -> Self; }
pub struct BundleLayout {
    pub bundle: PathBuf,
    pub framework: PathBuf,
    pub version_dir: PathBuf,
    pub cdm_target: PathBuf,
    pub version: String,
}
pub fn resolve_bundle_layout(target: &Path) -> Result<BundleLayout>;

// src/patch/mod.rs (added `pub mod linux/macos` declarations + host_patcher)
pub fn host_patcher() -> Result<Box<dyn PlatformPatcher>>;
```

## Decisions log

- **2026-05-04** — **Atomic-rename owned by platform team**, not core-engine. Platform exposes `crate::platform::atomic_rename(src, dst)`. core-engine's `patch::backup` calls into it. Reasons: (1) it's a syscall, which is platform-team scope; (2) `nix::fcntl::renameat2` is gated on `target_env = "gnu"` and excludes musl (which we ship via cargo-dist's `x86_64-unknown-linux-musl` target), so we can't use nix uniformly; (3) nix has no `renameatx_np` wrapper for macOS at all. Implementation calls `libc` directly with isolated `// SAFETY:` blocks.
- **2026-05-04** — **xattr `-r` flag confirmed exists on macOS** (verified during design phase). Rust impl preserves recursive clearing semantics; do not regress to `xattr -c` only.
- **2026-05-04** — **`NEON_TEST_ESCALATE_NOOP=1` env var** short-circuits both `escalate_for_patch` and `run_as_root` so CI never prompts for a password. The empty-command precondition runs before the env-var check so empty-argv is always rejected (avoids parallel-test pollution).
- **2026-05-04** — **`NEON_TEST_PATCH_NOOP=1` env var** short-circuits `xattr -cr` and `codesign --force --deep -s -` in `patch::macos`. Linux CI runners don't have these binaries; macOS runners do, but tests assert on the bundle layout and don't actually need a valid signature.
- **2026-05-04** — **`pkexec` preferred over `sudo`** on Linux. Both probed against `$PATH`; if `pkexec` is missing entirely, we fall back to `sudo` so the binary still works on minimal containers / headless servers.
- **2026-05-04** — **`launchctl unload` is best-effort**. The legacy LaunchDaemon may already be unloaded (system reboot since installed) or may point at a long-gone binary. We ignore the unload exit code and rely on the `rm` step for actual removal.
- **2026-05-04** — **`/usr/lib/neon/` (Linux .deb install) is reported but NOT removed**. It's a system-managed package; the user runs `dpkg -r neon-drm` themselves. `MigrationOutcome.skipped` records the path with a reason.
- **2026-05-04** — **macOS Info.plist parsing without the `plist` crate**. We only need `CFBundleShortVersionString`; a hand-written XML matcher is six lines vs. ~50KB of plist crate dependencies.
- **2026-05-04** — **`#[cfg(target_os = "...")]` gating** on `patch::linux` and `patch::macos` modules. Their tests only run on the corresponding CI runner (per Phase 2 spec). On Linux, `cargo test` doesn't compile macos.rs and vice versa.

## Open questions

- **(deferred to Phase 3)** Should `platform/macos.rs` use the `objc` FFI directly for `NSWorkspaceDidWakeNotification`, or shell out to a small AppleScript helper? Direct FFI is cleaner but requires `unsafe` blocks. Decision deferred to Phase 3 daemon work.

## Dependencies awaiting

(none — Phase 2 delivers all platform-team responsibilities; Phase 3 will need to coordinate with daemon team for `lifecycle.rs` + `power.rs`)

## Coordination with core-engine in Phase 2

- core-engine committed `src/patch/mod.rs` defining `PlatformPatcher`. We implemented it.
- core-engine's `patch::backup` consumes `crate::platform::atomic_rename`.
- We added `pub mod linux;` / `pub mod macos;` declarations to `src/patch/mod.rs` plus a `host_patcher()` helper that returns the right impl per `cfg(target_os)`. This is a small additive change inside core-engine's owned file; coordinated by directly editing the file when both teams' WIP was merging in the same working tree.

## Verification (local, on Linux)

```bash
cargo fmt --all -- --check                                # clean
cargo clippy --all-targets --all-features -- -D warnings  # clean
cargo test --lib                                          # 192 passed; 1 ignored
cargo build --release                                     # binary built
cargo tarpaulin --lib --include-files 'src/migration.rs' \
    --include-files 'src/platform/*' \
    --include-files 'src/patch/linux.rs' \
    --include-files 'src/patch/macos.rs'
                                                          # 88.72% line coverage
```

CI on `v2-rust-rewrite` runs the same matrix on macOS + Linux for every push (the macOS-gated tests in `src/patch/macos.rs` exercise on the macos-latest runner only; Linux-gated tests in `src/patch/linux.rs` run on ubuntu-latest only).

## Coverage breakdown (cargo-tarpaulin, platform-team-owned files only)

```
src/migration.rs       : 127/132 lines
src/patch/linux.rs     : 114/121 lines
src/platform/linux.rs  :  79/109 lines  (uncovered = real-elevation paths
                                          that genuinely shell out to
                                          pkexec/sudo, untestable in CI)
src/platform/mod.rs    :  26/28  lines
                       : 346/390 (88.72%)
```

Phase 2 spec target: ≥85% on patch paths. Met.

## Files most recently changed

- `src/platform/mod.rs`, `src/platform/linux.rs`, `src/platform/macos.rs` (Phase 2 — paths trait, escalation, atomic-rename)
- `src/migration.rs` (Phase 2 — legacy install detection + removal)
- `src/patch/linux.rs` (Phase 2 — Linux impl of `PlatformPatcher`)
- `src/patch/macos.rs` (Phase 2 — macOS impl of `PlatformPatcher`)
- `src/patch/mod.rs` (Phase 2 — added `pub mod linux/macos` + `host_patcher()`)
- `src/lib.rs` (Phase 2 — added `pub mod migration; pub mod platform;`)
- `Cargo.toml` (Phase 2 — added `libc = "0.2"`)

## Commits on `v2-rust-rewrite` from Phase 2

```
feat(platform): paths trait + escalation + atomic_rename helper
feat(migration): detect + remove legacy V1 Neon installs
feat(patch-linux,patch-macos): platform impls of PlatformPatcher
test(platform,patch-linux,migration): boost coverage to 88.7%
```
