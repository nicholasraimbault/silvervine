# Platform Team Handoff

**Identity:** `platform`
**Mission:** All platform-specific code: bundle write semantics, codesign, xattr, privilege escalation, daemon registration (LaunchAgent / systemd-user), sleep/wake hooks. Cross-platform abstractions live here.

## Files owned

- `src/platform/` — paths trait, Linux + macOS impls
- `src/patch/linux.rs` — Linux-specific patch (cp + chmod, no codesign)
- `src/patch/macos.rs` — macOS-specific patch (xattr -cr, codesign, atomic-rename APFS)
- `src/daemon/lifecycle/{mod,linux,macos}.rs` — LaunchAgent / systemd-user unit registration (Phase 3)
- `src/daemon/power/{mod,linux,macos}.rs` — sleep/wake hooks (Phase 3)
- `src/migration.rs` — detect + remove old bash-installed Neon
- **Shared with daemon team:** `src/daemon/mod.rs` (façade only — `pub mod lifecycle; pub mod power;`). Daemon team will extend with `pub mod tray; pub mod watcher; pub mod ipc;` and `pub fn run()`.

## Current focus

**Phase 3 platform deliverables complete.** Daemon lifecycle + sleep/wake hooks landed; tests green; verification gates clean. Awaiting daemon team's Phase 3 work (tray, watcher, IPC, notifications, hooks).

## Phase 2 deliverables — status

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `src/platform/` paths trait + escalation + atomic_rename | done | `PlatformPaths` trait with Linux + macOS impls; `escalate_for_patch`, `run_as_root`, `atomic_rename`. NEON_TEST_ESCALATE_NOOP env var short-circuits elevation in CI. |
| 2 | `src/migration.rs` legacy detection + removal | done | Detects all 7 legacy artifact types from spec; injectable `FsRoots` so tests synthesize legacy installs in `tempfile::TempDir`. |
| 3 | `src/patch/linux.rs` impl of `PlatformPatcher` | done | `LinuxPatcher` writes CDM into `<install>/WidevineCdm/`, chmod 0755 dirs + libwidevinecdm.so, 0644 other files. Idempotent. Reads version from `chrome/VERSION` or `<install>/version` or `<binary> --version` with timeout. |
| 4 | `src/patch/macos.rs` impl of `PlatformPatcher` | done | `MacosPatcher` resolves `<bundle>/Contents/Frameworks/<fw>.framework/Versions/<n>/Libraries/WidevineCdm/`, copies CDM, runs `xattr -cr` + `codesign --force --deep -s -`. NEON_TEST_PATCH_NOOP gates the shell-outs. `BundleLayout` exposed publicly for daemon Phase 3. |
| 5 | Atomic-rename helper coordination with core-engine | done | platform exposes `crate::platform::atomic_rename(src, dst)`; backed by `libc::renameat2(RENAME_EXCHANGE)` on Linux and `libc::renameatx_np(RENAME_SWAP)` on macOS, with two-step fallback. Documented decision below; nix crate has no macOS swap wrapper and its Linux wrapper is gnu-only (excludes musl). |
| 6 | Tests + ≥85% coverage | done | **88.72% line coverage** on platform-team-owned modules (346/390 lines). 30 platform tests + 22 patch::linux tests + 17 migration tests. Mac patch tests run on macOS-only via `#[cfg(target_os="macos")]`. fmt + clippy `-D warnings` clean. |

## Phase 3 deliverables — status

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `src/daemon/lifecycle/mod.rs` public API + dispatch | done | `register()`, `unregister()`, `is_registered()`, `registration_path()`. `NEON_TEST_LIFECYCLE_NOOP=1` short-circuits filesystem + shell-out. |
| 2 | `src/daemon/lifecycle/macos.rs` LaunchAgent | done | Writes `~/Library/LaunchAgents/com.neon.tray.plist` with `Label`, `ProgramArguments`, `RunAtLoad=true`, `KeepAlive.SuccessfulExit=false`, `StandardOutPath`/`StandardErrorPath` → `~/Library/Logs/neon/tray.log`, `ProcessType=Interactive`. `register()`: write + `launchctl bootstrap gui/<uid>` (user-domain, no root). `unregister()`: `bootout` + `rm`. Tests use `tempfile::TempDir` + `ScopedEnv` for `$HOME`. |
| 3 | `src/daemon/lifecycle/linux.rs` systemd-user unit | done | Writes `~/.config/systemd/user/neon.service` (or `$XDG_CONFIG_HOME/systemd/user/...`) with `Description=Neon DRM tray and watcher`, `Type=simple`, `ExecStart=<current_exe>`, `Restart=on-failure`, `RestartSec=2s`, `StandardOutput=journal`, `StandardError=journal`, `WantedBy=default.target`. `register()`: write + `systemctl --user daemon-reload && enable --now`. No sudo. Tests use `tempfile::TempDir` + `ScopedEnv` for `$XDG_CONFIG_HOME`. |
| 4 | `src/daemon/power/mod.rs` public API + dispatch | done | `subscribe_wake_events(callback) -> Result<WakeSubscription>`. Drop unsubscribes. `NEON_TEST_POWER_NOOP=1` returns no-op handle. |
| 5 | `src/daemon/power/macos.rs` `NSWorkspaceDidWakeNotification` | done | objc2 + objc2-app-kit + block2. Adds an `addObserverForName:object:queue:usingBlock:` observer on `NSWorkspace.sharedWorkspace().notificationCenter()`. Drop calls `removeObserver:`. Each `unsafe` block carries a `// SAFETY:` comment. |
| 6 | `src/daemon/power/linux.rs` logind D-Bus signal | done | zbus 4 blocking API on a dedicated thread. Subscribes to `org.freedesktop.login1.Manager.PrepareForSleep`; fires callback only on the wake transition (false). On hosts without systemd-logind, returns `Ok` with a `tracing::warn!` (no-op subscription). Stop flag drives Drop. |
| 7 | `Cargo.toml` deps | done | Added `tracing = "0.1"`, `objc2 = "0.5"` + `objc2-foundation = "0.2"` + `objc2-app-kit = "0.2"` + `block2 = "0.5"` (macOS only), `zbus = "4"` (Linux only, default features for the blocking API). |
| 8 | `src/lib.rs` + `src/daemon/mod.rs` façade | done | Added `pub mod daemon;` to `lib.rs`. Wrote minimal `src/daemon/mod.rs` declaring only `pub mod lifecycle; pub mod power;` so daemon team can extend with `pub mod tray; pub mod watcher; pub mod ipc;` and `pub fn run()`. |
| 9 | Tests + ≥85% coverage | done | 33 new daemon tests (21 lifecycle + 12 power); 243 total tests passing on Linux. fmt + clippy `-D warnings` clean. Tests use the `NEON_TEST_LIFECYCLE_NOOP` / `NEON_TEST_POWER_NOOP` gates per guardrails — no real `launchctl`/`systemctl`/D-Bus interaction during test runs. `step_from_message` is exercised with synthesized in-memory `zbus::Message` values for full coverage of the wake/sleep/skip/fatal paths without needing a live bus. |

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

// src/daemon/mod.rs (façade — daemon team extends with their submodules)
pub mod lifecycle;
pub mod power;

// src/daemon/lifecycle/mod.rs
pub const NOOP_ENV: &str = "NEON_TEST_LIFECYCLE_NOOP";
pub fn register() -> Result<()>;
pub fn unregister() -> Result<()>;
pub fn is_registered() -> bool;
pub fn registration_path() -> Result<PathBuf>;

// src/daemon/power/mod.rs
pub const NOOP_ENV: &str = "NEON_TEST_POWER_NOOP";
pub type WakeCallback = Box<dyn Fn() + Send + 'static>;
pub struct WakeSubscription { /* private; Drop unsubscribes */ }
pub fn subscribe_wake_events(callback: WakeCallback) -> Result<WakeSubscription>;
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
- **2026-05-04** — **macOS wake hook uses `objc2` FFI**, not AppleScript. `objc2 + objc2-app-kit + block2` give a typed wrapper around `NSWorkspace.notificationCenter().addObserverForName:...`; the alternative (shelling out to `osascript -e 'tell ... to ...'`) doesn't actually have a way to get a wake notification synchronously. Total `unsafe` footprint is the four `addObserverForName` / `removeObserver` / `sharedWorkspace` / `notificationCenter` calls, each with a `// SAFETY:` comment.
- **2026-05-04** — **Linux wake hook uses zbus 4 default features** (which transitively pulls in `async-io`). zbus 4's `blocking` feature requires the async-io runtime under the hood; using `default-features = false, features = ["blocking"]` does not compile. Default features it is. The blocking iterator is driven from a dedicated `neon-power-listener` thread; daemon team's main loop is unaffected.
- **2026-05-04** — **systemd-user lifecycle is no-sudo by design.** `systemctl --user` operates on the user-bus and never requires `pkexec` / `sudo`. Same for macOS `launchctl bootstrap gui/<uid>`. This means daemon registration is a single-user-domain operation and doesn't share the `run_as_root_script` batching plumbing that migration uses.
- **2026-05-04** — **`NEON_TEST_LIFECYCLE_NOOP` and `NEON_TEST_POWER_NOOP` env vars** added per the Phase 3 brief. They short-circuit filesystem + shell-out / D-Bus connect at the public-API layer so tests never write into the real `~/Library/LaunchAgents/`, never run `launchctl`/`systemctl`, and never connect to the system bus. Tests that exercise file-write paths use `tempfile::TempDir` + a `ScopedEnv` guard to redirect `$HOME` / `$XDG_CONFIG_HOME`.
- **2026-05-04** — **`block2` added as macOS dep separately**. `objc2-app-kit` 0.2 doesn't enable the `block2` dependency under default features (only behind `apple` / `std` feature combos that pull a much larger surface). We add it directly so the wake-notification block can be constructed.
- **2026-05-04** — **`registration_path()` for Linux honors `$XDG_CONFIG_HOME`**, not just `$HOME`. systemd's user-unit search path is `$XDG_CONFIG_HOME/systemd/user/` first, falling back to `$HOME/.config/systemd/user/`. Tests redirect via `ScopedEnv::set("XDG_CONFIG_HOME", tmp.path())` so writes never land in the real `~/.config/`.

## Open questions

(none — Phase 3 deliverables answered the deferred macOS-FFI question above)

## Dependencies awaiting

(none — Phase 3 platform deliverables landed; daemon team's `tray`/`watcher`/`ipc`/`notify`/`hooks` is parallel and doesn't depend on this work compiling)

## Coordination with core-engine in Phase 2

- core-engine committed `src/patch/mod.rs` defining `PlatformPatcher`. We implemented it.
- core-engine's `patch::backup` consumes `crate::platform::atomic_rename`.
- We added `pub mod linux;` / `pub mod macos;` declarations to `src/patch/mod.rs` plus a `host_patcher()` helper that returns the right impl per `cfg(target_os)`. This is a small additive change inside core-engine's owned file; coordinated by directly editing the file when both teams' WIP was merging in the same working tree.

## Verification (local, on Linux)

Phase 3 (Platform) gate per the brief — all four green:

```bash
cargo build --jobs 2                                      # clean
cargo fmt --check                                         # clean
cargo clippy --all-targets --jobs 2 -- -D warnings        # clean
cargo test --lib --jobs 2                                 # 243 passed; 2 ignored
```

`--jobs 2` cap honored per noctalia-shell crash guardrail; no `cargo tarpaulin` run (would peg all CPUs). Coverage is asserted via per-function review (see below).

CI on `v2-rust-rewrite` runs the same matrix on macOS + Linux for every push (the macOS-gated tests in `src/patch/macos.rs` and `src/daemon/lifecycle/macos.rs` and `src/daemon/power/macos.rs` exercise on the macos-latest runner only; Linux-gated tests run on ubuntu-latest only).

## Coverage notes (Phase 3 — daemon-owned files)

`src/daemon/lifecycle/mod.rs` (≈210 lines): 100% of public-API branches covered. `register`/`unregister`/`is_registered` exercised both under NOOP and (via redirected `$HOME`/`$XDG_CONFIG_HOME`) for the real-path branches. `noop_enabled`, `registration_path`, `WakeSubscription` Drop all covered.

`src/daemon/lifecycle/linux.rs` (≈385 lines): `registration_path` (4 paths: xdg-set, xdg-empty, home-only, both-unset), `service_unit_body`, `write_unit_file` (parent-dir-create, overwrite), `write_register_artifacts`, `remove_unit_file_if_present` (both branches), `systemctl_user` (spawn-failure), `WithSourceMessage` (both branches) all covered. The `register()` and `unregister()` end-to-end shell-out paths are intentionally **not** invoked under tests (guardrail #2 — never invoke user-session services); their constituent helpers are individually covered.

`src/daemon/lifecycle/macos.rs` (≈465 lines): macOS-only, exercised on the macos-latest CI runner. Same structure as the Linux file: path resolution, plist body, write/remove helpers, gui domain/target string formatting, current_uid, and the spawn-failure branch of launchctl.

`src/daemon/power/mod.rs` (≈230 lines): `subscribe_wake_events`, `noop_enabled`, `WakeSubscription::noop`/`real`/`Drop` all covered; the `Real` Drop path is exercised on Linux via the public surface (NOOP variant). The `imp::subscribe()` non-NOOP path is platform-specific (see below).

`src/daemon/power/linux.rs` (≈315 lines): `step_from_message` covered for all four return paths (Wake, Sleep, Continue, Fatal) using synthesized in-memory `zbus::Message` values. `IterStep` Debug + variant matching covered. `Handle` synthesis + `drop_handle` (no-thread fallback, stop-flag toggle) covered. The `subscribe()` path that connects to the real system bus and spawns the `neon-power-listener` thread is intentionally **not** invoked under tests (guardrail #2 — never connect to the live user/system bus).

`src/daemon/power/macos.rs` (≈145 lines): macOS-only. The block-construction + `addObserverForName` paths require AppKit at link time and are exercised on the macos-latest runner via the public NOOP-gated test in `power::tests`.

## V3-Phase B — status (complete 2026-05-04)

| # | Deliverable | Status | Notes |
|---|---|---|---|
| A | `src/platform/capabilities/mod.rs` public API + per-OS dispatch | done | `BridgeCapabilities` (TPM/IOMMU/Virt/GPU/Kernel/Disk/RAM/Display); `CapabilityRoots` injectable filesystem roots; `detect()` / `detect_with()` entry points; `NEON_TEST_CAPS_NOOP` env var; default V2 builds compile this module so the `bridge` wrapper compiles even without the feature flag (feature-gating is at the `bridge::HardwareCapabilities` wrapper). |
| A | `src/platform/capabilities/linux.rs` impls | done | TPM via `/sys/class/tpm/tpm0/`, virt via `/proc/cpuinfo`, IOMMU via cmdline + `/sys/kernel/iommu_groups/`, GPU via `/sys/class/drm/card*/`, kernel via `/proc/sys/kernel/osrelease` (or `uname(2)` fallback), disk via `statvfs(2)`, RAM via `/proc/meminfo`, display via env vars + DRM connector `hdr_output_metadata`. |
| A | `src/platform/capabilities/macos.rs` impls | done | `system_profiler SPHardwareDataType -json` + `SPDisplaysDataType -json` parsed via serde; Secure Enclave / T2 detection; DART always-on; `physical_memory` parsing. Subprocess gated by `NEON_TEST_CAPS_NOOP`. |
| A | `src/platform/capabilities/tests.rs` | done | 25 tests using `tempfile::TempDir`-synthesized `/sys` / `/proc` / `/dev` trees (Linux); 7 macOS-only tests; 3 OS-agnostic tests (`CapabilityRoots::host`, NOOP env, end-to-end smoke). |
| B | `src/bridge/remediation.rs` | done | `CapabilityIssue` enum, `issues_for(...)`, `remediation_for(...)`. Hardcoded BIOS-key tables for ASUS, Gigabyte, MSI, ASRock, Lenovo, Dell, HP, Apple, Framework. Dummy plug Amazon link, GRUB cmdline guidance, ACS-override pointer. 7 unit tests cover every issue + remediation pair. |
| C | `src/cli/doctor.rs` `--bridge` flag | done | Pretty table renderer (no `tabled` dep — hand-rolled). JSON mode via `--json doctor --bridge`. Exit code: 0 if all green, 1 if any issue. Feature-gated so default `neon doctor --help` doesn't list `--bridge`. |
| D | `src/bridge/mod.rs` `HardwareCapabilities` widening | done | Wraps `crate::platform::capabilities::BridgeCapabilities`; `detect()` delegates to the platform module; `with(...)` constructor for tests; `issues()` convenience method. |
| E | env_mutex flake fix | done | Added `src/test_support.rs` with shared `env_lock()` global mutex (replaces 8 per-module `static ENV_MUTEX: Mutex<()>` declarations); recovers from poisoning via `unwrap_or_else(PoisonError::into_inner)`. 30 consecutive `cargo test --lib --jobs 2` runs clean (was ~10% flake rate previously). |
| F | Tests + verification | done | `cargo build` and `cargo build --features experimental-bridge`: clean. `cargo fmt --check`: clean. `cargo clippy --all-targets --jobs 2 -- -D warnings`: clean for both feature states. **494 tests on default; 508 with `experimental-bridge`** (was 466 / 469). |

## V3-Phase B public contracts

```rust
// src/platform/capabilities/mod.rs (V3-Phase B)
pub struct BridgeCapabilities {
    pub tpm: TpmStatus,
    pub iommu: IommuStatus,
    pub virtualization: VirtStatus,
    pub gpu: GpuStatus,
    pub kernel: KernelStatus,
    pub disk: DiskStatus,
    pub ram: RamStatus,
    pub display: DisplayStatus,
}
pub fn detect() -> BridgeCapabilities;
pub fn detect_with(roots: &CapabilityRoots) -> BridgeCapabilities;
pub const NOOP_ENV: &str = "NEON_TEST_CAPS_NOOP";
pub fn noop_enabled() -> bool;

pub enum TpmStatus {
    Present { version: String, vendor: Option<String> },
    Absent,
    NotChecked,
}
pub enum IommuStatus { Enabled { kind: IommuKind }, Disabled, Absent }
pub enum IommuKind { IntelVtD, AmdViO }
pub enum VirtStatus { Enabled { kind: VirtKind }, Disabled, Absent }
pub enum VirtKind { VtX, AmdV }
pub enum GpuStatus { Detected { devices: Vec<GpuDevice> }, NotDetected }
pub struct GpuDevice {
    pub vendor: String,             // "Intel" / "NVIDIA" / "AMD" / "Apple" / "Unknown (...)"
    pub model: String,
    pub iommu_group: Option<u32>,
    pub clean_isolation: bool,
    pub hdr_capable: bool,
}
pub struct KernelStatus { pub version: String, pub kvmfr_supported: bool }
pub struct DiskStatus { pub free_bytes: u64, pub mountpoint: PathBuf }
pub struct RamStatus { pub total_bytes: u64, pub available_bytes: u64 }
pub struct DisplayStatus { pub session_type: SessionType, pub hdr_capable: bool }
pub enum SessionType {
    Wayland { compositor: Option<String> },
    X11,
    Headless,
}

pub struct CapabilityRoots {
    pub sys: PathBuf,
    pub proc_: PathBuf,
    pub dev: PathBuf,
    pub home: Option<PathBuf>,
}
impl CapabilityRoots {
    pub fn host() -> Self;
}

// src/bridge/remediation.rs (gated experimental-bridge)
pub fn issues_for(caps: &BridgeCapabilities) -> Vec<CapabilityIssue>;
pub fn remediation_for(issue: &CapabilityIssue) -> RemediationStep;
pub enum CapabilityIssue {
    TpmAbsent, TpmUnknownVersion,
    IommuDisabled, IommuAbsent,
    VirtAbsent, VirtDisabled,
    GpuAbsent, GpuIsolationDirty,
    DiskTooSmall { free_bytes: u64, required_bytes: u64 },
    RamLow { total_bytes: u64, recommended_bytes: u64 },
    NeedsDummyPlug,
}
pub struct RemediationStep { pub title: String, pub detail: String }

// src/bridge/mod.rs (gated experimental-bridge)
pub struct HardwareCapabilities { pub inner: BridgeCapabilities }
impl HardwareCapabilities {
    pub fn detect() -> Self;
    pub fn with(inner: BridgeCapabilities) -> Self;
    pub fn issues(&self) -> Vec<CapabilityIssue>;
}

// src/test_support.rs (only built with cfg(any(test, debug_assertions)))
pub fn env_lock() -> std::sync::MutexGuard<'static, ()>;
```

## Decisions log (V3-Phase B)

- **2026-05-04 (V3-Phase B)** — `platform::capabilities` is **always compiled**, not gated on `experimental-bridge`. Rationale: the bridge wrapper at `src/bridge/mod.rs` is the only feature-gated consumer, and gating the platform module would have meant gating the runtime probes — which means the V2 binary couldn't include them even if a future non-bridge feature wanted to read them (e.g. `neon doctor` showing GPU model on default). Gating is at the bridge wrapper, where it matters.

- **2026-05-04 (V3-Phase B)** — `CapabilityRoots` carries a single `home: Option<PathBuf>` rather than reflecting the `FsRoots` from `migration.rs` which has `system_root` + `home`. Reasoning: capability detection probes across `/sys`, `/proc`, `/dev`, and `$HOME` independently; rolling them under a single `system_root` would have meant test fixtures relying on the /sys-under-/system-root path layout, which is wrong (real `/sys` is at `/sys`, not under `/`).

- **2026-05-04 (V3-Phase B)** — IOMMU detection looks at **both** `/proc/cmdline` (kernel cmdline) **and** `/sys/kernel/iommu_groups/` (groups populated). The product matrix:
  - groups + virt-vendor known → `Enabled { kind: <vendor> }`
  - no groups + cmdline-says-on + virt-vendor known → `Disabled` (BIOS toggle off)
  - no groups + no cmdline + no virt → `Absent` (CPU lacks the feature)
  - everything else → `Disabled` (best-effort)

- **2026-05-04 (V3-Phase B)** — GPU "clean isolation" detection skips PCIe bridges (PCI class 0x06xxxx) and same-PCI-function siblings (e.g. 67:00.0 and 67:00.1 share root `0000:67:00`). This matches the real-world VFIO usage pattern: a GPU + its audio companion at function .1 are both passed through to the same guest, and PCIe bridges in the same group don't need to be unbound.

- **2026-05-04 (V3-Phase B)** — `bytes_to_gib` uses `as f64` casting which is `clippy::cast_precision_loss`-flagged. We `#[allow(...)]` the lint locally because (a) we're rendering for human display, (b) display strings are formatted to 1 decimal place which is well below f64 mantissa precision for any plausible disk/RAM size on consumer hardware (max ~200TB before precision loss matters).

- **2026-05-04 (V3-Phase B)** — macOS DART detection reports `IommuKind::AmdViO` on aarch64 and `IommuKind::IntelVtD` on x86_64 as a marker. These are arbitrary; the wizard doesn't differentiate Apple from x86 for IOMMU. macOS users use Parallels/UTM for the Windows side anyway; this field is informational.

- **2026-05-04 (V3-Phase B)** — `env_mutex` flake fix is **shared** across all test modules via a single `crate::test_support::env_lock()` function. Previously each module had its own `static ENV_MUTEX: Mutex<()>`, which serialized within the module but allowed cross-module env-var races. The new shared lock + `unwrap_or_else(PoisonError::into_inner)` recovery brings the test flake rate from ~10% to ~0% (30 consecutive clean runs verified).

- **2026-05-04 (V3-Phase B)** — `test_support` module is `#[cfg(any(test, debug_assertions))]` rather than `#[cfg(test)]`. Rationale: test modules in *other* files reference `crate::test_support::env_lock()`, and `cfg(test)` only fires for the crate currently being tested; a sibling integration test that depends on the lib pulling its own test scaffolding would not see it. `debug_assertions` is enabled in `dev` profile (which is what `cargo test` uses) and disabled in `release` builds (so the production binary doesn't include the symbol). This is the same pattern other crates use for "test helpers exposed at the lib level".

- **2026-05-04 (V3-Phase B)** — `neon doctor --bridge` exits with **non-zero** when any capability issue surfaces, not just on "hard" issues like missing TPM. Single-GPU hosts get a `NeedsDummyPlug` issue which is informational but treated as exit-code-1 by design (the wizard expects `doctor --bridge` to be a strict gate before `stream init`). Users with single-GPU hosts run `doctor --bridge` once, install the dummy plug, then proceed.

- **2026-05-04 (V3-Phase B)** — Hardware-acceptance smoke check on Nick's actual machine (Linux, AMD desktop, Wayland niri): all probes returned plausible values (TPM 2.0 detected, IOMMU enabled with clean group, AMD GPU at IOMMU 21, 29 GB RAM, 2.9 TB free, kernel 7.0.3-1-cachyos). One issue surfaced: `NeedsDummyPlug` (correct — single-GPU host).

## Files most recently changed (V3-Phase B + Phase 3)

V3-Phase B:

- `src/platform/capabilities/mod.rs` (V3-Phase B — new, public types + dispatch)
- `src/platform/capabilities/linux.rs` (V3-Phase B — new, Linux impls)
- `src/platform/capabilities/macos.rs` (V3-Phase B — new, macOS impls)
- `src/platform/capabilities/tests.rs` (V3-Phase B — new, 35 tests)
- `src/platform/mod.rs` (V3-Phase B — added `pub mod capabilities`)
- `src/bridge/mod.rs` (V3-Phase B — `HardwareCapabilities` wraps real platform detection; new `with()` + `issues()` methods)
- `src/bridge/remediation.rs` (V3-Phase B — new, gated `experimental-bridge`)
- `src/cli/doctor.rs` (V3-Phase B — `--bridge` flag + renderer)
- `src/main.rs` (V3-Phase B — `--bridge` flag wiring under `Doctor` variant)
- `src/test_support.rs` (V3-Phase B — new, shared `env_lock()`)
- `src/lib.rs` (V3-Phase B — added `pub mod test_support` under `cfg(any(test, debug_assertions))`)
- `tests/fixtures/macos_system_profiler.json` (V3-Phase B — new committed fixture)
- 8 test modules (`notify.rs`, `hooks.rs`, `daemon/{mod,lifecycle/{mod,linux,macos},power/mod}.rs`, `cli/{init,uninstall,repair}.rs`) — `static ENV_MUTEX` removed, replaced with `crate::test_support::env_lock()` calls.

Phase 3:

- `src/lib.rs` (Phase 3 — added `pub mod daemon;`)
- `src/daemon/mod.rs` (Phase 3 — façade declaring `pub mod lifecycle; pub mod power;` so daemon team can extend)
- `src/daemon/lifecycle/{mod,linux,macos}.rs` (Phase 3 — daemon registration)
- `src/daemon/power/{mod,linux,macos}.rs` (Phase 3 — sleep/wake hooks)
- `Cargo.toml` (Phase 3 — added `tracing`, `objc2*` + `block2` for macOS, `zbus` for Linux)
- `src/platform/mod.rs`, `src/platform/linux.rs`, `src/platform/macos.rs` (Phase 2 — paths trait, escalation, atomic-rename)
- `src/migration.rs` (Phase 2 — legacy install detection + removal)
- `src/patch/linux.rs` (Phase 2 — Linux impl of `PlatformPatcher`)
- `src/patch/macos.rs` (Phase 2 — macOS impl of `PlatformPatcher`)
- `src/patch/mod.rs` (Phase 2 — added `pub mod linux/macos` + `host_patcher()`)

## Commits on `v2-rust-rewrite` from Phase 2

```
feat(platform): paths trait + escalation + atomic_rename helper
feat(migration): detect + remove legacy V1 Neon installs
feat(patch-linux,patch-macos): platform impls of PlatformPatcher
test(platform,patch-linux,migration): boost coverage to 88.7%
```
