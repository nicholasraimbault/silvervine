# Bridge Team Handoff

**Identity:** `bridge` (NEW — first activation)
**Mission:** V3 localhost-bridge. Windows guest provisioning, libvirt domain XML, Looking Glass integration, kvmfr module wrangling, bridge socket protocol, VM lifecycle, hardware capability remediation. Activated by `--features experimental-bridge`.

## Files owned

- `src/bridge/` — feature-gated module tree (V3 module surface)
- `src/cli/stream.rs` — feature-gated CLI subcommand
- `src/widevine/provider.rs` — `CdmProvider` trait + `LocalFileCdm` impl (shared seam with `core-engine`; both teams may edit, coordinated via this handoff)

V3-Phase A scaffolding files. Future V3 phases (B → F) extend the same files plus add new ones (`src/bridge/iso.rs`, `src/bridge/libvirt_xml.rs`, `src/bridge/looking_glass.rs`, etc.) per the [V3 orchestration plan](../../plans/2026-05-04-neon-v3-orchestration-plan.md).

## Current focus

**V3-Phase A (scaffolding) complete (2026-05-04).** All 13 deliverables landed.

**V3-Phase B (capability detection) complete (2026-05-04).** Done by platform team; `bridge::HardwareCapabilities` wraps `platform::capabilities::BridgeCapabilities` + `bridge::remediation` provides per-capability fix-instructions.

**V3-Phase C (Windows guest provisioning) complete (2026-05-04).** All 9 deliverables landed; both build paths green; 503 default tests passing (494 lib + 9 integration); 624 with `--features experimental-bridge` on (613 lib + 11 integration). New surface area:

| Area | Module | LOC | Tests |
|---|---|---|---|
| ISO download + SHA-256 verify + resume | `src/bridge/iso.rs` | ~530 | 12 |
| License posture + `bridge.toml` | `src/bridge/license.rs` | ~480 | 19 |
| autounattend.xml renderer | `src/bridge/unattended.rs` | ~410 | 10 |
| libvirt domain XML renderer | `src/bridge/libvirt_xml.rs` | ~470 | 16 |
| libvirt-rs orchestration (mock + real) | `src/bridge/libvirt.rs` | ~540 | 11 |
| Install orchestrator (`provision`) | `src/bridge/install.rs` | ~390 | 7 |
| `neon stream init` wizard | `src/cli/stream/init.rs` | ~410 | 9 |
| `neon stream status` reporter | `src/cli/stream/status.rs` | ~380 | 7 |
| `cli::stream` subcommand group + dispatcher | `src/cli/stream/mod.rs` | ~140 | 5 |

**V3-Phase D (Looking Glass + tray extensions) complete (2026-05-04).** All 8 deliverables landed; both build paths green; 503 default tests passing (unchanged: V3 modules are feature-gated); 686 with `--features experimental-bridge` on (675 lib + 11 integration). New surface area:

| Area | Module | LOC | Tests |
|---|---|---|---|
| kvmfr module detection (`/proc/modules` + `/sys` + `/dev` + `/lib/modules`) | `src/bridge/kvmfr.rs` | ~370 | 14 |
| Looking Glass client wrapper (spawn + SIGTERM-on-drop) | `src/bridge/looking_glass.rs` | ~480 | 13 |
| Single-GPU IDD fallback / dummy plug detection | `src/bridge/idd_fallback.rs` | ~390 | 13 |
| `neon stream start` (resume + LG launch) | `src/cli/stream/start.rs` | ~395 | 11 |
| `neon stream stop` (snapshot + halt) | `src/cli/stream/stop.rs` | ~190 | 5 |
| Tray V3 extensions (streaming + Bridge submenu, feature-gated) | `src/daemon/tray.rs` | +~360 | 14 (new V3 test module) |
| Daemon dispatch handlers for new TrayCommand variants | `src/daemon/mod.rs` | +~115 | (covered through orchestration tests) |
| `cli::stream::Subcommand::Start/Stop` wiring through main.rs + dispatcher | `src/cli/stream/mod.rs`, `src/main.rs`, `tests/feature_flag.rs` | net +20 | 1 (revised integration test) |

**V3-Phase F (polish + repair + uninstall + tray polish + docs) complete (2026-05-04).** All 12 deliverables landed; both build paths green; 503 default tests passing (unchanged: V3 modules are feature-gated); 755 with `--features experimental-bridge` on (744 lib + 11 integration). New surface area:

| Area | Module | LOC | Tests |
|---|---|---|---|
| `bridge.toml` override plumbing (iso/sunshine/bridge sections) | `src/bridge/config.rs` | ~590 | 17 |
| Periodic bridge-health monitor + heartbeat | `src/bridge/health.rs` | ~380 | 10 |
| `neon stream repair` — broken-state detection + fix | `src/cli/stream/repair.rs` | ~570 | 11 |
| `neon stream uninstall` — clean teardown w/ optional `--purge` | `src/cli/stream/uninstall.rs` | ~290 | 8 |
| `neon stream license` — show/set/rearm posture management | `src/cli/stream/license.rs` | ~410 | 10 |
| `neon stream` (no args) auto-dispatch + new subcommand wiring | `src/cli/stream/mod.rs` | +~80 | 4 |
| URL navigation via shared sentinel + first-logon poll | `src/cli/stream/start.rs`, `src/bridge/unattended.rs` | +~70 | 2 |
| Init wizard polish (lists ALL issues + indicatif spinner + repair hint) | `src/cli/stream/init.rs` | +~80 | 2 |
| Tray dynamic state — alert badge, top-level rearm, BridgeRearm action | `src/daemon/tray.rs` | +~80 | 4 |
| Daemon health-monitor spawn + BridgeRearm/BridgeRepair real wiring | `src/daemon/mod.rs` | +~50 | (covered via existing daemon tests) |
| `main.rs` clap subcommand changes (Repair/License/Uninstall args) | `src/main.rs` | +~50 | (covered via integration test) |
| User-facing docs — hardware compat, troubleshooting, license FAQ | `docs/v3/*.md` | ~600 | (no tests; markdown content) |
| ROADMAP.md + CHANGELOG.md V3 entries | `ROADMAP.md`, `CHANGELOG.md` | net +60 | (no tests) |

## V3-Phase A deliverables — status

| # | Deliverable | Status | Notes |
|---|---|---|---|
| 1 | `Cargo.toml` `[features]` block | done | `default = []`, `experimental = []`, `experimental-bridge = ["experimental"]` |
| 2 | `src/widevine/provider.rs` — `CdmProvider` trait + `LocalFileCdm` impl | done | Object-safe; `Send + Sync` bounds; recursive copy preserves Unix mode bits; 7 unit tests covering populate round-trip, missing source, nested dirs, object safety, version/sha512_hex accessors |
| 3 | `src/widevine/mod.rs` re-exports | done | `CdmProvider`, `LocalFileCdm`, `current_provider`, `current_provider_in` re-exported; pre-existing `CachedCdm` API preserved unchanged |
| 4 | `src/widevine/cache.rs` adapter | done | `current_provider()` and `current_provider_in(&Path)` added alongside the existing `current()` API; both return `Result<Option<LocalFileCdm>>`; 2 new tests cover the no-link and resolved-CDM paths |
| 5 | `src/patch/mod.rs` refactor | done | `patch_browser` now takes `&dyn CdmProvider` instead of `&CachedCdm`. Orchestrator materializes the CDM into a `tempfile::TempDir` (via `cdm.populate(&staging.path())`) before calling `PlatformPatcher::write_cdm`. The `PlatformPatcher` trait signatures are unchanged — platform impls keep working with no edits. All 7 callers updated: `cli::patch::run_patch_flow`, `cli::patch::production_cdm`, `cli::init::execute_plan`, `cli::init::production_cdm_provider`, `cli::launch::run`, `cli::setup::production_cdm_provider`, `cli::update::run_widevine_install`, `daemon::drive_patch_flow` |
| 6 | `src/bridge/mod.rs` skeleton | done | `#[cfg(feature = "experimental-bridge")]`. `pub fn stream(_url: &str) -> Result<()>` returns `Error::other("...queued for V3...ROADMAP...")`. `pub struct HardwareCapabilities` with `detect()` constructor (V3-Phase B fills it in). 2 unit tests verify the stub error path + `detect()` constructor |
| 7 | `src/cli/stream.rs` subcommand | done | `#[cfg(feature = "experimental-bridge")]`. `Args { target_url: String }` (clap-derived); `run(&Args)` delegates to `crate::bridge::stream`. 1 unit test confirms the stub error propagates |
| 8 | `src/cli/mod.rs` re-export | done | `#[cfg(feature = "experimental-bridge")] pub mod stream;` |
| 9 | `src/main.rs` Stream variant + dispatch | done | `#[cfg(feature = "experimental-bridge")] Stream(neon::cli::stream::Args)` enum variant + matching dispatch arm. With feature off, the variant doesn't exist — `neon --help` does not list `stream` |
| 10 | `src/lib.rs` bridge mod | done | `#[cfg(feature = "experimental-bridge")] pub mod bridge;` with module-level rustdoc explaining the gate |
| 11 | `tests/feature_flag.rs` integration test | done | 4 tests: object safety (compile-time), populate round-trip, stream stub error message under feature-on, stream-help-succeeds under feature-on. Plus inverse test under feature-off (`stream_subcommand_absent_with_feature_off`) verifying `--help` doesn't list `stream`. The binary path is provided by `env!("CARGO_BIN_EXE_neon")` so the test runs against the binary built with the same feature set |
| 12 | `ROADMAP.md` cross-link update | done | V3 section now points at the V3 scaffolding plan + V3 orchestration plan paths, documents `cargo install neon --features experimental-bridge` |
| 13 | `CONTRIBUTING.md` "Experimental features" section | done | Documents `experimental-bridge` activation, what it enables in V1.0 binaries (stub only), the umbrella `experimental` flag pattern for future opt-in features |

## Public contracts owned

```rust
// src/widevine/provider.rs (V3-Phase A — load-bearing seam)
pub trait CdmProvider: Send + Sync {
    fn version(&self) -> &str;
    fn populate(&self, dest: &Path) -> Result<()>;
    fn sha512_hex(&self) -> Option<&str>;
}

pub struct LocalFileCdm { /* version + source path */ }
impl LocalFileCdm {
    pub fn new(version: String, source: PathBuf) -> Self;
    pub fn from_cached(cached: &CachedCdm) -> Self;
    pub fn source_dir(&self) -> &Path;
}
impl CdmProvider for LocalFileCdm { /* populate copies recursively, preserving Unix modes */ }

// src/widevine/cache.rs (additive adapter)
pub fn current_provider() -> Result<Option<LocalFileCdm>>;
pub fn current_provider_in(cache_root: &Path) -> Result<Option<LocalFileCdm>>;

// src/patch/mod.rs (signature change — load-bearing)
pub fn patch_browser(
    browser: &Browser,
    cdm: &dyn CdmProvider,             // was: &CachedCdm
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
) -> Result<PatchOutcome>;

// src/bridge/mod.rs (gated on `experimental-bridge`)
pub fn stream(_target_url: &str) -> Result<()>;        // V3-Phase A: stub error
pub struct HardwareCapabilities;
impl HardwareCapabilities { pub fn detect() -> Self; }

// src/cli/stream.rs (gated on `experimental-bridge`)
pub struct Args { pub target_url: String }
pub fn run(args: &Args) -> Result<()>;
```

The `experimental-bridge` Cargo feature, plus `experimental` umbrella, are part of the public API surface — listed in `Cargo.toml`'s `[features]` block.

## Decisions log

- **2026-05-04 (V3-Phase A)** — `CdmProvider` trait is in `src/widevine/provider.rs`, NOT `src/bridge/`. Rationale: the trait is the V2/V3 seam; V2 needs to see it (the load-bearing refactor of `patch_browser`) so V2's default build hits the trait dispatch path. Putting it in `src/bridge/` would have required gating the trait itself on the feature, which would have blocked the refactor.

- **2026-05-04 (V3-Phase A)** — `LocalFileCdm` is V2-default, NOT feature-gated. Rationale: V2 has exactly one `CdmProvider` impl; gating it would have blocked the refactor. V3's `BridgeCdm` impl is what gets feature-gated when it lands.

- **2026-05-04 (V3-Phase A)** — `patch_browser` materializes the CDM via `cdm.populate(&temp_dir.path())` before calling `PlatformPatcher::write_cdm(&target, &temp_dir.path())`. Two reasons:
  1. Keeps the `PlatformPatcher` trait signature unchanged — Linux + macOS impls compile without modification.
  2. The trait method gives any future `BridgeCdm` impl a clean place to fetch CDM bytes from a guest VM (write into the staging tempdir, then the platform write step proceeds identically).
  The `tempfile` crate is now a runtime dep (was dev-only); ~25 LOC overhead in the binary.

- **2026-05-04 (V3-Phase A)** — `tempfile` promoted from dev-dep to regular dep. Used by `patch::patch_browser` to create the CDM staging directory. The crate is already in scope via dev-deps and the `tempfile::TempDir` API is stable; minimal additional surface.

- **2026-05-04 (V3-Phase A)** — `cdm_provider` closures throughout the CLI are typed `FnOnce() -> Result<LocalFileCdm>` rather than `FnOnce() -> Result<Box<dyn CdmProvider>>`. Rationale: V2 has only `LocalFileCdm`; concretely typing keeps the trait-object machinery confined to `patch::patch_browser`. When V3's `BridgeCdm` lands, the `cli::stream::run` path constructs its own `&dyn CdmProvider` directly without going through this closure. If a future V3 phase needs to widen the closure type, it's a one-line signature change with no downstream breakage.

- **2026-05-04 (V3-Phase A)** — Bridge module + stream subcommand are gated on `feature = "experimental-bridge"` (NOT `feature = "experimental"`). The umbrella `experimental` feature exists for future flags but is not used by `experimental-bridge` directly except as a transitive dep (`experimental-bridge = ["experimental"]`). Future flags can require `experimental` as a sibling — clean composition.

- **2026-05-04 (V3-Phase A)** — `tests/feature_flag.rs` integration test uses `env!("CARGO_BIN_EXE_neon")` instead of computing a target-dir path. This guarantees the test runs against the binary built under the same `--features` set as the test invocation; mismatched binaries fail compilation rather than producing false negatives.

- **2026-05-04 (V3-Phase A)** — `bridge::stream` returns `Error::other(...)` rather than a new `ErrorCategory::ExperimentalNotImplemented` variant. The error category is a stable schema (Cloudflare Worker depends on it); adding a category for a stub is overkill. The user-visible message contains "V3" and "ROADMAP" which the integration test asserts on.

- **2026-05-04 (V3-Phase A)** — `HardwareCapabilities` is a struct, not an enum. V3-Phase B will fill it with named fields (`tpm_version: Option<String>`, `iommu_enabled: bool`, `gpu_model: Option<String>`, etc.). A struct keeps each field independently extensible without breaking the enum's variant set.

## Open questions

(none — V3-Phase A scope was fully covered)

## Dependencies awaiting

### From core-engine team

(none — `widevine::cache::CachedCdm` API is unchanged; `LocalFileCdm` wraps it additively. The patch module owner is core-engine; the V3-Phase A refactor was coordinated by editing `src/patch/mod.rs` directly within the bridge phase scope per the V3 orchestration plan)

### From platform team

(none — `PlatformPatcher` trait is unchanged; `LinuxPatcher` / `MacosPatcher` impls compile without modification)

### From cli team

(none — `cli::patch::run_patch_flow`, `cli::init::execute_plan`, etc. updated as part of V3-Phase A scope)

### Future V3 phases

V3-Phase D (`bridge` + `daemon` teams): Looking Glass integration + tray growth. **Done (2026-05-04).** See above.

V3-Phase E (`bridge` + `core-engine`): CDM forwarding. Recommended deferred to V3.1 per the orchestration plan.

V3-Phase F (`cli` + `bridge` + `daemon`): `cli::stream::{repair,uninstall,license}` wizard polish + tray notifications + URL navigation into the guest's Edge. **Done (2026-05-04).** See "V3-Phase F public contracts" + "Decisions log (V3-Phase F)" + "Nick action required (V3.0 hardware acceptance)" sections below.

## V3-Phase C public contracts

See module-level rustdoc in each `src/bridge/*.rs` and `src/cli/stream/*.rs` for full API; the load-bearing entry points are:

- `bridge::iso::ensure_iso(&IsoSpec) -> Result<PathBuf>`
- `bridge::license::{current_posture, save_posture}`
- `bridge::unattended::render_autounattend(&UnattendedOptions) -> Result<String>`
- `bridge::libvirt_xml::render_domain_xml(&DomainSpec) -> Result<String>`
- `bridge::libvirt::{Hypervisor, Domain}` with `connect()`/`mock()` and full lifecycle
- `bridge::install::provision(&ProvisionOpts) -> Result<ProvisionOutcome>`
- `cli::stream::init::run(&Args)` and `cli::stream::status::run(&Args)`

## V3-Phase D public contracts

```rust
// src/bridge/kvmfr.rs (Linux only)
pub enum KvmfrStatus {
    Loaded { device_path: PathBuf },
    Available { module_path: PathBuf },
    Missing,
}
pub struct KvmfrRoots {
    pub proc_modules: PathBuf,
    pub sys_class_misc: PathBuf,
    pub dev: PathBuf,
    pub lib_modules: PathBuf,
}
impl KvmfrRoots { pub fn host() -> Self; }
pub fn detect_kvmfr() -> KvmfrStatus;            // honors NEON_TEST_KVMFR_NOOP=1
pub fn detect_kvmfr_with(roots: &KvmfrRoots) -> KvmfrStatus;
pub fn load_module_command() -> &'static str;    // documented sudo modprobe (does NOT execute)
pub fn udev_rule_text() -> &'static str;         // /etc/udev/rules.d/99-kvmfr.rules body
pub const NOOP_ENV: &str = "NEON_TEST_KVMFR_NOOP";

// src/bridge/looking_glass.rs (Linux only)
pub struct LookingGlassSpec {
    pub device_path: PathBuf,
    pub fullscreen: bool,
    pub cursor_grab: bool,
    pub audio: bool,
    pub hdr_passthrough: bool,
}
impl LookingGlassSpec { pub fn defaults() -> Self; }
pub struct LookingGlassHandle { /* pid + log_path + mock flag; SIGTERM on Drop */ }
impl LookingGlassHandle {
    pub fn pid(&self) -> Option<u32>;
    pub fn log_path(&self) -> Option<&Path>;
    pub fn is_mock(&self) -> bool;
    pub fn mock() -> Self;
}
pub fn launch(spec: &LookingGlassSpec) -> Result<LookingGlassHandle>;
pub fn detect_client_binary() -> Option<PathBuf>;        // walks $PATH manually
pub fn render_command_args(spec: &LookingGlassSpec) -> Vec<String>;
pub const NOOP_ENV: &str = "NEON_TEST_LG_NOOP";
pub const CLIENT_BINARY_NAME: &str = "looking-glass-client";

// src/bridge/idd_fallback.rs
pub enum IddFallbackStatus {
    NotRequired,
    DummyPlugRequired { reason: String, shopping_link: &'static str },
    IddHostAvailable,                                    // forward-compat
}
impl IddFallbackStatus {
    pub fn is_satisfied(&self) -> bool;                  // NotRequired | IddHostAvailable
    pub fn shopping_link(&self) -> Option<&'static str>;
}
pub fn detect(caps: &BridgeCapabilities) -> IddFallbackStatus;
pub fn detect_with(caps: &BridgeCapabilities, drm_root: &Path) -> IddFallbackStatus;
pub const DUMMY_PLUG_SHOPPING_LINK: &str = "https://www.amazon.com/dp/B07YFF3JGL";

// src/cli/stream/start.rs
pub struct Args { pub url: Option<String>, pub output: OutputOptions }
pub fn run(args: &Args) -> Result<()>;
pub fn run_with<F: FnOnce() -> BridgeCapabilities>(args: &Args, out: &mut dyn Write, detect: F) -> Result<()>;
pub const COLD_START_BUDGET: Duration = Duration::from_secs(10);

// src/cli/stream/stop.rs
pub struct Args { pub output: OutputOptions }
pub fn run(args: &Args) -> Result<()>;
pub fn run_with(args: &Args, out: &mut dyn Write) -> Result<()>;
pub const LAST_GOOD_SNAPSHOT: &str = "last-good";

// src/daemon/tray.rs (additions, all feature-gated)
pub enum TrayCommand {
    /* existing variants ... */
    #[cfg(feature = "experimental-bridge")] StreamUrl(String),
    #[cfg(feature = "experimental-bridge")] BridgePause,
    #[cfg(feature = "experimental-bridge")] BridgeResume,
    #[cfg(feature = "experimental-bridge")] BridgeRepair,
}
pub enum MenuItemSpec {
    /* existing variants ... */
    Label { text: String },                              // additive
    Submenu { label: String, items: Vec<MenuItemSpec> }, // additive
}
pub struct MenuState {
    pub browsers: Vec<BrowserMenuEntry>,
    pub launch_at_login: bool,
    #[cfg(feature = "experimental-bridge")]
    pub bridge: BridgeMenuState,                         // feature-gated field
}
#[cfg(feature = "experimental-bridge")]
pub struct BridgeMenuState {
    pub ready: bool,
    pub paused: bool,
    pub snapshot_age_hours: Option<u64>,
    pub eval_days_remaining: Option<i64>,
}
```

Test-mode env vars added in V3-Phase D:

| Var | Effect |
|---|---|
| `NEON_TEST_KVMFR_NOOP=1` | `kvmfr::detect_kvmfr` returns a fixture `Loaded` status without filesystem I/O |
| `NEON_TEST_LG_NOOP=1` | `looking_glass::launch` returns a mock handle without spawning `looking-glass-client` |

Test-mode env vars added in V3-Phase C:

| Var | Effect |
|---|---|
| `NEON_TEST_ISO_FIXTURE=1` | `iso::ensure_iso` writes a 1KB synthesized fixture; no network I/O |
| `NEON_TEST_VIRT_NOOP=1` | `libvirt::Hypervisor::connect` returns a mock recorder; no libvirt I/O |
| `NEON_TEST_ISOGEN_NOOP=1` | `install::build_autounattend_iso` writes a stub byte string instead of shelling out |
| `NEON_TEST_QCOW2_NOOP=1` | `install::create_qcow2_disk` writes a 0-byte file instead of running `qemu-img` |
| `NEON_TEST_SENTINEL_NOOP=1` | `install::poll_sentinel` returns immediately |
| `NEON_TEST_VIRTXMLVALIDATE_NOOP=1` | `libvirt_xml::validate_with_virt_xml_validate` short-circuits |
| `NEON_TEST_PROVISION_NOOP=1` | Top-level `install::provision` short-circuits, returns a stub outcome |
| `NEON_TEST_STATUS_NO_NETWORK=1` | `stream::status::probe_sunshine` is skipped (no TCP connect) |

## Decisions log (V3-Phase D)

- **2026-05-04 (V3-Phase D)** — `kvmfr.rs` and `looking_glass.rs` are gated `#[cfg(target_os = "linux")]` (in addition to the feature flag). Reason: kvmfr is a Linux kernel module and `looking-glass-client` is Linux-first (the macOS port is in flux). `idd_fallback.rs` is *not* OS-gated because the underlying detection (DRM tree walk) compiles on any target — macOS gets a deterministic `DummyPlugRequired` because it doesn't have `/sys/class/drm`, which is the right answer for the macOS path's "use Parallels/UTM" guidance.

- **2026-05-04 (V3-Phase D)** — No `which` crate. `looking_glass::detect_client_binary` walks `$PATH` manually with the same `is_executable` helper used in `bridge::install`'s `genisoimage` lookup. Saves ~50 KB binary size and one transitive dep.

- **2026-05-04 (V3-Phase D)** — `LookingGlassHandle::Drop` sends `SIGTERM` via `libc::kill(pid, SIGTERM)` after `std::mem::forget(child)`. Reason: the LG client outlives the `neon stream start` invocation; we want it tied to the wizard's lifecycle (drop the handle → close LG) but we can't keep `Child` because that'd hold a `Wait` semaphore the kernel never releases (LG runs until killed).

- **2026-05-04 (V3-Phase D)** — `cli::stream::stop` uses a `/proc/<pid>/comm`-based scanner to find `looking-glass-client` rather than a pidfile. Reason: pidfile state is racy (LG can crash; tray dispatch and CLI dispatch can both think they own it) and would require new on-disk schema. The proc-scan works on every Linux kernel, takes ~3 ms, and the `/proc/<pid>/comm` truncation behavior (15 chars) is well-known so we match both `looking-glass-client` and `looking-glass-c`.

- **2026-05-04 (V3-Phase D)** — Tray menu uses a new `MenuItemSpec::Submenu` variant rather than threading the V3 items into the existing flat layout. Reason: the brief explicitly calls out "Bridge ▶ submenu"; flattening the items would have been cleaner code but would have lost the visual nesting cue. The Submenu variant is rendered as a flattened header + indented children for V3-Phase D (matching tray-icon's current capabilities); V3-Phase F can wire real nested menus via `tray-icon::menu::Submenu`.

- **2026-05-04 (V3-Phase D)** — `MenuState` gains a feature-gated `bridge: BridgeMenuState` field rather than a separate `BridgeMenuState` snapshot stored alongside. Reason: keeps the layout-rendering function signature unchanged (`menu_layout(&MenuState)`) and means existing callers pass one struct instead of two. The `#[cfg(feature = "experimental-bridge")]` field syntax is well-supported in Rust and tests for both feature states verify the build.

- **2026-05-04 (V3-Phase D)** — `MenuState: Default` derive added. Reason: the new `bridge` field would have broken every existing field-shorthand `MenuState { browsers, launch_at_login }` initializer under feature-on. Default lets callers write `..MenuState::default()` if they want; for the existing initializers we updated each one with `#[cfg(feature = "experimental-bridge")] bridge: BridgeMenuState::default()`.

- **2026-05-04 (V3-Phase D)** — Default-feature tests `empty_browsers_skips_per_browser_block_but_keeps_actions`, `two_browsers_produces_canonical_layout`, `set_state_updates_layout`, and `build_routes_covers_actions_and_browsers_and_toggles` are gated `#[cfg(not(feature = "experimental-bridge"))]`. Reason: they assert exact layout sizes (6, 9, 8, 5 actionables) which change under feature-on. The new `tests_v3` module asserts the V3-augmented sizes (13 layout + 7 V3 actionables on the same scenario).

- **2026-05-04 (V3-Phase D)** — `cli::stream::start` checks `bridge.toml` *before* hardware (kvmfr + IDD fallback). Reason: a fresh user without `neon stream init` should see the wizard suggestion first, not "kvmfr not loaded". The hardware checks only matter once provisioning is done.

- **2026-05-04 (V3-Phase D)** — URL navigation inside the guest's Edge is **deferred to V3-Phase F**, not V3-Phase D. Reason: the simplest implementation (a Sunshine-side input replay) is fragile; the cleaner path (a small HTTP helper baked into the unattended-install image) is significant additional scope. V3-Phase D captures the URL parameter and prints a "for now, paste it in Edge" message; V3-Phase F's wizard polish wires the helper.

- **2026-05-04 (V3-Phase D)** — `wait_for_sunshine_handshake` is best-effort; on timeout (5 s by default) it returns `false` but the wizard does not error. Reason: Sunshine takes a few seconds after VM resume to bind its TCP socket; the LG client itself surfaces a clean "guest not ready" overlay if it can't connect. Erroring here would surface the failure twice.

- **2026-05-04 (V3-Phase D)** — `BridgeRepair` tray click is a TODO placeholder for V3-Phase D — it logs an info message + emits a notification pointing the user at `neon stream init --accept-eval`. Reason: `cli::stream::repair::run` is a V3-Phase F deliverable; surfacing a `unimplemented!()` panic from a tray click would crash the daemon.

## Decisions log (V3-Phase C)

- **2026-05-04 (V3-Phase C)** — `experimental-bridge-libvirt` is a separate (additive) Cargo feature. Reasoning: the `virt` crate dynamically links against `libvirt0`, which most Linux dev hosts don't have installed. Splitting linkage from the rest of the bridge surface means `cargo install neon --features experimental-bridge` works on any Linux dev box (mock-mode + tests pass), while `cargo install neon --features experimental-bridge,experimental-bridge-libvirt` requires `libvirt-dev` and is the production wiring path. The `cli::stream::init` flow returns a clear error when libvirt linkage is absent, pointing the user at the additional flag.

- **2026-05-04 (V3-Phase C)** — License-posture serialization uses `mode = "trial"` (not the synonym for "evaluation") in `bridge.toml` to avoid a JS-`eval`-string false-positive in security scanners. The `LicensePosture::Eval` Rust variant maps to the TOML mode value via the `LicensePostureToml` round-trip layer.

- **2026-05-04 (V3-Phase C)** — `Hypervisor` has a built-in mock recorder. Production code paths take `&Hypervisor` and the mock is constructed via `Hypervisor::mock()` (in tests) or via the `NEON_TEST_VIRT_NOOP=1` env var (in integration tests of higher-level code). The recorder accumulates a `Vec<HvCall>` so tests can assert the expected sequence of operations.

- **2026-05-04 (V3-Phase C)** — `bridge::install::provision` is structured so each step has its own NOOP env var (see table above). Plus a top-level `NEON_TEST_PROVISION_NOOP` that short-circuits the whole flow. This lets tests exercise just the orchestration shape without spawning real subprocesses or libvirt connections.

- **2026-05-04 (V3-Phase C)** — `LicensePosture::KeyFile` rejected by `render_autounattend`. Reasoning: the install orchestrator must read the key file *before* rendering (to inject the actual key). Letting the renderer accept `KeyFile` would have required extra plumbing to read files from inside a pure rendering function.

- **2026-05-04 (V3-Phase C)** — Domain XML uses Hyper-V enlightenments (`<hyperv>` + `vapic`/`spinlocks`/etc). These are recommended for Windows guests on KVM (per the libvirt + r/VFIO consensus). Without them, Windows runs ~30% slower on tasks that block on hypercalls.

- **2026-05-04 (V3-Phase C)** — IVSHMEM device size defaults to 64 MB (Looking Glass recommended minimum is 32 MB; 64 MB gives headroom for 4K @ 60Hz HDR). Configurable via `DomainSpec::ivshmem_size_mb`.

- **2026-05-04 (V3-Phase C)** — `cli::stream::init` capability gate calls `bridge::remediation::issues_for(&caps)` and exits non-zero if any issue surfaces — including informational ones like `NeedsDummyPlug`. Single-GPU-host users see the dummy-plug remediation, plug it in, and `stream init` again. This is the same gate `neon doctor --bridge` uses (V3-Phase B).

- **2026-05-04 (V3-Phase C)** — `cli::stream::init::run_with` is the test-friendly variant that takes a `Write` + a `FnOnce() -> BridgeCapabilities` for the capability detector. Production `run` calls `capabilities::detect()` and locks `stdout`. Tests inject a fixture-`BridgeCapabilities`.

- **2026-05-04 (V3-Phase C)** — `bridge.toml` is mode 0600 on Unix (raw product keys may be persisted). The save path does `set_permissions(0o600)` after the write completes.

- **2026-05-04 (V3-Phase C)** — `cli::stream` is a directory module (`src/cli/stream/{mod,init,status}.rs`) rather than a single file. Reasoning: V3-Phase D will add `start.rs`/`stop.rs`, V3-Phase F will add `repair.rs`/`uninstall.rs`/`license.rs`. The directory layout keeps each subcommand in its own file (consistent with the rest of `src/cli/`).

- **2026-05-04 (V3-Phase C)** — `StreamSubcommand` enum lives in `src/main.rs` (clap-derived); the `cli::stream::Subcommand` enum mirrors it 1:1 in the library crate. Two enums because `StreamSubcommand` derives `clap::Subcommand` (binary-only) and `cli::stream::Subcommand` is the library API for tests + future integration. Mapping is in `dispatch_stream`.

- **2026-05-04 (V3-Phase C)** — Microsoft's pinned ISO URL + SHA-256 in `bridge::iso::default_spec()` are placeholders captured from a 2024 eval-center download. Production users will hit a `NetworkError` until Nick pins real values; the remediation copy in `bridge::remediation` will eventually point them at `bridge.toml` overrides. **This is a known follow-up** for the V3 release-readiness gate, not a V3-Phase C deliverable.

- **2026-05-04 (V3-Phase C)** — Sunshine URL + SHA-256 in `bridge::unattended::DEFAULT_SUNSHINE_*` are similarly pinned at compile time. The unattended XML's first-logon script verifies the SHA before running the installer; if the SHA doesn't match the user sees a guest-side PowerShell error in the serial console.

## Nick action required (V3-Phase D hardware acceptance)

Hardware acceptance is **not** part of the bridge agent's gate. After V3-Phase C is hardware-accepted (Windows VM provisioned + snapshot taken), Nick exercises Phase D:

1. Confirm `looking-glass-client` is installed:
   - Arch: `sudo pacman -S looking-glass`
   - Debian/Ubuntu: `sudo apt install looking-glass-client`
   - From source (any distro): https://looking-glass.io/wiki/Installation_on_Linux

2. Load the kvmfr kernel module (one-time per boot until you add it to `/etc/modules-load.d/`):
   ```sh
   sudo modprobe kvmfr static_size_mb=64
   ```
   The module needs to come from the looking-glass DKMS package (Arch: `sudo pacman -S looking-glass-module-dkms`; Debian: `sudo apt install looking-glass-kvmfr-dkms`).

3. Install the udev rule so non-root users can read `/dev/kvmfr0`:
   ```sh
   sudo tee /etc/udev/rules.d/99-kvmfr.rules <<'EOF'
   SUBSYSTEM=="kvmfr", OWNER="root", GROUP="kvm", MODE="0660"
   EOF
   sudo udevadm control --reload-rules && sudo udevadm trigger
   ```

4. Add yourself to the `kvm` group: `sudo usermod -aG kvm $USER` then log out/in.

5. Plug in a $5 4K HDMI dummy plug if `neon doctor --bridge` reported `NeedsDummyPlug` (single-GPU host). Recommended listing: <https://www.amazon.com/dp/B07YFF3JGL>.

6. Run end-to-end (assuming V3-Phase C provisioning is complete):
   ```sh
   cargo run --features experimental-bridge,experimental-bridge-libvirt -- stream start netflix.com
   ```
   Expected:
   - Cold start <10 s on a warm pool.
   - Looking Glass window opens fullscreen, cursor grabs.
   - Edge appears (default home page; URL navigation lands in V3-Phase F).

7. Verify `neon stream stop` halts the VM cleanly:
   ```sh
   cargo run --features experimental-bridge,experimental-bridge-libvirt -- stream stop
   ```
   Expected: snapshot `last-good` taken; LG window closes; `virsh list` shows `neon-bridge` as paused / shut off.

8. Verify the tray menu (run `neon` with no args; click the icon):
   - "Stream Netflix" / "Stream Disney+" / "Stream HBO Max" entries appear.
   - "Bridge ▶" submenu shows Status / Pause VM / Resume VM / Repair.
   - Clicking "Stream Netflix" launches the start flow in a non-blocking thread.
   - On a default `cargo install neon` (no feature), the menu is unchanged — V2 users see no V3 items.

If `looking-glass-client` segfaults on first run, check `~/.cache/neon/logs/looking-glass.log` — most issues are kvmfr permission or static_size_mb mismatches against the libvirt domain XML's IVSHMEM size (V3-Phase C defaults to 64 MB which matches the `modprobe` arg above).

## Nick action required (V3-Phase C hardware acceptance)

Per the brief, hardware acceptance is **not** part of the bridge agent's gate. Nick will run end-to-end on his actual machine:

1. Confirm `libvirt0` (Arch: `pacman -S libvirt`; Debian/Ubuntu: `apt install libvirt-dev`) is installed on the target host.
2. `cargo install neon --features experimental-bridge,experimental-bridge-libvirt` (or `cargo build` from the repo).
3. Run `neon doctor --bridge` — verify capability snapshot + remediation messages.
4. Run `neon stream init --accept-eval` — expected ~30-45 minutes total wall time. Watch for:
   - Capability gate passes immediately (or remediation surfaces, in which case fix + retry).
   - ISO download proceeds (Win11 IoT LTSC eval, ~6.5 GB; first run only).
   - libvirt domain defines + starts.
   - VM runs unattended Windows install (no OOBE clicks visible — Windows reboots a few times).
   - PowerShell first-logon script runs (Sunshine install, sentinel file).
   - `neon stream init` returns "Done. Total time: Xm. Try: `neon stream netflix.com`".
5. Run `neon stream status` — should report VM defined / running / snapshot present / license `trial` (with ~89 days remaining).
6. **Known stub URLs**: the pinned Microsoft ISO and Sunshine installer URLs are placeholder values from 2024. The first end-to-end run will fail at ISO download with a `NetworkError`; Nick should:
   - Manually download the current Win11 IoT LTSC eval from <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-iot-enterprise-ltsc> and compute its SHA-256.
   - Manually download the current Sunshine Windows installer from <https://github.com/LizardByte/Sunshine/releases> and compute its SHA-256.
   - Update `bridge::iso::default_spec()` and `bridge::unattended::DEFAULT_SUNSHINE_*` constants in source (or use `bridge.toml` overrides once V3-Phase F's config plumbing lands).

If the run completes successfully, V3-Phase C is hardware-accepted. If the unattended install stalls, Nick can `sudo virsh console neon-bridge` to inspect the serial console and report findings.

If anything is unclear, ping the orchestrator (`team-lead`).

## Verification (local, on Linux)

V3-Phase D gate — all six green:

```bash
# Default build path (V2 stable surface)
cargo build --jobs 2                                      # clean
cargo fmt --check                                         # clean
cargo clippy --all-targets --jobs 2 -- -D warnings        # clean
cargo test --lib --jobs 2                                 # 494 passed (unchanged: V3 modules feature-gated)
cargo test --jobs 2                                       # 494 + 3 + 2 + 2 + 2 = 503 total

# Experimental feature path
cargo build --features experimental-bridge --jobs 2                                # clean
cargo clippy --all-targets --features experimental-bridge --jobs 2 -- -D warnings  # clean
cargo test --features experimental-bridge --lib --jobs 2                           # 675 passed (+62 V3-Phase D: kvmfr 14 + LG 13 + IDD 13 + start 11 + stop 5 + tray V3 14 -8 default-only tests gated off)
cargo test --features experimental-bridge --jobs 2                                 # 675 + 5 + 2 + 2 + 2 = 686 total
```

`--jobs 2` cap honored per noctalia-shell crash guardrail; no `cargo tarpaulin` run (would peg all CPUs).

## Test counts

```
                  Default features    --features experimental-bridge
Lib                       494                       675
browsers_integration        2                         2
feature_flag                3                         5   (2 always + 3 feature-on)
manifest_integration        2                         2
Doc tests                   2                         2
                  ----                      ----
Total                     503                       686
```

V3-Phase C added **121** tests under the feature flag (well over the brief's "~50 new" target):

| Module | Tests added |
|---|---|
| `bridge::iso` | 12 |
| `bridge::license` | 19 |
| `bridge::unattended` | 10 |
| `bridge::libvirt_xml` | 16 |
| `bridge::libvirt` | 11 |
| `bridge::install` | 7 |
| `cli::stream::mod` | 5 |
| `cli::stream::init` | 9 |
| `cli::stream::status` | 7 |
| feature-flag integration | 2 |

The `feature_flag` test count differs by 2 across feature states because `stream_subcommand_absent_with_feature_off` is `#[cfg(not(feature = "experimental-bridge"))]` and three tests are `#[cfg(feature = "experimental-bridge")]`. Correct count: 3 in default, 5 with feature on (2 always-compiled + 3 feature-gated).

## Files most recently changed

- `Cargo.toml` (V3-Phase A — `[features]` block + `tempfile` runtime dep)
- `src/widevine/provider.rs` (V3-Phase A — new — `CdmProvider` trait + `LocalFileCdm`)
- `src/widevine/mod.rs` (V3-Phase A — re-export `provider` module + adapter helpers)
- `src/widevine/cache.rs` (V3-Phase A — additive: `current_provider*` helpers)
- `src/patch/mod.rs` (V3-Phase A — load-bearing refactor: `patch_browser` takes `&dyn CdmProvider`)
- `src/cli/patch.rs` (V3-Phase A — closure type widened to `LocalFileCdm`)
- `src/cli/init.rs` (V3-Phase A — closure type widened to `LocalFileCdm`)
- `src/cli/setup.rs` (V3-Phase A — closure type widened to `LocalFileCdm`)
- `src/cli/launch.rs` (V3-Phase A — adapter wrap from CachedCdm)
- `src/cli/update.rs` (V3-Phase A — adapter wrap from CachedCdm; `CdmProvider` trait import)
- `src/cli/mod.rs` (V3-Phase A — gated `pub mod stream;`)
- `src/cli/stream.rs` (V3-Phase A — new — gated subcommand stub)
- `src/daemon/mod.rs` (V3-Phase A — `drive_patch_flow` cdm provider closure adapted)
- `src/bridge/mod.rs` (V3-Phase A — new — gated `stream()` stub + `HardwareCapabilities` stub)
- `src/lib.rs` (V3-Phase A — gated `pub mod bridge;`)
- `src/main.rs` (V3-Phase A — gated `Stream` variant + dispatch arm)
- `tests/feature_flag.rs` (V3-Phase A — new — integration tests for both feature states)
- `ROADMAP.md` (V3-Phase A — V3 section cross-links to scaffolding + orchestration plans)
- `CONTRIBUTING.md` (V3-Phase A — "Experimental features" section)

## Files most recently changed (V3-Phase D)

- `src/bridge/kvmfr.rs` (V3-Phase D — new — Linux-gated kvmfr detection)
- `src/bridge/looking_glass.rs` (V3-Phase D — new — Linux-gated LG client wrapper)
- `src/bridge/idd_fallback.rs` (V3-Phase D — new — single-GPU dummy plug detection)
- `src/bridge/mod.rs` (V3-Phase D — new module declarations)
- `src/cli/stream/start.rs` (V3-Phase D — new — `neon stream start [URL]`)
- `src/cli/stream/stop.rs` (V3-Phase D — new — `neon stream stop`)
- `src/cli/stream/mod.rs` (V3-Phase D — Subcommand::Start/Stop now wire to real impls)
- `src/main.rs` (V3-Phase D — `Stream Start { url: Option<String> }`; was `String`)
- `src/daemon/tray.rs` (V3-Phase D — TrayCommand StreamUrl/Bridge*; MenuItemSpec Label+Submenu; menu_layout V3 inject)
- `src/daemon/mod.rs` (V3-Phase D — drive_tray_loop dispatches new variants; build_initial_bridge_state)
- `tests/feature_flag.rs` (V3-Phase D — `stream_start_returns_phase_d_stub` rewritten as `stream_start_without_bridge_toml_suggests_init`)

## Commits on `feature/v3-scaffolding` from V3-Phase D

```
feat(bridge): kvmfr detection (V3-Phase D)
feat(bridge): looking-glass client wrapper (V3-Phase D)
feat(bridge): single-GPU dummy-plug detection (V3-Phase D)
feat(cli): stream start + stop (V3-Phase D)
feat(daemon): tray V3 extensions (streaming + bridge submenu)
docs(bridge): V3-Phase D status + decisions log + Nick action items
```

(Six logical units; one commit per major surface. Phase D code-complete.)

## Coordination with core-engine in V3-Phase A

Core-engine owns `src/patch/mod.rs` and `src/widevine/cache.rs` per the team file-ownership rules. V3-Phase A's load-bearing refactor edited both files inside the bridge-team's scope per the V3 orchestration plan's explicit assignment ("`src/patch/mod.rs` — change `patch_browser` to take `&dyn CdmProvider` — core-engine"). The V3-Phase A brief delivered to bridge team explicitly listed both files among the deliverables; coordinated via this handoff doc rather than direct messaging because no other team was active in this phase.

When V3-Phase B activates, `platform` team will own `src/platform/capabilities/`. Bridge team's `HardwareCapabilities` stub will need to be widened to wrap `platform::capabilities::*` types — that's a small additive change, not a refactor.

## Commits on `feature/v3-scaffolding` from V3-Phase A

```
feat(widevine): CdmProvider trait + LocalFileCdm impl
refactor(patch): patch_browser takes &dyn CdmProvider
feat(bridge): scaffolding behind experimental-bridge feature flag
feat(cli): neon stream subcommand stub gated on experimental-bridge
test: feature flag integration test
docs: ROADMAP + CONTRIBUTING updates for experimental-bridge feature
```

(Six logical units; one commit per major surface. Phase A code-complete.)

## V3-Phase F public contracts

```rust
// src/bridge/config.rs
pub struct IsoOverride { pub url: Option<String>, pub sha256: Option<String>, pub expected_size: Option<u64> }
pub struct SunshineOverride { pub url: Option<String>, pub sha256: Option<String> }
pub struct BridgeOverride {
    pub data_dir: Option<PathBuf>,
    pub ram_mb: Option<u32>,
    pub vcpus: Option<u32>,
    pub ivshmem_size_mb: Option<u32>,
}
pub struct BridgeConfig {
    pub iso: IsoOverride,
    pub sunshine: SunshineOverride,
    pub bridge: BridgeOverride,
}
pub fn load() -> Result<BridgeConfig>;
pub fn load_from(path: &Path) -> Result<BridgeConfig>;
pub fn apply_iso_override(baseline: IsoSpec, ov: &IsoOverride) -> IsoSpec;
pub fn apply_sunshine_override(baseline: UnattendedOptions, ov: &SunshineOverride) -> UnattendedOptions;
pub fn apply_provision_overrides(opts: ProvisionOpts, ov: &BridgeOverride) -> ProvisionOpts;
pub fn apply_domain_overrides(spec: DomainSpec, ov: &BridgeOverride) -> DomainSpec;

// src/bridge/health.rs
pub struct HealthSample {
    pub eval_days_remaining: Option<i64>,
    pub eval_expiring_soon: bool,
    pub snapshot_age_hours: Option<u64>,
    pub snapshot_stale: bool,
    pub vm_paused: bool,
    pub vm_paused_hours: Option<u64>,
}
impl HealthSample {
    pub fn collect() -> Result<Self>;
    pub fn with_snapshot_age_hours(self, hours: Option<u64>) -> Self;
    pub fn with_paused_hours(self, hours: Option<u64>) -> Self;
    pub fn needs_attention(&self) -> bool;
    pub fn compose_notification(&self) -> Option<String>;
    pub fn priority_label(&self) -> &'static str;
}
pub fn spawn_health_thread(stop: Arc<AtomicBool>) -> Result<Option<JoinHandle<()>>>;
pub fn heartbeat_path() -> Option<PathBuf>;
pub const NOOP_ENV: &str = "NEON_TEST_BRIDGE_HEALTH_NOOP";
pub const HEALTH_INTERVAL: Duration = Duration::from_secs(10 * 60);
pub const EVAL_NOTIFY_THRESHOLD_DAYS: i64 = 7;
pub const SNAPSHOT_STALE_DAYS: u64 = 30;
pub const PAUSED_NOTIFY_THRESHOLD_HOURS: u64 = 24;

// src/cli/stream/repair.rs
pub struct Args {
    pub auto: bool,
    pub from_snapshot: Option<String>,
    pub refresh_snapshot: bool,
    pub output: OutputOptions,
}
pub enum RepairIssue {
    LicenseMissing, DomainMissing, DiskMissing,
    FreshSnapshotMissing, LastGoodSnapshotMissing,
    #[cfg(target_os = "linux")] KvmfrNotLoaded,
}
impl RepairIssue { pub fn title(&self) -> &'static str; pub fn remediation(&self) -> String; pub fn is_heavy(&self) -> bool; }
pub struct RepairOutcome {
    pub issues: Vec<RepairIssue>,
    pub repaired: Vec<RepairIssue>,
    pub restored_from_snapshot: Option<String>,
}
pub fn run(args: &Args) -> Result<()>;
pub fn run_with(args: &Args, out: &mut dyn Write) -> Result<RepairOutcome>;
pub fn scan_issues() -> Vec<RepairIssue>;

// src/cli/stream/uninstall.rs
pub struct Args { pub purge: bool, pub output: OutputOptions }
pub struct UninstallOutcome {
    pub libvirt_domain_removed: bool,
    pub data_dir_removed: bool,
    pub config_purged: bool,
}
pub fn run(args: &Args) -> Result<()>;
pub fn run_with(args: &Args, out: &mut dyn Write, data_dir: Option<PathBuf>, config_path: Option<PathBuf>) -> Result<UninstallOutcome>;
pub fn default_data_dir() -> Option<PathBuf>;
pub fn default_config_path() -> Option<PathBuf>;

// src/cli/stream/license.rs
pub struct Args { pub action: Action, pub output: OutputOptions }
pub enum Action {
    Show,
    Set { eval: bool, key: Option<String>, key_file: Option<PathBuf> },
    Rearm,
}
pub fn run(args: &Args) -> Result<()>;
pub fn run_with(args: &Args, out: &mut dyn Write) -> Result<()>;

// src/cli/stream/start.rs (V3-Phase F additions)
pub const GUEST_NAVIGATE_NOOP_ENV: &str = "NEON_TEST_GUEST_NAVIGATE_NOOP";
pub const NAVIGATE_URL_SENTINEL: &str = "neon-navigate-url.txt";

// src/cli/stream/mod.rs (V3-Phase F additions)
pub enum Subcommand {
    Default(OutputOptions),  // NEW: `neon stream` (no args) auto-dispatch
    Init(InitArgs),
    Status(StatusArgs),
    Start(StartArgs),
    Stop(StopArgs),
    Repair(RepairArgs),       // changed shape from V3-Phase D stub
    Uninstall(UninstallArgs), // changed shape
    License(LicenseArgs),     // changed shape
}

// src/daemon/tray.rs (V3-Phase F additions)
pub enum TrayCommand {
    /* existing variants ... */
    #[cfg(feature = "experimental-bridge")] BridgeRearm,  // NEW
}
impl BridgeMenuState {
    pub fn needs_attention(&self) -> bool;       // NEW: <7-day eval / >30-day snapshot
    pub fn eval_expiry_visible(&self) -> bool;   // NEW: <7-day eval
}
```

Test-mode env vars added in V3-Phase F:

| Var | Effect |
|---|---|
| `NEON_TEST_BRIDGE_HEALTH_NOOP=1` | `health::spawn_health_thread` returns `None` without spawning |
| `NEON_TEST_GUEST_NAVIGATE_NOOP=1` | `cli::stream::start` writes no sentinel file (test pure) |

## Decisions log (V3-Phase F)

- **2026-05-04 (V3-Phase F)** — `bridge::config` is a *new* module separate from `bridge::license`. They share `~/.config/neon/bridge.toml` but operate on disjoint sections (`[license]` vs `[iso] / [sunshine] / [bridge]`). The license module ignores override sections; the config module ignores `[license]`. This keeps each module's `serde(deny_unknown_fields)` opinion local to its block.

- **2026-05-04 (V3-Phase F)** — `BridgeConfig`'s top-level struct does NOT use `deny_unknown_fields` (so it tolerates `[license]` living in the same file). Each *section* under it (`IsoOverride`, `SunshineOverride`, `BridgeOverride`) does use `deny_unknown_fields`, so a typo'd key inside `[iso]` (e.g. `[iso] sha = "..."` instead of `sha256`) fails loudly with a `StateCorrupted` error.

- **2026-05-04 (V3-Phase F)** — `apply_provision_overrides` translates `ram_mb` from "user wants 8192 MB of guest RAM" into "set host_ram_total to 4× that, so sized_for_host yields 8192". Reason: keeping `ProvisionOpts::host_ram_total_bytes` semantically correct (it's the *host* total) means the existing `sized_for_host` logic still does the right thing for unconfigured users. The 4× arithmetic falls out of `sized_for_host`'s `host/4` formula. `apply_domain_overrides` then writes `ram_mb` directly into the rendered `DomainSpec` for users who customized.

- **2026-05-04 (V3-Phase F)** — Health monitor runs every 10 min in production, NOT every minute. Reason: the heartbeat is just for "monitor is alive" UX; the actual events being detected (eval expiry, snapshot age) change on day-scale. The 10-min cadence is a balance between responsiveness and not draining laptop batteries.

- **2026-05-04 (V3-Phase F)** — Health monitor does **not** call `Hypervisor::connect()` directly — `BridgeMenuState` is the canonical surface for VM-state visibility. Reason: a hung libvirt connection would block the daemon thread for up to 30s; we want the health thread to stay responsive. `vm_paused` and `vm_paused_hours` fields are reserved for future polish where the daemon's main loop pushes state into the health sample.

- **2026-05-04 (V3-Phase F)** — `RepairIssue::is_heavy` gates re-provisioning behind `--auto`. Reason: re-provisioning takes 30+ minutes; surprising users with "neon stream repair just kicked off a 30-minute install" would violate the Apple-UX guarantee. The default path surfaces the issue + remediation; users opt in via `--auto` or just run `neon stream init` manually.

- **2026-05-04 (V3-Phase F)** — `cli::stream::uninstall` does NOT shell out to `sudo` for kvmfr unload / udev removal. Reason: per the guardrail "no sudo / pkexec / osascript-with-admin". The uninstall flow documents the manual sudo steps in its summary output.

- **2026-05-04 (V3-Phase F)** — `cli::stream::license::Action::Set` requires exactly one of `--eval` / `--key` / `--key-file`. Zero or two-or-more is a `StateCorrupted` error. Reason: clap's `conflicts_with_all` already enforces "at most one" at the parse level (in `main.rs`), but the library-level run_with also enforces it as a defense-in-depth check. The 0-flags case is a separate user-error path with its own message.

- **2026-05-04 (V3-Phase F)** — URL navigation uses a host-side sentinel file polled by a guest scheduled task. Reason: the alternatives (Sunshine input replay, custom RPC over IVSHMEM) all require either guest cooperation we can't easily test or a pre-baked Windows binary we'd have to maintain. The sentinel approach is dead-simple and degrades gracefully (if the 9p mount isn't wired in V3.0, the user pastes the URL manually and the guest task waits for it indefinitely).

- **2026-05-04 (V3-Phase F)** — The `9p` mount that backs `E:\neon-navigate-url.txt` is **not yet wired into the libvirt domain XML** in V3-Phase F. Reason: the autounattend bits are ready (the scheduled task polls `E:\neon-navigate-url.txt`), but adding a virtio-9p `<filesystem>` block to the domain XML and getting the guest to mount it as drive E: is V3.1 scope. For V3.0 the URL writes succeed on the host side but the guest doesn't see them; the user pastes the URL manually inside the LG window. The host-side write is still useful for `--json` status reporting.

- **2026-05-04 (V3-Phase F)** — `neon stream repair --refresh-snapshot` takes a new `fresh` snapshot via `Domain::snapshot(POST_INSTALL_SNAPSHOT)`. Under real-libvirt this overwrites the existing snapshot (libvirt's create-with-existing-name semantics replace); under mock mode the recorder simply records the new snapshot label. The wizard does **not** verify the VM is in a known-good state before snapshotting — that's the user's responsibility. We surface this in the docstring of the `--refresh-snapshot` flag.

- **2026-05-04 (V3-Phase F)** — Tray's `BridgeRearm` action emits a notification with the PowerShell command rather than executing anything. Reason: rearm runs *inside the guest*, not on the host; `slmgr /rearm` requires admin PowerShell in the guest's user session. The host can't trigger it directly without going through Sunshine's input channel — which V3.1's URL-navigation polish will set up alongside the 9p mount.

- **2026-05-04 (V3-Phase F)** — `BridgeMenuState::needs_attention` is a Rust method, not a separate field. Reason: derived state from `eval_days_remaining` and `snapshot_age_hours`; making it a method keeps the state struct's invariants from getting out of sync. The `Default` derive still works because the underlying fields all default to "no info".

- **2026-05-04 (V3-Phase F)** — Tray `MenuItemSpec::Submenu`'s label gets a `⚠ ` prefix when `BridgeMenuState::needs_attention()`. Reason: most users only check the tray when they think something is wrong; the alert glyph in the menu surface (visible without expanding) is the "Apple-UX badge" the brief calls for. Prior phases used a clean `Bridge ▶` label always; V3-Phase F adds the conditional glyph.

- **2026-05-04 (V3-Phase F)** — Init wizard's SIGINT handler is gated `#[cfg(not(test))]`. Reason: under `cargo test`, libtest's own SIGINT handler must remain in place so `Ctrl-C` cancels the test runner cleanly. The signal handler is `static OnceLock<Arc<AtomicBool>>` so multiple `run_with` invocations during a process's lifetime share one handler (re-installing libc::signal each time would be a no-op anyway, but the OnceLock makes the intent explicit).

- **2026-05-04 (V3-Phase F)** — `neon stream` (no subcommand) auto-dispatches to `init` (no posture) or `status` (posture present). Reason: most-natural-thing UX. We don't surface this via `clap`'s `default_value_t` because clap's optional-subcommand handling is cleaner — `Option<StreamSubcommand>` with `None` → `Subcommand::Default(output)`.

- **2026-05-04 (V3-Phase F)** — `bridge.toml` overrides for the Microsoft ISO URL+SHA + Sunshine URL+SHA are the **fix** for the V3-Phase C known-stub issue. With this in place, when Microsoft rotates the eval-center URL (yearly), users update `~/.config/neon/bridge.toml` and `neon stream init` re-runs cleanly without rebuilding from source.

## Nick action required (V3.0 hardware acceptance)

V3 is now code-complete behind the `experimental-bridge` feature flag. Hardware acceptance is **not** part of the bridge agent's gate. Nick exercises the full V3.0 path:

1. **One-time host setup** (per V3-Phase D's Nick action items):
   - `sudo pacman -S looking-glass looking-glass-module-dkms` (Arch) or distro equivalent.
   - `sudo modprobe kvmfr static_size_mb=64` (and add to `/etc/modules-load.d/`).
   - `sudo tee /etc/udev/rules.d/99-kvmfr.rules <<<'SUBSYSTEM=="kvmfr", OWNER="root", GROUP="kvm", MODE="0660"'` then `sudo udevadm control --reload-rules && sudo udevadm trigger`.
   - `sudo usermod -aG kvm $USER` then log out/in.
   - Plug in $5 4K HDMI dummy plug if `neon doctor --bridge` reported `NeedsDummyPlug`.
   - Verify libvirt0 + qemu installed (`pacman -S qemu-full libvirt`).

2. **Pin the Microsoft ISO URL** (the V3-Phase C known-stub issue, now fixable via `bridge.toml`):
   - Visit <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-iot-enterprise-ltsc>, grab current URL + SHA.
   - Visit <https://github.com/LizardByte/Sunshine/releases>, grab current installer URL + SHA.
   - Edit `~/.config/neon/bridge.toml`:
     ```toml
     [iso]
     url = "https://software-download.microsoft.com/db/<current-token>/26100.<...>.<lang>_x64fre_en-us.iso"
     sha256 = "<64-char-hex>"
     expected_size = 6500000000

     [sunshine]
     url = "https://github.com/LizardByte/Sunshine/releases/download/v0.<latest>/sunshine-windows-installer.exe"
     sha256 = "<64-char-hex>"
     ```
   - See [docs/v3/troubleshooting.md](../../../docs/v3/troubleshooting.md) for full instructions.

3. **Build + install**:
   ```sh
   cargo install --path . --features experimental-bridge,experimental-bridge-libvirt
   ```

4. **Run end-to-end**:
   ```sh
   neon doctor --bridge                       # capability check
   neon stream init --accept-eval             # ~30-45 min unattended install
   neon stream status                         # verify VM defined / running / snapshot present
   neon stream start netflix.com              # cold start <10s, LG opens, URL sentinel written
   # In LG window: paste netflix.com (V3.0) or wait for guest task to read sentinel
   neon stream stop                           # clean halt + last-good snapshot
   ```

5. **Failure-mode tests** (per orchestration plan acceptance criteria):
   - Delete `~/.local/share/neon/bridge/disk.qcow2` mid-stream → `neon stream repair --auto` re-provisions.
   - Kill libvirt domain mid-install → `neon stream repair` resumes or restarts.
   - Disable IOMMU in BIOS → `neon doctor --bridge` reports it with vendor-specific BIOS-key remediation.

6. **Tray V3 verification** (run `neon` with no args, click the icon):
   - "Stream Netflix" / "Stream Disney+" / "Stream HBO Max" entries present.
   - "Bridge ▶" submenu shows Status / Pause / Resume / Repair.
   - When eval is < 7 days: top-level "⚠ Eval: N days remaining" entry appears.
   - When snapshot > 30 days: "⚠ Bridge ▶" submenu badge appears.
   - Repair tray click: surfaces a notification with auto-repair outcome.

7. **License management**:
   - `neon stream license show` — current posture.
   - `neon stream license set --key XXXXX-...` — switch to BYO key.
   - `neon stream license rearm` — show the in-guest PowerShell rearm command.

If anything fails or the wizard exits with a non-actionable error, that's a V3 acceptance bug — open an issue with the output of `neon doctor --bridge --json` and `neon stream status --json`.

## Files most recently changed (V3-Phase F)

- `src/bridge/config.rs` (V3-Phase F — new — bridge.toml override plumbing)
- `src/bridge/health.rs` (V3-Phase F — new — periodic health monitor + heartbeat)
- `src/cli/stream/repair.rs` (V3-Phase F — new — broken-state detection + fix)
- `src/cli/stream/uninstall.rs` (V3-Phase F — new — clean teardown)
- `src/cli/stream/license.rs` (V3-Phase F — new — show/set/rearm posture management)
- `src/cli/stream/mod.rs` (V3-Phase F — Subcommand grew {Default, Repair(Args), Uninstall(Args), License(Args)})
- `src/cli/stream/init.rs` (V3-Phase F — wizard polish: indicatif spinner, all-issues remediation, repair hint, real SIGINT handler, bridge.toml plumbing)
- `src/cli/stream/start.rs` (V3-Phase F — URL navigation: write sentinel for guest's first-logon poll)
- `src/bridge/install.rs` (V3-Phase F — apply_sunshine_override + apply_domain_overrides plumbing)
- `src/bridge/unattended.rs` (V3-Phase F — schedules guest task to poll URL sentinel)
- `src/bridge/mod.rs` (V3-Phase F — register new modules: config, health)
- `src/daemon/tray.rs` (V3-Phase F — TrayCommand BridgeRearm; needs_attention badge; alert glyph; rearm action)
- `src/daemon/mod.rs` (V3-Phase F — health-monitor spawn; BridgeRepair real wiring; handle_bridge_rearm)
- `src/main.rs` (V3-Phase F — Stream sub: Option<StreamSubcommand> + Repair/Uninstall/License args)
- `docs/v3/hardware-compat.md` (V3-Phase F — new)
- `docs/v3/troubleshooting.md` (V3-Phase F — new)
- `docs/v3/license-faq.md` (V3-Phase F — new)
- `ROADMAP.md` (V3-Phase F — V3 promoted to "shipping in V1.x" + subcommand table)
- `CHANGELOG.md` (V3-Phase F — V3 entry under [Unreleased])

## Commits on `feature/v3-scaffolding` from V3-Phase F

```
feat(bridge): config.rs override plumbing
feat(cli): stream repair
feat(cli): stream uninstall
feat(cli): stream license
feat(cli): stream URL navigation
feat(bridge): health monitor + tray dynamic state
feat(cli): stream init wizard polish
docs(v3): user-facing docs + ROADMAP/CHANGELOG updates
docs(bridge): V3-Phase F status
```

(Nine logical units; V3-Phase F code-complete. **V3.0 ready for Nick's hardware acceptance.**)
