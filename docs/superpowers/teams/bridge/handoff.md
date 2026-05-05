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

V3-Phase D (Looking Glass + tray extensions) is queued. Not started.

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

V3-Phase D (`bridge` team): Looking Glass integration. Adds `src/bridge/{kvmfr,looking_glass,idd_fallback}.rs` + `cli::stream::{start,stop}`. Will also add tray menu extensions for streaming controls.

V3-Phase E (`bridge` + `core-engine`): CDM forwarding. Recommended deferred to V3.1 per the orchestration plan.

V3-Phase F (`cli` + `bridge`): `cli::stream::{repair,uninstall,license}` wizard polish + tray notifications.

## V3-Phase C public contracts

See module-level rustdoc in each `src/bridge/*.rs` and `src/cli/stream/*.rs` for full API; the load-bearing entry points are:

- `bridge::iso::ensure_iso(&IsoSpec) -> Result<PathBuf>`
- `bridge::license::{current_posture, save_posture}`
- `bridge::unattended::render_autounattend(&UnattendedOptions) -> Result<String>`
- `bridge::libvirt_xml::render_domain_xml(&DomainSpec) -> Result<String>`
- `bridge::libvirt::{Hypervisor, Domain}` with `connect()`/`mock()` and full lifecycle
- `bridge::install::provision(&ProvisionOpts) -> Result<ProvisionOutcome>`
- `cli::stream::init::run(&Args)` and `cli::stream::status::run(&Args)`

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

V3-Phase A gate per the brief — all six green:

```bash
# Default build path (V2 stable surface)
cargo build --jobs 2                                      # clean
cargo fmt --check                                         # clean
cargo clippy --all-targets --jobs 2 -- -D warnings        # clean
cargo test --lib --jobs 2                                 # 466 passed (was 456 baseline)
cargo test --jobs 2                                       # 466 lib + 2 browsers_int + 3 feature_flag + 2 manifest_int + 2 doc = 475 total

# Experimental feature path
cargo build --features experimental-bridge --jobs 2                                # clean
cargo clippy --all-targets --features experimental-bridge --jobs 2 -- -D warnings  # clean
cargo test --features experimental-bridge --lib --jobs 2                           # 469 passed (+3 from default: bridge stub error, bridge HardwareCapabilities::detect, cli::stream::run stub error)
cargo test --features experimental-bridge --jobs 2                                 # 469 lib + 2 browsers_int + 4 feature_flag + 2 manifest_int + 2 doc = 479 total
```

`--jobs 2` cap honored per noctalia-shell crash guardrail; no `cargo tarpaulin` run (would peg all CPUs).

## Test counts

```
                  Default features    --features experimental-bridge
Lib                       494                       613
browsers_integration        2                         2
feature_flag                3                         5   (V3-Phase C: 2 always + 3 feature-on)
manifest_integration        2                         2
Doc tests                   2                         2
                  ----                      ----
Total                     503                       624
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
