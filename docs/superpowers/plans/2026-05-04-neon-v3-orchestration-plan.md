# Neon V3: Localhost-Bridge Orchestration Plan

**Date:** 2026-05-04
**Spec:** [V3 scaffolding plan](../specs/2026-05-04-neon-v3-localhost-bridge-scaffolding-plan.md)
**Relates to:** [V2 design spec](../specs/2026-05-04-neon-rust-rewrite-design.md), [V2 orchestration plan](./2026-05-04-neon-v2-orchestration-plan.md), [ROADMAP](../../../ROADMAP.md)
**Status:** Draft — awaiting user approval before execution

## North star: "just works like Apple"

Every design decision in this plan is filtered through one question: **does it feel like an Apple product?**

- One command. Not twelve.
- Hardware that doesn't qualify is told *exactly* what it needs to qualify (specific BIOS keys for the user's motherboard model, specific Amazon listing for a $5 dummy HDMI plug if they need one).
- Windows install happens silently in the background — user does not see the OOBE, does not click "Next" 12 times, does not pick a region/keyboard.
- After provisioning, `neon stream netflix.com` opens Netflix in 4K HDR in <5 seconds.
- If state ever goes weird, `neon stream repair` rebuilds from snapshot. If snapshot is gone, full re-provision (~30 min) with one command and zero further user interaction.
- No half-states where user has to debug.

What the user touches:
1. Once: agree they own a Windows license (or accept the eval) by typing `--accept-eval` or providing a key
2. Once: type Netflix/Disney+ password (cookie persists in snapshot afterward)
3. Once: plug in $5 dummy HDMI plug if their hardware can't share GPU between host + guest

Everything else: automatic.

## Summary

V3 ships `neon stream` — a feature-flagged subcommand (`cargo install neon --features experimental-bridge`) that automates the full QEMU/KVM + Win11 IoT LTSC + Looking Glass + GPU/TPM-passthrough setup needed to deliver hardware-attested 4K HDR DRM streaming on Linux desktops.

Code-complete in **6 sub-phases**, mirrors the V2 plan structure. Three real-hardware acceptance gates (Linux x86_64 desktop with TPM + dGPU, Linux laptop with single GPU + dummy plug, macOS for cross-platform parity) gate the eventual V3 release tag.

## Plan model

Same long-lived-team model as V2. Bridge work is mostly new code (~5,000-8,000 LOC estimated), but it composes on top of existing V2 modules (`platform`, `widevine`, `error`, `cli`).

### Teams (returning + one new)

| Team | Mission | Status |
|---|---|---|
| **bridge** (NEW) | Windows guest provisioning, libvirt domain XML, Looking Glass integration, kvmfr module wrangling, bridge socket protocol, VM lifecycle | First activation in V3 |
| **platform** (returning) | Hardware capability detection (TPM 2.0, IOMMU, GPU model, RAM, disk) extending existing `platform/` module | Returning |
| **core-engine** (returning) | `CdmProvider` trait abstraction; `BridgeCdm` impl; refactor of `patch::patch_browser` to use trait | Returning |
| **cli** (returning) | `neon stream <subcommand>` UX (`init`, `start`, `stop`, `status`, `repair`, `uninstall`); setup wizard | Returning |
| **infra** (returning) | Cargo feature flag plumbing; V3 CI matrix (gate the bridge tests behind the feature); release-please integration so `v1.x` and V3 features can ship independently | Returning |

### Guardrails

Same as V2 phases 3-5 (see `docs/superpowers/teams/orchestrator/agent-guardrails.md`):

- No parallel heavy cargo
- `--jobs 2` cap
- No `cargo tarpaulin`
- No D-Bus / compositor / desktop-session calls in tests
- No graphical processes during `cargo test`
- No file writes outside the repo
- No sudo / pkexec / osascript-with-admin
- Commits must compile cleanly
- No Claude attribution in git artifacts

Plus one V3-specific:

- **No real VM boots in tests.** Every `virsh`/`libvirt`/`qemu`-shell-out is gated by `NEON_TEST_VIRT_NOOP=1`. CI uses mock libvirt fixtures.

## Sub-phase plan

Six phases, designed for serial execution (one team active at a time). Roughly 3-6 weeks total at hobbyist pace.

### V3-Phase A: Scaffolding (foundation)

**Goal:** Cargo feature flag, empty bridge module, CdmProvider trait refactor, hidden `stream` subcommand. **No user-visible feature** — just architecture seam.

Per the [V3 scaffolding plan](../specs/2026-05-04-neon-v3-localhost-bridge-scaffolding-plan.md). Effort: ~3-4 hours, single agent (or orchestrator-driven).

| Deliverable | Owner | DoD |
|---|---|---|
| `Cargo.toml` `[features]` block with `experimental-bridge` | infra | Default build unchanged; `cargo build --features experimental-bridge` succeeds |
| `src/widevine/provider.rs` — `CdmProvider` trait + `LocalFileCdm` impl | core-engine | Trait is object-safe; LocalFileCdm passes 456 existing tests |
| `src/patch/mod.rs` — `patch_browser` takes `&dyn CdmProvider` | core-engine | All 456 tests still pass |
| `src/bridge/mod.rs` — gated stub returning `Err("not implemented")` | bridge | Compiles only with feature; `neon stream` returns the stub error |
| `src/cli/stream.rs` — gated subcommand stub | cli | Visible in `neon --help` only with feature |
| `tests/feature_flag.rs` — verify both flag states compile | infra | Passes |
| ROADMAP.md + CONTRIBUTING.md updates | infra | Cross-references this plan |

**Gate:** all 456 tests still pass; new build matrix (default + feature-on) green; `neon stream` stub returns error pointing at ROADMAP.

**Hardware gate:** none — this phase is pure software.

### V3-Phase B: Hardware capability detection

**Goal:** `neon doctor --bridge` reports exactly what hardware a user has, what it can do, and what's missing. Same code path the wizard uses. **No VM yet.**

| Deliverable | Owner | DoD |
|---|---|---|
| `src/platform/capabilities/mod.rs` — `BridgeCapabilities` struct + per-OS dispatch | platform | Detects: TPM 2.0 presence + version, IOMMU enabled, CPU virt extensions (VT-x/AMD-V), GPU vendor + model + IOMMU-grouping, RAM, available disk, HDR-capable display (Wayland) |
| `src/platform/capabilities/linux.rs` | platform | Reads `/dev/tpm0`, `dmesg \| grep -i iommu`, `/proc/cpuinfo`, `/sys/class/drm`, `lspci -vk`, `free -h`, `df`. Honors `NEON_TEST_CAPS_NOOP=1` returning a fixture. |
| `src/platform/capabilities/macos.rs` | platform | Reads via `system_profiler SPHardwareDataType` + `system_profiler SPDisplaysDataType` + `sysctl hw.optional.arm.FEAT_*` for Secure Enclave presence. (macOS V3 path is much smaller — no QEMU; instead bundles instructions for users to run a Windows installer in Parallels/UTM.) |
| `src/cli/doctor.rs` extension — `--bridge` flag | cli | Renders capability matrix as a table or JSON; specific remediation advice per missing item |
| `src/bridge/remediation.rs` — capability → fix-instructions map | bridge | Tables for known motherboard BIOS keys, dummy plug Amazon links, kernel boot params, etc. |
| Tests | platform/bridge | Unit tests cover every capability detection path + every remediation message |

**Gate:** `neon doctor --bridge` runs on Nick's actual machine, reports honest capability findings, and per-issue remediation is concrete (not "consult your manufacturer's manual").

**Hardware gate:** Nick runs `neon doctor --bridge` once on each of: Linux desktop (or laptop), macOS. Output is reviewed for accuracy.

### V3-Phase C: Windows guest provisioning (the big one)

**Goal:** `neon stream init` downloads Win11 IoT LTSC ISO, generates unattended XML, defines a libvirt domain with TPM + GPU passthrough, boots the VM, lets Windows install itself silently, then auto-installs Edge + Sunshine + HEVC Video Extension in the guest. ~30-45 min total user wait time.

| Deliverable | Owner | DoD |
|---|---|---|
| `src/bridge/iso.rs` — ISO download + SHA verification | bridge | Fetches Win11 IoT LTSC eval ISO from Microsoft's eval center URL; SHA-256 verified against published value; fixture-friendly for tests |
| `src/bridge/license.rs` — license posture management | bridge | Three modes: `--accept-eval` (90-day eval, auto-handles re-arm), `--license-key <KMS_KEY>` (user-provided), `--license-file <path>` (.csv). Stores choice in `~/.config/neon/bridge.toml` |
| `src/bridge/unattended.rs` — Windows unattended XML generation | bridge | Generates `autounattend.xml` that: skips OOBE, creates `neon-bridge` local user, sets US-English locale, accepts EULA, runs PowerShell first-logon script that installs Edge, HEVC Video Extension (winget), Sunshine, then snapshots; gated `NEON_TEST_UNATTENDED_NOOP=1` returns the rendered XML for inspection |
| `src/bridge/libvirt_xml.rs` — domain XML generation | bridge | Generates libvirt domain XML with TPM 2.0 passthrough, GPU passthrough (vfio-pci), virtio-net, virtio-disk, IVSHMEM device for Looking Glass, sane CPU pinning, hugepages where available. Tests verify XML is libvirt-schema-valid via `virt-xml-validate` (subprocess gated) |
| `src/bridge/libvirt.rs` — libvirt-rs orchestration | bridge | Define domain, start, stop, snapshot, restore. Uses `virt` crate (libvirt bindings). Gated `NEON_TEST_VIRT_NOOP=1` returns canned responses |
| `src/bridge/install.rs` — install orchestration | bridge | Mounts ISO + autounattend.xml into VM, starts domain, polls for "install complete" sentinel (Sunshine running), takes a "post-install" snapshot, marks domain as ready in state file |
| `src/cli/stream/init.rs` — init wizard | cli | Single command: detects capabilities → if any red, print remediation + exit; if all green, proceed: ask for license posture (or take from flag) → download ISO → generate XML → define + start → wait + spin → done. Spinners + progress per phase via `indicatif` |
| `src/cli/stream/status.rs` — VM status | cli | Reports: VM defined? running? snapshot age? Looking Glass connection healthy? |
| Cargo deps | infra | `virt` (libvirt-rs), `quick-xml`, `indicatif`, `sha2` (already), `reqwest` (already) |

**Gate:** `neon stream init --accept-eval` on a real desktop with TPM + dGPU produces a defined libvirt domain that boots Windows, runs unattended install, lands at a logged-in `neon-bridge` desktop with Sunshine running and Edge installed. Total wall time: under 45 minutes, zero user interaction past the initial command.

**Hardware gate:** Nick runs end-to-end on Linux desktop with VFIO-capable hardware (or Nick uses a borrowed machine). Records video of the unattended install for archival.

### V3-Phase D: Looking Glass integration

**Goal:** After Phase C provisions a working Windows guest, Phase D wires up the Looking Glass shared-memory transport so `neon stream` opens a near-zero-latency view of the guest desktop on the Linux host.

| Deliverable | Owner | DoD |
|---|---|---|
| `src/bridge/kvmfr.rs` — kvmfr module management | bridge | Detects whether kvmfr kernel module is loaded; if not, builds + loads from source (akmod/dkms-style); generates udev rule for `/dev/kvmfr0` permissions; gated `NEON_TEST_KVMFR_NOOP=1` |
| `src/bridge/looking_glass.rs` — LG client wrapper | bridge | Spawns `looking-glass-client` with auto-discovered `/dev/kvmfr0`; auto-fullscreen; auto-cursor-grab; lifecycle tied to VM lifecycle |
| `src/bridge/idd_fallback.rs` — dummy plug detection | bridge | If single-GPU host and Looking Glass IDD-host not yet shipped, detect whether dummy HDMI/DP plug is connected via `/sys/class/drm/<output>/status`; surface clear "you need a dummy plug at $X URL" message if not |
| `src/cli/stream/start.rs` — start command | cli | Resumes VM from snapshot, waits for Sunshine handshake, launches Looking Glass client. Total cold-start target: <10s on hot snapshot |
| `src/cli/stream/stop.rs` — stop command | cli | Snapshots VM, closes Looking Glass client, leaves domain defined for next start |
| Tests | bridge/cli | Mock kvmfr device + libvirt domain; verify orchestration logic without real LG client |

**Gate:** `neon stream start` on the same hardware from Phase C launches Looking Glass client in <10s; window grabs cursor cleanly; VM is responsive.

**Hardware gate:** Nick runs end-to-end + plays a non-DRM YouTube 4K HDR clip in the guest's Edge through the Looking Glass window. No tearing, no audio dropout.

### V3-Phase E: Bridge protocol + CDM forwarding (the experimental piece)

**Goal:** Edge in the guest does the actual Widevine/PlayReady decryption (since it has hardware attestation); decoded video frames pass through Looking Glass to the host. Phase E adds the *optional* CDM forwarding path where the host's existing Chromium-family browsers (Helium, etc.) can issue EME challenges that get *forwarded* to the guest's CDM and decrypted there. This is the "host browser plays Netflix at L1" path — speculative but the moat for V3.

**Note: this phase is optional for V3 V1.0.** The simpler "open Edge in the guest" approach (Phases C+D) already delivers 4K HDR Netflix. Phase E is a stretch within V3 itself. **Recommend deferring to V3.1.**

If pursued:

| Deliverable | Owner | DoD |
|---|---|---|
| `src/bridge/protocol.rs` — Unix socket / vsock RPC types | bridge | Serde-defined request/response: ChallengeForward, ResponseForward, KeyDeliver. Length-prefixed JSON over `~/.cache/neon/bridge.sock` (or vsock) |
| `src/widevine/bridge_cdm.rs` — `BridgeCdm` impl of `CdmProvider` | core-engine | Talks to host-side bridge socket; satisfies trait |
| `bridge-host-companion.exe` (in guest) — Windows-side endpoint | bridge | Native Windows binary, installed in guest by Phase C unattended setup, listens on bridge socket from VM side, forwards EME calls to local Edge instance |
| Tests | bridge/core-engine | Mock both sides; protocol round-trips |

**Gate:** Stretch — if Phase E pursued, Helium-on-host loads Netflix at higher than L3 cap (verified by quality option > 720p). If deferred, V3.0 ships without this path.

**Hardware gate:** Same as Phase D + actual Netflix playback test.

### V3-Phase F: Setup wizard polish + repair + uninstall

**Goal:** Production polish — every error path has a remediation; full lifecycle (install/start/stop/repair/uninstall) is bullet-proof.

| Deliverable | Owner | DoD |
|---|---|---|
| `src/cli/stream/repair.rs` | cli | Detects broken state (snapshot corrupt, VM domain missing, kvmfr not loaded, etc.); restores from last good snapshot; if snapshot gone, re-provisions from scratch |
| `src/cli/stream/uninstall.rs` | cli | Removes libvirt domain, deletes ISO + snapshots, unloads kvmfr module, removes config; preserves `~/.config/neon/config.toml` unless `--purge` |
| `src/bridge/health.rs` — periodic health check | bridge | Daemon-side: every 10 min, verifies VM is healthy, snapshot is recent, Sunshine is responsive; logs to `~/.cache/neon/logs/bridge.log` |
| `src/cli/stream/init.rs` — wizard polish | cli | Every error gets specific remediation; spinners with ETA per phase; cancellation handler that reverts cleanly |
| ROADMAP.md update + CHANGELOG entry | infra | V3 features documented |
| `docs/v3/` — user-facing docs | infra | Hardware compat matrix, troubleshooting, license FAQ |

**Gate:** Nick can break and fix the V3 setup three times in a row (delete a snapshot, kill the VM mid-install, etc.) with `neon stream repair` recovering each time.

**Hardware gate:** Same hardware as previous phases, exercised through fault scenarios.

## Cross-cutting concerns

### "Apple-level UX" enforcement

Every CLI subcommand goes through a UX review checklist:

- [ ] One command, no follow-up steps required (unless absolutely needed and surfaced)
- [ ] All hardware/system issues surface with specific remediation, not "consult docs"
- [ ] Progress visible (spinners with ETA, not silent multi-minute waits)
- [ ] Errors include a `neon stream repair` suggestion when applicable
- [ ] Cancellation (Ctrl-C) is graceful — partial state cleaned up automatically
- [ ] Defaults are sensible — user doesn't pick keyboard layout, locale, timezone, etc.
- [ ] License posture is asked once, stored, never re-prompted

### Testing strategy

- **No real VM in CI.** Every libvirt/qemu/virsh shell-out is `NEON_TEST_VIRT_NOOP=1`-gated returning fixtures.
- **No real ISO download in CI.** `NEON_TEST_ISO_FIXTURE=1` returns a synthesized 1KB "ISO" with the expected SHA.
- **Mock libvirt domain XML validation** uses fixtures and `virt-xml-validate` only when available; CI runners have it installed via apt.
- **Hardware acceptance is manual.** Phases B, C, D, F each have explicit Nick-runs-this-on-real-hardware acceptance criteria. Documented as `docs/v3/acceptance/<phase>.md`.

### Security

- VM has no network access by default beyond an HTTPS pinhole to streaming services (configured in libvirt XML)
- Bridge socket mode 0600
- Snapshot encryption (LUKS-on-loop) for stored Netflix cookies — defer to V3.1 if too complex
- No user-supplied PowerShell scripts run in guest (unattended XML is generated only from spec, not user input)

### Logging

- Bridge events go to `~/.cache/neon/logs/bridge.log` rotated daily
- Looking Glass client logs to its own file
- VM serial console captured to `~/.cache/neon/logs/vm-console.log`

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| User's hardware lacks IOMMU but BIOS toggle is unfamiliar | Medium | Per-vendor BIOS-key remediation in `bridge::remediation` |
| Microsoft changes the IoT LTSC eval URL or SHA | Medium | URL + SHA fetched from a config file at startup; can be hot-patched without binary release |
| `virt` crate (libvirt-rs) lags libvirt API changes | Low | Test on Arch + Ubuntu; pin libvirt minimum version; contribute upstream fixes if needed |
| Single-GPU host can't host + guest concurrently | Medium | Detect; fall back to "VM uses GPU; host shows fallback monitor or dummy plug"; clear remediation message |
| Looking Glass IDD-host doesn't ship in V3 timeframe | High | Already documented; dummy-plug fallback is the workaround |
| Win11 IoT LTSC eval expiration auto-rearm fails | Medium | Periodic re-arm via PowerShell scheduled task; surface to user via notification if rearm fails |
| Streaming services detect VM and refuse 4K HDR | Low (with proper passthrough) | Document; fall back to "1080p HDR if 4K refused"; rare per Proxmox forum reports |
| HDCP key revocation if hardware fingerprint leaks | Very low | Each user's PlayReady SL3000 is per-machine; no shared keys; revocation is per-device |
| Disk space (60GB+ for Win VM) on small laptops | Medium | Detect; surface as red capability; suggest external SSD path |
| First-time provisioning takes >45 min and user assumes it's broken | Medium | Spinners with ETA based on observed averages; "this is normal" message |
| User's BIOS doesn't allow vfio-pci binding without "Above 4G Decoding" or similar obscure setting | Medium | `bridge::remediation` includes the most common per-vendor settings list |

## Hardware acceptance plan

V3 cannot ship until Nick (or beta testers) runs three hardware paths end-to-end successfully:

| Path | Hardware | Validation |
|---|---|---|
| **Linux desktop, dual-GPU** | Any with iGPU + dGPU + TPM 2.0 + IOMMU | Phases C+D end-to-end: `neon stream init` → wait 30 min → `neon stream start netflix.com` → 4K HDR plays |
| **Linux laptop, single-GPU + dummy plug** | Any with single dGPU + TPM 2.0 + IOMMU + ~$5 dummy HDMI/DP plug | Same as above; verifies dummy-plug remediation works in practice |
| **macOS** | Any Mac with `system_profiler` (i.e. all of them) | `neon doctor --bridge` correctly reports macOS path; surfaces "use Parallels/UTM" guidance; doesn't crash |

Plus three failure-mode tests:

- Delete `~/.cache/neon/bridge/snapshot.qcow2` mid-stream → `neon stream repair` re-provisions cleanly
- Kill libvirt domain mid-install → `neon stream repair` resumes or restarts cleanly
- IOMMU disabled in BIOS → `neon doctor --bridge` reports it with vendor-specific BIOS-key remediation

## Open questions for user review

1. **macOS V3 scope.** Realistic options: (a) macOS gets `neon doctor --bridge` only — surfaces capability + points to Parallels/UTM for Windows guest setup; (b) Implement full V3 on macOS via Apple Virtualization Framework (huge scope expansion; macOS 12+ supports TPM/GPU virtualization but with different APIs); (c) Skip macOS entirely from V3 — it's Linux-only. **My recommendation: (a)** — macOS V3 is reading capability + telling the user "use Parallels Desktop or UTM for the Windows side; once you have Edge + Sunshine running, neon stream connects."

2. **Phase E (CDM forwarding) — V3.0 or V3.1?** The simpler "open Edge in the guest, watch Netflix in the guest" path satisfies the 4K HDR goal. Phase E is the lateral "host browser plays Netflix at L1" path and adds significant complexity. **My recommendation: defer to V3.1.** V3.0 ships the bigger UX win without overreaching.

3. **Disk space requirement** (Win11 IoT LTSC + Edge + snapshots = ~60GB). Default location: `~/.local/share/neon/bridge/`. Should this be configurable to an external drive? **Recommendation: yes via `~/.config/neon/bridge.toml`.**

4. **Microsoft Eval license auto-renewal.** Eval is 90 days; eval mode supports `slmgr /rearm` for ~3 additional 90-day cycles before it expires permanently. Beyond that, user must provide a real license key. **Recommendation: `neon stream` reminds user 7 days before eval expiry; auto-rearm if available; surface clear "you need a license key" message at exhaustion.**

5. **Beta tester recruitment for V3.** V3 has a much smaller addressable audience than V2 (must own VFIO-capable hardware). **Recommendation: recruit 5-10 beta testers via the V2 GitHub issue + r/VFIO + Level1Techs forum thread.** V3 release waits on confirmation from at least 3 beta testers across the three hardware paths.

## Estimated timeline (hobbyist pace)

```
V3-Phase A: Scaffolding                    ~1 evening (3-4 hrs)
V3-Phase B: Hardware capability detection  ~1-2 weekends
V3-Phase C: Windows guest provisioning     ~3-5 weekends (the heavy phase)
V3-Phase D: Looking Glass integration      ~2 weekends
V3-Phase E: CDM forwarding (DEFER to V3.1) [skip for V3.0]
V3-Phase F: Setup wizard polish + repair   ~2 weekends
Manual hardware acceptance                 ~1-2 weekends
Beta period                                ~2-4 weeks calendar

Total V3.0:  ~9-12 weekends focused work + 2-4 weeks beta
```

## Acceptance criteria for V3.0 (the release tag)

- [ ] All 6 sub-phases shipped except Phase E (deferred to V3.1)
- [ ] All cross-cutting UX checklist items met
- [ ] 3 hardware paths verified end-to-end (Nick + 2+ beta testers)
- [ ] 3 failure-mode tests pass
- [ ] `cargo test --features experimental-bridge --jobs 2` passes
- [ ] `cargo build --release --features experimental-bridge` produces a binary
- [ ] V3 ships behind the experimental flag — default install (no flag) is unchanged
- [ ] Documentation: hardware compat matrix, license FAQ, troubleshooting, CHANGELOG

## Approval and handoff

After user approves this plan:

1. Orchestrator creates `feature/v3` branch from `v2-rust-rewrite` — keeps V3 isolated from main V2 stabilization
2. Orchestrator executes V3-Phase A (scaffolding) — orchestrator-driven (no agent needed; ~3-4 hours)
3. After Phase A is committed and clean, orchestrator spawns the bridge team for V3-Phase B with full guardrails baked in (single agent, not parallel)
4. After Phase B passes hardware acceptance, V3-Phase C → D → F sequentially
5. Phase E queued for V3.1
6. V3.0 ships as `v1.x` with the feature flag; users opt in via `cargo install neon --features experimental-bridge`

The plan does NOT execute until user explicit approval. After approval, the orchestrator handles as much as automation allows — Nick is consulted only for: (a) hardware-acceptance test runs at gates B/C/D/F, (b) final ship/no-ship decisions, (c) license-posture confirmations (eval vs key).
