# Neon Roadmap

This document covers what's shipped, what's queued, and what's a stretch goal. Read alongside the [V2 design spec](docs/superpowers/specs/2026-05-04-neon-rust-rewrite-design.md).

## V1.0 — current branch (`v2-rust-rewrite`, ships as V2 on master)

Despite the directory naming, the first stable Neon release goes out as **V1.0** — the prior bash + Swift + Go implementation was V0.x in retrospect. The `v2-rust-rewrite` branch name reflects "second-generation rewrite," not the public version number.

V1.0 ships:

- **Single-binary cross-platform CLI + tray daemon.** ~10 MB statically-linked Rust binary; same code path on macOS (x86_64 + aarch64) and Linux (x86_64-musl). Replaces the V0 bash + Swift + Go triple-implementation.
- **Atomic patching with rollback.** `renameat2(RENAME_EXCHANGE)` on Linux, `renameatx_np(RENAME_SWAP)` on macOS, two-step fallback otherwise. Snapshot every patch to `~/.cache/neon/backups/<browser>-<ver>-<ts>/`; restore on any failure.
- **Browser-running detection.** Refuses to patch a running browser by default; daemon defers + retries when the browser quits (mtime stable for 30s, hard cap 1h).
- **Tray icon + native notifications.** `tray-icon` crate; `notify-rust` for notifications. macOS lacks notification action buttons (platform limitation); Linux has full button support.
- **Mozilla manifest URL fallback chain.** Primary: `hg.mozilla.org`. Fallback: GitHub `mozilla-firefox/firefox` mirror. Final: 24h-cached manifest.
- **`neon doctor` with EME error-code translation.** 14 codes across 5 services (Netflix, Disney+, HBO Max, Spotify, Hulu) mapped to actionable advice. `--share` produces a pre-filled GitHub issue URL.
- **`neon repair`.** uninstall + setup composition; preserves user config.
- **Opt-in error reporting.** Cloudflare Worker + D1 SQLite backend. Default off. Asked during `neon init`. No PII; only categorized failures.
- **Migration from V0.** Detects + cleans up legacy bash, Homebrew, AUR, .deb, and Mac DMG installs. See [MIGRATION.md](MIGRATION.md).
- **Sleep/wake hooks.** macOS `NSWorkspaceDidWakeNotification` (objc2 FFI); Linux `org.freedesktop.login1.Manager.PrepareForSleep` (zbus). Re-verifies all browser patches after wake.
- **Single distribution channel.** `cargo-dist`-driven `curl | sh` installer. No Homebrew tap (V1 tap archived 30 days post-release); no .deb / .rpm / AppImage / AUR yet.

Phase 6 of the orchestration plan covers the V1.0 beta period — pinned-issue tester recruitment, fix dispatch by error category, eventual `v1.0.0` tag.

## V1.1 — queued

Targeted at the first six months post-V1.0 ship. Driven by user demand observed during beta + early prod.

### Distribution channels

- **AUR package** for Arch users. Probably published as `neon-bin` (downloads cargo-dist artifact) plus `neon-git` (builds from source). Coordination with V0's `neon-drm` AUR maintainer to claim the namespace cleanly.
- **.deb package** for Debian/Ubuntu via [`cargo-deb`](https://github.com/kornelski/cargo-deb). Auto-built in the cargo-dist release pipeline once the V1 distribution story is stable. Includes a `postinst` that nudges users toward `neon setup`.
- **`.rpm` package** if anyone asks. `cargo-generate-rpm` available; not a high priority.
- **`zipsign` artifact signing.** cargo-dist 0.31 doesn't natively produce zipsign signatures. We add a post-build signing step in `release.yml` that signs each artifact with a private key from a GitHub secret. The `self_update` crate's `signatures` feature can then verify on update. Public key embedded in the binary at build time. Requires Nick to generate a keypair.

### Diagnostics + media-stack helpers

- **`neon doctor --media-stack`** — extends `neon doctor` to check codec presence (h264/h265/av1/vp9), HDR support (Wayland color management protocol availability + monitor capability + GPU driver), and GPU acceleration flags (VAAPI/VideoToolbox bindings active). Reports a "media stack health" summary with concrete fixes (install `libavcodec-extra-VERSION`; enable `chrome://flags#enable-webgpu-developer-features`; configure VAAPI in `chrome://flags#use-vaapi`).
- **`neon configure-youtube-hdr`** — one-shot helper that flips the right flags + extension installation for YouTube HDR on supported configurations (Wayland + HDR display + HEVC codec). The actual recipe is documented in upstream Helium issue #N (referenced from the command).
- **Codec presence detection** as a separate library module so `neon doctor` and `neon configure-youtube-hdr` share the logic.

### Operational improvements

- **Pre-patch hooks** (currently only post-patch / post-update ship). `~/.config/neon/hooks/pre-patch` runs before each patch; non-zero exit aborts the patch.
- **`neon log` TUI viewer** — interactive viewer over the daily-rotated log files at `~/.cache/neon/logs/`. ratatui-based; filter by category, browser, time window.
- **Schema versioning for IPC.** Add a `"version"` field to the JSON envelope, default 0 for backwards compatibility. Triggered by the first post-V1 schema change.

## V2 — planned

Targeted at the year+ horizon. Each item is multi-PR scope; some require platform research.

### Windows support

There are multiple upstream issues on `vikas5914/helium-drm-fixer` (V0's predecessor) from Windows users asking for the same DRM-fix workflow. The Chromium DRM mechanics are similar enough on Windows that a port is straightforward in principle:

- Bundle layout differs (no `.app`; `<install>/Application/<version>/`).
- Privilege escalation differs (`runas verb`, UAC prompt).
- Daemon registration differs (Windows Service or Task Scheduler entry).
- File watching differs (`ReadDirectoryChangesW`; `notify` crate already abstracts this).
- No `xattr` / `codesign` finalization; just `cp` + permission set.

The `tray-icon` crate already supports Windows. Most of the cross-platform abstractions in `src/platform/` and `src/daemon/` will accept a third backend; the work is bounded.

### ARM64 Linux with proper ELF binary patching

V1 cuts ARM64 Linux because the V0 implementation used a hacky LaCrOS extraction that (the design spec verifies) probably doesn't actually work at runtime on Asahi / Pi. To do this properly, we need to port the [`widevine_fixup.py`](https://github.com/proprietary/chromeos-widevine-cdm-extractor) semantics to Rust:

1. Extract Widevine from a ChromeOS LaCrOS aarch64 image.
2. Patch the ELF binary's relocations + symbol references to work against vanilla glibc (LaCrOS uses musl-flavored glibc with non-standard symbol versions).
3. Patch hardcoded 4K-page assumptions to work on 16K-page systems (Asahi).
4. Output a patched `libwidevinecdm.so` that drops into Linux aarch64 Chromium-family browsers.

This is bounded but involved — two-three weeks of focused work. Apple Silicon Macs already work in V1 via the Darwin_arm64 CDM that Mozilla ships; this is specifically about Asahi Linux + Raspberry Pi 4/5 + ARM Chromebooks running Linux.

### Inside-out codesigning on macOS

Apple deprecated `codesign --deep` as of macOS 13. V1 still uses it because that's what V0 used and the deprecation doesn't break things yet. V2 migrates to inside-out codesigning: sign the framework's `.dylib` first, then sign the framework, then sign the bundle. Each layer's signature is verifiable independently. Documented at `https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution/resolving_common_notarization_issues`.

## V3 stretch goal — `neon localhost-bridge` (experimental)

**Status:** behind a Cargo feature flag `experimental-bridge`. Architectural scaffolding (feature flag, stub `neon stream` subcommand, `CdmProvider` trait, `bridge` module skeleton) ships in V1.0 alongside V2's stable surface. The real V3 implementation lands incrementally after V1.0 stabilizes.

- Architecture and scaffolding plan: [V3 scaffolding plan](docs/superpowers/specs/2026-05-04-neon-v3-localhost-bridge-scaffolding-plan.md)
- Six-sub-phase orchestration: [V3 orchestration plan](docs/superpowers/plans/2026-05-04-neon-v3-orchestration-plan.md)

Activated by:

```sh
cargo install neon --features experimental-bridge
```

Enables a `neon stream <url>` subcommand. In V1.0 binaries it returns a "queued for V3" stub error pointing back here; subsequent V3 phases (B → C → D → F) fill it in.


The L3 ceiling is real. There's no software path to 4K HDR on a de-Googled Chromium fork. But there's a hardware path: a Win11 IoT VM with GPU + TPM passthrough, running Edge or Chrome with a real signed Widevine binary, streamed back to the host via Looking Glass.

We've verified the gap analysis: this space is empty. **WinBoat (21k stars)** explicitly walked away from Looking Glass complexity and shipped CPU-only RDP. **Shadow.tech** and similar cloud SaaS players ban VOD streaming in their ToS — none of them target this use case. Addressable audience: ~50–200k de-Googled-browser users on x86_64 Linux who'd pay for premium DRM.

The recipe:

1. **Win11 IoT LTSC.** Free for evaluation; **BYO production license** (mitigates the licensing grey area — Neon doesn't ship Microsoft binaries; user provides their own LTSC license).
2. **Looking Glass B7** for ultra-low-latency frame transport over a shared memory ring buffer between host + guest. ~3-5 ms vs. RDP's ~25-40 ms.
3. **GPU passthrough** via VFIO (single-GPU passthrough or dual-GPU).
4. **TPM passthrough** via swtpm (software TPM emulator) — Widevine L1 needs a TPM 2.0 endorsement key chain.
5. **HEVC** (free in IoT LTSC, paid in retail Win11) — Netflix and Disney+ deliver HEVC at higher quality tiers.
6. **Looking Glass IDD driver** (status: paused upstream; mitigated by **$5 dummy HDMI plug** to give Windows a "real" display target without forcing GPU resync).

Three blockers, all mitigated:

- **Licensing grey-area** — mitigated by BYO posture; Neon never distributes Microsoft binaries.
- **Looking Glass IDD paused upstream** — mitigated by dummy HDMI plug ($5 from Amazon).
- **Niche pricing** — mitigated by shipping it free, as a Neon Cargo feature, no separate product / paywall.

The interface would be:

```sh
cargo install neon --features experimental-bridge
neon localhost-bridge install              # downloads Win11 IoT LTSC ISO; configures VM
neon localhost-bridge configure-passthrough  # wizard for GPU + TPM
neon localhost-bridge launch                # starts VM + Looking Glass client; pipes audio
```

The Cargo feature flag means it stays out of the default binary entirely. Default builds remain ~10 MB. With the feature, we add VM management + Looking Glass client glue (probably ~5 MB more, plus runtime deps for QEMU + KVM). The user opts into the complexity.

This is reach-extending work, not core mission. We'd build it because the L3 ceiling is the most-asked-about limitation in V0's issue tracker, and because the gap-analysis confirmed nobody else is filling the niche. See `docs/superpowers/teams/orchestrator/status.md` for the full gap-analysis decision record.

## Watch list (no commitment, just monitoring)

- **Wayland HDR maturity.** The color management protocol landed in early 2025; KDE and GNOME compositors are still implementing. Once Helium / Thorium pick up first-class Wayland HDR support, `neon configure-youtube-hdr` becomes more useful and HDR matters more.
- **Looking Glass IDD GA.** Currently paused upstream. If/when it ships, the V3 bridge story gets simpler (no dummy plug needed).
- **AMD GIM consumer Radeon SR-IOV.** Currently SR-IOV is professional-tier only. If AMD ships SR-IOV on consumer Radeons, GPU passthrough for the V3 bridge becomes a single-GPU operation (no second card needed).
- **HDCP 2.3 maturity.** Studios are starting to demand HDCP 2.3 over HDCP 2.2 for 4K HDR. If Linux GPU drivers ship full HDCP 2.3 support, more cards become eligible for the L1 path.
- **Apple's deprecation of codesign --deep.** Currently deprecated but still working. If a future macOS removes it entirely, we MUST have V2's inside-out signing migration done.

## Out of scope (probably forever)

- **Browser extension companion.** The Chromium sandbox prevents writing to the browser bundle from within an extension. This was investigated in V0 and is verified out of scope.
- **Codec installation helpers.** Helium and Thorium ship full codec support already. Not Neon's job to install codecs the browser handles itself.
- **Firefox / LibreWolf / Tor / Mullvad / Cromite support.** Firefox auto-downloads Widevine on x86_64 (needs no help). LibreWolf has a built-in toggle. Tor / Mullvad / Cromite explicitly reject DRM by design — patching them around their security model would break what their users want.
- **Headless server / Docker image.** Neon needs a user session and a browser to be useful. Server images don't have either.
- **Per-machine config sync.** XDG paths are user-local by design. If someone wants this, they can put `~/.config/neon/` on a syncthing share.
- **Webhook integrations (Discord/Slack).** Out of scope for a desktop DRM helper.
- **`neon://` URL handler.** Solving for use cases that don't exist.

## Versioning

V1 starts at `v0.1.0` (current Cargo version) and progresses through `v0.x` during the beta period. The first non-beta release is `v1.0.0`. Breaking changes to the IPC protocol bump the major version. Breaking changes to the CLI surface require a deprecation cycle (one minor version warning, removal at next major). CHANGELOG entries auto-generated from conventional commits via release-please.

## Schedule

This document is updated as items move between V1.0 / V1.1 / V2 / V3. Last updated: 2026-05-04.
