# Silvervine Roadmap

What's shipped, what's queued, what's a stretch goal, and who has to do it.

## Maintenance posture

Silvervine is maintained by [@nicholasraimbault](https://github.com/nicholasraimbault). I develop on Arch, so **Arch (and Arch-like distros) get first-class testing.** Everything else is best-effort and contributor-driven:

- **macOS** — builds and lints cleanly in CI; functional verification depends on Mac users running the binary and filing issues. The old `homebrew-neon` V1 tap is retired; migration from it remains supported.
- **Debian / Ubuntu / Fedora / RHEL** — V2's musl binary *runs*, but `.deb` / `.rpm` packaging and distro-specific migration paths need volunteers from those distros to verify.
- **Windows** — speculative, contributor-driven entirely. The protocol is sketched below; the code isn't.
- **ARM64 Linux** — not in V2's target list; needs Apple Silicon Asahi research or a maintainer with hardware.

Items below tagged `[contributor]` or `[needs <platform> verifier]` aren't blocked on me — they're blocked on someone who actually uses that platform stepping up. Open an issue when something breaks, send a PR when you fix it. The project will move at the speed of contributors on platforms I can't run.

## V2.0 — current (`v2.0.0`)

V2 is the first Rust-rewrite release. The prior bash + Swift + Go implementation shipped as `v1.0.0` and is V1.x in retrospect. V2 ships:

- **Single-binary cross-platform CLI + tray daemon.** One Rust executable; the same code path supports macOS (x86_64 + aarch64) and Linux (x86_64-musl).
- **Atomic patch rollback.** `renameat2(RENAME_EXCHANGE)` on Linux (via `syscall(SYS_renameat2, …)` for musl compatibility) and `renameatx_np(RENAME_SWAP)` on macOS. Privileged patches use exclusive, randomized snapshots under a validated same-filesystem parent and restore after write or verification failures.
- **Browser-running detection.** Defers patches when the browser is running; retries when it quits (mtime-stable + 1h hard cap).
- **Tray icon + native notifications.** `ksni` on Linux (StatusNotifierItem directly over D-Bus — zero GTK / libappindicator runtime dep); `tray-icon` on macOS; `notify-rust` for notifications.
- **Mozilla manifest URL fallback chain.** `hg.mozilla.org` → GitHub mirror → 24h on-disk cache.
- **`silvervine doctor` with EME error-code translation** across Netflix, Disney+, HBO Max, Spotify, Hulu; `--share` produces a pre-filled GitHub issue URL.
- **`silvervine repair`.** Uninstall + setup composition; preserves user config.
- **Migration from V1.** Detects bash installs and packaged installs (AUR / .deb / .rpm) with a pkg-manager-aware uninstall hint sniffed from `/etc/os-release`. Probes `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/lib/systemd/system/`; dedupes merged-usr symlinks. See [MIGRATION.md](MIGRATION.md).
- **Sleep/wake hooks.** `NSWorkspaceDidWakeNotification` on macOS; `org.freedesktop.login1.PrepareForSleep` on Linux.
- **Distribution.** `cargo-dist`-driven `curl … | sh` installer + tarballs at GitHub Releases. The old Neon V1 AUR/deb sources and `homebrew-neon` tap are retired; migration remains supported. No Silvervine Homebrew tap is planned.

The release-candidate window is for soaking Neon→Silvervine migration paths on real machines. Bug reports during this window get prioritized.

## V2.1 — queued

First six months post-V2.0. Driven by what surfaces during the rc and early prod.

### Distribution channels

- **AUR package** — `silvervine-bin` (downloads cargo-dist artifact) + `silvervine-git` (builds from source). Replaces the retired V1 `neon-drm` PKGBUILD.
- **`.deb` package** for Debian / Ubuntu via [`cargo-deb`](https://github.com/kornelski/cargo-deb), auto-built in the cargo-dist release pipeline. `[needs Debian/Ubuntu verifier]`
- **`.rpm` package** via `cargo-generate-rpm`. `[needs Fedora/RHEL verifier]`

### Diagnostics + media-stack helpers

- **`silvervine doctor --media-stack`** — checks codec presence (h264/h265/av1/vp9), HDR support (Wayland color management + monitor + GPU driver), GPU-accel flags (VAAPI / VideoToolbox). Reports a "media stack health" summary with concrete fixes. Linux side by me; macOS VideoToolbox detection `[needs macOS verifier]`.
- **`silvervine configure-youtube-hdr`** — one-shot helper that flips the right flags + installs the right extension for YouTube HDR on supported configurations (Wayland + HDR display + HEVC). Linux-only at the start.
- **Codec presence detection** as a shared library module so `silvervine doctor` and `silvervine configure-youtube-hdr` share the logic.

### Operational improvements

- **Pre-patch hooks.** `~/.config/silvervine/hooks/pre-patch` runs before each patch; non-zero exit aborts. Symmetric with the existing post-patch / post-update hooks.
- **`silvervine log` TUI viewer** — ratatui-based, over the daily-rotated logs at `~/.cache/silvervine/logs/`; filter by category, browser, time window.
- **Schema versioning for IPC.** `"version"` field in the JSON envelope, default 0 for back-compat. Triggered by the first post-V2 schema change.

### macOS

- **Inside-out codesigning.** Apple deprecated `codesign --deep` in macOS 13. V2 still uses it (same as V1). V2.1 migrates to inside-out: sign the framework's `.dylib` first, then the framework, then the bundle. `[needs macOS contributor]`

## Experimental work

The former premium-streaming experiment is not part of the release roadmap or
release-branch build. Its code and documentation are preserved on the protected
`experimental-bridge` branch for contributors who want to continue that research.
The release branch remains focused on the software-only Widevine L3 helper.

## Future / unscheduled

Items with no release vehicle; gated on contributors or hardware I don't have.

### Windows support `[contributor]`

Chromium DRM mechanics on Windows are similar enough to macOS/Linux that a port is bounded:

- Bundle layout: `<install>/Application/<version>/` (no `.app`).
- Privilege escalation: `runas verb` + UAC prompt.
- Daemon registration: Windows Service or Task Scheduler entry.
- File watching: `ReadDirectoryChangesW` (the `notify` crate already abstracts this).
- No `xattr` / `codesign` finalization.

`tray-icon` already supports Windows; the cross-platform abstractions in `src/platform/` and `src/daemon/` will accept a third backend. The work lands when a Windows maintainer shows up — I have no Windows machine to develop or test against.

### ARM64 Linux Widevine `[contributor / hardware]`

V2 cuts ARM64 Linux because V1's LaCrOS-extraction approach probably never worked at runtime on Asahi / Pi. Doing it properly is two-three weeks of focused ELF patching:

1. Extract Widevine from a ChromeOS LaCrOS aarch64 image.
2. Patch relocations + symbol references against vanilla glibc (LaCrOS uses non-standard symbol versions).
3. Patch hardcoded 4K-page assumptions for 16K-page Asahi systems.
4. Output a patched `libwidevinecdm.so` that drops into Linux aarch64 Chromium-family browsers.

This is specifically Asahi Linux + Raspberry Pi 4/5 + ARM Chromebooks running Linux. Apple Silicon Macs already work via the Darwin_arm64 CDM that Mozilla ships.

## Watch list (no commitment, just monitoring)

- **Wayland HDR maturity.** Once Helium / Thorium pick up first-class Wayland HDR, `silvervine configure-youtube-hdr` becomes more useful.
- **HDCP 2.3 maturity.** Could open more Linux GPU drivers to the L1 path.
- **Apple removing `codesign --deep` entirely.** Forcing function for the V2.1 inside-out signing work.

## Out of scope (probably forever)

- **Browser extension companion.** The Chromium sandbox prevents writing to the browser bundle from within an extension.
- **Codec installation helpers.** Helium and Thorium ship full codec support already.
- **Firefox / LibreWolf / Tor / Mullvad / Cromite support.** Firefox auto-downloads Widevine on x86_64; LibreWolf has a built-in toggle; Tor / Mullvad / Cromite reject DRM by design — patching them around their security model would break what their users want.
- **Headless server / Docker image.** Silvervine needs a user session and a browser to be useful.
- **Per-machine config sync.** XDG paths are user-local by design. Use a Syncthing share if you want this.
- **Webhook integrations (Discord / Slack).** Out of scope for a desktop DRM helper.
- **`silvervine://` URL handler.** Solving for use cases that don't exist.

## Versioning

V2 follows semantic versioning. Breaking changes to the IPC protocol bump the major version. Breaking changes to the CLI surface require a deprecation cycle (one minor with a warning, removal at the next major). CHANGELOG entries are generated from conventional commits via release-please.

This document moves items between sections as they ship or get cut. Last updated: 2026-07-16.
