# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Once V1.0 ships, future entries will be auto-generated from
[Conventional Commits](https://www.conventionalcommits.org/) via
[release-please](https://github.com/googleapis/release-please).

## [Unreleased]

### Added

- **V3 localhost-bridge (experimental, behind `experimental-bridge`
  Cargo feature)**: `neon stream` subcommand tree that provisions a
  Windows IoT LTSC guest VM with GPU + TPM passthrough and streams the
  desktop back via Looking Glass for premium 4K HDR DRM playback.
  Activated by `cargo install neon --features experimental-bridge`.
  Default `cargo install neon` is unchanged.
  - `neon stream init` — single-command provisioning (~30-45 min
    unattended).
  - `neon stream start [URL]` — resumes VM, launches Looking Glass,
    writes the URL into a sentinel the guest's Edge picks up.
  - `neon stream stop` — snapshots + halts cleanly.
  - `neon stream status [--json]` — VM state, snapshot age, license
    expiry, Sunshine reachability.
  - `neon stream repair [--auto] [--from-snapshot] [--refresh-snapshot]`
    — detects broken state, applies fixes in priority order.
  - `neon stream uninstall [--purge]` — clean teardown; `--purge`
    removes config too.
  - `neon stream license {show | set | rearm}` — manage license
    posture (eval / key / key-file).
  - `neon stream` (no args) — auto-dispatch: `init` if not provisioned,
    `status` otherwise.
  - `~/.config/neon/bridge.toml` overrides for Microsoft ISO URL +
    SHA, Sunshine installer URL + SHA, VM RAM / vCPU / IVSHMEM /
    data-dir. Lets users pin a fresh ISO when Microsoft rotates the
    eval-center URL without rebuilding from source.
  - Tray icon V3 extensions: streaming quick-launches, Bridge submenu
    (status / pause / resume / repair), eval-expiry badge with
    one-click rearm, alert glyph (⚠) when state needs attention.
  - Bridge health monitor: per-10-min check thread inside the daemon,
    surfaces eval-expiry / stale-snapshot / paused-VM as native
    notifications.
  - User-facing docs at `docs/v3/`: hardware compat matrix,
    troubleshooting guide, license FAQ.
- Single-binary cross-platform Rust rewrite (replaces V0 bash + Swift + Go).
- Atomic patching with snapshot/rollback (`renameat2(RENAME_EXCHANGE)` on
  Linux, `renameatx_np(RENAME_SWAP)` on macOS).
- Browser-running detection with patch deferral (mtime-stable + 1h hard cap).
- Tray icon + native notifications (Linux + macOS).
- 13 CLI subcommands: `init`, `setup`, `patch`, `status`, `list-browsers`,
  `doctor`, `test`, `update`, `repair`, `launch`, `uninstall`, `completion`,
  `manpage`.
- EME error-code translator covering 14 codes across Netflix, Disney+, HBO
  Max, Spotify, and Hulu.
- Mozilla manifest URL fallback chain (hg.mozilla.org → mozilla-firefox/firefox
  GitHub mirror → 24h on-disk cache).
- Sleep/wake hooks (NSWorkspace on macOS, logind on Linux).
- Migration logic for V0 installs (bash, Homebrew, AUR, .deb, Mac DMG).
- Opt-in error reporting (Cloudflare Worker + D1).
- Single distribution channel: `cargo-dist`-driven `curl | sh` installer.
- User hook system (`~/.config/neon/hooks/post-patch`, `post-update`).

### Changed

- Sudo prompts batched into a single elevation per `neon setup` invocation
  (previously up to 7 separate prompts during V0 → V2 migration).
- Distribution dropped Homebrew tap (V0 tap archived 30 days post-release in
  favor of unified `curl | sh` installer covering both macOS and Linux).

### Removed

- ARM64 Linux Widevine extraction (the V0 LaCrOS path likely never worked on
  Apple Silicon Asahi without ELF binary patching). Tracked for V2 in
  [ROADMAP.md](ROADMAP.md).

### Fixed

- Migration cleanup of legacy systemd units and LaunchDaemons no longer
  produces N separate password prompts; batches into one `pkexec` / `sudo` /
  `osascript` invocation via the new `platform::run_as_root_script` helper.

### Security

- All elevation paths route through `platform::run_as_root` /
  `run_as_root_script`, both honoring `NEON_TEST_ESCALATE_NOOP=1` so CI never
  prompts for credentials.
- Daemon socket created at `~/.cache/neon/daemon.sock` with mode 0600.
- Hooks runner refuses non-executable scripts.
- IPC message size capped at 1 MiB.

[Unreleased]: https://github.com/nicholasraimbault/neon/compare/v0.x...HEAD
