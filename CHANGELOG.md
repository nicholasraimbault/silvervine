# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Future entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) via
[release-please](https://github.com/googleapis/release-please).

## [Unreleased]

## [2.0.0] - 2026-07-16

### Added

- Added automatic, non-destructive Neon V2 → Silvervine migration for user
  config, cache, and log directories before logging starts.
- Added 2.x hook compatibility aliases: hooks receive both `SILVERVINE_*` and
  deprecated matching `NEON_*` context variables without overwriting explicit
  values.

### Changed

- Renamed the product, repository, crate, library, binary, paths, user daemon,
  and current documentation from Neon to Silvervine for `v2.0.0`.
- Silvervine daemon migration starts the replacement registration before
  retiring the retained Neon V2 registration (`neon.service` or
  `com.neon.tray`), with rollback to the prior data and running state if
  retirement fails.
- Retired the Neon V1 Homebrew/AUR/deb sources. Their legacy migration paths
  and package-manager guidance remain supported; no Silvervine Homebrew tap is
  created.

### Fixed

- Fixed macOS daemon IPC connections closing before clients could send their
  request when accepted sockets inherited nonblocking mode.
- Fixed macOS file-watcher events failing to match browser paths reported
  through canonical aliases such as `/private/var` versus `/var`.

### Removed

- Removed the unsupported experimental VM/GPU bridge, including the
  `neon stream` command tree, `neon doctor --bridge`, libvirt dependencies,
  and bridge-specific daemon/tray integration. The research implementation is
  preserved on the `experimental-bridge` branch for contributors.
- Removed the bridge-only CDM provider abstraction and its redundant temporary
  copy of the cached Widevine payload during every browser patch.
- Removed the unsigned `neon update self` mechanism. Install updates through a
  supported package manager or GitHub Releases instead.

## [2.0.0-rc.2] - 2026-05-17

A polish release: every change addresses a bug or UX failure surfaced
testing rc.1 on a real Linux install. No new features. Strongly
recommended for anyone running rc.1 — especially macOS users, where
rc.1 has a hard deadlock on the patch path.

### Fixed

- **macOS `sudo neon patch` deadlocks on the lockfile after a
  redundant osascript re-prompt** ([#30](https://github.com/nicholasraimbault/silvervine/issues/30),
  reported by [@yzaimoglu](https://github.com/yzaimoglu)). The patch
  flow no longer re-escalates when `geteuid() == 0`, and the
  privileged child skips the lockfile the parent already holds.
- **`neon doctor` reported "patched" for browsers whose on-disk CDM
  was stale.** Doctor now reads each bundle's
  `WidevineCdm/manifest.json` version, compares it to the cache, and
  surfaces an inline out-of-date warning (`run "Patch Now"`).
- **Daemon could enter a watcher → patch → pkexec re-prompt loop.**
  `drive_patch_flow` now checks `installed_cdm_version()` vs the
  cached version up front and short-circuits browsers already at the
  cached version — no patcher invocation, no root escalation, no
  watcher refire.
- **Tray "Update Widevine" only refreshed the cache.** Now it also
  re-patches every detected browser, which is what users expect a
  button by that name to do.
- **Every tray action was silent.** PatchAll, PatchOne,
  UpdateWidevine, and the success branch of ToggleLaunchAtLogin now
  emit toast notifications.
- **`~/.config/neon/config.toml` carrying a legacy `[reporting]`
  block from v1 / rc.0 crashed the daemon on first launch of rc.1**
  with an opaque `StateCorrupted: TOML parse error`. Config schema
  now silently drops deprecated top-level sections (typos in current
  sections still fail loudly).
- **Migration silently misreported success when the elevated cleanup
  script failed.** Paths now route to `outcome.skipped` with the
  failure reason rather than into `outcome.removed`.
- **Watcher fired on the first event of a browser-update storm,
  patching on top of an in-flight bundle.** Switched to trailing-edge
  debounce: the callback only fires after the install path has been
  quiet for the full debounce window.
- **Widevine cache TOCTOU between `target_dir.exists()` and the
  staging→target rename** let two concurrent neon invocations (CLI +
  daemon, double-clicked installer) corrupt the cache. New
  `<cache>/download.lock` serializes the slow path.
- **`platform::format_exit_status`**: replaces the opaque
  `(exit None)` error message on signal-killed escalation children
  with a readable `killed by signal N`.

### Added

- Auto-discover Helium installed via the official `apt` repo (lands
  at `/opt/helium` on Debian / Ubuntu / Pop!_OS) in addition to the
  existing AUR path `/opt/helium-browser-bin`. Thanks to
  [@PeterDrakulic](https://github.com/PeterDrakulic) (#3).

### Performance

- Tray PatchAll / PatchOne reuse the daemon's shared browser list
  rather than running a fresh `detect_browsers` filesystem walk on
  every click.
- CDM cache: clean orphaned CRX3 archives after a successful
  extraction, and have `prune` sweep any stale ones left by older
  neon versions (each was ~5–7 MB; they piled up indefinitely).

## [2.0.0-rc.1] - 2026-05-13

### Added

> **Historical note:** The experimental bridge described below was later removed
> from the release branch and preserved on the `experimental-bridge` branch.

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
- patch privilege escalation: `neon patch` now correctly escalates via
  pkexec/sudo when the target install path requires root, rather than
  silently failing with EACCES
- patch backup location: same-filesystem sibling directory under
  `<install-parent>/.neon-backups/` instead of `~/.cache/neon/backups/`,
  so atomic_rename rollback works (was failing with EXDEV when /opt and
  /home were different filesystems)
- patch restore: only attempted when `perform_patch` actually modified
  the original; pre-modification failures no longer trigger an
  incorrect restore
- Migration silently missed v1 installs whose systemd units lived
  under `/usr/lib/systemd/system/` (AUR-packaged) or
  `/lib/systemd/system/` (Debian pre-merged-usr). Now probes all three
  locations; dedupes merged-usr symlinks; routes package-managed
  artifacts to a skip-with-advisory rather than rm-ing files behind
  the package manager's back. The advisory text is sniffed from
  `/etc/os-release` so Arch sees `pacman -R neon-drm`, Debian sees
  `dpkg -r neon-drm`, Fedora sees `rpm -e neon-drm`, etc.

### Security

- All elevation paths route through `platform::run_as_root` /
  `run_as_root_script`, both honoring `NEON_TEST_ESCALATE_NOOP=1` so CI never
  prompts for credentials.
- Daemon socket created at `~/.cache/neon/daemon.sock` with mode 0600.
- Hooks runner refuses non-executable scripts.
- IPC message size capped at 1 MiB.

### Credits

- @bfayers (#1) — independently caught the Mozilla widevine URL
  rotation and the macOS `xattr -r → -c` regression in the v1 bash
  scripts. Both bugs are obsoleted by the rewrite, but the reports
  were on the money.

[Unreleased]: https://github.com/nicholasraimbault/silvervine/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/nicholasraimbault/silvervine/compare/v2.0.0-rc.2...v2.0.0
[2.0.0-rc.2]: https://github.com/nicholasraimbault/silvervine/compare/v2.0.0-rc.1...v2.0.0-rc.2
[2.0.0-rc.1]: https://github.com/nicholasraimbault/silvervine/compare/v1.0.0...v2.0.0-rc.1
