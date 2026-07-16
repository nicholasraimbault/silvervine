# Silvervine

[![CI](https://github.com/nicholasraimbault/silvervine/actions/workflows/ci.yml/badge.svg)](https://github.com/nicholasraimbault/silvervine/actions/workflows/ci.yml)

**Single-binary cross-platform DRM (Widevine) helper for Chromium-family browsers on macOS and Linux.**

Silvervine patches Google's Widevine CDM into Chromium-family browsers that don't ship with it (Helium, Thorium, ungoogled-chromium, plain Chromium), enabling Netflix, Spotify, Disney+, HBO Max, and other DRM-protected content. It re-patches automatically when your browser updates, so you set it up once and forget about it.

## Install

Install the latest release on Linux or macOS:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nicholasraimbault/silvervine/releases/latest/download/silvervine-installer.sh | sh
silvervine setup
```

The installer places the `silvervine` executable in `$CARGO_HOME/bin` (typically `~/.cargo/bin`). `silvervine setup` then detects supported browsers, downloads and verifies Widevine from Mozilla's GMP manifest, patches each browser, and registers a user-session daemon for automatic re-patching after browser updates.

Release files and checksums are also available from [GitHub Releases](https://github.com/nicholasraimbault/silvervine/releases).

**Homebrew:** the old `nicholasraimbault/homebrew-neon` tap is a retired Neon V1 distribution channel. No Silvervine tap is planned; install Silvervine with the release installer above. Migration from that V1 install remains supported.

If you previously installed Neon via the V1 bash script, Homebrew tap, AUR package, or .deb — `silvervine setup` detects and migrates the old install (with a pkg-manager-aware uninstall hint for AUR / .deb / .rpm). Neon V2 config, cache, and logs are also migrated automatically on startup. See [MIGRATION.md](MIGRATION.md).

## Supported browsers

Silvervine patches any Chromium-family browser. The following are auto-discovered out of the box:

| Browser | macOS path | Linux path(s) |
|---|---|---|
| [Helium](https://helium.computer) | `/Applications/Helium.app` | `/opt/helium` (apt), `/opt/helium-browser-bin` (AUR) |
| [Thorium](https://thorium.rocks) | `/Applications/Thorium.app` | `/opt/chromium.org/thorium`, `/opt/thorium-browser` |
| [ungoogled-chromium](https://ungoogled-software.github.io/ungoogled-chromium-binaries/) | `/Applications/Chromium.app` | `/usr/lib/chromium`, `/usr/lib64/chromium` |
| [Chromium](https://www.chromium.org/) | `/Applications/Chromium.app` | `/usr/lib/chromium-browser` |

Additional Chromium-family browsers are auto-discovered by scanning `/Applications/*.app` (macOS) and `/opt`, `/usr/lib`, `/usr/lib64`, `/usr/local/lib` (Linux) for the Chromium framework signature.

You can add custom browsers via `~/.config/silvervine/config.toml`:

```toml
[[browsers]]
name = "MyCustomBrowser"
# macOS:
bundle_path = "/Users/me/Applications/MyCustomBrowser.app"
framework_name = "MyCustomBrowser Framework"
# Or Linux:
# install_path = "/home/me/builds/my-chromium"
```

## The L3 ceiling — please read

Patched Widevine is **software-only L3**. Streaming services cap L3 playback at roughly **720p**. That means:

- **Netflix, Disney+, HBO Max, Hulu, etc. will not deliver 4K HDR** through a patched browser, regardless of your monitor, GPU, or subscription tier.
- This is a DRM platform constraint enforced by the studios, **not a Silvervine limitation**. No software patch can change it.
- Spotify, YouTube Music, and audio-only services work at full quality (DRM tier doesn't bound audio bitrate).
- 1080p SDR works on most services. Some services downgrade further (Netflix sometimes caps L3 at 540p depending on title).

Hardware-DRM L1 requires a Widevine binary signed by your device's TPM/Secure Enclave + browser binary signed by the browser vendor + CDN-side allow-listing. None of that exists for de-Googled Chromium forks. If you need 4K HDR, you need a device blessed by the studios — Apple TV, smart TV, official Edge/Safari/Chrome.

## Features

- **One binary, two modes.** The same `silvervine` executable is both the CLI and the long-running tray daemon. No daemon-spawn race conditions, no second-source-of-truth bugs.
- **Filesystem-safe patching with rollback.** Every patch creates an exclusive same-filesystem snapshot before modifying the browser. A failed write or verification atomically restores that snapshot (`renameat2(RENAME_EXCHANGE)` on Linux, `renameatx_np(RENAME_SWAP)` on macOS); interrupted operations retain a recovery snapshot rather than silently deleting it.
- **Browser-running detection.** Refuses to patch a running browser by default; the daemon defers and retries automatically when the browser quits (mtime stable for 30s).
- **Tray icon + native notifications.** Per-browser status, one-click re-patch, native success/failure notifications via libnotify (Linux) or NSUserNotificationCenter (macOS).
- **`silvervine doctor`** produces structured diagnostics with EME error-code translation (Netflix N-codes, Disney+ codes, Spotify codes, etc.) — paste a Netflix code right into `silvervine doctor N8156-6024` for actionable advice.
- **`silvervine repair`** brings any broken state back to working in one command.
- **Mozilla manifest fallback chain.** Primary: `hg.mozilla.org`. Fallback: GitHub mirror. Final fallback: 24h-cached manifest. Survives `hg.mozilla.org` flakes (which is why Mozilla mirrors the manifest themselves).
- **Migration from V1.** Detects and cleans up legacy bash installs, V1 Homebrew formula installs, AUR / `.deb` / `.rpm` packages, with a pkg-manager-aware uninstall hint sniffed from `/etc/os-release`.

## CLI reference

| Command | Description |
|---|---|
| `silvervine` | Run the tray daemon (default when invoked without args) |
| `silvervine init` | Interactive first-run wizard |
| `silvervine setup` | Non-interactive install (scriptable; runs migration first) |
| `silvervine patch [--force] [--dry-run] [<browser>]` | Patch one or more browsers |
| `silvervine status [--json] [--watch]` | Show per-browser patch status |
| `silvervine list-browsers [--all] [--json]` | Enumerate known + auto-discovered browsers |
| `silvervine doctor [--json] [--share] [<error-code>]` | Diagnostics + EME error code translation |
| `silvervine test` | EME health-check against Shaka Player demo |
| `silvervine update widevine [--rollback] [--cdm-source <url>]` | Update the Widevine CDM |
| `silvervine repair` | uninstall + setup composition |
| `silvervine launch <browser>` | Verify-then-launch wrapper (re-patches if needed) |
| `silvervine uninstall` | Remove daemon + cache (preserves browser bundles) |
| `silvervine completion <shell>` | Generate shell completions (bash/zsh/fish/powershell) |
| `silvervine manpage` | Generate man page (roff) |

Global flags: `-v`/`-vv` for verbose logging, `-q` to silence non-error output, `--no-color` to disable colored output (`NO_COLOR` env honored), `--json` for structured output where applicable.

## How it works

1. **Manifest fetch.** `silvervine update widevine` pulls Mozilla's `widevinecdm.json` (or the GitHub mirror, or the 24h cache), parses the platform-specific entry (`Linux_x86_64-gcc3` / `Darwin_x86_64-gcc3-u-i386-x86_64` / `Darwin_arm64-gcc3`), and resolves the CRX3 download URL + SHA-512.
2. **Download.** CRX3 (Chrome Extension v3) is downloaded to `~/.cache/silvervine/widevine/downloads/<hash>.crx3`, SHA-512 verified, ZIP body extracted to `~/.cache/silvervine/widevine/<version>/`.
3. **Patch.** For each detected browser, Silvervine creates an exclusive same-filesystem snapshot, writes the CDM into the selected browser, and runs platform-specific finalization (`xattr -cr` + `codesign --force --deep -s -` on macOS; `chmod 0755` on Linux). A failed write or verification swaps the snapshot back into place atomically; successful patches remove it.
4. **Daemon.** The daemon (LaunchAgent / systemd-user unit) watches each browser's framework path via `notify` (FSEvents on macOS, inotify on Linux). When a browser self-updates, the watcher fires, the daemon checks the browser is closed, re-patches, and emits a desktop notification.
5. **Sleep/wake hooks.** On wake-from-sleep, the daemon re-verifies every browser's patch status (browsers can update via package manager while the laptop is asleep).

Module-level rustdoc covers the patch protocol, atomic-rename mechanics, and the daemon IPC envelope in detail — `cargo doc --open` after cloning to browse it locally.

## Why Silvervine

Helium, Thorium, ungoogled-chromium, and similar Chromium forks intentionally remove Google's proprietary blobs (including the Widevine CDM) for privacy / de-Googling reasons. Streaming sites won't play DRM-protected video without a CDM, so a fresh install of any of these browsers can't watch Netflix.

Silvervine fills that gap. It downloads the CDM from the same Mozilla manifest that Firefox uses, drops it into the browser bundle, and keeps it in sync as the browser updates. This is the same workflow as `vikas5914/helium-drm-fixer` (which Silvervine is a successor to) but with cross-platform support, atomic patching, no-root user-session daemon, and integrated diagnostics.

If you're using Helium, Thorium, ungoogled-chromium, or a custom-built Chromium and you want Netflix to work — Silvervine is for you.

If you're using regular Chrome, regular Edge, regular Brave, or Firefox — you don't need Silvervine. Those browsers ship a working Widevine binary already.

## Requirements

- macOS (x86_64 or aarch64) or Linux (x86_64).
- On Linux: any tray bar that speaks the StatusNotifierItem protocol — KDE Plasma, sway/Hyprland with waybar, Quickshell-based shells (noctalia, Caelestia), Cinnamon, etc. Vanilla GNOME [removed tray support in 2017](https://blogs.gnome.org/aday/2017/08/31/status-icons-and-gnome/) and needs the [AppIndicator extension](https://extensions.gnome.org/extension/615/appindicator-support/). Without a working tray bar, the daemon falls back to notifications-only.
- A Chromium-family browser to patch.

## Platform support

| Platform | Validation | Status |
|---|---|---|
| Linux x86_64 | Native CI plus maintainer testing on Arch Linux | Supported |
| macOS Intel and Apple Silicon | Native macOS CI; hardware smoke testing is community-assisted | Supported |
| Linux ARM64 | Not currently built or tested | Unsupported in V2 |
| Windows | Not currently built or tested | Unsupported in V2 |

Every pull request must pass formatting plus native Linux and macOS Clippy, tests, and release builds. macOS GUI, privilege-prompt, playback, and tray behavior cannot be fully exercised in CI, so hardware test reports are welcome through [GitHub Issues](https://github.com/nicholasraimbault/silvervine/issues). See [ROADMAP.md](ROADMAP.md#maintenance-posture) for the maintenance policy and future platform plans.

## Documentation

- [MIGRATION.md](MIGRATION.md) — upgrading from V1 (bash, Homebrew, DMG, AUR, .deb / .rpm)
- [ROADMAP.md](ROADMAP.md) — V2.1 and future L3-helper plans, maintenance posture
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, conventional commits, PR conventions
- [SECURITY.md](SECURITY.md) — disclosure policy, supported versions
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [CHANGELOG.md](CHANGELOG.md) — release history

## License

[MIT](LICENSE)
