# Neon

**Single-binary cross-platform DRM (Widevine) helper for Chromium-family browsers on macOS and Linux.**

Neon patches Google's Widevine CDM into Chromium-family browsers that don't ship with it (Helium, Thorium, ungoogled-chromium, plain Chromium), enabling Netflix, Spotify, Disney+, HBO Max, and other DRM-protected content. It re-patches automatically when your browser updates, so you set it up once and forget about it.

## Install

**Currently shipping a release candidate (v2.0.0-rc.1).** Please file issues if anything misbehaves; promotion to `v2.0.0` stable follows after the rc has had a quiet ~week.

```sh
# Linux and macOS — pinned to the rc.1 tag while we're pre-stable.
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nicholasraimbault/neon/releases/download/v2.0.0-rc.1/neon-installer.sh | sh
neon setup
```

Once v2.0.0 stable lands, this snippet swaps the pinned tag for `…/releases/latest/download/neon-installer.sh` and self-updates with each release.

The installer drops a single statically-linked binary into `$CARGO_HOME/bin` (typically `~/.cargo/bin`); `neon setup` then detects your browsers, downloads the Widevine CDM from Mozilla's GMP manifest, patches each browser, and registers a user-session daemon (LaunchAgent on macOS, systemd-user unit on Linux) that re-patches automatically on browser self-updates.

**Mac users heads-up.** `brew install nicholasraimbault/neon/neon` still installs **v1.0.0** — the bash-script implementation that predated this Rust rewrite. The tap is intentionally pinned at v1 during the rc because v2 hasn't been end-to-end validated on macOS yet. To try v2 on a Mac, use the `curl … | sh` snippet above. We'll auto-publish a v2 Formula to the tap once the macOS path is validated.

If you previously installed Neon via the V1 bash script, Homebrew tap, AUR package, or .deb — `neon setup` detects and migrates the old install (with a pkg-manager-aware uninstall hint for AUR / .deb / .rpm). See [MIGRATION.md](MIGRATION.md).

## Supported browsers

Neon patches any Chromium-family browser. The following are auto-discovered out of the box:

| Browser | macOS path | Linux path(s) |
|---|---|---|
| [Helium](https://helium.computer) | `/Applications/Helium.app` | `/opt/helium-browser-bin` |
| [Thorium](https://thorium.rocks) | `/Applications/Thorium.app` | `/opt/chromium.org/thorium`, `/opt/thorium-browser` |
| [ungoogled-chromium](https://ungoogled-software.github.io/ungoogled-chromium-binaries/) | `/Applications/Chromium.app` | `/usr/lib/chromium`, `/usr/lib64/chromium` |
| [Chromium](https://www.chromium.org/) | `/Applications/Chromium.app` | `/usr/lib/chromium-browser` |

Additional Chromium-family browsers are auto-discovered by scanning `/Applications/*.app` (macOS) and `/opt`, `/usr/lib`, `/usr/lib64`, `/usr/local/lib` (Linux) for the Chromium framework signature.

You can add custom browsers via `~/.config/neon/config.toml`:

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
- This is a DRM platform constraint enforced by the studios, **not a Neon limitation**. No software patch can change it.
- Spotify, YouTube Music, and audio-only services work at full quality (DRM tier doesn't bound audio bitrate).
- 1080p SDR works on most services. Some services downgrade further (Netflix sometimes caps L3 at 540p depending on title).

Hardware-DRM L1 requires a Widevine binary signed by your device's TPM/Secure Enclave + browser binary signed by the browser vendor + CDN-side allow-listing. None of that exists for de-Googled Chromium forks. If you need 4K HDR, you need a device blessed by the studios — Apple TV, smart TV, official Edge/Safari/Chrome.

There's an experimental escape hatch — `neon stream` — that runs a Win11 IoT VM with GPU + TPM passthrough and streams its desktop back via Looking Glass. **It requires dual-GPU hardware** (single-GPU laptops can't use it; the host has no GPU left while the VM runs). And it gives you 4K *with tone-mapped HDR*, not true HDR end-to-end (Wayland HDR + Looking Glass HDR confluence is ~2026). Behind the `experimental-bridge` Cargo feature flag, off by default. See the V3 section in [ROADMAP.md](ROADMAP.md) for the honest hardware-and-quality matrix before you opt in.

## Features

- **One binary, two modes.** The same `neon` executable is both the CLI and the long-running tray daemon. No daemon-spawn race conditions, no second-source-of-truth bugs.
- **Atomic patching with rollback.** Every patch snapshots the original framework, writes the new one to a staging copy, and atomic-renames into place (`renameat2(RENAME_EXCHANGE)` on Linux, `renameatx_np(RENAME_SWAP)` on macOS). A crash mid-patch never destroys the browser bundle.
- **Browser-running detection.** Refuses to patch a running browser by default; the daemon defers and retries automatically when the browser quits (mtime stable for 30s).
- **Tray icon + native notifications.** Per-browser status, one-click re-patch, native success/failure notifications via libnotify (Linux) or NSUserNotificationCenter (macOS).
- **`neon doctor`** produces structured diagnostics with EME error-code translation (Netflix N-codes, Disney+ codes, Spotify codes, etc.) — paste a Netflix code right into `neon doctor N8156-6024` for actionable advice.
- **`neon repair`** brings any broken state back to working in one command.
- **Opt-in error reporting.** Default off. If enabled in `neon init`, categorized failure reports flow to a Cloudflare Worker so trends become visible without depending on user-filed issues. No PII; no telemetry; only failures.
- **Mozilla manifest fallback chain.** Primary: `hg.mozilla.org`. Fallback: GitHub mirror. Final fallback: 24h-cached manifest. Survives `hg.mozilla.org` flakes (which is why Mozilla mirrors the manifest themselves).
- **Migration from V1.** Detects and cleans up legacy bash installs, V1 Homebrew formula installs, AUR / `.deb` / `.rpm` packages, with a pkg-manager-aware uninstall hint sniffed from `/etc/os-release`.

## CLI reference

| Command | Description |
|---|---|
| `neon` | Run the tray daemon (default when invoked without args) |
| `neon init` | Interactive first-run wizard |
| `neon setup` | Non-interactive install (scriptable; runs migration first) |
| `neon patch [--force] [--dry-run] [<browser>]` | Patch one or more browsers |
| `neon status [--json] [--watch]` | Show per-browser patch status |
| `neon list-browsers [--all] [--json]` | Enumerate known + auto-discovered browsers |
| `neon doctor [--json] [--share] [<error-code>]` | Diagnostics + EME error code translation |
| `neon test` | EME health-check against Shaka Player demo |
| `neon update widevine [--rollback] [--cdm-source <url>]` | Update the Widevine CDM |
| `neon update self [--rollback]` | Self-update Neon |
| `neon repair` | uninstall + setup composition |
| `neon launch <browser>` | Verify-then-launch wrapper (re-patches if needed) |
| `neon uninstall` | Remove daemon + cache (preserves browser bundles) |
| `neon completion <shell>` | Generate shell completions (bash/zsh/fish/powershell) |
| `neon manpage` | Generate man page (roff) |

Global flags: `-v`/`-vv` for verbose logging, `-q` to silence non-error output, `--no-color` to disable colored output (`NO_COLOR` env honored), `--json` for structured output where applicable.

## How it works

1. **Manifest fetch.** `neon update widevine` pulls Mozilla's `widevinecdm.json` (or the GitHub mirror, or the 24h cache), parses the platform-specific entry (`Linux_x86_64-gcc3` / `Darwin_x86_64-gcc3-u-i386-x86_64` / `Darwin_arm64-gcc3`), and resolves the CRX3 download URL + SHA-512.
2. **Download.** CRX3 (Chrome Extension v3) is downloaded to `~/.cache/neon/widevine/downloads/<hash>.crx3`, SHA-512 verified, ZIP body extracted to `~/.cache/neon/widevine/<version>/`.
3. **Patch.** For each detected browser, Neon snapshots the framework directory, writes the CDM in, runs platform-specific finalization (`xattr -cr` + `codesign --force --deep -s -` on macOS; just `chmod 0755` on Linux), and atomic-renames the staging copy into place.
4. **Daemon.** The daemon (LaunchAgent / systemd-user unit) watches each browser's framework path via `notify` (FSEvents on macOS, inotify on Linux). When a browser self-updates, the watcher fires, the daemon checks the browser is closed, re-patches, and emits a desktop notification.
5. **Sleep/wake hooks.** On wake-from-sleep, the daemon re-verifies every browser's patch status (browsers can update via package manager while the laptop is asleep).

Module-level rustdoc covers the patch protocol, atomic-rename mechanics, and the daemon IPC envelope in detail — `cargo doc --open` after cloning to browse it locally.

## Why Neon

Helium, Thorium, ungoogled-chromium, and similar Chromium forks intentionally remove Google's proprietary blobs (including the Widevine CDM) for privacy / de-Googling reasons. Streaming sites won't play DRM-protected video without a CDM, so a fresh install of any of these browsers can't watch Netflix.

Neon fills that gap. It downloads the CDM from the same Mozilla manifest that Firefox uses, drops it into the browser bundle, and keeps it in sync as the browser updates. This is the same workflow as `vikas5914/helium-drm-fixer` (which Neon is a successor to) but with cross-platform support, atomic patching, no-root user-session daemon, and integrated diagnostics.

If you're using Helium, Thorium, ungoogled-chromium, or a custom-built Chromium and you want Netflix to work — Neon is for you.

If you're using regular Chrome, regular Edge, regular Brave, or Firefox — you don't need Neon. Those browsers ship a working Widevine binary already.

## Requirements

- macOS (x86_64 or aarch64) or Linux (x86_64).
- On Linux: any tray bar that speaks the StatusNotifierItem protocol — KDE Plasma, sway/Hyprland with waybar, Quickshell-based shells (noctalia, Caelestia), Cinnamon, etc. Vanilla GNOME [removed tray support in 2017](https://blogs.gnome.org/aday/2017/08/31/status-icons-and-gnome/) and needs the [AppIndicator extension](https://extensions.gnome.org/extension/615/appindicator-support/). Without a working tray bar, the daemon falls back to notifications-only.
- A Chromium-family browser to patch.

ARM64 Linux (Asahi, Pi) and Windows aren't supported in V2 — see [ROADMAP.md](ROADMAP.md) for the future plans.

## Project posture

Neon is maintained by one person on an **Arch Linux laptop**. Arch (and Arch-like distros) get first-class testing. **macOS, Debian / Ubuntu, Fedora / RHEL, Windows, and ARM64 are best-effort and contributor-driven** — Nick can write the code but needs people on those platforms to verify it works and file issues when it doesn't. See [ROADMAP.md](ROADMAP.md#maintenance-posture) for details and a list of items currently tagged `[needs <platform> verifier]`. PRs on those platforms are very welcome.

## Documentation

- [MIGRATION.md](MIGRATION.md) — upgrading from V1 (bash, Homebrew, DMG, AUR, .deb / .rpm)
- [ROADMAP.md](ROADMAP.md) — V2.1 / V3 / future plans, maintenance posture
- [CONTRIBUTING.md](CONTRIBUTING.md) — dev setup, conventional commits, PR conventions
- [SECURITY.md](SECURITY.md) — disclosure policy, supported versions
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [CHANGELOG.md](CHANGELOG.md) — release history

## License

MIT
