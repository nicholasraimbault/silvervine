# Silvervine

[![CI](https://github.com/nicholasraimbault/silvervine/actions/workflows/ci.yml/badge.svg)](https://github.com/nicholasraimbault/silvervine/actions/workflows/ci.yml)

Silvervine installs and maintains Widevine for Chromium-family browsers that do not bundle it. It runs on Linux and macOS, with Windows x64 joining in the **2.3 preview**.

Close your browser, run setup once, and the user-session tray daemon keeps Widevine in place after browser updates. Silvervine supports software-only Widevine L3; streaming services decide playback quality and access.

## Install

Stable release for Linux x64 and macOS (Intel or Apple Silicon):

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nicholasraimbault/silvervine/releases/latest/download/silvervine-installer.sh | sh
silvervine setup
silvervine status
```

The installer adds the binary and updater to `$CARGO_HOME/bin` (normally `~/.cargo/bin`). Reopen your terminal if the command is not found. Linux system-owned browser installations may prompt for administrator approval; the daemon runs as your user.

[Release archives and checksums](https://github.com/nicholasraimbault/silvervine/releases) are also available.

## Try 2.3 RC

2.3 adds **Windows x64**, a **terminal control panel**, and explicit **Stable / Preview update preferences**. RCs require an intentional install; stable users are not automatically moved to them.

Linux / macOS:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nicholasraimbault/silvervine/releases/download/v2.3.0-rc.1/silvervine-installer.sh | sh
```

Windows x64, from PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://github.com/nicholasraimbault/silvervine/releases/download/v2.3.0-rc.1/silvervine-installer.ps1 | iex"
```

Then reopen your terminal, close the browser, and run:

```text
silvervine setup
silvervine tui
```

No GitHub account, Rust installation, or source checkout is needed. See the [Windows guide and test checklist](docs/windows.md). RCs are for testing; Windows streaming-service playback and sleep/resume still need verification on real PCs.

## Browsers

Built-in detection covers Helium, Thorium, ungoogled-chromium, and Chromium where their supported platform layouts are recognized. Add other compatible installations in the terminal UI or [configuration file](docs/usage.md#configuration). Chrome, Edge, Brave, and Firefox manage their own DRM components.

On macOS and Windows, Widevine is installed in the browser's per-user component directory. On Windows the browser must be closed, including when using `--force`.

## Everyday use

| Command | Purpose |
|---|---|
| `silvervine tui` | Manage browsers, diagnostics, updates, logs, and settings |
| `silvervine` | Run the tray daemon |
| `silvervine status` | Check browser and daemon state |
| `silvervine doctor --media-stack` | Inspect local browser, CDM, and media evidence |
| `silvervine test --browser Helium` | Open an explicit browser capability test |
| `silvervine update widevine` | Refresh Widevine and patch browsers |
| `silvervine update self` | Update Silvervine using the saved release channel |

Automatic self-updates default to **off**. The update channel defaults to **Stable**, even when an RC was installed manually. Choose Preview in Settings to receive later RCs; this does not turn on automatic installation. See [updates and terminal controls](docs/usage.md).

## More

[Usage and configuration](docs/usage.md) · [Troubleshooting](docs/troubleshooting.md) · [Roadmap](ROADMAP.md) · [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

Linux ARM64, Windows ARM64/32-bit, hardware-backed L1, and guaranteed HD/4K/HDR streaming are outside current support. Existing Neon users can consult the [legacy migration guide](MIGRATION.md).

Windows support builds on [paparei's Windows port](https://github.com/paparei/silvervine-window), preserved with its original authorship.

[MIT license](LICENSE)
