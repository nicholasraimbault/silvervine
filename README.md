# Silvervine

[![CI](https://github.com/nicholasraimbault/silvervine/actions/workflows/ci.yml/badge.svg)](https://github.com/nicholasraimbault/silvervine/actions/workflows/ci.yml)

Silvervine installs and maintains Widevine L3 for compatible Chromium-family browsers that do not bundle it, enabling DRM-protected media on Linux and macOS.

## Install

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nicholasraimbault/silvervine/releases/latest/download/silvervine-installer.sh | sh
silvervine setup
```

The installer places `silvervine` in `$CARGO_HOME/bin` (usually `~/.cargo/bin`). If the command is not found, add that directory to `PATH` or run `~/.cargo/bin/silvervine setup`.

Setup detects browsers, downloads Widevine through Mozilla's distribution manifest, verifies its SHA-512 digest, attempts to patch each browser, and registers a user-session daemon. Run `silvervine status` afterward to verify the result.

System-owned browsers may require administrator approval for patching. The registered daemon remains in your user session.

Release archives and checksums are available from [GitHub Releases](https://github.com/nicholasraimbault/silvervine/releases).

## Supported browsers

Built-in detection covers [Helium](https://helium.computer), [Thorium](https://thorium.rocks), [ungoogled-chromium](https://ungoogled-software.github.io/ungoogled-chromium-binaries/), and [Chromium](https://www.chromium.org/). Silvervine also scans standard application directories for compatible Chromium layouts.

Custom installations can be added to the configuration file:

- Linux: `~/.config/silvervine/config.toml`
- macOS: `~/Library/Application Support/silvervine/config.toml`

```toml
[[browsers]]
name = "My Browser"
install_path = "/home/me/my-browser" # Linux
# bundle_path = "/Users/me/Applications/My Browser.app" # macOS
# framework_name = "My Browser Framework"               # optional
```

Chrome, Edge, Brave, and Firefox already manage Widevine and do not need Silvervine.

## Behavior and limitations

Silvervine provides software-only Widevine L3. Playback quality is controlled by each streaming service and may be lower than in an officially supported browser. Silvervine does not provide hardware-backed L1 DRM or guarantee HD, 4K, or HDR playback.

Silvervine refuses to patch a running browser unless forced. It creates an exclusive rollback snapshot before each change, verifies the result, and restores the snapshot on failure. The user-session daemon watches for browser updates and re-patches as needed.

## Commands

| Command | Purpose |
|---|---|
| `silvervine` | Run the tray daemon |
| `silvervine setup` | Configure browsers and the daemon |
| `silvervine init` | Run the interactive setup wizard |
| `silvervine patch [browser]` | Patch one or all detected browsers |
| `silvervine status` | Show browser and daemon status |
| `silvervine list-browsers` | List detected browsers |
| `silvervine doctor [error-code]` | Run diagnostics or explain an EME error |
| `silvervine test` | Open the playback health check |
| `silvervine update widevine` | Update or roll back the CDM |
| `silvervine launch <browser>` | Verify, patch if needed, then launch |
| `silvervine repair` | Rebuild Silvervine's local state |
| `silvervine uninstall [--purge]` | Remove the daemon and cache; `--purge` also removes config; the binary and browser changes remain |

Run `silvervine --help` or `silvervine <command> --help` for all options, JSON output, shell completions, and man-page generation.

## Migrating from Neon

Silvervine automatically migrates Neon V2 configuration, cache, logs, and user-daemon registration. `silvervine setup` also detects older Neon V1 Bash, Homebrew, AUR, `.deb`, and `.rpm` installations and provides package-manager-specific cleanup guidance.

The former Homebrew tap is retired. See [MIGRATION.md](MIGRATION.md) for paths, conflict handling, and recovery instructions.

## Platform support

Silvervine supports x86_64 Linux and Intel or Apple Silicon macOS. Linux ARM64 and Windows are unsupported in V2. Linux receives native CI and maintainer testing on Arch; macOS receives native CI with contributor-led hardware verification.

Linux tray integration uses the StatusNotifierItem protocol. Desktops without a compatible tray host can run Silvervine in notifications-only mode.

## Documentation

- [Migration](MIGRATION.md)
- [Roadmap](ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Experimental bridge research](https://github.com/nicholasraimbault/silvervine/tree/experimental-bridge) — unsupported and excluded from releases
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

[MIT](LICENSE)
