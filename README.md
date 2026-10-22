# Silvervine — Windows-compatible fork

[![CI](https://github.com/nicholasraimbault/silvervine/actions/workflows/ci.yml/badge.svg)](https://github.com/nicholasraimbault/silvervine/actions/workflows/ci.yml)

Silvervine installs and maintains Widevine L3 for compatible Chromium-family browsers that do not bundle it. This fork adds Windows x64 support while retaining the upstream Linux and macOS backends.

## Install

### Windows x64

Build with [Rust](https://rustup.rs/) and Visual Studio Build Tools (Desktop development with C++), or download the `silvervine-windows-x64` artifact from this fork's CI:

```powershell
cargo build --release --locked
.\target\release\silvervine.exe setup
.\target\release\silvervine.exe status
.\target\release\silvervine.exe test --browser Helium
```

Keep the executable in a permanent location before running `setup`: its per-user Startup shortcut points to that file. Close the browser first. Use `setup --no-daemon` for manual installation only. No administrator privileges are required; the CDM is installed in the browser's user-data directory, not Program Files.

Portable browsers and custom profiles can be configured in `%APPDATA%\silvervine\config.toml`:

```toml
[[browsers]]
name = "Helium"
install_path = 'C:\Browsers\Helium'
user_data_dir = 'C:\Users\you\AppData\Local\Helium\User Data'
```

`user_data_dir` must be absolute and must identify the profile actually used by that browser. Silvervine passes it when launching/probing configured Windows browsers. Unknown products require this explicit path. Recognized Helium, Thorium and Chromium products use their standard LocalAppData profiles.

Windows builds use Mozilla's SHA-512-verified Windows DLL, immutable version directories, and atomic component-registration updates. Existing conflicting versions are preserved rather than overwritten. The tray daemon uses user-restricted local named pipes and a native Windows tray. Hardware acceleration diagnostics and hardware DRM are not provided.

Verified locally with Helium 0.20.1.1 x64 and Widevine 4.10.3112.0: browser EME baseline and software-secure video decoding accepted. Streaming-service playback and sleep/resume hardware behavior were not tested. Windows ARM64 and 32-bit builds are not supported. Upstream releases and their shell installer below do **not** contain this Windows port; self-update requires a matching fork release/receipt, not an upstream installer.

### Linux and macOS (upstream)

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nicholasraimbault/silvervine/releases/latest/download/silvervine-installer.sh | sh
silvervine setup
```

The installer places `silvervine` in `$CARGO_HOME/bin` (usually `~/.cargo/bin`). If the command is not found, add that directory to `PATH` or run `~/.cargo/bin/silvervine setup`.

Setup detects browsers, downloads Widevine through Mozilla's distribution manifest, verifies its SHA-512 digest, attempts to patch each browser, and registers a user-session daemon. Run `silvervine status` afterward to verify the result.

On Linux, system-owned browsers may require administrator approval for patching. The registered daemon remains in your user session.

Release archives and checksums are available from [GitHub Releases](https://github.com/nicholasraimbault/silvervine/releases).

## Supported browsers

Built-in detection covers [Helium](https://helium.computer), [Thorium](https://thorium.rocks), [ungoogled-chromium](https://ungoogled-software.github.io/ungoogled-chromium-binaries/), and [Chromium](https://www.chromium.org/). Silvervine also scans standard application directories for compatible Chromium layouts.

Custom installations can be added to the configuration file:

- Linux: `~/.config/silvervine/config.toml`
- macOS: `~/Library/Application Support/silvervine/config.toml`
- Windows: `%APPDATA%\silvervine\config.toml`

```toml
[[browsers]]
name = "My Browser"
install_path = "/home/me/my-browser" # Linux
# bundle_path = "/Users/me/Applications/My Browser.app" # macOS

[updates]
# Off by default. When true, the daemon applies the latest *stable* GitHub
# release via silvervine-update (cargo-dist sidecar + receipt). Never mid-patch.
auto_apply = false
```

Chrome, Edge, Brave, and Firefox already manage Widevine and do not need Silvervine.

## Behavior and limitations

Silvervine provides software-only Widevine L3. Playback quality is controlled by each streaming service and may be lower than in an officially supported browser. Silvervine does not provide hardware-backed L1 DRM or guarantee HD, 4K, or HDR playback.

Silvervine refuses to patch a running browser unless forced on Unix. Windows always requires the browser to be closed, including with `--force`, because component registration modifies Local State. It stages and verifies a complete CDM tree before atomically publishing it. On macOS and Windows, Silvervine installs the component in the browser's per-user profile and leaves the vendor application untouched. The user-session daemon watches for browser updates and CDM changes.

## Commands

| Command | Purpose |
|---|---|
| `silvervine` | Run the tray daemon |
| `silvervine setup` | Configure browsers and the daemon |
| `silvervine init` | Run the interactive setup wizard |
| `silvervine patch [browser]` | Patch one or all detected browsers |
| `silvervine status` | Show browser and daemon status |
| `silvervine list-browsers` | List detected browsers |
| `silvervine doctor [error-code] [--media-stack]` | Run diagnostics, collect passive media evidence, or explain an EME error |
| `silvervine test [--browser <name>]` | Run an explicit browser-reported EME capability check |
| `silvervine update widevine` | Update or roll back the CDM |
| `silvervine launch <browser>` | Verify, patch if needed, then launch |
| `silvervine repair` | Rebuild Silvervine's local state |
| `silvervine uninstall [--purge]` | Remove the daemon and cache; `--purge` also removes config; the binary and browser changes remain |

Run `silvervine --help` or `silvervine <command> --help` for all options, JSON output, shell completions, and man-page generation.

`silvervine doctor --media-stack` does not launch a browser or access the network. It
inspects local browser/CDM versions, binary architecture, Silvervine ownership
and digest provenance, and a fixed allowlist of optional graphics utilities.
`silvervine test` is the explicit live mode: it opens the selected browser with
its normal profile against a tokenized `127.0.0.1` page, then caches the result
only for the exact browser version and verified CDM digest. Use
`silvervine test --url <url>` to open a manual test page without an automated
result. Browser capability evidence is not proof of certified L1, HD/4K access,
or streaming-service entitlement.

## Upgrading an existing installation

Silvervine automatically migrates configuration, cache, logs, and user-daemon registration created by earlier releases of this project. `silvervine setup` also detects legacy Bash, Homebrew, AUR, `.deb`, and `.rpm` installations and provides package-manager-specific cleanup guidance.

The former Homebrew tap is retired. See [MIGRATION.md](MIGRATION.md) for paths, conflict handling, and recovery instructions.

## Platform support

This fork targets Windows x64, x86_64 Linux, and Intel or Apple Silicon macOS. Windows CI builds a standalone executable artifact. Linux and macOS retain upstream CI; they were not re-exercised during the Windows port. Linux ARM64, Windows ARM64 and Windows x86 are unsupported.

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
