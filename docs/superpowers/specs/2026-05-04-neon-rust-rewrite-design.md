# Neon V2: Rust Rewrite Design

**Date:** 2026-05-04
**Status:** Draft — awaiting final user sign-off
**Replaces:** Existing bash + Swift + Go implementation

## Summary

Replace the current three-language implementation (bash scripts + Swift macOS menu bar app + Go Linux systray app) with a single Rust binary that handles CLI, daemon, and tray UI in one codebase. Distribute as a static musl/macOS-native binary via a unified `curl | sh` installer for both platforms.

The rewrite consolidates ~1,100 lines of mixed bash/Swift/Go (with three parallel implementations of browser detection, file watching, and patch state) into one Rust crate with a single source of truth, atomic patching, integrated error reporting, and substantially better failure-mode handling.

## Motivation

### Current architecture pain points

The existing implementation has the same logic implemented three times across three languages:

| Concern | bash | Swift | Go | Drift risk |
|---|---|---|---|---|
| Browser list | `fix-drm.sh` array | `main.swift` tuples | `browser.go` struct | High |
| "Is patched" check | `fix-drm.sh:115-128` | `main.swift:112-118` | `browser.go:28-31` | High |
| File watching | LaunchDaemon `WatchPaths` / systemd `.path` | `DispatchSourceFileSystemObject` | `fsnotify` | Already drifted |
| Privilege escalation | `osascript` / `sudo` | `osascript` | `pkexec` / `sudo` | Path-specific bugs |
| Daemon model | Root LaunchDaemon / systemd | In-app watcher (no root) | In-app watcher | Two competing models on Mac |

Adding a new browser requires touching all three implementations. This multiplier is the primary maintenance cost.

### Verified failure modes in the current code

1. **`rm -rf $app_path; mv $tmp $app_path`** is not atomic — process death between `rm` and `mv` permanently destroys the browser bundle.
2. **No browser-running detection** — patches a running browser, leaving stale framework references.
3. **No concurrent-patch protection** — daemon and CLI can race on the same file.
4. **Single point of failure on `hg.mozilla.org`** for the Widevine version manifest. PR #1 already shows this URL has been intermittently failing.
5. **No migration path** for existing bash-installed users when upgrading.
6. **Zero tests** anywhere in the codebase.
7. **Issues disabled** on the GitHub repo — no user feedback loop.
8. **ARM64 LaCrOS extraction** does not patch the binary for vanilla glibc / 16K-page systems, so the Apple Silicon path likely doesn't actually work at runtime.

## Goals

- One Rust binary, one source of truth for browsers / patching / detection / file watching.
- Atomic, recoverable patching (no possible state where the user's browser is destroyed).
- One install command per platform: `curl -fsSL <url>/neon-installer.sh | sh`.
- Daemon runs in user session; privilege escalation only when actually writing to browser bundles.
- Native notifications for patch events; tray icon for persistent status.
- `neon doctor` produces structured diagnostic output with actionable error-code translation.
- `neon repair` brings any broken state back to working in one command.
- Opt-in error reporting so failure-mode trends become visible without depending on user-filed issues.
- Release pipeline fully automated via `cargo-dist` (binary builds, multi-platform artifacts, installer script).

## Non-goals

- Windows support in V1 (planned V2; documented in ROADMAP).
- ARM64 Linux support in V1 (cut — current implementation likely doesn't work on Apple Silicon Asahi anyway; revisit in V2 with proper ELF binary patching).
- Firefox-family or principled-privacy-browser support (verified out of scope: Firefox auto-downloads Widevine on x86_64; LibreWolf has built-in toggle; Tor/Mullvad/Cromite explicitly reject DRM).
- Homebrew distribution (dropped; `curl | sh` covers both Mac and Linux).
- AUR / `.deb` / `.rpm` registry publishing in V1 (deferred to V1.1 if user demand exists).
- macOS notarization or paid Apple Developer account.
- Browser extension companion (Chromium sandbox prevents writing to browser bundle from within an extension).
- Codec installation helpers (verified: Helium, Thorium ship full codecs; not Neon's job).
- VAAPI hardware decode configuration (verified: Helium has `use_vaapi=true`; out of scope).

## Architecture

### One binary, two modes

```
neon (single Rust binary, ~10MB statically-linked)
├── Tray mode (default subcommand: no args)
│   - Long-running process in user session
│   - Tray icon (libayatana-appindicator on Linux, NSStatusItem on macOS)
│   - File watcher (notify crate: inotify / FSEvents)
│   - Notification trigger on patch events
│   - Hosts IPC socket for CLI ↔ tray communication
└── CLI mode (any other subcommand)
    - One-shot operations
    - Can run independently of tray, OR signal the running tray
    - Privilege-escalation re-invokes neon itself with elevated rights
```

### Module layout

```
src/
├── main.rs                  # CLI dispatcher
├── cli/
│   ├── mod.rs               # subcommand definitions (clap derive)
│   ├── init.rs              # interactive first-run wizard
│   ├── setup.rs             # non-interactive install (scriptable)
│   ├── patch.rs             # patch one or more browsers
│   ├── status.rs            # text + JSON status output
│   ├── list_browsers.rs     # enumerate known + discovered browsers
│   ├── doctor.rs            # diagnostics + error-code translation
│   ├── test.rs              # EME health-check
│   ├── update.rs            # widevine + self-update
│   ├── repair.rs            # uninstall + setup composition
│   ├── launch.rs            # verify-then-launch wrapper
│   ├── uninstall.rs         # remove daemon, cache
│   ├── completion.rs        # generate shell completions
│   └── manpage.rs           # generate man page
├── widevine/
│   ├── mod.rs               # public API
│   ├── manifest.rs          # parse Mozilla widevinecdm.json (with URL fallback chain)
│   ├── download.rs          # CRX3 download + SHA-512 verify + integrity recheck
│   ├── extract.rs           # CRX3 → Widevine directory
│   └── cache.rs             # ~/.cache/neon/widevine/<version>/ management + rollback
├── browsers/
│   ├── mod.rs               # Browser trait + detection orchestration
│   ├── known.rs             # Helium / Thorium / uChromium / Chromium constants per platform
│   ├── discovery.rs         # filesystem + process-based auto-discovery
│   └── config.rs            # ~/.config/neon/config.toml — custom browser entries
├── patch/
│   ├── mod.rs               # public patch API + atomic patch protocol
│   ├── linux.rs             # #[cfg(target_os = "linux")] - WidevineCdm placement
│   ├── macos.rs             # #[cfg(target_os = "macos")] - bundle write + xattr -cr + codesign
│   └── backup.rs            # snapshot / rollback / atomic rename helpers
├── daemon/
│   ├── mod.rs               # tray + watcher orchestration + heartbeat
│   ├── tray.rs              # tray-icon crate UI
│   ├── watcher.rs           # notify crate (cross-platform fsnotify)
│   ├── ipc.rs               # Unix socket for CLI ↔ tray comms
│   ├── lifecycle.rs         # auto-register LaunchAgent / systemd-user unit
│   └── power.rs             # sleep/wake hooks (NSWorkspace / logind)
├── platform/
│   ├── mod.rs               # paths trait + platform detection
│   ├── linux.rs             # XDG paths, polkit/pkexec, systemd-user units
│   └── macos.rs             # ~/Library paths, osascript, LaunchAgent plists
├── eme/
│   ├── mod.rs               # EME error code → actionable advice mapping
│   └── test.rs              # headless browser test harness for `neon test`
├── notify.rs                # native notifications via notify-rust + platform fallbacks
├── lockfile.rs              # flock-based concurrent-patch protection
├── error.rs                 # categorized error type + reporting
├── reporter.rs              # opt-in failure reporting (categorized payload)
├── migration.rs             # detect + remove old bash-installed Neon
├── config.rs                # global config schema (~/.config/neon/config.toml)
├── log.rs                   # tracing setup, log file rotation
└── hooks.rs                 # ~/.config/neon/hooks/ runner
```

### Key external crates

All chosen for cross-platform support and active maintenance:

| Crate | Purpose | Notes |
|---|---|---|
| `clap` (with `derive`) | CLI argument parsing | + `clap_complete`, `clap_mangen` |
| `notify` | Cross-platform file watching | inotify / FSEvents abstraction |
| `tray-icon` (Tauri) | Tray icon UI | Linux requires GTK + libayatana-appindicator runtime |
| `notify-rust` | Native notifications | macOS lacks action-button support; document this |
| `reqwest` (with `rustls-tls`) | HTTPS for manifest + Widevine CRX | No OpenSSL dependency |
| `sha2` | SHA-512 verification | |
| `serde` / `serde_json` / `toml` | Config + manifest parsing | |
| `tracing` + `tracing-subscriber` | Structured logging | |
| `self_update` (with `signatures` feature + `zipsign`) | Self-update | Privilege handling requires custom wrapper |
| `dialoguer` or `inquire` | Interactive prompts for `neon init` | |
| `fs2` | `flock`-based lockfile | |
| `nix` | `renameat2` (Linux) for atomic rename | |
| `sysinfo` | Process scanning for browser-running detection | |
| `dirs` | XDG / Apple-conventional paths | |
| `anyhow` / `thiserror` | Error handling | |

## CLI surface

```
neon                                # Run tray (default)
neon init                           # Interactive first-run wizard
neon setup                          # Non-interactive install (for scripts/CI)
neon patch [--force] [--dry-run] [<browser>]
neon status [--json] [--watch]
neon list-browsers [--all] [--json]
neon doctor [--json] [--share] [<error-code>]
neon test                           # EME health-check
neon update [widevine|self] [--rollback] [--cdm-source <url>]
neon repair                         # uninstall + setup composition
neon launch <browser>               # verify-then-launch wrapper
neon uninstall
neon completion <shell>             # generate completions
neon manpage                        # generate man page

Global flags:
  -v, --verbose             # one or more -v increases log level
  -q, --quiet               # silence non-error output
  --no-color                # disable colored output (NO_COLOR env honored)
  --json                    # structured JSON output (where applicable)
```

## Data flow

### Patch flow (one browser)

```
1. Acquire lockfile  ~/.cache/neon/patch.lock  (flock exclusive)
2. Verify Widevine cache integrity (SHA-512 against manifest)
   ├─ if missing/corrupted → invoke widevine::download  
   └─ if download fails → categorize error, report, abort
3. Detect browser running  (sysinfo + lsof)
   ├─ if running → notify "deferring patch — close <browser>"  
   └─ register file-watch trigger to retry on quit
4. Permission audit  (write access to target paths)
   ├─ if denied → categorize PermissionDenied; if not running as root, escalate via osascript/pkexec
5. Atomic patch:
   a. Snapshot original bundle  → ~/.cache/neon/backups/<browser>-<version>-<timestamp>/
   b. Write CDM into staging copy of bundle
   c. (macOS) xattr -cr staging; codesign --force --deep -s - staging
   d. Atomic rename: original → original.tmp, staging → original
   e. Remove original.tmp
   ├─ on any failure between (a) and (e) → restore from snapshot, report
6. Verify post-patch:
   ├─ check CDM file present at expected path
   ├─ (optional, if `neon test` invoked) run EME health-check
7. Update state file: ~/.config/neon/state.json — { browser → patched_version, timestamp }
8. Emit notification: "Patched <browser> <version>"
9. Run post-patch hook: ~/.config/neon/hooks/post-patch (if exists)
10. Release lockfile.
```

### Update flow (Widevine)

```
1. Acquire ~/.cache/neon/update.lock
2. Fetch Mozilla manifest with URL fallback chain:
   a. https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/content/gmp-sources/widevinecdm.json
   b. https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/toolkit/content/gmp-sources/widevinecdm.json
   c. ~/.cache/neon/last-manifest.json (if recent enough; 24h TTL)
   ├─ all fail → ManifestFetchFailed; abort.
3. Parse manifest, select platform key (Darwin_arm64-gcc3 / Darwin_x86_64-gcc3-u-i386-x86_64 / Linux_x86_64-gcc3).
4. Compare manifest version against cached version.
   ├─ same → no-op (unless --force)
   └─ newer → proceed
5. Download CRX3, verify SHA-512, extract.
6. Stage to ~/.cache/neon/widevine/<version>/ (do not overwrite previous yet).
7. Update symlink: ~/.cache/neon/widevine/current → <version>.
8. Re-patch all currently-patched browsers to use new version.
9. Old versions: keep latest 3, prune older.
10. Release lockfile.
```

### Daemon lifecycle

```
Start (LaunchAgent / systemd-user fires):
1. Read state file, resolve last known browser configurations.
2. Create tray icon, build menu.
3. Start file watcher on browser install paths.
4. Start IPC listener on Unix socket  (~/.cache/neon/daemon.sock, mode 0600).
5. Start heartbeat thread: write ~/.cache/neon/heartbeat every 60s.
6. Subscribe to power notifications (NSWorkspaceDidWakeNotification / logind PrepareForSleep).
7. Periodic CDM integrity check: weekly, recompute SHA-512 of cached CDM, redownload on mismatch.

On file watch event (debounced 2s):
- Resolve which browser changed
- Verify it's a meaningful change (version directory change, not just Atime touch)
- Trigger patch flow for that browser
- Update tray menu

On wake-from-sleep:
- Re-read state file (browsers may have been updated by an external mechanism)
- Verify each browser's patch status
- Re-patch any unpatched

On IPC message from CLI:
- Dispatch (`patch`, `status`, `update`, `repair`, etc.)
- Return result over socket

On quit signal:
- Cancel watchers, close socket, remove heartbeat file.
```

### IPC contract (CLI ↔ daemon)

Daemon listens on `~/.cache/neon/daemon.sock`. Messages are length-prefixed JSON:

```json
// Request
{ "method": "status" }
{ "method": "patch", "params": { "browser": "Helium", "force": false } }
{ "method": "trigger_check" }

// Response
{ "ok": true, "result": { ... } }
{ "ok": false, "error": { "category": "PermissionDenied", "message": "..." } }
```

If CLI command is invoked while daemon isn't running:
- `status`, `list-browsers`, `doctor`: read state file directly; no daemon required
- `patch`, `update`, `repair`: execute directly (CLI takes its own lockfile)
- `init`, `setup`, `uninstall`: don't talk to daemon (these manage daemon lifecycle)

## Browser support

### Known browsers (compiled-in constants)

```rust
// browsers/known.rs
pub const KNOWN_MACOS: &[BrowserSpec] = &[
    BrowserSpec { name: "Helium",   bundle: "Helium",   framework: "Helium Framework" },
    BrowserSpec { name: "Thorium",  bundle: "Thorium",  framework: "Thorium Framework" },
    BrowserSpec { name: "Chromium", bundle: "Chromium", framework: "Chromium Framework" },
];

pub const KNOWN_LINUX: &[BrowserSpec] = &[
    BrowserSpec { name: "Helium",             paths: &["/opt/helium-browser-bin"] },
    BrowserSpec { name: "Thorium",            paths: &["/opt/chromium.org/thorium", "/opt/thorium-browser"] },
    BrowserSpec { name: "ungoogled-chromium", paths: &["/usr/lib/chromium", "/usr/lib64/chromium"] },
    BrowserSpec { name: "Chromium",           paths: &["/usr/lib/chromium-browser"] },
];
```

### Auto-discovery

- **macOS:** scan `/Applications/*.app`. For each, check `Contents/Frameworks/*.framework/Versions/<n>.<n>...`. If matches Chromium framework structure, add to detected list.
- **Linux:** scan `/opt/*`, `/usr/lib/*`, `/usr/lib64/*`, `/usr/local/lib/*`. For each directory, check for presence of `chrome-sandbox` or `chromium-sandbox`. If present, add to detected list.
- **Process-based fallback:** scan running processes via `sysinfo`. For each Chromium-like process, resolve binary path → install dir.

### Custom browser config (`~/.config/neon/config.toml`)

```toml
[notifications]
on_success = true
on_failure = true

[reporting]
opt_in_error_reporting = false  # default off; user opts in during `neon init`
endpoint = "https://errors.neon.example/v1/report"  # configurable

[[browsers]]
name = "MyCustomBrowser"
# macOS:
bundle_path = "/Users/me/Applications/MyCustomBrowser.app"
framework_name = "MyCustomBrowser Framework"
# Linux alternative:
# install_path = "/home/me/dev/my-build"

[hooks]
post_patch = "~/.config/neon/hooks/post-patch"
post_update = "~/.config/neon/hooks/post-update"
```

## Error handling & resilience

### Categorized errors

```rust
// error.rs
#[derive(Debug, Serialize)]
pub enum ErrorCategory {
    PermissionDenied,
    BrowserRunning,
    NetworkError,
    ManifestFetchFailed,
    HashMismatch,
    DiskFull,
    UnknownBundleStructure,
    DaemonNotRunning,
    StateCorrupted,
    UnsupportedPlatform,
    Other,
}
```

Every error surfaces a category. Notifications, `doctor`, and the (opt-in) reporter use the category for grouping and actionable advice.

### Atomic patch protocol

Use platform-specific atomic rename:
- **Linux:** `renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_EXCHANGE)` — single syscall, atomic swap
- **macOS:** `renameatx_np(AT_FDCWD, src, AT_FDCWD, dst, RENAME_SWAP)` — single syscall, atomic swap (APFS only)
- **Fallback** (older Linux, non-APFS macOS): two-step — `rename(orig, orig.tmp); rename(staging, orig); rm orig.tmp` — atomic in the typical case but not perfectly crash-safe; documented limitation

### Mozilla manifest URL fallback chain

```
1. https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/content/gmp-sources/widevinecdm.json
2. https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/toolkit/content/gmp-sources/widevinecdm.json
3. ~/.cache/neon/last-manifest.json  (TTL 24h, surfaced as warning)
```

If all three fail, return `ManifestFetchFailed` and surface `--cdm-source <url>` as user workaround.

### Migration from bash-installed Neon

`neon setup` and `neon init` first run a migration check:

```
- Detect /Library/LaunchDaemons/com.neon.fix-drm.plist  → unload + remove (with sudo)
- Detect /etc/systemd/system/neon-fix-drm.path           → disable + remove
- Detect /etc/systemd/system/neon-fix-drm.service        → remove
- Detect /usr/lib/neon/                                   → remove
- Detect ~/Library/LaunchAgents/com.neon.app.plist       → unload + remove
- Detect ~/.config/autostart/neon.desktop                 → remove
- Preserve: ~/.local/share/WidevineCdm/                  → migrate to ~/.cache/neon/widevine/<version>/
```

Existing users running `neon setup` get a friendly summary: "Found legacy Neon installation; cleaning up before installing V2."

### Concurrent patch protection

`flock` exclusive lock on `~/.cache/neon/patch.lock`. Second invocation blocks (CLI) or skips with notification (daemon, to avoid blocking UI thread).

### Heartbeat / liveness

Daemon writes Unix timestamp to `~/.cache/neon/heartbeat` every 60s. `neon doctor` reads it; if stale (>5min), reports daemon-not-running with instructions to relaunch.

### Periodic CDM integrity check

Weekly, daemon recomputes SHA-512 of cached CDM against the manifest's expected hash. On mismatch: trigger redownload, notify user, log incident.

### Browser-running detection

Before any patch operation, scan running processes for the browser binary (`sysinfo` crate matching on path). If found:
- CLI: refuse with clear "close <browser> first or pass `--force-while-running` (not recommended)" message
- Daemon: defer; register one-shot file watch on browser bundle to retry when modification time stops changing for 30s (suggesting browser has quit)

## Platform-specific design

### macOS

- **Tray:** `NSStatusItem` via `tray-icon` crate (which uses Cocoa under the hood)
- **Notifications:** `notify-rust` (delegates to `mac-notification-sys`); no action-button support — clicking notification opens a `neon doctor` terminal session
- **Privilege escalation:** `osascript -e "do shell script ... with administrator privileges"` — prompts for password via system dialog
- **Daemon registration:** LaunchAgent at `~/Library/LaunchAgents/com.neon.tray.plist`, with `KeepAlive` and `RunAtLoad`
- **Sleep/wake:** subscribe to `NSWorkspaceDidWakeNotification` via `objc` FFI (small unsafe block, well-isolated)
- **Atomic rename:** `renameatx_np` with `RENAME_SWAP` (APFS); fall back to two-step rename otherwise
- **xattr clearing:** shell out to `xattr -cr <path>` (verified `-r` exists; semantics match current bash) — alternative is `xattr` Rust crate with manual recursion
- **Codesign:** shell out to `codesign --force --deep -s - <path>`. (Note: `--deep` is deprecated by Apple as of macOS 13 but still works ad-hoc; preserve current behavior in V1, evaluate inside-out signing in V2.)

### Linux

- **Tray:** `tray-icon` crate using GTK + libayatana-appindicator (runtime dependency; documented in install instructions)
- **Notifications:** `notify-rust` via libnotify / D-Bus; supports action buttons
- **Privilege escalation:** `pkexec` (preferred, GUI prompt) → `sudo` (terminal fallback). Both invoke the same Neon binary with `--as-root` flag for the privileged sub-operation
- **Daemon registration:** systemd-user unit at `~/.config/systemd/user/neon.service` with `Restart=on-failure`
- **Sleep/wake:** subscribe to `org.freedesktop.login1.Manager.PrepareForSleep` via D-Bus (zbus crate)
- **Atomic rename:** `renameat2` with `RENAME_EXCHANGE` (works on ext4/btrfs/xfs/f2fs); fall back to two-step otherwise
- **No-tray fallback:** if libayatana-appindicator absent at runtime, daemon runs in `--no-tray` mode (notifications-only). Documented in error message.

### Caveats documented in design

- macOS notification action buttons not supported (unavoidable platform limitation)
- Linux tray requires GTK + libayatana-appindicator runtime dependency (cannot fully eliminate via static linking)
- Self-update with root-owned binary requires staging-then-escalate pattern (download as user, rename via privilege escalation)

## Testing strategy

### Unit tests

- `widevine::manifest::parse` — sample manifests covering Linux/Darwin keys, malformed input
- `widevine::extract` — sample CRX3 file (committed test fixture)
- `browsers::discovery` — fake `/Applications` and `/opt` directories
- `patch::backup::atomic_rename` — verify rollback semantics with simulated crash points
- `eme::translate_error_code` — Netflix N-codes, Disney+ codes, Spotify codes
- `migration::detect_legacy` — synthesized old-install state on a temp filesystem
- `lockfile` — concurrent acquisition test
- `error::categorize` — every error path produces a category

### Integration tests (real network, gated behind `--ignored` flag)

- Download real Widevine from Mozilla manifest, verify SHA-512
- Round-trip CRX3 extraction
- Manifest URL fallback (block primary, verify fallback succeeds)

### Platform tests in CI matrix

```
ubuntu-latest:  cargo test, integration tests, build static-musl binary
macos-latest:   cargo test, build native binary, smoke-test against a sample .app fixture
```

### EME health-check (`neon test`)

Spawns headless Chromium-family browser against a known EME test page (e.g., Shaka Player demo at `https://shaka-player-demo.appspot.com/`). Parses page-script-emitted result. Reports per-browser EME status. Documented limitations: not all networks/regions can reach the test page; users behind corporate proxies may need offline test fixture.

### Test fixtures

- Sample manifest JSON (offline)
- Sample CRX3 file (small, compiled into test binary)
- Synthesized `.app` bundle structure for Mac patch tests
- Synthesized `/opt/fake-chromium` for Linux patch tests

### Coverage target

70% line coverage minimum (cargo-tarpaulin in CI). Critical paths (patch, atomic-rename, manifest-fetch) at 90%+.

## Distribution & release

### Single distribution channel: `cargo-dist`

`cargo dist init` configures:
- Build matrix: x86_64-apple-darwin, aarch64-apple-darwin, x86_64-unknown-linux-musl
- Installer script: `neon-installer.sh` that detects OS/arch, downloads correct artifact
- Signing: `zipsign` for `.tar.gz` artifacts (signature feature of `self_update` crate)
- Release: triggered by `git tag v<X.Y.Z>` push, GitHub Actions handles everything

### Release flow

```
git tag v0.1.0 && git push --tags
  ↓
GitHub Actions (release.yml from cargo-dist):
  - Build for each target on appropriate runner
  - Sign artifacts with zipsign
  - Upload to GitHub Releases
  - Update neon-installer.sh on the release-assets URL
  - Auto-generate release notes from conventional commits (release-please)
```

User install:
```
curl -fsSL https://github.com/nicholasraimbault/neon/releases/latest/download/neon-installer.sh | sh
```

### Self-update

`neon update self`:
1. Check GitHub Releases for newer version
2. If newer, download to `~/.cache/neon/staging/neon-<new>`
3. Verify zipsign signature
4. If running binary is in user-writable location: atomic rename
5. If running binary is root-owned (`/usr/local/bin/neon`): re-invoke with `osascript`/`pkexec` to perform the rename
6. Notify user of new version

### Versioning

- SemVer 0.x.y during V1 development (breaking changes allowed at minor bumps)
- 1.0.0 when V1 ships and is considered stable
- CHANGELOG auto-generated from conventional commits

## Project hygiene & community

### Repository changes pre-V1 release

- **Re-enable issues** on `nicholasraimbault/neon`
- Add `.github/ISSUE_TEMPLATE/bug.yml` and `feature.yml` (auto-fill bug template from `neon doctor --share`)
- `CONTRIBUTING.md` — build instructions, test commands, PR conventions, conventional commits format
- `SECURITY.md` — disclosure email, supported versions, response SLA
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1 boilerplate
- `ROADMAP.md` — current state, V1.1 plans (AUR/.deb), V2 plans (Windows, ARM64-with-binary-patching)
- `CHANGELOG.md` — managed by release-please
- License remains MIT (unchanged)

### Issue triage & failure visibility

- Opt-in error reporting (default off) writes categorized error reports to a configurable endpoint
- Default endpoint: a simple HTTP receiver Nick controls; payload is `{os, arch, neon_version, browser, browser_version, cdm_version, error_category, redacted_message}`
- No PII; no install/uninstall events; no usage telemetry — only failures
- Privacy policy in repo describes exactly what's sent

## Migration plan for existing users

```
Before V2 release:
- README on master adds banner: "V2 rewrite in progress; see #<discussion>"
- ROADMAP.md added with V2 timeline

V2 release (when shipped):
- Single curl|sh installer:  curl -fsSL .../neon-installer.sh | sh
- First run of neon setup auto-detects legacy bash install and cleans up
- Cached Widevine at ~/.local/share/WidevineCdm/ migrated to ~/.cache/neon/widevine/<version>/
- Old LaunchDaemon (root) replaced with new LaunchAgent (user)
- Old systemd .path unit replaced with new systemd-user service
- User notified via terminal output: "Migrated from legacy install. Run `neon doctor` to verify."

For users on the old DMG / Swift menu bar app:
- README points them to the new installer
- The new installer's setup phase removes the LaunchAgent registered by the old app
- Old Neon.app left in /Applications until user manually deletes (we don't auto-remove user-installed apps)
```

## Out of scope / future work

Items deferred to future versions, documented in ROADMAP.md:

- **V1.1**
  - AUR + `.deb` registry publishing
  - More distribution channels if user demand
  - Hooks `pre-patch` (currently only `post-*` shipped)
  - `neon log` TUI viewer
- **V2**
  - Windows support (multiple upstream issues filed by Windows users)
  - ARM64 Linux with proper ELF binary patching (port `widevine_fixup.py` semantics to Rust)
  - Inside-out codesigning on Mac (replace `--deep`)
- **Indeterminate**
  - Browser version-pinning per-browser
  - Multi-CDM cache with rollback (V1 keeps only "previous" + "current"; full pinning is V2+)
  - Per-machine config sync
  - Headless server / Docker support
  - URL handler (`neon://`)
  - Webhook integrations (Discord/Slack notifications)

## Acceptance criteria for V1

- [ ] All four supported browsers patch successfully on at least one tester's machine each (Helium/Thorium/uChromium/Chromium × macOS/Linux)
- [ ] Atomic patch verified: `kill -9` during patch leaves browser in pre-patch state, never destroyed
- [ ] Migration from existing bash install works without manual intervention
- [ ] `neon doctor` produces useful output for at least 5 known error codes
- [ ] Release pipeline produces signed binaries on `git tag` push, no manual steps
- [ ] CI matrix passes on Linux + macOS for every PR
- [ ] Issues re-enabled with templates that auto-fill diagnostic info
- [ ] CHANGELOG, CONTRIBUTING, SECURITY, ROADMAP exist and are accurate
- [ ] Coverage report shows ≥70% line coverage; ≥90% on patch/manifest paths
- [ ] One-line install (`curl | sh`) works on a fresh Mac and a fresh Linux box
- [ ] V1 binary on disk is statically linked (verify via `file` and `ldd`)
- [ ] No bash, no Swift, no Go in the codebase

## Resolved decisions

1. **Error reporting endpoint:** Self-hosted via Cloudflare Worker + D1 SQLite. Free tier (100k req/day, 5GB DB). Full control, no third-party data sharing. Schema: `(timestamp, neon_version, os, arch, browser, browser_version, cdm_version, error_category, redacted_message)`.
2. **`neon test`:** Ships in V1.
3. **Branch strategy:** Long-lived `v2-rust-rewrite` branch. `master` stays on current bash/Swift/Go V1 until V2 is ready, then squash-merge.
4. **Repository name:** Stays `neon`.

## CI / release pipeline

### Workflows

**`.github/workflows/ci.yml`** — runs on every PR and push to dev branches:

```yaml
matrix: [ubuntu-latest, macos-latest]
steps:
  - cargo fmt --check
  - cargo clippy -- -D warnings
  - cargo test --all-features
  - cargo test --no-default-features      # ensure headless build compiles
  - cargo audit
  - cargo deny check
  - cargo tarpaulin --out Xml             # coverage → codecov.io
  - cargo build --release
```

**`.github/workflows/release.yml`** — generated by `cargo dist init`, triggered on `v*` tag push:

```yaml
matrix:
  - x86_64-apple-darwin
  - aarch64-apple-darwin
  - x86_64-unknown-linux-musl
steps:
  - build statically-linked binary per target
  - sign artifacts via zipsign
  - publish to GitHub Releases
  - generate and upload neon-installer.sh
  - release-please opens CHANGELOG PR for next version
```

### Branch protection

Both `master` and `v2-rust-rewrite`:
- Require PR before merge
- Require all CI status checks to pass
- Solo dev: dismiss the "1 approving review" rule but keep CI gate

### Dependabot + auto-merge

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: cargo
    directory: /
    schedule: { interval: weekly }
    open-pull-requests-limit: 5
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
```

Auto-merge enabled for **Dependabot patch + minor** updates if CI passes. Major updates and human PRs always require manual review. Implementation via `pascalgn/automerge-action` filtered by `semver-patch` / `semver-minor` PR labels.

### MSRV (minimum supported Rust version)

Pinned in `Cargo.toml` (`rust-version = "1.75"`); CI matrix includes MSRV check on stable channel.

## Branch model

```
master                            ← V1 (bash + Swift + Go) — frozen except critical fixes
└─ design/v2-rust-rewrite         ← this spec lives here
   └─ v2-rust-rewrite             ← long-lived V2 development branch
      ├─ feature/cli-skeleton     ← short-lived feature branches
      ├─ feature/widevine-mod
      ├─ feature/atomic-patch
      └─ ...                      ← merged into v2-rust-rewrite via PR + CI
```

When V2 is ready: squash-merge `v2-rust-rewrite` → `master`, tag `v2.0.0`, ship.

---

*This is a design spec, not an implementation plan. Once approved, the next step is to invoke the writing-plans skill to produce a step-by-step implementation plan that breaks V1 into independently-shippable milestones on the `v2-rust-rewrite` branch.*
