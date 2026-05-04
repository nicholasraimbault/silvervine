# Migrating from Neon V1 to V2

V2 is a single-binary Rust rewrite of the V1 bash + Swift + Go implementation. The on-disk layout, daemon model, and CLI surface have all changed. `neon setup` (and its interactive sibling `neon init`) detects most legacy installs and cleans them up automatically; this document covers the per-install-path details and the manual steps that can't be automated.

If you've never installed V1, skip this doc — go straight to the [README install instructions](README.md#install).

## What `neon setup` migrates automatically

The migration logic lives in `src/migration.rs`. On first invocation, `neon setup` calls `migration::detect_legacy_install`, which scans for these legacy artifacts:

| Legacy artifact | Source install path | Action |
|---|---|---|
| `/Library/LaunchDaemons/com.neon.fix-drm.plist` | V1 macOS bash + V1 Homebrew | unload + remove (requires sudo — V2 prompts once) |
| `~/Library/LaunchAgents/com.neon.app.plist` | V1 Mac DMG menu-bar app | unload + remove (no sudo) |
| `/etc/systemd/system/neon-fix-drm.path` | V1 Linux bash + .deb | disable + remove (sudo) |
| `/etc/systemd/system/neon-fix-drm.service` | V1 Linux bash + .deb | remove (sudo) |
| `~/.config/autostart/neon.desktop` | V1 Linux tray app | remove (no sudo) |
| `~/.local/share/WidevineCdm/<version>/` | All Linux V1 paths | migrate to `~/.cache/neon/widevine/<version>/` (no sudo) |
| `/usr/lib/neon/` | V1 Linux .deb | reported but **not** removed (system-managed; user runs `dpkg -r neon-drm`) |

After migration completes, `neon setup` continues with:

- Download Widevine CDM from Mozilla manifest (skipped if a freshly migrated `~/.cache/neon/widevine/<version>/` is recent enough).
- Detect browsers and patch each (atomic patch with snapshot + rollback).
- Register the V2 user-session daemon (LaunchAgent on macOS at `~/Library/LaunchAgents/com.neon.tray.plist`; systemd-user unit on Linux at `~/.config/systemd/user/neon.service`). No root required for the daemon — V2 runs entirely in user session.

`neon setup` prints a summary like:

```
Migrated from legacy install:
  - removed /Library/LaunchDaemons/com.neon.fix-drm.plist
  - removed ~/.config/autostart/neon.desktop
  - migrated ~/.local/share/WidevineCdm/4.10.2710.0 → ~/.cache/neon/widevine/4.10.2710.0
  - skipped /usr/lib/neon/ (run `dpkg -r neon-drm` to remove the V1 .deb package)

V2 setup complete. Run `neon doctor` to verify.
```

## Per-install-path migration steps

### 1. Manual bash install (V1 `install.sh`)

This is the simplest case. The V1 bash install drops a LaunchDaemon (macOS) or systemd `.path` unit (Linux) plus the `~/.local/share/WidevineCdm/` directory.

```sh
curl -fsSL https://github.com/nicholasraimbault/neon/releases/latest/download/neon-installer.sh | sh
neon setup
```

`neon setup` detects the legacy LaunchDaemon / systemd unit, prompts for sudo once (to remove the root-owned daemon files), unloads + removes them, migrates the CDM cache, and installs the V2 daemon. **No manual steps.**

If you previously ran `bash uninstall.sh` and installed V2 from scratch on the same machine, no migration is needed — `neon setup` finds nothing to clean up.

### 2. Homebrew (`nicholasraimbault/neon` tap)

The V1 Homebrew formula installed the same LaunchDaemon as the bash install plus a `neon-install` wrapper script. The tap is being archived 30 days after V2 ships; you'll want to remove it.

```sh
# Uninstall V1 from Homebrew (removes the wrapper scripts; LaunchDaemon left in place)
brew uninstall nicholasraimbault/neon/neon
brew untap nicholasraimbault/neon

# Install V2
curl -fsSL https://github.com/nicholasraimbault/neon/releases/latest/download/neon-installer.sh | sh
neon setup
```

`neon setup` then migrates the LaunchDaemon left behind by `brew uninstall`. **Three commands, fully automatic after that.**

If you skip the `brew untap` step, Homebrew will remember the (now-archived) tap; `brew update` may print warnings. Cleanest to untap.

### 3. Mac DMG / menu-bar app (V1 `Neon.app` from Releases)

The V1 menu-bar app is a Swift `.app` bundle in `/Applications`. It registers itself via a `LaunchAgent` (not a LaunchDaemon — no root required), so the migration is fully user-session.

```sh
# Install V2
curl -fsSL https://github.com/nicholasraimbault/neon/releases/latest/download/neon-installer.sh | sh
neon setup
```

`neon setup` detects `~/Library/LaunchAgents/com.neon.app.plist` and unloads + removes it.

**Manual step:** drag `/Applications/Neon.app` to the Trash. V2 doesn't auto-delete user-installed apps — that crosses a privacy line we don't want to cross.

### 4. Linux AUR (`neon-drm` package)

```sh
# Uninstall the AUR package (removes /usr/lib/neon/, /usr/bin/neon, the systemd units)
pacman -R neon-drm
# or: yay -R neon-drm

# Install V2
curl -fsSL https://github.com/nicholasraimbault/neon/releases/latest/download/neon-installer.sh | sh
neon setup
```

The AUR package's own `pre-remove` hook handles `systemctl disable --now neon-fix-drm.path`. After that, `neon setup` finds nothing left to clean up and proceeds with V2 setup.

V1.1 will publish a V2 AUR package (see [ROADMAP.md](ROADMAP.md)); until then, the curl|sh installer is the supported path on Arch.

### 5. Linux .deb (`neon-drm.deb`)

```sh
# Uninstall the .deb (removes /usr/lib/neon/, /usr/bin/neon, the systemd units)
sudo dpkg -r neon-drm

# Install V2
curl -fsSL https://github.com/nicholasraimbault/neon/releases/latest/download/neon-installer.sh | sh
neon setup
```

The .deb's `prerm` hook handles `systemctl disable --now neon-fix-drm.path`. After `dpkg -r`, the systemd units are gone and `neon setup` proceeds clean.

If you want to skip `dpkg -r` and let `neon setup` detect a partial install, it will: it sees `/usr/lib/neon/` and reports it as `LinuxDebPackage` with `needs_root: true`, but **does not remove it** — the V2 migration logic intentionally won't touch system-managed package files. You'd need to run `dpkg -r neon-drm` yourself anyway.

V1.1 will publish a V2 .deb package (see [ROADMAP.md](ROADMAP.md)).

## Cache migration: `~/.local/share/WidevineCdm/` → `~/.cache/neon/widevine/`

V1 stored the downloaded CDM at `~/.local/share/WidevineCdm/<version>/`. V2 stores it at `~/.cache/neon/widevine/<version>/` per the XDG Cache spec (CDMs are downloadable artifacts, not configuration).

`migration::remove_legacy` invokes `migration::migrate_cdm_cache` to copy the V1 cache into place under the new path. The original V1 directory is left intact (we don't delete user data) — you can `rm -rf ~/.local/share/WidevineCdm` manually after verifying V2 works.

## Rolling back to V1

We strongly recommend not doing this — V1 has known issues (non-atomic patches that can destroy a browser bundle on a poorly-timed `kill -9`, no migration path forward, no way to file bugs). But if you need to:

1. `neon uninstall` — removes the V2 daemon, cache, and config. Browser bundles remain patched (V2 doesn't unpatch on uninstall).
2. Reinstall V1 from your previous install path (Homebrew tap is archived; the `master` branch on GitHub still has the V1 `install.sh` until V2 ships, after which it'll be on a `v1` tag).

If you uninstall V2 and don't reinstall anything, your browsers stay patched until they next update themselves — at which point they're un-patched and DRM stops working until you re-patch.

## Migration troubleshooting

**`neon setup` says "Failed to remove /Library/LaunchDaemons/com.neon.fix-drm.plist".**

The LaunchDaemon file is owned by root. V2 prompts for sudo via `osascript` (macOS) — make sure you typed your password correctly and that your user is in the `admin` group. Re-run `neon setup` to retry.

**`neon setup` says "Skipped /usr/lib/neon (system package)".**

This is expected. V2 won't remove dpkg/pacman-managed files. Run `sudo dpkg -r neon-drm` (or `pacman -R neon-drm`) yourself, then re-run `neon setup`.

**Migration succeeds but Netflix still doesn't work.**

Run `neon doctor`. The output covers heartbeat status, current CDM version, per-browser patch state, and (if you pass an EME error code) translation. Common causes:

- The browser was running during patch and we deferred — close it and run `neon patch` again.
- Streaming service is geo-restricting your account — try a different title or service.
- You're hitting the L3 ceiling for higher resolutions — see [README.md](README.md#the-l3-ceiling--please-read).

If `neon doctor` doesn't surface the issue, run `neon doctor --share` to get a pre-filled GitHub issue URL.

**I removed Neon, my browser updated, and now Netflix doesn't work.**

Reinstall Neon. The browser update overwrote the patched framework with the unpatched original. `curl|sh` + `neon setup` will fix it.

## Schedule

- **V2.0.0 release day** — V2 ships; V1 install paths still work (we don't break V1 users).
- **V2.0.0 + 30 days** — `homebrew-neon` tap archived (read-only). V1 Homebrew users continue to work but won't get updates. Migration to V2 is the supported upgrade.
- **V2.x** — V1 install paths (manual bash, Homebrew, .deb, AUR, DMG) remain supported targets for `neon setup` migration logic indefinitely. We won't drop migration support; V1 users can take their time.
