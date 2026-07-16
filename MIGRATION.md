# Migrating from Neon to Silvervine

Silvervine 2.0 is the renamed Rust successor to Neon. It preserves migration support for both the original Neon V1 Bash/Swift/Go distributions and Neon V2 release candidates. New commands, paths, registrations, and package names use `silvervine`.

If you have never installed Neon, follow the [Silvervine install instructions](README.md#install).

## Install Silvervine

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nicholasraimbault/silvervine/releases/latest/download/silvervine-installer.sh | sh
silvervine setup
```

## Neon V2 data migration

Before logging initializes, every Silvervine invocation checks for Neon V2 user data. When the Silvervine destination is absent, the directory is atomically renamed:

| Neon V2 source | Silvervine destination |
|---|---|
| `~/.config/neon/` | `~/.config/silvervine/` |
| `~/.cache/neon/` | `~/.cache/silvervine/` |
| `~/Library/Application Support/neon/` | `~/Library/Application Support/silvervine/` |
| `~/Library/Caches/neon/` | `~/Library/Caches/silvervine/` |
| `~/Library/Logs/neon/` | `~/Library/Logs/silvervine/` |

The cache move includes tracing logs stored under `logs/`. If the source is absent, the check is an idempotent no-op. If both source and destination exist, Silvervine preserves both and reports the conflict; it never merges, deletes, or overwrites either directory.

A hook path explicitly stored under the old Neon config root resolves to the corresponding migrated Silvervine config root when the old path no longer exists. An existing explicit Neon hook path remains authoritative.

When a prior Neon V2 user daemon is registered, startup performs a locked transition: it records whether Neon is running, stops it, migrates the data, starts Silvervine, and only then retires the retained Neon registration. If retirement fails, Silvervine is stopped and unregistered before the data is moved back, and Neon is restarted only when it was running before the transition.

- Linux: `silvervine.service` is enabled and started before the retained `neon.service` user unit is disabled and removed.
- macOS: `com.nicholasraimbault.silvervine.tray` is bootstrapped before the retained `com.neon.tray` / `com.neon.tray.plist` registration is removed.

These are distinct from the root-level Neon V1 registrations described below.

## Neon V1 migration

`silvervine setup` runs the existing V1 detector and cleanup. The following names are deliberately retained because they identify files installed by Neon V1:

| Legacy Neon artifact | Source distribution | Action |
|---|---|---|
| `/Library/LaunchDaemons/com.neon.fix-drm.plist` | macOS Bash / Homebrew V1 | unload and remove with elevation |
| `~/Library/LaunchAgents/com.neon.app.plist` | Neon V1 macOS app | unload and remove as the user |
| `/etc/systemd/system/neon-fix-drm.{path,service}` | Linux `install.sh` | disable and remove with elevation |
| `/usr/lib/systemd/system/neon-fix-drm.{path,service}` | AUR / RPM | preserve; show package-manager uninstall hint |
| `/lib/systemd/system/neon-fix-drm.{path,service}` | Debian / pre-merged-usr | preserve; show package-manager uninstall hint |
| `~/.config/autostart/neon.desktop` | Neon V1 Linux tray | remove as the user |
| `~/.local/share/WidevineCdm/` | Neon V1 Linux cache | migrate to the Silvervine Widevine cache |
| `/usr/lib/neon/` | Neon V1 package | preserve; show package-manager uninstall hint |

Package-managed paths are never deleted behind the package manager's back. Silvervine detects the distro and suggests the legacy Neon package command:

- Arch/AUR: `pacman -R neon-drm` (or `paru -R neon-drm` / `yay -R neon-drm`).
- Debian/Ubuntu: `dpkg -r neon-drm` (or `apt remove neon-drm`).
- Fedora/RHEL: `rpm -e neon-drm` (or `dnf remove neon-drm`).

The legacy identifiers, package hints, and `v1.0.0` references are compatibility data and will remain supported throughout Silvervine 2.x.

## Retired V1 distribution paths

### Homebrew

The old `nicholasraimbault/homebrew-neon` tap distributed Neon V1 and is retired. It is not being renamed or reused, and there is no Silvervine Homebrew tap.

```sh
brew uninstall nicholasraimbault/neon/neon
brew untap nicholasraimbault/neon
silvervine setup
```

Silvervine still detects and removes the V1 `com.neon.fix-drm.plist` left by that installation.

### AUR

```sh
pacman -R neon-drm       # or: paru -R neon-drm / yay -R neon-drm
silvervine setup
```

### Debian package

```sh
sudo dpkg -r neon-drm
silvervine setup
```

### macOS Neon.app

After `silvervine setup` removes `~/Library/LaunchAgents/com.neon.app.plist`, manually move the old `/Applications/Neon.app` to the Trash. Silvervine does not delete application bundles.

## Verification and troubleshooting

Run:

```sh
silvervine doctor
silvervine status
```

If cleanup requiring elevation was cancelled, rerun `silvervine setup`. If a package-managed `/usr/lib/neon` or `neon-fix-drm.*` artifact is reported as skipped, remove the `neon-drm` package with the suggested host package manager and rerun setup.

Browser bundles remain patched only until the browser next updates. If playback stops after migration, close the browser and run `silvervine patch`.

## Compatibility commitment

Neon V1 migration detection and cleanup remains supported during Silvervine 2.x. Neon V2 data migration is non-destructive and safe to run repeatedly. Historical changelog entries retain the Neon name where that was the released product identity.
