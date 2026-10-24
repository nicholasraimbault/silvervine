# Windows 2.3 preview

Silvervine 2.3 targets **Windows x64**. Windows ARM64 and 32-bit builds are not
supported. The port builds on [paparei's work](https://github.com/paparei/silvervine-window).
Its contributor verified browser EME acceptance with Helium 0.20.1.1 x64 and
Widevine 4.10.3112.0; that is not a verified streaming-service playback result.

## Install like a normal user

Open PowerShell as your normal user. No GitHub account, repository clone,
Visual Studio, or Rust installation is required.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://github.com/nicholasraimbault/silvervine/releases/download/v2.3.0-rc.2/silvervine-installer.ps1 | iex"
```

This explicitly selects the RC. It installs `silvervine.exe` and
`silvervine-update.exe` in `$env:CARGO_HOME\bin` (normally
`$env:USERPROFILE\.cargo\bin`) and creates an update receipt. Open a new
PowerShell window afterward. Close the browser, including background processes,
then run:

```powershell
silvervine --version
silvervine list-browsers --all
silvervine setup
silvervine status
silvervine tui
```

When re-running the installer over an existing Windows installation, first quit
Silvervine from its tray menu and close any TUI sessions. Normal `update self`
handles a running executable and restarts a registered daemon itself.

If the command is not found, try:

```powershell
& "$env:USERPROFILE\.cargo\bin\silvervine.exe" --version
```

Use your chosen `$env:CARGO_HOME` location instead if customized. Public
[release assets](https://github.com/nicholasraimbault/silvervine/releases/tag/v2.3.0-rc.2)
also contain a Windows zip and checksums. Extracting the zip is useful for a
portable executable, but self-updates require the installer receipt.

## What it changes

Widevine is verified and published under the browser's per-user `WidevineCdm`
component directory. Silvervine updates component registration in `Local State`
and preserves conflicting files instead of overwriting an unknown installation.
The browser application directory is left intact. Patching requires a closed
browser, including with `--force`; Windows patching does not request elevation.

Setup enables a `Silvervine.lnk` shortcut in your user Startup folder and starts
the tray daemon. IPC uses a local named pipe restricted to your Windows user.
`silvervine daemon disable` stops the registered daemon and removes the shortcut.

Configure custom installations/profiles in the TUI or
`%APPDATA%\silvervine\config.toml`; see [configuration](usage.md#configuration).
Disposable data lives under `%LOCALAPPDATA%\silvervine\cache`. Repair and
uninstall remove that cache while keeping the updater receipt. The receipt normally lives under
`%LOCALAPPDATA%\silvervine\silvervine-receipt.json` (or `$env:XDG_CONFIG_HOME`
when explicitly configured for the installer).

## Test the RC on a real PC

Record the Windows version, browser version, GPU, and `silvervine --version`.
Use the installed release, as a normal user, for these checks:

1. **Fresh install:** the public installer works without a GitHub login or
   development tools. Setup detects the intended browser and status shows its
   CDM. An unknown/portable browser works with an explicit profile path.
2. **Playback:** run `silvervine test --browser Helium` (substitute your browser)
   and try a DRM video you normally watch. Record the service, whether playback
   succeeds, and observed quality. Capability acceptance alone is insufficient.
3. **Browser safety:** try patching while the browser is open; it must defer or
   refuse. Close it and patch again. Browser settings and other profiles remain
   usable. A browser update should trigger rechecking and repatching as needed.
4. **Tray/startup:** the tray opens and reports state; disable/enable startup from
   Settings, sign out/in, and check that exactly one daemon is running.
5. **Sleep/resume:** sleep the PC, resume it, and confirm the tray responds and
   playback still works. Repeat with the browser open and closed.
6. **TUI:** switch all six views, run diagnostics, filter logs, export a report,
   save notification preferences, and restart the daemon. Changing to Preview
   must leave automatic installation off unless separately enabled.
7. **Updater:** `silvervine update self --dry-run` finds the receipt/sidecar.
   When a newer RC is available, `silvervine update self --channel preview`
   installs it, the daemon restarts, and a new terminal reports the new version.
   A same-version check should leave the installation usable.
8. **Recovery/removal:** run repair with the browser closed, then uninstall.
   Confirm the Startup shortcut/daemon is removed and the browser remains usable.
   Configuration remains unless `--purge` was requested.

Only mark checks complete after observing them. CI covers compilation, lint,
automated installation/security tests, and executable update/rollback cases;
it does not validate actual streaming-service playback or a physical sleep cycle.

For a problem, save diagnostics from the TUI or run:

```powershell
silvervine doctor --media-stack --browser Helium
silvervine doctor --share
```

Review local paths before sharing a report. A tester can send the report to the
maintainer without signing into GitHub on the test PC.

## Update preferences

Stable is the default channel, including after manually installing an RC.
Select Preview in Settings to receive later RCs. Automatic installation remains
off until separately enabled. Returning to Stable waits for a newer final
release; it does not downgrade. See [update details](usage.md#updates).
