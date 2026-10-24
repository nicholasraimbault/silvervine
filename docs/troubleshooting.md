# Troubleshooting

Start with `silvervine status` and `silvervine doctor --media-stack`, or the
Diagnostics view in `silvervine tui`. Keep the browser name and version with
your report. `silvervine doctor --share` prepares an issue URL for you to review.

## Command not found

Reopen the terminal after installation. The default executable is
`~/.cargo/bin/silvervine` on Unix or
`%USERPROFILE%\.cargo\bin\silvervine.exe` on Windows. Use `$CARGO_HOME/bin`
instead when customized, and ensure that directory is on `PATH`.

## Browser not detected or the wrong profile is used

Run `silvervine list-browsers --all`. Add a custom absolute installation path
in Settings or [configuration](usage.md#configuration). Give multiple copies
distinct names. On Windows, an unknown product requires an absolute
`user_data_dir`; portable installations may also need that override. Use the
profile the browser actually opens.

## Browser is running

Close all browser windows and background browser processes before patching.
The daemon retries deferred work after the browser exits. Windows always
requires a closed browser, even with `--force`, to protect component registration.

## Existing Widevine conflicts

Silvervine preserves an existing component it cannot establish ownership of.
Inspect the diagnostic provenance before deciding to replace it. The explicit
CLI override is `silvervine patch <browser> --replace-external-cdm`; it requires
a selected browser and should only be used when you intend to replace that CDM.

## Playback still fails or quality is limited

Run the explicit `silvervine test --browser <name>` capability test and compare
the browser/CDM versions in diagnostics. Try the service in a browser it
officially supports. Silvervine supplies Widevine L3; a successful capability
test cannot grant hardware DRM, service entitlement, or HD/4K/HDR playback.

## Updater missing or RC not offered

Re-run the versioned GitHub installer to obtain the adjacent updater and install
receipt. `update self --dry-run` checks their presence, not the latest release.
Stable ignores RCs. On 2.3, use `--channel preview` for one update or save Preview
in Settings. Installing the first RC uses the explicit installer in the README.
The update channel and automatic installation are separate settings.

## Daemon or tray is missing

Use `silvervine daemon enable` to register/start it, or `daemon restart` after
changing settings. On Linux, a desktop without a StatusNotifierItem tray host
can run the daemon in notifications-only mode. `silvervine` with no arguments
runs the daemon; `silvervine tui` opens the separate terminal control panel.

## Configuration changed while the TUI was open

Reload in Settings with `R` before saving again. This discards the TUI draft and
loads the external edit. Saving normalizes TOML formatting/comments. A symlinked
configuration must be edited at its target directly.

## Legacy Neon installation

See [the migration guide](../MIGRATION.md). Compatibility remains supported in
2.x; package-managed legacy files are handled with package-manager cleanup
guidance rather than deletion behind the package manager's back.
