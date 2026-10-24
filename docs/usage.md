# Using Silvervine

## Terminal control panel

Run `silvervine tui` in a terminal. Use Tab / Shift-Tab or 1–6 to switch views,
arrow keys to select, and Page Up / Page Down to scroll. Press `?` for help.
`q` exits; unsaved settings require confirmation before discarding.

| View | Controls |
|---|---|
| Overview / Browsers | Select a browser; `p` patch, `l` launch, `t` live test, `d` diagnostics, `i` setup |
| Diagnostics | Read the last report; `d` collects again, `x` exports to a new local file |
| Updates | `u` update Silvervine, `w` update Widevine, `v` validate updater installation without downloading |
| Logs | `/` search, `!` warnings/errors, `b` selected browser, `x` export filtered text |
| Settings | Enter edit/toggle, `a` add browser, Delete remove entry, `s` save, `R` reload |
| Settings: daemon | `r` restart, `g` enable startup and start, `z` disable startup and stop |

Actions that change the installation or open a browser ask for confirmation.
They temporarily return to the normal terminal so progress and operating-system
permission prompts remain usable. Press Enter afterward to return. A self-update
closes the TUI afterward; reopen it to run the new version.

The log view refreshes every two seconds and reads at most the last 256 KiB of
each of the three most recent daily files. It does not fetch logs or upload them.
Export writes a new file and refuses to overwrite an existing one. Reports can
include local paths and browser information; review them before sharing.

Settings remain a draft until saved. Saving preserves configuration fields but
rewrites TOML formatting/comments; it refuses to overwrite a file changed since
the TUI opened or last saved. Reload to inspect an external edit. Restart the
daemon after saving so it loads the new preferences. Browser actions use saved
configuration, so save custom paths before using them.

## Updates

`silvervine update widevine` updates the CDM; `silvervine update self` updates
Silvervine. They are separate operations.

Self-updates require installation with the GitHub installer, including the
adjacent `silvervine-update` sidecar and install receipt. An unpacked executable
or `cargo install` does not create that receipt. Re-run the installer once to
enable updates. `silvervine update self --dry-run` checks those prerequisites;
it does not contact GitHub or check whether a newer version exists.

```toml
[updates]
channel = "stable"  # Default: published stable releases only
auto_apply = false  # Default: run updates manually
```

Choose `channel = "preview"` to include RCs and final releases. Enabling preview
does not enable automatic installation, and enabling automatic installation
does not enable preview. Older configurations containing only `auto_apply`
continue to select stable releases.

One-time channel overrides in 2.3:

```sh
silvervine update self --channel preview
silvervine update self --channel stable
```

The override does not save the preference. Returning to Stable waits for a newer
stable version; it does not force a downgrade from an RC to an older release.
Use the versioned installer in the README for the first 2.3 RC installation.

With `auto_apply = true`, the daemon periodically invokes the updater, skips
while a patch is in progress, and restarts after a successful update. With
manual updates on Unix, run `silvervine daemon restart` afterward. Windows
manual updates restart a registered daemon automatically. Close and reopen any
other Silvervine terminal sessions to load the replacement executable.

## Configuration

All sections are optional. The default file locations are:

| Platform | Configuration |
|---|---|
| Linux | `$XDG_CONFIG_HOME/silvervine/config.toml`, normally `~/.config/silvervine/config.toml` |
| macOS | `~/Library/Application Support/silvervine/config.toml` |
| Windows | `%APPDATA%\silvervine\config.toml` |

```toml
[notifications]
on_success = true
on_failure = true

[updates]
channel = "stable"
auto_apply = false

# Optional hooks. Omit to use hooks/pre-patch, hooks/post-patch, and
# hooks/post-update beneath the Silvervine configuration directory.
# [hooks]
# pre_patch = "/absolute/path/to/pre-patch"
# post_patch = "/absolute/path/to/post-patch"
# post_update = "/absolute/path/to/post-update"

# Repeat for custom browser installations; use a distinct display name.
# [[browsers]]
# name = "My Browser"
# install_path = "/home/me/my-browser" # Linux
# bundle_path = "/Users/me/Applications/My Browser.app" # macOS instead
```

Windows custom browser example (TOML literal strings preserve backslashes):

```toml
[[browsers]]
name = "Portable Chromium"
install_path = 'C:\Browsers\Chromium'
user_data_dir = 'C:\Users\me\AppData\Local\Chromium\User Data'
```

The installation and profile paths must match the browser actually being used.
Unknown Windows products require an explicit absolute `user_data_dir`.
Recognized Helium, Thorium, and Chromium products have standard profile defaults.
Silvervine uses a configured Windows profile when launching or testing that
browser. A profile override can be necessary for a portable installation.

Hooks run locally with your user permissions and have a 15-second timeout.
A failing or timed-out pre-patch hook aborts the patch. Hook values support `~`
expansion. Only configure scripts you intend to execute.

## Diagnostics

```sh
silvervine status
silvervine list-browsers --all
silvervine doctor
silvervine doctor --media-stack --browser Helium
silvervine test --browser Helium
silvervine doctor --share
```

`doctor --media-stack` inspects local browser/CDM provenance, architecture,
and available media evidence without opening a browser or accessing the network.
The explicit `test` command opens a temporary tokenized `127.0.0.1` page with
the browser's normal profile. Results describe what that browser reports; they
do not prove service entitlement, HD/4K playback, or certified hardware DRM.
`test --url <url>` opens a manual test page instead.

The TUI shows the same diagnostics. `doctor --share` produces a prefilled GitHub
issue URL; it does not submit the report. There is no telemetry endpoint.

## Other CLI operations

```sh
silvervine patch Helium
silvervine launch Helium
silvervine status --watch
silvervine daemon enable
silvervine daemon restart
silvervine daemon disable
silvervine repair
silvervine uninstall
```

`uninstall` stops/removes the user daemon and removes Silvervine's cache.
`--purge` also removes configuration and state. It does not remove the installed
Silvervine executable/updater or revert browser components. Remove the binary
files from the install directory separately if desired.

Run `silvervine --help` or `<command> --help` for all flags, JSON output,
shell completion, man-page generation, and Widevine rollback options.
