# Silvervine roadmap

Silvervine focuses on installing and maintaining Widevine L3 for compatible desktop Chromium browsers. Releases follow working features and verified fixes; there is no fixed feature schedule after 2.3.

## 2.3 release candidate

Skip 2.2.2 and validate 2.3.0-rc.2 with:

- The pending dependency and CI updates, plus current security fixes.
- Windows x64 discovery, profile-scoped Widevine installation, tray/startup/wake integration, and normal-user installation and updates. Credit the community port.
- A terminal control panel for browser actions, diagnostics, updates, filtered logs, configuration, and daemon controls. Keep the CLI and tray daemon.
- Explicit Stable / Preview update preferences. Stable is the default; automatic installation remains a separate opt-in.
- A shorter README and focused usage, Windows, and troubleshooting guides.

Before publishing an RC: formatting, strict lint, full tests, dependency audit, MSRV, and release builds pass on their applicable platforms. Publish it as a GitHub prerelease, with versioned installers and checksums.

Before 2.3 stable: exercise normal-user Windows installation, actual service playback, browser auto-updates, tray/startup, sleep/resume, repair/uninstall, and the TUI on real hardware. Repeat the Linux/macOS smoke checks and resolve release-blocking failures. The [Windows checklist](docs/windows.md#test-the-rc-on-a-real-pc) records the manual checks.

## Already available

The CLI and tray daemon already provide verified CDM downloads, guarded publication and rollback, browser discovery, update watching, sleep/wake handling, hooks, notifications, status, repair, and passive/live media diagnostics. Diagnostics and media-stack helpers are maintenance surfaces, not a new promised feature bundle.

Legacy Neon migration remains compatible throughout 2.x. Its instructions live in the [legacy guide](MIGRATION.md), outside the main install flow.

## After 2.3

- Fix reproducible bugs and browser compatibility changes as evidence arrives.
- Maintain dependencies and release security; revisit the temporary D-Bus maintenance exceptions by 2027-01-23.
- Improve diagnostics or terminal usability where actual testing shows a useful gap.
- Consider ARM64 Linux only with a viable CDM source and contributors able to verify it on hardware.

There are no commitments to AUR, deb, rpm, Homebrew, or other distribution channels. The existing installers and release archives remain the distribution path. HDR configuration automation and additional DRM capability detection are not planned for 2.3.

## Research archive

The former bridge experiment is preserved at [archive/experimental-bridge](https://github.com/nicholasraimbault/silvervine/tree/archive/experimental-bridge). It is unsupported and excluded from releases. Silvervine does not provide L1 or a premium-streaming bypass.

## Validation and versioning

[Performance budgets and historical measurements](docs/performance.md) guide regression checks. Native CI covers Linux, macOS, and Windows; real playback and desktop behavior require hardware tests. Linux maintainer testing is on Arch; other desktop environments benefit from contributor verification.

Stable releases follow semantic versioning. IPC breaking changes require a major version; CLI removals receive a deprecation cycle. Release notes are maintained in [CHANGELOG.md](CHANGELOG.md).
