# macOS Tray Event Loop Design

Date: 2026-08-01
Status: Approved for implementation
Target release: 2.1.3

## Problem

Silvervine 2.1.2 creates a `tray-icon` `NSStatusItem` from the process main thread, but the command-line process remains an AppKit-prohibited application and never services an AppKit event loop. The daemon's main loop polls its command channel and sleeps for 100 ms. On the test MacBook, the installed 2.1.2 LaunchAgent is healthy, but its activation policy is `Prohibited`, its main thread remains in `nanosleep`, and it owns no on-screen status-item surface.

The Linux tray works because `ksni` owns a separate D-Bus service loop. The macOS backend instead requires status-item creation and event delivery on the AppKit main thread.

## Goals

- Display Silvervine's status item when the daemon runs as a macOS GUI LaunchAgent.
- Keep the process out of the Dock by using the `Accessory` activation policy.
- Deliver status-menu events without preventing the existing daemon loop from observing Quit and shutdown state.
- Keep all AppKit objects and mutations on the process main thread.
- Refresh the rendered macOS menu and its command routes when `MenuState` changes.
- Confirm the release candidate and final official 2.1.3 artifact in the real Mac GUI session.

## Non-goals

- Replacing `tray-icon` or Linux `ksni`.
- Adding `tao`, `winit`, or another GUI event-loop framework.
- Moving patch, IPC, watcher, or shutdown orchestration to background threads.
- Changing the public `doctor --json` schema. Its existing macOS tray field remains a platform-capability indicator and will not be used as runtime proof.

## Architecture

### AppKit initialization

The macOS tray constructor will:

1. Acquire `objc2::MainThreadMarker`; failure remains a tray-initialization error.
2. Obtain `NSApplication::sharedApplication`.
3. Set `NSApplicationActivationPolicy::Accessory`; a `false` result is a tray-initialization error.
4. Call `finishLaunching`.
5. Build the menu and `TrayIcon`.

Initialization happens before `TrayIconBuilder::build`, under a short Objective-C autorelease pool. `TrayInner` retains the shared application for the tray lifetime.

The direct macOS dependency feature lists will include the APIs actually imported:

- `objc2-app-kit`: `NSApplication`, `NSResponder`, `NSRunningApplication`, `NSEvent`, and the existing `NSWorkspace`.
- `objc2-foundation`: `NSDate`, `NSRunLoop`, `NSObjCRuntime`, `NSString`, and the existing notification/workspace support.

### Bounded event pumping

`Tray` will expose a crate-private platform wait/pump method used by the daemon loop.

On macOS, the method calls `NSApplication::nextEventMatchingMask_untilDate_inMode_dequeue` with:

- `NSEventMask::Any`;
- a deadline derived from the existing 100 ms idle interval;
- `NSDefaultRunLoopMode`;
- dequeue enabled.

If an event is returned, the method calls `NSApplication::sendEvent`, then drains immediately pending events with a zero-duration deadline. Each pump runs inside an autorelease pool.

On Linux and in the headless fallback, the method preserves the current bounded sleep behavior. `NSApplication::run()` is explicitly not used because it would prevent the existing command loop from observing the stop flag or handling daemon commands.

The daemon loop replaces its direct `thread::sleep` with this platform method only when no tray command is pending. Command dispatch, shutdown, IPC, and patch flow remain unchanged.

### Menu and route updates

The current macOS handler captures an immutable route map at initial construction, while `set_state` changes only stored state. The new macOS inner state will hold:

- the `TrayIcon` behind main-thread interior mutability;
- an `Arc<Mutex<HashMap<String, TrayCommand>>>` read by the global menu-event handler;
- a monotonically increasing menu generation.

A helper will build the native menu and route map from one `MenuState` snapshot. Menu IDs include the generation so a queued event from a replaced menu cannot be interpreted as a command from the new menu.

`set_state` builds the next menu and routes without holding the state lock, updates the native tray menu on the main thread, replaces the shared route map, and then stores the accepted state snapshot. The menu handler ignores IDs absent from the current generation.

## Error handling

- Failure to acquire the main-thread marker, set accessory policy, or build the status item returns the existing categorized tray-initialization error.
- `build_tray_with_fallback` retains current behavior: log the concrete failure and continue notifications-only rather than terminating the daemon.
- Event pumping has no recoverable Rust error result in the bound AppKit API. An empty event result means only that the deadline expired.
- Poisoned internal locks retain the repository's current fail-fast policy for daemon-internal invariants.

## Testing and verification

### Automated checks

- Add behavior tests for generated menu IDs, generation changes, and route-map correctness.
- Preserve existing headless event-loop tests.
- Run formatting, Clippy, all-feature tests, release build, and `cargo deny` on Linux.
- Build, test, and lint the same source natively on Apple Silicon macOS.

### Live Mac release-candidate gate

Before merge or tag:

1. Preserve the installed official 2.1.2 binary as a rollback copy.
2. Install the 2.1.3 candidate and restart the LaunchAgent in `gui/501`.
3. Require a live, non-stale daemon heartbeat.
4. Query `NSRunningApplication` and require activation policy raw value `1` (`Accessory`).
5. Require an actual on-screen status-item surface owned by the candidate process or direct visual confirmation of the Silvervine icon.
6. Sample the process and confirm the main thread is servicing AppKit rather than remaining exclusively in `nanosleep`.
7. Open the menu and exercise a non-destructive menu action; confirm the corresponding daemon command is delivered.
8. Confirm Quit removes the status item and exits cleanly, then restart the LaunchAgent.

Any failed gate restores the saved official binary and restarts the prior LaunchAgent.

### Official release gate

After candidate success and CI success:

1. Merge the fix and publish tag `v2.1.3` through the existing release workflow.
2. Require all expected release assets and valid published checksums.
3. Install using the official latest-release installer.
4. Confirm installed version and binary digest against the published asset.
5. Repeat the activation-policy, status-item, menu, heartbeat, and clean-Quit checks.

The Mac finishes on the official 2.1.3 release, not a locally built candidate.

## Acceptance criteria

- Silvervine 2.1.3 displays a usable macOS menu-bar icon from its GUI LaunchAgent without a Dock icon.
- The live process reports `Accessory` activation policy.
- Menu clicks reach the existing `TrayCommand` dispatcher.
- Rendered menu state and command routing update together.
- Quit removes the status item and shuts down the daemon cleanly.
- Linux tray behavior and headless fallback behavior remain unchanged.
- The final Mac installation is byte-for-byte traceable to an official 2.1.3 release asset.
