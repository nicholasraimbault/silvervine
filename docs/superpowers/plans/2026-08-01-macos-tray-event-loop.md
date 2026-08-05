# macOS Tray Event Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Silvervine's macOS LaunchAgent display and service a live menu-bar status item, then publish and install the verified fix as official release 2.1.3.

**Architecture:** Initialize an accessory `NSApplication` before constructing `tray-icon`, and let the existing daemon loop service AppKit through a bounded `nextEvent…`/`sendEvent` pump instead of sleeping. Keep status-item mutation on the main thread; use generation-scoped menu IDs and a shared route map so live menu refreshes cannot misroute queued clicks.

**Tech Stack:** Rust 1.88, `objc2` 0.6, `objc2-app-kit` 0.3, `objc2-foundation` 0.3, `tray-icon` 0.24, Cargo, launchd, GitHub Actions/cargo-dist.

## Global Constraints

- Target release is exactly `2.1.3`.
- Do not call `NSApplication::run()`; the existing daemon loop must continue observing Quit and shutdown state.
- Do not add `tao`, `winit`, or another GUI/event-loop framework.
- Keep all AppKit objects and mutations on the process main thread.
- Keep the process out of the Dock with `NSApplicationActivationPolicy::Accessory`.
- Preserve Linux `ksni`, notifications-only fallback, IPC, watcher, patch, and shutdown behavior.
- Keep the public `doctor --json` schema unchanged; do not treat its macOS capability field as runtime verification.
- A failed live-candidate gate must atomically restore the official 2.1.2 binary and restart its LaunchAgent.
- The final Mac installation must come from, and match, an official 2.1.3 release asset.

---

### Task 1: Generation-safe macOS menu routes

**Files:**
- Modify: `src/daemon/tray.rs:653-713`
- Test: `src/daemon/tray.rs:1083-1116`

**Interfaces:**
- Consumes: `MenuState`, `MenuItemSpec`, and `TrayCommand` already defined in `src/daemon/tray.rs`.
- Produces: `build_routes(state: &MenuState, generation: u64) -> HashMap<String, TrayCommand>` and `menu_item_id(generation: u64, index: usize, item: &MenuItemSpec) -> String` for Task 2.

- [ ] **Step 1: Write failing generation tests**

Replace the stable-ID test and add a disjoint-route test:

```rust
#[test]
fn menu_item_id_is_stable_within_generation_and_changes_between_generations() {
    let item = MenuItemSpec::Action {
        label: "Patch Now".into(),
        command: TrayCommand::PatchAll,
    };
    assert_eq!(
        menu_item_id(7, 2, &item),
        menu_item_id(7, 2, &item)
    );
    assert_ne!(menu_item_id(7, 1, &item), menu_item_id(7, 2, &item));
    assert_ne!(menu_item_id(7, 2, &item), menu_item_id(8, 2, &item));
}

#[test]
fn route_ids_are_disjoint_between_menu_generations() {
    let state = MenuState {
        browsers: vec![BrowserMenuEntry::from_browser(
            &fake_browser("Helium"),
            true,
        )],
        launch_at_login: false,
    };
    let first = build_routes(&state, 4);
    let second = build_routes(&state, 5);
    assert!(first.keys().all(|id| !second.contains_key(id)));
    assert_eq!(first.len(), second.len());
    for command in first.values() {
        let first_count = first.values().filter(|candidate| *candidate == command).count();
        let second_count = second
            .values()
            .filter(|candidate| *candidate == command)
            .count();
        assert_eq!(first_count, second_count);
    }
}
```

Update `build_routes_covers_actions_and_browsers_and_toggles` to call `build_routes(&state, 0)`.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
cargo test --locked daemon::tray::tests::menu_item_id_is_stable_within_generation_and_changes_between_generations -- --exact
cargo test --locked daemon::tray::tests::route_ids_are_disjoint_between_menu_generations -- --exact
```

Expected: compilation fails because `menu_item_id` and `build_routes` do not yet accept a generation.

- [ ] **Step 3: Thread generation through route construction**

Change the helpers to this shape and update every call:

```rust
fn build_routes(
    state: &MenuState,
    generation: u64,
) -> std::collections::HashMap<String, TrayCommand> {
    let mut routes = std::collections::HashMap::new();
    for (idx, item) in menu_layout(state).iter().enumerate() {
        route_item_into(&mut routes, generation, idx, item);
    }
    routes
}

fn route_item_into(
    routes: &mut std::collections::HashMap<String, TrayCommand>,
    generation: u64,
    idx: usize,
    item: &MenuItemSpec,
) {
    let id = menu_item_id(generation, idx, item);
    match item {
        MenuItemSpec::Action { command, .. } => {
            routes.insert(id, command.clone());
        }
        MenuItemSpec::Toggle {
            command_when_toggled,
            ..
        } => {
            routes.insert(id, command_when_toggled.clone());
        }
        MenuItemSpec::BrowserStatus { browser_name, .. } => {
            routes.insert(id, TrayCommand::PatchOne(browser_name.clone()));
        }
        MenuItemSpec::Separator => {}
    }
}

fn menu_item_id(generation: u64, index: usize, item: &MenuItemSpec) -> String {
    let kind_and_label = match item {
        MenuItemSpec::BrowserStatus { browser_name, .. } => {
            format!("browser-{index}-{browser_name}")
        }
        MenuItemSpec::Action { label, .. } => format!("action-{index}-{label}"),
        MenuItemSpec::Toggle { label, .. } => format!("toggle-{index}-{label}"),
        MenuItemSpec::Separator => format!("sep-{index}"),
    };
    format!("silvervine-{generation}-{kind_and_label}")
}
```

Remove the obsolete `_parent_id` argument. Keep IDs deterministic within one generation.

- [ ] **Step 4: Run focused and module tests and verify GREEN**

Run:

```bash
cargo test --locked daemon::tray::tests::menu_item_id_is_stable_within_generation_and_changes_between_generations -- --exact
cargo test --locked daemon::tray::tests::route_ids_are_disjoint_between_menu_generations -- --exact
cargo test --locked daemon::tray::tests
```

Expected: all tray tests pass with zero failures.

- [ ] **Step 5: Commit the route invariant**

```bash
git add src/daemon/tray.rs
git commit -m "fix: generation-scope macOS tray routes"
```

---

### Task 2: Bootstrap and pump AppKit on the daemon main thread

**Files:**
- Modify: `Cargo.toml:113-134`
- Modify: `Cargo.lock`
- Modify: `src/daemon/tray.rs:53-55,300-319,516-616,715-790`
- Modify: `src/daemon/mod.rs:514-568`
- Test: existing `src/daemon/mod.rs:1287-1324` and `src/daemon/tray.rs:792-1172`

**Interfaces:**
- Consumes: generation-aware `build_routes` and `menu_item_id` from Task 1.
- Produces: `Tray::wait_for_platform_event(&self, timeout: Duration)`, retained macOS `NSApplication`, live mutable `TrayIcon`, and shared current-generation route state.

- [ ] **Step 1: Reproduce the released runtime failure before editing behavior**

Against the official 2.1.2 LaunchAgent, resolve its PID and run the Swift probe:

```bash
ssh -o BatchMode=yes -o IdentitiesOnly=yes -i ~/.ssh/dell_hermes \
  lanaraimbault@192.168.20.232 \
  'SILVERVINE_PID=$(/usr/bin/pgrep -x silvervine); \
   export SILVERVINE_PID; \
   /Users/lanaraimbault/.cargo/bin/silvervine --version; \
   /usr/bin/xcrun swift -e '\''import AppKit; import CoreGraphics; import Foundation; \
   let pid = pid_t(Int(ProcessInfo.processInfo.environment["SILVERVINE_PID"]!)!); \
   let app = NSRunningApplication(processIdentifier: pid); \
   let surfaces = (CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []).filter { ($0[kCGWindowOwnerPID as String] as? Int32) == pid }.count; \
   print("pid=\(pid) policy=\(app?.activationPolicy.rawValue ?? -1) surfaces=\(surfaces)")'\'''
```

Expected failing baseline: `silvervine 2.1.2`, activation policy `2` (`Prohibited`), and `surfaces=0`.

- [ ] **Step 2: Enable only the required Objective-C bindings**

Update the macOS dependency features:

```toml
objc2-foundation = { version = "0.3", features = [
    "NSObject",
    "NSString",
    "NSNotification",
    "NSOperation",
    "NSDate",
    "NSRunLoop",
    "NSObjCRuntime",
    "block2",
] }
objc2-app-kit = { version = "0.3", features = [
    "NSApplication",
    "NSResponder",
    "NSRunningApplication",
    "NSEvent",
    "NSWorkspace",
] }
```

Run `cargo check --locked --all-targets --all-features` once so `Cargo.lock` records any feature-driven dependency edges.

- [ ] **Step 3: Add AppKit ownership and initialization**

Change the macOS inner type and builder around these exact responsibilities:

```rust
#[cfg(target_os = "macos")]
struct TrayInner {
    application: objc2::rc::Retained<objc2_app_kit::NSApplication>,
    tray: std::cell::RefCell<tray_icon::TrayIcon>,
    routes: std::sync::Arc<Mutex<std::collections::HashMap<String, TrayCommand>>>,
    generation: std::cell::Cell<u64>,
}
```

At the beginning of the macOS tray builder, before constructing any `Menu` or `TrayIcon`:

```rust
use objc2::MainThreadMarker;
use objc2::rc::autoreleasepool;
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy,
};

let mtm = MainThreadMarker::new().ok_or_else(|| {
    Error::unsupported_platform("macOS tray initialization requires the process main thread")
})?;
let application = autoreleasepool(|_| {
    let application = NSApplication::sharedApplication(mtm);
    if !application.setActivationPolicy(NSApplicationActivationPolicy::Accessory) {
        return Err(Error::unsupported_platform(
            "macOS refused accessory activation policy for the tray daemon",
        ));
    }
    application.finishLaunching();
    Ok(application)
})?;
```

Change the builder return type to the crate's `Result<TrayInner>` and construct one shared route table:

```rust
let generation = 0;
let routes = std::sync::Arc::new(Mutex::new(build_routes(state, generation)));
let routes_for_handler = std::sync::Arc::clone(&routes);
let tx_for_handler = tx.clone();
tray_icon::menu::MenuEvent::set_event_handler(Some(move |event| {
    let command = routes_for_handler
        .lock()
        .unwrap()
        .get(&event.id().0)
        .cloned();
    if let Some(command) = command {
        let _ = tx_for_handler.send(command);
    }
}));

let menu = build_macos_menu(state, generation);
let mut builder = TrayIconBuilder::new()
    .with_tooltip("Silvervine — Widevine helper")
    .with_menu(Box::new(menu));
if let Some(decoded) = decoded_tray_icon() {
    match tray_icon::Icon::from_rgba(
        decoded.rgba.clone(),
        decoded.width,
        decoded.height,
    ) {
        Ok(icon) => {
            builder = builder.with_icon(icon).with_icon_as_template(true);
        }
        Err(error) => tracing::warn!(
            target: "silvervine::daemon::tray",
            error = %error,
            "could not construct macOS tray icon; continuing without an icon"
        ),
    }
} else {
    tracing::warn!(
        target: "silvervine::daemon::tray",
        "could not decode embedded tray icon; continuing without an icon"
    );
}
let tray = builder.build().map_err(|error| {
    Error::unsupported_platform(format!("tray-icon initialization failed: {error}"))
})?;

Ok(TrayInner {
    application,
    tray: std::cell::RefCell::new(tray),
    routes,
    generation: std::cell::Cell::new(generation),
})
```

- [ ] **Step 4: Install one shared route handler and live menu replacement**

Extract native menu construction so initial render and refresh use identical IDs:

```rust
#[cfg(target_os = "macos")]
fn build_macos_menu(state: &MenuState, generation: u64) -> tray_icon::menu::Menu {
    use tray_icon::menu::{
        CheckMenuItem, Menu, MenuId, MenuItem, PredefinedMenuItem,
    };

    let menu = Menu::new();
    for (idx, spec) in menu_layout(state).iter().enumerate() {
        let id = MenuId::new(menu_item_id(generation, idx, spec));
        match spec {
            MenuItemSpec::BrowserStatus { .. } | MenuItemSpec::Action { .. } => {
                let item = MenuItem::with_id(id, spec.label(), true, None);
                let _ = menu.append(&item);
            }
            MenuItemSpec::Toggle { checked, .. } => {
                let item =
                    CheckMenuItem::with_id(id, spec.label(), true, *checked, None);
                let _ = menu.append(&item);
            }
            MenuItemSpec::Separator => {
                let item = PredefinedMenuItem::separator();
                let _ = menu.append(&item);
            }
        }
    }
    menu
}

#[cfg(target_os = "macos")]
impl TrayInner {
    fn replace_menu(&self, state: &MenuState) {
        let next_generation = self
            .generation
            .get()
            .checked_add(1)
            .expect("macOS tray menu generation overflow");
        let menu = build_macos_menu(state, next_generation);
        let routes = build_routes(state, next_generation);

        *self.routes.lock().unwrap() = routes;
        self.tray
            .borrow_mut()
            .set_menu(Some(Box::new(menu)));
        self.generation.set(next_generation);
    }
}
```

Call `replace_menu` from the macOS branch of `Tray::set_state` before replacing the stored state:

```rust
#[cfg(target_os = "macos")]
if let Some(inner) = &self.inner {
    inner.replace_menu(&state);
}
*self.state.lock().unwrap() = state.clone();
```

Keep the existing Linux `ksni` update after the stored-state assignment. Delete the obsolete comment claiming the daemon reconstructs `Tray`, and delete the compile-only `tray_inner_routes_field_present` test that does not inspect `TrayInner`.

- [ ] **Step 5: Add the bounded AppKit event pump**

Add this macOS-only method to `TrayInner`:

```rust
#[cfg(target_os = "macos")]
impl TrayInner {
    fn pump_events(&self, timeout: std::time::Duration) {
        use objc2::rc::autoreleasepool;
        use objc2_app_kit::NSEventMask;
        use objc2_foundation::{NSDate, NSDefaultRunLoopMode};

        autoreleasepool(|_| {
            let deadline = NSDate::dateWithTimeIntervalSinceNow(timeout.as_secs_f64());
            if let Some(event) = self.application
                .nextEventMatchingMask_untilDate_inMode_dequeue(
                    NSEventMask::Any,
                    Some(&deadline),
                    NSDefaultRunLoopMode,
                    true,
                )
            {
                self.application.sendEvent(&event);
            }

            let drain_deadline = NSDate::distantPast();
            while let Some(event) = self.application
                .nextEventMatchingMask_untilDate_inMode_dequeue(
                    NSEventMask::Any,
                    Some(&drain_deadline),
                    NSDefaultRunLoopMode,
                    true,
                )
            {
                self.application.sendEvent(&event);
            }
            self.application.updateWindows();
        });
    }
}
```

Add the cross-platform boundary on `Tray`:

```rust
pub(crate) fn wait_for_platform_event(&self, timeout: std::time::Duration) {
    #[cfg(target_os = "macos")]
    if let Some(inner) = &self.inner {
        inner.pump_events(timeout);
        return;
    }
    std::thread::sleep(timeout);
}
```

Replace `std::thread::sleep(Duration::from_millis(100))` in `run_event_loop` with:

```rust
tray.wait_for_platform_event(Duration::from_millis(100));
```

Do not invoke `NSApplication::run()` anywhere.

- [ ] **Step 6: Run focused tests and Linux regression gates**

Run:

```bash
cargo fmt --all -- --check
cargo test --locked daemon::tray::tests
cargo test --locked daemon::tests::run_event_loop_returns_on_quit -- --exact
cargo test --locked daemon::tests::run_event_loop_single_iteration_returns_immediately -- --exact
cargo test --locked daemon::tests::run_event_loop_observes_stop_flag -- --exact
cargo check --locked --all-targets --all-features
```

Expected: formatting is clean and every command exits 0. Linux compiles only the sleep/`ksni` branch; native macOS compilation remains a required Task 3 gate.

- [ ] **Step 7: Commit the AppKit lifecycle fix**

```bash
git add Cargo.toml Cargo.lock src/daemon/tray.rs src/daemon/mod.rs
git commit -m "fix: service the macOS tray event loop"
```

---

### Task 3: Build and prove the 2.1.3 candidate on Apple Silicon

**Files:**
- Modify: `Cargo.toml:3`
- Modify: `Cargo.lock` root `silvervine` package version
- GitHub pull request from `fix/macos-tray-event-loop` to `master`
- User-operated candidate binary: `~/.cargo/bin/silvervine`
- User-operated rollback binary: `~/.cargo/bin/silvervine-2.1.2.rollback`

**Interfaces:**
- Consumes: completed and reviewed code from Tasks 1-2.
- Produces: a 2.1.3 candidate that passes native GitHub macOS compilation/tests and a separate physical-Mac visual/menu confirmation.

- [ ] **Step 1: Set and commit the candidate version**

Change the package version in `Cargo.toml` and root package version in `Cargo.lock` from `2.1.2` to `2.1.3`:

```toml
[package]
name = "silvervine"
version = "2.1.3"
```

Run and commit:

```bash
cargo check --locked --all-targets --all-features
cargo run --locked -- --version
git add Cargo.toml Cargo.lock
git commit -m "chore: prepare version 2.1.3"
```

Expected version output: `silvervine 2.1.3`.

- [ ] **Step 2: Run the complete local source gate**

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features --no-fail-fast
cargo build --release --locked
cargo deny check advisories bans licenses sources
git diff --check
```

Expected: every command exits 0. Record the total test count and intentional ignored-test count.

- [ ] **Step 3: Push a draft PR and require native macOS CI**

Push `fix/macos-tray-event-loop`, open a draft pull request, and wait for every CI job. The existing `ci.yml` matrix must report success for:

```text
clippy (macos-latest)
test (macos-latest)
cargo build --release (macos-latest)
```

Linux, formatting, MSRV, and cargo-deny jobs must also pass. Native CI proves the AppKit code compiles and the repository tests pass on macOS; it does not count as proof that a physical menu-bar icon is visible.

- [ ] **Step 4: Give the physical Mac an exact candidate install**

Because controller SSH access is unavailable, the user runs these commands in Terminal on the physical Mac:

```bash
cp "$HOME/.cargo/bin/silvervine" \
   "$HOME/.cargo/bin/silvervine-2.1.2.rollback"
cargo install --git https://github.com/nicholasraimbault/silvervine.git \
  --branch fix/macos-tray-event-loop --locked --force
launchctl kickstart -k \
  "gui/$(id -u)/com.nicholasraimbault.silvervine.tray"
silvervine --version
```

Required version output: `silvervine 2.1.3`.

The user then runs this local policy probe:

```bash
SILVERVINE_PID=$(/usr/bin/pgrep -x silvervine)
export SILVERVINE_PID
/usr/bin/xcrun swift -e '
import AppKit
import CoreGraphics
import Foundation

let pid = pid_t(Int(ProcessInfo.processInfo.environment["SILVERVINE_PID"]!)!)
let app = NSRunningApplication(processIdentifier: pid)!
let surfaces = (CGWindowListCopyWindowInfo(
    [.optionOnScreenOnly, .excludeDesktopElements],
    kCGNullWindowID
) as? [[String: Any]] ?? []).filter {
    ($0[kCGWindowOwnerPID as String] as? Int32) == pid
}
print("policy=\(app.activationPolicy.rawValue) surfaces=\(surfaces.count)")
'
```

Required policy output: `policy=1`. A positive surface count is supporting evidence; direct visual confirmation remains authoritative if WindowServer attributes the status-item surface to another process.

- [ ] **Step 5: Obtain the physical icon and menu confirmation**

The user must confirm all of these observations before the stable tag is created:

- the Silvervine icon is visible in the macOS menu bar;
- Silvervine has no Dock icon;
- clicking the icon opens the expected Silvervine menu;
- choosing **Quit Silvervine** removes the icon and exits cleanly;
- `launchctl kickstart -k "gui/$(id -u)/com.nicholasraimbault.silvervine.tray"` restores the icon.

If any physical-Mac requirement fails, the user restores 2.1.2:

```bash
cp "$HOME/.cargo/bin/silvervine-2.1.2.rollback" \
   "$HOME/.cargo/bin/silvervine.restore"
chmod 755 "$HOME/.cargo/bin/silvervine.restore"
mv "$HOME/.cargo/bin/silvervine.restore" \
   "$HOME/.cargo/bin/silvervine"
launchctl kickstart -k \
  "gui/$(id -u)/com.nicholasraimbault.silvervine.tray"
```

Do not merge or create `v2.1.3` until the physical confirmation passes.

---

### Task 4: Merge, publish, install, and reverify official 2.1.3

**Files:**
- GitHub pull request from `fix/macos-tray-event-loop` to `master`
- Git tag: `v2.1.3`
- Published release assets generated by `.github/workflows/release.yml`
- User-operated final Mac binary: `~/.cargo/bin/silvervine`

**Interfaces:**
- Consumes: green CI and the physical candidate confirmation from Task 3.
- Produces: merged source, official cargo-dist release, and a physical Mac running the official 2.1.3 artifact.

- [ ] **Step 1: Review and merge the pull request**

Record the failing 2.1.2 baseline, passing source gates, native macOS CI, and physical candidate observations in the PR body. Review the final diff for the approved invariants, mark the PR ready, and squash-merge only when every required check passes and no review finding remains.

- [ ] **Step 2: Tag the exact merged commit and monitor publication**

Fast-forward local `master` to the merged commit. Confirm `Cargo.toml` reports `2.1.3`, create annotated tag `v2.1.3` on that exact commit, and push the tag. Watch `.github/workflows/release.yml` to successful completion.

Required release state:

- release is neither draft nor prerelease;
- target commit equals the merged commit;
- all expected macOS and Linux archives, installers, and checksum files are uploaded;
- unified and per-archive checksums validate.

- [ ] **Step 3: Install the official latest release on the physical Mac**

The user replaces the branch-built candidate through the official installer:

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nicholasraimbault/silvervine/releases/latest/download/silvervine-installer.sh \
  | sh
launchctl kickstart -k \
  "gui/$(id -u)/com.nicholasraimbault.silvervine.tray"
silvervine --version
```

Required output: `silvervine 2.1.3`.

- [ ] **Step 4: Repeat the physical tray gate on the official binary**

Repeat Task 3 Steps 4-5 against the official installed binary: require policy `1`, a visible icon without a Dock icon, a working menu, clean Quit, successful LaunchAgent restart, and a fresh heartbeat. Independently download the published Apple Silicon archive and checksum, validate the archive, and confirm the published binary reports `silvervine 2.1.3`.

Remove `~/.cargo/bin/silvervine-2.1.2.rollback` only after the official-binary checks pass.
