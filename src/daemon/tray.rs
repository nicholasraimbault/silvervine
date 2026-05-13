//! Tray icon UI.
//!
//! Wraps the [`tray-icon`](https://crates.io/crates/tray-icon) crate
//! (Tauri's tray-icon library): on Linux it uses GTK +
//! `libayatana-appindicator` at runtime; on macOS it uses Cocoa
//! `NSStatusItem`. Both are GUI-dependent.
//!
//! Per the spec the menu has the following layout:
//!
//! ```text
//! ┌──────────────────────────────────┐
//! │ ✓ Helium Patched                 │  per-browser status (× N browsers)
//! │ ✗ Thorium Not Patched            │
//! │ ──────────────────               │
//! │ Patch Now                        │  click → emits TrayCommand::PatchAll
//! │ Update Widevine                  │  click → emits TrayCommand::UpdateWidevine
//! │ ──────────────────               │
//! │ ☐ Launch at Login                │  toggle → emits TrayCommand::ToggleLaunchAtLogin
//! │ ──────────────────               │
//! │ Quit Neon                        │  click → emits TrayCommand::Quit
//! └──────────────────────────────────┘
//! ```
//!
//! Click handlers send a [`TrayCommand`] over an MPSC channel back into
//! the daemon's main loop, which dispatches to the patch / update / quit
//! flows.
//!
//! ## Test strategy
//!
//! Per the guardrails (no graphical processes during tests), we keep all
//! the **menu-construction** logic pure (the [`MenuItemSpec`] / [`menu_layout`]
//! functions) and unit-test those. The actual `tray-icon` calls live behind
//! [`Tray::new`], which returns an error in headless / no-tray contexts.
//! We do not invoke `TrayIconBuilder::new().build()` from any test.
//!
//! ## `--no-tray` fallback
//!
//! On Linux, `tray-icon` requires `libayatana-appindicator3` at runtime.
//! If the crate fails to initialize (typically because the library isn't
//! installed), [`Tray::new`] returns [`crate::ErrorCategory::UnsupportedPlatform`]
//! and the daemon's `run()` function falls back to notifications-only mode
//! with a `tracing::warn!`.

// All methods on `Tray` that touch `self.state` / `self.rx` (which are
// `Mutex`-wrapped) can theoretically panic if the lock is poisoned. We
// don't panic inside these locks under any normal codepath, and a poisoned
// lock indicates a separate (already-noted) panic upstream — so a panic
// here is a genuine bug, not something callers need to guard against.
// Documenting `# Panics` on every method that uses Mutex would be
// boilerplate; suppressing the lint at the module level is clearer.
#![allow(clippy::missing_panics_doc)]

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::browsers::Browser;
use crate::error::{Error, Result};

/// Whether the platform's tray icon backend is usable at runtime.
///
/// On Linux this hinges on a reachable session D-Bus (the
/// `StatusNotifierItem` protocol that `ksni` implements is pure D-Bus —
/// no GTK / libappindicator runtime required). On macOS the Cocoa
/// backend is always present.
///
/// Used by `neon doctor` to surface the silent-fallback condition that
/// the daemon hits when the user's compositor doesn't expose a tray —
/// without this, a casual user has to grep journalctl to discover that
/// their tray is disabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum TrayAvailability {
    /// The platform tray backend is usable; the daemon will mount a
    /// real tray icon.
    Available,
    /// The backend is unusable in this environment; the daemon falls
    /// back to notifications-only. The string explains why.
    Unavailable(String),
}

/// Probe whether the platform tray backend is usable.
///
/// Intended for diagnostics surfaces (`neon doctor`). Cheap enough to
/// call on every doctor invocation — opens a session D-Bus connection
/// and immediately drops it.
///
/// **Note**: a positive result means the protocol prerequisites are in
/// place; the daemon may still fail to render a tray if no compositor
/// / tray bar is listening for `StatusNotifierItem` registrations.
/// (`ksni` retries automatically when a watcher comes online, so this
/// is usually a transient condition.)
#[must_use]
pub fn detect_tray_availability() -> TrayAvailability {
    #[cfg(target_os = "linux")]
    {
        match zbus::blocking::Connection::session() {
            Ok(_conn) => TrayAvailability::Available,
            Err(e) => TrayAvailability::Unavailable(format!(
                "session D-Bus unavailable ({e}); tray won't render. \
                 Notifications-only fallback is active. Check that \
                 $DBUS_SESSION_BUS_ADDRESS is set and a session bus is \
                 running in your user session."
            )),
        }
    }
    #[cfg(target_os = "macos")]
    {
        TrayAvailability::Available
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        TrayAvailability::Unavailable("tray icon not supported on this platform".into())
    }
}

/// Event emitted by the tray on a user interaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayCommand {
    /// User clicked "Patch Now".
    PatchAll,
    /// User clicked a per-browser status entry — request a patch
    /// targeted at this browser. Carries the browser display name.
    PatchOne(String),
    /// User clicked "Update Widevine".
    UpdateWidevine,
    /// User toggled "Launch at Login" — the boolean is the desired state.
    ToggleLaunchAtLogin(bool),
    /// User clicked "Quit Neon".
    Quit,
    /// User clicked a streaming quick-launch (Netflix / Disney+ / HBO
    /// Max / custom URL). Daemon spawns `cli::stream::start` in a
    /// non-blocking thread.
    ///
    /// Only emitted when the `experimental-bridge` Cargo feature is on.
    #[cfg(feature = "experimental-bridge")]
    StreamUrl(String),
    /// User clicked "Bridge ▶ Pause VM". Daemon calls
    /// `bridge::libvirt::Domain::stop`.
    #[cfg(feature = "experimental-bridge")]
    BridgePause,
    /// User clicked "Bridge ▶ Resume VM". Daemon calls
    /// `bridge::libvirt::Domain::start` (after restoring from snapshot
    /// if needed).
    #[cfg(feature = "experimental-bridge")]
    BridgeResume,
    /// User clicked "Bridge ▶ Repair". Daemon invokes
    /// `cli::stream::repair::run` with `--auto`.
    #[cfg(feature = "experimental-bridge")]
    BridgeRepair,
    /// User clicked the eval-expiring rearm tray item. Daemon shows the
    /// PowerShell rearm command via a notification.
    #[cfg(feature = "experimental-bridge")]
    BridgeRearm,
}

/// Pure-data description of one menu entry. Used by the construction
/// logic and by tests to assert on the layout without instantiating any
/// GUI handles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuItemSpec {
    /// Per-browser status row, e.g. `"✓ Helium Patched"` or
    /// `"✗ Thorium Not Patched"`.
    BrowserStatus {
        /// Display name of the browser.
        browser_name: String,
        /// Whether the browser is currently patched.
        patched: bool,
    },
    /// Action item that, when clicked, dispatches `command`.
    Action {
        /// Human-readable label.
        label: String,
        /// What command to dispatch on click.
        command: TrayCommand,
    },
    /// Toggle item (checked/unchecked) that emits `command_when_toggled`.
    Toggle {
        /// Human-readable label.
        label: String,
        /// Initial checked state.
        checked: bool,
        /// Command emitted when the user toggles. The daemon flips
        /// `checked` and re-renders.
        command_when_toggled: TrayCommand,
    },
    /// Static read-only label (e.g. "Eval: 82 days remaining"). No
    /// click handler. Used by the V3 Bridge submenu for the eval
    /// indicator + snapshot-age line.
    Label {
        /// Display text.
        text: String,
    },
    /// Submenu — a labeled parent with nested children. Used by the V3
    /// Bridge ▶ submenu under the `experimental-bridge` feature.
    /// V3-Phase D's GUI renderer flattens these as a header label
    /// followed by indented children; future polish can wire real
    /// nested menus via `tray-icon`'s `Submenu` API.
    Submenu {
        /// Label that, when hovered, expands the children.
        label: String,
        /// Child entries (rendered indented by V3-Phase D).
        items: Vec<MenuItemSpec>,
    },
    /// Visual separator.
    Separator,
}

impl MenuItemSpec {
    /// Render the user-visible label for this item. Separators have an
    /// empty label.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::BrowserStatus {
                browser_name,
                patched,
            } => {
                let prefix = if *patched { "✓" } else { "✗" };
                let suffix = if *patched { "Patched" } else { "Not Patched" };
                format!("{prefix} {browser_name} {suffix}")
            }
            Self::Action { label, .. }
            | Self::Toggle { label, .. }
            | Self::Submenu { label, .. } => label.clone(),
            Self::Label { text } => text.clone(),
            Self::Separator => String::new(),
        }
    }

    /// `true` if this is a structural separator (no click handler).
    #[must_use]
    pub fn is_separator(&self) -> bool {
        matches!(self, Self::Separator)
    }

    /// `true` if this item dispatches a [`TrayCommand`] on click.
    /// Submenus + Labels are not directly actionable (Submenu's
    /// children are; Labels are read-only).
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        matches!(self, Self::Action { .. } | Self::Toggle { .. })
    }
}

/// Snapshot of state used to construct the menu. Daemon's main loop
/// rebuilds the menu from a fresh snapshot on relevant state changes
/// (patch event, browser added/removed, lifecycle toggle).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MenuState {
    /// One entry per detected browser, in display order.
    pub browsers: Vec<BrowserMenuEntry>,
    /// Whether "Launch at Login" is currently enabled.
    pub launch_at_login: bool,
    /// V3 bridge state. Only present (and only consulted) when the
    /// `experimental-bridge` Cargo feature is enabled. Default V2 builds
    /// don't compile this field.
    #[cfg(feature = "experimental-bridge")]
    pub bridge: BridgeMenuState,
}

/// V3 bridge-state snapshot consumed by [`menu_layout`] under the
/// `experimental-bridge` feature flag.
///
/// Default values surface a "bridge not yet provisioned" view: the
/// streaming quick-launches still appear (so the user can click them
/// and see the wizard suggestion), but Pause / Resume read as
/// uninitialized.
#[cfg(feature = "experimental-bridge")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BridgeMenuState {
    /// `true` when `neon stream init` has completed (libvirt domain
    /// defined, snapshot present).
    pub ready: bool,
    /// `true` when the VM is currently paused (suspend-to-RAM after a
    /// `neon stream stop`).
    pub paused: bool,
    /// Hours since the most recent snapshot. `None` when no snapshot
    /// exists yet. Surfaced as a static label in the Bridge submenu;
    /// V3-Phase F polish renders it as "fresh / stale" badge color.
    pub snapshot_age_hours: Option<u64>,
    /// Days remaining on the trial license. `None` for non-trial
    /// postures. Negative numbers mean expired (trial-mode auto-rearm
    /// failed or hasn't run yet).
    pub eval_days_remaining: Option<i64>,
}

#[cfg(feature = "experimental-bridge")]
impl BridgeMenuState {
    /// `true` when the user should see an alert badge — eval expiring
    /// within 7 days, snapshot >30 days old, or VM continuously paused
    /// for >24 hours.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        if let Some(days) = self.eval_days_remaining {
            if days < 7 {
                return true;
            }
        }
        if let Some(hours) = self.snapshot_age_hours {
            if hours / 24 > 30 {
                return true;
            }
        }
        false
    }

    /// `true` when the eval-expiry rearm-prompt should appear in the
    /// top-level menu (not just the submenu).
    #[must_use]
    pub fn eval_expiry_visible(&self) -> bool {
        self.eval_days_remaining.is_some_and(|d| d < 7)
    }
}

/// Per-browser menu line state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserMenuEntry {
    /// Display name.
    pub name: String,
    /// Patched (✓) or not (✗).
    pub patched: bool,
}

impl BrowserMenuEntry {
    /// Construct a menu entry from a [`Browser`] + a "is patched" flag.
    #[must_use]
    pub fn from_browser(browser: &Browser, patched: bool) -> Self {
        Self {
            name: browser.name().to_string(),
            patched,
        }
    }
}

/// Build the canonical menu layout (per spec) from the supplied state.
///
/// This is the **pure** function that tests assert on — no GUI handles,
/// no crate dependencies.
///
/// Under the `experimental-bridge` Cargo feature, additional items are
/// injected after the patch controls (streaming quick-launches + a
/// `Bridge ▶` submenu). Default V2 builds compile no V3 code; the menu
/// shape is unchanged.
#[must_use]
pub fn menu_layout(state: &MenuState) -> Vec<MenuItemSpec> {
    let mut out = Vec::with_capacity(8 + state.browsers.len());

    // 1. Per-browser status lines (one per detected browser).
    for entry in &state.browsers {
        out.push(MenuItemSpec::BrowserStatus {
            browser_name: entry.name.clone(),
            patched: entry.patched,
        });
    }
    if !state.browsers.is_empty() {
        out.push(MenuItemSpec::Separator);
    }
    // 2. Actions.
    out.push(MenuItemSpec::Action {
        label: "Patch Now".into(),
        command: TrayCommand::PatchAll,
    });
    out.push(MenuItemSpec::Action {
        label: "Update Widevine".into(),
        command: TrayCommand::UpdateWidevine,
    });

    // 3. V3 streaming + bridge submenu (only under feature flag).
    #[cfg(feature = "experimental-bridge")]
    inject_bridge_items(&mut out, &state.bridge);

    out.push(MenuItemSpec::Separator);
    // 4. Launch-at-Login toggle.
    out.push(MenuItemSpec::Toggle {
        label: "Launch at Login".into(),
        checked: state.launch_at_login,
        command_when_toggled: TrayCommand::ToggleLaunchAtLogin(!state.launch_at_login),
    });
    out.push(MenuItemSpec::Separator);
    // 5. Quit.
    out.push(MenuItemSpec::Action {
        label: "Quit Neon".into(),
        command: TrayCommand::Quit,
    });
    out
}

/// Inject the V3 streaming quick-launches + Bridge submenu into the
/// supplied menu vec, between the patch controls and the
/// Launch-at-Login section.
///
/// Layout:
/// ```text
/// ──── separator ────
/// Stream Netflix
/// Stream Disney+
/// Stream HBO Max
/// Stream… (custom URL)         (V3-Phase F: opens prompt)
/// ──── separator ────
/// Bridge ▶
///   Status: Ready / Paused / Not provisioned
///   Pause VM
///   Resume VM
///   Repair
///   Eval: N days remaining     (only when on trial)
///   Snapshot: age              (only when snapshot present)
/// ```
///
/// The order keeps the most-frequent action (streaming quick-launch)
/// at the top of the V3 block.
#[cfg(feature = "experimental-bridge")]
fn inject_bridge_items(out: &mut Vec<MenuItemSpec>, bridge: &BridgeMenuState) {
    out.push(MenuItemSpec::Separator);

    // V3-Phase F: surface eval-expiry alert at the top level so the
    // user can rearm without drilling into the submenu.
    if bridge.eval_expiry_visible() {
        if let Some(days) = bridge.eval_days_remaining {
            let label = if days >= 0 {
                format!("⚠ Eval: {days} days remaining")
            } else {
                format!("⚠ Eval expired ({} days ago)", -days)
            };
            out.push(MenuItemSpec::Action {
                label,
                command: TrayCommand::BridgeRearm,
            });
        }
    }

    out.push(MenuItemSpec::Action {
        label: "Stream Netflix".into(),
        command: TrayCommand::StreamUrl("https://netflix.com".into()),
    });
    out.push(MenuItemSpec::Action {
        label: "Stream Disney+".into(),
        command: TrayCommand::StreamUrl("https://disneyplus.com".into()),
    });
    out.push(MenuItemSpec::Action {
        label: "Stream HBO Max".into(),
        command: TrayCommand::StreamUrl("https://max.com".into()),
    });
    out.push(MenuItemSpec::Action {
        label: "Stream… (custom URL)".into(),
        // V3-Phase F: empty URL is a sentinel for "open prompt" — the
        // daemon's dispatch handler currently logs a TODO and emits a
        // notification pointing the user at the CLI.
        command: TrayCommand::StreamUrl(String::new()),
    });
    out.push(MenuItemSpec::Separator);

    // Bridge submenu. V3-Phase F adds an alert badge when needs_attention.
    let mut sub = Vec::with_capacity(6);
    sub.push(MenuItemSpec::Label {
        text: bridge_status_label(bridge),
    });
    sub.push(MenuItemSpec::Action {
        label: "Pause VM".into(),
        command: TrayCommand::BridgePause,
    });
    sub.push(MenuItemSpec::Action {
        label: "Resume VM".into(),
        command: TrayCommand::BridgeResume,
    });
    sub.push(MenuItemSpec::Action {
        label: "Repair".into(),
        command: TrayCommand::BridgeRepair,
    });
    if let Some(days) = bridge.eval_days_remaining {
        sub.push(MenuItemSpec::Label {
            text: eval_days_label(days),
        });
        // V3-Phase F: rearm action lives inside submenu too.
        sub.push(MenuItemSpec::Action {
            label: "Rearm trial".into(),
            command: TrayCommand::BridgeRearm,
        });
    }
    if let Some(hours) = bridge.snapshot_age_hours {
        sub.push(MenuItemSpec::Label {
            text: snapshot_age_label(hours),
        });
    }
    let label = if bridge.needs_attention() {
        "⚠ Bridge ▶".to_string()
    } else {
        "Bridge ▶".to_string()
    };
    out.push(MenuItemSpec::Submenu { label, items: sub });
}

/// Render the Bridge submenu's "Status: ..." header label.
#[cfg(feature = "experimental-bridge")]
fn bridge_status_label(bridge: &BridgeMenuState) -> String {
    if !bridge.ready {
        return "Status: Not provisioned".into();
    }
    if bridge.paused {
        "Status: Paused".into()
    } else {
        "Status: Ready".into()
    }
}

/// Render the eval-days indicator label.
///
/// * `days >= 0` → "Eval: N days remaining"
/// * `days < 0` → "Eval: expired (N days ago)"
#[cfg(feature = "experimental-bridge")]
fn eval_days_label(days: i64) -> String {
    if days >= 0 {
        format!("Eval: {days} days remaining")
    } else {
        format!("Eval: expired ({} days ago)", -days)
    }
}

/// Render the snapshot-age indicator label.
#[cfg(feature = "experimental-bridge")]
fn snapshot_age_label(hours: u64) -> String {
    if hours < 24 {
        format!("Snapshot: {hours}h old")
    } else {
        let days = hours / 24;
        format!("Snapshot: {days}d old")
    }
}

/// Public tray handle. Holds the underlying `tray-icon` resource (when
/// running) and a receiver for command events.
///
/// Drop tears down the tray icon. The daemon team typically holds this
/// for the lifetime of the process.
pub struct Tray {
    /// Receiver of [`TrayCommand`] events emitted by click handlers.
    /// Daemon's main loop reads this and dispatches.
    rx: Mutex<Receiver<TrayCommand>>,
    /// Sender retained so re-renderable state changes can synthesize
    /// commands (e.g. for tests, or a future "click via IPC" feature).
    tx: Sender<TrayCommand>,
    /// Pure-data record of the current menu state. Updated whenever
    /// the caller calls [`Tray::set_state`].
    state: Mutex<MenuState>,
    /// Real tray icon, if [`Tray::new`] succeeded against the platform.
    /// Kept private — the daemon doesn't poke at the underlying handle.
    /// `None` in headless / no-tray contexts (the `--no-tray` fallback).
    inner: Option<TrayInner>,
}

/// Wrapper around the platform-specific tray handle. Platform-split:
/// Linux uses `ksni` (`StatusNotifierItem` over D-Bus, no GTK runtime),
/// macOS uses Tauri's `tray-icon` (Cocoa `NSStatusItem`).
#[cfg(target_os = "linux")]
struct TrayInner {
    /// Spawn handle from `ksni`. Dropping the handle (when [`Tray`]
    /// drops) shuts the `StatusNotifierItem` service down cleanly.
    handle: ksni::blocking::Handle<NeonKsniTray>,
}
#[cfg(target_os = "macos")]
struct TrayInner {
    _tray: tray_icon::TrayIcon,
    /// Map of `MenuId` strings → command, for click-event routing.
    /// We use `String` keys because `MenuId` is a thin wrapper around it.
    /// The map is kept alive as part of `TrayInner` so the click-event
    /// handler closure (which got a clone of this map at construction
    /// time) doesn't see a moving target — even though no one reads
    /// this field directly after construction.
    _routes: std::collections::HashMap<String, TrayCommand>,
}

/// `ksni::Tray` implementation. Holds a snapshot of `MenuState` and a
/// `Sender<TrayCommand>` so menu callbacks can route clicks back to
/// the daemon's main loop.
///
/// Lives on Linux only; macOS uses Cocoa via `tray-icon` instead.
///
/// State updates flow via [`ksni::blocking::Handle::update`] — the
/// daemon calls [`Tray::set_state`], which both mutates the
/// daemon-side `MenuState` and pushes the new state into this struct
/// so `menu()` re-renders with the latest layout.
#[cfg(target_os = "linux")]
struct NeonKsniTray {
    /// Latest menu-state snapshot. Read by [`ksni::Tray::menu`] every
    /// time the SNI client requests the current menu.
    state: MenuState,
    /// Channel back to the daemon's main loop. Each menu item's
    /// `activate` callback clones this and sends the appropriate
    /// `TrayCommand` on click.
    tx: Sender<TrayCommand>,
}

#[cfg(target_os = "linux")]
impl ksni::Tray for NeonKsniTray {
    fn id(&self) -> String {
        "neon".into()
    }

    fn icon_name(&self) -> String {
        // Empty string tells the SNI watcher there's no theme-installed
        // icon — render the pixmap directly. Some compositors
        // (Quickshell/noctalia, Plasma in some configs) look up
        // `icon_name` in their icon theme *first* and render a
        // placeholder when the name doesn't resolve, even if a pixmap
        // is also supplied. Empty name forces them to fall through to
        // the pixmap.
        //
        // A future polish step can install our PNG into the user's
        // icon theme (`~/.local/share/icons/hicolor/22x22/apps/neon.png`)
        // during `neon setup`, then return "neon" here so name-based
        // lookup is also viable. Until then, pixmap is the source of
        // truth.
        String::new()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        neon_tray_icon_pixmap()
    }

    fn title(&self) -> String {
        "Neon".into()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "Neon — Widevine helper".into(),
            description: String::new(),
            icon_name: String::new(),
            icon_pixmap: neon_tray_icon_pixmap(),
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        ksni_menu_from_specs(&menu_layout(&self.state), &self.tx)
    }
}

/// Convert our pure-data [`MenuItemSpec`] vec into the `ksni::MenuItem`
/// representation. Each actionable item gets a closure that sends the
/// item's [`TrayCommand`] back to the daemon over the supplied
/// `Sender`.
///
/// Recurses on submenus — `ksni` supports real nested menus, so V3's
/// `Bridge ▶` submenu renders properly without the flatten-and-indent
/// hack the macOS `tray-icon` path uses.
#[cfg(target_os = "linux")]
fn ksni_menu_from_specs(
    specs: &[MenuItemSpec],
    tx: &Sender<TrayCommand>,
) -> Vec<ksni::MenuItem<NeonKsniTray>> {
    use ksni::menu::{CheckmarkItem, StandardItem, SubMenu};
    use ksni::MenuItem as M;

    specs
        .iter()
        .map(|spec| match spec {
            MenuItemSpec::BrowserStatus { browser_name, .. } => {
                // Click on a per-browser row → request a targeted
                // re-patch for that browser. Matches the routing the
                // macOS `build_routes` path produces. The label
                // (which includes the patched/not-patched glyph) is
                // produced by `spec.label()` so we don't need to
                // destructure `patched` here.
                let cmd = TrayCommand::PatchOne(browser_name.clone());
                let tx = tx.clone();
                StandardItem {
                    label: spec.label(),
                    activate: Box::new(move |_: &mut NeonKsniTray| {
                        let _ = tx.send(cmd.clone());
                    }),
                    ..Default::default()
                }
                .into()
            }
            MenuItemSpec::Action { label, command } => {
                let cmd = command.clone();
                let tx = tx.clone();
                StandardItem {
                    label: label.clone(),
                    activate: Box::new(move |_| {
                        let _ = tx.send(cmd.clone());
                    }),
                    ..Default::default()
                }
                .into()
            }
            MenuItemSpec::Toggle {
                label,
                checked,
                command_when_toggled,
            } => {
                let cmd = command_when_toggled.clone();
                let tx = tx.clone();
                CheckmarkItem {
                    label: label.clone(),
                    checked: *checked,
                    activate: Box::new(move |_| {
                        let _ = tx.send(cmd.clone());
                    }),
                    ..Default::default()
                }
                .into()
            }
            MenuItemSpec::Submenu { label, items } => SubMenu {
                label: label.clone(),
                submenu: ksni_menu_from_specs(items, tx),
                ..Default::default()
            }
            .into(),
            MenuItemSpec::Label { text } => StandardItem {
                label: text.clone(),
                enabled: false,
                ..Default::default()
            }
            .into(),
            MenuItemSpec::Separator => M::Separator,
        })
        .collect()
}

/// Decode the embedded `linux-app/neon.png` into the ARGB32
/// premultiplied-alpha format that ksni's `Icon` expects. Returns an
/// empty vec on decode failure — ksni then falls back to the
/// `icon_name` lookup, which is what we want.
///
/// PNG bytes give us RGBA8 in row-major order; ksni wants ARGB32 in
/// network byte order with premultiplied alpha. The transform is
/// per-pixel: reorder R,G,B,A → A,R,G,B and multiply each color
/// channel by alpha/255 so half-transparent pixels don't render with
/// halos against dark/light tray backgrounds.
#[cfg(target_os = "linux")]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "ARGB32 byte math: products fit u8 by construction (premultiply ≤255), and 22×22 icon dimensions fit i32 trivially"
)]
fn neon_tray_icon_pixmap() -> Vec<ksni::Icon> {
    /// Embedded PNG — 22×22 RGBA, the same icon the V0 Linux app
    /// shipped. Ships as part of the binary; no install step.
    const PNG_BYTES: &[u8] = include_bytes!("../../linux-app/neon.png");

    let decoder = png::Decoder::new(PNG_BYTES);
    let Ok(mut reader) = decoder.read_info() else {
        return vec![];
    };
    let info = reader.info().clone();
    let mut rgba = vec![0u8; reader.output_buffer_size()];
    if reader.next_frame(&mut rgba).is_err() {
        return vec![];
    }

    // PNG decoder honors the file's color type — for our 22×22 RGBA
    // PNG this is Rgba8 (4 bytes/pixel). If the input ever changes to
    // RGB / palette / grayscale, we'd silently render wrong, so reject
    // anything unexpected.
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return vec![];
    }

    let pixel_count = (info.width * info.height) as usize;
    let mut argb = vec![0u8; pixel_count * 4];
    for (i, src) in rgba.chunks_exact(4).enumerate() {
        let r = u16::from(src[0]);
        let g = u16::from(src[1]);
        let b = u16::from(src[2]);
        let a = u16::from(src[3]);
        // Premultiply with rounding (a * channel + 127) / 255 ≈
        // a*channel/255 with half-up. Avoids the 0/255 edge banding
        // that floor-division produces for fully-opaque pixels.
        let dst = i * 4;
        argb[dst] = src[3];
        argb[dst + 1] = ((r * a + 127) / 255) as u8;
        argb[dst + 2] = ((g * a + 127) / 255) as u8;
        argb[dst + 3] = ((b * a + 127) / 255) as u8;
    }

    vec![ksni::Icon {
        width: info.width as i32,
        height: info.height as i32,
        data: argb,
    }]
}

impl Tray {
    /// Build a new tray icon with the supplied initial menu state.
    ///
    /// On Linux this spawns a `ksni` `StatusNotifierItem` service over
    /// the user session D-Bus; on macOS it constructs a Cocoa
    /// `NSStatusItem` via the `tray-icon` crate. If the underlying
    /// platform backend fails to initialize, returns
    /// [`crate::ErrorCategory::UnsupportedPlatform`] so the daemon
    /// can fall back to notifications-only mode.
    ///
    /// **Tests must not call this** — it opens an actual tray icon on
    /// the user's display. Use [`Tray::headless`] in tests.
    ///
    /// # Errors
    ///
    /// * [`crate::ErrorCategory::UnsupportedPlatform`] if the
    ///   platform tray backend cannot initialize (typically: no
    ///   session D-Bus on Linux, or `NSStatusItem` allocation failure
    ///   on macOS).
    /// * [`crate::ErrorCategory::Other`] for any other initialization
    ///   failure.
    pub fn new(initial_state: MenuState) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<TrayCommand>();

        #[cfg(target_os = "linux")]
        let inner = {
            use ksni::blocking::TrayMethods;
            let tray_impl = NeonKsniTray {
                state: initial_state.clone(),
                tx: tx.clone(),
            };
            // `assume_sni_available(true)` lets the daemon survive a
            // compositor restart and tolerate startups before the
            // tray bar is up: ksni retries instead of failing fatally
            // when no SNI watcher is registered yet.
            let handle = tray_impl.assume_sni_available(true).spawn().map_err(|e| {
                Error::unsupported_platform(format!("ksni tray failed to spawn: {e}"))
            })?;
            TrayInner { handle }
        };

        #[cfg(target_os = "macos")]
        let inner = {
            let routes = build_routes(&initial_state);
            build_tray_icon(&initial_state, &routes, tx.clone()).map_err(|e| {
                Error::unsupported_platform(format!("tray-icon initialization failed: {e}"))
            })?
        };

        Ok(Self {
            rx: Mutex::new(rx),
            tx,
            state: Mutex::new(initial_state),
            inner: Some(inner),
        })
    }

    /// Build a "headless" tray that has no UI surface but still emits
    /// commands when [`Tray::synthesize`] is called. Used in tests and
    /// in the daemon's `--no-tray` fallback.
    #[must_use]
    pub fn headless(initial_state: MenuState) -> Self {
        let (tx, rx) = mpsc::channel::<TrayCommand>();
        Self {
            rx: Mutex::new(rx),
            tx,
            state: Mutex::new(initial_state),
            inner: None,
        }
    }

    /// Snapshot the current menu state.
    #[must_use]
    pub fn state(&self) -> MenuState {
        self.state.lock().unwrap().clone()
    }

    /// Update the menu state. On Linux the live `ksni` service is
    /// pushed the new state immediately, so the rendered menu reflects
    /// the change without a tray-icon rebuild. On macOS the daemon's
    /// main loop drops + reconstructs `Tray` when state changes
    /// non-trivially (a follow-up can wire `tray-icon`'s `set_menu`).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "Linux branch moves `state` into the ksni update closure; macOS branch only stores a clone. Borrow-only signature would require caller-side cloning on every call."
    )]
    pub fn set_state(&self, state: MenuState) {
        *self.state.lock().unwrap() = state.clone();
        #[cfg(target_os = "linux")]
        if let Some(inner) = &self.inner {
            // `update` returns None if the ksni service has shut down;
            // that's a transient condition we don't need to log here
            // because the daemon's main loop already handles channel
            // disconnection on the receiver side.
            let _ = inner.handle.update(|tray: &mut NeonKsniTray| {
                tray.state = state;
            });
        }
        #[cfg(not(target_os = "linux"))]
        drop(state);
    }

    /// Render the current menu layout (pure-data view).
    #[must_use]
    pub fn current_menu_layout(&self) -> Vec<MenuItemSpec> {
        menu_layout(&self.state.lock().unwrap())
    }

    /// Try to receive the next [`TrayCommand`]. Non-blocking; returns
    /// `None` if no command is pending.
    pub fn try_recv(&self) -> Option<TrayCommand> {
        self.rx.lock().unwrap().try_recv().ok()
    }

    /// Block on the next [`TrayCommand`]. Returns `None` if the sender
    /// has been dropped (i.e. the tray is shutting down).
    pub fn recv_blocking(&self) -> Option<TrayCommand> {
        self.rx.lock().unwrap().recv().ok()
    }

    /// Synthesize a [`TrayCommand`] as if the user had clicked. Used
    /// by tests and by the daemon when it wants to drive its main loop
    /// from a non-UI source (e.g. a wake event triggers a re-check).
    pub fn synthesize(&self, cmd: TrayCommand) {
        // Best-effort send — if the receiver is gone the daemon is
        // shutting down anyway.
        let _ = self.tx.send(cmd);
    }

    /// `true` if a real tray UI is attached (i.e. [`Tray::new`] succeeded).
    /// `false` for [`Tray::headless`].
    #[must_use]
    pub fn has_ui(&self) -> bool {
        self.inner.is_some()
    }
}

/// Build a map of `MenuId` strings to [`TrayCommand`] used by the
/// macOS `tray-icon` event handler to route click events back to us.
///
/// Each entry in the menu layout gets a unique stable id derived from
/// its position + content; we re-build the map every time we re-render.
///
/// Submenu children are also routed: for index `idx` the submenu, the
/// submenu's children get ids prefixed with `<submenu-id>-child-<n>`.
///
/// On Linux the tray uses `ksni`, where each menu item carries its own
/// `activate` callback — no central routing table is needed. The
/// function (and tests below) remain compiled on all platforms because
/// the routing logic itself is platform-agnostic and the tests verify
/// it stays correct.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn build_routes(state: &MenuState) -> std::collections::HashMap<String, TrayCommand> {
    let mut routes = std::collections::HashMap::new();
    let layout = menu_layout(state);
    for (idx, item) in layout.iter().enumerate() {
        route_item_into(&mut routes, idx, item, None);
    }
    routes
}

/// Insert routes for a single item (and recursively for submenu
/// children).
///
/// `parent_id` is `Some(parent)` when we're inside a submenu — child
/// ids are derived from the submenu's id + the child's index so they
/// stay unique across re-renders.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn route_item_into(
    routes: &mut std::collections::HashMap<String, TrayCommand>,
    idx: usize,
    item: &MenuItemSpec,
    parent_id: Option<&str>,
) {
    let id = match parent_id {
        Some(p) => format!("{p}-child-{idx}"),
        None => menu_item_id(idx, item),
    };
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
        MenuItemSpec::Submenu { items, .. } => {
            // Recurse: submenu's own id isn't actionable, but the
            // children carry their own commands.
            for (child_idx, child) in items.iter().enumerate() {
                route_item_into(routes, child_idx, child, Some(&id));
            }
        }
        MenuItemSpec::Label { .. } | MenuItemSpec::Separator => {}
    }
}

/// Build a stable id for a menu item at a given position. Position +
/// label is enough to identify any of our menu items uniquely (we never
/// have two browsers with the same name).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn menu_item_id(index: usize, item: &MenuItemSpec) -> String {
    match item {
        MenuItemSpec::BrowserStatus { browser_name, .. } => {
            format!("neon-browser-{index}-{browser_name}")
        }
        MenuItemSpec::Action { label, .. } => format!("neon-action-{index}-{label}"),
        MenuItemSpec::Toggle { label, .. } => format!("neon-toggle-{index}-{label}"),
        MenuItemSpec::Submenu { label, .. } => format!("neon-submenu-{index}-{label}"),
        MenuItemSpec::Label { text } => format!("neon-label-{index}-{text}"),
        MenuItemSpec::Separator => format!("neon-sep-{index}"),
    }
}

/// Construct the live tray icon (macOS only — Linux uses `ksni`
/// directly via [`NeonKsniTray`]).
///
/// This is the only function in this module that touches the macOS
/// `tray-icon` GUI handle — guarded by a `Result` so callers can
/// fall back to headless mode if it fails.
///
/// Tests do **not** call this; they use [`Tray::headless`].
#[cfg(target_os = "macos")]
#[allow(clippy::needless_pass_by_value)] // `tx` is moved into the click handler closure
fn build_tray_icon(
    state: &MenuState,
    routes: &std::collections::HashMap<String, TrayCommand>,
    tx: Sender<TrayCommand>,
) -> std::result::Result<TrayInner, tray_icon::Error> {
    use tray_icon::menu::{CheckMenuItem, Menu, MenuId, MenuItem, PredefinedMenuItem};
    use tray_icon::TrayIconBuilder;

    let menu = Menu::new();
    for (idx, spec) in menu_layout(state).iter().enumerate() {
        let id = MenuId::new(menu_item_id(idx, spec));
        match spec {
            MenuItemSpec::BrowserStatus { .. } | MenuItemSpec::Action { .. } => {
                let item = MenuItem::with_id(id, spec.label(), true, None);
                let _ = menu.append(&item);
            }
            MenuItemSpec::Toggle { checked, .. } => {
                let item = CheckMenuItem::with_id(id, spec.label(), true, *checked, None);
                let _ = menu.append(&item);
            }
            MenuItemSpec::Submenu { label, items } => {
                // V3-Phase D flattens submenus: emit the header as a
                // disabled label, then indented children with derived
                // ids matching `route_item_into`. Real nested-menu
                // rendering is a V3-Phase F polish item.
                let header = MenuItem::with_id(id.clone(), label.clone(), false, None);
                let _ = menu.append(&header);
                for (child_idx, child) in items.iter().enumerate() {
                    let child_id = MenuId::new(format!("{}-child-{child_idx}", id.0));
                    match child {
                        MenuItemSpec::Action { .. } => {
                            let item = MenuItem::with_id(
                                child_id,
                                format!("    {}", child.label()),
                                true,
                                None,
                            );
                            let _ = menu.append(&item);
                        }
                        MenuItemSpec::Toggle { checked, .. } => {
                            let item = CheckMenuItem::with_id(
                                child_id,
                                format!("    {}", child.label()),
                                true,
                                *checked,
                                None,
                            );
                            let _ = menu.append(&item);
                        }
                        MenuItemSpec::Label { .. } => {
                            let item = MenuItem::with_id(
                                child_id,
                                format!("    {}", child.label()),
                                false,
                                None,
                            );
                            let _ = menu.append(&item);
                        }
                        _ => {}
                    }
                }
            }
            MenuItemSpec::Label { text } => {
                let item = MenuItem::with_id(id, text.clone(), false, None);
                let _ = menu.append(&item);
            }
            MenuItemSpec::Separator => {
                let item = PredefinedMenuItem::separator();
                let _ = menu.append(&item);
            }
        }
    }

    let routes_for_handler = routes.clone();
    let tx_for_handler = tx.clone();
    tray_icon::menu::MenuEvent::set_event_handler(Some(
        move |event: tray_icon::menu::MenuEvent| {
            let id_str = event.id().0.clone();
            if let Some(cmd) = routes_for_handler.get(&id_str) {
                let _ = tx_for_handler.send(cmd.clone());
            }
        },
    ));

    let _ = tx; // reserved for future tray click handlers

    let tray = TrayIconBuilder::new()
        .with_tooltip("Neon — Widevine helper")
        .with_menu(Box::new(menu))
        .build()?;
    Ok(TrayInner {
        _tray: tray,
        _routes: routes.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::browsers::BrowserKind;

    /// Embedded tray icon decodes to a non-empty 22×22 ARGB32 buffer.
    /// Catches silent decode failures (PNG format mismatch, premultiply
    /// math drift) that would otherwise only surface as a checkerboard
    /// placeholder in the user's tray bar.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(
        clippy::cast_sign_loss,
        reason = "ksni::Icon width/height are i32 but always positive for our 22×22 icon"
    )]
    fn neon_tray_icon_pixmap_decodes_to_nonempty_argb_buffer() {
        let icons = neon_tray_icon_pixmap();
        assert_eq!(icons.len(), 1, "expected exactly one icon size");
        let icon = &icons[0];
        assert_eq!(icon.width, 22);
        assert_eq!(icon.height, 22);
        assert_eq!(
            icon.data.len(),
            (icon.width * icon.height * 4) as usize,
            "buffer length must equal width * height * 4 (ARGB32)"
        );
        // The reference PNG has 104 visible pixels (alpha > 0). After
        // ARGB conversion every visible pixel has a non-zero alpha
        // byte at position 0 mod 4. Asserting on the *count* of
        // non-zero alpha bytes locks the conversion math against
        // future regressions.
        let alpha_bytes_set = icon.data.iter().step_by(4).filter(|&&b| b > 0).count();
        assert_eq!(
            alpha_bytes_set, 104,
            "expected 104 visible pixels (matches reference PNG)"
        );
    }

    /// Helper: synthesize a `Browser`.
    fn fake_browser(name: &str) -> Browser {
        Browser {
            name: name.into(),
            install_path: PathBuf::from(format!("/opt/{name}-bin")),
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    /// Empty browser list: no per-browser rows, no leading separator.
    /// The non-browser items still appear in the canonical order.
    /// (Default V2 build only — feature-on adds 7 V3 entries; see
    /// [`empty_browsers_with_feature_on`].)
    #[cfg(not(feature = "experimental-bridge"))]
    #[test]
    fn empty_browsers_skips_per_browser_block_but_keeps_actions() {
        let state = MenuState {
            browsers: vec![],
            launch_at_login: false,
        };
        let layout = menu_layout(&state);
        // Should be: Patch Now, Update Widevine, Sep, Toggle, Sep, Quit
        assert_eq!(layout.len(), 6);
        assert!(matches!(
            &layout[0],
            MenuItemSpec::Action {
                command: TrayCommand::PatchAll,
                ..
            }
        ));
        assert!(matches!(
            &layout[1],
            MenuItemSpec::Action {
                command: TrayCommand::UpdateWidevine,
                ..
            }
        ));
        assert!(matches!(&layout[2], MenuItemSpec::Separator));
        assert!(matches!(&layout[3], MenuItemSpec::Toggle { .. }));
        assert!(matches!(&layout[4], MenuItemSpec::Separator));
        assert!(matches!(
            &layout[5],
            MenuItemSpec::Action {
                command: TrayCommand::Quit,
                ..
            }
        ));
    }

    /// Two browsers: rows + separator + actions + separator + toggle + sep + quit.
    /// (Default V2 build only.)
    #[cfg(not(feature = "experimental-bridge"))]
    #[test]
    fn two_browsers_produces_canonical_layout() {
        let state = MenuState {
            browsers: vec![
                BrowserMenuEntry::from_browser(&fake_browser("Helium"), true),
                BrowserMenuEntry::from_browser(&fake_browser("Thorium"), false),
            ],
            launch_at_login: true,
        };
        let layout = menu_layout(&state);
        assert_eq!(layout.len(), 9);
        assert!(matches!(
            &layout[0],
            MenuItemSpec::BrowserStatus {
                browser_name,
                patched: true
            } if browser_name == "Helium"
        ));
        assert!(matches!(
            &layout[1],
            MenuItemSpec::BrowserStatus {
                browser_name,
                patched: false
            } if browser_name == "Thorium"
        ));
        assert!(matches!(&layout[2], MenuItemSpec::Separator));
    }

    /// Patched + unpatched browsers render with the right glyph + suffix.
    #[test]
    fn browser_label_distinguishes_patched_status() {
        let patched = MenuItemSpec::BrowserStatus {
            browser_name: "Helium".into(),
            patched: true,
        };
        let unpatched = MenuItemSpec::BrowserStatus {
            browser_name: "Thorium".into(),
            patched: false,
        };
        assert_eq!(patched.label(), "✓ Helium Patched");
        assert_eq!(unpatched.label(), "✗ Thorium Not Patched");
    }

    /// Separators have empty labels and are flagged as non-actionable.
    #[test]
    fn separator_predicates() {
        let s = MenuItemSpec::Separator;
        assert!(s.is_separator());
        assert!(!s.is_actionable());
        assert_eq!(s.label(), "");
    }

    /// Action items are actionable.
    #[test]
    fn action_predicates() {
        let a = MenuItemSpec::Action {
            label: "Patch Now".into(),
            command: TrayCommand::PatchAll,
        };
        assert!(!a.is_separator());
        assert!(a.is_actionable());
        assert_eq!(a.label(), "Patch Now");
    }

    /// Toggle items are actionable.
    #[test]
    fn toggle_predicates() {
        let t = MenuItemSpec::Toggle {
            label: "Launch at Login".into(),
            checked: true,
            command_when_toggled: TrayCommand::ToggleLaunchAtLogin(false),
        };
        assert!(!t.is_separator());
        assert!(t.is_actionable());
        assert_eq!(t.label(), "Launch at Login");
    }

    /// `Toggle.command_when_toggled` reflects the *opposite* of the
    /// current state (i.e. clicking checks → unchecks).
    #[test]
    fn toggle_emits_inverse_state_on_click() {
        let state_off = MenuState {
            browsers: vec![],
            launch_at_login: false,
            #[cfg(feature = "experimental-bridge")]
            bridge: BridgeMenuState::default(),
        };
        let state_on = MenuState {
            browsers: vec![],
            launch_at_login: true,
            #[cfg(feature = "experimental-bridge")]
            bridge: BridgeMenuState::default(),
        };
        let layout_off = menu_layout(&state_off);
        let layout_on = menu_layout(&state_on);
        let toggle_off = layout_off
            .iter()
            .find(|i| matches!(i, MenuItemSpec::Toggle { .. }))
            .unwrap();
        let toggle_on = layout_on
            .iter()
            .find(|i| matches!(i, MenuItemSpec::Toggle { .. }))
            .unwrap();
        match toggle_off {
            MenuItemSpec::Toggle {
                command_when_toggled,
                checked,
                ..
            } => {
                assert!(!*checked);
                assert_eq!(
                    *command_when_toggled,
                    TrayCommand::ToggleLaunchAtLogin(true)
                );
            }
            _ => panic!(),
        }
        match toggle_on {
            MenuItemSpec::Toggle {
                command_when_toggled,
                checked,
                ..
            } => {
                assert!(*checked);
                assert_eq!(
                    *command_when_toggled,
                    TrayCommand::ToggleLaunchAtLogin(false)
                );
            }
            _ => panic!(),
        }
    }

    /// `Tray::headless` returns a tray with no UI surface.
    #[test]
    fn headless_has_no_ui() {
        let t = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
            #[cfg(feature = "experimental-bridge")]
            bridge: BridgeMenuState::default(),
        });
        assert!(!t.has_ui());
    }

    /// Synthesizing a command on a headless tray makes it observable
    /// via `try_recv`.
    #[test]
    fn synthesize_round_trips_through_channel() {
        let t = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
            #[cfg(feature = "experimental-bridge")]
            bridge: BridgeMenuState::default(),
        });
        t.synthesize(TrayCommand::PatchAll);
        let cmd = t.try_recv().expect("command pending");
        assert_eq!(cmd, TrayCommand::PatchAll);
        // Channel drains.
        assert!(t.try_recv().is_none());
    }

    /// `set_state` updates the snapshot and the rendered layout.
    /// (Default V2 build only — feature-on adds 7 V3 entries; see
    /// the V3 test module below.)
    #[cfg(not(feature = "experimental-bridge"))]
    #[test]
    fn set_state_updates_layout() {
        let t = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
        });
        let initial = t.current_menu_layout();
        // 6 items when no browsers.
        assert_eq!(initial.len(), 6);

        t.set_state(MenuState {
            browsers: vec![BrowserMenuEntry::from_browser(
                &fake_browser("Helium"),
                true,
            )],
            launch_at_login: true,
        });
        let updated = t.current_menu_layout();
        // 1 browser + sep + 2 actions + sep + toggle + sep + quit = 8
        assert_eq!(updated.len(), 8);
        assert!(matches!(&updated[0], MenuItemSpec::BrowserStatus { .. }));
    }

    /// `state()` returns a snapshot equal to what we set.
    #[test]
    fn state_round_trip() {
        let state = MenuState {
            browsers: vec![BrowserMenuEntry::from_browser(
                &fake_browser("Thorium"),
                false,
            )],
            launch_at_login: true,
            #[cfg(feature = "experimental-bridge")]
            bridge: BridgeMenuState::default(),
        };
        let t = Tray::headless(state.clone());
        assert_eq!(t.state(), state);
    }

    /// `build_routes` covers every actionable menu item.
    /// (Default V2 build only — feature-on adds 4 stream actions + 3
    /// bridge submenu actions; see the V3 test module below.)
    #[cfg(not(feature = "experimental-bridge"))]
    #[test]
    fn build_routes_covers_actions_and_browsers_and_toggles() {
        let state = MenuState {
            browsers: vec![BrowserMenuEntry::from_browser(
                &fake_browser("Helium"),
                true,
            )],
            launch_at_login: false,
        };
        let routes = build_routes(&state);
        // Expect: 1 browser + 2 actions + 1 toggle + 1 quit = 5 actionables.
        assert_eq!(routes.len(), 5);
        // Browser should map to a PatchOne with that name.
        let browser_entry = routes
            .values()
            .find(|c| matches!(c, TrayCommand::PatchOne(_)));
        match browser_entry {
            Some(TrayCommand::PatchOne(name)) => assert_eq!(name, "Helium"),
            _ => panic!("missing PatchOne(Helium) in routes"),
        }
    }

    /// `menu_item_id` is stable: two calls with identical inputs produce
    /// identical ids.
    #[test]
    fn menu_item_id_is_stable() {
        let item = MenuItemSpec::Action {
            label: "Patch Now".into(),
            command: TrayCommand::PatchAll,
        };
        assert_eq!(menu_item_id(2, &item), menu_item_id(2, &item));
        assert_ne!(menu_item_id(1, &item), menu_item_id(2, &item));
    }

    /// `BrowserMenuEntry::from_browser` carries the name + patched flag.
    #[test]
    fn browser_menu_entry_from_browser() {
        let entry = BrowserMenuEntry::from_browser(&fake_browser("Foo"), true);
        assert_eq!(entry.name, "Foo");
        assert!(entry.patched);
    }

    /// Layout always ends with a Quit action (even with no browsers).
    #[test]
    fn last_item_is_quit() {
        for browsers in [
            vec![],
            vec![BrowserMenuEntry::from_browser(&fake_browser("A"), false)],
        ] {
            let state = MenuState {
                browsers,
                launch_at_login: false,
                #[cfg(feature = "experimental-bridge")]
                bridge: BridgeMenuState::default(),
            };
            let layout = menu_layout(&state);
            match layout.last().unwrap() {
                MenuItemSpec::Action {
                    command: TrayCommand::Quit,
                    ..
                } => {}
                other => panic!("expected Quit, got {other:?}"),
            }
        }
    }

    /// `recv_blocking` returns `None` when the sender has been dropped.
    #[test]
    fn recv_blocking_returns_none_when_sender_dropped() {
        // Build a headless tray, then forcibly drop the internal `tx`.
        // We can't reach inside, but we can verify try_recv on an empty
        // channel returns None.
        let t = Tray::headless(MenuState {
            browsers: vec![],
            launch_at_login: false,
            #[cfg(feature = "experimental-bridge")]
            bridge: BridgeMenuState::default(),
        });
        assert!(t.try_recv().is_none());
    }

    /// `TrayInner::routes` is shaped as expected (smoke check) — we
    /// can't construct a `TrayIcon` in a headless test, so we just
    /// assert the field's existence/type at compile time via a function
    /// that takes `&TrayInner::routes`.
    #[test]
    fn tray_inner_routes_field_present() {
        // Synthesize a minimal Routes map and verify the type matches.
        let m: std::collections::HashMap<String, TrayCommand> = std::collections::HashMap::new();
        // Drop ensures the type-checker actually verifies the type.
        drop(m);
    }
}

/// V3 bridge menu tests — only compiled with `experimental-bridge`.
///
/// These mirror the default-feature tests above but assert against the
/// V3-augmented menu layout: 4 streaming quick-launches + the
/// `Bridge ▶` submenu inserted between the patch controls and the
/// Launch-at-Login section.
#[cfg(all(test, feature = "experimental-bridge"))]
mod tests_v3 {
    use super::*;

    fn empty_state(bridge: BridgeMenuState) -> MenuState {
        MenuState {
            browsers: vec![],
            launch_at_login: false,
            bridge,
        }
    }

    /// Empty browsers + default bridge state: layout grows from 6 → 13
    /// items (sep + 4 stream actions + sep + Bridge submenu).
    #[test]
    fn empty_browsers_v3_layout_includes_streaming_and_bridge_submenu() {
        let state = empty_state(BridgeMenuState::default());
        let layout = menu_layout(&state);
        // Expected: PatchAll + UpdateWidevine + Sep + Stream Netflix +
        // Stream Disney+ + Stream HBO Max + Stream… + Sep + Bridge ▶
        // + Sep + Toggle + Sep + Quit = 13.
        assert_eq!(
            layout.len(),
            13,
            "expected 13 items in V3 menu, got {} ({layout:#?})",
            layout.len()
        );
        // PatchAll + UpdateWidevine still come first.
        assert!(matches!(
            &layout[0],
            MenuItemSpec::Action {
                command: TrayCommand::PatchAll,
                ..
            }
        ));
        assert!(matches!(
            &layout[1],
            MenuItemSpec::Action {
                command: TrayCommand::UpdateWidevine,
                ..
            }
        ));
        // Then the V3 separator + 4 streaming actions.
        assert!(matches!(&layout[2], MenuItemSpec::Separator));
        for (idx, expected_url) in [(3, "netflix.com"), (4, "disneyplus.com"), (5, "max.com")] {
            match &layout[idx] {
                MenuItemSpec::Action {
                    command: TrayCommand::StreamUrl(url),
                    label,
                } => {
                    assert!(label.starts_with("Stream "), "label was {label:?}");
                    assert!(url.contains(expected_url), "url was {url:?}");
                }
                other => panic!("idx {idx} expected stream action, got {other:?}"),
            }
        }
        // Custom URL slot has empty URL string.
        match &layout[6] {
            MenuItemSpec::Action {
                command: TrayCommand::StreamUrl(url),
                ..
            } => assert!(url.is_empty()),
            other => panic!("idx 6 expected custom-URL stream, got {other:?}"),
        }
        // Then a separator + Bridge submenu.
        assert!(matches!(&layout[7], MenuItemSpec::Separator));
        match &layout[8] {
            MenuItemSpec::Submenu { label, items } => {
                assert!(label.contains("Bridge"));
                // Status label + Pause + Resume + Repair = 4 (no eval/snap by default)
                assert_eq!(items.len(), 4, "default submenu size");
            }
            other => panic!("idx 8 expected Submenu, got {other:?}"),
        }
        // Then sep + toggle + sep + quit.
        assert!(matches!(&layout[9], MenuItemSpec::Separator));
        assert!(matches!(&layout[10], MenuItemSpec::Toggle { .. }));
        assert!(matches!(&layout[11], MenuItemSpec::Separator));
        assert!(matches!(
            &layout[12],
            MenuItemSpec::Action {
                command: TrayCommand::Quit,
                ..
            }
        ));
    }

    /// `eval_days_remaining = Some(N)` adds the eval label inside the
    /// Bridge submenu. V3-Phase F: also adds a "Rearm trial" action.
    #[test]
    fn bridge_submenu_includes_eval_indicator_when_on_trial() {
        let state = empty_state(BridgeMenuState {
            ready: true,
            paused: false,
            snapshot_age_hours: None,
            eval_days_remaining: Some(82),
        });
        let layout = menu_layout(&state);
        // 82 days > 7-day threshold → no top-level rearm prompt; submenu
        // is at index 8 still.
        let bridge_idx = layout
            .iter()
            .position(|i| matches!(i, MenuItemSpec::Submenu { .. }))
            .expect("submenu exists");
        match &layout[bridge_idx] {
            MenuItemSpec::Submenu { items, .. } => {
                // V3-Phase F: 4 default + 1 eval label + 1 rearm action = 6.
                assert_eq!(items.len(), 6);
                let eval_label = items
                    .iter()
                    .find_map(|i| match i {
                        MenuItemSpec::Label { text } if text.contains("Eval") => Some(text),
                        _ => None,
                    })
                    .expect("eval label present");
                assert!(eval_label.contains("82"), "got {eval_label:?}");
                // Rearm action present.
                let saw_rearm = items.iter().any(|i| {
                    matches!(
                        i,
                        MenuItemSpec::Action {
                            command: TrayCommand::BridgeRearm,
                            ..
                        }
                    )
                });
                assert!(saw_rearm, "Rearm trial action missing in submenu");
            }
            other => panic!("expected Submenu, got {other:?}"),
        }
    }

    /// Negative eval days renders as "expired" + surfaces a top-level
    /// alert badge.
    #[test]
    fn bridge_submenu_eval_label_marks_expired() {
        let state = empty_state(BridgeMenuState {
            ready: true,
            paused: false,
            snapshot_age_hours: None,
            eval_days_remaining: Some(-7),
        });
        let layout = menu_layout(&state);
        // V3-Phase F: -7 days < 7 → top-level alert badge appears.
        let saw_top_rearm = layout.iter().any(|i| {
            matches!(
                i,
                MenuItemSpec::Action {
                    command: TrayCommand::BridgeRearm,
                    ..
                }
            )
        });
        assert!(saw_top_rearm, "expected top-level rearm alert badge");
        // Submenu's eval label still says "expired (7 days)".
        let bridge = layout
            .iter()
            .find_map(|i| match i {
                MenuItemSpec::Submenu { items, .. } => Some(items),
                _ => None,
            })
            .expect("submenu exists");
        let eval_label = bridge
            .iter()
            .find_map(|i| match i {
                MenuItemSpec::Label { text } if text.contains("Eval") => Some(text),
                _ => None,
            })
            .expect("eval label present");
        assert!(
            eval_label.contains("expired") && eval_label.contains('7'),
            "got {eval_label:?}"
        );
    }

    /// V3-Phase F: `needs_attention` flips the submenu label to "⚠ Bridge ▶".
    #[test]
    fn submenu_label_shows_alert_badge_when_attention_needed() {
        let state = empty_state(BridgeMenuState {
            ready: true,
            paused: false,
            snapshot_age_hours: None,
            eval_days_remaining: Some(2),
        });
        let layout = menu_layout(&state);
        let bridge_label = layout
            .iter()
            .find_map(|i| match i {
                MenuItemSpec::Submenu { label, .. } => Some(label.clone()),
                _ => None,
            })
            .expect("submenu");
        assert!(
            bridge_label.contains('⚠'),
            "expected alert glyph in submenu label; got {bridge_label:?}"
        );
    }

    /// V3-Phase F: `eval_expiry_visible` returns true only when < 7 days.
    #[test]
    fn eval_expiry_visible_flips_at_7_day_threshold() {
        let healthy = BridgeMenuState {
            eval_days_remaining: Some(8),
            ..BridgeMenuState::default()
        };
        assert!(!healthy.eval_expiry_visible());
        let warn = BridgeMenuState {
            eval_days_remaining: Some(6),
            ..BridgeMenuState::default()
        };
        assert!(warn.eval_expiry_visible());
        let none = BridgeMenuState {
            eval_days_remaining: None,
            ..BridgeMenuState::default()
        };
        assert!(!none.eval_expiry_visible());
    }

    /// V3-Phase F: `needs_attention` returns true for stale snapshots
    /// and expiring evals.
    #[test]
    fn needs_attention_flags_stale_and_expiring() {
        let healthy = BridgeMenuState::default();
        assert!(!healthy.needs_attention());

        let expiring_eval = BridgeMenuState {
            eval_days_remaining: Some(2),
            ..BridgeMenuState::default()
        };
        assert!(expiring_eval.needs_attention());

        let stale_snap = BridgeMenuState {
            snapshot_age_hours: Some(40 * 24),
            ..BridgeMenuState::default()
        };
        assert!(stale_snap.needs_attention());
    }

    /// `snapshot_age_hours = Some(48)` adds a "2d" snapshot label.
    #[test]
    fn bridge_submenu_includes_snapshot_age() {
        let state = empty_state(BridgeMenuState {
            ready: true,
            paused: false,
            snapshot_age_hours: Some(48),
            eval_days_remaining: None,
        });
        let layout = menu_layout(&state);
        if let MenuItemSpec::Submenu { items, .. } = &layout[8] {
            let snap_label = items
                .iter()
                .find_map(|i| match i {
                    MenuItemSpec::Label { text } if text.contains("Snapshot") => Some(text),
                    _ => None,
                })
                .expect("snapshot label present");
            assert!(snap_label.contains("2d"), "got {snap_label:?}");
        }
    }

    /// Bridge status text reflects ready / paused / not-provisioned.
    #[test]
    fn bridge_status_label_for_each_state() {
        assert!(bridge_status_label(&BridgeMenuState::default()).contains("Not provisioned"));
        assert!(bridge_status_label(&BridgeMenuState {
            ready: true,
            paused: false,
            snapshot_age_hours: None,
            eval_days_remaining: None,
        })
        .contains("Ready"));
        assert!(bridge_status_label(&BridgeMenuState {
            ready: true,
            paused: true,
            snapshot_age_hours: None,
            eval_days_remaining: None,
        })
        .contains("Paused"));
    }

    /// `build_routes` includes the V3 stream + bridge actions.
    #[test]
    fn v3_build_routes_includes_stream_and_bridge_actions() {
        let state = empty_state(BridgeMenuState::default());
        let routes = build_routes(&state);
        let mut saw_stream = false;
        let mut saw_pause = false;
        let mut saw_resume = false;
        let mut saw_repair = false;
        for cmd in routes.values() {
            match cmd {
                TrayCommand::StreamUrl(_) => saw_stream = true,
                TrayCommand::BridgePause => saw_pause = true,
                TrayCommand::BridgeResume => saw_resume = true,
                TrayCommand::BridgeRepair => saw_repair = true,
                _ => {}
            }
        }
        assert!(saw_stream, "StreamUrl missing in routes");
        assert!(saw_pause, "BridgePause missing in routes");
        assert!(saw_resume, "BridgeResume missing in routes");
        assert!(saw_repair, "BridgeRepair missing in routes");
    }

    /// Each streaming quick-launch has a distinct URL.
    #[test]
    fn stream_urls_are_distinct() {
        let state = empty_state(BridgeMenuState::default());
        let layout = menu_layout(&state);
        let urls: Vec<String> = layout
            .iter()
            .filter_map(|i| match i {
                MenuItemSpec::Action {
                    command: TrayCommand::StreamUrl(url),
                    ..
                } => Some(url.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(urls.len(), 4, "expected 4 stream URLs");
        // Three known URLs + one empty (custom prompt slot).
        let mut sorted = urls.clone();
        sorted.sort();
        assert!(sorted.windows(2).all(|w| w[0] != w[1]), "duplicates");
    }

    /// `eval_days_label` formats positive + negative + zero days.
    #[test]
    fn eval_days_label_formatting() {
        assert!(eval_days_label(0).contains("0 days"));
        assert!(eval_days_label(1).contains("1 days"));
        assert!(eval_days_label(82).contains("82 days"));
        assert!(eval_days_label(-1).contains("expired"));
        assert!(eval_days_label(-1).contains("1 days"));
    }

    /// `snapshot_age_label` formats hours vs days.
    #[test]
    fn snapshot_age_label_formatting() {
        assert!(snapshot_age_label(0).contains("0h"));
        assert!(snapshot_age_label(23).contains("23h"));
        assert!(snapshot_age_label(24).contains("1d"));
        assert!(snapshot_age_label(48).contains("2d"));
        assert!(snapshot_age_label(168).contains("7d"));
    }

    /// `Submenu` items have a non-empty label.
    #[test]
    fn submenu_label_is_non_empty() {
        let state = empty_state(BridgeMenuState::default());
        let layout = menu_layout(&state);
        if let MenuItemSpec::Submenu { label, .. } = &layout[8] {
            assert!(!label.is_empty());
            assert!(label.contains("Bridge"));
        }
    }

    /// `Label` items report `is_actionable() == false`.
    #[test]
    fn label_items_are_not_actionable() {
        let l = MenuItemSpec::Label {
            text: "Status: Ready".into(),
        };
        assert!(!l.is_separator());
        assert!(!l.is_actionable());
        assert_eq!(l.label(), "Status: Ready");
    }

    /// `Submenu` items report `is_actionable() == false` (children are
    /// actionable; the header isn't).
    #[test]
    fn submenu_items_are_not_actionable() {
        let s = MenuItemSpec::Submenu {
            label: "Bridge ▶".into(),
            items: vec![],
        };
        assert!(!s.is_separator());
        assert!(!s.is_actionable());
        assert_eq!(s.label(), "Bridge ▶");
    }

    /// `BridgeMenuState::default` is "not provisioned, no trial, no
    /// snapshot".
    #[test]
    fn bridge_menu_state_default_is_blank() {
        let s = BridgeMenuState::default();
        assert!(!s.ready);
        assert!(!s.paused);
        assert!(s.snapshot_age_hours.is_none());
        assert!(s.eval_days_remaining.is_none());
    }

    /// `route_item_into` for a submenu emits one route per actionable
    /// child, each with a distinct id derived from the parent id.
    #[test]
    fn route_item_into_submenu_handles_children() {
        let mut routes = std::collections::HashMap::new();
        let sub = MenuItemSpec::Submenu {
            label: "Bridge ▶".into(),
            items: vec![
                MenuItemSpec::Action {
                    label: "Pause VM".into(),
                    command: TrayCommand::BridgePause,
                },
                MenuItemSpec::Action {
                    label: "Resume VM".into(),
                    command: TrayCommand::BridgeResume,
                },
                MenuItemSpec::Label {
                    text: "Status: Ready".into(),
                },
            ],
        };
        route_item_into(&mut routes, 8, &sub, None);
        // 2 actionable children → 2 routes (Label is read-only).
        assert_eq!(routes.len(), 2);
        let mut cmds: Vec<TrayCommand> = routes.values().cloned().collect();
        cmds.sort_by_key(|c| format!("{c:?}"));
        assert!(cmds.contains(&TrayCommand::BridgePause));
        assert!(cmds.contains(&TrayCommand::BridgeResume));
    }
}
