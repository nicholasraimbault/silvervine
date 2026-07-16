//! Native desktop notifications.
//!
//! Thin wrapper around the [`notify-rust`](https://crates.io/crates/notify-rust)
//! crate. We:
//!
//! * Compose body text once, with platform-aware truncation (macOS displays
//!   the body in a small popover and starts truncating around 250 chars; we
//!   truncate to a generous 240 to leave room for the ellipsis).
//! * Feature-gate action buttons to Linux only — macOS's notification stack
//!   does **not** support action buttons through this crate (verified
//!   upstream; spec calls this out).
//! * Honor a single env var, `SILVERVINE_TEST_NOTIFY_NOOP=1`, which short-circuits
//!   any actual D-Bus / `mac-notification-sys` dispatch. Tests rely on this
//!   to verify body composition without disturbing the user's notification
//!   center.
//!
//! ## Public API
//!
//! ```ignore
//! pub fn notify_success(browser: &str, version: &str);
//! pub fn notify_failure(category: ErrorCategory, message: &str);
//! pub fn notify_info(text: &str);
//! ```
//!
//! All three take primitive types so they can be called from anywhere
//! (daemon orchestrator, watcher callbacks) without hauling around an
//! `Error` value.
//!
//! ## What this module does NOT do
//!
//! * No tray-icon construction (that's `daemon::tray`).
//! * No retry / queueing — failed notifications are logged and dropped.
//!   The notification stack is best-effort UX, not a reliable channel.

use crate::error::ErrorCategory;

/// Env-var name that, when set, short-circuits the actual notification
/// dispatch. Used by tests + by callers that want "compose only" semantics.
pub const NOOP_ENV: &str = "SILVERVINE_TEST_NOTIFY_NOOP";

/// Application name shown as the source of the notification.
const APP_NAME: &str = "Silvervine";

/// Conservative body length cap. macOS Notification Center starts to clip
/// long bodies; this gives every platform a bounded payload regardless of
/// the user's notification settings.
const BODY_MAX_LEN: usize = 240;

/// Notify the user of a successful patch.
///
/// Example body: `"Helium patched (Widevine 4.10.2934.0)."`
///
/// Honors `SILVERVINE_TEST_NOTIFY_NOOP=1` — under that env the function returns
/// without dispatching.
pub fn notify_success(browser: &str, version: &str) {
    let summary = format!("Patched {browser}");
    let body = compose_success_body(browser, version);
    dispatch(&summary, &body, NotificationKind::Success);
}

/// Notify the user of a patch failure, surfacing the categorized error.
///
/// Example body: `"PermissionDenied: failed to write into /opt/helium-browser-bin"`
///
/// Honors `SILVERVINE_TEST_NOTIFY_NOOP=1`.
pub fn notify_failure(category: ErrorCategory, message: &str) {
    let summary = format!("Silvervine: {category} error");
    let body = compose_failure_body(category, message);
    dispatch(&summary, &body, NotificationKind::Failure);
}

/// Notify the user of a one-off informational event (e.g. "Widevine update
/// available").
///
/// Honors `SILVERVINE_TEST_NOTIFY_NOOP=1`.
pub fn notify_info(text: &str) {
    let summary = "Silvervine".to_string();
    let body = truncate_body(text);
    dispatch(&summary, &body, NotificationKind::Info);
}

/// Compose the success-notification body. Public-in-crate so daemon-team
/// orchestration code can reuse the exact text in tracing logs without
/// re-deriving it.
#[must_use]
pub(crate) fn compose_success_body(browser: &str, version: &str) -> String {
    let raw = format!("{browser} patched (Widevine {version}).");
    truncate_body(&raw)
}

/// Compose the failure-notification body.
#[must_use]
pub(crate) fn compose_failure_body(category: ErrorCategory, message: &str) -> String {
    let raw = format!("{category}: {message}");
    truncate_body(&raw)
}

/// Truncate `s` to [`BODY_MAX_LEN`] characters at a UTF-8 char boundary,
/// appending an ellipsis if truncation occurred. Operates on chars rather
/// than bytes so we never split a multi-byte sequence.
fn truncate_body(s: &str) -> String {
    if s.chars().count() <= BODY_MAX_LEN {
        return s.to_string();
    }
    let mut out: String = s.chars().take(BODY_MAX_LEN.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Internal classification used to pick a notification urgency / icon hint.
#[derive(Debug, Clone, Copy)]
enum NotificationKind {
    Success,
    Failure,
    Info,
}

/// Dispatch a composed notification, honoring `SILVERVINE_TEST_NOTIFY_NOOP=1`.
fn dispatch(summary: &str, body: &str, kind: NotificationKind) {
    if std::env::var_os(NOOP_ENV).is_some() {
        tracing::debug!(
            target: "silvervine::notify",
            summary,
            body,
            ?kind,
            "notify NOOP — env-gated short-circuit"
        );
        return;
    }
    if let Err(e) = send_native(summary, body, kind) {
        tracing::warn!(
            target: "silvervine::notify",
            summary,
            body,
            error = %e,
            "failed to dispatch native notification"
        );
    }
}

/// Send a notification via `notify-rust`. Linux supports action buttons;
/// macOS does not, so we feature-gate the button code.
#[allow(unused_variables)] // `kind` only consumed on Linux
fn send_native(
    summary: &str,
    body: &str,
    kind: NotificationKind,
) -> std::result::Result<(), notify_rust::error::Error> {
    let mut n = notify_rust::Notification::new();
    n.summary(summary).body(body).appname(APP_NAME);

    #[cfg(target_os = "linux")]
    {
        // notify-rust supports per-notification urgency on Linux only.
        let urgency = match kind {
            NotificationKind::Failure => notify_rust::Urgency::Critical,
            NotificationKind::Success | NotificationKind::Info => notify_rust::Urgency::Normal,
        };
        n.urgency(urgency);
        // Action-button slots — daemon team can wire these to IPC commands
        // in a follow-up. For Phase 3 we ship the button surface but no
        // reactive handler thread (button clicks are no-ops at the
        // notification daemon level until the IPC client adds a handler).
        // Action buttons are NOT supported on macOS per the spec.
        if matches!(kind, NotificationKind::Failure) {
            n.action("doctor", "Run silvervine doctor");
        }
    }

    n.show()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;

    struct ScopedEnv {
        key: &'static str,
        prev: Option<OsString>,
    }
    impl ScopedEnv {
        fn set(key: &'static str, value: &Path) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
        fn unset(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }
    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    /// Body composition includes browser name + version.
    #[test]
    fn success_body_includes_browser_and_version() {
        let body = compose_success_body("Helium", "4.10.2934.0");
        assert!(body.contains("Helium"));
        assert!(body.contains("4.10.2934.0"));
    }

    /// Failure body includes the category prefix.
    #[test]
    fn failure_body_starts_with_category() {
        let body = compose_failure_body(ErrorCategory::PermissionDenied, "denied");
        assert!(body.starts_with("PermissionDenied"));
        assert!(body.contains("denied"));
    }

    /// Truncation kicks in once we exceed `BODY_MAX_LEN` characters.
    #[test]
    fn truncate_body_does_not_alter_short_input() {
        let s = "x".repeat(50);
        assert_eq!(truncate_body(&s), s);
    }

    #[test]
    fn truncate_body_caps_long_input_with_ellipsis() {
        let s = "x".repeat(BODY_MAX_LEN + 50);
        let out = truncate_body(&s);
        assert_eq!(out.chars().count(), BODY_MAX_LEN);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn truncate_body_handles_multibyte_chars_without_panic() {
        // Each emoji is multi-byte; ensure we don't slice mid-codepoint.
        let s = "🌟".repeat(BODY_MAX_LEN + 10);
        let out = truncate_body(&s);
        // The output is well-formed UTF-8 (would panic at the assertion
        // below if we'd sliced into a codepoint).
        assert_eq!(out.chars().count(), BODY_MAX_LEN);
    }

    /// `SILVERVINE_TEST_NOTIFY_NOOP=1` short-circuits dispatch — the function
    /// returns without hitting D-Bus / mac-notification-sys.
    #[test]
    fn notify_noop_short_circuits_dispatch() {
        let _g = crate::test_support::env_lock();
        let _e = ScopedEnv::set(NOOP_ENV, Path::new("1"));
        // Should not panic / block / open notification.
        notify_success("Helium", "4.10.0.0");
        notify_failure(ErrorCategory::PermissionDenied, "x");
        notify_info("hello");
    }

    /// Unsetting NOOP makes dispatch *try* (and likely fail in CI without
    /// a notification server). We assert only that the function doesn't
    /// panic — the warning log path is exercised but we can't assert on
    /// internal logging.
    #[test]
    fn notify_without_noop_does_not_panic_when_dispatch_fails() {
        let _g = crate::test_support::env_lock();
        let _e = ScopedEnv::unset(NOOP_ENV);
        // We DO NOT actually want this to succeed in CI — the daemon's
        // best-effort behavior is to log+drop on failure. Calling it
        // here verifies the "log+drop" plumbing doesn't panic.
        // Passing a notification through libnotify involves a D-Bus call
        // that fails in a headless test runner; the function must catch
        // the error, log it, and return.
        notify_info("smoke");
    }

    /// `compose_success_body` produces a stable, deterministic string.
    #[test]
    fn compose_success_body_is_deterministic() {
        let a = compose_success_body("Helium", "1.2.3");
        let b = compose_success_body("Helium", "1.2.3");
        assert_eq!(a, b);
    }

    /// `compose_failure_body` truncates at the boundary.
    #[test]
    fn compose_failure_body_truncates_long_message() {
        let long = "x".repeat(BODY_MAX_LEN + 100);
        let body = compose_failure_body(ErrorCategory::Other, &long);
        assert_eq!(body.chars().count(), BODY_MAX_LEN);
        assert!(body.starts_with("Other:"));
    }
}
