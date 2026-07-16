//! Sleep/wake event subscription.
//!
//! The daemon needs to re-verify browser patches when the system wakes
//! from sleep — a system update / volume mount / browser self-update
//! could have run in the background and dropped our patched CDM. We
//! subscribe to a platform-native wake event:
//!
//! * **macOS:** `NSWorkspaceDidWakeNotification` via `NSWorkspace`'s
//!   notification center (Cocoa, `AppKit`). Implemented in [`macos`].
//! * **Linux:** `org.freedesktop.login1.Manager.PrepareForSleep` D-Bus
//!   signal (systemd-logind). Implemented in [`linux`]. The signal is
//!   emitted twice per sleep cycle — `true` before sleep, `false` after
//!   wake — and we fire the user callback only on the wake transition.
//!
//! # Public surface
//!
//! ```ignore
//! pub fn subscribe_wake_events(
//!     callback: Box<dyn Fn() + Send + 'static>,
//! ) -> Result<WakeSubscription>;
//!
//! pub struct WakeSubscription { /* private */ }
//! // Drop unsubscribes.
//! ```
//!
//! Each call to [`subscribe_wake_events`] creates an independent
//! subscription. When the returned [`WakeSubscription`] is dropped, the
//! underlying observer / D-Bus signal handler is torn down.
//!
//! # Test mode
//!
//! `SILVERVINE_TEST_POWER_NOOP=1` short-circuits the platform connection. In
//! test mode the returned subscription does nothing — `Drop` is a no-op
//! and the callback never fires. Tests assert on the no-op behavior;
//! actual system-bus / `NSWorkspace` integration is exercised manually
//! during smoke tests on the dev box.
//!
//! # Linux without systemd-logind
//!
//! On hosts without systemd-logind (e.g. minimal containers), the
//! subscription succeeds with a `tracing::warn!` and a no-op handle —
//! we don't error out, since the caller can't act on the absence of
//! wake events anyway.

use crate::error::Result;

/// Env-var name that, when set, short-circuits all platform integration.
/// Subscriptions return a no-op handle and the callback never fires.
pub const NOOP_ENV: &str = "SILVERVINE_TEST_POWER_NOOP";

/// Type alias for the user-provided wake callback.
///
/// `Send + 'static` so the platform impl can move it onto a background
/// thread (Linux) or into a closure that lives for the lifetime of the
/// observer (macOS).
pub type WakeCallback = Box<dyn Fn() + Send + 'static>;

/// Handle to an active wake-event subscription.
///
/// Dropping the handle un-subscribes the underlying observer or stops
/// the D-Bus listener thread. The handle is not `Clone` — there's at
/// most one owner per subscription. Use [`subscribe_wake_events`] again
/// for a second subscription.
///
/// In test mode (`SILVERVINE_TEST_POWER_NOOP=1`) the handle is a stub that
/// drops cleanly without any platform activity.
#[must_use = "WakeSubscription is unsubscribed on drop; bind it to a \
              variable that lives as long as you want the callback to fire"]
pub struct WakeSubscription {
    inner: SubscriptionInner,
}

/// Private inner state — kept inside [`WakeSubscription`] so callers
/// can't construct one outside this module.
enum SubscriptionInner {
    /// Test-mode handle: holds nothing, drops as a no-op.
    Noop,
    /// Real platform handle: defined per-OS.
    Real(imp::Handle),
}

impl WakeSubscription {
    fn noop() -> Self {
        Self {
            inner: SubscriptionInner::Noop,
        }
    }

    fn real(handle: imp::Handle) -> Self {
        Self {
            inner: SubscriptionInner::Real(handle),
        }
    }
}

impl Drop for WakeSubscription {
    fn drop(&mut self) {
        // We move the inner state out via `std::mem::replace` so the
        // platform-specific Drop runs (which it would anyway via the
        // enum field's drop, but being explicit makes the lifetime
        // story easier to follow when reading the code).
        match std::mem::replace(&mut self.inner, SubscriptionInner::Noop) {
            SubscriptionInner::Noop => {}
            SubscriptionInner::Real(handle) => imp::drop_handle(handle),
        }
    }
}

/// Subscribe to wake-from-sleep events.
///
/// `callback` is invoked exactly once per wake event, on a thread the
/// platform impl chooses (Linux: a dedicated D-Bus listener thread;
/// macOS: the `AppKit` run loop / `NSNotificationCenter` dispatch queue).
/// The callback must therefore be thread-safe (`Send`) and outlive the
/// returned subscription (`'static`).
///
/// Returns a [`WakeSubscription`] handle. **The caller must hold the
/// handle alive for as long as it wants events** — dropping it un-
/// subscribes.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] if the underlying D-Bus connection
///   (Linux) or `NSNotification` observer registration (macOS) fails.
/// * [`crate::ErrorCategory::UnsupportedPlatform`] on platforms outside
///   V1's scope.
///
/// # Test mode
///
/// If `SILVERVINE_TEST_POWER_NOOP=1` is set, returns a no-op subscription
/// without touching the platform bus.
pub fn subscribe_wake_events(callback: WakeCallback) -> Result<WakeSubscription> {
    if noop_enabled() {
        // Drop the callback — we won't be invoking it.
        drop(callback);
        return Ok(WakeSubscription::noop());
    }
    let handle = imp::subscribe(callback)?;
    Ok(WakeSubscription::real(handle))
}

/// Returns `true` when `SILVERVINE_TEST_POWER_NOOP=1` is in the environment.
fn noop_enabled() -> bool {
    std::env::var_os(NOOP_ENV).is_some()
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod imp {
    //! Stub for unsupported platforms.

    use crate::error::{Error, Result};

    pub(super) struct Handle;

    pub(super) fn subscribe(_cb: super::WakeCallback) -> Result<Handle> {
        Err(Error::unsupported_platform(
            "wake-event subscription is only implemented on Linux and macOS",
        ))
    }
    pub(super) fn drop_handle(_h: Handle) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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

    /// Under NOOP, `subscribe_wake_events` returns a handle that drops
    /// cleanly and never fires the callback.
    #[test]
    fn noop_subscription_returns_handle_without_firing() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(NOOP_ENV, Path::new("1"));

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_for_cb = Arc::clone(&counter);
        let sub = subscribe_wake_events(Box::new(move || {
            counter_for_cb.fetch_add(1, Ordering::SeqCst);
        }))
        .expect("subscribe ok in NOOP mode");

        // Drop the sub immediately — should not fire the callback.
        drop(sub);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    /// `noop_enabled()` reflects the env var.
    #[test]
    fn noop_enabled_reflects_env_var() {
        let _guard = crate::test_support::env_lock();
        let _u = ScopedEnv::unset(NOOP_ENV);
        assert!(!noop_enabled());
        let _s = ScopedEnv::set(NOOP_ENV, Path::new("yes"));
        assert!(noop_enabled());
    }

    /// Multiple NOOP subscriptions can co-exist and drop in any order.
    #[test]
    fn multiple_noop_subscriptions_independent() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(NOOP_ENV, Path::new("1"));
        let s1 = subscribe_wake_events(Box::new(|| {})).expect("ok");
        let s2 = subscribe_wake_events(Box::new(|| {})).expect("ok");
        drop(s2);
        drop(s1);
    }

    /// `WakeSubscription::noop()` constructs a stub.
    #[test]
    fn wake_subscription_noop_drops_cleanly() {
        let s = WakeSubscription::noop();
        drop(s);
    }
}
