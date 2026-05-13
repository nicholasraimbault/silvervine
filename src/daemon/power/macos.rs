//! macOS wake-event subscription via `NSWorkspaceDidWakeNotification`.
//!
//! Per Apple's
//! [`NSWorkspace` notification reference](https://developer.apple.com/documentation/appkit/nsworkspace#1614837):
//!
//! > Posted when the system wakes from sleep. ... Notifications are
//! > delivered through the notification center returned by
//! > `[NSWorkspace sharedWorkspace] notificationCenter]`.
//!
//! We use `objc2 + objc2-app-kit` to:
//!
//! 1. Get `NSWorkspace.sharedWorkspace().notificationCenter()`.
//! 2. Register a block-based observer for `NSWorkspaceDidWakeNotification`.
//! 3. Stash the returned `id<NSObject>` observer pointer in a [`Handle`].
//!
//! On drop we call `removeObserver:` to un-register and let the block
//! be released.
//!
//! ## Threading
//!
//! `NSNotificationCenter` dispatches to whatever queue the observer is
//! registered against. We pass `nil` for the queue (which means
//! "deliver synchronously on the posting thread") because the daemon's
//! main thread is the one that should react to wake events; the user's
//! callback can hand work off to a background thread internally if it
//! needs to.
//!
//! ## Safety
//!
//! The block holds a `Box<dyn Fn() + Send + 'static>` captured from the
//! caller. We move it into a `RcBlock` so ObjC retains it for as long
//! as the observer is registered. When the observer is removed (in
//! `Drop`), the block's retain count drops and the closure (along with
//! the captured callback) is freed.

use objc2::rc::Retained;
use objc2_app_kit::NSWorkspace;
use objc2_foundation::{NSNotification, NSNotificationCenter, NSObject, NSString};

use crate::error::{Error, Result};

use super::WakeCallback;

/// Live handle for an active observer.
///
/// Holds a strong reference to the observer object (`id` returned by
/// `addObserverForName`) so we can pass it back to `removeObserver:` on
/// drop.
pub(super) struct Handle {
    /// The observer object returned by AppKit. Drop runs `removeObserver:`.
    observer: Retained<NSObject>,
    /// Cached pointer to the notification center we registered against.
    notification_center: Retained<NSNotificationCenter>,
}

/// Subscribe to `NSWorkspaceDidWakeNotification`.
pub(super) fn subscribe(callback: WakeCallback) -> Result<Handle> {
    // `NSNotificationCenter::addObserverForName:object:queue:usingBlock:`
    // is what we want. The `object:` arg is the sender filter (nil =
    // "any sender"), `queue:` is the dispatch queue (nil = "the posting
    // thread"), and `usingBlock:` is our handler.

    // SAFETY: NSWorkspace is a singleton; `sharedWorkspace` returns a
    // retained `&NSWorkspace`. We hold the resulting reference only
    // long enough to fetch the notification center, after which the
    // workspace itself doesn't matter — the center is what we keep.
    let workspace = unsafe { NSWorkspace::sharedWorkspace() };
    // SAFETY: `notificationCenter` returns a retained reference; we
    // keep it alive in our handle so AppKit doesn't drop it under us.
    let center = unsafe { workspace.notificationCenter() };

    // The Cocoa notification name string. AppKit defines it as the
    // global `NSWorkspaceDidWakeNotification`. objc2-app-kit re-exports
    // these as `unsafe extern "C"` statics; we read the value once and
    // wrap it in an `NSString`.
    //
    // SAFETY: The static is initialized by AppKit at framework load.
    // We treat the resulting pointer as a `&NSString` valid for the
    // lifetime of the process.
    let wake_name: &NSString = unsafe { &objc2_app_kit::NSWorkspaceDidWakeNotification };

    // Build a block that wraps the user callback. `block2::RcBlock`
    // gives us an ObjC-callable block whose captures are reference-
    // counted; AppKit retains it for the observer's lifetime.
    let cb = std::sync::Mutex::new(Some(callback));
    let block = block2::RcBlock::new(move |_notification: std::ptr::NonNull<NSNotification>| {
        // Re-lock and call the inner closure each time the notification
        // fires. We `lock().ok()` rather than `unwrap()` so a poisoned
        // mutex from a panicking earlier call doesn't crash the whole
        // observer thread.
        if let Ok(guard) = cb.lock() {
            if let Some(ref f) = *guard {
                f();
            }
        }
    });

    // SAFETY: `addObserverForName:object:queue:usingBlock:` returns a
    // retained `id<NSObject>` that we own. Passing `None` for `object`
    // (any sender) and `None` for `queue` (synchronous on posting
    // thread) is well-defined per AppKit docs. The block lives as long
    // as the observer does; AppKit calls it with a non-null
    // `NSNotification*`.
    let observer = unsafe {
        center.addObserverForName_object_queue_usingBlock(Some(wake_name), None, None, &block)
    };

    Ok(Handle {
        observer,
        notification_center: center,
    })
}

/// Drop a handle: un-register the observer.
pub(super) fn drop_handle(handle: Handle) {
    // SAFETY: `removeObserver:` is the documented inverse of
    // `addObserverForName:`. After this call AppKit no longer holds
    // a strong reference to our block, so the captured callback is
    // freed when the local `observer` Retained drops.
    unsafe {
        handle.notification_center.removeObserver(&handle.observer);
    }
    // `handle.observer` and `handle.notification_center` drop here,
    // releasing the last AppKit-side references.
}

#[cfg(test)]
mod tests {
    /// macOS-specific tests run only on macOS hosts. The subscription
    /// path actually touches AppKit, which would attach to the user's
    /// running window server. We rely on the public-API NOOP gate
    /// (`NEON_TEST_POWER_NOOP=1`) — see `power::tests` in `mod.rs` —
    /// rather than running a real subscription here.
    ///
    /// Anything we'd test in this file (e.g. the block-construction
    /// path) requires AppKit at link time; the cfg gate keeps Linux CI
    /// from tripping over the missing symbols, while macOS CI exercises
    /// the public NOOP test.
    #[test]
    fn macos_module_compiles_and_links() {
        // Smoke: nothing actually tested here. The very fact that this
        // file compiles + links on the macOS CI runner is the test.
    }
}
