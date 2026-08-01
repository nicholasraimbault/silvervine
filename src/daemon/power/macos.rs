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
//! 3. Keep the returned `NSObjectProtocol` observer in a [`Handle`].
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
use objc2::runtime::ProtocolObject;
use objc2_app_kit::NSWorkspace;
use objc2_foundation::{NSNotification, NSNotificationCenter, NSObjectProtocol};

use crate::error::Result;

use super::WakeCallback;
/// Live handle for an active observer.
///
/// Holds a strong reference to the protocol-typed observer returned by
/// `addObserverForName` so drop can pass it back to `removeObserver:`.
pub(super) struct Handle {
    /// The observer object returned by AppKit. Drop runs `removeObserver:`.
    observer: Retained<ProtocolObject<dyn NSObjectProtocol>>,
    /// Cached pointer to the notification center we registered against.
    notification_center: Retained<NSNotificationCenter>,
}

/// Subscribe to `NSWorkspaceDidWakeNotification`.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Result return matches the Linux subscribe() signature; future failures can fit in here without rippling through callers"
)]
pub(super) fn subscribe(callback: WakeCallback) -> Result<Handle> {
    // `NSNotificationCenter::addObserverForName:object:queue:usingBlock:`
    // is what we want. The `object:` arg is the sender filter (nil =
    // "any sender"), `queue:` is the dispatch queue (nil = "the posting
    // thread"), and `usingBlock:` is our handler.

    // Both generated objc2 methods return retained objects safely. The handle
    // keeps the notification center alive after the workspace reference drops.
    let workspace = NSWorkspace::sharedWorkspace();
    let center = workspace.notificationCenter();

    // AppKit exports the typed Cocoa notification name as an extern static.
    //
    // SAFETY: AppKit initializes this process-lifetime reference when the
    // framework loads.
    let wake_name = unsafe { objc2_app_kit::NSWorkspaceDidWakeNotification };

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

    // SAFETY: the generated method returns a retained NSObjectProtocol
    // object. `None` means any sender and synchronous delivery on the posting
    // thread. AppKit retains the block and calls it with a non-null
    // `NSNotification` while the observer remains registered.
    let observer = unsafe {
        center.addObserverForName_object_queue_usingBlock(Some(wake_name), None, None, &block)
    };

    Ok(Handle {
        observer,
        notification_center: center,
    })
}

/// Drop a handle: un-register the observer.
#[allow(
    clippy::needless_pass_by_value,
    reason = "consume-by-value is intentional — handle's fields drop at end of scope and release AppKit refs"
)]
pub(super) fn drop_handle(handle: Handle) {
    // SAFETY: `removeObserver:` is the documented inverse of
    // `addObserverForName:`. After this call AppKit no longer holds
    // a strong reference to our block, so the captured callback is
    // freed when the local `observer` Retained drops.
    unsafe {
        let observer = AsRef::<objc2::runtime::AnyObject>::as_ref(&*handle.observer);
        handle.notification_center.removeObserver(observer);
    }
    // `handle.observer` and `handle.notification_center` drop here,
    // releasing the last AppKit-side references.
}

#[cfg(test)]
mod tests {
    /// macOS-specific tests run only on macOS hosts. The subscription
    /// path actually touches AppKit, which would attach to the user's
    /// running window server. We rely on the public-API NOOP gate
    /// (`SILVERVINE_TEST_POWER_NOOP=1`) — see `power::tests` in `mod.rs` —
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
