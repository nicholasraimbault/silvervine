//! PowrProf callbacks work without a window or a GUI message loop.
use crate::error::{Error, Result};
use std::{ffi::c_void, sync::Mutex};
#[repr(C)]
struct SubscribeParameters {
    callback: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> u32,
    context: *mut c_void,
}
#[link(name = "PowrProf")]
unsafe extern "system" {
    fn PowerRegisterSuspendResumeNotification(
        flags: u32,
        recipient: *const SubscribeParameters,
        handle: *mut *mut c_void,
    ) -> u32;
    fn PowerUnregisterSuspendResumeNotification(handle: *mut c_void) -> u32;
}
pub(super) struct Handle {
    registration: *mut c_void,
    callback: Box<Mutex<super::WakeCallback>>,
}
unsafe extern "system" fn on_power(context: *mut c_void, event: u32, _: *mut c_void) -> u32 {
    // PBT_APMRESUMEAUTOMATIC is delivered for both unattended and interactive wakes.
    if event == 0x12 {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let callback = unsafe { &*context.cast::<Mutex<super::WakeCallback>>() };
            if let Ok(callback) = callback.lock() {
                callback();
            }
        }));
    }
    0
}
pub(super) fn subscribe(callback: super::WakeCallback) -> Result<Handle> {
    let mut callback = Box::new(Mutex::new(callback));
    let parameters = SubscribeParameters {
        callback: on_power,
        context: (&mut *callback as *mut Mutex<super::WakeCallback>).cast(),
    };
    let mut registration = std::ptr::null_mut();
    let status =
        unsafe { PowerRegisterSuspendResumeNotification(2, &parameters, &mut registration) };
    if status != 0 {
        return Err(Error::other(format!(
            "register Windows wake callback: {}",
            std::io::Error::from_raw_os_error(status as i32)
        )));
    }
    Ok(Handle {
        registration,
        callback,
    })
}
pub(super) fn drop_handle(handle: Handle) {
    // Unregistration waits for callbacks before the boxed context is released.
    let status = unsafe { PowerUnregisterSuspendResumeNotification(handle.registration) };
    if status != 0 {
        tracing::error!(
            status,
            "could not unregister power callback; retaining callback context for safety"
        );
        std::mem::forget(handle.callback);
    }
}
