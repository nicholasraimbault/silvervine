//! Daemon registration: auto-start the Neon tray on user login.
//!
//! On macOS this writes a `LaunchAgent` plist into
//! `~/Library/LaunchAgents/com.neon.tray.plist` and bootstraps it via
//! `launchctl bootstrap gui/<uid>`. On Linux it writes a `systemd --user`
//! service unit into `~/.config/systemd/user/neon.service` and enables it
//! via `systemctl --user enable --now`.
//!
//! Both impls are user-domain only — no `sudo`/`pkexec` required. The
//! `register()` / `unregister()` functions are idempotent: re-registering
//! over an existing install replaces the unit; un-registering against a
//! missing install is a successful no-op.
//!
//! # Test mode
//!
//! Tests gate on `NEON_TEST_LIFECYCLE_NOOP=1` so CI never:
//!   * writes into the real `~/Library/LaunchAgents/` or `~/.config/systemd/`
//!   * shells out to `launchctl` or `systemctl`
//!
//! When the env var is set, `register` / `unregister` return `Ok(())`
//! immediately and `is_registered` returns `false`. Tests that exercise
//! the file-write path use `tempfile::TempDir` plus a `ScopedEnv` guard
//! to redirect `$HOME` (macOS) or `$XDG_CONFIG_HOME` (Linux) into the
//! tempdir.
//!
//! # Public surface
//!
//! ```ignore
//! pub fn register() -> Result<()>;
//! pub fn unregister() -> Result<()>;
//! pub fn is_registered() -> bool;
//! pub fn registration_path() -> Result<PathBuf>;
//! ```
//!
//! `registration_path` returns where the plist / service file lives — used
//! by `neon doctor` to surface "your daemon registration is at <path>".

use std::path::PathBuf;

use crate::error::Result;

/// Env-var name that, when set, short-circuits filesystem and shell-out
/// operations in this module. Used by tests and by code paths that want
/// to enumerate "what would happen" without actually mutating the host.
pub const NOOP_ENV: &str = "NEON_TEST_LIFECYCLE_NOOP";

/// Write the platform-specific daemon-launch unit into the user's
/// auto-start directory and start it.
///
/// On macOS: writes the `LaunchAgent` plist and runs
/// `launchctl bootstrap gui/<uid> <plist>`.
///
/// On Linux: writes the systemd-user service unit and runs
/// `systemctl --user daemon-reload && systemctl --user enable --now
/// neon.service`.
///
/// Idempotent: re-registering an already-registered daemon overwrites
/// the unit file and re-bootstraps the service.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] if writing the unit file or the
///   `launchctl` / `systemctl` invocation fails.
/// * [`crate::ErrorCategory::UnsupportedPlatform`] if the host is not
///   macOS or Linux.
///
/// # Test mode
///
/// If `NEON_TEST_LIFECYCLE_NOOP=1` is set, returns `Ok(())` without
/// writing or shelling out.
pub fn register() -> Result<()> {
    if noop_enabled() {
        return Ok(());
    }
    imp::register()
}

/// Reverse of [`register`]: stop the daemon and remove the unit file.
///
/// On macOS: runs `launchctl bootout gui/<uid>/com.neon.tray` and removes
/// the plist.
///
/// On Linux: runs `systemctl --user disable --now neon.service` and
/// removes the unit file (followed by `daemon-reload`).
///
/// Idempotent: unregistering when nothing is installed is `Ok(())`.
///
/// # Errors
///
/// Same categories as [`register`].
///
/// # Test mode
///
/// If `NEON_TEST_LIFECYCLE_NOOP=1` is set, returns `Ok(())` without
/// shelling out.
pub fn unregister() -> Result<()> {
    if noop_enabled() {
        return Ok(());
    }
    imp::unregister()
}

/// `true` if the unit file exists at the expected path.
///
/// This does **not** verify the daemon is currently running — only that
/// the registration artifact is on disk. Use the daemon team's heartbeat
/// helpers to detect liveness.
///
/// In test mode (`NEON_TEST_LIFECYCLE_NOOP=1`) always returns `false`.
#[must_use]
pub fn is_registered() -> bool {
    if noop_enabled() {
        return false;
    }
    match registration_path() {
        Ok(p) => p.is_file(),
        Err(_) => false,
    }
}

/// Filesystem path where the unit / plist lives.
///
/// macOS: `~/Library/LaunchAgents/com.neon.tray.plist`
///
/// Linux: `~/.config/systemd/user/neon.service` (or
/// `$XDG_CONFIG_HOME/systemd/user/neon.service`).
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] if `$HOME` (macOS) or
///   `$XDG_CONFIG_HOME` / `$HOME` (Linux) cannot be resolved.
/// * [`crate::ErrorCategory::UnsupportedPlatform`] on platforms outside
///   V1's scope.
pub fn registration_path() -> Result<PathBuf> {
    imp::registration_path()
}

/// Returns `true` when `NEON_TEST_LIFECYCLE_NOOP=1` is in the
/// environment.
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

    use std::path::PathBuf;

    use crate::error::{Error, Result};

    pub(super) fn register() -> Result<()> {
        Err(Error::unsupported_platform(
            "daemon registration is only implemented on Linux and macOS",
        ))
    }
    pub(super) fn unregister() -> Result<()> {
        Err(Error::unsupported_platform(
            "daemon registration is only implemented on Linux and macOS",
        ))
    }
    pub(super) fn registration_path() -> Result<PathBuf> {
        Err(Error::unsupported_platform(
            "daemon registration is only implemented on Linux and macOS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;
    use tempfile::TempDir;

    /// RAII env-var setter that restores on drop. Mirrors the helper in
    /// the per-platform impl modules but exposed at the public-API test
    /// layer so we can exercise `is_registered`/`registration_path`
    /// without going through the impl-private test helpers.
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

    /// `NEON_TEST_LIFECYCLE_NOOP=1` short-circuits register/unregister
    /// and forces `is_registered()` to `false`.
    #[test]
    fn noop_short_circuits_all_entry_points() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(NOOP_ENV, Path::new("1"));
        assert!(register().is_ok(), "register short-circuits under NOOP");
        assert!(unregister().is_ok(), "unregister short-circuits under NOOP");
        assert!(
            !is_registered(),
            "is_registered must return false under NOOP"
        );
    }

    /// `noop_enabled()` returns true when the var is set, false otherwise.
    #[test]
    fn noop_enabled_reflects_env_var() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::unset(NOOP_ENV);
        assert!(!noop_enabled());
        let _set = ScopedEnv::set(NOOP_ENV, Path::new("anything"));
        assert!(noop_enabled());
    }

    /// `registration_path()` resolves to a path inside the redirected
    /// environment (via `$HOME` on macOS, `$XDG_CONFIG_HOME` on Linux).
    #[test]
    fn registration_path_resolves_under_redirected_env() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _noop = ScopedEnv::unset(NOOP_ENV);

        #[cfg(target_os = "linux")]
        let _e = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        #[cfg(target_os = "macos")]
        let _e = ScopedEnv::set("HOME", tmp.path());

        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let path = registration_path().expect("path resolves");
            assert!(
                path.starts_with(tmp.path()),
                "registration path {} should be inside {}",
                path.display(),
                tmp.path().display()
            );
        }
    }

    /// `is_registered()` returns `true` when the unit file exists at the
    /// expected path, `false` otherwise. Exercised under non-NOOP env so
    /// the underlying `registration_path()` -> `is_file()` plumbing runs.
    #[test]
    fn is_registered_reflects_file_presence() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _noop = ScopedEnv::unset(NOOP_ENV);

        #[cfg(target_os = "linux")]
        let _e = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        #[cfg(target_os = "macos")]
        let _e = ScopedEnv::set("HOME", tmp.path());

        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(!is_registered(), "no file yet -> not registered");
            let path = registration_path().unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "stub").unwrap();
            assert!(is_registered(), "after write -> registered");
        }
    }

    /// On Linux with no `$HOME` / `$XDG_CONFIG_HOME`, `registration_path()`
    /// errors and `is_registered()` returns `false` (not a panic). This
    /// path is Linux-only because macOS resolution depends only on $HOME.
    #[test]
    #[cfg(target_os = "linux")]
    fn is_registered_returns_false_when_paths_unresolvable() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::unset(NOOP_ENV);
        let _xdg = ScopedEnv::unset("XDG_CONFIG_HOME");
        let _home = ScopedEnv::unset("HOME");
        assert!(!is_registered());
    }

    /// On macOS with no $HOME, the same property holds.
    #[test]
    #[cfg(target_os = "macos")]
    fn is_registered_returns_false_when_home_unset() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::unset(NOOP_ENV);
        let _home = ScopedEnv::unset("HOME");
        assert!(!is_registered());
    }
}
