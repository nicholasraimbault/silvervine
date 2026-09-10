//! Shared test helpers — only exposed in test/dev builds.
//!
//! ## Why this module exists
//!
//! Multiple test modules across the crate mutate process-wide env vars
//! like `$HOME`, `$XDG_CONFIG_HOME`, `SILVERVINE_TEST_*`. Each test module
//! historically had its own `static ENV_MUTEX: Mutex<()>` to serialize
//! tests *within that module*, but two tests **in different modules**
//! could still race on the same env var because they hold different
//! mutexes.
//!
//! The fix: every env-mutating test acquires the *same* global guard
//! exposed by `env_lock` before touching env state. This crate-wide
//! singleton serializes env mutations across the entire test binary so
//! `cargo test --jobs N` for any N is reproducible.
//!
//! ## API
//!
//! Tests call:
//!
//! ```ignore
//! let _guard = silvervine::test_support::env_lock();
//! ```
//!
//! `env_lock()` recovers from a poisoned mutex automatically — when a
//! prior test panics while holding the guard, the next caller still
//! gets a usable lock. (The previous behavior was to also panic, which
//! cascaded test failures.)

#![cfg(any(test, debug_assertions))]

use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, MutexGuard};

/// Global env-mutation guard shared by every test module in the crate.
///
/// Initialized lazily on first use. Subsequent callers wait for the
/// previous lock holder to drop their `MutexGuard`.
fn global_env_mutex() -> &'static Mutex<()> {
    static M: Mutex<()> = Mutex::new(());
    &M
}

/// Acquire the global env-mutation guard.
///
/// Recovers from poisoning by extracting the guard from the
/// [`std::sync::PoisonError`] — see the module-level docs for the
/// rationale.
pub fn env_lock() -> MutexGuard<'static, ()> {
    global_env_mutex()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// RAII process environment setter. Restores the previous value on drop.
///
/// Callers that mutate the environment must hold [`env_lock`] for the
/// lifetime of this guard.
pub struct ScopedEnv {
    key: &'static str,
    prev: Option<OsString>,
}

impl ScopedEnv {
    /// Set `key` to `value`, remembering the previous mapping.
    #[must_use]
    pub fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
        let prev = std::env::var_os(key);
        // SAFETY: the caller holds `env_lock` for the guard's lifetime.
        unsafe { std::env::set_var(key, value) };
        Self { key, prev }
    }

    /// Remove `key` for the lifetime of the guard.
    #[must_use]
    pub fn unset(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        // SAFETY: the caller holds `env_lock` for the guard's lifetime.
        unsafe { std::env::remove_var(key) };
        Self { key, prev }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        match &self.prev {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

/// Point `XDG_CACHE_HOME` at a fresh tempdir. Hold [`env_lock`] first.
///
/// # Panics
///
/// Panics if a temporary directory cannot be created.
#[cfg(test)]
#[must_use]
pub fn isolated_xdg_cache() -> (tempfile::TempDir, ScopedEnv) {
    let home = tempfile::TempDir::new().expect("cache home");
    let env = ScopedEnv::set("XDG_CACHE_HOME", home.path());
    (home, env)
}

/// Set a regular file's mtime.
///
/// # Panics
///
/// Panics if `path` cannot be opened or its mtime cannot be set.
#[cfg(test)]
pub fn set_mtime(path: &std::path::Path, modified: std::time::SystemTime) {
    std::fs::File::open(path)
        .expect("open for mtime")
        .set_modified(modified)
        .expect("set mtime");
}

/// Default `hooks/<name>` path under the current platform config dir.
///
/// Call after `HOME` / `XDG_CONFIG_HOME` are redirected, while holding
/// [`env_lock`]. Linux uses `$XDG_CONFIG_HOME/silvervine/hooks/<name>`;
/// macOS uses `$HOME/Library/Application Support/silvervine/hooks/<name>`.
#[cfg(test)]
#[must_use]
pub fn default_hook_path(name: &str) -> std::path::PathBuf {
    crate::platform::config_dir().join("hooks").join(name)
}

/// Write an executable shell script at `path`.
///
/// # Panics
///
/// Panics if the parent directory, file, or `0o755` mode cannot be applied.
#[cfg(all(test, unix))]
pub fn write_executable_script(path: &std::path::Path, body: &str) {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("script parent");
    }
    let mut file = std::fs::File::create(path).expect("write script");
    file.write_all(body.as_bytes()).expect("write script body");
    file.sync_all().expect("fsync script");
    drop(file);
    let mut permissions = std::fs::metadata(path)
        .expect("script metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("chmod script");
}

/// Flat `WidevineCdm` target used by cross-platform status tests.
#[cfg(test)]
pub(crate) struct FlatCdmPatcher;

#[cfg(test)]
impl crate::patch::PlatformPatcher for FlatCdmPatcher {
    fn write_cdm(
        &self,
        _target: &std::path::Path,
        _cdm_source: &std::path::Path,
    ) -> crate::Result<()> {
        unreachable!("FlatCdmPatcher only resolves test targets")
    }

    fn verify_post_patch(&self, _target: &std::path::Path) -> crate::Result<()> {
        unreachable!("FlatCdmPatcher only resolves test targets")
    }

    fn read_browser_version(&self, _target: &std::path::Path) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two consecutive `env_lock()` calls don't deadlock — the first
    /// drops before the second locks.
    #[test]
    fn env_lock_can_be_re_acquired_sequentially() {
        let g1 = env_lock();
        drop(g1);
        let _g2 = env_lock();
    }

    #[test]
    fn scoped_env_restores_previous_value() {
        let _lock = env_lock();
        let key = "SILVERVINE_TEST_SCOPED_ENV";
        let _clear = ScopedEnv::unset(key);
        {
            let _set = ScopedEnv::set(key, "one");
            assert_eq!(
                std::env::var_os(key).as_deref(),
                Some(std::ffi::OsStr::new("one"))
            );
        }
        assert!(std::env::var_os(key).is_none());
    }
}
