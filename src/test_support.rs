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
//! exposed by [`env_lock`] before touching env state. This crate-wide
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
}
