//! `neon repair` — composition: uninstall (preserving config) + setup.
//!
//! Useful when state goes weird: the daemon won't start, the CDM cache
//! is corrupt, or the patch state file says one thing while the
//! browser bundle says another. Repair removes the daemon registration,
//! the CDM cache, and the state file, then re-runs `setup` (without the
//! EME health check) so the user ends with a known-clean install.

use std::io::Write;

use crate::cli::{setup, uninstall, OutputOptions};
use crate::error::{Error, Result};

/// Args for `neon repair`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Output flags.
    pub output: OutputOptions,
}

/// CLI entry point.
///
/// # Errors
///
/// * Any error from the underlying `uninstall` / `setup` steps.
pub fn run(args: &Args) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    writeln!(
        handle,
        "neon repair: removing existing install + reinstalling…"
    )
    .map_err(Error::from)?;

    let cache_root = dirs::cache_dir()
        .ok_or_else(|| Error::other("cannot resolve ~/.cache directory"))?
        .join("neon");
    let config_path = crate::config::default_config_path()
        .ok_or_else(|| Error::other("cannot resolve config path"))?;

    // Step 1: uninstall (without --purge — keep the user's config).
    let uninstall_args = uninstall::Args {
        purge: false,
        output: args.output,
    };
    let _ = uninstall::run_with(&uninstall_args, &cache_root, &config_path, &mut handle)?;

    writeln!(handle, "Reinstalling…").map_err(Error::from)?;
    // Step 2: setup with the EME test off.
    let setup_args = setup::Args {
        no_daemon: false,
        no_eme_test: true,
        reporting_on: false,
        output: args.output,
    };
    setup::run(&setup_args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

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
    }
    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    /// `repair` composes uninstall + setup. The pure-data composition
    /// is testable without driving the full repair flow:
    ///
    /// * uninstall is exercised via its own tests.
    /// * setup's plan-builder is exercised via its own tests.
    ///
    /// We additionally smoke-test that the uninstall step preserves
    /// config when invoked with `purge: false`.
    #[test]
    fn uninstall_step_preserves_config() {
        let _g = ENV_MUTEX.lock().unwrap();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        let config = tmp.path().join("config.toml");
        fs::create_dir_all(&cache).unwrap();
        fs::write(
            &config,
            "[notifications]\non_success=true\non_failure=true\n",
        )
        .unwrap();
        let mut buf = Vec::new();
        let args = uninstall::Args {
            purge: false,
            ..Default::default()
        };
        let outcome = uninstall::run_with(&args, &cache, &config, &mut buf).unwrap();
        assert!(outcome.cache_removed);
        assert!(!outcome.config_purged);
        assert!(config.exists());
    }
}
