//! `neon uninstall` — remove the daemon registration + CDM cache.
//!
//! Browsers stay patched until they auto-update — we don't unpatch
//! them (per spec V2 design — too invasive). The user keeps their
//! `~/.config/neon/config.toml` unless `--purge` is passed.

use std::io::Write;
use std::path::Path;

use crate::cli::OutputOptions;
use crate::error::{Error, Result};

/// Args for `neon uninstall`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// `--purge`: also remove the user's config + state files.
    pub purge: bool,
    /// Output flags.
    pub output: OutputOptions,
}

/// Outcome record for tests + JSON output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallOutcome {
    /// `true` if the daemon was unregistered (or wasn't installed).
    pub daemon_unregistered: bool,
    /// `true` if the cache directory was removed.
    pub cache_removed: bool,
    /// `true` if the config file was removed (only with `--purge`).
    pub config_purged: bool,
}

/// Run the uninstall flow against arbitrary cache + config paths.
///
/// Production callers leave the paths `None` and resolve via
/// `dirs::cache_dir()` / `dirs::config_dir()`; tests pass tempdirs.
///
/// # Errors
///
/// * `Other` if removing the cache directory fails for an unexpected
///   reason (we tolerate "doesn't exist").
pub fn run_with(
    args: &Args,
    cache_root: &Path,
    config_path: &Path,
    out: &mut dyn Write,
) -> Result<UninstallOutcome> {
    let mut outcome = UninstallOutcome {
        daemon_unregistered: false,
        cache_removed: false,
        config_purged: false,
    };

    // 1. Unregister the daemon.
    match crate::daemon::lifecycle::unregister() {
        Ok(()) => {
            writeln!(out, "Daemon: unregistered (or not installed).").map_err(Error::from)?;
            outcome.daemon_unregistered = true;
        }
        Err(e) => writeln!(out, "Daemon: unregister warning — {e}").map_err(Error::from)?,
    }

    // 2. Remove the CDM + state cache.
    if cache_root.exists() {
        match std::fs::remove_dir_all(cache_root) {
            Ok(()) => {
                writeln!(out, "Removed cache: {}", cache_root.display()).map_err(Error::from)?;
                outcome.cache_removed = true;
            }
            Err(e) => writeln!(out, "Cache removal warning ({}): {e}", cache_root.display())
                .map_err(Error::from)?,
        }
    } else {
        writeln!(out, "No cache at {} (already clean).", cache_root.display())
            .map_err(Error::from)?;
        outcome.cache_removed = true;
    }

    // 3. Optionally purge the config.
    if args.purge && config_path.exists() {
        match std::fs::remove_file(config_path) {
            Ok(()) => {
                writeln!(out, "Removed config: {}", config_path.display()).map_err(Error::from)?;
                outcome.config_purged = true;
            }
            Err(e) => writeln!(
                out,
                "Config removal warning ({}): {e}",
                config_path.display()
            )
            .map_err(Error::from)?,
        }
    } else if args.purge {
        writeln!(
            out,
            "No config at {} (already absent).",
            config_path.display()
        )
        .map_err(Error::from)?;
        outcome.config_purged = true;
    } else {
        writeln!(
            out,
            "Config preserved at {} (use --purge to remove).",
            config_path.display()
        )
        .map_err(Error::from)?;
    }

    writeln!(
        out,
        "Browsers stay patched until their next auto-update; neon does not unpatch them.",
    )
    .map_err(Error::from)?;

    Ok(outcome)
}

/// CLI entry point.
///
/// # Errors
///
/// See [`run_with`].
pub fn run(args: &Args) -> Result<()> {
    let cache_root = dirs::cache_dir()
        .ok_or_else(|| Error::other("cannot resolve ~/.cache directory"))?
        .join("neon");
    let config_path = crate::config::default_config_path()
        .ok_or_else(|| Error::other("cannot resolve ~/.config/neon/config.toml path"))?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = run_with(args, &cache_root, &config_path, &mut handle)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
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

    #[test]
    fn run_with_removes_existing_cache() {
        let _g = ENV_MUTEX.lock().unwrap();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        let config = tmp.path().join("config.toml");
        fs::create_dir_all(cache.join("widevine")).unwrap();
        fs::write(
            &config,
            "[notifications]\non_success=true\non_failure=true\n",
        )
        .unwrap();
        let args = Args {
            purge: false,
            ..Default::default()
        };
        let mut buf = Vec::new();
        let outcome = run_with(&args, &cache, &config, &mut buf).expect("ok");
        assert!(outcome.daemon_unregistered);
        assert!(outcome.cache_removed);
        assert!(!cache.exists());
        // Without --purge, config stays.
        assert!(!outcome.config_purged);
        assert!(config.exists());
    }

    #[test]
    fn run_with_purge_removes_config() {
        let _g = ENV_MUTEX.lock().unwrap();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        let config = tmp.path().join("config.toml");
        fs::create_dir_all(&cache).unwrap();
        fs::write(&config, "").unwrap();
        let args = Args {
            purge: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        let outcome = run_with(&args, &cache, &config, &mut buf).expect("ok");
        assert!(outcome.config_purged);
        assert!(!config.exists());
    }

    #[test]
    fn run_with_purge_says_already_absent_when_missing() {
        let _g = ENV_MUTEX.lock().unwrap();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        let config = tmp.path().join("config.toml");
        fs::create_dir_all(&cache).unwrap();
        // No config exists.
        let args = Args {
            purge: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        let outcome = run_with(&args, &cache, &config, &mut buf).expect("ok");
        assert!(outcome.config_purged);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("already absent"));
    }

    #[test]
    fn run_with_no_cache_says_already_clean() {
        let _g = ENV_MUTEX.lock().unwrap();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("does-not-exist");
        let config = tmp.path().join("config.toml");
        let args = Args::default();
        let mut buf = Vec::new();
        let outcome = run_with(&args, &cache, &config, &mut buf).expect("ok");
        assert!(outcome.cache_removed);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("already clean"));
    }

    #[test]
    fn run_with_default_preserves_config() {
        let _g = ENV_MUTEX.lock().unwrap();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        let config = tmp.path().join("config.toml");
        fs::create_dir_all(&cache).unwrap();
        fs::write(&config, "x").unwrap();
        let args = Args::default();
        let mut buf = Vec::new();
        let outcome = run_with(&args, &cache, &config, &mut buf).expect("ok");
        assert!(!outcome.config_purged);
        assert!(config.exists());
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("preserved"));
    }

    #[test]
    fn uninstall_outcome_clone_eq() {
        let o = UninstallOutcome {
            daemon_unregistered: true,
            cache_removed: true,
            config_purged: false,
        };
        assert_eq!(o, o.clone());
    }
}
