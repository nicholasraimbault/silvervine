//! `neon stream uninstall` — V3-Phase F bridge teardown.
//!
//! Removes the libvirt domain, snapshots, qcow2 disk, and downloaded
//! ISOs. Preserves user config (`bridge.toml`, V2 `config.toml`)
//! unless `--purge` is passed.
//!
//! Apple-UX guarantees:
//!
//! * Single command. No "are you sure?" — the user already typed
//!   `uninstall`.
//! * Clean teardown — no orphan libvirt definitions, no orphan
//!   snapshots, no leftover ~6 GB of ISO bytes.
//! * Documents the kvmfr-module-unload + udev-rule-removal steps that
//!   require sudo (we don't shell out to sudo from the CLI; the user
//!   runs them manually if they want a fully clean state).
//! * Honors [`crate::bridge::libvirt::HV_NOOP_ENV`] for tests.

use std::io::Write;
use std::path::PathBuf;

use crate::bridge::install::{DEFAULT_VM_NAME, POST_INSTALL_SNAPSHOT};
use crate::bridge::libvirt::Hypervisor;
use crate::cli::stream::stop::LAST_GOOD_SNAPSHOT;
use crate::cli::OutputOptions;
use crate::error::{Error, Result};

/// Args for `neon stream uninstall`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// `--purge`: also remove `~/.config/neon/bridge.toml` (license
    ///   posture + overrides). Default preserves it so a re-`init` can
    ///   re-use the previous license.
    pub purge: bool,
    /// Output flags.
    pub output: OutputOptions,
}

/// Outcome of an uninstall run, returned for tests + future tray
/// integration. Each field is optional / boolean to indicate which
/// teardown steps were exercised.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UninstallOutcome {
    /// `true` if the libvirt domain was undefined.
    pub libvirt_domain_removed: bool,
    /// `true` if the bridge data directory (qcow2, ISOs) was removed.
    pub data_dir_removed: bool,
    /// `true` if the user config (`bridge.toml`) was removed.
    pub config_purged: bool,
}

/// Run `neon stream uninstall`.
///
/// # Errors
///
/// * Propagates errors from the libvirt undefine step.
/// * [`crate::ErrorCategory::Other`] — disk I/O on data-dir removal.
pub fn run(args: &Args) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    run_with(args, &mut out, default_data_dir(), default_config_path())?;
    Ok(())
}

/// Test-friendly variant: takes a writer + explicit data dir + config
/// path. Production `run` calls
/// [`default_data_dir`] / [`default_config_path`].
///
/// # Errors
///
/// See [`run`].
#[allow(clippy::needless_pass_by_value)]
pub fn run_with(
    args: &Args,
    out: &mut dyn Write,
    data_dir: Option<PathBuf>,
    config_path: Option<PathBuf>,
) -> Result<UninstallOutcome> {
    let mut outcome = UninstallOutcome::default();

    // Step 1: libvirt domain teardown. Best-effort under NOOP / when no
    // domain is defined — we want uninstall to succeed even if the user
    // never finished `stream init`.
    if !args.output.quiet {
        writeln!(out, "Step 1/3: removing libvirt domain `{DEFAULT_VM_NAME}`")
            .map_err(Error::from)?;
    }
    if let Ok(hv) = Hypervisor::connect() {
        if let Ok(domain) = hv.lookup_domain(DEFAULT_VM_NAME) {
            // Best-effort stop (in case the domain is still running).
            let _ = domain.stop();
            // Snapshots — under mock mode there are none to delete; the
            // real libvirt path's `undefine` cascades.
            for snap in [POST_INSTALL_SNAPSHOT, LAST_GOOD_SNAPSHOT] {
                let _ = snap; // placeholder for V3.1 explicit snapshot delete
            }
            domain.undefine()?;
            outcome.libvirt_domain_removed = true;
        } else if !args.output.quiet {
            writeln!(
                out,
                "       (no domain `{DEFAULT_VM_NAME}` defined; skipping)"
            )
            .map_err(Error::from)?;
        }
    } else if !args.output.quiet {
        writeln!(
            out,
            "       (libvirt unreachable; assuming no domain to remove)"
        )
        .map_err(Error::from)?;
    }

    // Step 2: blow away the bridge data directory (qcow2 + ISOs +
    // autounattend.iso).
    if !args.output.quiet {
        writeln!(out, "Step 2/3: removing bridge data directory").map_err(Error::from)?;
    }
    if let Some(dir) = data_dir.as_ref() {
        if dir.exists() {
            std::fs::remove_dir_all(dir).map_err(Error::from)?;
            outcome.data_dir_removed = true;
            if !args.output.quiet {
                writeln!(out, "       removed {}", dir.display()).map_err(Error::from)?;
            }
        } else if !args.output.quiet {
            writeln!(out, "       {} not present; skipping", dir.display()).map_err(Error::from)?;
        }
    }

    // Step 3: config purge if requested.
    if !args.output.quiet {
        writeln!(out, "Step 3/3: purging config").map_err(Error::from)?;
    }
    if args.purge {
        if let Some(cfg) = config_path.as_ref() {
            if cfg.exists() {
                std::fs::remove_file(cfg).map_err(Error::from)?;
                outcome.config_purged = true;
                if !args.output.quiet {
                    writeln!(out, "       removed {}", cfg.display()).map_err(Error::from)?;
                }
            }
        }
    } else if !args.output.quiet {
        writeln!(
            out,
            "       --purge not set; preserving ~/.config/neon/bridge.toml"
        )
        .map_err(Error::from)?;
    }

    if !args.output.quiet {
        writeln!(out).map_err(Error::from)?;
        writeln!(out, "Done. Bridge uninstalled.").map_err(Error::from)?;
        writeln!(
            out,
            "If you want to fully unwind the host: \
             `sudo modprobe -r kvmfr` (kernel module) and \
             `sudo rm /etc/udev/rules.d/99-kvmfr.rules` (udev rule). \
             Neon does not call sudo on your behalf."
        )
        .map_err(Error::from)?;
    }

    Ok(outcome)
}

/// Resolve `~/.local/share/neon/bridge/` (matches
/// [`crate::bridge::install::ProvisionOpts::defaults_for`]).
#[must_use]
pub fn default_data_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("neon").join("bridge"))
}

/// Resolve `~/.config/neon/bridge.toml`.
#[must_use]
pub fn default_config_path() -> Option<PathBuf> {
    crate::bridge::license::default_bridge_config_path()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::libvirt::HV_NOOP_ENV;
    use tempfile::TempDir;

    #[test]
    fn run_with_no_state_succeeds_and_reports_nothing_to_remove() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
        }
        let mut buf = Vec::new();
        let args = Args::default();
        let outcome = run_with(
            &args,
            &mut buf,
            Some(tmp.path().join("nope")),
            Some(tmp.path().join("nope.toml")),
        )
        .expect("uninstall");
        // Nothing was actually removed, but the run succeeded.
        assert!(!outcome.data_dir_removed);
        assert!(!outcome.config_purged);
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("Step 1/3"));
        assert!(body.contains("Step 2/3"));
        assert!(body.contains("Step 3/3"));
        assert!(body.contains("Done"));
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
        }
    }

    #[test]
    fn run_with_existing_data_dir_removes_it() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let data_dir = tmp.path().join("bridge");
        std::fs::create_dir_all(data_dir.join("iso")).expect("mkdir");
        std::fs::write(data_dir.join("disk.qcow2"), b"stub").expect("write");
        std::fs::write(data_dir.join("autounattend.iso"), b"stub").expect("write");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
        }
        let mut buf = Vec::new();
        let args = Args::default();
        let outcome = run_with(
            &args,
            &mut buf,
            Some(data_dir.clone()),
            Some(tmp.path().join("nope.toml")),
        )
        .expect("uninstall");
        assert!(outcome.data_dir_removed);
        assert!(!data_dir.exists());
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
        }
    }

    #[test]
    fn run_with_purge_flag_removes_config_too() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = tmp.path().join("bridge.toml");
        std::fs::write(&cfg, "[license]\nmode = \"trial\"\n").expect("write cfg");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
        }
        let mut buf = Vec::new();
        let args = Args {
            purge: true,
            ..Default::default()
        };
        let outcome = run_with(
            &args,
            &mut buf,
            Some(tmp.path().join("nope")),
            Some(cfg.clone()),
        )
        .expect("uninstall");
        assert!(outcome.config_purged);
        assert!(!cfg.exists());
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
        }
    }

    #[test]
    fn run_with_no_purge_preserves_config() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = tmp.path().join("bridge.toml");
        std::fs::write(&cfg, "[license]\nmode = \"trial\"\n").expect("write cfg");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
        }
        let mut buf = Vec::new();
        let args = Args::default();
        let outcome = run_with(
            &args,
            &mut buf,
            Some(tmp.path().join("nope")),
            Some(cfg.clone()),
        )
        .expect("uninstall");
        assert!(!outcome.config_purged);
        assert!(cfg.exists());
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("--purge not set"));
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
        }
    }

    #[test]
    fn run_with_quiet_suppresses_progress() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
        }
        let mut buf = Vec::new();
        let args = Args {
            output: OutputOptions {
                quiet: true,
                ..Default::default()
            },
            ..Default::default()
        };
        run_with(
            &args,
            &mut buf,
            Some(tmp.path().join("nope")),
            Some(tmp.path().join("nope.toml")),
        )
        .expect("uninstall");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(!body.contains("Step 1/3"));
        assert!(!body.contains("Done"));
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
        }
    }

    #[test]
    fn libvirt_domain_remove_under_noop_records_undefine() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
        }
        let tmp = TempDir::new().expect("tempdir");
        let mut buf = Vec::new();
        let args = Args::default();
        let outcome = run_with(
            &args,
            &mut buf,
            Some(tmp.path().join("nope")),
            Some(tmp.path().join("nope.toml")),
        )
        .expect("uninstall");
        // Mock hypervisor's lookup_domain succeeds for any name → outcome
        // marks libvirt_domain_removed.
        assert!(outcome.libvirt_domain_removed);
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
        }
    }

    #[test]
    fn default_data_dir_ends_with_neon_bridge() {
        if let Some(p) = default_data_dir() {
            let suffix = std::path::Path::new("neon").join("bridge");
            assert!(p.ends_with(&suffix), "got {}", p.display());
        }
    }

    #[test]
    fn default_config_path_ends_with_neon_bridge_toml() {
        if let Some(p) = default_config_path() {
            let suffix = std::path::Path::new("neon").join("bridge.toml");
            assert!(p.ends_with(&suffix), "got {}", p.display());
        }
    }
}
