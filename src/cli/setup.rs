//! `neon setup` — non-interactive equivalent of `init`.
//!
//! Runs the same flow as [`crate::cli::init`] without prompting:
//! detect → migrate → CDM → patch → daemon. Designed for scripts and CI.
//!
//! ## Flags
//!
//! * `--no-daemon` — skip the daemon registration step.
//! * `--no-eme-test` — already the default; explicit flag for symmetry.

use std::io::Write;

use crate::cli::init::{execute_plan, Plan};
use crate::cli::OutputOptions;
use crate::error::Result;
use crate::patch::{self, PatchOptions};
use crate::widevine::provider::LocalFileCdm;
use crate::{browsers, migration, widevine};

/// Args for `neon setup`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Skip the daemon registration step.
    pub no_daemon: bool,
    /// Skip the EME health check (already the default; explicit flag
    /// for parity with `init`).
    pub no_eme_test: bool,
    /// Output flags inherited from the global parser.
    pub output: OutputOptions,
}

/// Build the [`Plan`] from the non-interactive args + detected browsers.
///
/// `setup` defaults to **not** running the EME health check (it requires
/// network + a graphical display). The `--no-eme-test` flag is accepted
/// for symmetry with `init`'s prompt but the resulting field is always
/// `false` — only `init` exposes EME-test opt-in.
#[must_use]
pub fn build_plan(
    args: &Args,
    detected: Vec<crate::browsers::Browser>,
    legacy_present: bool,
) -> Plan {
    let _ = args.no_eme_test; // accepted for symmetry; always off in setup
    Plan {
        browsers_to_manage: detected,
        run_migration: legacy_present,
        install_daemon: !args.no_daemon,
        run_eme_test: false,
    }
}

/// CLI entry point for `neon setup`.
///
/// # Errors
///
/// Propagates from `execute_plan`; `Other` if the host platform isn't
/// supported (no `host_patcher`).
pub fn run(args: &Args) -> Result<()> {
    let detected = browsers::detect_browsers().unwrap_or_default();
    let legacy = migration::detect_legacy_install();
    let plan = build_plan(args, detected, !legacy.is_empty());

    let patcher = patch::host_patcher()?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_args_summary(args, &mut handle).map_err(crate::error::Error::from)?;
    execute_plan(
        &plan,
        production_cdm_provider,
        patcher.as_ref(),
        &mut handle,
        PatchOptions::default(),
    )
}

fn production_cdm_provider() -> Result<LocalFileCdm> {
    let manifest = widevine::fetch_manifest()?;
    let cached = widevine::cache::ensure_cdm_for(&manifest)?;
    Ok(LocalFileCdm::from_cached(&cached))
}

fn write_args_summary(args: &Args, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "neon setup — daemon: {} | eme-test: {}",
        if args.no_daemon { "no" } else { "yes" },
        if args.no_eme_test {
            "no"
        } else {
            "off (default)"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::{Browser, BrowserKind};
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn fake_browser(name: &str, install: PathBuf) -> Browser {
        Browser {
            name: name.into(),
            install_path: install,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    #[test]
    fn build_plan_default_args_install_daemon() {
        let plan = build_plan(&Args::default(), vec![], false);
        assert!(plan.install_daemon);
        assert!(!plan.run_migration);
        assert!(plan.browsers_to_manage.is_empty());
    }

    #[test]
    fn build_plan_no_daemon_flag_skips_daemon() {
        let args = Args {
            no_daemon: true,
            ..Default::default()
        };
        let plan = build_plan(&args, vec![], false);
        assert!(!plan.install_daemon);
    }

    #[test]
    fn build_plan_legacy_present_runs_migration() {
        let args = Args::default();
        let plan = build_plan(&args, vec![], true);
        assert!(plan.run_migration);
    }

    #[test]
    fn build_plan_carries_browser_list() {
        let tmp = TempDir::new().unwrap();
        let browsers = vec![fake_browser("Helium", tmp.path().join("h"))];
        let plan = build_plan(&Args::default(), browsers.clone(), false);
        assert_eq!(plan.browsers_to_manage.len(), 1);
        assert_eq!(plan.browsers_to_manage[0].name, "Helium");
    }

    #[test]
    fn write_args_summary_includes_each_flag_state() {
        let args = Args {
            no_daemon: true,
            no_eme_test: true,
            ..Default::default()
        };
        let mut buf = Vec::new();
        write_args_summary(&args, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("daemon: no"));
        assert!(s.contains("eme-test"));
    }
}
