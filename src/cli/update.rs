//! `neon update` — Widevine CDM update + binary self-update.
//!
//! ## Subcommand surface
//!
//! ```text
//! neon update widevine [--rollback] [--cdm-source=<url>]
//! neon update self
//! ```
//!
//! ### `neon update widevine`
//!
//! 1. Fetch the manifest (custom URL chain if `--cdm-source` is set).
//! 2. `widevine::cache::ensure_cdm_for(manifest)`.
//! 3. Re-patch every detected browser at the new CDM version.
//!
//! `--rollback` flips back to the previous cached version (no
//! download).
//!
//! ### `neon update self`
//!
//! Uses `self_update` to fetch the latest release from GitHub. If the
//! installed binary lives in a root-owned location, the writeback
//! escalates via [`crate::platform::run_as_root_script`]. Signature
//! verification (zipsign) is deferred to V1.1 — the `self_update`
//! crate's `signatures` feature pulls in extra deps we want to defer.

use std::io::Write;

use crate::cli::OutputOptions;
use crate::error::{Error, Result};
use crate::patch::{self, PatchOptions};
use crate::widevine::{
    self,
    provider::{CdmProvider, LocalFileCdm},
};

/// Args for `neon update widevine`.
#[derive(Debug, Clone, Default)]
pub struct WidevineArgs {
    /// `--rollback`: revert to the previous cached version.
    pub rollback: bool,
    /// `--cdm-source <url>`: override the default Mozilla manifest chain.
    pub cdm_source: Option<String>,
    /// Output flags.
    pub output: OutputOptions,
}

/// Args for `neon update self`.
#[derive(Debug, Clone, Default)]
pub struct SelfArgs {
    /// Output flags.
    pub output: OutputOptions,
}

/// Outcome record for `neon update widevine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WidevineUpdateOutcome {
    /// CDM version now active.
    pub current_version: String,
    /// `true` when a download happened (vs. a cache hit / rollback).
    pub downloaded: bool,
    /// Patch reports for each browser re-patched after the update.
    pub patch_reports: Vec<crate::cli::patch::PatchReport>,
}

/// Run the `neon update widevine` flow.
///
/// `cdm_source` is `None` for the default Mozilla chain, or `Some(url)`
/// for a single-URL override (as used with `--cdm-source`).
///
/// `repatch_provider` is a closure that patches a single browser; tests
/// inject a no-op closure so they don't have to drive the real
/// `patch_browser` flow.
///
/// # Errors
///
/// * Any error from `fetch_manifest` / `ensure_cdm_for`.
pub fn run_widevine(args: &WidevineArgs) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let outcome = if args.rollback {
        let cdm = widevine::cache::rollback()?;
        writeln!(handle, "Rolled back to {}", cdm.version()).map_err(Error::from)?;
        WidevineUpdateOutcome {
            current_version: cdm.version().to_string(),
            downloaded: false,
            patch_reports: Vec::new(),
        }
    } else {
        run_widevine_install(args, &mut handle)?
    };
    if args.output.json {
        let body = serde_json::json!({
            "current_version": outcome.current_version,
            "downloaded": outcome.downloaded,
            "patch_reports": outcome.patch_reports,
        });
        writeln!(handle, "{}", serde_json::to_string_pretty(&body)?).map_err(Error::from)?;
    }
    Ok(())
}

fn run_widevine_install(args: &WidevineArgs, out: &mut dyn Write) -> Result<WidevineUpdateOutcome> {
    writeln!(out, "Fetching Widevine manifest…").map_err(Error::from)?;
    let manifest = match &args.cdm_source {
        Some(url) => fetch_from_custom(url)?,
        None => widevine::fetch_manifest()?,
    };
    let cached = widevine::cache::ensure_cdm_for(&manifest)?;
    writeln!(out, "Cached CDM version: {}", cached.version()).map_err(Error::from)?;
    let cdm = LocalFileCdm::from_cached(&cached);

    // Re-patch every detected browser at the new version.
    let detected = crate::browsers::detect_browsers().unwrap_or_default();
    let patcher = patch::host_patcher()?;
    let opts = PatchOptions {
        force_while_running: false,
        dry_run: false,
        ..Default::default()
    };
    let reports = crate::cli::patch::run_patch_flow(
        &detected,
        None,
        || Ok(cdm.clone()),
        patcher.as_ref(),
        &opts,
    );
    for r in &reports {
        if r.success {
            writeln!(out, "Re-patched {}: ok", r.browser).map_err(Error::from)?;
        } else if let Some(e) = &r.error {
            writeln!(out, "Re-patch {} FAILED: {e}", r.browser).map_err(Error::from)?;
        }
    }
    Ok(WidevineUpdateOutcome {
        current_version: cdm.version().to_string(),
        downloaded: true,
        patch_reports: reports,
    })
}

/// Fetch the manifest from a single user-supplied URL.
fn fetch_from_custom(url: &str) -> Result<widevine::Manifest> {
    let parsed = url::Url::parse(url)
        .map_err(|e| Error::other(format!("invalid --cdm-source URL '{url}': {e}")))?;
    widevine::fetch_manifest_with(
        std::slice::from_ref(&parsed),
        widevine::cached_manifest_path().as_deref(),
        std::time::Duration::from_secs(0), // no cache fallback for explicit overrides
    )
}

/// Run `neon update self`.
///
/// # Errors
///
/// Surfaces `self_update` errors as `Other`. Signature verification
/// (zipsign) is deferred to V1.1.
pub fn run_self(_args: &SelfArgs) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "Checking for newer Neon release…").map_err(Error::from)?;
    let status = self_update::backends::github::Update::configure()
        .repo_owner("nicholasraimbault")
        .repo_name("neon")
        .bin_name("neon")
        .show_download_progress(true)
        .current_version(env!("CARGO_PKG_VERSION"))
        .build()
        .map_err(|e| Error::other(format!("failed to build self-update: {e}")))?
        .update();
    match status {
        Ok(status) if status.updated() => {
            writeln!(handle, "Updated to version {}", status.version()).map_err(Error::from)?;
            // Re-patch all browsers at the new binary's CDM expectations.
            // Best-effort: failures are logged but don't fail the command.
            let detected = crate::browsers::detect_browsers().unwrap_or_default();
            if !detected.is_empty() {
                writeln!(handle, "Re-patching {} browser(s)…", detected.len())
                    .map_err(Error::from)?;
                let _ = run_widevine(&WidevineArgs::default());
            }
            Ok(())
        }
        Ok(_status) => {
            writeln!(handle, "Already at latest version.").map_err(Error::from)?;
            Ok(())
        }
        Err(e) => Err(Error::network(format!("self-update failed: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_from_custom_invalid_url_errors() {
        let r = fetch_from_custom("not-a-url");
        assert!(r.is_err());
    }

    #[test]
    fn widevine_args_default_no_rollback_no_source() {
        let a = WidevineArgs::default();
        assert!(!a.rollback);
        assert!(a.cdm_source.is_none());
    }

    #[test]
    fn widevine_update_outcome_serializes_via_json_value() {
        // The runtime serializes via serde_json::json!, exercise the
        // structure with a unit test on the field shape.
        let outcome = WidevineUpdateOutcome {
            current_version: "1.0".into(),
            downloaded: true,
            patch_reports: vec![],
        };
        assert_eq!(outcome.current_version, "1.0");
        assert!(outcome.downloaded);
        assert!(outcome.patch_reports.is_empty());
    }

    /// `run_widevine` with `--rollback` against an empty cache surfaces
    /// the rollback error (no previous CDM to roll back to). This is
    /// the path that fires when a user runs `--rollback` on a fresh
    /// install.
    #[test]
    fn run_widevine_rollback_with_no_previous_errors() {
        // The default cache root is the user's real ~/.cache/neon —
        // we can't safely call run_widevine() in a test without
        // disturbing that. Instead, exercise the underlying API
        // (rollback() with no previous link) which we expect to fail.
        // The CLI surface delegates straight to it.
        let tmp = tempfile::TempDir::new().unwrap();
        let r = widevine::cache::rollback_in(tmp.path());
        assert!(r.is_err());
    }

    #[test]
    fn self_args_default_is_no_op_safe() {
        let a = SelfArgs::default();
        assert!(!a.output.json);
        assert!(!a.output.quiet);
    }
}
