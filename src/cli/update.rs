//! `silvervine update widevine` — update or roll back the Widevine CDM.
//!
//! ## Subcommand surface
//!
//! ```text
//! silvervine update widevine [--rollback] [--cdm-source=<url>]
//! ```
//!
//! ### `silvervine update widevine`
//!
//! 1. Fetch the manifest (custom URL chain if `--cdm-source` is set).
//! 2. `widevine::cache::ensure_cdm_for(manifest)`.
//! 3. Re-patch every detected browser at the new CDM version.
//!
//! `--rollback` flips back to the previous cached version (no
//! download).

use std::io::Write;

use crate::cli::OutputOptions;
use crate::error::{Error, Result};
use crate::patch::{self, PatchOptions};
use crate::widevine;

/// Args for `silvervine update widevine`.
#[derive(Debug, Clone, Default)]
pub struct WidevineArgs {
    /// `--rollback`: revert to the previous cached version.
    pub rollback: bool,
    /// `--cdm-source <url>`: override the default Mozilla manifest chain.
    pub cdm_source: Option<String>,
    /// Output flags.
    pub output: OutputOptions,
}

/// Outcome record for `silvervine update widevine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WidevineUpdateOutcome {
    /// CDM version now active.
    pub current_version: String,
    /// `true` when a download happened (vs. a cache hit / rollback).
    pub downloaded: bool,
    /// Patch reports for each browser re-patched after the update.
    pub patch_reports: Vec<crate::cli::patch::PatchReport>,
}

/// Run the `silvervine update widevine` flow.
///
/// `cdm_source` is `None` for the default Mozilla chain, or `Some(url)`
/// for a single-URL override (as used with `--cdm-source`).
///
/// # Errors
///
/// * Any error from `fetch_manifest` / `ensure_cdm_for`.
pub fn run_widevine(args: &WidevineArgs) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let mut operation = || -> Result<WidevineUpdateOutcome> {
        if args.rollback {
            let cdm = widevine::cache::rollback()?;
            if !args.output.json {
                writeln!(handle, "Rolled back to {}", cdm.version()).map_err(Error::from)?;
            }
            Ok(WidevineUpdateOutcome {
                current_version: cdm.version().to_string(),
                downloaded: false,
                patch_reports: Vec::new(),
            })
        } else {
            run_widevine_install(args, &mut handle)
        }
    };
    let outcome = match operation() {
        Ok(outcome) => {
            crate::hooks::emit_post_update(Some(&outcome.current_version), true);
            outcome
        }
        Err(error) => {
            crate::hooks::emit_post_update(None, false);
            return Err(error);
        }
    };
    if args.output.json {
        render_json(&outcome, &mut handle)?;
    }
    Ok(())
}

fn render_json(outcome: &WidevineUpdateOutcome, out: &mut dyn Write) -> Result<()> {
    let body = serde_json::json!({
        "current_version": outcome.current_version,
        "downloaded": outcome.downloaded,
        "patch_reports": outcome.patch_reports,
    });
    writeln!(out, "{}", serde_json::to_string_pretty(&body)?).map_err(Error::from)
}

fn run_widevine_install(args: &WidevineArgs, out: &mut dyn Write) -> Result<WidevineUpdateOutcome> {
    if !args.output.json {
        writeln!(out, "Fetching Widevine manifest…").map_err(Error::from)?;
    }
    let manifest = match &args.cdm_source {
        Some(url) => fetch_from_custom(url)?,
        None => widevine::fetch_manifest()?,
    };
    let cdm = widevine::cache::ensure_cdm_for(&manifest)?;
    if !args.output.json {
        writeln!(out, "Cached CDM version: {}", cdm.version()).map_err(Error::from)?;
    }

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
    if !args.output.json {
        for r in &reports {
            if r.success {
                writeln!(out, "Re-patched {}: ok", r.browser).map_err(Error::from)?;
            } else if let Some(e) = &r.error {
                writeln!(out, "Re-patch {} FAILED: {e}", r.browser).map_err(Error::from)?;
            }
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
    fn install_or_cache_hit_json_is_one_parseable_document() {
        let outcome = WidevineUpdateOutcome {
            current_version: "1.0".into(),
            downloaded: true,
            patch_reports: vec![],
        };
        let mut output = Vec::new();
        render_json(&outcome, &mut output).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(parsed["current_version"], "1.0");
        assert_eq!(parsed["downloaded"], true);
    }

    /// `run_widevine` with `--rollback` against an empty cache surfaces
    /// the rollback error (no previous CDM to roll back to). This is
    /// the path that fires when a user runs `--rollback` on a fresh
    /// install.
    #[test]
    fn run_widevine_rollback_with_no_previous_errors() {
        // The default cache root is the user's real ~/.cache/silvervine —
        // we can't safely call run_widevine() in a test without
        // disturbing that. Instead, exercise the underlying API
        // (rollback() with no previous link) which we expect to fail.
        // The CLI surface delegates straight to it.
        let tmp = tempfile::TempDir::new().unwrap();
        let r = widevine::cache::rollback_in(tmp.path());
        assert!(r.is_err());
    }
}
