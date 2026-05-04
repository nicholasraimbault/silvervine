//! `neon patch` — patch one or all browsers with the Widevine CDM.
//!
//! Default behavior: detect installed browsers, fetch the manifest,
//! ensure the CDM is cached, then call [`crate::patch::patch_browser`]
//! for each. `--dry-run` skips the actual write but runs every other
//! pre-flight step. `--force` skips the "browser running" check.
//!
//! ## Wire-up
//!
//! This is the function the daemon team's IPC handler delegates to in
//! Phase 4. The daemon wires `patch::patch_browser` calls in here so
//! the daemon's `dispatch_ipc` for `IpcRequest::Patch` can produce
//! real per-browser results instead of the Phase 3 placeholder
//! `false` value.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::browsers::{self, Browser};
use crate::cli::OutputOptions;
use crate::error::{Error, Result};
use crate::patch::{self, PatchOptions, PatchOutcome, PlatformPatcher};
use crate::widevine;

/// Args for `neon patch`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// `--force`: patch even when the browser is currently running.
    pub force: bool,
    /// `--dry-run`: run pre-flight + permission audit but skip the CDM write.
    pub dry_run: bool,
    /// Optional positional arg: only patch the named browser.
    pub browser: Option<String>,
    /// Output flags.
    pub output: OutputOptions,
}

/// JSON-friendly outcome record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchReport {
    /// Display name of the browser.
    pub browser: String,
    /// `true` when the patch succeeded (or dry-run completed).
    pub success: bool,
    /// CDM version that was written (or would have been, in dry-run).
    pub cdm_version: Option<String>,
    /// Browser version detected before patching.
    pub version_before: Option<String>,
    /// Browser version detected after patching.
    pub version_after: Option<String>,
    /// `true` if dry-run mode was used.
    pub dry_run: bool,
    /// Error message if `success == false`.
    pub error: Option<String>,
}

impl PatchReport {
    fn success(outcome: &PatchOutcome) -> Self {
        Self {
            browser: outcome.browser_name.clone(),
            success: true,
            cdm_version: Some(outcome.cdm_version.clone()),
            version_before: outcome.version_before.clone(),
            version_after: outcome.version_after.clone(),
            dry_run: outcome.dry_run,
            error: None,
        }
    }

    fn failure(name: &str, dry_run: bool, error: &Error) -> Self {
        Self {
            browser: name.to_string(),
            success: false,
            cdm_version: None,
            version_before: None,
            version_after: None,
            dry_run,
            error: Some(error.to_string()),
        }
    }
}

/// Core patch loop, factored so it can be invoked by both the CLI
/// runtime and (in Phase 4) the daemon's IPC handler.
///
/// `browsers` is the list of detected browsers to consider. `name_filter`
/// constrains it: when `Some(name)`, only the matching browser is
/// patched; otherwise every entry is patched.
///
/// `cdm_provider` is a closure that returns a [`crate::widevine::cache::CachedCdm`]
/// — tests inject a synthetic CDM so they don't trigger downloads.
///
/// `patcher` is the [`PlatformPatcher`] (a mock in tests, the host
/// impl in production via [`patch::host_patcher`]).
///
/// # Errors
///
/// Returns an aggregated error if **all** patches failed. Per-browser
/// failures show up in the returned [`Vec<PatchReport>`] regardless.
pub fn run_patch_flow<F>(
    browsers: &[Browser],
    name_filter: Option<&str>,
    cdm_provider: F,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
) -> Vec<PatchReport>
where
    F: FnOnce() -> Result<crate::widevine::cache::CachedCdm>,
{
    let candidates: Vec<&Browser> = browsers
        .iter()
        .filter(|b| name_filter.is_none_or(|n| n.eq_ignore_ascii_case(b.name())))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    // Lazily resolve the CDM only after we've confirmed we have at
    // least one candidate. If CDM resolution fails, we still return a
    // failure report per candidate rather than erroring out — the user
    // sees what would have happened.
    let cdm = match cdm_provider() {
        Ok(c) => c,
        Err(e) => {
            return candidates
                .into_iter()
                .map(|b| PatchReport::failure(b.name(), options.dry_run, &e))
                .collect();
        }
    };
    candidates
        .into_iter()
        .map(|b| match patch::patch_browser(b, &cdm, patcher, options) {
            Ok(outcome) => PatchReport::success(&outcome),
            Err(e) => PatchReport::failure(b.name(), options.dry_run, &e),
        })
        .collect()
}

/// Production CDM provider: fetches the manifest + ensures the cache
/// is current. Used by the `neon patch` runtime path.
///
/// # Errors
///
/// * `ManifestFetchFailed` if the URL chain is exhausted.
/// * `NetworkError` / `HashMismatch` from download.
fn production_cdm() -> Result<crate::widevine::cache::CachedCdm> {
    let manifest = widevine::fetch_manifest()?;
    widevine::cache::ensure_cdm_for(&manifest)
}

/// Render a list of reports as a friendly per-line summary.
fn render_text(reports: &[PatchReport], dry_run: bool, out: &mut dyn Write) -> std::io::Result<()> {
    if reports.is_empty() {
        writeln!(out, "No browsers detected to patch.")?;
        return Ok(());
    }
    if dry_run {
        writeln!(out, "Dry run: no files will be modified.")?;
    }
    for r in reports {
        if r.success {
            let cdm = r.cdm_version.as_deref().unwrap_or("(unknown)");
            let ver = r.version_before.as_deref().unwrap_or("(unknown)");
            let prefix = if r.dry_run { "[dry-run] " } else { "" };
            writeln!(
                out,
                "{}{}: ok — browser {}, Widevine {}",
                prefix, r.browser, ver, cdm
            )?;
        } else {
            let err = r.error.as_deref().unwrap_or("unknown error");
            writeln!(out, "{}: FAILED — {err}", r.browser)?;
        }
    }
    Ok(())
}

/// Render reports as a pretty-printed JSON array.
fn render_json(reports: &[PatchReport], out: &mut dyn Write) -> Result<()> {
    let s = serde_json::to_string_pretty(reports)?;
    writeln!(out, "{s}").map_err(Error::from)?;
    Ok(())
}

/// CLI entry point.
///
/// # Errors
///
/// * `Other` if no browsers were detected to patch.
/// * Any error from manifest / CDM resolution.
pub fn run(args: &Args) -> Result<()> {
    let detected = browsers::detect_browsers().unwrap_or_default();
    let patcher = patch::host_patcher()?;
    let options = PatchOptions {
        force_while_running: args.force,
        dry_run: args.dry_run,
        ..Default::default()
    };
    let reports = run_patch_flow(
        &detected,
        args.browser.as_deref(),
        production_cdm,
        patcher.as_ref(),
        &options,
    );

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if args.output.json {
        render_json(&reports, &mut handle)?;
    } else {
        render_text(&reports, args.dry_run, &mut handle).map_err(Error::from)?;
    }

    // Exit with a non-zero category if everything failed; otherwise
    // success even if some entries failed (parity with `apt-get`-style
    // "we did what we could").
    if !reports.is_empty() && reports.iter().all(|r| !r.success) {
        let first_err = reports
            .iter()
            .find_map(|r| r.error.as_deref())
            .unwrap_or("all patches failed");
        return Err(Error::other(first_err.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::BrowserKind;
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    /// Same mock used by `crate::patch` tests, copied here for self-
    /// containedness.
    #[derive(Default)]
    struct MockPatcher {
        write_calls: AtomicUsize,
        verify_calls: AtomicUsize,
        version_calls: AtomicUsize,
        version: RefCell<Option<String>>,
        write_should_fail: bool,
        verify_should_fail: bool,
    }

    impl MockPatcher {
        fn with_version(version: &str) -> Self {
            Self {
                version: RefCell::new(Some(version.to_string())),
                ..Default::default()
            }
        }
    }

    impl PlatformPatcher for MockPatcher {
        fn write_cdm(&self, target: &Path, _cdm_source: &Path) -> Result<()> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            if self.write_should_fail {
                return Err(Error::permission_denied(format!(
                    "mock failure writing to {}",
                    target.display()
                )));
            }
            fs::write(target.join("CDM_WRITTEN"), b"1").map_err(Error::from)?;
            Ok(())
        }
        fn verify_post_patch(&self, target: &Path) -> Result<()> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            if self.verify_should_fail {
                return Err(Error::unknown_bundle_structure(format!(
                    "mock verify failed for {}",
                    target.display()
                )));
            }
            Ok(())
        }
        fn read_browser_version(&self, _target: &Path) -> Option<String> {
            self.version_calls.fetch_add(1, Ordering::SeqCst);
            self.version.borrow().clone()
        }
    }

    fn make_browser(install: PathBuf, name: &str) -> Browser {
        Browser {
            name: name.into(),
            install_path: install,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    fn make_cdm(root: &Path, version: &str) -> crate::widevine::cache::CachedCdm {
        let dir = root.join(version);
        fs::create_dir_all(dir.join("_platform_specific/linux_x64")).unwrap();
        fs::write(
            dir.join("_platform_specific/linux_x64/libwidevinecdm.so"),
            b"fake",
        )
        .unwrap();
        fs::write(dir.join("manifest.json"), br#"{"version":"x"}"#).unwrap();
        crate::widevine::cache::CachedCdm::new(version.to_string(), dir)
    }

    #[test]
    fn run_patch_flow_empty_browsers_returns_empty_reports() {
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let reports = run_patch_flow(
            &[],
            None,
            || Ok(make_cdm(&cache, "1.0")),
            &MockPatcher::with_version("v"),
            &PatchOptions::default(),
        );
        assert!(reports.is_empty());
    }

    #[test]
    fn run_patch_flow_filter_by_name_only_patches_match() {
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let t = tmp.path().join("t");
        fs::create_dir_all(&t).unwrap();
        let browsers_list = vec![make_browser(h, "Helium"), make_browser(t, "Thorium")];
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let reports = run_patch_flow(
            &browsers_list,
            Some("Helium"),
            || Ok(make_cdm(&cache, "1.0")),
            &MockPatcher::with_version("v"),
            &opts,
        );
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].browser, "Helium");
        assert!(reports[0].success);
    }

    #[test]
    fn run_patch_flow_case_insensitive_filter() {
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let browsers_list = vec![make_browser(h, "Helium")];
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let reports = run_patch_flow(
            &browsers_list,
            Some("helium"),
            || Ok(make_cdm(&cache, "1.0")),
            &MockPatcher::with_version("v"),
            &opts,
        );
        assert_eq!(reports.len(), 1);
        assert!(reports[0].success);
    }

    #[test]
    fn run_patch_flow_dry_run_does_not_write() {
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let browsers_list = vec![make_browser(h.clone(), "Helium")];
        let patcher = MockPatcher::with_version("v");
        let opts = PatchOptions {
            force_while_running: true,
            dry_run: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
        };
        let reports = run_patch_flow(
            &browsers_list,
            None,
            || Ok(make_cdm(&cache, "1.0")),
            &patcher,
            &opts,
        );
        assert_eq!(reports.len(), 1);
        assert!(reports[0].dry_run);
        assert!(reports[0].success);
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
        assert!(!h.join("CDM_WRITTEN").exists());
    }

    #[test]
    fn run_patch_flow_cdm_failure_yields_per_browser_failure_reports() {
        let tmp = TempDir::new().unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let browsers_list = vec![make_browser(h, "Helium")];
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let reports = run_patch_flow(
            &browsers_list,
            None,
            || Err(Error::network("mock manifest fetch failed")),
            &MockPatcher::with_version("v"),
            &opts,
        );
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].success);
        assert!(reports[0].error.as_deref().unwrap().contains("mock"));
    }

    #[test]
    fn run_patch_flow_records_per_browser_write_failure() {
        let tmp = TempDir::new().unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let browsers_list = vec![make_browser(h, "Helium")];
        let mut patcher = MockPatcher::with_version("v");
        patcher.write_should_fail = true;
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let reports = run_patch_flow(
            &browsers_list,
            None,
            || Ok(make_cdm(&cache, "1.0")),
            &patcher,
            &opts,
        );
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].success);
        assert!(reports[0].error.is_some());
    }

    #[test]
    fn render_text_dry_run_includes_marker() {
        let reports = vec![PatchReport {
            browser: "Helium".into(),
            success: true,
            cdm_version: Some("1.0".into()),
            version_before: Some("128".into()),
            version_after: Some("128".into()),
            dry_run: true,
            error: None,
        }];
        let mut buf = Vec::new();
        render_text(&reports, true, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Dry run"));
        assert!(s.contains("[dry-run]"));
        assert!(s.contains("Helium"));
    }

    #[test]
    fn render_text_failure_shows_error() {
        let reports = vec![PatchReport {
            browser: "Helium".into(),
            success: false,
            cdm_version: None,
            version_before: None,
            version_after: None,
            dry_run: false,
            error: Some("disk full".into()),
        }];
        let mut buf = Vec::new();
        render_text(&reports, false, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("FAILED"));
        assert!(s.contains("disk full"));
    }

    #[test]
    fn render_text_empty_reports_says_nothing() {
        let mut buf = Vec::new();
        render_text(&[], false, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("No browsers"));
    }

    #[test]
    fn render_json_emits_array() {
        let reports = vec![PatchReport {
            browser: "Helium".into(),
            success: true,
            cdm_version: Some("1.0".into()),
            version_before: None,
            version_after: None,
            dry_run: false,
            error: None,
        }];
        let mut buf = Vec::new();
        render_json(&reports, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.is_array());
        assert_eq!(v[0]["browser"], "Helium");
        assert_eq!(v[0]["success"], true);
    }

    #[test]
    fn patch_report_serialize_round_trip() {
        let r = PatchReport {
            browser: "X".into(),
            success: true,
            cdm_version: Some("1".into()),
            version_before: None,
            version_after: None,
            dry_run: false,
            error: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: PatchReport = serde_json::from_str(&s).unwrap();
        assert_eq!(back.browser, "X");
    }
}
