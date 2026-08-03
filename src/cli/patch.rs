//! `silvervine patch` — patch one or all browsers with the Widevine CDM.
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
use std::path::PathBuf;

use crate::browsers::{self, Browser};
use crate::cli::OutputOptions;
use crate::error::{Error, ErrorCategory, Result};
pub use crate::patch::PatchReport;
use crate::patch::{self, PatchOptions, PlatformPatcher};
use crate::widevine::{self, CachedCdm};

/// Args for `silvervine patch`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// `--force`: patch even when the browser is currently running.
    pub force: bool,
    /// `--dry-run`: run pre-flight + permission audit but skip the CDM write.
    pub dry_run: bool,
    /// `--replace-external-cdm`: explicit consent to replace an unmarked CDM.
    pub replace_external_cdm: bool,
    /// Optional positional arg: only patch the named browser.
    pub browser: Option<String>,
    /// Output flags.
    pub output: OutputOptions,
}

/// Internal privileged patch inputs selected by the locked parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedArgs {
    /// Exact absolute browser install selected by the locked parent.
    pub install_path: PathBuf,
    /// Trusted same-filesystem directory selected by the unprivileged parent
    /// for exclusive snapshot creation.
    pub backup_parent: PathBuf,
    /// Mutable extracted CDM directory selected by the parent.
    pub cdm_dir: PathBuf,
    /// Exact payload identity verified by the unprivileged parent.
    pub managed_marker: crate::widevine::ownership::ManagedMarker,
    /// Browser display name used only for diagnostics and snapshots.
    pub browser_name: String,
    /// Parent-selected ownership classification. `None` means a direct
    /// hidden invocation and reconstructs as [`BrowserKind::Detected`].
    pub browser_kind: Option<crate::browsers::BrowserKind>,
    /// Inherit the parent's running-browser override.
    pub force: bool,
    /// Inherit the parent's explicit external-CDM replacement consent.
    pub replace_external_cdm: bool,
}

/// CLI boundary around the core [`patch::PatchBatch`] transaction.
///
/// Browser selection and patch execution stay in the core module. This
/// wrapper only emits user hooks after non-dry-run, non-privileged attempts.
pub fn run_patch_flow<F>(
    browsers: &[Browser],
    name_filter: Option<&str>,
    cdm_resolver: F,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
) -> Vec<PatchReport>
where
    F: FnOnce() -> Result<CachedCdm>,
{
    let candidates = patch::select_browsers(browsers, name_filter);
    let reports = patch::PatchBatch::new(patcher, options).execute(&candidates, cdm_resolver);
    if should_emit_hooks(options) {
        for report in &reports {
            crate::hooks::emit_post_patch(report);
        }
    }
    reports
}

fn should_emit_hooks(options: &PatchOptions) -> bool {
    !options.as_root && !options.dry_run
}

/// Production CDM resolver: fetches the manifest and ensures the cache is
/// current. Used by the `silvervine patch` runtime path.
///
/// # Errors
///
/// * `ManifestFetchFailed` if the URL chain is exhausted.
/// * `NetworkError` / `HashMismatch` from download.
fn production_cdm() -> Result<CachedCdm> {
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
    super::write_json(out, reports)
}

/// CLI entry point.
///
/// # Errors
///
/// * `Other` if no browsers were detected to patch.
/// * Any error from browser detection, manifest retrieval, or CDM resolution.
pub fn run(args: &Args) -> Result<()> {
    if args.replace_external_cdm && args.browser.as_deref().is_none_or(str::is_empty) {
        return Err(Error::other(
            "--replace-external-cdm requires an explicit browser name;              bulk external CDM replacement is not allowed",
        ));
    }
    let detected = browsers::detect_browsers()?;
    let patcher = patch::host_patcher()?;
    let options = PatchOptions {
        force_while_running: args.force,
        replace_external_cdm: args.replace_external_cdm,
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

    // A requested browser that did not match must never be reported as an
    // empty success (especially because the privileged parent trusts exit 0).
    if reports.is_empty() {
        return Err(Error::other(match &args.browser {
            Some(name) => format!("requested browser '{name}' was not found"),
            None => "no browsers detected to patch".to_string(),
        }));
    }
    if let Some(error) = all_failed_error(&reports) {
        return Err(error);
    }
    Ok(())
}

fn all_failed_error(reports: &[PatchReport]) -> Option<Error> {
    if reports.is_empty() || reports.iter().any(|report| report.success) {
        return None;
    }
    let report = reports.first()?;
    let category = report.error_category.unwrap_or(ErrorCategory::Other);
    let rendered = report.error.as_deref().unwrap_or("all patches failed");
    let prefix = format!("{category}: ");
    let message = rendered.strip_prefix(&prefix).unwrap_or(rendered);
    Some(Error::new(category, message))
}

/// Reconstruct the parent-selected browser for the privileged child.
///
/// Direct hidden invocations omit `browser_kind` and default to
/// [`BrowserKind::Detected`]; elevated parents pass the closed token.
#[must_use]
pub fn privileged_browser(args: &PrivilegedArgs) -> Browser {
    Browser {
        name: args.browser_name.clone(),
        install_path: args.install_path.clone(),
        kind: args
            .browser_kind
            .unwrap_or(crate::browsers::BrowserKind::Detected),
    }
}

/// Execute the narrow privileged child operation. This function deliberately
/// performs no discovery, manifest/network/cache work, configuration loading,
/// logging, migration, or hooks. The parent still holds `patch.lock` while it
/// waits, so `as_root` safely reuses that lock contract.
///
/// # Errors
///
/// Returns an error for non-absolute/missing inputs or any snapshot, patch,
/// or verification failure.
pub fn run_privileged(args: &PrivilegedArgs) -> Result<()> {
    if !args.install_path.is_absolute()
        || !args.backup_parent.is_absolute()
        || !args.cdm_dir.is_absolute()
    {
        return Err(Error::other(
            "privileged patch paths must be exact absolute paths",
        ));
    }
    if !args.install_path.is_dir() {
        return Err(Error::unknown_bundle_structure(format!(
            "browser install path does not exist: {}",
            args.install_path.display()
        )));
    }
    // A macOS component belongs to the login user's profile. Running this
    // child as root would select root's profile and create incorrectly-owned
    // state, so macOS never supports the privileged patch path.
    #[cfg(target_os = "macos")]
    {
        Err(Error::permission_denied(
            "macOS Widevine installation does not support privileged execution",
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let staged = crate::widevine::ownership::stage_verified_payload(
            &args.cdm_dir,
            &args.backup_parent,
            &args.managed_marker,
        )?;
        let browser = privileged_browser(args);
        let cdm = CachedCdm::from_verified_payload(
            args.managed_marker.cdm_version.clone(),
            staged.path().to_owned(),
            args.managed_marker.library_sha512.clone(),
            args.managed_marker.manifest_sha512.clone(),
        );
        let patcher = patch::host_patcher()?;
        patch::patch_browser(
            &browser,
            &cdm,
            patcher.as_ref(),
            &PatchOptions {
                force_while_running: args.force,
                replace_external_cdm: args.replace_external_cdm,
                backups_dir: Some(args.backup_parent.clone()),
                as_root: true,
                ..Default::default()
            },
        )?;
        Ok(())
    }
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
    fn test_managed_marker() -> crate::widevine::ownership::ManagedMarker {
        let manifest = br#"{"version":"1.0"}"#;
        crate::widevine::ownership::ManagedMarker {
            schema_version: 3,
            silvervine_version: env!("CARGO_PKG_VERSION").into(),
            cdm_version: "1.0".into(),
            platform: crate::widevine::current_platform_key()
                .expect("platform")
                .as_str()
                .into(),
            library_sha512: "0".repeat(128),
            manifest_sha512: crate::widevine::sha512_hex(manifest),
        }
    }

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
        fn write_cdm(&self, target: &Path, cdm_source: &Path) -> Result<()> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            if self.write_should_fail {
                return Err(Error::permission_denied(format!(
                    "mock failure writing to {}",
                    target.display()
                )));
            }
            let destination = target.join("WidevineCdm");
            let platform = destination
                .join("_platform_specific")
                .join(test_platform_dir());
            fs::create_dir_all(&platform).map_err(Error::from)?;
            fs::copy(
                cdm_source.join("manifest.json"),
                destination.join("manifest.json"),
            )
            .map_err(Error::from)?;
            fs::copy(
                cdm_source
                    .join("_platform_specific")
                    .join(test_platform_dir())
                    .join(test_library_name()),
                platform.join(test_library_name()),
            )
            .map_err(Error::from)?;
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
        }
    }

    fn make_cdm(root: &Path, version: &str) -> CachedCdm {
        let dir = root.join(version);
        let platform = dir.join("_platform_specific").join(test_platform_dir());
        fs::create_dir_all(&platform).unwrap();
        fs::write(platform.join(test_library_name()), b"fake").unwrap();
        let manifest_body = format!(r#"{{"version":"{version}"}}"#);
        fs::write(dir.join("manifest.json"), &manifest_body).unwrap();
        CachedCdm::from_verified_payload(
            version.to_string(),
            dir,
            crate::widevine::sha512_hex(b"fake"),
            crate::widevine::sha512_hex(manifest_body.as_bytes()),
        )
    }

    fn test_platform_dir() -> &'static str {
        if cfg!(target_os = "macos") {
            if cfg!(target_arch = "aarch64") {
                "mac_arm64"
            } else {
                "mac_x64"
            }
        } else {
            "linux_x64"
        }
    }

    fn test_library_name() -> &'static str {
        if cfg!(target_os = "macos") {
            "libwidevinecdm.dylib"
        } else {
            "libwidevinecdm.so"
        }
    }

    #[test]
    fn privileged_child_explicitly_skips_hooks() {
        assert!(!should_emit_hooks(&PatchOptions {
            as_root: true,
            ..Default::default()
        }));
        assert!(should_emit_hooks(&PatchOptions::default()));
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
    fn external_replacement_requires_one_unique_installation() {
        let tmp = TempDir::new().unwrap();
        let first = tmp.path().join("first");
        let second = tmp.path().join("second");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        let browsers_list = vec![
            make_browser(first, "Chromium"),
            make_browser(second, "Chromium"),
        ];
        let patcher = MockPatcher::with_version("v");
        let opts = PatchOptions {
            force_while_running: true,
            replace_external_cdm: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };

        let reports = run_patch_flow(
            &browsers_list,
            Some("Chromium"),
            || panic!("ambiguous override must not resolve a CDM"),
            &patcher,
            &opts,
        );

        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|report| !report.success));
        assert!(reports.iter().all(|report| report
            .error
            .as_deref()
            .is_some_and(|error| error.contains("multiple installations"))));
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
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
            replace_external_cdm: false,
            dry_run: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            as_root: false,
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
            error_category: None,
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
            error_category: None,
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
            error_category: None,
        }];
        let mut buf = Vec::new();
        render_json(&reports, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.is_array());
        assert_eq!(v[0]["browser"], "Helium");
        assert_eq!(v[0]["success"], true);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn privileged_child_is_disabled_for_profile_installation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let install = tmp.path().join("Custom.app");
        let cdm = tmp.path().join("cdm");
        fs::create_dir_all(&install).unwrap();
        fs::create_dir_all(&cdm).unwrap();
        let error = run_privileged(&PrivilegedArgs {
            install_path: install,
            backup_parent: tmp.path().to_path_buf(),
            cdm_dir: cdm,
            managed_marker: test_managed_marker(),
            browser_name: "Custom".into(),
            browser_kind: None,
            force: true,
            replace_external_cdm: false,
        })
        .unwrap_err();
        assert!(error.to_string().contains("privileged execution"));
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
            error_category: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: PatchReport = serde_json::from_str(&s).unwrap();
        assert_eq!(back.browser, "X");
    }

    #[test]
    fn aggregated_failure_preserves_external_cdm_category() {
        let report = PatchReport::failure(
            "Custom Chromium",
            false,
            &Error::external_cdm("existing CDM was preserved"),
        );

        let error = all_failed_error(&[report]).expect("failure");

        assert_eq!(error.category, crate::ErrorCategory::ExternalCdm);
        assert_eq!(error.message, "existing CDM was preserved");
    }

    #[test]
    fn replace_external_cdm_requires_explicit_browser_name() {
        let err = run(&Args {
            replace_external_cdm: true,
            browser: None,
            ..Args::default()
        })
        .expect_err("untargeted override must fail");
        assert!(
            err.to_string().contains("--replace-external-cdm"),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("explicit browser"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn replace_external_cdm_rejects_empty_browser_name() {
        let err = run(&Args {
            replace_external_cdm: true,
            browser: Some(String::new()),
            ..Args::default()
        })
        .expect_err("empty browser name must fail");
        assert!(err.to_string().contains("explicit browser"));
    }

    #[test]
    fn privileged_browser_preserves_known_kind_when_supplied() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).unwrap();
        let browser = privileged_browser(&PrivilegedArgs {
            install_path: install.clone(),
            backup_parent: tmp.path().to_path_buf(),
            cdm_dir: tmp.path().join("cdm"),
            managed_marker: test_managed_marker(),
            browser_name: "Helium".into(),
            browser_kind: Some(BrowserKind::Known),
            force: false,
            replace_external_cdm: false,
        });
        assert_eq!(browser.kind, BrowserKind::Known);
        assert_eq!(browser.name, "Helium");
        assert_eq!(browser.install_path, install);
    }

    #[test]
    fn privileged_browser_defaults_to_detected_without_kind() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).unwrap();
        let browser = privileged_browser(&PrivilegedArgs {
            install_path: install,
            backup_parent: tmp.path().to_path_buf(),
            cdm_dir: tmp.path().join("cdm"),
            managed_marker: test_managed_marker(),
            browser_name: "Custom".into(),
            browser_kind: None,
            force: false,
            replace_external_cdm: false,
        });
        assert_eq!(browser.kind, BrowserKind::Detected);
    }
}
