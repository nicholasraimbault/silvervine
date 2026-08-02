//! `silvervine test` — explicit live browser EME capability testing.
//!
//! With no URL override, this command launches the selected browser with its
//! normal profile against Silvervine's tokenized loopback probe. `--url`
//! preserves the manual test-page launcher and deliberately reports no
//! automated playback result.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::thread;
use std::time::Duration;

use crate::browsers::{self, runtime, Browser};
use crate::cli::OutputOptions;
use crate::diagnostics::collect::{collect_browser, BrowserDiagnostics};
use crate::diagnostics::store::{save_default, ProbeFingerprint, StoredProbeReport};
use crate::diagnostics::{DiagnosticCheck, DiagnosticStatus};
use crate::eme::browser_probe::run_browser_probe;
use crate::eme::probe::{CapabilityAssessment, RawProbeResult};
use crate::error::{Error, Result};

/// Test-only guard that prevents both manual and automated browser launches.
pub const NOOP_ENV: &str = "SILVERVINE_TEST_BROWSER_TEST_NOOP";

/// Default page used only by the manual launch plan in tests and callers that
/// do not supply a URL.
pub const DEFAULT_TEST_URL: &str = "https://shaka-player-demo.appspot.com/demo/";

/// Args for `silvervine test`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Browser to use. Defaults to the first detected browser.
    pub browser: Option<String>,
    /// Open a manual test page instead of collecting an automated result.
    pub url: Option<String>,
    /// Output flags.
    pub output: OutputOptions,
}

/// Manual page-launch plan used by the `--url` compatibility mode.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Plan {
    #[serde(rename = "browser")]
    /// Browser to launch.
    pub browser_name: String,
    /// Absolute path to the browser binary that would be spawned.
    #[serde(rename = "executable", serialize_with = "serialize_path_lossy")]
    pub browser_executable: PathBuf,
    /// URL to navigate to.
    pub url: String,
}

fn serialize_path_lossy<S>(path: &Path, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(path.to_string_lossy().as_ref())
}

impl Plan {
    /// Build the launch plan from a snapshot of detected browsers + the
    /// args.
    ///
    /// # Errors
    ///
    /// * `Other` if no detected browser matches the filter.
    /// * `UnknownBundleStructure` if the matched browser's install path
    ///   doesn't yield a runnable executable.
    pub fn build(detected: &[Browser], args: &Args) -> Result<Self> {
        let candidate = select_browser(detected, args.browser.as_deref())?;
        let browser_executable = runtime::executable_path(candidate)?;
        Ok(Self {
            browser_name: candidate.name().to_string(),
            browser_executable,
            url: args.url.clone().unwrap_or_else(|| DEFAULT_TEST_URL.into()),
        })
    }

    /// Render this plan to a human-readable description (no side effects).
    /// Used by tests + by the runtime "what would happen" path when the
    /// user passes `--dry-run` (currently unsupported but on the spec
    /// roadmap).
    #[must_use]
    pub fn dry_run(&self) -> String {
        format!(
            "Would launch: {} ({}) → {}",
            self.browser_name,
            self.browser_executable.display(),
            self.url,
        )
    }

    /// Actually spawn the browser. **Only callable from the user's
    /// runtime command path** — short-circuits if `SILVERVINE_TEST_BROWSER_TEST_NOOP=1`.
    ///
    /// # Errors
    ///
    /// * `Other` if the browser binary isn't executable or the spawn
    ///   itself fails.
    pub fn execute_real_browser(&self) -> Result<()> {
        if std::env::var_os(NOOP_ENV).is_some() {
            return Ok(());
        }
        let mut child = std::process::Command::new(&self.browser_executable)
            .arg(&self.url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                Error::other(format!(
                    "failed to spawn {}",
                    self.browser_executable.display()
                ))
                .with_source(error)
            })?;
        thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

fn select_browser<'a>(detected: &'a [Browser], name: Option<&str>) -> Result<&'a Browser> {
    match name {
        Some(name) => detected
            .iter()
            .find(|browser| browser.name().eq_ignore_ascii_case(name))
            .ok_or_else(|| Error::other(format!("no detected browser named '{name}'"))),
        None => detected
            .first()
            .ok_or_else(|| Error::other("no browsers detected to run EME test against")),
    }
}

/// CLI entry point.
///
/// # Errors
///
/// Returns browser detection, launch, probe, persistence, or output errors.
/// A completed automated probe also returns an error when the software
/// playback baseline does not pass.
pub fn run(args: &Args) -> Result<()> {
    let detected = browsers::detect_browsers()?;
    let browser = select_browser(&detected, args.browser.as_deref())?;
    if args.url.is_some() {
        return run_manual(&detected, args);
    }
    run_automated(browser, args)
}

fn run_manual(detected: &[Browser], args: &Args) -> Result<()> {
    let plan = Plan::build(detected, args)?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if args.output.json {
        let body = serde_json::json!({
            "mode": "manual_page",
            "browser": plan.browser_name,
            "executable": plan.browser_executable,
            "url": plan.url,
            "automated_result": null,
        });
        super::write_json(&mut handle, &body)?;
    } else {
        writeln!(handle, "{}", plan.dry_run()).map_err(Error::from)?;
        writeln!(
            handle,
            "Manual page mode: Silvervine will not claim an automated playback result.",
        )
        .map_err(Error::from)?;
    }
    plan.execute_real_browser()
}

fn run_automated(browser: &Browser, args: &Args) -> Result<()> {
    if std::env::var_os(NOOP_ENV).is_some() {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        if args.output.json {
            writeln!(
                handle,
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "mode": "automated",
                    "browser": browser.name(),
                    "noop": true,
                }))?
            )
            .map_err(Error::from)?;
        } else {
            writeln!(
                handle,
                "Would run the browser-reported EME capability probe for {}.",
                browser.name()
            )
            .map_err(Error::from)?;
        }
        return Ok(());
    }

    if !args.output.json {
        eprintln!(
            "Launching {} with its normal profile for a browser-reported EME capability check…",
            browser.name()
        );
    }
    let passive = collect_browser(browser);
    let outcome = run_browser_probe(browser, Duration::from_secs(60), &passive.ownership).map_err(
        |error| {
            if matches!(
                error.category,
                crate::ErrorCategory::BrowserProbeFailed
                    | crate::ErrorCategory::StateCorrupted
                    | crate::ErrorCategory::NetworkError
            ) {
                Error::browser_probe_failed(error.message.clone()).with_source(error)
            } else {
                error
            }
        },
    )?;
    let probe = outcome.raw;
    let assessment = outcome.assessment;
    let (cache_path, cache_warning) = persist_report(browser, &passive, &probe, &assessment);

    let stored = build_stored_report(browser, &passive, probe, assessment.clone())?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if args.output.json {
        // Exactly one StoredProbeReport document on stdout.
        writeln!(handle, "{}", serde_json::to_string_pretty(&stored)?).map_err(Error::from)?;
        if let Some(warning) = &cache_warning {
            eprintln!("warning: {warning}");
        }
    } else {
        render_live_text(
            browser.name(),
            &passive,
            &assessment,
            cache_path.as_deref(),
            cache_warning.as_deref(),
            &mut handle,
        )
        .map_err(Error::from)?;
    }
    // Optional row Warn must not fail the command. Overall Unavailable means the
    // software baseline could not be established (EME API/baseline missing) and
    // is a BrowserProbeFailed exit, same as Fail.
    match assessment.status {
        DiagnosticStatus::Fail | DiagnosticStatus::Unavailable => {
            Err(Error::browser_probe_failed(format!(
                "{} did not meet the browser-reported software playback baseline",
                browser.name()
            )))
        }
        DiagnosticStatus::Pass | DiagnosticStatus::Warn => Ok(()),
    }
}

fn persist_report(
    browser: &Browser,
    passive: &BrowserDiagnostics,
    probe: &RawProbeResult,
    assessment: &CapabilityAssessment,
) -> (Option<PathBuf>, Option<String>) {
    persist_report_to(None, browser, passive, probe, assessment)
}

fn persist_report_to(
    root: Option<&Path>,
    browser: &Browser,
    passive: &BrowserDiagnostics,
    probe: &RawProbeResult,
    assessment: &CapabilityAssessment,
) -> (Option<PathBuf>, Option<String>) {
    let Some(fingerprint) = passive.fingerprint.clone() else {
        return (
            None,
            Some(format!(
                "exact browser fingerprint unavailable for {}; report not cached",
                browser.name()
            )),
        );
    };
    let stored = match StoredProbeReport::now(
        browser.name(),
        fingerprint,
        probe.clone(),
        assessment.clone(),
    ) {
        Ok(stored) => stored,
        Err(error) => {
            return (
                None,
                Some(format!(
                    "could not cache live probe report for {}: {}",
                    browser.name(),
                    error.message
                )),
            );
        }
    };
    let save = match root {
        Some(root) => crate::diagnostics::store::save_report(root, &stored),
        None => save_default(&stored),
    };
    match save {
        Ok(path) => (Some(path), None),
        Err(error) => (
            None,
            Some(format!(
                "could not cache live probe report for {}: {}",
                browser.name(),
                error.message
            )),
        ),
    }
}

fn build_stored_report(
    browser: &Browser,
    passive: &BrowserDiagnostics,
    probe: RawProbeResult,
    assessment: CapabilityAssessment,
) -> Result<StoredProbeReport> {
    if let Some(fingerprint) = passive.fingerprint.clone() {
        return StoredProbeReport::now(browser.name(), fingerprint, probe, assessment);
    }
    // JSON mode still emits exactly one StoredProbeReport even without a cacheable fingerprint.
    let fingerprint = ProbeFingerprint::new(
        passive.browser_executable.as_ref().map_or_else(
            || format!("unresolved:{}", browser.name()),
            |path| path.display().to_string(),
        ),
        passive.browser_version.clone(),
        0,
        0,
        Vec::new(),
    );
    StoredProbeReport::now(browser.name(), fingerprint, probe, assessment)
}

fn render_live_text(
    browser: &str,
    passive: &BrowserDiagnostics,
    assessment: &CapabilityAssessment,
    cache_path: Option<&Path>,
    cache_warning: Option<&str>,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    writeln!(out, "Silvervine EME capability test — {browser}")?;
    writeln!(
        out,
        "Baseline: {} ({:?}) — {}",
        status_name(assessment.status),
        assessment.domain,
        assessment.summary
    )?;
    if !assessment.findings.is_empty() {
        writeln!(out, "Findings:")?;
        for finding in &assessment.findings {
            writeln!(out, "  - {finding}")?;
        }
    }
    if !assessment.actions.is_empty() {
        writeln!(out, "Actions:")?;
        for action in &assessment.actions {
            writeln!(out, "  - {action}")?;
        }
    }
    if !assessment.service_limits.is_empty() {
        writeln!(out, "Service limits:")?;
        for limit in &assessment.service_limits {
            writeln!(out, "  - {limit}")?;
        }
    }
    for check in passive.checks.iter().chain(&assessment.checks) {
        render_check(check, out)?;
    }
    match cache_path {
        Some(path) => writeln!(out, "Cached exact-fingerprint report: {}", path.display())?,
        None => writeln!(out, "Report cache path: null")?,
    }
    if let Some(warning) = cache_warning {
        writeln!(out, "Cache warning: {warning}")?;
    }
    writeln!(
        out,
        "Boundary: browser-reported evidence is not certified L1 or service entitlement."
    )
}

fn render_check(check: &DiagnosticCheck, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "  [{}] {} ({:?}/{:?})",
        status_name(check.status),
        check.summary,
        check.source,
        check.failure_domain
    )?;
    if let Some(action) = &check.action {
        writeln!(out, "      Action: {action}")?;
    }
    Ok(())
}

fn status_name(status: DiagnosticStatus) -> &'static str {
    match status {
        DiagnosticStatus::Pass => "PASS",
        DiagnosticStatus::Warn => "WARN",
        DiagnosticStatus::Fail => "FAIL",
        DiagnosticStatus::Unavailable => "UNAVAILABLE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::BrowserKind;
    use crate::diagnostics::store::STORE_SCHEMA_VERSION;
    use crate::eme::probe::{assess, EmeProbeResult};
    use crate::widevine::ownership::OwnershipAssessment;
    use std::fs;
    use tempfile::TempDir;

    /// Create a fake Linux browser install directory with the given
    /// executable name.
    #[cfg(target_os = "linux")]
    fn make_linux_browser(tmp: &Path, name: &str, exe: &str) -> Browser {
        let install = tmp.join(name);
        fs::create_dir_all(&install).unwrap();
        let exe_path = install.join(exe);
        fs::write(&exe_path, "#!/bin/sh\nexit 0").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&exe_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&exe_path, perms).unwrap();
        }
        Browser {
            name: name.into(),
            install_path: install,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    #[cfg(target_os = "macos")]
    fn make_macos_browser(tmp: &Path, name: &str) -> Browser {
        let app = tmp.join(format!("{name}.app"));
        fs::create_dir_all(app.join("Contents").join("MacOS")).unwrap();
        fs::write(app.join("Contents").join("MacOS").join(name), "fake").unwrap();
        Browser {
            name: name.into(),
            install_path: app,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    #[test]
    fn plan_build_with_no_browsers_errors() {
        let r = Plan::build(&[], &Args::default());
        assert!(r.is_err());
    }

    #[test]
    fn plan_build_unknown_filter_name_errors() {
        let tmp = TempDir::new().unwrap();
        #[cfg(target_os = "linux")]
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        #[cfg(target_os = "macos")]
        let detected = vec![make_macos_browser(tmp.path(), "Helium")];
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let detected: Vec<Browser> = vec![];
        let args = Args {
            browser: Some("DoesNotExist".into()),
            ..Default::default()
        };
        let r = Plan::build(&detected, &args);
        assert!(r.is_err());
        let _ = tmp;
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_default_uses_first_detected_with_lowercase_exe() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        assert_eq!(plan.browser_name, "Helium");
        assert!(plan.browser_executable.ends_with("helium"));
        assert_eq!(plan.url, DEFAULT_TEST_URL);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_falls_back_to_chrome_binary() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "chrome")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        assert!(plan.browser_executable.ends_with("chrome"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_filter_is_case_insensitive() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let args = Args {
            browser: Some("HELIUM".into()),
            ..Default::default()
        };
        let plan = Plan::build(&detected, &args).expect("ok");
        assert_eq!(plan.browser_name, "Helium");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_url_override_takes_effect() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let args = Args {
            url: Some("https://example.com/test".into()),
            ..Default::default()
        };
        let plan = Plan::build(&detected, &args).expect("ok");
        assert_eq!(plan.url, "https://example.com/test");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_with_no_executable_errors() {
        let tmp = TempDir::new().unwrap();
        // Browser exists but has no recognizable executable.
        let install = tmp.path().join("Helium");
        fs::create_dir_all(&install).unwrap();
        let detected = vec![Browser {
            name: "Helium".into(),
            install_path: install,
            kind: BrowserKind::Detected,
            framework_name: None,
        }];
        let r = Plan::build(&detected, &Args::default());
        assert!(r.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_dry_run_includes_browser_path_and_url() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        let s = plan.dry_run();
        assert!(s.contains("Helium"));
        assert!(s.contains("helium"));
        assert!(s.contains(DEFAULT_TEST_URL));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_execute_real_browser_short_circuits_under_noop() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        // SAFETY: env mutations happen in serial test threads; we restore
        // at end-of-test.
        unsafe { std::env::set_var(NOOP_ENV, "1") };
        plan.execute_real_browser().expect("noop short-circuits");
        unsafe { std::env::remove_var(NOOP_ENV) };
    }

    #[cfg(unix)]
    #[test]
    fn plan_serializes_non_utf8_executable_as_lossy_text() {
        use std::os::unix::ffi::OsStringExt;

        let executable = PathBuf::from(std::ffi::OsString::from_vec(vec![
            b'/', b't', b'm', b'p', b'/', 0xff,
        ]));
        let plan = Plan {
            browser_name: "NonUtf8".into(),
            browser_executable: executable,
            url: DEFAULT_TEST_URL.into(),
        };

        let value = serde_json::to_value(plan).expect("path should serialize lossily");
        assert_eq!(value["executable"], "/tmp/\u{fffd}");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn plan_build_macos_resolves_app_bundle() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_macos_browser(tmp.path(), "Helium")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        assert!(plan.browser_executable.ends_with("MacOS/Helium"));
    }

    #[test]
    fn live_text_labels_browser_evidence_and_claim_boundary() {
        let passive = BrowserDiagnostics {
            browser: "Chromium".into(),
            browser_executable: None,
            browser_version: None,
            cdm_target: None,
            cdm_version: None,
            cdm_library: None,
            cdm_library_sha512: None,
            ownership: crate::widevine::ownership::OwnershipAssessment::default(),
            external_cdms: Vec::new(),
            fingerprint: None,
            checks: Vec::new(),
        };
        let probe = EmeProbeResult {
            schema_version: crate::eme::probe::PROBE_SCHEMA_VERSION,
            user_agent: "Chromium/150".into(),
            eme_api: true,
            media_capabilities_api: true,
            baseline: crate::eme::probe::CapabilityStatus::Supported,
            baseline_error: None,
            robustness: vec![crate::eme::probe::RobustnessResult {
                media_kind: crate::eme::probe::MediaKind::Video,
                robustness: "SW_SECURE_CRYPTO".into(),
                accepted: true,
                error: None,
            }],
            encryption_schemes: Vec::new(),
            hdcp: Vec::new(),
            codecs: vec![crate::eme::probe::CodecCapability {
                codec: "avc1.640028".into(),
                content_type: "video/mp4; codecs=\"avc1.640028\"".into(),
                width: 1920,
                height: 1080,
                framerate: 30,
                mse_supported: true,
                direct_playback: "probably".into(),
                media_capabilities: Some(crate::eme::probe::MediaCapabilitiesFacts {
                    supported: true,
                    smooth: Some(true),
                    power_efficient: Some(false),
                    key_system_access: Some(true),
                }),
                error: None,
            }],
        };
        let assessment = assess(&probe, &passive.ownership);
        let mut output = Vec::new();

        render_live_text(
            "Chromium",
            &passive,
            &assessment,
            None,
            Some("report not cached"),
            &mut output,
        )
        .expect("render");
        let text = String::from_utf8(output).expect("UTF-8");

        assert!(text.contains("Baseline: PASS"));
        assert!(text.contains("BrowserMediaStack"));
        assert!(
            text.contains("LiveBrowser/BrowserMediaStack")
                || text.contains("VerifiedFile/Silvervine")
                || text.contains("(BrowserMediaStack)")
        );
        assert!(text.contains("not certified L1"));
        assert!(
            text.contains("null") || text.contains("not cached") || text.contains("Cache warning")
        );
    }

    #[test]
    fn stored_report_json_schema_is_exact_top_level_document() {
        let probe = EmeProbeResult {
            schema_version: crate::eme::probe::PROBE_SCHEMA_VERSION,
            user_agent: "Chromium/150".into(),
            eme_api: true,
            media_capabilities_api: true,
            baseline: crate::eme::probe::CapabilityStatus::Supported,
            baseline_error: None,
            robustness: vec![crate::eme::probe::RobustnessResult {
                media_kind: crate::eme::probe::MediaKind::Video,
                robustness: "SW_SECURE_CRYPTO".into(),
                accepted: true,
                error: None,
            }],
            encryption_schemes: Vec::new(),
            hdcp: Vec::new(),
            codecs: vec![crate::eme::probe::CodecCapability {
                codec: "avc1.640028".into(),
                content_type: "video/mp4; codecs=\"avc1.640028\"".into(),
                width: 1920,
                height: 1080,
                framerate: 30,
                mse_supported: true,
                direct_playback: "probably".into(),
                media_capabilities: Some(crate::eme::probe::MediaCapabilitiesFacts {
                    supported: true,
                    smooth: Some(true),
                    power_efficient: Some(false),
                    key_system_access: Some(true),
                }),
                error: None,
            }],
        };
        let assessment = crate::eme::probe::assess(&probe, &OwnershipAssessment::default());
        let report = StoredProbeReport {
            schema_version: STORE_SCHEMA_VERSION,
            probed_at: 1,
            browser_name: "Chromium".into(),
            fingerprint: ProbeFingerprint::new("chromium", Some("1".into()), 1, 1, Vec::new()),
            raw: probe,
            assessment,
        };
        let value = serde_json::to_value(&report).expect("json");
        let keys = value
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "assessment",
                "browser_name",
                "fingerprint",
                "probed_at",
                "raw",
                "schema_version"
            ]
        );
        assert_eq!(value["browser_name"], "Chromium");
        assert!(value["raw"].get("persistent_license").is_none());
    }

    #[test]
    fn cache_write_failure_keeps_passing_assessment() {
        use crate::browsers::BrowserKind;
        use std::fs;
        use tempfile::TempDir;

        let probe = EmeProbeResult {
            schema_version: crate::eme::probe::PROBE_SCHEMA_VERSION,
            user_agent: "Chromium/150".into(),
            eme_api: true,
            media_capabilities_api: true,
            baseline: crate::eme::probe::CapabilityStatus::Supported,
            baseline_error: None,
            robustness: vec![crate::eme::probe::RobustnessResult {
                media_kind: crate::eme::probe::MediaKind::Video,
                robustness: "SW_SECURE_CRYPTO".into(),
                accepted: true,
                error: None,
            }],
            encryption_schemes: Vec::new(),
            hdcp: Vec::new(),
            codecs: vec![crate::eme::probe::CodecCapability {
                codec: "avc1.640028".into(),
                content_type: "video/mp4; codecs=\"avc1.640028\"".into(),
                width: 1920,
                height: 1080,
                framerate: 30,
                mse_supported: true,
                direct_playback: "probably".into(),
                media_capabilities: None,
                error: None,
            }],
        };
        let ownership = OwnershipAssessment::default();
        let assessment = assess(&probe, &ownership);
        assert_eq!(assessment.status, DiagnosticStatus::Pass);

        let browser = Browser {
            name: "Chromium".into(),
            install_path: PathBuf::from("/tmp/chromium"),
            kind: BrowserKind::Detected,
            framework_name: None,
        };
        let fingerprint = ProbeFingerprint::new(
            "/opt/test/chromium",
            Some("150".into()),
            10,
            1_700_000_000,
            Vec::new(),
        );
        let passive = BrowserDiagnostics {
            browser: "Chromium".into(),
            browser_executable: Some(PathBuf::from("/opt/test/chromium")),
            browser_version: Some("150".into()),
            cdm_target: None,
            cdm_version: None,
            cdm_library: None,
            cdm_library_sha512: None,
            ownership: ownership.clone(),
            external_cdms: Vec::new(),
            fingerprint: Some(fingerprint),
            checks: Vec::new(),
        };

        // File path as cache root makes save_report fail.
        let tmp = TempDir::new().expect("tmp");
        let blocker = tmp.path().join("not-a-dir");
        fs::write(&blocker, b"x").expect("blocker");

        let (cache_path, cache_warning) =
            persist_report_to(Some(&blocker), &browser, &passive, &probe, &assessment);
        let stored =
            build_stored_report(&browser, &passive, probe, assessment).expect("stored report");

        assert_eq!(stored.assessment.status, DiagnosticStatus::Pass);
        assert!(cache_path.is_none());
        assert!(cache_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("could not cache")));

        let json = serde_json::to_value(&stored).expect("json");
        assert!(json.get("assessment").is_some());
        assert_eq!(json["assessment"]["status"], "pass");
        assert!(json.get("mode").is_none());

        let mut out = Vec::new();
        render_live_text(
            "Chromium",
            &passive,
            &stored.assessment,
            cache_path.as_deref(),
            cache_warning.as_deref(),
            &mut out,
        )
        .expect("render");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("Baseline: PASS"));
        assert!(text.contains("Cache warning") || text.contains("null"));
    }

    #[test]
    fn baseline_failure_uses_browser_probe_failed_category() {
        let err = Error::browser_probe_failed("baseline failed");
        assert_eq!(err.category, crate::ErrorCategory::BrowserProbeFailed);
    }
}
