//! `silvervine doctor` — diagnostics + EME error-code translation.
//!
//! ## Modes
//!
//! 1. **Plain** (`silvervine doctor`) — print a friendly diagnostic summary.
//! 2. **JSON** (`silvervine doctor --json`) — same data, machine-readable.
//! 3. **Share** (`silvervine doctor --share`) — print a clickable URL that
//!    pre-fills a GitHub issue with the diagnostic body.
//! 4. **Code translation** (`silvervine doctor <code>`) — translate an EME
//!    error code via [`crate::eme::translate_error_code`] into
//!    actionable advice.

use std::collections::BTreeMap;
use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::browsers;
use crate::cli::OutputOptions;
use crate::daemon::tray::{detect_tray_availability, TrayAvailability};
use crate::diagnostics::collect::{collect_browser, collect_host_media_checks, BrowserDiagnostics};
use crate::diagnostics::store::{load_default, CacheLookup, ProbeFingerprint, StoredProbeReport};
use crate::diagnostics::{DiagnosticCheck, DiagnosticStatus, EvidenceSource, FailureDomain};
use crate::eme;
use crate::error::{Error, Result};

/// Args for `silvervine doctor`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Optional positional: an EME error code to translate. When set,
    /// `doctor` prints the diagnosis and exits.
    pub error_code: Option<String>,
    /// `--share`: emit an issue-template URL prefilled with the report.
    pub share: bool,
    /// `--media-stack`: collect passive browser, CDM, codec, and graphics evidence.
    pub media_stack: bool,
    /// Optional browser filter for `--media-stack`.
    pub browser: Option<String>,
    /// Output flags.
    pub output: OutputOptions,
}

/// Bundle of diagnostic information used by both human + JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Diagnostics {
    /// `silvervine` version (from `Cargo.toml`).
    pub silvervine_version: String,
    /// Heartbeat timestamp (Unix seconds), if the daemon is/was running.
    pub heartbeat_at: Option<u64>,
    /// `true` when the heartbeat is older than the staleness threshold.
    pub heartbeat_stale: bool,
    /// Currently-cached CDM version, if any.
    pub current_cdm_version: Option<String>,
    /// Per-browser status snapshot. Reuses the [`crate::cli::status`]
    /// shape so consumers can swap the two payloads.
    pub browsers: Vec<crate::cli::status::BrowserStatus>,
    /// Whether the legacy V1 install was detected on disk.
    pub legacy_install_present: bool,
    /// Whether the tray icon backend is usable in this environment.
    /// Surfaces silent-fallback to notifications-only mode (e.g. when
    /// no session D-Bus is reachable) so users don't have to grep
    /// journalctl to figure out why their tray icon is missing.
    pub tray: TrayAvailability,
    /// Optional passive media evidence and exact-fingerprint cached live probes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_stack: Option<MediaDiagnostics>,
}

/// Passive media evidence plus exact-fingerprint cached browser results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaDiagnostics {
    /// Per-browser passive and cached live evidence.
    pub browsers: Vec<BrowserMediaDiagnostics>,
    /// Optional fixed platform utility checks.
    pub host_checks: Vec<DiagnosticCheck>,
}

/// Media evidence associated with one detected browser.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserMediaDiagnostics {
    /// Passive browser, binary, and CDM evidence.
    pub passive: BrowserDiagnostics,
    /// Live browser evidence only when the complete fingerprint matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_probe: Option<StoredProbeReport>,
    /// Explicit hit, stale, missing, or malformed cache observation.
    pub cache_check: DiagnosticCheck,
}

/// Heartbeat staleness threshold (per spec: 5 minutes).
pub const HEARTBEAT_STALE_AFTER_SECS: u64 = 300;

/// Build the diagnostic bundle from a snapshot of inputs.
///
/// Pure — tests pass synthetic inputs. Production wires the inputs
/// from real detectors.
#[must_use]
pub fn build_diagnostics(
    detected: &[crate::browsers::Browser],
    heartbeat_at: Option<u64>,
    current_cdm_version: Option<String>,
    legacy_install_present: bool,
    tray: TrayAvailability,
    now: u64,
) -> Diagnostics {
    let heartbeat_stale = match heartbeat_at {
        Some(ts) => now.saturating_sub(ts) > HEARTBEAT_STALE_AFTER_SECS,
        None => false,
    };
    let browsers_snapshot = detected
        .iter()
        .map(crate::cli::status::BrowserStatus::from_browser)
        .collect();
    Diagnostics {
        silvervine_version: env!("CARGO_PKG_VERSION").to_string(),
        heartbeat_at,
        heartbeat_stale,
        current_cdm_version,
        browsers: browsers_snapshot,
        legacy_install_present,
        tray,
        media_stack: None,
    }
}

/// Render diagnostics as a friendly human-readable report.
///
/// # Errors
///
/// Propagates `std::io::Error` from `writeln!`.
pub fn render_text(d: &Diagnostics, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(out, "Silvervine doctor v{}", d.silvervine_version)?;
    writeln!(out)?;
    if d.legacy_install_present {
        writeln!(
            out,
            "WARN: A legacy V1 install was detected. Run `silvervine repair` or"
        )?;
        writeln!(out, "      run setup again to migrate.")?;
    }
    match (d.heartbeat_at, d.heartbeat_stale) {
        (Some(ts), true) => writeln!(
            out,
            "Daemon: heartbeat is STALE (last seen {ts} Unix-secs ago)"
        )?,
        (Some(ts), false) => writeln!(out, "Daemon: heartbeat OK (Unix {ts})")?,
        (None, _) => writeln!(out, "Daemon: not running (no heartbeat file)")?,
    }
    if let Some(v) = &d.current_cdm_version {
        writeln!(out, "CDM: cached version {v}")?;
    } else {
        writeln!(
            out,
            "CDM: no cached version (run `silvervine update widevine`)"
        )?;
    }
    match &d.tray {
        TrayAvailability::Available => {
            writeln!(out, "Tray: available")?;
        }
        TrayAvailability::Unavailable(reason) => {
            writeln!(out, "Tray: unavailable — {reason}")?;
        }
    }
    writeln!(out)?;
    if d.browsers.is_empty() {
        writeln!(out, "Browsers: none detected")?;
    } else {
        writeln!(out, "Browsers:")?;
        for b in &d.browsers {
            write_browser_line(out, b, d.current_cdm_version.as_deref())?;
        }
    }
    if let Some(media) = &d.media_stack {
        render_media(media, out)?;
    }
    Ok(())
}

/// Render one browser row inside the `Browsers:` block.
///
/// Format: `  {name} — {status}[, {detail}] ({install_path})`
/// where detail is one of:
///   * `CDM x.y.z` when patched and matching the cache;
///   * `CDM x.y.z — out of date, cache has w.v.u; run "Patch Now"` when
///     the on-disk CDM is older than what the cache holds;
///   * nothing when the on-disk version can't be read.
fn write_browser_line(
    out: &mut dyn Write,
    b: &crate::cli::status::BrowserStatus,
    cached_cdm: Option<&str>,
) -> std::io::Result<()> {
    let status = if b.patched { "patched" } else { "NOT patched" };
    match (b.patched, b.cdm_version.as_deref(), cached_cdm) {
        (true, Some(on_disk), Some(cached)) if on_disk != cached => writeln!(
            out,
            "  {name} — {status} (CDM {on_disk} — out of date, \
             cache has {cached}; run \"Patch Now\") ({path})",
            name = b.name,
            path = b.install_path,
        ),
        (true, Some(on_disk), _) => writeln!(
            out,
            "  {name} — {status} (CDM {on_disk}) ({path})",
            name = b.name,
            path = b.install_path,
        ),
        _ => writeln!(
            out,
            "  {name} — {status} ({path})",
            name = b.name,
            path = b.install_path,
        ),
    }
}

fn render_media(media: &MediaDiagnostics, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(out)?;
    writeln!(out, "Passive media diagnostics (did not launch a browser):")?;
    for browser in &media.browsers {
        writeln!(out, "  {}:", browser.passive.browser)?;
        for check in &browser.passive.checks {
            render_media_check(check, out)?;
        }
        render_media_check(&browser.cache_check, out)?;
        if let Some(report) = &browser.cached_probe {
            writeln!(
                out,
                "    Cached live baseline: [{}] {}",
                status_name(report.assessment.status),
                report.assessment.summary
            )?;
            for check in &report.assessment.checks {
                render_media_check(check, out)?;
            }
        }
    }
    if !media.host_checks.is_empty() {
        writeln!(out, "  Host media utilities:")?;
        for check in &media.host_checks {
            render_media_check(check, out)?;
        }
    }
    writeln!(
        out,
        "  Boundary: browser-reported evidence is not certified L1 or service entitlement."
    )
}

fn render_media_check(check: &DiagnosticCheck, out: &mut dyn Write) -> std::io::Result<()> {
    writeln!(
        out,
        "    [{}] {} ({:?}/{:?})",
        status_name(check.status),
        check.summary,
        check.source,
        check.failure_domain
    )?;
    if let Some(action) = &check.action {
        writeln!(out, "        Action: {action}")?;
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

fn collect_media(detected: &[&crate::browsers::Browser]) -> MediaDiagnostics {
    let browsers = detected
        .iter()
        .copied()
        .map(|browser| {
            let passive = collect_browser(browser);
            let (cached_probe, cache_check) =
                cached_probe(browser.name(), passive.fingerprint.as_ref());
            BrowserMediaDiagnostics {
                passive,
                cached_probe,
                cache_check,
            }
        })
        .collect();
    MediaDiagnostics {
        browsers,
        host_checks: collect_host_media_checks(),
    }
}

fn cached_probe(
    browser: &str,
    fingerprint: Option<&ProbeFingerprint>,
) -> (Option<StoredProbeReport>, DiagnosticCheck) {
    let Some(fingerprint) = fingerprint else {
        return (
            None,
            unavailable_cache_check(
                browser,
                "Exact browser executable fingerprint is unavailable.",
                BTreeMap::new(),
            ),
        );
    };
    match load_default(fingerprint) {
        Ok(CacheLookup::Hit(report)) => cache_hit(report),
        Ok(CacheLookup::Stale(report)) => (
            None,
            unavailable_cache_check(
                browser,
                "Cached live EME evidence is stale because the browser or CDM changed.",
                BTreeMap::from([
                    (
                        "cached_browser_version".into(),
                        version_or_unavailable(report.fingerprint.browser_version.as_deref()),
                    ),
                    (
                        "current_browser_version".into(),
                        version_or_unavailable(fingerprint.browser_version.as_deref()),
                    ),
                    (
                        "cached_cdm_version".into(),
                        version_or_unavailable(report.fingerprint.primary_cdm_version()),
                    ),
                    (
                        "current_cdm_version".into(),
                        version_or_unavailable(fingerprint.primary_cdm_version()),
                    ),
                ]),
            ),
        ),
        Ok(CacheLookup::Missing) => (
            None,
            unavailable_cache_check(
                browser,
                "No exact-fingerprint live EME evidence is cached.",
                BTreeMap::new(),
            ),
        ),
        Err(error) => (
            None,
            DiagnosticCheck {
                id: "eme.cached_probe".into(),
                status: DiagnosticStatus::Warn,
                source: EvidenceSource::HostProbe,
                failure_domain: FailureDomain::Silvervine,
                summary: "The cached live EME report could not be read safely.".into(),
                action: Some(cache_action(browser)),
                details: BTreeMap::from([
                    ("error_category".into(), error.category.as_str().into()),
                    ("error".into(), error.message),
                ]),
            },
        ),
    }
}

fn cache_hit(report: StoredProbeReport) -> (Option<StoredProbeReport>, DiagnosticCheck) {
    let check = DiagnosticCheck {
        id: "eme.cached_probe".into(),
        status: report.assessment.status,
        source: EvidenceSource::LiveBrowser,
        failure_domain: FailureDomain::BrowserMediaStack,
        summary: format!(
            "Exact-fingerprint live EME evidence was probed at Unix {}.",
            report.probed_at
        ),
        action: report.assessment.action().map(str::to_owned),
        details: BTreeMap::from([
            ("probed_at".into(), report.probed_at.to_string()),
            (
                "browser_version".into(),
                version_or_unavailable(report.fingerprint.browser_version.as_deref()),
            ),
            (
                "cdm_version".into(),
                version_or_unavailable(report.fingerprint.primary_cdm_version()),
            ),
        ]),
    };
    (Some(report), check)
}

fn unavailable_cache_check(
    browser: &str,
    summary: &str,
    details: BTreeMap<String, String>,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: "eme.cached_probe".into(),
        status: DiagnosticStatus::Unavailable,
        source: EvidenceSource::HostProbe,
        failure_domain: FailureDomain::BrowserMediaStack,
        summary: summary.into(),
        action: Some(cache_action(browser)),
        details,
    }
}

fn cache_action(browser: &str) -> String {
    format!("Run `silvervine test --browser {browser}`.")
}

fn version_or_unavailable(version: Option<&str>) -> String {
    version.unwrap_or("unavailable").into()
}

/// Build the `?body=<urlencoded>` string for a GitHub issue template.
///
/// The user's diagnostic bundle (rendered as text) is URL-encoded and
/// placed in the issue body. The link resolves to:
///
/// ```text
/// https://github.com/nicholasraimbault/silvervine/issues/new?template=bug.yml&body=<encoded>
/// ```
#[must_use]
pub fn share_url(diagnostics: &Diagnostics) -> String {
    let mut buf = Vec::new();
    let _ = render_text_compact(diagnostics, &mut buf);
    let text = String::from_utf8_lossy(&buf);
    let body = format!("```\n{text}\n```\n\n_Generated by `silvervine doctor --share`._");
    let encoded = urlencoding::encode(&body);
    format!("https://github.com/nicholasraimbault/silvervine/issues/new?template=bug.yml&body={encoded}")
}

fn render_text_compact(d: &Diagnostics, out: &mut dyn Write) -> std::io::Result<()> {
    // Compact share body omits raw matrices while retaining domain-labeled outcomes.
    writeln!(out, "Silvervine {} diagnostics", d.silvervine_version)?;
    writeln!(
        out,
        "CDM cache: {}",
        d.current_cdm_version.as_deref().unwrap_or("none")
    )?;
    writeln!(out, "Browsers: {}", d.browsers.len())?;
    for browser in &d.browsers {
        writeln!(
            out,
            "  {}: {}",
            browser.name,
            browser
                .cdm_version
                .as_deref()
                .unwrap_or("no install-root CDM")
        )?;
    }
    if let Some(media) = &d.media_stack {
        writeln!(out, "Media stack (passive, no browser launch):")?;
        for browser in &media.browsers {
            writeln!(
                out,
                "  {} ownership: {}",
                browser.passive.browser, browser.passive.ownership.summary
            )?;
            writeln!(
                out,
                "    cache: [{}] {}",
                status_name(browser.cache_check.status),
                browser.cache_check.summary
            )?;
            if let Some(report) = &browser.cached_probe {
                writeln!(
                    out,
                    "    live baseline: [{}] {}",
                    status_name(report.assessment.status),
                    report.assessment.summary
                )?;
                for action in &report.assessment.actions {
                    writeln!(out, "      action: {action}")?;
                }
            }
        }
        if !media.host_checks.is_empty() {
            writeln!(out, "  Host checks: {}", media.host_checks.len())?;
            for check in &media.host_checks {
                writeln!(out, "    [{}] {}", status_name(check.status), check.summary)?;
            }
        }
    }
    Ok(())
}

fn filter_browsers<'a>(
    detected: &'a [crate::browsers::Browser],
    browser: Option<&str>,
) -> Result<Vec<&'a crate::browsers::Browser>> {
    match browser {
        None => Ok(detected.iter().collect()),
        Some(name) => {
            let matched: Vec<_> = detected
                .iter()
                .filter(|candidate| candidate.name().eq_ignore_ascii_case(name))
                .collect();
            if matched.is_empty() {
                Err(Error::other(format!("no detected browser named '{name}'")))
            } else {
                Ok(matched)
            }
        }
    }
}

/// CLI entry point.
///
/// # Errors
///
/// * Errors from browser detection or writing to stdout.
pub fn run(args: &Args) -> Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    if args.media_stack && args.error_code.is_some() {
        return Err(Error::other(
            "`doctor --media-stack` conflicts with error-code translation",
        ));
    }
    if args.browser.is_some() && !args.media_stack {
        return Err(Error::other("`doctor --browser` requires `--media-stack`"));
    }

    // Code-translation mode short-circuits the diagnostic bundle.
    if let Some(code) = &args.error_code {
        return run_translate(code, args.output, &mut handle);
    }

    let detected = browsers::detect_browsers()?;
    let heartbeat_at = crate::cli::status::read_heartbeat();
    let current_cdm = crate::cli::status::current_cdm_version();
    let legacy_present = !crate::migration::detect_legacy_install().is_empty();
    let tray = detect_tray_availability();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut d = build_diagnostics(
        &detected,
        heartbeat_at,
        current_cdm,
        legacy_present,
        tray,
        now,
    );
    if args.media_stack {
        let browsers = filter_browsers(&detected, args.browser.as_deref())?;
        d.media_stack = Some(collect_media(&browsers));
    }

    if args.share {
        writeln!(handle, "{}", share_url(&d)).map_err(Error::from)?;
        return Ok(());
    }
    if args.output.json {
        super::write_json(&mut handle, &d)?;
    } else {
        render_text(&d, &mut handle).map_err(Error::from)?;
    }
    Ok(())
}

fn run_translate(code: &str, output: OutputOptions, out: &mut dyn Write) -> Result<()> {
    if let Some(d) = eme::translate_error_code(code) {
        if output.json {
            super::write_json(out, &d)?;
        } else {
            writeln!(out, "Service: {}", d.service).map_err(Error::from)?;
            writeln!(out, "Code: {}", d.code).map_err(Error::from)?;
            writeln!(out, "Likely cause: {}", d.likely_cause).map_err(Error::from)?;
            if let Some(cmd) = d.suggested_command {
                writeln!(out, "Suggested: {cmd}").map_err(Error::from)?;
            } else {
                writeln!(out, "(silvervine cannot fix this code automatically)")
                    .map_err(Error::from)?;
            }
        }
        Ok(())
    } else {
        writeln!(
            out,
            "Unknown error code '{code}'. Try `silvervine doctor` to check Widevine state."
        )
        .map_err(Error::from)?;
        Err(Error::other(format!("unknown EME error code: {code}")))
    }
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

    /// Build a fake patched browser whose `WidevineCdm/manifest.json`
    /// reports the given CDM version. Used to exercise the doctor's
    /// version-freshness rendering.
    fn fake_patched_browser(name: &str, tmp: &TempDir, cdm_version: &str) -> Browser {
        let install = tmp.path().join(name);
        let cdm = install.join("WidevineCdm");
        std::fs::create_dir_all(&cdm).expect("mkdir cdm");
        std::fs::write(
            cdm.join("manifest.json"),
            format!(r#"{{"version":"{cdm_version}"}}"#),
        )
        .expect("write manifest");
        fake_browser(name, install)
    }

    #[test]
    fn build_diagnostics_no_browsers_no_heartbeat() {
        let d = build_diagnostics(
            &[],
            None,
            None,
            false,
            TrayAvailability::Available,
            1_700_000_000,
        );
        assert!(d.browsers.is_empty());
        assert!(d.heartbeat_at.is_none());
        assert!(!d.heartbeat_stale);
        assert!(!d.legacy_install_present);
    }

    #[test]
    fn build_diagnostics_marks_stale_heartbeat() {
        let d = build_diagnostics(
            &[],
            Some(1_700_000_000),
            None,
            false,
            TrayAvailability::Available,
            1_700_000_500,
        );
        assert_eq!(d.heartbeat_at, Some(1_700_000_000));
        assert!(d.heartbeat_stale);
    }

    #[test]
    fn build_diagnostics_fresh_heartbeat_not_stale() {
        let d = build_diagnostics(
            &[],
            Some(1_700_000_000),
            None,
            false,
            TrayAvailability::Available,
            1_700_000_100,
        );
        assert!(!d.heartbeat_stale);
    }

    #[test]
    fn build_diagnostics_legacy_present_flag_propagates() {
        let d = build_diagnostics(&[], None, None, true, TrayAvailability::Available, 0);
        assert!(d.legacy_install_present);
    }

    #[test]
    fn build_diagnostics_includes_browser_snapshot() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![fake_browser("Helium", tmp.path().join("h"))];
        let d = build_diagnostics(
            &detected,
            None,
            Some("4.10.0".into()),
            false,
            TrayAvailability::Available,
            0,
        );
        assert_eq!(d.browsers.len(), 1);
        assert_eq!(d.browsers[0].name, "Helium");
        assert_eq!(d.current_cdm_version.as_deref(), Some("4.10.0"));
    }

    #[test]
    fn render_text_indicates_no_daemon() {
        let d = build_diagnostics(&[], None, None, false, TrayAvailability::Available, 0);
        let mut buf = Vec::new();
        render_text(&d, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("not running"));
    }

    #[test]
    fn render_text_legacy_install_warning() {
        let d = build_diagnostics(&[], None, None, true, TrayAvailability::Available, 0);
        let mut buf = Vec::new();
        render_text(&d, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("legacy") && s.contains("WARN"));
    }

    #[test]
    fn render_text_browser_status_lines() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![fake_browser("Helium", tmp.path().join("h"))];
        let d = build_diagnostics(&detected, None, None, false, TrayAvailability::Available, 0);
        let mut buf = Vec::new();
        render_text(&d, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Helium"));
        assert!(s.contains("NOT patched"));
    }

    /// build_diagnostics must read the on-disk CDM version from each
    /// patched browser's bundle so doctor can compare it to the cache.
    #[test]
    fn build_diagnostics_populates_installed_cdm_version() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![fake_patched_browser("Helium", &tmp, "4.10.2891.0")];
        let d = build_diagnostics(
            &detected,
            None,
            Some("4.10.2934.0".into()),
            false,
            TrayAvailability::Available,
            0,
        );
        assert_eq!(d.browsers[0].cdm_version.as_deref(), Some("4.10.2891.0"));
    }

    /// When the on-disk CDM matches the cache, doctor renders the version
    /// inline but emits no out-of-date warning.
    #[test]
    fn render_text_shows_cdm_version_when_patched() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![fake_patched_browser("Helium", &tmp, "4.10.2934.0")];
        let d = build_diagnostics(
            &detected,
            None,
            Some("4.10.2934.0".into()),
            false,
            TrayAvailability::Available,
            0,
        );
        let mut buf = Vec::new();
        render_text(&d, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("CDM 4.10.2934.0"), "expected version in: {s}");
        assert!(
            !s.to_lowercase().contains("out of date"),
            "should not warn when fresh: {s}"
        );
    }

    /// When the on-disk CDM is older than the cache, doctor flags it as
    /// out-of-date and tells the user how to fix it.
    #[test]
    fn render_text_flags_stale_cdm() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![fake_patched_browser("Helium", &tmp, "4.10.2891.0")];
        let d = build_diagnostics(
            &detected,
            None,
            Some("4.10.2934.0".into()),
            false,
            TrayAvailability::Available,
            0,
        );
        let mut buf = Vec::new();
        render_text(&d, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.to_lowercase().contains("out of date"),
            "expected stale warning in: {s}"
        );
        assert!(s.contains("4.10.2891.0"), "expected on-disk version: {s}");
        assert!(s.contains("4.10.2934.0"), "expected cache version: {s}");
    }

    #[test]
    fn share_url_starts_with_github_template() {
        let d = build_diagnostics(&[], None, None, false, TrayAvailability::Available, 0);
        let url = share_url(&d);
        assert!(url.starts_with("https://github.com/nicholasraimbault/silvervine/issues/new"));
        assert!(url.contains("template=bug.yml"));
        assert!(url.contains("body="));
    }

    #[test]
    fn share_url_url_encodes_diagnostics() {
        // Synthesize a diagnostics with specific text so we can verify
        // the URL-encoded body roundtrips.
        let tmp = TempDir::new().unwrap();
        let detected = vec![fake_browser("Helium", tmp.path().join("h"))];
        let d = build_diagnostics(&detected, None, None, false, TrayAvailability::Available, 0);
        let url = share_url(&d);
        // The "Helium" name appears in the diagnostics; the URL should
        // contain its encoded form (no special chars).
        assert!(url.contains("Helium"));
    }

    #[test]
    fn run_translate_known_code_returns_ok() {
        let mut buf = Vec::new();
        let opts = OutputOptions::default();
        run_translate("N8156-6024", opts, &mut buf).expect("known code");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Netflix"));
        assert!(s.contains("Suggested:"));
    }

    #[test]
    fn run_translate_unknown_code_errors_and_writes_message() {
        let mut buf = Vec::new();
        let opts = OutputOptions::default();
        let r = run_translate("ZZZZ-0", opts, &mut buf);
        assert!(r.is_err());
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Unknown"));
    }

    #[test]
    fn run_translate_json_emits_object() {
        let mut buf = Vec::new();
        let opts = OutputOptions {
            json: true,
            ..Default::default()
        };
        run_translate("N8156-6024", opts, &mut buf).expect("ok");
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["service"], "Netflix");
    }

    #[test]
    fn run_translate_no_command_code_says_so() {
        // Netflix M7111-1331-2206 is a VPN block — silvervine can't fix it.
        let mut buf = Vec::new();
        let opts = OutputOptions::default();
        run_translate("M7111-1331-2206", opts, &mut buf).expect("known");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("cannot fix this code"));
    }

    #[test]
    fn diagnostics_round_trips_through_json() {
        let d = build_diagnostics(
            &[],
            Some(1),
            None,
            true,
            TrayAvailability::Unavailable("synthetic".into()),
            100,
        );
        let s = serde_json::to_string(&d).unwrap();
        let back: Diagnostics = serde_json::from_str(&s).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn render_text_includes_tray_available_row() {
        let d = build_diagnostics(&[], None, None, false, TrayAvailability::Available, 0);
        let mut buf = Vec::new();
        render_text(&d, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Tray: available"));
    }

    #[test]
    fn render_text_includes_tray_unavailable_reason() {
        let d = build_diagnostics(
            &[],
            None,
            None,
            false,
            TrayAvailability::Unavailable("session D-Bus unavailable".into()),
            0,
        );
        let mut buf = Vec::new();
        render_text(&d, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Tray: unavailable"));
        assert!(s.contains("session D-Bus unavailable"));
    }

    #[test]
    fn render_text_labels_passive_media_sources_and_claim_boundary() {
        let mut diagnostics =
            build_diagnostics(&[], None, None, false, TrayAvailability::Available, 0);
        diagnostics.media_stack = Some(MediaDiagnostics {
            browsers: vec![BrowserMediaDiagnostics {
                passive: crate::diagnostics::collect::BrowserDiagnostics {
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
                },
                cached_probe: None,
                cache_check: crate::diagnostics::DiagnosticCheck {
                    id: "eme.cached_probe".into(),
                    status: crate::diagnostics::DiagnosticStatus::Unavailable,
                    source: crate::diagnostics::EvidenceSource::HostProbe,
                    failure_domain: crate::diagnostics::FailureDomain::BrowserMediaStack,
                    summary: "No exact-fingerprint live EME report is cached.".into(),
                    action: Some("Run `silvervine test --browser Chromium`.".into()),
                    details: std::collections::BTreeMap::new(),
                },
            }],
            host_checks: Vec::new(),
        });

        let mut output = Vec::new();
        render_text(&diagnostics, &mut output).expect("render");
        let text = String::from_utf8(output).expect("UTF-8");

        assert!(text.contains("Passive media diagnostics"));
        assert!(text.contains("[UNAVAILABLE]"));
        assert!(text.contains("HostProbe/BrowserMediaStack"));
        assert!(text.contains("did not launch a browser"));
        assert!(text.contains("not certified L1"));
    }
}
