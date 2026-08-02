//! Host and aggregated passive media-stack reports.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::browsers::Browser;
use crate::diagnostics::collect::{collect_browser_with_candidate, BrowserDiagnostics};
use crate::diagnostics::DiagnosticCheck;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use crate::diagnostics::{DiagnosticStatus, EvidenceSource, FailureDomain};
use crate::error::{Error, Result};
use crate::widevine::CachedCdm;

#[cfg(target_os = "linux")]
use crate::diagnostics::linux;
#[cfg(target_os = "macos")]
use crate::diagnostics::macos;

/// One browser's passive media evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserMediaReport {
    /// Browser display name.
    pub browser_name: String,
    /// Passive collector output.
    pub passive: BrowserDiagnostics,
}

/// Host-level media/GPU evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostMediaReport {
    /// Platform identifier (`linux`, `macos`, …).
    pub platform: String,
    /// Source-labeled host checks.
    pub checks: Vec<DiagnosticCheck>,
}

/// Complete passive media-stack report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaStackReport {
    /// Generation timestamp in Unix seconds.
    pub generated_at: u64,
    /// Per-browser passive evidence.
    pub browsers: Vec<BrowserMediaReport>,
    /// Host media/GPU evidence.
    pub host: HostMediaReport,
}

/// Collect passive media evidence for the selected browsers.
///
/// # Errors
///
/// Returns only for invalid browser filter selection. Collector failures become
/// per-check evidence.
pub fn collect(
    browsers: &[Browser],
    browser_filter: Option<&str>,
    candidate: Option<&CachedCdm>,
) -> Result<MediaStackReport> {
    let selected: Vec<&Browser> = if let Some(filter) = browser_filter {
        let matched: Vec<&Browser> = browsers
            .iter()
            .filter(|browser| browser.name().eq_ignore_ascii_case(filter))
            .collect();
        if matched.is_empty() {
            return Err(Error::other(format!(
                "no detected browser matched filter `{filter}`"
            )));
        }
        matched
    } else {
        browsers.iter().collect()
    };

    let browser_reports = selected
        .into_iter()
        .map(|browser| BrowserMediaReport {
            browser_name: browser.name().into(),
            passive: collect_browser_with_candidate(browser, candidate),
        })
        .collect();

    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    Ok(MediaStackReport {
        generated_at,
        browsers: browser_reports,
        host: HostMediaReport {
            platform: std::env::consts::OS.into(),
            checks: collect_host_checks(),
        },
    })
}

/// Platform host media checks used by doctor and media reports.
#[must_use]
pub fn collect_host_checks() -> Vec<DiagnosticCheck> {
    #[cfg(target_os = "linux")]
    {
        linux::collect_host_checks()
    }
    #[cfg(target_os = "macos")]
    {
        macos::collect_host_checks()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        vec![DiagnosticCheck {
            id: "host.media_acceleration".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "Host media acceleration diagnostics are unavailable on this platform.".into(),
            action: None,
            details: Default::default(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::{Browser, BrowserKind};
    use std::path::PathBuf;

    #[test]
    fn unknown_browser_filter_is_an_error() {
        let browsers = [Browser {
            name: "Chromium".into(),
            install_path: PathBuf::from("/opt/chromium"),
            kind: BrowserKind::Known,
            framework_name: None,
        }];
        let error = collect(&browsers, Some("Helium"), None).expect_err("filter");
        assert!(error.message.contains("Helium"));
    }

    #[test]
    fn host_checks_never_abort() {
        let checks = collect_host_checks();
        assert!(checks.iter().all(|check| !check.id.is_empty()));
    }
}
