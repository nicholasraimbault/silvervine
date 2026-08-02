//! Shared media diagnostic evidence model.

pub mod binary;
pub mod collect;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod media;
pub mod store;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Outcome severity for an individual diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    /// The observed capability or invariant is satisfied.
    Pass,
    /// The check completed but found a limitation or degraded state.
    Warn,
    /// The check found a condition that prevents the relevant capability.
    Fail,
    /// The host or browser did not expose enough evidence to decide.
    Unavailable,
}

/// Origin of the evidence behind a diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Reported by a live browser through browser-native APIs.
    LiveBrowser,
    /// Read from a file whose Silvervine provenance and digest were verified.
    VerifiedFile,
    /// Observed from the local operating system or a bounded host utility.
    HostProbe,
    /// Inferred from incomplete evidence and labeled accordingly.
    Heuristic,
}

/// Product boundary responsible for a result or remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureDomain {
    /// Silvervine installation, integrity, or patch state.
    Silvervine,
    /// Chromium, codecs, graphics drivers, or the local media stack.
    BrowserMediaStack,
    /// Account, title, allowlist, license, certification, or service policy.
    StreamingService,
}

/// One actionable, source-labeled diagnostic observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    /// Stable machine-readable check identifier.
    pub id: String,
    /// Outcome severity.
    pub status: DiagnosticStatus,
    /// Evidence origin.
    pub source: EvidenceSource,
    /// Product boundary responsible for failure or remediation.
    pub failure_domain: FailureDomain,
    /// Concise observed fact.
    pub summary: String,
    /// Concrete remediation when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Deterministically ordered source-specific evidence.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{DiagnosticCheck, DiagnosticStatus, EvidenceSource, FailureDomain};

    #[test]
    fn diagnostic_enums_serialize_as_stable_snake_case() {
        assert_eq!(
            serde_json::to_string(&DiagnosticStatus::Unavailable).expect("status"),
            r#""unavailable""#
        );
        assert_eq!(
            serde_json::to_string(&EvidenceSource::LiveBrowser).expect("source"),
            r#""live_browser""#
        );
        assert_eq!(
            serde_json::to_string(&FailureDomain::BrowserMediaStack).expect("domain"),
            r#""browser_media_stack""#
        );
    }

    #[test]
    fn diagnostic_check_preserves_action_and_sorted_details() {
        let check = DiagnosticCheck {
            id: "cdm.architecture".into(),
            status: DiagnosticStatus::Fail,
            source: EvidenceSource::VerifiedFile,
            failure_domain: FailureDomain::Silvervine,
            summary: "CDM architecture does not match the host".into(),
            action: Some("Run `silvervine update widevine`".into()),
            details: BTreeMap::from([
                ("host".into(), "x86_64".into()),
                ("library".into(), "aarch64".into()),
            ]),
        };

        let value = serde_json::to_value(check).expect("serialize");
        assert_eq!(value["status"], "fail");
        assert_eq!(value["source"], "verified_file");
        assert_eq!(value["failure_domain"], "silvervine");
        assert_eq!(value["details"]["host"], "x86_64");
        assert_eq!(value["details"]["library"], "aarch64");
    }
}
