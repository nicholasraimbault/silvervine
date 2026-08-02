//! Browser-reported Encrypted Media Extensions capability model.
//!
//! The embedded page posts raw facts only. Rust validates the document,
//! produces the bounded assessment, and returns that same assessment to the
//! page and CLI. No result claims certified L1, a protected hardware path, or
//! streaming-service entitlement.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::diagnostics::{DiagnosticCheck, DiagnosticStatus, EvidenceSource, FailureDomain};
use crate::widevine::ownership::{OwnershipAssessment, OwnershipKind};

/// Current JSON contract emitted by the embedded browser probe.
pub const PROBE_SCHEMA_VERSION: u8 = 1;

const MAX_USER_AGENT_LEN: usize = 512;
const MAX_ERROR_LEN: usize = 240;
const MAX_ROBUSTNESS_ROWS: usize = 32;
const MAX_SCHEME_ROWS: usize = 8;
const MAX_HDCP_ROWS: usize = 8;
const MAX_CODEC_ROWS: usize = 64;
/// Approved live matrix: 5 robustness × 2 media kinds.
pub const EXPECTED_ROBUSTNESS_ROWS: usize = 10;
/// Approved live matrix: cenc + cbcs.
pub const EXPECTED_SCHEME_ROWS: usize = 2;
/// Approved live matrix: HDCP 1.4 + 2.2.
pub const EXPECTED_HDCP_ROWS: usize = 2;
/// Approved live matrix: 4 video codecs × 3 sizes.
pub const EXPECTED_CODEC_ROWS: usize = 12;

/// Browser outcome for one EME or Media Capabilities request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    /// The browser accepted the request.
    Supported,
    /// The browser evaluated and rejected the request.
    Rejected,
    /// The required browser API was absent.
    Unavailable,
    /// The browser API threw or returned malformed state.
    Error,
}

/// Media track type associated with a capability request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    /// Audio capability.
    Audio,
    /// Video capability.
    Video,
}

/// Known Widevine robustness strings ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RobustnessLevel {
    /// `SW_SECURE_CRYPTO`.
    SoftwareSecureCrypto,
    /// `SW_SECURE_DECODE`.
    SoftwareSecureDecode,
    /// `HW_SECURE_CRYPTO`.
    HardwareSecureCrypto,
    /// `HW_SECURE_DECODE`.
    HardwareSecureDecode,
    /// `HW_SECURE_ALL`.
    HardwareSecureAll,
}

impl RobustnessLevel {
    /// Parse only standardized Widevine robustness strings.
    #[must_use]
    pub fn from_eme(value: &str) -> Option<Self> {
        match value {
            "SW_SECURE_CRYPTO" => Some(Self::SoftwareSecureCrypto),
            "SW_SECURE_DECODE" => Some(Self::SoftwareSecureDecode),
            "HW_SECURE_CRYPTO" => Some(Self::HardwareSecureCrypto),
            "HW_SECURE_DECODE" => Some(Self::HardwareSecureDecode),
            "HW_SECURE_ALL" => Some(Self::HardwareSecureAll),
            _ => None,
        }
    }

    /// Canonical Widevine EME string.
    #[must_use]
    pub fn as_eme(self) -> &'static str {
        match self {
            Self::SoftwareSecureCrypto => "SW_SECURE_CRYPTO",
            Self::SoftwareSecureDecode => "SW_SECURE_DECODE",
            Self::HardwareSecureCrypto => "HW_SECURE_CRYPTO",
            Self::HardwareSecureDecode => "HW_SECURE_DECODE",
            Self::HardwareSecureAll => "HW_SECURE_ALL",
        }
    }

    /// Whether this level is optional evidence outside the software baseline.
    #[must_use]
    pub const fn is_hardware(self) -> bool {
        matches!(
            self,
            Self::HardwareSecureCrypto | Self::HardwareSecureDecode | Self::HardwareSecureAll
        )
    }
}

/// Optional browser API result that may be unsupported without invalidating
/// the whole report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeValue<T> {
    /// Whether the value was observed.
    pub status: CapabilityStatus,
    /// Observed value when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<T>,
    /// Sanitized exception or rejection detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of requesting one robustness/media-kind combination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RobustnessResult {
    /// Audio or video.
    pub media_kind: MediaKind,
    /// Exact robustness string requested from the browser.
    pub robustness: String,
    /// Whether the browser accepted the configuration.
    pub accepted: bool,
    /// Sanitized exception or rejection detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of requesting one common encryption scheme.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionSchemeResult {
    /// Encryption scheme identifier (`cenc` or `cbcs`).
    pub scheme: String,
    /// Whether the browser accepted the scheme.
    pub accepted: bool,
    /// Sanitized exception or rejection detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of `MediaKeys.getStatusForPolicy()` for one HDCP floor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HdcpResult {
    /// Requested minimum HDCP version, such as `"1.4"` or `"2.2"`.
    pub min_version: String,
    /// Browser policy status string when returned (`usable`, `output-restricted`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Sanitized exception or rejection detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// MediaCapabilities.decodingInfo facts for one codec configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaCapabilitiesFacts {
    /// Whether decodingInfo reported support.
    pub supported: bool,
    /// Whether decodingInfo reported smooth playback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smooth: Option<bool>,
    /// Whether decodingInfo reported power-efficient playback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub power_efficient: Option<bool>,
    /// Whether a key-system configuration was accepted with the query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_system_access: Option<bool>,
}

/// Closed `HTMLMediaElement.canPlayType` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanPlayStatus {
    /// The browser returned the empty string.
    #[serde(rename = "")]
    Unsupported,
    /// The browser reported uncertain support.
    #[serde(rename = "maybe")]
    Maybe,
    /// The browser reported affirmative support.
    #[serde(rename = "probably")]
    Probably,
}

impl CanPlayStatus {
    const fn is_supported(self) -> bool {
        matches!(self, Self::Probably)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "",
            Self::Maybe => "maybe",
            Self::Probably => "probably",
        }
    }
}

/// Result of probing one codec at one resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodecCapability {
    /// Short codec identifier (`avc1.640028`, …).
    pub codec: String,
    /// Full MIME content type supplied to the browser.
    pub content_type: String,
    /// Requested width in pixels.
    pub width: u32,
    /// Requested height in pixels.
    pub height: u32,
    /// Requested framerate.
    pub framerate: u32,
    /// Whether `MediaSource.isTypeSupported` accepted the content type.
    pub mse_supported: bool,
    /// Closed `HTMLMediaElement.canPlayType` result.
    pub direct_playback: CanPlayStatus,
    /// Optional MediaCapabilities facts for this configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_capabilities: Option<MediaCapabilitiesFacts>,
    /// Sanitized exception detail when MediaCapabilities failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Complete JSON document posted by the embedded browser probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawProbeResult {
    /// Must equal [`PROBE_SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Browser user agent reported by JavaScript.
    pub user_agent: String,
    /// Whether `navigator.requestMediaKeySystemAccess` exists.
    pub eme_api: bool,
    /// Whether `navigator.mediaCapabilities.decodingInfo` exists.
    pub media_capabilities_api: bool,
    /// Baseline temporary-session Widevine key-system access outcome.
    pub baseline: CapabilityStatus,
    /// Sanitized baseline rejection detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_error: Option<String>,
    /// Robustness ladder results.
    pub robustness: Vec<RobustnessResult>,
    /// Common encryption scheme results.
    pub encryption_schemes: Vec<EncryptionSchemeResult>,
    /// HDCP policy-query results.
    pub hdcp: Vec<HdcpResult>,
    /// Codec × resolution matrix results.
    pub codecs: Vec<CodecCapability>,
}

/// Backward-compatible name used by persistence and older call sites.
pub type EmeProbeResult = RawProbeResult;

impl RawProbeResult {
    /// Validate schema revision and bounded field sizes before assessment.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCategory::StateCorrupted`](crate::ErrorCategory::StateCorrupted)
    /// when the document violates the probe contract.
    pub fn validate(&self) -> crate::Result<()> {
        if self.schema_version != PROBE_SCHEMA_VERSION {
            return Err(crate::Error::state_corrupted(format!(
                "unsupported EME probe schema {}; expected {PROBE_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.user_agent.is_empty() || self.user_agent.len() > MAX_USER_AGENT_LEN {
            return Err(crate::Error::state_corrupted(
                "browser returned an out-of-bounds user agent",
            ));
        }
        if self.robustness.len() > MAX_ROBUSTNESS_ROWS
            || self.encryption_schemes.len() > MAX_SCHEME_ROWS
            || self.hdcp.len() > MAX_HDCP_ROWS
            || self.codecs.len() > MAX_CODEC_ROWS
        {
            return Err(crate::Error::state_corrupted(
                "browser returned an oversized EME capability matrix",
            ));
        }
        if let Some(error) = &self.baseline_error {
            reject_error_len(error, "baseline_error")?;
        }
        for row in &self.robustness {
            if let Some(error) = &row.error {
                reject_error_len(error, "robustness.error")?;
            }
            if RobustnessLevel::from_eme(&row.robustness).is_none() {
                return Err(crate::Error::state_corrupted(format!(
                    "browser returned unknown robustness {}",
                    row.robustness
                )));
            }
        }
        for row in &self.encryption_schemes {
            if row.scheme != "cenc" && row.scheme != "cbcs" {
                return Err(crate::Error::state_corrupted(format!(
                    "browser returned unexpected encryption scheme {}",
                    row.scheme
                )));
            }
            if let Some(error) = &row.error {
                reject_error_len(error, "encryption_schemes.error")?;
            }
        }
        for row in &self.hdcp {
            if row.min_version != "1.4" && row.min_version != "2.2" {
                return Err(crate::Error::state_corrupted(format!(
                    "browser returned unexpected HDCP version {}",
                    row.min_version
                )));
            }
            if let Some(error) = &row.error {
                reject_error_len(error, "hdcp.error")?;
            }
            if let Some(status) = &row.status {
                if status.len() > MAX_ERROR_LEN {
                    return Err(crate::Error::state_corrupted(
                        "browser returned an oversized HDCP status",
                    ));
                }
            }
        }
        for row in &self.codecs {
            if !is_approved_codec(&row.codec) {
                return Err(crate::Error::state_corrupted(format!(
                    "browser returned unexpected codec {}",
                    row.codec
                )));
            }
            if !is_approved_size(row.width, row.height, row.framerate) {
                return Err(crate::Error::state_corrupted(format!(
                    "browser returned unexpected codec size {}x{}@{}",
                    row.width, row.height, row.framerate
                )));
            }
            if row.content_type.len() > MAX_ERROR_LEN {
                return Err(crate::Error::state_corrupted(
                    "browser returned oversized codec fields",
                ));
            }
            if let Some(error) = &row.error {
                reject_error_len(error, "codecs.error")?;
            }
        }
        Ok(())
    }

    /// Validate the top-level schema revision.
    ///
    /// # Errors
    ///
    /// Returns a state-corrupted error when validation fails.
    pub fn validate_schema(&self) -> crate::Result<()> {
        self.validate()
    }

    /// Validate the approved live probe matrix shape on the POST boundary.
    ///
    /// Requires exact unique key sets — not merely matching array lengths — so
    /// duplicate SW/video rows or repeated cenc/HDCP/AVC720 entries cannot pass.
    ///
    /// # Errors
    ///
    /// Returns a state-corrupted error when the document is invalid or incomplete.
    pub fn validate_live_matrix(&self) -> crate::Result<()> {
        self.validate()?;
        if self.robustness.len() != EXPECTED_ROBUSTNESS_ROWS
            || self.encryption_schemes.len() != EXPECTED_SCHEME_ROWS
            || self.hdcp.len() != EXPECTED_HDCP_ROWS
            || self.codecs.len() != EXPECTED_CODEC_ROWS
        {
            return Err(crate::Error::state_corrupted(format!(
                "browser returned incomplete EME matrix (robustness={}, schemes={}, hdcp={}, codecs={}); expected {EXPECTED_ROBUSTNESS_ROWS}/{EXPECTED_SCHEME_ROWS}/{EXPECTED_HDCP_ROWS}/{EXPECTED_CODEC_ROWS}",
                self.robustness.len(),
                self.encryption_schemes.len(),
                self.hdcp.len(),
                self.codecs.len()
            )));
        }
        validate_live_robustness(&self.robustness)?;
        validate_live_schemes(&self.encryption_schemes)?;
        validate_live_hdcp(&self.hdcp)?;
        validate_live_codecs(&self.codecs)
    }
}
fn validate_live_robustness(rows: &[RobustnessResult]) -> crate::Result<()> {
    let expected = approved_robustness_keys();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let Some(level) = RobustnessLevel::from_eme(&row.robustness) else {
            return Err(crate::Error::state_corrupted(format!(
                "browser returned unknown robustness {}",
                row.robustness
            )));
        };
        let key = (row.media_kind, level);
        if !expected.contains(&key) {
            return Err(crate::Error::state_corrupted(
                "browser returned unexpected robustness matrix key",
            ));
        }
        if !seen.insert(key) {
            return Err(crate::Error::state_corrupted(
                "browser returned duplicate robustness matrix key",
            ));
        }
    }
    if seen != expected {
        return Err(crate::Error::state_corrupted(
            "browser robustness matrix is missing required media_kind × level pairs",
        ));
    }
    Ok(())
}

fn validate_live_schemes(rows: &[EncryptionSchemeResult]) -> crate::Result<()> {
    let expected: std::collections::BTreeSet<&str> = ["cenc", "cbcs"].into_iter().collect();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if !expected.contains(row.scheme.as_str()) {
            return Err(crate::Error::state_corrupted(format!(
                "browser returned unexpected encryption scheme {}",
                row.scheme
            )));
        }
        if !seen.insert(row.scheme.as_str()) {
            return Err(crate::Error::state_corrupted(
                "browser returned duplicate encryption scheme",
            ));
        }
    }
    if seen != expected {
        return Err(crate::Error::state_corrupted(
            "browser encryption-scheme matrix is missing cenc/cbcs",
        ));
    }
    Ok(())
}

fn validate_live_hdcp(rows: &[HdcpResult]) -> crate::Result<()> {
    let expected: std::collections::BTreeSet<&str> = ["1.4", "2.2"].into_iter().collect();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if !expected.contains(row.min_version.as_str()) {
            return Err(crate::Error::state_corrupted(format!(
                "browser returned unexpected HDCP version {}",
                row.min_version
            )));
        }
        if !seen.insert(row.min_version.as_str()) {
            return Err(crate::Error::state_corrupted(
                "browser returned duplicate HDCP version",
            ));
        }
    }
    if seen != expected {
        return Err(crate::Error::state_corrupted(
            "browser HDCP matrix is missing 1.4/2.2",
        ));
    }
    Ok(())
}

fn validate_live_codecs(rows: &[CodecCapability]) -> crate::Result<()> {
    let expected = approved_codec_keys();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let key = (row.codec.as_str(), row.width, row.height, row.framerate);
        let Some(expected_content_type) = expected.get(&key) else {
            return Err(crate::Error::state_corrupted(format!(
                "browser returned unexpected codec matrix key {} {}x{}@{}",
                row.codec, row.width, row.height, row.framerate
            )));
        };
        if row.content_type != *expected_content_type {
            return Err(crate::Error::state_corrupted(format!(
                "browser codec {} content_type mismatch",
                row.codec
            )));
        }
        if !seen.insert(key) {
            return Err(crate::Error::state_corrupted(
                "browser returned duplicate codec matrix key",
            ));
        }
    }
    if seen.len() != expected.len() {
        return Err(crate::Error::state_corrupted(
            "browser codec matrix is missing required codec × size pairs",
        ));
    }
    Ok(())
}

fn approved_robustness_keys() -> std::collections::BTreeSet<(MediaKind, RobustnessLevel)> {
    let levels = [
        RobustnessLevel::SoftwareSecureCrypto,
        RobustnessLevel::SoftwareSecureDecode,
        RobustnessLevel::HardwareSecureCrypto,
        RobustnessLevel::HardwareSecureDecode,
        RobustnessLevel::HardwareSecureAll,
    ];
    let mut keys = std::collections::BTreeSet::new();
    for kind in [MediaKind::Audio, MediaKind::Video] {
        for level in levels {
            keys.insert((kind, level));
        }
    }
    keys
}

fn approved_codec_keys() -> std::collections::BTreeMap<(&'static str, u32, u32, u32), &'static str>
{
    let codecs = [
        ("avc1.640028", "video/mp4; codecs=\"avc1.640028\""),
        ("hvc1.1.6.L120.B0", "video/mp4; codecs=\"hvc1.1.6.L120.B0\""),
        ("vp09.00.51.08", "video/webm; codecs=\"vp09.00.51.08\""),
        ("av01.0.08M.08", "video/mp4; codecs=\"av01.0.08M.08\""),
    ];
    let sizes = [
        (1280_u32, 720_u32, 30_u32),
        (1920, 1080, 30),
        (3840, 2160, 30),
    ];
    let mut keys = std::collections::BTreeMap::new();
    for (codec, content_type) in codecs {
        for (width, height, framerate) in sizes {
            keys.insert((codec, width, height, framerate), content_type);
        }
    }
    keys
}

fn reject_error_len(error: &str, field: &str) -> crate::Result<()> {
    if error.len() > MAX_ERROR_LEN {
        Err(crate::Error::state_corrupted(format!(
            "browser returned oversized {field}"
        )))
    } else {
        Ok(())
    }
}

fn is_approved_codec(codec: &str) -> bool {
    matches!(
        codec,
        "avc1.640028" | "hvc1.1.6.L120.B0" | "vp09.00.51.08" | "av01.0.08M.08" | "mp4a.40.2"
    )
}

fn is_approved_size(width: u32, height: u32, framerate: u32) -> bool {
    matches!(
        (width, height, framerate),
        (1280, 720, 30) | (1920, 1080, 30) | (3840, 2160, 30) | (0, 0, 0)
    )
}

/// Named acceptance profile used to interpret browser evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineProfile {
    /// Widevine access plus software robustness and one supported video codec.
    SoftwarePlayback,
}

/// Conservative interpretation of one browser probe document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityAssessment {
    /// Baseline applied to the result.
    pub baseline: BaselineProfile,
    /// Whether the named baseline was met.
    pub status: DiagnosticStatus,
    /// Product boundary responsible for the baseline outcome.
    pub domain: FailureDomain,
    /// Human-readable interpretation with claim boundaries.
    pub summary: String,
    /// Short findings derived from required and optional evidence.
    pub findings: Vec<String>,
    /// Next actions when the baseline did not pass or ownership is incomplete.
    pub actions: Vec<String>,
    /// Explicit service/policy limits that remain untested.
    pub service_limits: Vec<String>,
    /// Highest known accepted video robustness, if any.
    pub highest_video_robustness: Option<RobustnessLevel>,
    /// Highest known accepted audio robustness, if any.
    pub highest_audio_robustness: Option<RobustnessLevel>,
    /// Source-level capability checks.
    pub checks: Vec<DiagnosticCheck>,
}

impl CapabilityAssessment {
    /// First action, when any, for callers that still expect a single string.
    #[must_use]
    pub fn action(&self) -> Option<&str> {
        self.actions.first().map(String::as_str)
    }
}

/// Assess browser evidence against the software-playback baseline without
/// inferring L1, hardware protection, or streaming-service entitlement.
#[must_use]
pub fn assess(result: &RawProbeResult, ownership: &OwnershipAssessment) -> CapabilityAssessment {
    assess_with_baseline(result, ownership, BaselineProfile::SoftwarePlayback)
}

/// Assess browser evidence against a named baseline.
#[must_use]
pub fn assess_with_baseline(
    result: &RawProbeResult,
    ownership: &OwnershipAssessment,
    baseline: BaselineProfile,
) -> CapabilityAssessment {
    let highest_video_robustness = highest_robustness(result, MediaKind::Video);
    let highest_audio_robustness = highest_robustness(result, MediaKind::Audio);
    let has_sw_video = result.robustness.iter().any(|row| {
        row.media_kind == MediaKind::Video
            && row.accepted
            && matches!(
                RobustnessLevel::from_eme(&row.robustness),
                Some(RobustnessLevel::SoftwareSecureCrypto | RobustnessLevel::SoftwareSecureDecode)
            )
    });
    // Baseline codec evidence is MSE / canPlayType only. MediaCapabilities is
    // optional and never alone decides SoftwarePlayback failure.
    let has_video_codec = result.codecs.iter().any(|codec| {
        codec.width > 0 && (codec.mse_supported || codec.direct_playback.is_supported())
    });
    // Baseline-required: EME API, temporary key-system access, software
    // robustness, and at least one supported video codec configuration.
    let required_ok = result.eme_api
        && result.baseline == CapabilityStatus::Supported
        && has_sw_video
        && has_video_codec;

    let domain = select_domain(result, ownership, required_ok);
    let status = if required_ok {
        DiagnosticStatus::Pass
    } else if !result.eme_api || result.baseline == CapabilityStatus::Unavailable {
        DiagnosticStatus::Unavailable
    } else {
        DiagnosticStatus::Fail
    };

    let checks = build_checks(result, ownership, domain);
    let findings = build_findings(result, ownership, &checks);
    let actions = build_actions(status, ownership, domain);
    let service_limits = vec![
        "Streaming-service policy and entitlement were not tested.".into(),
        "Hardware robustness, HDCP policy, and powerEfficient are browser-reported evidence only."
            .into(),
        "No certified Widevine L1, protected GPU path, or UHD entitlement claim is made.".into(),
    ];
    let summary = match status {
        DiagnosticStatus::Pass => {
            "Software playback baseline passed using browser-reported EME capability evidence; this is not certified L1 or service entitlement.".into()
        }
        DiagnosticStatus::Unavailable => {
            "The browser EME API was unavailable, so no playback baseline can be claimed.".into()
        }
        DiagnosticStatus::Fail if domain == FailureDomain::Silvervine => {
            format!(
                "Software playback baseline failed because Silvervine-managed CDM state is incomplete: {}",
                ownership.summary
            )
        }
        DiagnosticStatus::Fail => {
            "The browser media stack rejected the software playback baseline despite local CDM evidence.".into()
        }
        DiagnosticStatus::Warn => {
            "Software playback baseline completed with warnings; service entitlement remains untested."
                .into()
        }
    };

    CapabilityAssessment {
        baseline,
        status,
        domain,
        summary,
        findings,
        actions,
        service_limits,
        highest_video_robustness,
        highest_audio_robustness,
        checks,
    }
}

fn select_domain(
    result: &RawProbeResult,
    ownership: &OwnershipAssessment,
    required_ok: bool,
) -> FailureDomain {
    if required_ok {
        return FailureDomain::BrowserMediaStack;
    }
    match ownership.kind {
        OwnershipKind::Missing | OwnershipKind::InvalidMarker | OwnershipKind::External => {
            // Missing or unverified Silvervine state owns the failure when the
            // browser cannot establish a baseline key system.
            if !result.eme_api || result.baseline != CapabilityStatus::Supported {
                FailureDomain::Silvervine
            } else {
                FailureDomain::BrowserMediaStack
            }
        }
        OwnershipKind::Managed | OwnershipKind::LegacyManaged => FailureDomain::BrowserMediaStack,
    }
}

fn highest_robustness(result: &RawProbeResult, media_kind: MediaKind) -> Option<RobustnessLevel> {
    result
        .robustness
        .iter()
        .filter(|probe| probe.media_kind == media_kind && probe.accepted)
        .filter_map(|probe| RobustnessLevel::from_eme(&probe.robustness))
        .max()
}

fn build_checks(
    result: &RawProbeResult,
    ownership: &OwnershipAssessment,
    baseline_domain: FailureDomain,
) -> Vec<DiagnosticCheck> {
    let mut checks = Vec::with_capacity(
        3 + result.robustness.len()
            + result.encryption_schemes.len()
            + result.codecs.len()
            + result.hdcp.len(),
    );
    checks.extend(build_baseline_checks(result, ownership, baseline_domain));
    checks.extend(build_robustness_checks(result));
    checks.extend(build_scheme_checks(result));
    checks.extend(build_codec_checks(result));
    checks.extend(build_hdcp_checks(result));
    checks
}

fn build_baseline_checks(
    result: &RawProbeResult,
    ownership: &OwnershipAssessment,
    baseline_domain: FailureDomain,
) -> [DiagnosticCheck; 3] {
    [
        DiagnosticCheck {
            id: "eme.api".into(),
            status: if result.eme_api {
                DiagnosticStatus::Pass
            } else {
                DiagnosticStatus::Unavailable
            },
            source: EvidenceSource::LiveBrowser,
            failure_domain: baseline_domain,
            summary: if result.eme_api {
                "navigator.requestMediaKeySystemAccess is present.".into()
            } else {
                "navigator.requestMediaKeySystemAccess is unavailable.".into()
            },
            action: None,
            details: BTreeMap::new(),
        },
        DiagnosticCheck {
            id: "eme.baseline".into(),
            status: status_for_required(result.baseline),
            source: EvidenceSource::LiveBrowser,
            failure_domain: baseline_domain,
            summary: format!(
                "Temporary Widevine key-system access: {}.",
                status_adjective(result.baseline)
            ),
            action: None,
            details: baseline_details(result),
        },
        DiagnosticCheck {
            id: "cdm.ownership".into(),
            status: match ownership.kind {
                OwnershipKind::Managed | OwnershipKind::LegacyManaged => DiagnosticStatus::Pass,
                OwnershipKind::Missing => DiagnosticStatus::Fail,
                OwnershipKind::External | OwnershipKind::InvalidMarker => DiagnosticStatus::Warn,
            },
            source: EvidenceSource::VerifiedFile,
            failure_domain: FailureDomain::Silvervine,
            summary: ownership.summary.clone(),
            action: ownership.action.clone(),
            details: ownership.details.clone(),
        },
    ]
}

fn build_robustness_checks(result: &RawProbeResult) -> Vec<DiagnosticCheck> {
    // Baseline needs any one SW video robustness. When at least one SW video
    // rung is accepted, other SW rejections are Warn — not Fail.
    let has_sw_video = result.robustness.iter().any(|row| {
        row.media_kind == MediaKind::Video
            && row.accepted
            && matches!(
                RobustnessLevel::from_eme(&row.robustness),
                Some(RobustnessLevel::SoftwareSecureCrypto | RobustnessLevel::SoftwareSecureDecode)
            )
    });
    result
        .robustness
        .iter()
        .enumerate()
        .map(|(index, probe)| {
            let level = RobustnessLevel::from_eme(&probe.robustness);
            let is_sw_video = matches!(
                level,
                Some(RobustnessLevel::SoftwareSecureCrypto | RobustnessLevel::SoftwareSecureDecode)
            ) && probe.media_kind == MediaKind::Video;
            let is_hardware = level.is_some_and(RobustnessLevel::is_hardware);
            let status = if probe.accepted {
                DiagnosticStatus::Pass
            } else if is_sw_video && !has_sw_video {
                DiagnosticStatus::Fail
            } else if is_hardware || is_sw_video || probe.error.is_some() {
                DiagnosticStatus::Warn
            } else {
                DiagnosticStatus::Unavailable
            };
            let mut details = BTreeMap::from([
                (
                    "media_kind".into(),
                    media_kind_name(probe.media_kind).into(),
                ),
                ("robustness".into(), probe.robustness.clone()),
                ("accepted".into(), probe.accepted.to_string()),
            ]);
            if let Some(error) = &probe.error {
                details.insert("error".into(), error.clone());
            }
            DiagnosticCheck {
                id: format!("eme.robustness.{index}"),
                status,
                source: EvidenceSource::LiveBrowser,
                failure_domain: FailureDomain::BrowserMediaStack,
                summary: format!(
                    "Browser {} robustness {}.",
                    if probe.accepted {
                        "accepted"
                    } else {
                        "did not accept"
                    },
                    probe.robustness
                ),
                action: None,
                details,
            }
        })
        .collect()
}

fn build_scheme_checks(result: &RawProbeResult) -> impl Iterator<Item = DiagnosticCheck> + '_ {
    result
        .encryption_schemes
        .iter()
        .enumerate()
        .map(|(index, scheme)| {
            let status = if scheme.accepted {
                DiagnosticStatus::Pass
            } else {
                DiagnosticStatus::Warn
            };
            let mut details = BTreeMap::from([
                ("scheme".into(), scheme.scheme.clone()),
                ("accepted".into(), scheme.accepted.to_string()),
            ]);
            if let Some(error) = &scheme.error {
                details.insert("error".into(), error.clone());
            }
            DiagnosticCheck {
                id: format!("eme.scheme.{index}"),
                status,
                source: EvidenceSource::LiveBrowser,
                failure_domain: FailureDomain::BrowserMediaStack,
                summary: format!(
                    "Encryption scheme {} was {}.",
                    scheme.scheme,
                    if scheme.accepted {
                        "accepted"
                    } else {
                        "not accepted"
                    }
                ),
                action: None,
                details,
            }
        })
}

fn build_codec_checks(result: &RawProbeResult) -> impl Iterator<Item = DiagnosticCheck> + '_ {
    result.codecs.iter().enumerate().map(|(index, codec)| {
        let supported = codec
            .media_capabilities
            .as_ref()
            .is_some_and(|facts| facts.supported)
            || codec.mse_supported
            || codec.direct_playback.is_supported();
        // Only the first successful software path is baseline-required; individual
        // codec/size rows remain optional evidence.
        let status = if supported {
            DiagnosticStatus::Pass
        } else if codec.error.is_some() {
            DiagnosticStatus::Warn
        } else {
            DiagnosticStatus::Unavailable
        };
        let mut details = BTreeMap::from([
            ("codec".into(), codec.codec.clone()),
            ("content_type".into(), codec.content_type.clone()),
            ("width".into(), codec.width.to_string()),
            ("height".into(), codec.height.to_string()),
            ("framerate".into(), codec.framerate.to_string()),
            ("mse_supported".into(), codec.mse_supported.to_string()),
            (
                "direct_playback".into(),
                codec.direct_playback.as_str().into(),
            ),
        ]);
        if let Some(facts) = &codec.media_capabilities {
            details.insert("mc_supported".into(), facts.supported.to_string());
            if let Some(smooth) = facts.smooth {
                details.insert("smooth".into(), smooth.to_string());
            }
            if let Some(power_efficient) = facts.power_efficient {
                details.insert("power_efficient".into(), power_efficient.to_string());
            }
            if let Some(key_system_access) = facts.key_system_access {
                details.insert("key_system_access".into(), key_system_access.to_string());
            }
        }
        if let Some(error) = &codec.error {
            details.insert("error".into(), error.clone());
        }
        DiagnosticCheck {
            id: format!("eme.codec.{index}"),
            status,
            source: EvidenceSource::LiveBrowser,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: format!(
                "Codec {} at {}x{} is {}.",
                codec.codec,
                codec.width,
                codec.height,
                if supported {
                    "supported"
                } else {
                    "not supported"
                }
            ),
            action: None,
            details,
        }
    })
}

fn build_hdcp_checks(result: &RawProbeResult) -> impl Iterator<Item = DiagnosticCheck> + '_ {
    result.hdcp.iter().map(|hdcp| {
        let usable = hdcp.status.as_deref() == Some("usable");
        let status = if usable {
            DiagnosticStatus::Pass
        } else if hdcp.error.is_some() || hdcp.status.is_some() {
            DiagnosticStatus::Warn
        } else {
            DiagnosticStatus::Unavailable
        };
        let mut details = BTreeMap::from([("min_version".into(), hdcp.min_version.clone())]);
        if let Some(policy_status) = &hdcp.status {
            details.insert("status".into(), policy_status.clone());
        }
        if let Some(error) = &hdcp.error {
            details.insert("error".into(), error.clone());
        }
        DiagnosticCheck {
            id: format!("eme.hdcp.{}", hdcp.min_version.replace('.', "_")),
            status,
            source: EvidenceSource::LiveBrowser,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: format!(
                "The browser reported HDCP {} policy as {}; this is not service entitlement.",
                hdcp.min_version,
                hdcp.status.as_deref().unwrap_or("unavailable")
            ),
            action: None,
            details,
        }
    })
}

fn baseline_details(result: &RawProbeResult) -> BTreeMap<String, String> {
    let mut details = BTreeMap::from([
        ("eme_api".into(), result.eme_api.to_string()),
        (
            "media_capabilities_api".into(),
            result.media_capabilities_api.to_string(),
        ),
    ]);
    if let Some(error) = &result.baseline_error {
        details.insert("error".into(), error.clone());
    }
    details
}

fn build_findings(
    result: &RawProbeResult,
    ownership: &OwnershipAssessment,
    checks: &[DiagnosticCheck],
) -> Vec<String> {
    let mut findings = vec![ownership.summary.clone()];
    findings.push(format!(
        "Widevine temporary key-system access: {}.",
        status_adjective(result.baseline)
    ));
    if let Some(level) = highest_robustness(result, MediaKind::Video) {
        findings.push(format!(
            "Highest accepted video robustness: {}.",
            level.as_eme()
        ));
    } else {
        findings.push("No accepted video robustness level was reported.".into());
    }
    let supported_codecs = result
        .codecs
        .iter()
        .filter(|codec| {
            codec.mse_supported
                || codec.direct_playback.is_supported()
                || codec
                    .media_capabilities
                    .as_ref()
                    .is_some_and(|facts| facts.supported)
        })
        .map(|codec| codec.codec.as_str())
        .collect::<Vec<_>>();
    if supported_codecs.is_empty() {
        findings.push("No approved video codec configuration was supported.".into());
    } else {
        findings.push(format!(
            "Supported codec evidence includes {}.",
            supported_codecs.join(", ")
        ));
    }
    for check in checks
        .iter()
        .filter(|check| {
            matches!(
                check.status,
                DiagnosticStatus::Fail | DiagnosticStatus::Warn
            )
        })
        .take(6)
    {
        findings.push(check.summary.clone());
    }
    findings
}

fn build_actions(
    status: DiagnosticStatus,
    ownership: &OwnershipAssessment,
    domain: FailureDomain,
) -> Vec<String> {
    let mut actions = Vec::new();
    if let Some(action) = &ownership.action {
        actions.push(action.clone());
    }
    if status != DiagnosticStatus::Pass {
        match domain {
            FailureDomain::Silvervine => actions.push(
                "Install or repair the Silvervine-managed CDM with `silvervine patch`, then rerun `silvervine test`."
                    .into(),
            ),
            FailureDomain::BrowserMediaStack => actions.push(
                "Verify the browser opens with its normal profile and readable CDM, then run `silvervine test` again."
                    .into(),
            ),
            FailureDomain::StreamingService => actions.push(
                "Streaming-service policy was not tested; retry after confirming local playback baseline."
                    .into(),
            ),
        }
    }
    actions
}

fn status_for_required(status: CapabilityStatus) -> DiagnosticStatus {
    match status {
        CapabilityStatus::Supported => DiagnosticStatus::Pass,
        CapabilityStatus::Rejected | CapabilityStatus::Error => DiagnosticStatus::Fail,
        CapabilityStatus::Unavailable => DiagnosticStatus::Unavailable,
    }
}

fn status_adjective(status: CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Supported => "supported",
        CapabilityStatus::Rejected => "rejected",
        CapabilityStatus::Unavailable => "unavailable",
        CapabilityStatus::Error => "error",
    }
}

fn media_kind_name(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Audio => "audio",
        MediaKind::Video => "video",
    }
}

/// Ownership fixture used by unit tests when no CDM classification is needed.
#[cfg(test)]
pub(crate) fn managed_ownership() -> OwnershipAssessment {
    OwnershipAssessment {
        kind: OwnershipKind::Managed,
        summary: "The installed CDM has valid Silvervine provenance.".into(),
        action: None,
        details: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostics::DiagnosticStatus;

    fn full_matrix_result() -> RawProbeResult {
        let mut robustness = Vec::new();
        for media_kind in [MediaKind::Audio, MediaKind::Video] {
            for level in [
                "SW_SECURE_CRYPTO",
                "SW_SECURE_DECODE",
                "HW_SECURE_CRYPTO",
                "HW_SECURE_DECODE",
                "HW_SECURE_ALL",
            ] {
                robustness.push(RobustnessResult {
                    media_kind,
                    robustness: level.into(),
                    accepted: matches!(level, "SW_SECURE_CRYPTO" | "SW_SECURE_DECODE")
                        && media_kind == MediaKind::Video
                        || matches!(level, "SW_SECURE_CRYPTO") && media_kind == MediaKind::Audio,
                    error: None,
                });
            }
        }
        let encryption_schemes = vec![
            EncryptionSchemeResult {
                scheme: "cenc".into(),
                accepted: true,
                error: None,
            },
            EncryptionSchemeResult {
                scheme: "cbcs".into(),
                accepted: true,
                error: None,
            },
        ];
        let hdcp = vec![
            HdcpResult {
                min_version: "1.4".into(),
                status: Some("usable".into()),
                error: None,
            },
            HdcpResult {
                min_version: "2.2".into(),
                status: Some("output-restricted".into()),
                error: None,
            },
        ];
        let mut codecs = Vec::new();
        for codec in [
            ("avc1.640028", "video/mp4; codecs=\"avc1.640028\""),
            ("hvc1.1.6.L120.B0", "video/mp4; codecs=\"hvc1.1.6.L120.B0\""),
            ("vp09.00.51.08", "video/webm; codecs=\"vp09.00.51.08\""),
            ("av01.0.08M.08", "video/mp4; codecs=\"av01.0.08M.08\""),
        ] {
            for (width, height, framerate) in [
                (1280_u32, 720_u32, 30_u32),
                (1920, 1080, 30),
                (3840, 2160, 30),
            ] {
                codecs.push(CodecCapability {
                    codec: codec.0.into(),
                    content_type: codec.1.into(),
                    width,
                    height,
                    framerate,
                    mse_supported: codec.0 == "avc1.640028" && width <= 1920,
                    direct_playback: if codec.0 == "avc1.640028" {
                        CanPlayStatus::Probably
                    } else {
                        CanPlayStatus::Unsupported
                    },
                    media_capabilities: Some(MediaCapabilitiesFacts {
                        supported: codec.0 == "avc1.640028" && width <= 1920,
                        smooth: Some(true),
                        power_efficient: Some(false),
                        key_system_access: Some(true),
                    }),
                    error: None,
                });
            }
        }
        RawProbeResult {
            schema_version: PROBE_SCHEMA_VERSION,
            user_agent: "Chromium/150".into(),
            eme_api: true,
            media_capabilities_api: true,
            baseline: CapabilityStatus::Supported,
            baseline_error: None,
            robustness,
            encryption_schemes,
            hdcp,
            codecs,
        }
    }

    fn baseline_result() -> RawProbeResult {
        full_matrix_result()
    }

    #[test]
    fn probe_schema_round_trips_without_forbidden_fields() {
        let result = baseline_result();
        let value = serde_json::to_value(&result).expect("serialize");
        let decoded: RawProbeResult = serde_json::from_value(value.clone()).expect("decode");

        assert_eq!(decoded, result);
        assert!(value.get("persistent_license").is_none());
        assert!(value.get("distinctive_identifier").is_none());
        assert_eq!(value["baseline"], "supported");
        assert_eq!(value["encryption_schemes"][0]["scheme"], "cenc");
    }

    #[test]
    fn validate_rejects_unknown_fields_and_forbidden_hdcp() {
        let err = serde_json::from_str::<RawProbeResult>(
            r#"{"schema_version":1,"user_agent":"x","eme_api":true,"media_capabilities_api":true,"baseline":"supported","robustness":[],"encryption_schemes":[],"hdcp":[{"min_version":"2.3"}],"codecs":[],"persistent_license":"supported"}"#,
        )
        .expect_err("unknown field");
        assert!(
            err.to_string().contains("unknown field") || err.to_string().contains("persistent")
        );

        let mut bad = baseline_result();
        bad.hdcp[0].min_version = "2.3".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn software_baseline_passes_without_claiming_service_or_l1_support() {
        let assessment = assess(&baseline_result(), &managed_ownership());

        assert_eq!(assessment.status, DiagnosticStatus::Pass);
        assert_eq!(
            assessment.highest_video_robustness,
            Some(RobustnessLevel::SoftwareSecureDecode)
        );
        assert!(assessment.summary.contains("browser-reported"));
        assert!(assessment.summary.contains("not certified L1"));
        assert!(assessment
            .service_limits
            .iter()
            .any(|limit| limit.contains("not tested")));
    }

    #[test]
    fn optional_hardware_and_hdcp_rejections_are_warnings() {
        let assessment = assess(&baseline_result(), &managed_ownership());
        let hw = assessment
            .checks
            .iter()
            .find(|check| check.summary.contains("HW_SECURE_ALL"))
            .expect("hw row");
        let hdcp22 = assessment
            .checks
            .iter()
            .find(|check| check.id == "eme.hdcp.2_2")
            .expect("hdcp 2.2");

        assert_eq!(hw.status, DiagnosticStatus::Warn);
        assert_eq!(hdcp22.status, DiagnosticStatus::Warn);
        assert_eq!(assessment.status, DiagnosticStatus::Pass);
    }

    #[test]
    fn rejected_baseline_with_managed_cdm_is_browser_domain() {
        let mut result = baseline_result();
        result.baseline = CapabilityStatus::Rejected;
        let assessment = assess(&result, &managed_ownership());

        assert_eq!(assessment.status, DiagnosticStatus::Fail);
        assert_eq!(assessment.domain, FailureDomain::BrowserMediaStack);
        assert!(assessment
            .actions
            .iter()
            .any(|action| action.contains("normal profile")));
    }

    #[test]
    fn missing_cdm_owns_failed_baseline() {
        let mut result = baseline_result();
        result.baseline = CapabilityStatus::Rejected;
        let ownership = OwnershipAssessment {
            kind: OwnershipKind::Missing,
            summary: "No Widevine CDM is installed at the patch target.".into(),
            action: Some("Run `silvervine patch`.".into()),
            details: BTreeMap::new(),
        };

        let assessment = assess(&result, &ownership);
        assert_eq!(assessment.status, DiagnosticStatus::Fail);
        assert_eq!(assessment.domain, FailureDomain::Silvervine);
        assert!(assessment
            .actions
            .iter()
            .any(|action| action.contains("silvervine patch")));
    }

    #[test]
    fn assessment_roundtrip_identity_is_stable() {
        let result = baseline_result();
        let ownership = managed_ownership();
        let first = assess(&result, &ownership);
        let second = assess(&result, &ownership);
        assert_eq!(first, second);

        let encoded = serde_json::to_value(&first).expect("json");
        let decoded: CapabilityAssessment = serde_json::from_value(encoded).expect("decode");
        assert_eq!(decoded, first);
    }

    #[test]
    fn hdcp_policy_success_is_reported_only_as_browser_evidence() {
        let assessment = assess(&baseline_result(), &managed_ownership());
        let hdcp = assessment
            .checks
            .iter()
            .find(|check| check.id == "eme.hdcp.1_4")
            .expect("HDCP check");

        assert_eq!(hdcp.status, DiagnosticStatus::Pass);
        assert!(hdcp.summary.contains("browser reported"));
        assert!(hdcp.summary.contains("not service entitlement"));
    }

    #[test]
    fn software_baseline_passes_without_media_capabilities() {
        let mut result = baseline_result();
        result.media_capabilities_api = false;
        for codec in &mut result.codecs {
            codec.media_capabilities = None;
            codec.mse_supported = true;
            codec.direct_playback = CanPlayStatus::Probably;
        }
        let assessment = assess(&result, &managed_ownership());
        assert_eq!(assessment.status, DiagnosticStatus::Pass);
    }

    #[test]
    fn software_baseline_requires_affirmative_codec_support() {
        let mut result = baseline_result();
        for codec in &mut result.codecs {
            codec.mse_supported = false;
            codec.direct_playback = CanPlayStatus::Maybe;
            codec.media_capabilities = Some(MediaCapabilitiesFacts {
                supported: true,
                smooth: Some(true),
                power_efficient: Some(true),
                key_system_access: Some(true),
            });
        }

        let assessment = assess(&result, &managed_ownership());
        assert_eq!(assessment.status, DiagnosticStatus::Fail);
        assert_eq!(assessment.domain, FailureDomain::BrowserMediaStack);
    }

    #[test]
    fn software_baseline_passes_on_mse_even_if_mc_rejects() {
        let mut result = baseline_result();
        for codec in &mut result.codecs {
            codec.mse_supported = true;
            codec.direct_playback = CanPlayStatus::Maybe;
            codec.media_capabilities = Some(MediaCapabilitiesFacts {
                supported: false,
                smooth: Some(false),
                power_efficient: Some(false),
                key_system_access: Some(false),
            });
        }
        let assessment = assess(&result, &managed_ownership());
        assert_eq!(assessment.status, DiagnosticStatus::Pass);
    }

    #[test]
    fn one_sw_video_robustness_keeps_other_sw_as_warn() {
        let mut result = baseline_result();
        result.robustness = vec![
            RobustnessResult {
                media_kind: MediaKind::Video,
                robustness: "SW_SECURE_CRYPTO".into(),
                accepted: true,
                error: None,
            },
            RobustnessResult {
                media_kind: MediaKind::Video,
                robustness: "SW_SECURE_DECODE".into(),
                accepted: false,
                error: Some("NotSupportedError".into()),
            },
        ];
        let assessment = assess(&result, &managed_ownership());
        assert_eq!(assessment.status, DiagnosticStatus::Pass);
        let decode = assessment
            .checks
            .iter()
            .find(|c| c.summary.contains("SW_SECURE_DECODE"))
            .expect("decode row");
        assert_eq!(decode.status, DiagnosticStatus::Warn);
    }

    #[test]
    fn exact_approved_matrix_shape() {
        let result = full_matrix_result();
        result
            .validate_live_matrix()
            .expect("full matrix validates");
        assert_eq!(result.robustness.len(), EXPECTED_ROBUSTNESS_ROWS);
        assert_eq!(result.encryption_schemes.len(), EXPECTED_SCHEME_ROWS);
        assert_eq!(result.hdcp.len(), EXPECTED_HDCP_ROWS);
        assert_eq!(result.codecs.len(), EXPECTED_CODEC_ROWS);

        let levels: Vec<_> = result
            .robustness
            .iter()
            .map(|row| (row.media_kind, row.robustness.as_str()))
            .collect();
        for kind in [MediaKind::Audio, MediaKind::Video] {
            for level in [
                "SW_SECURE_CRYPTO",
                "SW_SECURE_DECODE",
                "HW_SECURE_CRYPTO",
                "HW_SECURE_DECODE",
                "HW_SECURE_ALL",
            ] {
                assert!(levels.contains(&(kind, level)), "missing {kind:?} {level}");
            }
        }
        let schemes: Vec<_> = result
            .encryption_schemes
            .iter()
            .map(|row| row.scheme.as_str())
            .collect();
        assert_eq!(schemes, ["cenc", "cbcs"]);
        let hdcp: Vec<_> = result
            .hdcp
            .iter()
            .map(|row| row.min_version.as_str())
            .collect();
        assert_eq!(hdcp, ["1.4", "2.2"]);
        let codec_keys: Vec<_> = result
            .codecs
            .iter()
            .map(|row| (row.codec.as_str(), row.width, row.height, row.framerate))
            .collect();
        for codec in [
            "avc1.640028",
            "hvc1.1.6.L120.B0",
            "vp09.00.51.08",
            "av01.0.08M.08",
        ] {
            for (w, h, f) in [
                (1280_u32, 720_u32, 30_u32),
                (1920, 1080, 30),
                (3840, 2160, 30),
            ] {
                assert!(
                    codec_keys.contains(&(codec, w, h, f)),
                    "missing codec row {codec} {w}x{h}@{f}"
                );
            }
        }
    }

    #[test]
    fn incomplete_matrix_is_rejected() {
        let mut result = full_matrix_result();
        result.codecs.pop();
        assert!(
            result.validate().is_ok(),
            "partial docs remain schema-valid for cache"
        );
        assert!(result.validate_live_matrix().is_err());
    }

    #[test]
    fn duplicate_matrix_keys_are_rejected() {
        let mut result = full_matrix_result();
        // Keep length 10 but duplicate SW/video by overwriting audio SW_CRYPTO with video SW_CRYPTO.
        result.robustness[0] = RobustnessResult {
            media_kind: MediaKind::Video,
            robustness: "SW_SECURE_CRYPTO".into(),
            accepted: true,
            error: None,
        };
        assert!(result.validate_live_matrix().is_err());

        let mut result = full_matrix_result();
        result.encryption_schemes[1].scheme = "cenc".into();
        assert!(result.validate_live_matrix().is_err());

        let mut result = full_matrix_result();
        result.hdcp[1].min_version = "1.4".into();
        assert!(result.validate_live_matrix().is_err());

        let mut result = full_matrix_result();
        // Duplicate AVC 720p over HEVC 720p slot while keeping length 12.
        result.codecs[3] = result.codecs[0].clone();
        assert!(result.validate_live_matrix().is_err());
    }

    #[test]
    fn missing_matrix_combo_is_rejected() {
        let mut result = full_matrix_result();
        // Drop AV1@4K by turning that unique row into a duplicate AVC@720 entry.
        let avc720 = result.codecs[0].clone();
        result.codecs[11] = avc720;
        assert!(result.validate_live_matrix().is_err());
    }
}
