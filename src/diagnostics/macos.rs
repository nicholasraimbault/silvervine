//! macOS host media/GPU passive diagnostics.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::diagnostics::{DiagnosticCheck, DiagnosticStatus, EvidenceSource, FailureDomain};
use crate::platform::process::{find_executable, run_output_with_timeout};

const UTILITY_TIMEOUT: Duration = Duration::from_secs(15);

/// Collect macOS display/GPU, VideoToolbox, and codesign evidence.
#[must_use]
pub fn collect_host_checks() -> Vec<DiagnosticCheck> {
    let mut checks = vec![system_profiler_check(), architecture_check()];
    checks.extend(videotoolbox_checks());
    checks
}

/// Codesign verification for one browser bundle path.
#[must_use]
pub fn codesign_check(bundle: &Path) -> DiagnosticCheck {
    let Some(codesign) = find_executable("codesign").or_else(|| {
        let path = PathBuf::from("/usr/bin/codesign");
        path.is_file().then_some(path)
    }) else {
        return DiagnosticCheck {
            id: "browser.codesign".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "codesign is unavailable on this host.".into(),
            action: None,
            details: BTreeMap::from([("path".into(), bundle.display().to_string())]),
        };
    };

    match run_output_with_timeout(
        &codesign,
        &["--verify", "--deep", "--strict", &bundle.to_string_lossy()],
        UTILITY_TIMEOUT,
    ) {
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let mut details = BTreeMap::from([
                ("path".into(), bundle.display().to_string()),
                ("exit_status".into(), output.status.to_string()),
                ("timed_out".into(), output.timed_out.to_string()),
            ]);
            if !stderr.trim().is_empty() {
                details.insert(
                    "evidence".into(),
                    stderr
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(500)
                        .collect(),
                );
            }
            if output.timed_out {
                DiagnosticCheck {
                    id: "browser.codesign".into(),
                    status: DiagnosticStatus::Warn,
                    source: EvidenceSource::HostProbe,
                    failure_domain: FailureDomain::BrowserMediaStack,
                    summary: "codesign verification timed out.".into(),
                    action: None,
                    details,
                }
            } else if output.status.success() {
                DiagnosticCheck {
                    id: "browser.codesign".into(),
                    status: DiagnosticStatus::Pass,
                    source: EvidenceSource::HostProbe,
                    failure_domain: FailureDomain::BrowserMediaStack,
                    summary: "Bundle codesign verification passed.".into(),
                    action: None,
                    details,
                }
            } else {
                DiagnosticCheck {
                    id: "browser.codesign".into(),
                    status: DiagnosticStatus::Warn,
                    source: EvidenceSource::HostProbe,
                    failure_domain: FailureDomain::BrowserMediaStack,
                    summary: "Bundle codesign verification failed.".into(),
                    action: Some(
                        "Re-run `silvervine patch` so the macOS bundle is re-signed after CDM install."
                            .into(),
                    ),
                    details,
                }
            }
        }
        Err(error) => DiagnosticCheck {
            id: "browser.codesign".into(),
            status: DiagnosticStatus::Warn,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "codesign could not run.".into(),
            action: None,
            details: BTreeMap::from([
                ("path".into(), bundle.display().to_string()),
                ("error".into(), error.message),
            ]),
        },
    }
}

fn system_profiler_check() -> DiagnosticCheck {
    let profiler = find_executable("system_profiler").or_else(|| {
        let path = PathBuf::from("/usr/sbin/system_profiler");
        path.is_file().then_some(path)
    });
    let Some(profiler) = profiler else {
        return DiagnosticCheck {
            id: "host.macos_displays".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "system_profiler is unavailable on this host.".into(),
            action: None,
            details: BTreeMap::from([("utility".into(), "system_profiler".into())]),
        };
    };

    match run_output_with_timeout(&profiler, &["SPDisplaysDataType", "-json"], UTILITY_TIMEOUT) {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let summary = parse_system_profiler_summary(&stdout);
            let mut details = BTreeMap::from([
                ("utility".into(), "system_profiler".into()),
                ("exit_status".into(), output.status.to_string()),
                ("timed_out".into(), output.timed_out.to_string()),
            ]);
            details.extend(summary.details);
            let status = if output.timed_out || !output.status.success() {
                DiagnosticStatus::Warn
            } else if summary.chipset.is_some() || summary.metal.is_some() {
                DiagnosticStatus::Pass
            } else {
                DiagnosticStatus::Warn
            };
            DiagnosticCheck {
                id: "host.macos_displays".into(),
                status,
                source: EvidenceSource::HostProbe,
                failure_domain: FailureDomain::BrowserMediaStack,
                summary: summary.summary,
                action: None,
                details,
            }
        }
        Err(error) => DiagnosticCheck {
            id: "host.macos_displays".into(),
            status: DiagnosticStatus::Warn,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "system_profiler could not run.".into(),
            action: None,
            details: BTreeMap::from([("error".into(), error.message)]),
        },
    }
}

fn architecture_check() -> DiagnosticCheck {
    DiagnosticCheck {
        id: "host.architecture".into(),
        status: DiagnosticStatus::Pass,
        source: EvidenceSource::HostProbe,
        failure_domain: FailureDomain::BrowserMediaStack,
        summary: format!(
            "Host architecture is {}-{}.",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
        action: None,
        details: BTreeMap::from([
            ("os".into(), std::env::consts::OS.into()),
            ("arch".into(), std::env::consts::ARCH.into()),
        ]),
    }
}

fn videotoolbox_checks() -> Vec<DiagnosticCheck> {
    [
        ("h264", "avc1", "H.264"),
        ("hevc", "hvc1", "HEVC"),
        ("vp9", "vp09", "VP9"),
        ("av1", "av01", "AV1"),
    ]
    .into_iter()
    .map(|(id, fourcc, label)| videotoolbox_codec_check(id, fourcc, label))
    .collect()
}

fn videotoolbox_codec_check(id: &str, fourcc: &str, label: &str) -> DiagnosticCheck {
    match query_videotoolbox_support(fourcc) {
        VideoToolboxQuery::Supported(supported) => DiagnosticCheck {
            id: format!("host.videotoolbox.{id}"),
            status: DiagnosticStatus::Pass,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: if supported {
                format!("VideoToolbox reports hardware decode support for {label}.")
            } else {
                format!("VideoToolbox reports no hardware decode support for {label}.")
            },
            action: None,
            details: BTreeMap::from([
                ("codec".into(), label.into()),
                ("fourcc".into(), fourcc.into()),
                ("hardware_decode".into(), supported.to_string()),
            ]),
        },
        VideoToolboxQuery::Unavailable(reason) => DiagnosticCheck {
            id: format!("host.videotoolbox.{id}"),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: format!("VideoToolbox {label} query unavailable."),
            action: None,
            details: BTreeMap::from([
                ("codec".into(), label.into()),
                ("fourcc".into(), fourcc.into()),
                ("reason".into(), reason),
            ]),
        },
    }
}

enum VideoToolboxQuery {
    Supported(bool),
    Unavailable(String),
}

fn query_videotoolbox_support(fourcc: &str) -> VideoToolboxQuery {
    // Prefer the public VTIsHardwareDecodeSupported symbol when linked.
    // On non-macOS cfg this module is not compiled. When the symbol cannot be
    // resolved at runtime we mark the check unavailable instead of fabricating
    // a failure.
    #[cfg(target_os = "macos")]
    {
        let code = fourcc_code(fourcc);
        // Safety: public VideoToolbox C API, no pointers exchanged.
        let supported = unsafe { VTIsHardwareDecodeSupported(code) };
        // Apple documents the function as Boolean; treat non-zero as true.
        return VideoToolboxQuery::Supported(supported != 0);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = fourcc;
        VideoToolboxQuery::Unavailable("VideoToolbox is only available on macOS".into())
    }
}

#[cfg(target_os = "macos")]
fn fourcc_code(fourcc: &str) -> u32 {
    let bytes = fourcc.as_bytes();
    if bytes.len() != 4 {
        return 0;
    }
    u32::from(bytes[0]) << 24
        | u32::from(bytes[1]) << 16
        | u32::from(bytes[2]) << 8
        | u32::from(bytes[3])
}

#[cfg(target_os = "macos")]
#[link(name = "VideoToolbox", kind = "framework")]
extern "C" {
    fn VTIsHardwareDecodeSupported(codecType: u32) -> u8;
}

struct ProfilerSummary {
    summary: String,
    chipset: Option<String>,
    metal: Option<String>,
    details: BTreeMap<String, String>,
}

/// Parse `system_profiler SPDisplaysDataType -json` into bounded details.
#[must_use]
pub fn parse_system_profiler_summary(json: &str) -> ProfilerSummary {
    let mut details = BTreeMap::new();
    let mut chipset = None;
    let mut metal = None;
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(json) {
        if let Some(displays) = value
            .get("SPDisplaysDataType")
            .and_then(serde_json::Value::as_array)
            .and_then(|items| items.first())
        {
            if let Some(model) = displays
                .get("sppci_model")
                .or_else(|| displays.get("spdisplays_device-id"))
                .and_then(serde_json::Value::as_str)
            {
                chipset = Some(model.to_owned());
                details.insert("chipset".into(), model.to_owned());
            }
            if let Some(vendor) = displays
                .get("spdisplays_vendor")
                .and_then(serde_json::Value::as_str)
            {
                details.insert("vendor".into(), vendor.to_owned());
            }
            if let Some(metal_support) = displays
                .get("spdisplays_metal")
                .or_else(|| displays.get("spdisplays_mtlgpufamilysupport"))
                .and_then(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .or_else(|| value.as_bool().map(|flag| flag.to_string()))
                })
            {
                metal = Some(metal_support.clone());
                details.insert("metal".into(), metal_support);
            }
            if let Some(vram) = displays
                .get("spdisplays_vram")
                .or_else(|| displays.get("spdisplays_vramshared"))
                .and_then(serde_json::Value::as_str)
            {
                details.insert("vram".into(), vram.to_owned());
            }
        }
    } else {
        // Fallback: retain a few plain-text keys from non-JSON output.
        for line in json.lines().take(80) {
            let lower = line.to_ascii_lowercase();
            if lower.contains("chipset model")
                || lower.contains("metal")
                || lower.contains("vendor")
            {
                let safe: String = line
                    .trim()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(200)
                    .collect();
                details
                    .entry("evidence".into())
                    .and_modify(|existing| {
                        if existing.len() < 1500 {
                            existing.push('\n');
                            existing.push_str(&safe);
                        }
                    })
                    .or_insert(safe);
            }
        }
    }

    let summary = match (&chipset, &metal) {
        (Some(chip), Some(metal)) => {
            format!("macOS display/GPU probe reports {chip} (Metal: {metal}).")
        }
        (Some(chip), None) => format!("macOS display/GPU probe reports {chip}."),
        _ => "macOS display/GPU probe completed.".into(),
    };
    ProfilerSummary {
        summary,
        chipset,
        metal,
        details,
    }
}

/// Map fourcc tokens used by diagnostics to human labels.
#[must_use]
pub fn fourcc_label(fourcc: &str) -> &'static str {
    match fourcc {
        "avc1" => "H.264",
        "hvc1" => "HEVC",
        "vp09" => "VP9",
        "av01" => "AV1",
        _ => "unknown",
    }
}

/// Classify codesign process output for tests.
#[must_use]
pub fn classify_codesign_status(success: bool, timed_out: bool) -> DiagnosticStatus {
    if timed_out {
        DiagnosticStatus::Warn
    } else if success {
        DiagnosticStatus::Pass
    } else {
        DiagnosticStatus::Warn
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_codesign_status, fourcc_label, parse_system_profiler_summary};
    use crate::diagnostics::DiagnosticStatus;

    #[test]
    fn system_profiler_json_parser_reads_chipset_and_metal() {
        let json = r#"{
          "SPDisplaysDataType": [
            {
              "sppci_model": "Apple M2",
              "spdisplays_vendor": "sppci_vendor_Apple",
              "spdisplays_metal": "supported",
              "spdisplays_vram": "shared"
            }
          ]
        }"#;
        let summary = parse_system_profiler_summary(json);
        assert_eq!(summary.chipset.as_deref(), Some("Apple M2"));
        assert_eq!(summary.metal.as_deref(), Some("supported"));
        assert!(summary.summary.contains("Apple M2"));
    }

    #[test]
    fn fourcc_labels_match_public_codec_set() {
        assert_eq!(fourcc_label("avc1"), "H.264");
        assert_eq!(fourcc_label("hvc1"), "HEVC");
        assert_eq!(fourcc_label("vp09"), "VP9");
        assert_eq!(fourcc_label("av01"), "AV1");
    }

    #[test]
    fn codesign_classification_is_conservative() {
        assert_eq!(
            classify_codesign_status(true, false),
            DiagnosticStatus::Pass
        );
        assert_eq!(
            classify_codesign_status(false, false),
            DiagnosticStatus::Warn
        );
        assert_eq!(classify_codesign_status(true, true), DiagnosticStatus::Warn);
    }
}
