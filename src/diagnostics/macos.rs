//! macOS host media/GPU passive diagnostics.

use std::collections::BTreeMap;
use std::path::Path;
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

/// Verify the vendor-signed browser bundle and, when managed, the signed
/// Widevine library in the user profile.
#[must_use]
pub fn codesign_check(bundle: &Path, cdm_library: Option<&Path>, managed: bool) -> DiagnosticCheck {
    let paths = CodesignPaths {
        bundle,
        cdm_library,
    };
    if let Some(check) = missing_managed_codesign_paths(paths, managed) {
        return check;
    }
    let Some(codesign) =
        find_executable("/usr/bin/codesign").or_else(|| find_executable("codesign"))
    else {
        return DiagnosticCheck {
            id: "browser.codesign".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "codesign is unavailable on this host.".into(),
            action: None,
            details: BTreeMap::from([("bundle_path".into(), bundle.display().to_string())]),
        };
    };
    run_codesign_check(&codesign, paths, managed)
}

#[derive(Clone, Copy)]
struct CodesignPaths<'a> {
    bundle: &'a Path,
    cdm_library: Option<&'a Path>,
}

impl<'a> CodesignPaths<'a> {
    fn scopes(self, managed: bool) -> [Option<(&'static str, &'a Path)>; 2] {
        [
            Some(("bundle", self.bundle)),
            managed
                .then_some(self.cdm_library)
                .flatten()
                .map(|path| ("cdm_library", path)),
        ]
    }
}

fn missing_managed_codesign_paths(
    paths: CodesignPaths<'_>,
    managed: bool,
) -> Option<DiagnosticCheck> {
    if !managed || paths.cdm_library.is_some() {
        return None;
    }
    Some(DiagnosticCheck {
        id: "browser.codesign".into(),
        status: DiagnosticStatus::Fail,
        source: EvidenceSource::HostProbe,
        failure_domain: FailureDomain::Silvervine,
        summary: "The Silvervine-managed Widevine library could not be resolved for codesign verification."
            .into(),
        action: Some("Run `silvervine repair` to restore the managed macOS CDM layout.".into()),
        details: BTreeMap::from([
            ("bundle_path".into(), paths.bundle.display().to_string()),
            ("missing_managed_scopes".into(), "cdm_library".into()),
        ]),
    })
}

fn classify_codesign_result(
    bundle: [bool; 3],
    silvervine: [bool; 3],
    managed: bool,
) -> (
    DiagnosticStatus,
    FailureDomain,
    &'static str,
    Option<String>,
) {
    let [bundle_invalid, bundle_incomplete, bundle_timed_out] = bundle;
    let [managed_invalid, managed_incomplete, managed_timed_out] = silvervine;
    if managed_invalid {
        (
            DiagnosticStatus::Fail,
            FailureDomain::Silvervine,
            "Codesign verification failed for the Silvervine-managed Widevine library.",
            Some("Re-run `silvervine patch` to reinstall the verified Widevine component.".into()),
        )
    } else if managed_incomplete {
        (
            DiagnosticStatus::Unavailable,
            FailureDomain::Silvervine,
            if managed_timed_out {
                "Silvervine-managed Widevine signature verification timed out."
            } else {
                "Silvervine-managed Widevine signature verification could not complete."
            },
            None,
        )
    } else if bundle_invalid {
        (
            DiagnosticStatus::Warn,
            FailureDomain::BrowserMediaStack,
            "Browser bundle codesign verification failed.",
            Some("Repair or reinstall the browser to restore its code signature.".into()),
        )
    } else if bundle_incomplete {
        (
            DiagnosticStatus::Unavailable,
            FailureDomain::BrowserMediaStack,
            if bundle_timed_out {
                "Browser bundle codesign verification timed out."
            } else {
                "Browser bundle codesign verification could not complete."
            },
            None,
        )
    } else if managed {
        (
            DiagnosticStatus::Pass,
            FailureDomain::Silvervine,
            "Codesign verification passed for the vendor browser bundle and managed Widevine library.",
            None,
        )
    } else {
        (
            DiagnosticStatus::Pass,
            FailureDomain::BrowserMediaStack,
            "Browser bundle codesign verification passed.",
            None,
        )
    }
}

fn run_codesign_check(codesign: &Path, paths: CodesignPaths<'_>, managed: bool) -> DiagnosticCheck {
    let mut details = BTreeMap::new();
    let mut bundle_invalid = false;
    let mut bundle_incomplete = false;
    let mut bundle_timed_out = false;
    let mut managed_invalid = false;
    let mut managed_incomplete = false;
    let mut managed_timed_out = false;
    for (scope, path) in paths.scopes(managed).into_iter().flatten() {
        details.insert(format!("{scope}_path"), path.display().to_string());
        match run_output_with_timeout(
            codesign,
            &["--verify", "--strict", &path.to_string_lossy()],
            UTILITY_TIMEOUT,
        ) {
            Ok(output) => {
                if output.timed_out {
                    if scope == "bundle" {
                        bundle_incomplete = true;
                        bundle_timed_out = true;
                    } else {
                        managed_incomplete = true;
                        managed_timed_out = true;
                    }
                } else if !output.status.success() {
                    if scope == "bundle" {
                        bundle_invalid = true;
                    } else {
                        managed_invalid = true;
                    }
                }
                details.insert(format!("{scope}_exit_status"), output.status.to_string());
                details.insert(format!("{scope}_timed_out"), output.timed_out.to_string());
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.trim().is_empty() {
                    details.insert(
                        format!("{scope}_evidence"),
                        stderr
                            .chars()
                            .filter(|character| !character.is_control())
                            .take(500)
                            .collect(),
                    );
                }
            }
            Err(error) => {
                if scope == "bundle" {
                    bundle_incomplete = true;
                } else {
                    managed_incomplete = true;
                }
                details.insert(format!("{scope}_error"), error.message);
            }
        }
    }

    let (status, failure_domain, summary, action) = classify_codesign_result(
        [bundle_invalid, bundle_incomplete, bundle_timed_out],
        [managed_invalid, managed_incomplete, managed_timed_out],
        managed,
    );
    DiagnosticCheck {
        id: "browser.codesign".into(),
        status,
        source: EvidenceSource::HostProbe,
        failure_domain,
        summary: summary.into(),
        action,
        details,
    }
}

fn system_profiler_check() -> DiagnosticCheck {
    let profiler =
        find_executable("/usr/sbin/system_profiler").or_else(|| find_executable("system_profiler"));
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
    let supported = query_videotoolbox_support(fourcc);
    DiagnosticCheck {
        id: format!("host.videotoolbox.{id}"),
        status: videotoolbox_status(supported),
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
    }
}

const fn videotoolbox_status(supported: bool) -> DiagnosticStatus {
    if supported {
        DiagnosticStatus::Pass
    } else {
        DiagnosticStatus::Warn
    }
}

#[cfg(target_os = "macos")]
fn query_videotoolbox_support(fourcc: &str) -> bool {
    let code = fourcc_code(fourcc);
    // Safety: public VideoToolbox C API, no pointers exchanged.
    let supported = unsafe { VTIsHardwareDecodeSupported(code) };
    // Apple documents the function as Boolean; treat non-zero as true.
    supported != 0
}

#[cfg(not(target_os = "macos"))]
fn query_videotoolbox_support(_fourcc: &str) -> bool {
    false
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
fn parse_system_profiler_summary(json: &str) -> ProfilerSummary {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::{Path, PathBuf};

    use super::{fourcc_label, parse_system_profiler_summary, videotoolbox_status};
    use crate::diagnostics::{DiagnosticStatus, FailureDomain};

    fn write_fake_codesign(tmp: &tempfile::TempDir, body: &str) -> PathBuf {
        let tool = tmp.path().join("codesign");
        fs::write(&tool, body).expect("write fake codesign");
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755))
            .expect("make fake codesign executable");
        tool
    }

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
    fn absent_videotoolbox_hardware_support_is_not_a_pass() {
        assert_eq!(videotoolbox_status(false), DiagnosticStatus::Warn);
        assert_eq!(videotoolbox_status(true), DiagnosticStatus::Pass);
    }

    #[test]
    fn codesign_verification_avoids_recursive_bundle_scan() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let args_path = tmp.path().join("codesign-args");
        let tool = write_fake_codesign(
            &tmp,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
                args_path.display()
            ),
        );
        let bundle = Path::new("/Applications/Helium.app");
        let paths = super::CodesignPaths {
            bundle,
            cdm_library: None,
        };

        let check = super::run_codesign_check(&tool, paths, false);

        assert_eq!(check.status, DiagnosticStatus::Pass);
        let args = fs::read_to_string(args_path).expect("captured codesign args");
        assert!(args.lines().any(|argument| argument == "--verify"));
        assert!(args.lines().any(|argument| argument == "--strict"));
        assert!(
            args.lines().all(|argument| argument != "--deep"),
            "recursive verification scans unrelated nested browser code"
        );
    }

    #[test]
    fn codesign_scopes_vendor_bundle_and_profile_library() {
        let bundle = Path::new("/Applications/Helium.app");
        let library = Path::new(
            "/Users/me/Library/Application Support/net.imput.helium/WidevineCdm/4.10.3050.0/_platform_specific/mac_arm64/libwidevinecdm.dylib",
        );
        let managed = super::CodesignPaths {
            bundle,
            cdm_library: Some(library),
        };

        assert_eq!(
            managed.scopes(true),
            [Some(("bundle", bundle)), Some(("cdm_library", library)),]
        );
        assert_eq!(managed.scopes(false), [Some(("bundle", bundle)), None]);
    }

    #[test]
    fn managed_signature_failure_is_silvervine_owned_and_blocking() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let tool = write_fake_codesign(&tmp, "#!/bin/sh\nexit 1\n");
        let bundle = Path::new("/Applications/Helium.app");
        let library = Path::new(
            "/Users/me/Library/Application Support/net.imput.helium/WidevineCdm/4.10.3050.0/_platform_specific/mac_arm64/libwidevinecdm.dylib",
        );
        let paths = super::CodesignPaths {
            bundle,
            cdm_library: Some(library),
        };

        let check = super::run_codesign_check(&tool, paths, true);

        assert_eq!(check.status, DiagnosticStatus::Fail);
        assert_eq!(check.failure_domain, FailureDomain::Silvervine);
    }

    #[test]
    fn managed_verification_incomplete_takes_precedence_over_bundle_failure() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let tool = write_fake_codesign(&tmp, "#!/bin/sh\nrm \"$0\"\nexit 1\n");
        let bundle = Path::new("/Applications/Helium.app");
        let library = Path::new(
            "/Users/me/Library/Application Support/net.imput.helium/WidevineCdm/4.10.3050.0/_platform_specific/mac_arm64/libwidevinecdm.dylib",
        );
        let paths = super::CodesignPaths {
            bundle,
            cdm_library: Some(library),
        };

        let check = super::run_codesign_check(&tool, paths, true);

        assert_eq!(check.status, DiagnosticStatus::Unavailable);
        assert_eq!(check.failure_domain, FailureDomain::Silvervine);
        assert_eq!(
            check.summary,
            "Silvervine-managed Widevine signature verification could not complete."
        );
    }

    #[test]
    fn managed_missing_library_never_reports_codesign_pass() {
        let check = super::codesign_check(Path::new("/Applications/Helium.app"), None, true);

        assert_eq!(check.status, DiagnosticStatus::Fail);
        assert_eq!(check.failure_domain, FailureDomain::Silvervine);
        assert_eq!(
            check.details.get("missing_managed_scopes"),
            Some(&"cdm_library".to_owned())
        );
    }

    #[test]
    fn external_bundle_signature_failure_has_browser_owned_remediation() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let tool = write_fake_codesign(&tmp, "#!/bin/sh\nexit 1\n");
        let bundle = Path::new("/Applications/Chrome.app");
        let paths = super::CodesignPaths {
            bundle,
            cdm_library: None,
        };

        let check = super::run_codesign_check(&tool, paths, false);

        assert_eq!(check.status, DiagnosticStatus::Warn);
        assert_eq!(
            check.action.as_deref(),
            Some("Repair or reinstall the browser to restore its code signature.")
        );
    }
}
