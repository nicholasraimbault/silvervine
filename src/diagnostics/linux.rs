//! Linux host media/GPU passive diagnostics.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::diagnostics::{DiagnosticCheck, DiagnosticStatus, EvidenceSource, FailureDomain};
use crate::platform::process::{find_executable, run_output_with_timeout};
use crate::widevine::download::sha512_file_hex;

const UTILITY_TIMEOUT: Duration = Duration::from_secs(10);

/// Collect Linux session, DRM render-node, sysfs, vainfo, and glibc evidence.
#[must_use]
pub fn collect_host_checks() -> Vec<DiagnosticCheck> {
    let mut checks = Vec::new();
    checks.push(session_check());
    checks.extend(render_node_checks());
    checks.push(vainfo_check());
    checks.push(glibc_check());
    checks
}

/// Collect dependency evidence for a verified CDM library only.
#[must_use]
pub fn collect_verified_library_deps(library: &Path) -> DiagnosticCheck {
    ldd_check(library, true)
}

fn session_check() -> DiagnosticCheck {
    let mut details = BTreeMap::new();
    if let Ok(session) = std::env::var("XDG_SESSION_TYPE") {
        details.insert("xdg_session_type".into(), session);
    }
    if let Ok(desktop) = std::env::var("XDG_CURRENT_DESKTOP") {
        details.insert("xdg_current_desktop".into(), desktop);
    }
    if let Ok(wayland) = std::env::var("WAYLAND_DISPLAY") {
        details.insert("wayland_display".into(), wayland);
    }
    if let Ok(display) = std::env::var("DISPLAY") {
        details.insert("display".into(), display);
    }
    if details.is_empty() {
        DiagnosticCheck {
            id: "host.session".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "No graphical session environment variables were exposed.".into(),
            action: None,
            details,
        }
    } else {
        DiagnosticCheck {
            id: "host.session".into(),
            status: DiagnosticStatus::Pass,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "Graphical session environment variables were observed.".into(),
            action: None,
            details,
        }
    }
}

fn render_node_checks() -> Vec<DiagnosticCheck> {
    let dri = Path::new("/dev/dri");
    let entries = match fs::read_dir(dri) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return vec![DiagnosticCheck {
                id: "host.render_nodes".into(),
                status: DiagnosticStatus::Unavailable,
                source: EvidenceSource::HostProbe,
                failure_domain: FailureDomain::BrowserMediaStack,
                summary: "/dev/dri is not present on this host.".into(),
                action: None,
                details: BTreeMap::new(),
            }];
        }
        Err(error) => {
            return vec![DiagnosticCheck {
                id: "host.render_nodes".into(),
                status: DiagnosticStatus::Warn,
                source: EvidenceSource::HostProbe,
                failure_domain: FailureDomain::BrowserMediaStack,
                summary: "Could not list /dev/dri render nodes.".into(),
                action: None,
                details: BTreeMap::from([("error".into(), error.to_string())]),
            }];
        }
    };

    let mut nodes = Vec::new();
    for entry in entries.flatten().take(32) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("renderD") || name.starts_with("card")) {
            continue;
        }
        let path = entry.path();
        let accessible = fs::File::open(&path).is_ok();
        let mut details = BTreeMap::from([
            ("path".into(), path.display().to_string()),
            ("accessible".into(), accessible.to_string()),
        ]);
        if let Some(sysfs) = sysfs_for_dri_node(&name) {
            details.extend(sysfs);
        }
        nodes.push(DiagnosticCheck {
            id: format!("host.render_node.{name}"),
            status: if accessible {
                DiagnosticStatus::Pass
            } else {
                DiagnosticStatus::Warn
            },
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: if accessible {
                format!("DRM node {name} is present and readable.")
            } else {
                format!("DRM node {name} is present but not readable by this user.")
            },
            action: (!accessible).then(|| {
                "Add your user to the `render`/`video` groups or adjust DRM node permissions."
                    .into()
            }),
            details,
        });
    }

    if nodes.is_empty() {
        vec![DiagnosticCheck {
            id: "host.render_nodes".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "No DRM card/render nodes were found under /dev/dri.".into(),
            action: None,
            details: BTreeMap::new(),
        }]
    } else {
        nodes
    }
}

fn sysfs_for_dri_node(name: &str) -> Option<BTreeMap<String, String>> {
    // /sys/class/drm/<name>/device/{vendor,device,driver}
    let device_root = PathBuf::from("/sys/class/drm").join(name).join("device");
    if !device_root.exists() {
        return None;
    }
    let mut details = BTreeMap::new();
    for key in ["vendor", "device"] {
        if let Ok(value) = fs::read_to_string(device_root.join(key)) {
            let trimmed = value.trim();
            if !trimmed.is_empty() && trimmed.len() <= 32 {
                details.insert(key.into(), trimmed.to_owned());
            }
        }
    }
    let driver_link = device_root.join("driver");
    if let Ok(target) = fs::read_link(&driver_link) {
        if let Some(name) = target.file_name() {
            details.insert("driver".into(), name.to_string_lossy().into_owned());
        }
    }
    (!details.is_empty()).then_some(details)
}

fn vainfo_check() -> DiagnosticCheck {
    let Some(executable) = find_executable("vainfo") else {
        return DiagnosticCheck {
            id: "host.vaapi".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary:
                "VA-API codec acceleration probe unavailable because `vainfo` is not installed."
                    .into(),
            action: Some(
                "Install `vainfo` with your distribution's package manager, then rerun this command."
                    .into(),
            ),
            details: BTreeMap::from([("utility".into(), "vainfo".into())]),
        };
    };
    match run_output_with_timeout(&executable, &[], UTILITY_TIMEOUT) {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let codecs = parse_vainfo_codecs(&stdout);
            let mut details = BTreeMap::from([
                ("utility".into(), "vainfo".into()),
                ("exit_status".into(), output.status.to_string()),
                ("timed_out".into(), output.timed_out.to_string()),
            ]);
            if !codecs.is_empty() {
                details.insert("codecs".into(), codecs.join(","));
            }
            if let Some(evidence) = first_interesting_lines(&stdout, &stderr, 40) {
                details.insert("evidence".into(), evidence);
            }
            let status = if output.timed_out || !output.status.success() {
                DiagnosticStatus::Warn
            } else {
                DiagnosticStatus::Pass
            };
            DiagnosticCheck {
                id: "host.vaapi".into(),
                status,
                source: EvidenceSource::HostProbe,
                failure_domain: FailureDomain::BrowserMediaStack,
                summary: if output.timed_out {
                    "VA-API probe timed out.".into()
                } else if output.status.success() {
                    if codecs.is_empty() {
                        "VA-API probe completed.".into()
                    } else {
                        format!("VA-API probe completed (codecs: {}).", codecs.join(", "))
                    }
                } else {
                    "VA-API probe exited unsuccessfully.".into()
                },
                action: (status != DiagnosticStatus::Pass).then(|| {
                    "Run `vainfo` in the same graphical session and resolve its driver or display error."
                        .into()
                }),
                details,
            }
        }
        Err(error) => DiagnosticCheck {
            id: "host.vaapi".into(),
            status: DiagnosticStatus::Warn,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "VA-API probe could not run.".into(),
            action: Some(
                "Run `vainfo` directly in this graphical session and resolve the reported error."
                    .into(),
            ),
            details: BTreeMap::from([
                ("utility".into(), "vainfo".into()),
                ("error".into(), error.message),
            ]),
        },
    }
}

fn glibc_check() -> DiagnosticCheck {
    let Some(ldd) = find_executable("ldd") else {
        return DiagnosticCheck {
            id: "host.glibc".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "glibc version unavailable because `ldd` is not installed.".into(),
            action: None,
            details: BTreeMap::from([("utility".into(), "ldd".into())]),
        };
    };
    match run_output_with_timeout(&ldd, &["--version"], UTILITY_TIMEOUT) {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let version = parse_ldd_version(&stdout);
            let mut details = BTreeMap::from([
                ("utility".into(), "ldd".into()),
                ("exit_status".into(), output.status.to_string()),
            ]);
            if let Some(version) = &version {
                details.insert("glibc_version".into(), version.clone());
            }
            let status = if output.timed_out || !output.status.success() {
                DiagnosticStatus::Warn
            } else {
                DiagnosticStatus::Pass
            };
            DiagnosticCheck {
                id: "host.glibc".into(),
                status,
                source: EvidenceSource::HostProbe,
                failure_domain: FailureDomain::BrowserMediaStack,
                summary: match version {
                    Some(version) => format!("glibc version {version} reported by ldd."),
                    None => "ldd --version completed without a parseable glibc version.".into(),
                },
                action: None,
                details,
            }
        }
        Err(error) => DiagnosticCheck {
            id: "host.glibc".into(),
            status: DiagnosticStatus::Warn,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "ldd --version could not run.".into(),
            action: None,
            details: BTreeMap::from([("error".into(), error.message)]),
        },
    }
}

fn ldd_check(library: &Path, verified: bool) -> DiagnosticCheck {
    if !verified {
        return DiagnosticCheck {
            id: "cdm.dependencies".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "ldd is only run against verified Silvervine-managed CDM libraries.".into(),
            action: None,
            details: BTreeMap::from([("path".into(), library.display().to_string())]),
        };
    }
    // Cheap integrity gate before spawning ldd.
    if sha512_file_hex(library).is_err() {
        return DiagnosticCheck {
            id: "cdm.dependencies".into(),
            status: DiagnosticStatus::Warn,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::Silvervine,
            summary: "Verified CDM library could not be hashed before dependency inspection."
                .into(),
            action: None,
            details: BTreeMap::from([("path".into(), library.display().to_string())]),
        };
    }
    let Some(ldd) = find_executable("ldd") else {
        return DiagnosticCheck {
            id: "cdm.dependencies".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "CDM dependency probe unavailable because `ldd` is not installed.".into(),
            action: None,
            details: BTreeMap::from([("path".into(), library.display().to_string())]),
        };
    };
    match run_output_with_timeout(&ldd, &[&library.to_string_lossy()], UTILITY_TIMEOUT) {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let missing = parse_ldd_missing(&stdout);
            let mut details = BTreeMap::from([
                ("path".into(), library.display().to_string()),
                ("exit_status".into(), output.status.to_string()),
            ]);
            if !missing.is_empty() {
                details.insert("missing".into(), missing.join(","));
            }
            if let Some(evidence) = first_interesting_lines(&stdout, "", 40) {
                details.insert("evidence".into(), evidence);
            }
            if !missing.is_empty() {
                DiagnosticCheck {
                    id: "cdm.dependencies".into(),
                    status: DiagnosticStatus::Fail,
                    source: EvidenceSource::VerifiedFile,
                    failure_domain: FailureDomain::Silvervine,
                    summary: format!(
                        "Verified CDM library is missing shared dependencies: {}.",
                        missing.join(", ")
                    ),
                    action: Some(
                        "Install the missing libraries or reinstall the matching CDM payload."
                            .into(),
                    ),
                    details,
                }
            } else if output.timed_out || !output.status.success() {
                DiagnosticCheck {
                    id: "cdm.dependencies".into(),
                    status: DiagnosticStatus::Warn,
                    source: EvidenceSource::VerifiedFile,
                    failure_domain: FailureDomain::Silvervine,
                    summary: "ldd could not fully inspect the verified CDM library.".into(),
                    action: None,
                    details,
                }
            } else {
                DiagnosticCheck {
                    id: "cdm.dependencies".into(),
                    status: DiagnosticStatus::Pass,
                    source: EvidenceSource::VerifiedFile,
                    failure_domain: FailureDomain::Silvervine,
                    summary: "Verified CDM library dependencies resolve.".into(),
                    action: None,
                    details,
                }
            }
        }
        Err(error) => DiagnosticCheck {
            id: "cdm.dependencies".into(),
            status: DiagnosticStatus::Warn,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::Silvervine,
            summary: "ldd could not run against the verified CDM library.".into(),
            action: None,
            details: BTreeMap::from([
                ("path".into(), library.display().to_string()),
                ("error".into(), error.message),
            ]),
        },
    }
}

/// Extract codec family names from vainfo output.
#[must_use]
pub fn parse_vainfo_codecs(output: &str) -> Vec<String> {
    let mut codecs = Vec::new();
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        for (needle, label) in [
            ("h264", "H.264"),
            ("avc", "H.264"),
            ("hevc", "HEVC"),
            ("h265", "HEVC"),
            ("vp9", "VP9"),
            ("av1", "AV1"),
            ("vp8", "VP8"),
        ] {
            if lower.contains(needle) && !codecs.iter().any(|item| item == label) {
                codecs.push(label.into());
            }
        }
    }
    codecs
}

/// Parse `ldd --version` first-line glibc version.
#[must_use]
pub fn parse_ldd_version(output: &str) -> Option<String> {
    let first = output.lines().next()?.trim();
    // e.g. "ldd (GNU libc) 2.40" or "ldd (Ubuntu GLIBC 2.39-0ubuntu8.3) 2.39"
    let version = first
        .split_whitespace()
        .rev()
        .find(|token| token.chars().next().is_some_and(|c| c.is_ascii_digit()))?;
    let clean: String = version
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!clean.is_empty()).then_some(clean)
}

/// Extract `=> not found` dependency names from ldd output.
#[must_use]
pub fn parse_ldd_missing(output: &str) -> Vec<String> {
    let mut missing = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("not found") {
            continue;
        }
        let name = trimmed.split_whitespace().next().unwrap_or_default();
        if !name.is_empty() && name.len() <= 128 {
            missing.push(name.to_owned());
        }
    }
    missing
}

fn first_interesting_lines(stdout: &str, stderr: &str, limit: usize) -> Option<String> {
    let keys = [
        "va-api",
        "driver",
        "vendor",
        "device",
        "profile",
        "entrypoint",
        "glibc",
        "not found",
    ];
    let mut retained = Vec::new();
    let mut length = 0_usize;
    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if !keys.iter().any(|key| lower.contains(key)) {
            continue;
        }
        let safe: String = trimmed
            .chars()
            .filter(|c| !c.is_control() || *c == '\t')
            .take(240)
            .collect();
        if length + safe.len() > 8 * 1024 || retained.len() >= limit {
            break;
        }
        length += safe.len();
        retained.push(safe);
    }
    (!retained.is_empty()).then(|| retained.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::{parse_ldd_missing, parse_ldd_version, parse_vainfo_codecs};

    #[test]
    fn vainfo_codec_parser_extracts_families() {
        let output = r"
VAProfileH264Main
VAProfileHEVCMain
VAProfileVP9Profile0
VAProfileAV1Profile0
";
        assert_eq!(
            parse_vainfo_codecs(output),
            vec!["H.264", "HEVC", "VP9", "AV1"]
        );
    }

    #[test]
    fn ldd_version_parser_reads_trailing_version() {
        assert_eq!(
            parse_ldd_version("ldd (GNU libc) 2.40\nCopyright"),
            Some("2.40".into())
        );
        assert_eq!(
            parse_ldd_version("ldd (Ubuntu GLIBC 2.39-0ubuntu8.3) 2.39\n"),
            Some("2.39".into())
        );
    }

    #[test]
    fn ldd_missing_parser_collects_not_found_rows() {
        let output = "\tlibfoo.so.1 => not found\n\tlibc.so.6 => /lib/libc.so.6\n";
        assert_eq!(parse_ldd_missing(output), vec!["libfoo.so.1".to_string()]);
    }
}
