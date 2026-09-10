//! Passive, local-only browser, CDM, codec, and graphics diagnostics.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use self::external::{collect_external_cdms, hint_to_fingerprint_entry};
use crate::browsers::{runtime, Browser};
use crate::diagnostics::binary::{self, BinaryArchitecture, BinaryFormat};
#[cfg(target_os = "linux")]
use crate::diagnostics::linux;
#[cfg(target_os = "macos")]
use crate::diagnostics::macos;
use crate::diagnostics::store::{canonicalize_path, CdmFingerprintEntry, ProbeFingerprint};
use crate::diagnostics::{DiagnosticCheck, DiagnosticStatus, EvidenceSource, FailureDomain};
use crate::error::{Error, Result};
use crate::patch;
use crate::widevine::download::sha512_file_hex;
use crate::widevine::ownership::{self, OwnershipAssessment, OwnershipKind};
use crate::widevine::CachedCdm;

/// Origin of an external/component CDM hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCdmOrigin {
    /// Browser user-profile `WidevineCdm` directory.
    ProfileWidevineCdm,
    /// Component-updater hint under the browser profile.
    ComponentUpdater,
    /// Other known component location outside the install-root target.
    KnownComponentLocation,
}

/// Bounded external/component CDM evidence discovered without dumping profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalCdmHint {
    /// Canonical path of the discovered CDM root or library.
    pub path: PathBuf,
    /// Manifest/component version when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Library path when a single regular library is contained under the hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<PathBuf>,
    /// SHA-512 of the library when safely readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library_sha512: Option<String>,
    /// Where the hint came from.
    pub origin: ExternalCdmOrigin,
}

/// Passive evidence for one selected browser and its installed CDM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserDiagnostics {
    /// Browser display name.
    pub browser: String,
    /// Resolved executable, when available.
    pub browser_executable: Option<PathBuf>,
    /// Passive browser version, when available.
    pub browser_version: Option<String>,
    /// Platform-resolved CDM target.
    pub cdm_target: Option<PathBuf>,
    /// Install-root CDM version when readable (managed or external layout).
    pub cdm_version: Option<String>,
    /// Install-root CDM library path when readable.
    pub cdm_library: Option<PathBuf>,
    /// Install-root CDM library digest when safely hashed.
    pub cdm_library_sha512: Option<String>,
    /// Ownership assessment for the install-root patch target.
    pub ownership: OwnershipAssessment,
    /// Bounded external/component CDM hints from normal profile metadata.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub external_cdms: Vec<ExternalCdmHint>,
    /// Exact cache identity when the browser executable resolves.
    pub fingerprint: Option<ProbeFingerprint>,
    /// Source-labeled passive checks.
    pub checks: Vec<DiagnosticCheck>,
}

/// Collect local browser/CDM evidence without launching the browser, scanning
/// its processes, dumping profiles, or making network requests.
#[must_use]
pub fn collect_browser(browser: &Browser) -> BrowserDiagnostics {
    let validation = crate::widevine::cache::validated_current_readonly();
    collect_browser_with_cache_validation(browser, &validation)
}

#[must_use]
pub(crate) fn collect_browser_with_cache_validation(
    browser: &Browser,
    validation: &Result<Option<CachedCdm>>,
) -> BrowserDiagnostics {
    match validation {
        Ok(candidate) => collect_browser_with_candidate(browser, candidate.as_ref()),
        Err(error) => {
            let mut diagnostics = collect_browser_with_candidate(browser, None);
            diagnostics.fingerprint = None;
            diagnostics.checks.push(DiagnosticCheck {
                id: "cdm.cache".into(),
                status: DiagnosticStatus::Warn,
                source: EvidenceSource::HostProbe,
                failure_domain: FailureDomain::Silvervine,
                summary: "The current Silvervine CDM cache failed integrity validation.".into(),
                action: Some("Run `silvervine update widevine`, then retry.".into()),
                details: BTreeMap::from([
                    ("error_category".into(), error.category.as_str().into()),
                    ("error".into(), error.message.clone()),
                ]),
            });
            diagnostics
        }
    }
}

/// Collect passive browser evidence using an explicit cached CDM candidate.
#[must_use]
pub fn collect_browser_with_candidate(
    browser: &Browser,
    candidate: Option<&CachedCdm>,
) -> BrowserDiagnostics {
    let executable = runtime::executable_path(browser);
    let browser_version = runtime::passive_version(browser);
    let cdm_target =
        patch::host_patcher().and_then(|patcher| patcher.cdm_target(browser.install_path()));
    collect_browser_at(
        browser,
        executable,
        browser_version,
        cdm_target,
        candidate,
        None,
    )
}

fn collect_browser_at(
    browser: &Browser,
    executable: Result<PathBuf>,
    browser_version: Option<String>,
    cdm_target: Result<PathBuf>,
    candidate: Option<&CachedCdm>,
    profile_roots: Option<&[PathBuf]>,
) -> BrowserDiagnostics {
    let (browser_executable, executable_check) = collect_executable(browser, executable);
    let cdm = collect_cdm(browser, cdm_target, candidate);
    let external = collect_external_cdms(browser, profile_roots, cdm.target.as_deref());
    let mut checks = Vec::with_capacity(3 + cdm.checks.len() + external.checks.len());
    checks.push(executable_check);
    checks.push(version_check(browser_version.as_deref()));
    checks.extend(cdm.checks);
    checks.extend(external.checks);

    #[cfg(target_os = "linux")]
    if cdm.ownership.kind == OwnershipKind::Managed {
        if let Some(library) = cdm.library.as_ref() {
            checks.push(linux::collect_library_dependency_limit(library));
        }
    }
    #[cfg(target_os = "macos")]
    {
        checks.push(macos::codesign_check(
            browser.install_path(),
            cdm.library.as_deref(),
            cdm.ownership.kind == OwnershipKind::Managed,
        ));
    }

    let fingerprint = if external.profile_scope_complete {
        browser_executable.as_ref().and_then(|path| {
            let mut entries = Vec::new();
            if let Some(entry) = cdm.fingerprint_entry.clone() {
                entries.push(entry);
            }
            for hint in &external.hints {
                entries.push(hint_to_fingerprint_entry(hint));
            }
            // Do not discard undigested hints here. `from_executable` deliberately
            // refuses the entire cache key when any relevant CDM identity cannot
            // be bound to bytes; omitting that hint would make stale evidence look exact.
            ProbeFingerprint::from_executable(path, browser_version.clone(), entries).ok()
        })
    } else {
        None
    };

    BrowserDiagnostics {
        browser: browser.name().into(),
        browser_executable,
        browser_version,
        cdm_target: cdm.target,
        cdm_version: cdm.version,
        cdm_library: cdm.library,
        cdm_library_sha512: cdm.library_sha512,
        ownership: cdm.ownership,
        external_cdms: external.hints,
        fingerprint,
        checks,
    }
}

fn collect_executable(
    browser: &Browser,
    executable: Result<PathBuf>,
) -> (Option<PathBuf>, DiagnosticCheck) {
    match executable {
        Ok(path) => {
            let check = binary_check(
                "browser.binary",
                "Browser entry point",
                &path,
                FailureDomain::BrowserMediaStack,
                EvidenceSource::HostProbe,
            );
            (Some(path), check)
        }
        Err(error) => (
            None,
            error_check(
                "browser.binary",
                DiagnosticStatus::Fail,
                EvidenceSource::HostProbe,
                FailureDomain::BrowserMediaStack,
                format!("Could not resolve the {} executable.", browser.name()),
                Some("Correct the browser installation or configured path, then retry.".into()),
                &error,
            ),
        ),
    }
}

fn version_check(version: Option<&str>) -> DiagnosticCheck {
    match version {
        Some(version) => DiagnosticCheck {
            id: "browser.version".into(),
            status: DiagnosticStatus::Pass,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: format!("Browser version {version} was read without launching it."),
            action: None,
            details: BTreeMap::from([("version".into(), version.into())]),
        },
        None => DiagnosticCheck {
            id: "browser.version".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "Browser version was not available from passive installation metadata.".into(),
            action: None,
            details: BTreeMap::new(),
        },
    }
}

#[derive(Default)]
struct CdmEvidence {
    target: Option<PathBuf>,
    version: Option<String>,
    library: Option<PathBuf>,
    library_sha512: Option<String>,
    ownership: OwnershipAssessment,
    fingerprint_entry: Option<CdmFingerprintEntry>,
    checks: Vec<DiagnosticCheck>,
}

fn collect_cdm(
    browser: &Browser,
    cdm_target: Result<PathBuf>,
    candidate: Option<&CachedCdm>,
) -> CdmEvidence {
    let target = match cdm_target {
        Ok(target) => target,
        Err(error) => {
            return CdmEvidence {
                ownership: OwnershipAssessment {
                    kind: OwnershipKind::InvalidMarker,
                    summary: "Could not resolve the browser's platform-specific CDM target.".into(),
                    action: Some(
                        "Run `silvervine repair` and review the reported browser layout.".into(),
                    ),
                    details: BTreeMap::from([
                        ("error_category".into(), error.category.as_str().into()),
                        ("error".into(), error.message.clone()),
                    ]),
                },
                checks: vec![error_check(
                    "cdm.provenance",
                    DiagnosticStatus::Fail,
                    EvidenceSource::HostProbe,
                    FailureDomain::Silvervine,
                    "Could not resolve the browser's platform-specific CDM target.".into(),
                    Some("Run `silvervine repair` and review the reported browser layout.".into()),
                    &error,
                )],
                ..CdmEvidence::default()
            };
        }
    };

    let ownership = classify_passive(browser, &target, candidate);
    let known = ownership
        .details
        .get("library_sha512")
        .map(String::as_str)
        .filter(|digest| !digest.is_empty())
        .or_else(|| match ownership.kind {
            OwnershipKind::Managed | OwnershipKind::LegacyManaged => {
                candidate.and_then(CachedCdm::verified_library_sha512)
            }
            _ => None,
        });
    let identity = inspect_cdm_identity(&target, known);
    let mut checks = vec![ownership_check(&ownership, &target)];

    if let Some(library) = identity.library.as_ref() {
        let source = if ownership.kind == OwnershipKind::Managed {
            EvidenceSource::VerifiedFile
        } else {
            EvidenceSource::HostProbe
        };
        let domain = match ownership.kind {
            OwnershipKind::Managed | OwnershipKind::LegacyManaged | OwnershipKind::Missing => {
                FailureDomain::Silvervine
            }
            OwnershipKind::External | OwnershipKind::InvalidMarker => {
                FailureDomain::BrowserMediaStack
            }
        };
        checks.push(binary_check(
            "cdm.binary",
            "Widevine library",
            library,
            domain,
            source,
        ));
    }

    let fingerprint_entry = identity.library.as_ref().map(|library| {
        let path = canonicalize_path(library).map_or_else(
            |_| library.to_string_lossy().into_owned(),
            |path| path.to_string_lossy().into_owned(),
        );
        CdmFingerprintEntry::new(
            path,
            identity.version.clone(),
            identity.library_sha512.clone(),
        )
    });

    CdmEvidence {
        target: Some(target),
        version: identity.version,
        library: identity.library,
        library_sha512: identity.library_sha512,
        ownership,
        fingerprint_entry,
        checks,
    }
}

fn classify_passive(
    browser: &Browser,
    target: &Path,
    candidate: Option<&CachedCdm>,
) -> OwnershipAssessment {
    // Unverified cache handles (metadata/drift-only) must not participate in
    // marker construction or ownership classification.
    let verified_candidate = candidate.filter(|cdm| {
        cdm.verified_library_sha512().is_some() && cdm.verified_manifest_sha512().is_some()
    });
    match verified_candidate {
        Some(candidate) => match ownership::marker_for_cached(candidate) {
            Ok(marker) => {
                ownership::classify(browser, target, candidate, &marker).unwrap_or_else(|error| {
                    OwnershipAssessment {
                    kind: OwnershipKind::InvalidMarker,
                    summary: "The CDM target could not be classified safely.".into(),
                    action: Some(
                        "Inspect the browser CDM path and retry `silvervine doctor --media-stack`."
                            .into(),
                    ),
                    details: BTreeMap::from([
                        ("error_category".into(), error.category.as_str().into()),
                        ("error".into(), error.message),
                    ]),
                }
                })
            }
            Err(_) => {
                // marker_for_cached refuses unverified/drifted handles. Treat as
                // no authenticated candidate rather than InvalidMarker noise.
                ownership::classify_without_candidate(browser, target).unwrap_or_else(|error| {
                    OwnershipAssessment {
                        kind: OwnershipKind::InvalidMarker,
                        summary: "The CDM target could not be classified safely.".into(),
                        action: Some(
                            "Inspect the browser CDM path and retry `silvervine doctor --media-stack`."
                                .into(),
                        ),
                        details: BTreeMap::from([
                            ("error_category".into(), error.category.as_str().into()),
                            ("error".into(), error.message),
                        ]),
                    }
                })
            }
        },
        None => ownership::classify_without_candidate(browser, target).unwrap_or_else(|error| {
            OwnershipAssessment {
                kind: OwnershipKind::InvalidMarker,
                summary: "The CDM target could not be classified safely.".into(),
                action: Some(
                    "Inspect the browser CDM path and retry `silvervine doctor --media-stack`."
                        .into(),
                ),
                details: BTreeMap::from([
                    ("error_category".into(), error.category.as_str().into()),
                    ("error".into(), error.message),
                ]),
            }
        }),
    }
}

fn ownership_check(ownership: &OwnershipAssessment, target: &Path) -> DiagnosticCheck {
    let (status, source, domain) = match ownership.kind {
        OwnershipKind::Managed => (
            DiagnosticStatus::Pass,
            EvidenceSource::VerifiedFile,
            FailureDomain::Silvervine,
        ),
        OwnershipKind::LegacyManaged => (
            DiagnosticStatus::Warn,
            EvidenceSource::HostProbe,
            FailureDomain::Silvervine,
        ),
        OwnershipKind::Missing | OwnershipKind::InvalidMarker => (
            DiagnosticStatus::Fail,
            EvidenceSource::HostProbe,
            FailureDomain::Silvervine,
        ),
        OwnershipKind::External => (
            DiagnosticStatus::Warn,
            EvidenceSource::HostProbe,
            FailureDomain::BrowserMediaStack,
        ),
    };
    let mut details = ownership.details.clone();
    details.insert(
        "ownership_kind".into(),
        ownership_kind_name(ownership.kind).into(),
    );
    details.insert("cdm_target".into(), target.display().to_string());
    DiagnosticCheck {
        id: "cdm.provenance".into(),
        status,
        source,
        failure_domain: domain,
        summary: ownership.summary.clone(),
        action: ownership.action.clone(),
        details,
    }
}

fn ownership_kind_name(kind: OwnershipKind) -> &'static str {
    match kind {
        OwnershipKind::Missing => "missing",
        OwnershipKind::Managed => "managed",
        OwnershipKind::LegacyManaged => "legacy_managed",
        OwnershipKind::External => "external",
        OwnershipKind::InvalidMarker => "invalid_marker",
    }
}

#[derive(Default)]
struct CdmIdentity {
    version: Option<String>,
    library: Option<PathBuf>,
    library_sha512: Option<String>,
}

fn inspect_cdm_identity(target: &Path, known: Option<&str>) -> CdmIdentity {
    let version = read_manifest_version(&target.join("manifest.json"));
    let library = find_contained_library(target);
    let library_sha512 = library
        .as_ref()
        .and_then(|path| library_digest(path, known));
    CdmIdentity {
        version,
        library,
        library_sha512,
    }
}

fn read_manifest_version(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1024 {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.is_empty() && version.len() <= 64)
        .map(str::to_owned)
}

fn find_contained_library(root: &Path) -> Option<PathBuf> {
    let platform_root = root.join("_platform_specific");
    let metadata = fs::symlink_metadata(&platform_root).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return None;
    }
    let mut found = Vec::new();
    let entries = fs::read_dir(&platform_root).ok()?;
    for entry in entries.flatten().take(8) {
        let platform = entry.path();
        let meta = fs::symlink_metadata(&platform).ok()?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            continue;
        }
        if !is_contained(&platform_root, &platform) {
            continue;
        }
        for name in ["libwidevinecdm.so", "libwidevinecdm.dylib"] {
            let library = platform.join(name);
            let Ok(lib_meta) = fs::symlink_metadata(&library) else {
                continue;
            };
            if lib_meta.file_type().is_symlink() || !lib_meta.is_file() || lib_meta.len() == 0 {
                continue;
            }
            if !is_contained(&platform, &library) {
                continue;
            }
            // Bound digest work: skip absurdly large files.
            if lib_meta.len() > 64 * 1024 * 1024 {
                continue;
            }
            found.push(library);
        }
    }
    if found.len() == 1 {
        found.pop()
    } else {
        None
    }
}

fn library_digest(path: &Path, known: Option<&str>) -> Option<String> {
    if let Some(digest) = known {
        if !digest.is_empty() {
            return Some(digest.to_owned());
        }
    }
    safe_library_digest(path)
}

fn safe_library_digest(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    if metadata.len() == 0 || metadata.len() > 64 * 1024 * 1024 {
        return None;
    }
    sha512_file_hex(path).ok()
}

fn is_contained(root: &Path, candidate: &Path) -> bool {
    let Ok(root) = fs::canonicalize(root) else {
        return false;
    };
    let Ok(candidate) = fs::canonicalize(candidate) else {
        return false;
    };
    candidate.starts_with(&root)
}

/// Run a fixed, optional platform utility allowlist for graphics and codec
/// acceleration evidence. Missing utilities are reported as unavailable.
#[must_use]
pub fn collect_host_media_checks() -> Vec<DiagnosticCheck> {
    crate::diagnostics::media::collect_host_checks()
}

fn binary_check(
    id: &str,
    label: &str,
    path: &Path,
    failure_domain: FailureDomain,
    source: EvidenceSource,
) -> DiagnosticCheck {
    if has_shebang(path) {
        return DiagnosticCheck {
            id: id.into(),
            status: DiagnosticStatus::Warn,
            source,
            failure_domain,
            summary: format!(
                "{label} is a script wrapper; architecture cannot be inferred from the wrapper."
            ),
            action: None,
            details: BTreeMap::from([
                ("path".into(), path.display().to_string()),
                ("format".into(), "script".into()),
            ]),
        };
    }
    match binary::inspect(path) {
        Ok(info) => {
            let architectures = info
                .architectures
                .iter()
                .copied()
                .map(architecture_name)
                .collect::<Vec<_>>()
                .join(",");
            let compatible = info
                .architectures
                .iter()
                .copied()
                .any(architecture_matches_host);
            DiagnosticCheck {
                id: id.into(),
                status: if compatible {
                    DiagnosticStatus::Pass
                } else {
                    DiagnosticStatus::Fail
                },
                source,
                failure_domain,
                summary: format!(
                    "{label} format is {}-bit {} with {architectures} architecture.",
                    info.bits,
                    format_name(info.format)
                ),
                action: (!compatible).then(|| {
                    "Install a browser and Widevine payload built for the current host architecture."
                        .into()
                }),
                details: BTreeMap::from([
                    ("path".into(), path.display().to_string()),
                    ("format".into(), format_name(info.format).into()),
                    ("bits".into(), info.bits.to_string()),
                    ("architectures".into(), architectures),
                ]),
            }
        }
        Err(error) => error_check(
            id,
            DiagnosticStatus::Fail,
            source,
            failure_domain,
            format!("{label} could not be inspected."),
            None,
            &error,
        ),
    }
}

fn architecture_matches_host(architecture: BinaryArchitecture) -> bool {
    matches!(
        (std::env::consts::ARCH, architecture),
        ("x86_64", BinaryArchitecture::X86_64) | ("aarch64", BinaryArchitecture::Aarch64)
    )
}

fn format_name(format: BinaryFormat) -> &'static str {
    match format {
        BinaryFormat::Elf => "elf",
        BinaryFormat::MachO => "mach_o",
    }
}

fn architecture_name(architecture: BinaryArchitecture) -> String {
    match architecture {
        BinaryArchitecture::X86_64 => "x86_64".into(),
        BinaryArchitecture::Aarch64 => "aarch64".into(),
        BinaryArchitecture::Other(machine) => format!("other-{machine:#x}"),
    }
}

fn has_shebang(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut prefix = [0_u8; 2];
    file.read_exact(&mut prefix).is_ok() && prefix == *b"#!"
}

fn error_check(
    id: &str,
    status: DiagnosticStatus,
    source: EvidenceSource,
    failure_domain: FailureDomain,
    summary: String,
    action: Option<String>,
    error: &Error,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        status,
        source,
        failure_domain,
        summary,
        action,
        details: BTreeMap::from([
            ("error_category".into(), error.category.as_str().into()),
            ("error".into(), error.message.clone()),
        ]),
    }
}

/// Expose executable metadata helpers for tests and live probe wiring.
#[must_use]
pub fn executable_identity(path: &Path) -> Option<(u64, u64)> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    let modified = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some((metadata.len(), modified))
}

/// Test seam: collect with explicit profile roots and optional candidate.
#[cfg(test)]
pub(crate) fn collect_browser_for_test(
    browser: &Browser,
    executable: Result<PathBuf>,
    browser_version: Option<String>,
    cdm_target: Result<PathBuf>,
    candidate: Option<&CachedCdm>,
    profile_roots: &[PathBuf],
) -> BrowserDiagnostics {
    collect_browser_at(
        browser,
        executable,
        browser_version,
        cdm_target,
        candidate,
        Some(profile_roots),
    )
}

mod external;
#[cfg(test)]
mod tests;
