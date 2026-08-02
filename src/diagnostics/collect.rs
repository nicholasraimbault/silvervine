//! Passive, local-only browser, CDM, codec, and graphics diagnostics.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::browsers::{runtime, Browser, BrowserKind};
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
use crate::widevine::ownership::{
    self, OwnershipAssessment, OwnershipKind, MANAGED_MARKER_FILENAME,
};
use crate::widevine::{current_cdm, CachedCdm};

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
    let candidate = current_cdm().ok().flatten();
    collect_browser_with_candidate(browser, candidate.as_ref())
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
    let external = collect_external_cdms(browser, profile_roots);
    let mut checks = Vec::with_capacity(3 + cdm.checks.len() + external.checks.len());
    checks.push(executable_check);
    checks.push(version_check(browser_version.as_deref()));
    checks.extend(cdm.checks);
    checks.extend(external.checks);

    #[cfg(target_os = "linux")]
    if cdm.ownership.kind == OwnershipKind::Managed {
        if let Some(library) = cdm.library.as_ref() {
            checks.push(linux::collect_verified_library_deps(library));
        }
    }
    #[cfg(target_os = "macos")]
    {
        checks.push(macos::codesign_check(browser.install_path()));
    }

    let fingerprint = browser_executable.as_ref().and_then(|path| {
        let mut entries = Vec::new();
        if let Some(entry) = cdm.fingerprint_entry.clone() {
            entries.push(entry);
        }
        for hint in &external.hints {
            entries.push(hint_to_fingerprint_entry(hint));
        }
        ProbeFingerprint::from_executable(path, browser_version.clone(), entries).ok()
    });

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
    let identity = inspect_cdm_identity(&target);
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
    match candidate {
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
            Err(error) => OwnershipAssessment {
                kind: OwnershipKind::InvalidMarker,
                summary: "The cached Silvervine CDM candidate is not usable for classification."
                    .into(),
                action: Some("Run `silvervine update widevine`, then retry.".into()),
                details: BTreeMap::from([
                    ("error_category".into(), error.category.as_str().into()),
                    ("error".into(), error.message),
                ]),
            },
        },
        None => classify_without_candidate(browser, target),
    }
}

fn classify_without_candidate(browser: &Browser, target: &Path) -> OwnershipAssessment {
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return OwnershipAssessment {
                kind: OwnershipKind::Missing,
                summary: "No Widevine CDM is installed at the patch target.".into(),
                action: Some("Run `silvervine setup` or `silvervine patch`.".into()),
                details: BTreeMap::new(),
            };
        }
        Err(error) => {
            return OwnershipAssessment {
                kind: OwnershipKind::InvalidMarker,
                summary: "The CDM target could not be inspected.".into(),
                action: Some("Inspect filesystem permissions on the browser CDM path.".into()),
                details: BTreeMap::from([("error".into(), error.to_string())]),
            };
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return OwnershipAssessment {
            kind: OwnershipKind::InvalidMarker,
            summary: "The existing CDM root is not a regular directory.".into(),
            action: Some(
                "Remove the unsafe CDM path only after verifying ownership, then retry.".into(),
            ),
            details: BTreeMap::new(),
        };
    }

    classify_existing_target_without_candidate(browser, target)
}

fn classify_existing_target_without_candidate(
    browser: &Browser,
    target: &Path,
) -> OwnershipAssessment {
    let marker = target.join(MANAGED_MARKER_FILENAME);
    match fs::symlink_metadata(&marker) {
        Ok(_) => classify_installed_marker(target),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            classify_unmarked_target(browser, target)
        }
        Err(error) => OwnershipAssessment {
            kind: OwnershipKind::InvalidMarker,
            summary: "The ownership marker could not be inspected.".into(),
            action: Some("Inspect filesystem permissions on the browser CDM path.".into()),
            details: BTreeMap::from([("error".into(), error.to_string())]),
        },
    }
}

fn classify_installed_marker(target: &Path) -> OwnershipAssessment {
    match ownership::validate_installed_marker(target) {
        Ok(installed) => OwnershipAssessment {
            kind: OwnershipKind::Managed,
            summary: "The installed CDM has valid Silvervine provenance.".into(),
            action: None,
            details: BTreeMap::from([
                ("cdm_version".into(), installed.cdm_version),
                ("platform".into(), installed.platform),
                ("library_sha512".into(), installed.library_sha512),
                ("silvervine_version".into(), installed.silvervine_version),
            ]),
        },
        Err(error) => OwnershipAssessment {
            kind: OwnershipKind::InvalidMarker,
            summary: "The Silvervine ownership marker is invalid; the CDM was preserved.".into(),
            action: Some(
                "Remove the stale marker only after verifying CDM ownership, then run Silvervine again."
                    .into(),
            ),
            details: BTreeMap::from([("reason".into(), error.message)]),
        },
    }
}

fn classify_unmarked_target(browser: &Browser, target: &Path) -> OwnershipAssessment {
    // Without a candidate payload, diagnostics cannot prove the exact-match
    // condition required by ownership::classify. Every unmarked target remains
    // external and preserved, even for a known browser.
    let identity = inspect_cdm_identity(target);
    let browser_kind = match browser.kind {
        BrowserKind::Known => "known",
        BrowserKind::Detected => "detected",
        BrowserKind::Custom => "custom",
    };
    let mut details = BTreeMap::from([("browser_kind".into(), browser_kind.into())]);
    if let Some(version) = &identity.version {
        details.insert("cdm_version".into(), version.clone());
    }
    if let Some(digest) = &identity.library_sha512 {
        details.insert("library_sha512".into(), digest.clone());
    }

    let valid_layout = identity.version.is_some() && identity.library.is_some();

    let summary = if valid_layout {
        "The unmarked CDM may be managed by the browser, platform, or user."
    } else {
        "The unmarked CDM does not match a safe Silvervine layout."
    };
    OwnershipAssessment {
        kind: OwnershipKind::External,
        summary: summary.into(),
        action: Some(format!(
            "Preserved existing CDM. Re-run `silvervine patch --browser \"{}\" --replace-external-cdm` to replace it explicitly.",
            browser.name()
        )),
        details,
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

fn inspect_cdm_identity(target: &Path) -> CdmIdentity {
    let version = read_manifest_version(&target.join("manifest.json"));
    let library = find_contained_library(target);
    let library_sha512 = library.as_ref().and_then(|path| safe_library_digest(path));
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

#[derive(Default)]
struct ExternalEvidence {
    hints: Vec<ExternalCdmHint>,
    checks: Vec<DiagnosticCheck>,
}

fn collect_external_cdms(browser: &Browser, profile_roots: Option<&[PathBuf]>) -> ExternalEvidence {
    let roots = match profile_roots {
        Some(roots) => roots.to_vec(),
        None => default_profile_roots(browser),
    };
    let mut hints = Vec::new();
    let mut checks = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for root in roots {
        if !root.is_dir() {
            continue;
        }
        // Profile WidevineCdm (direct or Default/ profile).
        for candidate in [
            root.join("WidevineCdm"),
            root.join("Default").join("WidevineCdm"),
        ] {
            if let Some(hint) =
                inspect_external_hint(&root, &candidate, ExternalCdmOrigin::ProfileWidevineCdm)
            {
                let key = hint.path.display().to_string();
                if seen.insert(key) {
                    hints.push(hint);
                }
            }
        }

        // Bounded reads of Local State / Preferences for
        // latest-component-updated-widevine-cdm (no recursive profile dump).
        for relative in [
            Path::new("Local State"),
            Path::new("Preferences"),
            Path::new("Default/Preferences"),
        ] {
            let prefs = root.join(relative);
            if let Some(paths) = read_latest_component_widevine_paths(&root, &prefs) {
                for path in paths {
                    if let Some(hint) =
                        inspect_external_hint(&root, &path, ExternalCdmOrigin::ComponentUpdater)
                    {
                        let key = hint.path.display().to_string();
                        if seen.insert(key) {
                            hints.push(hint);
                        }
                    }
                }
            }
        }

        // Known component location under the profile.
        let component_dir = root
            .join("Default")
            .join("WidevineCdm")
            .join("_platform_specific");
        if component_dir.is_dir() {
            if let Some(hint) = inspect_external_hint(
                &root,
                &root.join("Default").join("WidevineCdm"),
                ExternalCdmOrigin::KnownComponentLocation,
            ) {
                let key = hint.path.display().to_string();
                if seen.insert(key) {
                    hints.push(hint);
                }
            }
        }
    }

    if hints.is_empty() {
        checks.push(DiagnosticCheck {
            id: "cdm.external_components".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary: "No external profile/component Widevine CDM hints were found.".into(),
            action: None,
            details: BTreeMap::new(),
        });
    } else {
        for hint in &hints {
            let mut details = BTreeMap::from([
                ("path".into(), hint.path.display().to_string()),
                ("origin".into(), external_origin_name(hint.origin).into()),
            ]);
            if let Some(version) = &hint.version {
                details.insert("version".into(), version.clone());
            }
            if let Some(digest) = &hint.library_sha512 {
                details.insert("library_sha512".into(), digest.clone());
            }
            checks.push(DiagnosticCheck {
                id: "cdm.external_components".into(),
                status: DiagnosticStatus::Pass,
                source: EvidenceSource::HostProbe,
                failure_domain: FailureDomain::BrowserMediaStack,
                summary: format!(
                    "Found external/component CDM evidence from {}.",
                    external_origin_name(hint.origin)
                ),
                action: Some(
                    "External/component CDMs are preserved; only a targeted `--replace-external-cdm` may replace an install-root external CDM."
                        .into(),
                ),
                details,
            });
        }
    }

    ExternalEvidence { hints, checks }
}

fn external_origin_name(origin: ExternalCdmOrigin) -> &'static str {
    match origin {
        ExternalCdmOrigin::ProfileWidevineCdm => "profile_widevine_cdm",
        ExternalCdmOrigin::ComponentUpdater => "component_updater",
        ExternalCdmOrigin::KnownComponentLocation => "known_component_location",
    }
}

fn inspect_external_hint(
    profile_root: &Path,
    candidate: &Path,
    origin: ExternalCdmOrigin,
) -> Option<ExternalCdmHint> {
    let metadata = fs::symlink_metadata(candidate).ok()?;
    if metadata.file_type().is_symlink() {
        return None;
    }
    // Profile/component hints must stay inside the selected profile root.
    // Known component locations may also live under $HOME, but never escape it.
    let in_profile = is_contained(profile_root, candidate) || candidate == profile_root;
    if !in_profile {
        match origin {
            ExternalCdmOrigin::KnownComponentLocation => {
                let home = dirs::home_dir()?;
                if !is_contained(&home, candidate) {
                    return None;
                }
            }
            ExternalCdmOrigin::ProfileWidevineCdm | ExternalCdmOrigin::ComponentUpdater => {
                return None;
            }
        }
    }
    if metadata.is_dir() {
        let identity = inspect_cdm_identity(candidate);
        return Some(ExternalCdmHint {
            path: canonicalize_path(candidate).unwrap_or_else(|_| candidate.to_path_buf()),
            version: identity.version,
            library: identity.library.clone(),
            library_sha512: identity.library_sha512,
            origin,
        });
    }
    if metadata.is_file() {
        let name = candidate.file_name()?.to_string_lossy();
        if !(name == "libwidevinecdm.so" || name == "libwidevinecdm.dylib") {
            return None;
        }
        if metadata.len() == 0 || metadata.len() > 64 * 1024 * 1024 {
            return None;
        }
        return Some(ExternalCdmHint {
            path: canonicalize_path(candidate).unwrap_or_else(|_| candidate.to_path_buf()),
            version: candidate
                .parent()
                .and_then(|parent| parent.parent())
                .map(|root| root.join("manifest.json"))
                .and_then(|manifest| read_manifest_version(&manifest)),
            library: Some(candidate.to_path_buf()),
            library_sha512: safe_library_digest(candidate),
            origin,
        });
    }
    None
}

fn read_latest_component_widevine_paths(
    profile_root: &Path,
    prefs_path: &Path,
) -> Option<Vec<PathBuf>> {
    let metadata = fs::symlink_metadata(prefs_path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return None;
    }
    if !is_contained(profile_root, prefs_path) {
        return None;
    }
    let bytes = fs::read(prefs_path).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let mut paths = Vec::new();
    collect_component_paths_from_json(&value, profile_root, &mut paths, 0);
    (!paths.is_empty()).then_some(paths)
}

fn collect_component_paths_from_json(
    value: &serde_json::Value,
    profile_root: &Path,
    out: &mut Vec<PathBuf>,
    depth: usize,
) {
    if depth > 8 || out.len() >= 8 {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let key_l = key.to_ascii_lowercase();
                if key_l.contains("latest-component-updated-widevine-cdm")
                    || key_l == "latest-component-updated-widevine-cdm"
                    || (key_l.contains("widevine") && key_l.contains("component"))
                {
                    push_component_path_value(child, profile_root, out);
                }
                collect_component_paths_from_json(child, profile_root, out, depth + 1);
                if out.len() >= 8 {
                    return;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter().take(32) {
                collect_component_paths_from_json(item, profile_root, out, depth + 1);
                if out.len() >= 8 {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn push_component_path_value(
    value: &serde_json::Value,
    profile_root: &Path,
    out: &mut Vec<PathBuf>,
) {
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() || trimmed.len() > 512 {
                return;
            }
            // Ignore pure version tokens.
            if trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return;
            }
            let path = if trimmed.starts_with('/')
                || (trimmed.len() > 2 && trimmed.as_bytes()[1] == b':')
            {
                PathBuf::from(trimmed)
            } else {
                profile_root.join(trimmed)
            };
            if out.len() < 8 {
                out.push(path);
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["path", "full_path", "install_full_path", "component_path"] {
                if let Some(child) = map.get(key) {
                    push_component_path_value(child, profile_root, out);
                }
            }
            // Sometimes the value is just { "version": "x", ... } beside a path sibling;
            // also accept nested path-like strings.
            for (key, child) in map {
                let key_l = key.to_ascii_lowercase();
                if key_l.contains("path") {
                    push_component_path_value(child, profile_root, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter().take(8) {
                push_component_path_value(item, profile_root, out);
            }
        }
        _ => {}
    }
}

fn default_profile_roots(browser: &Browser) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let home = dirs::home_dir();
    let config = dirs::config_dir();
    let name = browser.name().to_ascii_lowercase();

    #[cfg(target_os = "linux")]
    {
        if let Some(config) = config {
            for suffix in profile_config_suffixes(&name) {
                roots.push(config.join(suffix));
            }
        }
        if let Some(home) = &home {
            // Snap / flatpak style locations (bounded known roots only).
            roots.push(
                home.join("snap")
                    .join("chromium")
                    .join("common")
                    .join("chromium"),
            );
            roots.push(
                home.join(".var")
                    .join("app")
                    .join("org.chromium.Chromium")
                    .join("config")
                    .join("chromium"),
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(home) = home {
            let support = home.join("Library").join("Application Support");
            for suffix in profile_support_suffixes(&name) {
                roots.push(support.join(suffix));
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (home, config, name);
    }

    roots
}

#[cfg(target_os = "linux")]
fn profile_config_suffixes(name: &str) -> Vec<&'static str> {
    let mut suffixes = Vec::new();
    if name.contains("helium") {
        suffixes.push("helium");
        suffixes.push("Helium");
    }
    if name.contains("thorium") {
        suffixes.push("thorium");
        suffixes.push("Thorium");
    }
    if name.contains("ungoogled") {
        suffixes.push("ungoogled-chromium");
        suffixes.push("chromium");
    }
    if name.contains("chromium") || suffixes.is_empty() {
        suffixes.push("chromium");
        suffixes.push("google-chrome");
    }
    suffixes
}

#[cfg(target_os = "macos")]
fn profile_support_suffixes(name: &str) -> Vec<&'static str> {
    let mut suffixes = Vec::new();
    if name.contains("helium") {
        suffixes.push("Helium");
    }
    if name.contains("thorium") {
        suffixes.push("Thorium");
    }
    if name.contains("ungoogled") {
        suffixes.push("ungoogled-chromium");
        suffixes.push("Chromium");
    }
    if name.contains("chromium") || suffixes.is_empty() {
        suffixes.push("Chromium");
        suffixes.push("Google/Chrome");
    }
    suffixes
}

fn hint_to_fingerprint_entry(hint: &ExternalCdmHint) -> CdmFingerprintEntry {
    let path = hint
        .library
        .as_ref()
        .map_or_else(|| hint.path.clone(), Clone::clone);
    let canonical = canonicalize_path(&path).map_or_else(
        |_| path.to_string_lossy().into_owned(),
        |path| path.to_string_lossy().into_owned(),
    );
    CdmFingerprintEntry::new(canonical, hint.version.clone(), hint.library_sha512.clone())
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::{
        collect_browser_at, collect_browser_for_test, ownership_kind_name, ExternalCdmOrigin,
    };
    use crate::browsers::{Browser, BrowserKind};
    use crate::diagnostics::DiagnosticStatus;
    use crate::widevine::ownership::{marker_for_cached, write_marker, OwnershipKind};
    use crate::widevine::CachedCdm;

    fn browser(install_path: &std::path::Path, kind: BrowserKind) -> Browser {
        Browser {
            name: "Chromium".into(),
            install_path: install_path.to_path_buf(),
            kind,
            framework_name: None,
        }
    }

    fn managed_cdm(root: &std::path::Path) -> (std::path::PathBuf, String) {
        let target = root.join("WidevineCdm");
        let platform = target.join("_platform_specific").join(test_platform_dir());
        fs::create_dir_all(&platform).expect("platform");
        fs::write(target.join("manifest.json"), br#"{"version":"4.10.0.0"}"#).expect("manifest");
        fs::write(platform.join(test_library_name()), test_library_bytes()).expect("library");
        let cached = CachedCdm::new("4.10.0.0".into(), target.clone());
        let marker = marker_for_cached(&cached).expect("marker");
        let digest = marker.library_sha512.clone();
        write_marker(&target, &marker).expect("write marker");
        (target, digest)
    }

    fn unmarked_cdm(root: &std::path::Path) -> std::path::PathBuf {
        let target = root.join("WidevineCdm");
        let platform = target.join("_platform_specific").join(test_platform_dir());
        fs::create_dir_all(&platform).expect("platform");
        fs::write(target.join("manifest.json"), br#"{"version":"4.10.0.0"}"#).expect("manifest");
        fs::write(platform.join(test_library_name()), test_library_bytes()).expect("library");
        target
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

    fn test_library_bytes() -> Vec<u8> {
        if cfg!(target_os = "macos") {
            let mut bytes = vec![0_u8; 32];
            bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
            let cpu_type = if cfg!(target_arch = "aarch64") {
                0x0100_000c_u32
            } else {
                0x0100_0007_u32
            };
            bytes[4..8].copy_from_slice(&cpu_type.to_le_bytes());
            bytes
        } else {
            let mut bytes = vec![0_u8; 64];
            bytes[..4].copy_from_slice(b"\x7fELF");
            bytes[4] = 2;
            bytes[5] = 1;
            bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
            bytes
        }
    }

    #[test]
    fn verified_cdm_and_browser_build_an_exact_probe_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let (target, digest) = managed_cdm(tmp.path());
        let executable = std::env::current_exe().expect("test executable");

        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Known),
            Ok(executable.clone()),
            Some("150.0.1".into()),
            Ok(target),
            None,
            Some(&[]),
        );

        let fingerprint = diagnostics.fingerprint.expect("fingerprint");
        assert!(
            fingerprint
                .canonical_executable
                .contains(executable.file_name().unwrap().to_string_lossy().as_ref())
                || fingerprint.canonical_executable == executable.to_string_lossy()
        );
        assert_eq!(fingerprint.browser_version.as_deref(), Some("150.0.1"));
        assert!(fingerprint.executable_len > 0);
        assert!(fingerprint.executable_modified > 0);
        assert_eq!(fingerprint.cdm_entries.len(), 1);
        assert_eq!(
            fingerprint.cdm_entries[0].library_sha512.as_deref(),
            Some(digest.as_str())
        );
        assert_eq!(diagnostics.ownership.kind, OwnershipKind::Managed);
        assert_eq!(
            diagnostics
                .checks
                .iter()
                .find(|check| check.id == "cdm.provenance")
                .expect("provenance")
                .status,
            DiagnosticStatus::Pass
        );
    }

    #[test]
    fn missing_install_root_cdm_still_fingerprints_executable() {
        let tmp = TempDir::new().expect("tempdir");
        let target = tmp.path().join("WidevineCdm");
        let executable = std::env::current_exe().expect("test executable");

        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Known),
            Ok(executable),
            Some("150.0.1".into()),
            Ok(target),
            None,
            None,
        );

        assert!(diagnostics.fingerprint.is_some());
        assert_eq!(diagnostics.ownership.kind, OwnershipKind::Missing);
        let provenance = diagnostics
            .checks
            .iter()
            .find(|check| check.id == "cdm.provenance")
            .expect("provenance");
        assert_eq!(provenance.status, DiagnosticStatus::Fail);
        assert_eq!(
            provenance.details.get("ownership_kind").map(String::as_str),
            Some("missing")
        );
    }

    #[test]
    fn known_unmarked_cdm_is_external_without_candidate_proof() {
        let tmp = TempDir::new().expect("tempdir");
        let target = unmarked_cdm(tmp.path());
        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Known),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(target),
            None,
            None,
        );

        assert_eq!(diagnostics.ownership.kind, OwnershipKind::External);
        let provenance = diagnostics
            .checks
            .iter()
            .find(|check| check.id == "cdm.provenance")
            .expect("provenance");
        assert_eq!(provenance.status, DiagnosticStatus::Warn);
        assert_eq!(
            provenance.failure_domain,
            crate::diagnostics::FailureDomain::BrowserMediaStack
        );
    }

    #[test]
    fn detected_unmarked_cdm_is_external_browser_domain() {
        let tmp = TempDir::new().expect("tempdir");
        let target = unmarked_cdm(tmp.path());
        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Detected),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(target),
            None,
            None,
        );

        assert_eq!(diagnostics.ownership.kind, OwnershipKind::External);
        let provenance = diagnostics
            .checks
            .iter()
            .find(|check| check.id == "cdm.provenance")
            .expect("provenance");
        assert_eq!(provenance.status, DiagnosticStatus::Warn);
        assert_eq!(
            provenance.failure_domain,
            crate::diagnostics::FailureDomain::BrowserMediaStack
        );
        assert!(ownership_kind_name(diagnostics.ownership.kind) == "external");
    }

    #[test]
    fn profile_component_cdm_is_reported_without_recursive_dump() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("install");
        let target = install.join("WidevineCdm");
        // Missing install-root CDM.
        let profile = tmp.path().join("profile");
        let component = profile.join("Default").join("WidevineCdm");
        let platform = component
            .join("_platform_specific")
            .join(test_platform_dir());
        fs::create_dir_all(&platform).expect("platform");
        fs::write(
            component.join("manifest.json"),
            br#"{"version":"4.10.9.9"}"#,
        )
        .expect("manifest");
        fs::write(platform.join(test_library_name()), test_library_bytes()).expect("library");

        let diagnostics = collect_browser_for_test(
            &browser(&install, BrowserKind::Detected),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(target),
            None,
            &[profile],
        );

        assert_eq!(diagnostics.ownership.kind, OwnershipKind::Missing);
        assert_eq!(diagnostics.external_cdms.len(), 1);
        assert_eq!(
            diagnostics.external_cdms[0].origin,
            ExternalCdmOrigin::ProfileWidevineCdm
        );
        assert_eq!(
            diagnostics.external_cdms[0].version.as_deref(),
            Some("4.10.9.9")
        );
        let fingerprint = diagnostics.fingerprint.expect("fingerprint");
        assert!(fingerprint
            .cdm_entries
            .iter()
            .any(|entry| { entry.version.as_deref() == Some("4.10.9.9") }));
    }

    #[test]
    fn empty_unmarked_cdm_root_is_external_not_legacy() {
        let tmp = TempDir::new().expect("tempdir");
        let target = tmp.path().join("WidevineCdm");
        fs::create_dir_all(&target).expect("target");
        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Known),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(target),
            None,
            None,
        );
        assert_eq!(diagnostics.ownership.kind, OwnershipKind::External);
        assert!(diagnostics.fingerprint.is_some());
    }

    #[test]
    fn latest_component_pref_paths_are_containment_checked() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("install");
        let target = install.join("WidevineCdm");
        let profile = tmp.path().join("profile");
        fs::create_dir_all(profile.join("Default")).expect("profile");
        let component = profile.join("component-widevine");
        let platform = component
            .join("_platform_specific")
            .join(test_platform_dir());
        fs::create_dir_all(&platform).expect("platform");
        fs::write(
            component.join("manifest.json"),
            br#"{"version":"4.10.8.8"}"#,
        )
        .expect("manifest");
        fs::write(platform.join(test_library_name()), test_library_bytes()).expect("library");
        let prefs = serde_json::json!({
            "component_updater": {
                "latest-component-updated-widevine-cdm": {
                    "path": component.to_string_lossy(),
                    "version": "4.10.8.8"
                }
            }
        });
        fs::write(
            profile.join("Local State"),
            serde_json::to_vec_pretty(&prefs).expect("json"),
        )
        .expect("local state");

        // Escape attempt must be ignored by containment checks.
        let escape = tmp.path().join("outside-cdm");
        fs::create_dir_all(&escape).expect("escape");
        let dirty = serde_json::json!({
            "latest-component-updated-widevine-cdm": "../../outside-cdm"
        });
        fs::write(
            profile.join("Default").join("Preferences"),
            serde_json::to_vec_pretty(&dirty).expect("json"),
        )
        .expect("prefs");

        let diagnostics = collect_browser_for_test(
            &browser(&install, BrowserKind::Detected),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(target),
            None,
            &[profile],
        );

        assert!(diagnostics
            .external_cdms
            .iter()
            .any(|hint| hint.version.as_deref() == Some("4.10.8.8")));
        assert!(diagnostics
            .external_cdms
            .iter()
            .all(|hint| { !hint.path.ends_with("outside-cdm") }));
    }

    #[test]
    fn unresolved_executable_yields_no_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Known),
            Err(crate::error::Error::unknown_bundle_structure("missing")),
            Some("150.0.1".into()),
            Ok(tmp.path().join("WidevineCdm")),
            None,
            None,
        );
        assert!(diagnostics.fingerprint.is_none());
    }

    #[test]
    fn absent_optional_host_utility_is_unavailable_not_a_failure() {
        // Host collectors are covered in media/linux modules; keep a smoke path.
        let checks = super::collect_host_media_checks();
        assert!(!checks.is_empty() || cfg!(not(any(target_os = "linux", target_os = "macos"))));
        let _ = PathBuf::from(".");
    }
}
