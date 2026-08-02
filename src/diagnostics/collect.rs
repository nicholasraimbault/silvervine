//! Passive, local-only browser, CDM, codec, and graphics diagnostics.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

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
    match crate::widevine::cache::validated_current_readonly() {
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
                    ("error".into(), error.message),
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
    let external = collect_external_cdms(browser, profile_roots);
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
        checks.push(macos::codesign_check(browser.install_path()));
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
    profile_scope_complete: bool,
}

/// Maximum normal profile directories inspected under one user-data root.
const MAX_PROFILES_PER_USER_DATA_ROOT: usize = 16;
/// Maximum directory entries examined while discovering profile folders.
const MAX_USER_DATA_DIR_ENTRIES: usize = 64;
/// Maximum `profile.info_cache` entries accepted from Local State.
const MAX_LOCAL_STATE_PROFILE_ENTRIES: usize = 16;
/// Local State / Preferences size cap for bounded metadata reads.
const MAX_PROFILE_METADATA_BYTES: u64 = 1024 * 1024;

fn collect_external_cdms(browser: &Browser, profile_roots: Option<&[PathBuf]>) -> ExternalEvidence {
    let (roots, mut profile_scope_complete) = match profile_roots {
        // Explicit roots (including empty) are a deliberate test/production seam:
        // completeness still depends on successful bounded inspection of each root.
        Some(roots) => (roots.to_vec(), true),
        None => match default_profile_roots(browser) {
            Some(roots) => (roots, true),
            None => (Vec::new(), false),
        },
    };
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();

    for root in roots {
        match collect_from_user_data_root(&root) {
            UserDataCollection::Missing => {}
            UserDataCollection::Incomplete { hints: root_hints } => {
                profile_scope_complete = false;
                merge_external_hints(&mut hints, &mut seen, root_hints);
            }
            UserDataCollection::Complete { hints: root_hints } => {
                merge_external_hints(&mut hints, &mut seen, root_hints);
            }
        }
    }

    let checks = external_checks(&hints, profile_scope_complete);

    ExternalEvidence {
        hints,
        checks,
        profile_scope_complete,
    }
}

enum UserDataCollection {
    /// User-data root is absent; alternate install locations may legitimately miss.
    Missing,
    Complete {
        hints: Vec<ExternalCdmHint>,
    },
    Incomplete {
        hints: Vec<ExternalCdmHint>,
    },
}

fn merge_external_hints(
    hints: &mut Vec<ExternalCdmHint>,
    seen: &mut BTreeSet<String>,
    incoming: Vec<ExternalCdmHint>,
) {
    for hint in incoming {
        push_unique_hint(hints, seen, hint);
    }
}

fn canonical_user_data_root(root: &Path) -> std::result::Result<Option<PathBuf>, ()> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(());
    }
    fs::canonicalize(root).map(Some).map_err(|_| ())
}

fn collect_from_user_data_root(root: &Path) -> UserDataCollection {
    let canonical_root = match canonical_user_data_root(root) {
        Ok(Some(root)) => root,
        Ok(None) => return UserDataCollection::Missing,
        Err(()) => return UserDataCollection::Incomplete { hints: Vec::new() },
    };

    let mut complete = true;
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();

    // Root-level evidence (component caches occasionally live beside profiles).
    if !collect_profile_dir_evidence(&canonical_root, &canonical_root, &mut hints, &mut seen) {
        complete = false;
    }

    let local_state_path = canonical_root.join("Local State");
    let mut named_profiles: BTreeSet<String> = BTreeSet::new();
    let mut required_profiles: BTreeSet<String> = BTreeSet::new();

    match read_bounded_metadata_file(&canonical_root, &local_state_path) {
        MetadataFile::Absent => {}
        MetadataFile::Invalid => complete = false,
        MetadataFile::Present(bytes) => match parse_local_state_profiles(&bytes) {
            LocalStateProfiles::Invalid => complete = false,
            LocalStateProfiles::Parsed(profiles) => {
                if profiles.truncated {
                    complete = false;
                }
                for name in &profiles.names {
                    named_profiles.insert(name.clone());
                    required_profiles.insert(name.clone());
                }
                if let Some(last_used) = profiles.last_used.as_ref() {
                    if is_plausible_profile_dir_name(last_used) {
                        named_profiles.insert(last_used.clone());
                        required_profiles.insert(last_used.clone());
                    } else {
                        complete = false;
                    }
                }
                for name in &profiles.last_active {
                    if is_plausible_profile_dir_name(name) {
                        named_profiles.insert(name.clone());
                        required_profiles.insert(name.clone());
                    } else {
                        complete = false;
                    }
                }
                match collect_component_hints_from_metadata(
                    &canonical_root,
                    &bytes,
                    &mut hints,
                    &mut seen,
                ) {
                    MetadataComponentRead::Ok => {}
                    MetadataComponentRead::Invalid => complete = false,
                }
            }
        },
    }

    match scan_normal_profile_dir_names(&canonical_root) {
        ProfileDirScan::Failed => complete = false,
        ProfileDirScan::Scanned {
            names: dir_names,
            truncated,
        } => {
            if truncated {
                complete = false;
            }
            named_profiles.extend(dir_names);
        }
    }

    // Always consider Default when present so single-profile installs stay complete
    // even without Local State profile metadata.
    if canonical_root.join("Default").is_dir() {
        named_profiles.insert("Default".into());
    }

    for name in named_profiles {
        match inspect_named_profile(&canonical_root, &name, &mut hints, &mut seen) {
            ProfileInspect::Collected => {}
            ProfileInspect::Missing => {
                if required_profiles.contains(&name) {
                    complete = false;
                }
            }
            ProfileInspect::Failed => complete = false,
        }
    }

    let root_preferences = canonical_root.join("Preferences");
    match read_and_collect_component_hints(
        &canonical_root,
        &root_preferences,
        &mut hints,
        &mut seen,
    ) {
        MetadataComponentRead::Ok => {}
        MetadataComponentRead::Invalid => complete = false,
    }

    if complete {
        UserDataCollection::Complete { hints }
    } else {
        UserDataCollection::Incomplete { hints }
    }
}

struct LocalStateProfileSet {
    names: BTreeSet<String>,
    last_used: Option<String>,
    last_active: Vec<String>,
    truncated: bool,
}

enum LocalStateProfiles {
    Invalid,
    Parsed(LocalStateProfileSet),
}

fn parse_local_state_profiles(bytes: &[u8]) -> LocalStateProfiles {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return LocalStateProfiles::Invalid,
    };
    let Some(profile) = value.get("profile") else {
        // Brand-new or minimal Local State may omit profile metadata; directory
        // inspection remains authoritative for Default / Profile N.
        return LocalStateProfiles::Parsed(LocalStateProfileSet {
            names: BTreeSet::new(),
            last_used: None,
            last_active: Vec::new(),
            truncated: false,
        });
    };
    if !profile.is_object() {
        return LocalStateProfiles::Invalid;
    }

    let mut names = BTreeSet::new();
    let mut truncated = false;
    if let Some(info_cache) = profile.get("info_cache") {
        let Some(map) = info_cache.as_object() else {
            return LocalStateProfiles::Invalid;
        };
        for (idx, key) in map.keys().enumerate() {
            if idx >= MAX_LOCAL_STATE_PROFILE_ENTRIES {
                truncated = true;
                break;
            }
            if !is_plausible_profile_dir_name(key) {
                return LocalStateProfiles::Invalid;
            }
            names.insert(key.clone());
        }
        if map.len() > MAX_LOCAL_STATE_PROFILE_ENTRIES {
            truncated = true;
        }
    }

    let last_used = match profile.get("last_used") {
        None => None,
        Some(serde_json::Value::String(name)) => {
            let name = name.trim();
            if name.is_empty() || name.len() > 64 {
                return LocalStateProfiles::Invalid;
            }
            Some(name.to_owned())
        }
        Some(_) => return LocalStateProfiles::Invalid,
    };

    let mut last_active = Vec::new();
    if let Some(active) = profile.get("last_active_profiles") {
        let Some(items) = active.as_array() else {
            return LocalStateProfiles::Invalid;
        };
        for (idx, item) in items.iter().enumerate() {
            if idx >= MAX_LOCAL_STATE_PROFILE_ENTRIES {
                truncated = true;
                break;
            }
            match item.as_str().map(str::trim) {
                Some(name) if !name.is_empty() && name.len() <= 64 => {
                    last_active.push(name.to_owned());
                }
                _ => return LocalStateProfiles::Invalid,
            }
        }
        if items.len() > MAX_LOCAL_STATE_PROFILE_ENTRIES {
            truncated = true;
        }
    }

    LocalStateProfiles::Parsed(LocalStateProfileSet {
        names,
        last_used,
        last_active,
        truncated,
    })
}

enum ProfileDirScan {
    Failed,
    Scanned {
        names: BTreeSet<String>,
        truncated: bool,
    },
}

fn scan_normal_profile_dir_names(root: &Path) -> ProfileDirScan {
    let Ok(entries) = fs::read_dir(root) else {
        return ProfileDirScan::Failed;
    };
    let mut names = BTreeSet::new();
    let mut examined = 0_usize;
    let mut truncated = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return ProfileDirScan::Failed;
        };
        examined += 1;
        if examined > MAX_USER_DATA_DIR_ENTRIES {
            truncated = true;
            break;
        }
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        if !is_plausible_profile_dir_name(name) {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            return ProfileDirScan::Failed;
        };
        if metadata.file_type().is_symlink() {
            // Profile directory symlinks are not followed; presence makes scope incomplete.
            truncated = true;
            continue;
        }
        if metadata.is_dir() {
            if names.len() >= MAX_PROFILES_PER_USER_DATA_ROOT {
                truncated = true;
                break;
            }
            names.insert(name.to_owned());
        }
    }
    ProfileDirScan::Scanned { names, truncated }
}

fn is_plausible_profile_dir_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 || name.contains('/') || name.contains('\\') {
        return false;
    }
    if name == "Default" || name == "Guest Profile" || name == "System Profile" {
        return true;
    }
    let Some(suffix) = name.strip_prefix("Profile ") else {
        return false;
    };
    !suffix.is_empty() && suffix.len() <= 8 && suffix.chars().all(|c| c.is_ascii_digit())
}

enum ProfileInspect {
    Collected,
    Missing,
    Failed,
}

fn inspect_named_profile(
    user_data_root: &Path,
    name: &str,
    hints: &mut Vec<ExternalCdmHint>,
    seen: &mut BTreeSet<String>,
) -> ProfileInspect {
    let profile_dir = user_data_root.join(name);
    let metadata = match fs::symlink_metadata(&profile_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProfileInspect::Missing;
        }
        Err(_) => return ProfileInspect::Failed,
    };
    if metadata.file_type().is_symlink() {
        return ProfileInspect::Failed;
    }
    if !metadata.is_dir() {
        return ProfileInspect::Failed;
    }
    let Ok(canonical_profile) = fs::canonicalize(&profile_dir) else {
        return ProfileInspect::Failed;
    };
    if !canonical_profile.starts_with(user_data_root) {
        return ProfileInspect::Failed;
    }

    if !collect_profile_dir_evidence(user_data_root, &canonical_profile, hints, seen) {
        return ProfileInspect::Failed;
    }

    let prefs = canonical_profile.join("Preferences");
    match read_and_collect_component_hints(user_data_root, &prefs, hints, seen) {
        MetadataComponentRead::Ok => ProfileInspect::Collected,
        MetadataComponentRead::Invalid => ProfileInspect::Failed,
    }
}

fn collect_profile_dir_evidence(
    containment_root: &Path,
    profile_dir: &Path,
    hints: &mut Vec<ExternalCdmHint>,
    seen: &mut BTreeSet<String>,
) -> bool {
    let widevine = profile_dir.join("WidevineCdm");
    let metadata = match fs::symlink_metadata(&widevine) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
        Err(_) => return false,
    };
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return false;
    }

    let Some(hint) = inspect_external_hint(
        containment_root,
        &widevine,
        ExternalCdmOrigin::ProfileWidevineCdm,
    ) else {
        return false;
    };
    push_unique_hint(hints, seen, hint);
    true
}

fn push_unique_hint(
    hints: &mut Vec<ExternalCdmHint>,
    seen: &mut BTreeSet<String>,
    hint: ExternalCdmHint,
) {
    let key = canonicalize_path(&hint.path).map_or_else(
        |_| hint.path.display().to_string(),
        |path| path.display().to_string(),
    );
    if seen.insert(key) {
        hints.push(hint);
    }
}

enum MetadataFile {
    Absent,
    Invalid,
    Present(Vec<u8>),
}

fn read_bounded_metadata_file(containment_root: &Path, path: &Path) -> MetadataFile {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return MetadataFile::Absent,
        Err(_) => return MetadataFile::Invalid,
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_PROFILE_METADATA_BYTES
        || !is_contained(containment_root, path)
    {
        return MetadataFile::Invalid;
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let Ok(mut file) = options.open(path) else {
        return MetadataFile::Invalid;
    };
    let Ok(opened) = file.metadata() else {
        return MetadataFile::Invalid;
    };
    if !opened.is_file() || opened.len() > MAX_PROFILE_METADATA_BYTES {
        return MetadataFile::Invalid;
    }

    let mut bytes = Vec::with_capacity(
        usize::try_from(opened.len())
            .unwrap_or(0)
            .min(usize::try_from(MAX_PROFILE_METADATA_BYTES).unwrap_or(usize::MAX)),
    );
    if (&mut file)
        .take(MAX_PROFILE_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_PROFILE_METADATA_BYTES
    {
        return MetadataFile::Invalid;
    }
    MetadataFile::Present(bytes)
}

enum MetadataComponentRead {
    Ok,
    Invalid,
}

fn read_and_collect_component_hints(
    containment_root: &Path,
    prefs_path: &Path,
    hints: &mut Vec<ExternalCdmHint>,
    seen: &mut BTreeSet<String>,
) -> MetadataComponentRead {
    match read_bounded_metadata_file(containment_root, prefs_path) {
        MetadataFile::Absent => MetadataComponentRead::Ok,
        MetadataFile::Invalid => MetadataComponentRead::Invalid,
        MetadataFile::Present(bytes) => {
            collect_component_hints_from_metadata(containment_root, &bytes, hints, seen)
        }
    }
}

fn collect_component_hints_from_metadata(
    containment_root: &Path,
    bytes: &[u8],
    hints: &mut Vec<ExternalCdmHint>,
    seen: &mut BTreeSet<String>,
) -> MetadataComponentRead {
    let value: serde_json::Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return MetadataComponentRead::Invalid,
    };
    let mut paths = Vec::new();
    let mut complete = collect_component_paths_from_json(&value, containment_root, &mut paths, 0);
    for path in paths {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                complete = false;
                continue;
            }
            Ok(_) => {}
        }
        if let Some(hint) =
            inspect_external_hint(containment_root, &path, ExternalCdmOrigin::ComponentUpdater)
        {
            push_unique_hint(hints, seen, hint);
        } else {
            complete = false;
        }
    }
    if complete {
        MetadataComponentRead::Ok
    } else {
        MetadataComponentRead::Invalid
    }
}

fn external_checks(
    hints: &[ExternalCdmHint],
    profile_scope_complete: bool,
) -> Vec<DiagnosticCheck> {
    if hints.is_empty() {
        let (summary, details) = if profile_scope_complete {
            (
                "No external profile/component Widevine CDM hints were found.".into(),
                BTreeMap::new(),
            )
        } else {
            (
                "External profile/component roots are unknown for this browser; persistent probe caching is disabled."
                    .into(),
                BTreeMap::from([("profile_scope_complete".into(), "false".into())]),
            )
        };
        return vec![DiagnosticCheck {
            id: "cdm.external_components".into(),
            status: DiagnosticStatus::Unavailable,
            source: EvidenceSource::HostProbe,
            failure_domain: FailureDomain::BrowserMediaStack,
            summary,
            action: None,
            details,
        }];
    }

    hints
        .iter()
        .map(|hint| {
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
            DiagnosticCheck {
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
            }
        })
        .collect()
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

fn collect_component_paths_from_json(
    value: &serde_json::Value,
    profile_root: &Path,
    out: &mut Vec<PathBuf>,
    depth: usize,
) -> bool {
    if depth > 8 || out.len() >= 8 {
        return false;
    }
    match value {
        serde_json::Value::Object(map) => {
            let mut complete = true;
            for (key, child) in map {
                let key_l = key.to_ascii_lowercase();
                if (key_l.contains("latest-component-updated-widevine-cdm")
                    || (key_l.contains("widevine") && key_l.contains("component")))
                    && !push_component_path_value(child, profile_root, out)
                {
                    complete = false;
                }
                if !collect_component_paths_from_json(child, profile_root, out, depth + 1) {
                    complete = false;
                }
            }
            complete
        }
        serde_json::Value::Array(items) => {
            let mut complete = true;
            for item in items {
                if !collect_component_paths_from_json(item, profile_root, out, depth + 1) {
                    complete = false;
                }
            }
            complete
        }
        _ => true,
    }
}

fn push_component_path_value(
    value: &serde_json::Value,
    profile_root: &Path,
    out: &mut Vec<PathBuf>,
) -> bool {
    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() || trimmed.len() > 512 {
                return true;
            }
            // Ignore pure version tokens.
            if trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return true;
            }
            let path = if trimmed.starts_with('/')
                || (trimmed.len() > 2 && trimmed.as_bytes()[1] == b':')
            {
                PathBuf::from(trimmed)
            } else {
                profile_root.join(trimmed)
            };
            if out.contains(&path) {
                return true;
            }
            if out.len() >= 8 {
                return false;
            }
            out.push(path);
            true
        }
        serde_json::Value::Object(map) => {
            let mut complete = true;
            for key in ["path", "full_path", "install_full_path", "component_path"] {
                if let Some(child) = map.get(key) {
                    complete &= push_component_path_value(child, profile_root, out);
                }
            }
            // Sometimes the value is just { "version": "x", ... } beside a path sibling;
            // also accept nested path-like strings.
            for (key, child) in map {
                if key.to_ascii_lowercase().contains("path") {
                    complete &= push_component_path_value(child, profile_root, out);
                }
            }
            complete
        }
        serde_json::Value::Array(items) => {
            let mut complete = true;
            for item in items {
                complete &= push_component_path_value(item, profile_root, out);
            }
            complete
        }
        _ => true,
    }
}

fn default_profile_roots(browser: &Browser) -> Option<Vec<PathBuf>> {
    if browser.kind != crate::browsers::BrowserKind::Known {
        return None;
    }
    let name = browser.name().to_ascii_lowercase();

    #[cfg(target_os = "linux")]
    {
        let config = dirs::config_dir()?;
        let suffixes = profile_config_suffixes(&name);
        if suffixes.is_empty() {
            return None;
        }
        let mut roots = suffixes
            .into_iter()
            .map(|suffix| config.join(suffix))
            .collect::<Vec<_>>();
        if name == "chromium" {
            let home = dirs::home_dir()?;
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
        Some(roots)
    }

    #[cfg(target_os = "macos")]
    {
        let suffixes = profile_support_suffixes(&name);
        if suffixes.is_empty() {
            return None;
        }
        let support = dirs::home_dir()?
            .join("Library")
            .join("Application Support");
        Some(
            suffixes
                .into_iter()
                .map(|suffix| support.join(suffix))
                .collect(),
        )
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = name;
        None
    }
}

#[cfg(target_os = "linux")]
fn profile_config_suffixes(name: &str) -> Vec<&'static str> {
    match name {
        "helium" => vec!["helium", "Helium"],
        "thorium" => vec!["thorium", "Thorium"],
        "ungoogled-chromium" => vec!["ungoogled-chromium"],
        "chromium" => vec!["chromium"],
        _ => Vec::new(),
    }
}

#[cfg(target_os = "macos")]
fn profile_support_suffixes(name: &str) -> Vec<&'static str> {
    match name {
        "helium" => vec!["Helium"],
        "thorium" => vec!["Thorium"],
        "ungoogled-chromium" => vec!["ungoogled-chromium"],
        "chromium" => vec!["Chromium"],
        _ => Vec::new(),
    }
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
        let manifest = br#"{"version":"4.10.0.0"}"#;
        fs::write(target.join("manifest.json"), manifest).expect("manifest");
        let library = test_library_bytes();
        fs::write(platform.join(test_library_name()), &library).expect("library");
        let cached = CachedCdm::from_verified_payload(
            "4.10.0.0".into(),
            target.clone(),
            crate::widevine::sha512_hex(&library),
            crate::widevine::sha512_hex(manifest),
        );
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
    fn detected_browser_without_authoritative_profile_roots_has_no_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let (target, digest) = managed_cdm(tmp.path());

        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Detected),
            Ok(std::env::current_exe().expect("test executable")),
            Some("150.0.1".into()),
            Ok(target),
            None,
            None,
        );

        assert_eq!(
            diagnostics.cdm_library_sha512.as_deref(),
            Some(digest.as_str())
        );
        assert_eq!(diagnostics.ownership.kind, OwnershipKind::Managed);
        assert!(
            diagnostics.fingerprint.is_none(),
            "partial profile scope must never persist as an exact cache key"
        );
    }

    #[test]
    fn missing_install_root_cdm_disables_probe_cache_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let target = tmp.path().join("WidevineCdm");
        let executable = std::env::current_exe().expect("test executable");

        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Known),
            Ok(executable),
            Some("150.0.1".into()),
            Ok(target),
            None,
            Some(&[]),
        );

        assert!(diagnostics.fingerprint.is_none());
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
            Some(&[]),
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
            Some(&[]),
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
            Some(&[]),
        );
        assert_eq!(diagnostics.ownership.kind, OwnershipKind::External);
        assert!(diagnostics.fingerprint.is_none());
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
            Some(&[]),
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

    fn write_profile_cdm(profile_dir: &std::path::Path, version: &str, library: &[u8]) {
        let component = profile_dir.join("WidevineCdm");
        let platform = component
            .join("_platform_specific")
            .join(test_platform_dir());
        fs::create_dir_all(&platform).expect("platform");
        fs::write(
            component.join("manifest.json"),
            format!(r#"{{"version":"{version}"}}"#),
        )
        .expect("manifest");
        fs::write(platform.join(test_library_name()), library).expect("library");
    }

    #[test]
    fn active_profile_one_cdm_joins_fingerprint_and_differs_from_default() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("install");
        let target = install.join("WidevineCdm");
        let user_data = tmp.path().join("chromium");
        fs::create_dir_all(user_data.join("Default")).expect("default");
        fs::create_dir_all(user_data.join("Profile 1")).expect("profile1");

        let default_library = test_library_bytes();
        let mut profile_library = test_library_bytes();
        // Ensure Profile 1 library digest differs from Default.
        if let Some(last) = profile_library.last_mut() {
            *last ^= 0x5a;
        }
        write_profile_cdm(&user_data.join("Default"), "4.10.1.1", &default_library);
        write_profile_cdm(&user_data.join("Profile 1"), "4.10.9.9", &profile_library);

        let local_state = serde_json::json!({
            "profile": {
                "info_cache": {
                    "Default": { "name": "Person 1" },
                    "Profile 1": { "name": "Work" }
                },
                "last_used": "Profile 1",
                "last_active_profiles": ["Profile 1"]
            }
        });
        fs::write(
            user_data.join("Local State"),
            serde_json::to_vec_pretty(&local_state).expect("json"),
        )
        .expect("local state");

        let diagnostics = collect_browser_for_test(
            &browser(&install, BrowserKind::Detected),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(target),
            None,
            &[user_data],
        );

        assert!(
            diagnostics
                .external_cdms
                .iter()
                .any(|hint| hint.version.as_deref() == Some("4.10.9.9")),
            "Profile 1 Widevine evidence must participate: {:?}",
            diagnostics.external_cdms
        );
        assert!(
            diagnostics
                .external_cdms
                .iter()
                .any(|hint| hint.version.as_deref() == Some("4.10.1.1")),
            "Default Widevine evidence must still be collected"
        );
        let fingerprint = diagnostics
            .fingerprint
            .expect("complete multi-profile scope must remain fingerprintable");
        assert!(fingerprint
            .cdm_entries
            .iter()
            .any(|entry| entry.version.as_deref() == Some("4.10.9.9")));
        assert!(fingerprint
            .cdm_entries
            .iter()
            .any(|entry| entry.version.as_deref() == Some("4.10.1.1")));
        let default_digest = diagnostics
            .external_cdms
            .iter()
            .find(|hint| hint.version.as_deref() == Some("4.10.1.1"))
            .and_then(|hint| hint.library_sha512.as_deref());
        let profile_digest = diagnostics
            .external_cdms
            .iter()
            .find(|hint| hint.version.as_deref() == Some("4.10.9.9"))
            .and_then(|hint| hint.library_sha512.as_deref());
        assert_ne!(default_digest, profile_digest);
    }

    #[test]
    fn unreadable_or_malformed_profile_metadata_suppresses_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("install");
        let target = install.join("WidevineCdm");
        let executable = std::env::current_exe().expect("exe");

        // Malformed Local State JSON.
        let malformed_root = tmp.path().join("malformed");
        fs::create_dir_all(malformed_root.join("Default")).expect("default");
        write_profile_cdm(
            &malformed_root.join("Default"),
            "4.10.2.2",
            &test_library_bytes(),
        );
        fs::write(malformed_root.join("Local State"), b"{not-json").expect("local state");
        let malformed = collect_browser_for_test(
            &browser(&install, BrowserKind::Detected),
            Ok(executable.clone()),
            Some("150.0.1".into()),
            Ok(target.clone()),
            None,
            &[malformed_root],
        );
        assert!(
            malformed.fingerprint.is_none(),
            "malformed Local State must suppress exact fingerprint"
        );

        // Oversized Preferences under an active profile.
        let oversized_root = tmp.path().join("oversized");
        fs::create_dir_all(oversized_root.join("Profile 1")).expect("profile");
        let local_state = serde_json::json!({
            "profile": {
                "info_cache": { "Profile 1": { "name": "Work" } },
                "last_used": "Profile 1"
            }
        });
        fs::write(
            oversized_root.join("Local State"),
            serde_json::to_vec_pretty(&local_state).expect("json"),
        )
        .expect("local state");
        let big = vec![b'x'; 1024 * 1024 + 8];
        fs::write(oversized_root.join("Profile 1").join("Preferences"), &big).expect("prefs");
        let oversized = collect_browser_for_test(
            &browser(&install, BrowserKind::Detected),
            Ok(executable.clone()),
            Some("150.0.1".into()),
            Ok(target.clone()),
            None,
            &[oversized_root],
        );
        assert!(
            oversized.fingerprint.is_none(),
            "oversized profile Preferences must suppress exact fingerprint"
        );

        // Truncated info_cache enumeration (>16 profiles listed).
        let truncated_root = tmp.path().join("truncated");
        fs::create_dir_all(truncated_root.join("Default")).expect("default");
        write_profile_cdm(
            &truncated_root.join("Default"),
            "4.10.3.3",
            &test_library_bytes(),
        );
        let mut info_cache = serde_json::Map::new();
        info_cache.insert("Default".into(), serde_json::json!({ "name": "Person 1" }));
        for idx in 1..=17 {
            let name = format!("Profile {idx}");
            fs::create_dir_all(truncated_root.join(&name)).expect("profile dir");
            info_cache.insert(name, serde_json::json!({ "name": format!("P{idx}") }));
        }
        let truncated_state = serde_json::json!({
            "profile": {
                "info_cache": info_cache,
                "last_used": "Default"
            }
        });
        fs::write(
            truncated_root.join("Local State"),
            serde_json::to_vec_pretty(&truncated_state).expect("json"),
        )
        .expect("local state");
        let truncated = collect_browser_for_test(
            &browser(&install, BrowserKind::Detected),
            Ok(executable),
            Some("150.0.1".into()),
            Ok(target),
            None,
            &[truncated_root],
        );
        assert!(
            truncated.fingerprint.is_none(),
            "bounded Local State truncation must suppress exact fingerprint"
        );
    }

    #[test]
    fn unrecognized_profile_metadata_suppresses_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("install");
        let user_data = tmp.path().join("chromium");
        fs::create_dir_all(&user_data).expect("user data");
        let local_state = serde_json::json!({
            "profile": {
                "info_cache": {
                    "unrecognized-profile-directory": { "name": "Unknown" }
                }
            }
        });
        fs::write(
            user_data.join("Local State"),
            serde_json::to_vec_pretty(&local_state).expect("json"),
        )
        .expect("local state");

        let diagnostics = collect_browser_for_test(
            &browser(&install, BrowserKind::Detected),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(install.join("WidevineCdm")),
            None,
            &[user_data],
        );

        assert!(
            diagnostics.fingerprint.is_none(),
            "an unrecognized profile directory in Local State makes scope incomplete"
        );
        assert_eq!(
            diagnostics
                .checks
                .iter()
                .find(|check| check.id == "cdm.external_components")
                .and_then(|check| check.details.get("profile_scope_complete"))
                .map(String::as_str),
            Some("false")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_profile_widevine_suppresses_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("install");
        let user_data = tmp.path().join("chromium");
        let default_profile = user_data.join("Default");
        fs::create_dir_all(&default_profile).expect("default");
        let outside = tmp.path().join("outside-widevine");
        fs::create_dir_all(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, default_profile.join("WidevineCdm"))
            .expect("widevine symlink");
        fs::write(
            user_data.join("Local State"),
            br#"{"profile":{"info_cache":{"Default":{}},"last_used":"Default"}}"#,
        )
        .expect("local state");

        let diagnostics = collect_browser_for_test(
            &browser(&install, BrowserKind::Detected),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(install.join("WidevineCdm")),
            None,
            &[user_data],
        );

        assert!(
            diagnostics.fingerprint.is_none(),
            "a profile CDM symlink must not be omitted from an exact fingerprint"
        );
        assert_eq!(
            diagnostics
                .checks
                .iter()
                .find(|check| check.id == "cdm.external_components")
                .and_then(|check| check.details.get("profile_scope_complete"))
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn unverified_cache_candidate_does_not_poison_ownership() {
        let tmp = TempDir::new().expect("tempdir");
        let target = unmarked_cdm(tmp.path());
        let unverified = CachedCdm::new("4.10.0.0".into(), target.clone());
        assert!(unverified.verified_library_sha512().is_none());

        let diagnostics = collect_browser_at(
            &browser(tmp.path(), BrowserKind::Known),
            Ok(std::env::current_exe().expect("exe")),
            Some("150.0.1".into()),
            Ok(target),
            Some(&unverified),
            Some(&[]),
        );

        assert_eq!(
            diagnostics.ownership.kind,
            OwnershipKind::External,
            "unverified cache handle must fall back to candidate-free classification"
        );
    }
}
