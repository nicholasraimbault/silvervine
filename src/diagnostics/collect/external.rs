//! Bounded profile/component CDM discovery without dumping browser profiles.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{
    inspect_cdm_identity, is_contained, read_manifest_version, safe_library_digest,
    ExternalCdmHint, ExternalCdmOrigin,
};
use crate::browsers::Browser;
use crate::diagnostics::store::{canonicalize_path, CdmFingerprintEntry};
use crate::diagnostics::{DiagnosticCheck, DiagnosticStatus, EvidenceSource, FailureDomain};

#[derive(Default)]
pub(super) struct ExternalEvidence {
    pub(super) hints: Vec<ExternalCdmHint>,
    pub(super) checks: Vec<DiagnosticCheck>,
    pub(super) profile_scope_complete: bool,
}

const MAX_PROFILES_PER_USER_DATA_ROOT: usize = 16;
const MAX_USER_DATA_DIR_ENTRIES: usize = 64;
const MAX_LOCAL_STATE_PROFILE_ENTRIES: usize = 16;
const MAX_PROFILE_METADATA_BYTES: u64 = 1024 * 1024;

pub(super) fn collect_external_cdms(
    browser: &Browser,
    profile_roots: Option<&[PathBuf]>,
    primary_target: Option<&Path>,
) -> ExternalEvidence {
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
    if let Some(primary_target) = primary_target.and_then(|target| canonicalize_path(target).ok()) {
        hints.retain(|hint| !hint_belongs_to_target(hint, &primary_target));
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

    let Some(root_hint) = inspect_external_hint(
        containment_root,
        &widevine,
        ExternalCdmOrigin::ProfileWidevineCdm,
    ) else {
        return false;
    };
    if root_hint.version.is_some() || root_hint.library.is_some() || metadata.is_file() {
        push_unique_hint(hints, seen, root_hint);
        return true;
    }

    let Ok(entries) = fs::read_dir(&widevine) else {
        return false;
    };
    let mut complete = true;
    let mut inspected = 0_usize;
    for entry in entries {
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            complete = false;
            continue;
        };
        if !is_dotted_numeric_version(&name) {
            continue;
        }
        inspected += 1;
        if inspected > MAX_PROFILES_PER_USER_DATA_ROOT {
            complete = false;
            break;
        }
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            complete = false;
            continue;
        };
        if file_type.is_symlink() || !file_type.is_dir() {
            complete = false;
            continue;
        }
        if let Some(hint) = inspect_external_hint(
            containment_root,
            &path,
            ExternalCdmOrigin::ProfileWidevineCdm,
        ) {
            if hint.version.is_some() || hint.library.is_some() {
                push_unique_hint(hints, seen, hint);
            } else {
                complete = false;
            }
        } else {
            complete = false;
        }
    }
    complete
}

fn is_dotted_numeric_version(name: &str) -> bool {
    !name.is_empty()
        && name
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn hint_belongs_to_target(hint: &ExternalCdmHint, target: &Path) -> bool {
    canonicalize_path(&hint.path).is_ok_and(|path| path == target)
        || hint.library.as_ref().is_some_and(|library| {
            canonicalize_path(library).is_ok_and(|path| path.starts_with(target))
        })
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
        let identity = inspect_cdm_identity(candidate, None);
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
        let suffixes = crate::patch::macos::profile_support_suffixes(&name);
        if suffixes.is_empty() {
            return None;
        }
        let support = dirs::home_dir()?
            .join("Library")
            .join("Application Support");
        Some(suffixes.iter().map(|suffix| support.join(suffix)).collect())
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

pub(super) fn hint_to_fingerprint_entry(hint: &ExternalCdmHint) -> CdmFingerprintEntry {
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
