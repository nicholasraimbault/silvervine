//! Silvervine CDM provenance markers and overwrite policy.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::browsers::{Browser, BrowserKind};
use crate::error::{Error, Result};
use crate::widevine::download::{hex_lower, sha512_reader};
use crate::widevine::{current_platform_key, CachedCdm};

/// File stored beside an installed CDM to establish Silvervine provenance.
pub const MANAGED_MARKER_FILENAME: &str = ".silvervine-managed.json";
const MARKER_SCHEMA_VERSION: u8 = 3;
const MAX_VERSION_BYTES: usize = 64;
const MAX_MARKER_BYTES: u64 = 16 * 1024;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_LIBRARY_BYTES: u64 = 128 * 1024 * 1024;

/// Verified ownership record for a CDM installed by Silvervine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedMarker {
    /// Marker schema revision.
    pub schema_version: u8,
    /// Silvervine version that installed the payload.
    pub silvervine_version: String,
    /// Installed Widevine version.
    pub cdm_version: String,
    /// Mozilla platform key for the installed payload.
    pub platform: String,
    /// SHA-512 digest of the installed Widevine library.
    pub library_sha512: String,
    /// SHA-512 digest of the installed root `manifest.json`.
    pub manifest_sha512: String,
}

/// Installed CDM whose marker, manifest, platform, and library digest agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedInstalledCdm {
    marker: ManagedMarker,
    library_path: PathBuf,
}

impl ValidatedInstalledCdm {
    /// Verified Silvervine ownership marker.
    #[must_use]
    pub fn marker(&self) -> &ManagedMarker {
        &self.marker
    }

    /// Verified non-symlink Widevine library path.
    #[must_use]
    pub fn library_path(&self) -> &Path {
        &self.library_path
    }
    /// Whether this verified install matches the selected candidate identity.
    /// macOS code signing may transform the library bytes after selection, so
    /// macOS binds the release through version, platform, and root manifest.
    /// Platforms without that trusted finalization require the library digest
    /// to match as well.
    #[must_use]
    pub fn matches_candidate(&self, candidate: &ManagedMarker) -> bool {
        let library_matches =
            cfg!(target_os = "macos") || self.marker.library_sha512 == candidate.library_sha512;
        self.marker.cdm_version == candidate.cdm_version
            && self.marker.platform == candidate.platform
            && self.marker.manifest_sha512 == candidate.manifest_sha512
            && library_matches
    }
}

/// Provenance classification for an existing browser CDM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipKind {
    /// No CDM exists at the target.
    #[default]
    Missing,
    /// A valid Silvervine marker matches the installed payload.
    Managed,
    /// A valid, unmarked Silvervine-compatible payload may be adopted once.
    LegacyManaged,
    /// An unmarked payload may belong to the browser, platform, or user.
    External,
    /// A marker exists but cannot safely establish ownership.
    InvalidMarker,
}

/// Evidence and guidance produced by ownership classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipAssessment {
    /// Resulting provenance class.
    pub kind: OwnershipKind,
    /// Short human-readable explanation.
    pub summary: String,
    /// Explicit next step when patching must stop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Deterministic evidence for JSON diagnostics.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl Default for OwnershipAssessment {
    fn default() -> Self {
        Self {
            kind: OwnershipKind::Missing,
            summary: "No Widevine CDM is installed at the patch target.".into(),
            action: None,
            details: BTreeMap::new(),
        }
    }
}

impl OwnershipAssessment {
    /// Whether normal patching may replace this target.
    #[must_use]
    pub fn is_safe_to_replace(&self) -> bool {
        matches!(
            self.kind,
            OwnershipKind::Missing | OwnershipKind::Managed | OwnershipKind::LegacyManaged
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PayloadIdentity {
    version: String,
    platform: String,
    library_sha512: String,
    manifest_sha512: String,
}

/// Construct the marker that must be committed with `cached`.
///
/// # Errors
///
/// Returns `InvalidMarker` when the cached payload is not a safe, internally
/// consistent CDM layout, or when the cache handle was not authenticated from
/// a live vendor CRX (or parent-selected marker). Returns `HashMismatch` when
/// current library or root-manifest bytes no longer match the authenticated
/// digests carried by the cache handle.
pub fn marker_for_cached(cached: &CachedCdm) -> Result<ManagedMarker> {
    let expected_library = cached.verified_library_sha512().ok_or_else(|| {
        Error::invalid_marker("cached CDM library was not authenticated from a live vendor payload")
    })?;
    let expected_manifest = cached.verified_manifest_sha512().ok_or_else(|| {
        Error::invalid_marker(
            "cached CDM manifest was not authenticated from a live vendor payload",
        )
    })?;
    let marker = marker_for_payload(cached.cdm_dir())?;
    if marker.cdm_version != cached.version() {
        return Err(Error::invalid_marker(format!(
            "cached CDM version {} does not match manifest version {}",
            cached.version(),
            marker.cdm_version
        )));
    }
    if !marker.library_sha512.eq_ignore_ascii_case(expected_library) {
        return Err(Error::hash_mismatch(
            "cached CDM library changed after integrity verification",
        ));
    }
    if !marker
        .manifest_sha512
        .eq_ignore_ascii_case(expected_manifest)
    {
        return Err(Error::hash_mismatch(
            "cached CDM manifest changed after integrity verification",
        ));
    }
    Ok(marker)
}

/// Construct a marker directly from one fully inspected payload directory.
pub(crate) fn marker_for_payload(target: &Path) -> Result<ManagedMarker> {
    let identity = inspect_payload(target)?;
    Ok(ManagedMarker {
        schema_version: MARKER_SCHEMA_VERSION,
        silvervine_version: env!("CARGO_PKG_VERSION").to_owned(),
        cdm_version: identity.version,
        platform: identity.platform,
        library_sha512: identity.library_sha512,
        manifest_sha512: identity.manifest_sha512,
    })
}
/// Rebuild a parent-selected marker after a trusted platform finalizer changes
/// only the library bytes (for example, macOS code signing).
///
/// # Errors
///
/// Returns `InvalidMarker` if the finalized payload changed the selected CDM
/// version, platform, or root-manifest digest, or if either payload or marker
/// is malformed.
pub(crate) fn marker_for_finalized_payload(
    target: &Path,
    parent: &ManagedMarker,
) -> Result<ManagedMarker> {
    validate_marker_header(parent)?;
    let identity = inspect_payload(target)?;
    if identity.version != parent.cdm_version
        || identity.platform != parent.platform
        || identity.manifest_sha512 != parent.manifest_sha512
    {
        return Err(Error::invalid_marker(
            "platform finalization changed the parent-selected CDM identity",
        ));
    }
    let mut finalized = parent.clone();
    finalized.library_sha512 = identity.library_sha512;
    Ok(finalized)
}

/// Atomically write `marker` after verifying it matches the installed payload.
///
/// # Errors
///
/// Returns [`ErrorCategory::InvalidMarker`](crate::ErrorCategory::InvalidMarker)
/// when `target` is unsafe or no longer matches `marker`, or an I/O category
/// when the marker cannot be committed.
pub fn write_marker(target: &Path, marker: &ManagedMarker) -> Result<()> {
    let identity = inspect_payload(target)?;
    validate_marker_fields(marker, &identity)?;
    let bytes = serde_json::to_vec_pretty(marker).map_err(Error::from)?;
    atomic_write_marker(&marker_path(target), &bytes)
}

/// Validate and return the marker for an installed CDM.
///
/// # Errors
///
/// Returns [`ErrorCategory::InvalidMarker`](crate::ErrorCategory::InvalidMarker)
/// for malformed, symlinked, stale, or mismatched marker state.
pub fn validate_installed_marker(target: &Path) -> Result<ManagedMarker> {
    let path = marker_path(target);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| {
            Error::invalid_marker(format!("could not safely open {}: {error}", path.display()))
                .with_source(error)
        })?;
    let metadata = file.metadata().map_err(|error| {
        Error::invalid_marker(format!("could not inspect {}: {error}", path.display()))
            .with_source(error)
    })?;
    if !metadata.is_file() {
        return Err(Error::invalid_marker(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_MARKER_BYTES {
        return Err(Error::invalid_marker(format!(
            "{} exceeds the marker size limit",
            path.display()
        )));
    }

    let capacity = usize::try_from(metadata.len())
        .map_err(|_| Error::invalid_marker("ownership marker size is not representable"))?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            Error::invalid_marker("could not read ownership marker").with_source(error)
        })?;
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(Error::invalid_marker(format!(
            "{} grew beyond the marker size limit while it was read",
            path.display()
        )));
    }
    let marker: ManagedMarker = serde_json::from_slice(&bytes).map_err(|error| {
        Error::invalid_marker("ownership marker is not valid JSON").with_source(error)
    })?;
    let identity = inspect_payload(target)?;
    validate_marker_fields(&marker, &identity)?;
    Ok(marker)
}

/// Validate an installed CDM and return its verified marker and library path.
///
/// # Errors
///
/// Returns [`ErrorCategory::InvalidMarker`](crate::ErrorCategory::InvalidMarker)
/// for malformed, symlinked, stale, mismatched, or incomplete installed state.
pub fn validate_installed_cdm(target: &Path) -> Result<ValidatedInstalledCdm> {
    let marker = validate_installed_marker(target)?;
    let library_path = target
        .join("_platform_specific")
        .join(expected_platform_dir())
        .join(expected_library_name());
    require_regular_file(&library_path, "Widevine library")?;
    Ok(ValidatedInstalledCdm {
        marker,
        library_path,
    })
}

/// Classify the installed CDM without changing browser state.
///
/// # Errors
///
/// Returns an I/O error only when the target cannot be inspected. Unsafe
/// marker and payload states are returned as [`OwnershipKind::InvalidMarker`]
/// so diagnostics can report them without aborting.
pub fn classify(
    browser: &Browser,
    target: &Path,
    candidate: &CachedCdm,
    candidate_marker: &ManagedMarker,
) -> Result<OwnershipAssessment> {
    let baseline = classify_without_candidate(browser, target)?;
    if baseline.kind != OwnershipKind::External {
        return Ok(baseline);
    }

    let Ok(installed) = inspect_payload(target) else {
        return Ok(baseline);
    };
    let exact_candidate = candidate.version() == candidate_marker.cdm_version
        && installed.version == candidate_marker.cdm_version
        && installed.platform == candidate_marker.platform
        && installed.library_sha512 == candidate_marker.library_sha512
        && installed.manifest_sha512 == candidate_marker.manifest_sha512;
    if exact_candidate {
        return Ok(assessment(
            OwnershipKind::LegacyManaged,
            "The unmarked CDM is eligible for one-time Silvervine adoption.",
            None,
            baseline.details,
        ));
    }
    Ok(baseline)
}

/// Conservatively classify an installed CDM when no verified cache candidate
/// is available. Unmarked targets remain external because exact payload
/// equality cannot be proven.
///
/// # Errors
///
/// Returns an I/O error only when the target itself cannot be inspected.
/// Unsafe marker or payload state is represented in the returned assessment.
pub fn classify_without_candidate(browser: &Browser, target: &Path) -> Result<OwnershipAssessment> {
    let target_metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(assessment(
                OwnershipKind::Missing,
                "No Widevine CDM is installed at the patch target.",
                Some("Run `silvervine setup` or `silvervine patch`.".into()),
                BTreeMap::new(),
            ));
        }
        Err(error) => return Err(Error::from(error)),
    };
    if target_metadata.file_type().is_symlink() || !target_metadata.is_dir() {
        return Ok(invalid_assessment(
            "The existing CDM root is not a regular directory.",
        ));
    }

    match fs::symlink_metadata(marker_path(target)) {
        Ok(_) => {
            return Ok(match validate_installed_marker(target) {
                Ok(installed) => {
                    let mut details = identity_details(&PayloadIdentity {
                        version: installed.cdm_version,
                        platform: installed.platform,
                        library_sha512: installed.library_sha512,
                        manifest_sha512: installed.manifest_sha512,
                    });
                    details.insert("silvervine_version".into(), installed.silvervine_version);
                    assessment(
                        OwnershipKind::Managed,
                        "The installed CDM has valid Silvervine provenance.",
                        None,
                        details,
                    )
                }
                Err(error) => invalid_assessment(&error.message),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Ok(invalid_assessment(&format!(
                "could not inspect ownership marker: {error}"
            )));
        }
    }

    let installed = match inspect_payload(target) {
        Ok(identity) => identity,
        Err(error) => {
            return Ok(assessment(
                OwnershipKind::External,
                "The unmarked CDM does not match a safe Silvervine layout.",
                Some(replacement_action(browser)),
                BTreeMap::from([("reason".into(), error.message)]),
            ));
        }
    };
    let mut details = identity_details(&installed);
    details.insert(
        "browser_kind".into(),
        browser_kind_name(browser.kind).into(),
    );
    Ok(assessment(
        OwnershipKind::External,
        "The unmarked CDM may be managed by the browser, platform, or user.",
        Some(replacement_action(browser)),
        details,
    ))
}

fn marker_path(target: &Path) -> PathBuf {
    target.join(MANAGED_MARKER_FILENAME)
}
static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Root-owned, verified payload staged beneath a trusted snapshot parent.
#[derive(Debug)]
pub struct StagedPayload(PathBuf);

impl StagedPayload {
    /// Exact payload root safe for the privileged platform writer to consume.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for StagedPayload {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Copy only the manifest and host library from a mutable cache into a trusted
/// directory, resolving every source component without following symlinks.
///
/// The copied library must match the digest selected by the unprivileged
/// parent. This is the privilege-boundary handoff: platform patchers never
/// recursively walk the user-writable cache as root.
///
/// # Errors
///
/// Returns [`ErrorCategory::InvalidMarker`](crate::ErrorCategory::InvalidMarker)
/// when the source changes, contains symlinks, exceeds bounds, or disagrees
/// with `marker`.
pub fn stage_verified_payload(
    source: &Path,
    trusted_parent: &Path,
    marker: &ManagedMarker,
) -> Result<StagedPayload> {
    validate_marker_header(marker)?;
    let expected_platform = current_platform_key()?.as_str().to_owned();
    if marker.platform != expected_platform {
        return Err(Error::invalid_marker(
            "parent-selected CDM platform does not match this host",
        ));
    }

    let source_root = open_directory_tree(source)?;
    let manifest_bytes = read_relative_file(
        &source_root,
        "manifest.json",
        MAX_MANIFEST_BYTES,
        "CDM manifest",
    )?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        Error::invalid_marker("CDM manifest is not valid JSON").with_source(error)
    })?;
    let version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| Error::invalid_marker("CDM manifest has no version"))?;
    if version != marker.cdm_version {
        return Err(Error::invalid_marker(
            "mutable CDM manifest no longer matches the parent-selected version",
        ));
    }
    let manifest_digest = sha512_hex_of(&manifest_bytes);
    if !manifest_digest.eq_ignore_ascii_case(&marker.manifest_sha512) {
        return Err(Error::invalid_marker(
            "mutable CDM manifest no longer matches the parent-selected digest",
        ));
    }

    let platform_root = open_relative_directory(&source_root, "_platform_specific")?;
    let platform = open_relative_directory(&platform_root, expected_platform_dir())?;
    let library = open_relative_regular_file(&platform, expected_library_name(), "CDM library")?;
    if library.metadata().map_err(Error::from)?.len() > MAX_LIBRARY_BYTES {
        return Err(Error::invalid_marker(
            "CDM library exceeds the privileged staging size limit",
        ));
    }

    let parent_metadata = fs::symlink_metadata(trusted_parent).map_err(Error::from)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(Error::invalid_marker(
            "privileged staging parent must be a regular directory",
        ));
    }
    let counter = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let stage_path = trusted_parent.join(format!(
        ".silvervine-cdm-stage-{}-{counter}",
        std::process::id()
    ));
    fs::create_dir(&stage_path).map_err(Error::from)?;
    let staged = StagedPayload(stage_path);
    fs::set_permissions(staged.path(), fs::Permissions::from_mode(0o755)).map_err(Error::from)?;
    let staged_platform = staged
        .path()
        .join("_platform_specific")
        .join(expected_platform_dir());
    fs::create_dir_all(&staged_platform).map_err(Error::from)?;
    fs::set_permissions(
        staged.path().join("_platform_specific"),
        fs::Permissions::from_mode(0o755),
    )
    .map_err(Error::from)?;
    fs::set_permissions(&staged_platform, fs::Permissions::from_mode(0o755))
        .map_err(Error::from)?;

    write_new_file(&staged.path().join("manifest.json"), &manifest_bytes, 0o644)?;
    copy_library(
        library,
        &staged_platform.join(expected_library_name()),
        MAX_LIBRARY_BYTES,
        &marker.library_sha512,
    )?;

    let identity = inspect_payload(staged.path())?;
    validate_marker_fields(marker, &identity)?;
    Ok(staged)
}

fn open_directory_tree(path: &Path) -> Result<fs::File> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(Error::invalid_marker(
            "privileged CDM source must be an absolute path",
        ));
    }
    let mut directory = open_directory(c"/")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = open_relative_directory_os(&directory, name)?;
            }
            _ => {
                return Err(Error::invalid_marker(
                    "privileged CDM source contains an unsafe path component",
                ));
            }
        }
    }
    Ok(directory)
}

fn open_directory(path: &CStr) -> Result<fs::File> {
    // SAFETY: `path` is NUL-terminated and the returned descriptor is owned by
    // the `File`. O_NOFOLLOW rejects a symlink at the opened component.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    owned_descriptor(descriptor, "could not open privileged CDM source directory")
}

fn open_relative_directory(parent: &fs::File, name: &str) -> Result<fs::File> {
    open_relative_directory_os(parent, std::ffi::OsStr::new(name))
}

fn open_relative_directory_os(parent: &fs::File, name: &std::ffi::OsStr) -> Result<fs::File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| Error::invalid_marker("CDM path component contains NUL"))?;
    // SAFETY: `name` is NUL-terminated; `parent` remains open for the call.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    owned_descriptor(descriptor, "could not open privileged CDM source directory")
}

fn open_relative_regular_file(parent: &fs::File, name: &str, label: &str) -> Result<fs::File> {
    let name =
        CString::new(name).map_err(|_| Error::invalid_marker("CDM path component contains NUL"))?;
    // SAFETY: `name` is NUL-terminated; `parent` remains open for the call.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let file = owned_descriptor(descriptor, &format!("could not open {label}"))?;
    let metadata = file.metadata().map_err(Error::from)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(Error::invalid_marker(format!(
            "{label} must be a non-empty regular file"
        )));
    }
    Ok(file)
}

fn owned_descriptor(descriptor: libc::c_int, message: &str) -> Result<fs::File> {
    if descriptor < 0 {
        return Err(Error::invalid_marker(message).with_source(io::Error::last_os_error()));
    }
    // SAFETY: a non-negative result from open/openat is a newly owned fd.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

fn read_relative_file(parent: &fs::File, name: &str, limit: usize, label: &str) -> Result<Vec<u8>> {
    let mut file = open_relative_regular_file(parent, name, label)?;
    let mut bytes = Vec::with_capacity(limit.min(16 * 1024));
    (&mut file)
        .take(u64::try_from(limit).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::from)?;
    if bytes.len() > limit {
        return Err(Error::invalid_marker(format!(
            "{label} exceeds the privileged staging size limit"
        )));
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(Error::from)?;
    file.write_all(bytes).map_err(Error::from)?;
    file.flush().map_err(Error::from)
}

fn copy_library(
    mut source: fs::File,
    destination: &Path,
    limit: u64,
    expected_digest: &str,
) -> Result<()> {
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(destination)
        .map_err(Error::from)?;
    let mut hasher = Sha512::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut buffer).map_err(Error::from)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(
                u64::try_from(count)
                    .map_err(|_| Error::invalid_marker("CDM library size overflow"))?,
            )
            .ok_or_else(|| Error::invalid_marker("CDM library size overflow"))?;
        if copied > limit {
            return Err(Error::invalid_marker(
                "CDM library exceeds the privileged staging size limit",
            ));
        }
        hasher.update(&buffer[..count]);
        target.write_all(&buffer[..count]).map_err(Error::from)?;
    }
    target.flush().map_err(Error::from)?;
    let digest = hex_lower(&hasher.finalize());
    if !digest.eq_ignore_ascii_case(expected_digest) {
        return Err(Error::invalid_marker(
            "mutable CDM library no longer matches the parent-selected digest",
        ));
    }
    Ok(())
}

static MARKER_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempMarker(PathBuf);

impl Drop for TempMarker {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn atomic_write_marker(path: &Path, bytes: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(Error::invalid_marker(format!(
                "{} must be a regular file",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::from(error)),
    }

    let parent = path
        .parent()
        .ok_or_else(|| Error::other("ownership marker path has no parent directory"))?;
    let counter = MARKER_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{MANAGED_MARKER_FILENAME}.tmp-{}-{counter}",
        std::process::id()
    ));
    let cleanup = TempMarker(temp.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(Error::from)?;
    file.write_all(bytes).map_err(Error::from)?;
    file.write_all(b"\n").map_err(Error::from)?;
    file.sync_all().map_err(Error::from)?;
    drop(file);

    fs::rename(&temp, path).map_err(Error::from)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(Error::from)?;
    std::mem::forget(cleanup);
    Ok(())
}

fn replacement_action(browser: &Browser) -> String {
    format!(
        "Preserved existing CDM. Re-run `silvervine patch --browser \"{}\" --replace-external-cdm` to replace it explicitly.",
        browser.name()
    )
}

fn assessment(
    kind: OwnershipKind,
    summary: impl Into<String>,
    action: Option<String>,
    details: BTreeMap<String, String>,
) -> OwnershipAssessment {
    OwnershipAssessment {
        kind,
        summary: summary.into(),
        action,
        details,
    }
}

fn invalid_assessment(reason: &str) -> OwnershipAssessment {
    assessment(
        OwnershipKind::InvalidMarker,
        "The Silvervine ownership marker is invalid; the CDM was preserved.",
        Some(
            "Remove the stale marker only after verifying CDM ownership, then run Silvervine again."
                .into(),
        ),
        BTreeMap::from([("reason".into(), reason.into())]),
    )
}

fn identity_details(identity: &PayloadIdentity) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("cdm_version".into(), identity.version.clone()),
        ("platform".into(), identity.platform.clone()),
        ("library_sha512".into(), identity.library_sha512.clone()),
        ("manifest_sha512".into(), identity.manifest_sha512.clone()),
    ])
}

fn browser_kind_name(kind: BrowserKind) -> &'static str {
    kind.as_str()
}

fn validate_marker_header(marker: &ManagedMarker) -> Result<()> {
    if marker.schema_version != MARKER_SCHEMA_VERSION {
        return Err(Error::invalid_marker(format!(
            "unsupported marker schema version {}",
            marker.schema_version
        )));
    }
    if marker.silvervine_version.is_empty()
        || marker.silvervine_version.len() > MAX_VERSION_BYTES
        || !marker
            .silvervine_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(Error::invalid_marker(
            "ownership marker has an invalid Silvervine version",
        ));
    }
    if !is_sha512_hex(&marker.library_sha512) || !is_sha512_hex(&marker.manifest_sha512) {
        return Err(Error::invalid_marker(
            "ownership marker has an invalid payload digest",
        ));
    }
    Ok(())
}

fn is_sha512_hex(value: &str) -> bool {
    value.len() == 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha512_hex_of(bytes: &[u8]) -> String {
    hex_lower(&Sha512::digest(bytes))
}

fn validate_marker_fields(marker: &ManagedMarker, identity: &PayloadIdentity) -> Result<()> {
    validate_marker_header(marker)?;
    if marker.cdm_version != identity.version
        || marker.platform != identity.platform
        || marker.library_sha512 != identity.library_sha512
        || marker.manifest_sha512 != identity.manifest_sha512
    {
        return Err(Error::invalid_marker(
            "ownership marker no longer matches the installed CDM",
        ));
    }
    Ok(())
}

fn inspect_payload(root: &Path) -> Result<PayloadIdentity> {
    require_regular_directory(root, "CDM root")?;
    let manifest_path = root.join("manifest.json");
    let manifest_bytes =
        read_bounded_regular_file(&manifest_path, "CDM manifest", MAX_MANIFEST_BYTES as u64)?;
    let manifest_sha512 = sha512_hex_of(&manifest_bytes);
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        Error::invalid_marker("CDM manifest is not valid JSON").with_source(error)
    })?;
    let version = manifest
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.is_empty())
        .ok_or_else(|| Error::invalid_marker("CDM manifest has no version"))?
        .to_owned();

    let platform_root = root.join("_platform_specific");
    require_regular_directory(&platform_root, "platform-specific CDM directory")?;
    let mut libraries = Vec::new();
    for entry in fs::read_dir(&platform_root).map_err(|error| {
        Error::invalid_marker("could not read CDM platform directory").with_source(error)
    })? {
        let entry = entry.map_err(|error| {
            Error::invalid_marker("could not inspect CDM platform entry").with_source(error)
        })?;
        let platform = entry.path();
        let metadata = fs::symlink_metadata(&platform).map_err(|error| {
            Error::invalid_marker("could not inspect CDM platform entry").with_source(error)
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        for name in ["libwidevinecdm.so", "libwidevinecdm.dylib"] {
            let library = platform.join(name);
            if fs::symlink_metadata(&library).is_ok() {
                libraries.push((entry.file_name().to_string_lossy().into_owned(), library));
            }
        }
    }
    if libraries.len() != 1 {
        return Err(Error::invalid_marker(format!(
            "expected one Widevine library, found {}",
            libraries.len()
        )));
    }
    let (platform_dir, library) = libraries.pop().expect("one library");
    let library_file = open_bounded_regular_file(&library, "Widevine library", MAX_LIBRARY_BYTES)?;
    let platform = current_platform_key()?.as_str().to_owned();
    if platform_dir != expected_platform_dir() {
        return Err(Error::invalid_marker(format!(
            "CDM platform directory {platform_dir} does not match host {}",
            expected_platform_dir()
        )));
    }
    let library_sha512 =
        sha512_reader(library_file.take(MAX_LIBRARY_BYTES + 1)).map_err(|error| {
            Error::invalid_marker("could not hash Widevine library").with_source(error)
        })?;
    Ok(PayloadIdentity {
        version,
        platform,
        library_sha512,
        manifest_sha512,
    })
}

fn require_regular_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::invalid_marker(format!("could not inspect {label}")).with_source(error)
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::invalid_marker(format!(
            "{label} must be a regular directory"
        )));
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::invalid_marker(format!("could not inspect {label}")).with_source(error)
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(Error::invalid_marker(format!(
            "{label} must be a non-empty regular file"
        )));
    }
    Ok(())
}

fn open_bounded_regular_file(path: &Path, label: &str, limit: u64) -> Result<fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            Error::invalid_marker(format!("could not safely open {label}")).with_source(error)
        })?;
    let metadata = file.metadata().map_err(|error| {
        Error::invalid_marker(format!("could not inspect opened {label}")).with_source(error)
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(Error::invalid_marker(format!(
            "{label} must be a non-empty regular file"
        )));
    }
    if metadata.len() > limit {
        return Err(Error::invalid_marker(format!(
            "{label} exceeds the {limit}-byte safety limit"
        )));
    }
    Ok(file)
}

fn read_bounded_regular_file(path: &Path, label: &str, limit: u64) -> Result<Vec<u8>> {
    let mut file = open_bounded_regular_file(path, label, limit)?;
    let capacity = usize::try_from(file.metadata().map_err(Error::from)?.len())
        .map_err(|_| Error::invalid_marker(format!("{label} size is not representable")))?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            Error::invalid_marker(format!("could not read {label}")).with_source(error)
        })?;
    if bytes.len() as u64 > limit {
        return Err(Error::invalid_marker(format!(
            "{label} grew beyond the {limit}-byte safety limit while it was read"
        )));
    }
    Ok(bytes)
}

fn expected_platform_dir() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "mac_arm64"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "mac_x64"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux_x64"
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64")
    )))]
    {
        ""
    }
}

fn expected_library_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libwidevinecdm.dylib"
    } else {
        "libwidevinecdm.so"
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{
        classify, marker_for_cached, marker_for_finalized_payload, stage_verified_payload,
        validate_installed_cdm, validate_installed_marker, write_marker, OwnershipKind,
        MANAGED_MARKER_FILENAME,
    };
    use crate::browsers::{Browser, BrowserKind};
    use crate::widevine::CachedCdm;

    fn platform_dir() -> &'static str {
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

    fn library_name() -> &'static str {
        if cfg!(target_os = "macos") {
            "libwidevinecdm.dylib"
        } else {
            "libwidevinecdm.so"
        }
    }

    fn write_payload(root: &Path, version: &str, library: &[u8]) {
        let platform = root.join("_platform_specific").join(platform_dir());
        fs::create_dir_all(&platform).expect("platform");
        fs::write(
            root.join("manifest.json"),
            format!(r#"{{"name":"WidevineCdm","version":"{version}"}}"#),
        )
        .expect("manifest");
        fs::write(platform.join(library_name()), library).expect("library");
    }

    fn cached(root: &Path, version: &str, library: &[u8]) -> CachedCdm {
        let cdm = root.join("cache").join(version);
        write_payload(&cdm, version, library);
        let manifest_body = format!(r#"{{"name":"WidevineCdm","version":"{version}"}}"#);
        CachedCdm::from_verified_payload(
            version.to_owned(),
            cdm,
            crate::widevine::sha512_hex(library),
            crate::widevine::sha512_hex(manifest_body.as_bytes()),
        )
    }

    fn browser(root: &Path, kind: BrowserKind) -> Browser {
        Browser {
            name: "Test Browser".into(),
            install_path: root.join("browser"),
            kind,
            framework_name: None,
        }
    }

    fn install_root(browser: &Browser) -> PathBuf {
        browser.install_path.join("WidevineCdm")
    }

    #[test]
    fn missing_install_root_is_manageable() {
        let tmp = TempDir::new().expect("tempdir");
        let browser = browser(tmp.path(), BrowserKind::Detected);
        let candidate = cached(tmp.path(), "4.10.1", b"candidate");
        let marker = marker_for_cached(&candidate).expect("marker");

        let assessment = classify(&browser, &install_root(&browser), &candidate, &marker)
            .expect("classification");

        assert_eq!(assessment.kind, OwnershipKind::Missing);
    }

    #[test]
    fn cached_marker_rejects_library_changed_after_cache_verification() {
        let tmp = TempDir::new().expect("tempdir");
        let candidate = cached(tmp.path(), "4.10.1", b"candidate");
        let library = candidate
            .cdm_dir()
            .join("_platform_specific")
            .join(platform_dir())
            .join(library_name());
        fs::write(library, b"tampered!").expect("tamper");

        let error = marker_for_cached(&candidate)
            .expect_err("post-verification cache changes must not be authorized");

        assert_eq!(error.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn cached_marker_rejects_metadata_only_unverified_handle() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm_dir = tmp.path().join("cache/1.0.0");
        write_payload(&cdm_dir, "1.0.0", b"library");
        let unverified = CachedCdm::new("1.0.0".into(), cdm_dir);

        let error = marker_for_cached(&unverified)
            .expect_err("unverified cache handles cannot authorize patch markers");
        assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);
    }

    #[test]
    fn cached_marker_rejects_manifest_changed_after_cache_verification() {
        let tmp = TempDir::new().expect("tempdir");
        let candidate = cached(tmp.path(), "4.10.1", b"candidate");
        fs::write(
            candidate.cdm_dir().join("manifest.json"),
            br#"{"name":"WidevineCdm","version":"4.10.1","extra":"tampered"}"#,
        )
        .expect("tamper manifest");

        let error = marker_for_cached(&candidate)
            .expect_err("post-verification manifest changes must not be authorized");
        assert_eq!(error.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn privileged_stage_copies_only_parent_verified_payload_files() {
        let tmp = TempDir::new().expect("tempdir");
        let candidate = cached(tmp.path(), "4.10.1", b"candidate");
        fs::write(candidate.cdm_dir().join("untrusted-extra"), b"do not copy").unwrap();
        let marker = marker_for_cached(&candidate).expect("marker");
        let trusted = tmp.path().join("trusted");
        fs::create_dir(&trusted).unwrap();

        let staged = stage_verified_payload(candidate.cdm_dir(), &trusted, &marker).expect("stage");

        assert!(!staged.path().join("untrusted-extra").exists());
        let staged_cdm = CachedCdm::from_verified_payload(
            marker.cdm_version.clone(),
            staged.path().to_owned(),
            marker.library_sha512.clone(),
            marker.manifest_sha512.clone(),
        );
        assert_eq!(
            marker_for_cached(&staged_cdm).expect("staged marker"),
            marker
        );
    }

    #[test]
    fn privileged_stage_rejects_parent_manifest_digest_substitution() {
        let tmp = TempDir::new().expect("tempdir");
        let candidate = cached(tmp.path(), "4.10.1", b"candidate");
        let mut marker = marker_for_cached(&candidate).expect("marker");
        marker.manifest_sha512 = crate::widevine::sha512_hex(br#"{"version":"substituted"}"#);
        let trusted = tmp.path().join("trusted");
        fs::create_dir(&trusted).unwrap();

        let error = stage_verified_payload(candidate.cdm_dir(), &trusted, &marker)
            .expect_err("parent-selected manifest digest must bind staged bytes");
        assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);
    }

    #[test]
    fn privileged_stage_rejects_oversized_manifest() {
        let tmp = TempDir::new().expect("tempdir");
        let candidate = cached(tmp.path(), "4.10.1", b"candidate");
        let marker = marker_for_cached(&candidate).expect("marker");
        fs::write(
            candidate.cdm_dir().join("manifest.json"),
            vec![b'x'; super::MAX_MANIFEST_BYTES + 1],
        )
        .expect("oversized manifest");
        let trusted = tmp.path().join("trusted");
        fs::create_dir(&trusted).unwrap();

        let error = stage_verified_payload(candidate.cdm_dir(), &trusted, &marker)
            .expect_err("oversized payload must not cross the privilege boundary");

        assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);
        assert!(error.message.contains("size limit"));
    }

    #[cfg(unix)]
    #[test]
    fn privileged_stage_rejects_symlinked_source_components() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().expect("tempdir");
        let candidate = cached(tmp.path(), "4.10.1", b"candidate");
        let marker = marker_for_cached(&candidate).expect("marker");
        let platform = candidate.cdm_dir().join("_platform_specific");
        fs::remove_dir_all(&platform).unwrap();
        let outside = tmp.path().join("outside");
        write_payload(&outside, "4.10.1", b"candidate");
        symlink(outside.join("_platform_specific"), &platform).unwrap();
        let trusted = tmp.path().join("trusted");
        fs::create_dir(&trusted).unwrap();

        let error = stage_verified_payload(candidate.cdm_dir(), &trusted, &marker)
            .expect_err("symlinked platform root must be rejected");

        assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);
    }

    #[test]
    fn valid_marker_matching_installed_payload_is_managed() {
        let tmp = TempDir::new().expect("tempdir");
        let browser = browser(tmp.path(), BrowserKind::Detected);
        let candidate = cached(tmp.path(), "4.10.1", b"candidate");
        let target = install_root(&browser);
        write_payload(&target, "4.10.1", b"candidate");
        let marker = marker_for_cached(&candidate).expect("marker");
        write_marker(&target, &marker).expect("write marker");

        let assessment = classify(&browser, &target, &candidate, &marker).expect("classification");

        assert_eq!(assessment.kind, OwnershipKind::Managed);
        assert_eq!(validate_installed_marker(&target).expect("valid"), marker);
    }
    #[test]
    fn candidate_match_applies_platform_library_digest_rules() {
        let tmp = TempDir::new().expect("tempdir");
        let candidate = cached(tmp.path(), "4.10.1", b"unsigned candidate");
        let candidate_marker = marker_for_cached(&candidate).expect("candidate marker");
        let target = tmp.path().join("installed");
        write_payload(&target, "4.10.1", b"signed candidate");
        let installed_marker =
            marker_for_finalized_payload(&target, &candidate_marker).expect("finalized marker");
        write_marker(&target, &installed_marker).expect("write marker");

        let installed = validate_installed_cdm(&target).expect("validated install");

        assert_ne!(
            installed.marker().library_sha512,
            candidate_marker.library_sha512
        );
        #[cfg(target_os = "macos")]
        assert!(installed.matches_candidate(&candidate_marker));
        #[cfg(not(target_os = "macos"))]
        assert!(!installed.matches_candidate(&candidate_marker));
        let newer = cached(tmp.path(), "4.10.2", b"newer");
        assert!(!installed.matches_candidate(&marker_for_cached(&newer).unwrap()));
    }

    #[test]
    fn caller_supplied_known_kind_does_not_authorize_replacement() {
        let tmp = TempDir::new().expect("tempdir");
        let browser = browser(tmp.path(), BrowserKind::Known);
        let candidate = cached(tmp.path(), "4.10.2", b"new");
        let target = install_root(&browser);
        write_payload(&target, "4.9.0", b"old");
        let marker = marker_for_cached(&candidate).expect("marker");

        let assessment = classify(&browser, &target, &candidate, &marker).expect("classification");

        assert_eq!(assessment.kind, OwnershipKind::External);
    }

    #[test]
    fn unmarked_custom_browser_requires_an_exact_candidate_payload() {
        let tmp = TempDir::new().expect("tempdir");
        let browser = browser(tmp.path(), BrowserKind::Custom);
        let candidate = cached(tmp.path(), "4.10.2", b"same");
        let target = install_root(&browser);
        write_payload(&target, "4.10.2", b"same");
        let marker = marker_for_cached(&candidate).expect("marker");

        let assessment = classify(&browser, &target, &candidate, &marker).expect("classification");

        assert_eq!(assessment.kind, OwnershipKind::LegacyManaged);
    }

    #[test]
    fn unmarked_detected_browser_with_different_payload_is_external() {
        let tmp = TempDir::new().expect("tempdir");
        let browser = browser(tmp.path(), BrowserKind::Detected);
        let candidate = cached(tmp.path(), "4.10.2", b"candidate");
        let target = install_root(&browser);
        write_payload(&target, "9.9.9", b"vendor payload");
        let marker = marker_for_cached(&candidate).expect("marker");

        let assessment = classify(&browser, &target, &candidate, &marker).expect("classification");

        assert_eq!(assessment.kind, OwnershipKind::External);
        assert!(assessment
            .action
            .as_deref()
            .is_some_and(|action| { action.contains("--replace-external-cdm") }));
    }

    #[test]
    fn malformed_or_stale_marker_never_grants_overwrite_permission() {
        let tmp = TempDir::new().expect("tempdir");
        let browser = browser(tmp.path(), BrowserKind::Known);
        let candidate = cached(tmp.path(), "4.10.2", b"candidate");
        let target = install_root(&browser);
        write_payload(&target, "4.10.2", b"candidate");
        fs::write(target.join(MANAGED_MARKER_FILENAME), b"not json").expect("bad marker");
        let expected = marker_for_cached(&candidate).expect("marker");

        let malformed = classify(&browser, &target, &candidate, &expected).expect("classification");
        assert_eq!(malformed.kind, OwnershipKind::InvalidMarker);

        write_marker(&target, &expected).expect("marker");
        fs::write(
            target
                .join("_platform_specific")
                .join(platform_dir())
                .join(library_name()),
            b"tampered",
        )
        .expect("tamper");
        let stale = classify(&browser, &target, &candidate, &expected).expect("classification");
        assert_eq!(stale.kind, OwnershipKind::InvalidMarker);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_marker_or_library_is_invalid() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().expect("tempdir");
        let browser = browser(tmp.path(), BrowserKind::Known);
        let candidate = cached(tmp.path(), "4.10.2", b"candidate");
        let target = install_root(&browser);
        write_payload(&target, "4.10.2", b"candidate");
        let expected = marker_for_cached(&candidate).expect("marker");

        let outside_marker = tmp.path().join("outside-marker");
        fs::write(
            &outside_marker,
            serde_json::to_vec(&expected).expect("json"),
        )
        .expect("outside");
        symlink(&outside_marker, target.join(MANAGED_MARKER_FILENAME)).expect("marker symlink");
        let marker_result =
            classify(&browser, &target, &candidate, &expected).expect("classification");
        assert_eq!(marker_result.kind, OwnershipKind::InvalidMarker);

        fs::remove_file(target.join(MANAGED_MARKER_FILENAME)).expect("remove marker");
        write_marker(&target, &expected).expect("marker");
        let library = target
            .join("_platform_specific")
            .join(platform_dir())
            .join(library_name());
        fs::remove_file(&library).expect("remove library");
        let outside_library = tmp.path().join("outside-library");
        fs::write(&outside_library, b"candidate").expect("outside library");
        symlink(&outside_library, &library).expect("library symlink");
        let library_result =
            classify(&browser, &target, &candidate, &expected).expect("classification");
        assert_eq!(library_result.kind, OwnershipKind::InvalidMarker);
    }
}
