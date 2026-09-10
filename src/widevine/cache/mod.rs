//! Widevine CDM cache management.
//!
//! ## On-disk layout
//!
//! ```text
//! ~/.cache/silvervine/widevine/
//! ├── 4.10.2899.0/        ← versioned extracted CDM
//! ├── 4.10.2934.0/        ← versioned extracted CDM
//! ├── current → 4.10.2934.0/   (symlink)
//! └── previous → 4.10.2899.0/  (symlink, set when current advances)
//! ```
//!
//! Each `<version>/` directory contains the unpacked CRX3 contents
//! (`manifest.json` + `_platform_specific/<platform>/libwidevinecdm.{so,dylib}`).
//!
//! ## API surface (per spec)
//!
//! * [`CdmCache::ensure`] — make sure the manifest version is present,
//!   downloading and extracting when needed, then advance `current`.
//! * [`CdmCache::current`] — resolve the active `current` symlink.
//! * [`CdmCache::rollback`] — atomically swap `current` and `previous`.
//! * [`CdmCache::prune`] — keep the latest N versions and remove older data.
//! * [`CdmCache::verify_integrity`] — recompute the library SHA-512 against
//!   metadata persisted when the verified archive entered the cache.
//!
//! ## What this module does NOT do
//!
//! * No actual patching — that's [`crate::patch`].
//! * No daemon scheduling — daemon team owns the weekly tick.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::widevine::manifest::{Manifest, Platform};
use crate::widevine::{
    crx3, download, extract, platform_directory, platform_library, CDM_MANIFEST_FILENAME,
    PLATFORM_SPECIFIC_DIRECTORY,
};

/// How many CDM versions to keep around by default ([`prune`] honors this).
pub const DEFAULT_RETENTION: usize = 3;

/// Default cache root: `~/.cache/silvervine/widevine/`.
///
/// Returns `None` if `dirs::cache_dir()` is unresolvable.
#[must_use]
pub fn default_cache_root() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("silvervine").join("widevine"))
}

/// Snapshot of an extracted CDM at a particular version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedCdm {
    version: String,
    /// Root of the extracted CDM (e.g. `~/.cache/silvervine/widevine/4.10.2934.0/`).
    /// Contains `manifest.json` + `_platform_specific/<platform>/`.
    cdm_dir: PathBuf,
    /// Library digest authenticated from a live fixed-origin Mozilla CRX during
    /// this process. Never minted from user-writable integrity metadata.
    verified_library_sha512: Option<String>,
    /// Root `manifest.json` digest authenticated from the same live CRX bytes.
    verified_manifest_sha512: Option<String>,
}

impl CachedCdm {
    /// Build a [`CachedCdm`] from a version + extracted-directory path.
    /// Public to the crate so the patch tests can construct a synthetic
    /// CDM without going through the full download flow.
    #[must_use]
    pub fn new(version: String, cdm_dir: PathBuf) -> Self {
        Self {
            version,
            cdm_dir,
            verified_library_sha512: None,
            verified_manifest_sha512: None,
        }
    }

    /// CDM version string (e.g. `"4.10.2934.0"`).
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Path to the extracted CDM root. Suitable as the `cdm_source`
    /// argument of [`crate::patch::PlatformPatcher::write_cdm`].
    #[must_use]
    pub fn cdm_dir(&self) -> &Path {
        &self.cdm_dir
    }

    /// Build a handle whose library and root-manifest bytes were authenticated
    /// against a live vendor CRX (or an already parent-selected marker).
    #[must_use]
    pub(crate) fn from_verified_payload(
        version: String,
        cdm_dir: PathBuf,
        library_sha512: String,
        manifest_sha512: String,
    ) -> Self {
        Self {
            version,
            cdm_dir,
            verified_library_sha512: Some(library_sha512),
            verified_manifest_sha512: Some(manifest_sha512),
        }
    }

    #[must_use]
    pub(crate) fn verified_library_sha512(&self) -> Option<&str> {
        self.verified_library_sha512.as_deref()
    }

    #[must_use]
    pub(crate) fn verified_manifest_sha512(&self) -> Option<&str> {
        self.verified_manifest_sha512.as_deref()
    }
}

const CACHE_METADATA_FILENAME: &str = ".silvervine-integrity.json";
const CACHE_METADATA_SCHEMA: u8 = 2;
const MAX_CACHED_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_CACHED_LIBRARY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CACHE_METADATA_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct CacheMetadata {
    schema_version: u8,
    version: String,
    platform: String,
    library_size: u64,
    library_sha512: String,
    /// Diagnostic drift hash of the root CDM `manifest.json`. Never an
    /// authenticity root for patch authorization.
    manifest_sha512: String,
}

/// One cache root and platform with serialized mutation operations.
#[derive(Debug, Clone)]
pub struct CdmCache {
    root: PathBuf,
    platform: Platform,
}

impl CdmCache {
    /// Bind cache operations to an explicit root and supported platform.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, platform: Platform) -> Self {
        Self {
            root: root.into(),
            platform,
        }
    }

    /// Cache root containing version directories and active links.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Ensure the manifest's CDM is cached and active.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform is absent from the manifest, the cache
    /// lock or filesystem cannot be used, or download, verification, or
    /// extraction fails.
    pub fn ensure(&self, manifest: &Manifest) -> Result<CachedCdm> {
        std::fs::create_dir_all(&self.root).map_err(Error::from)?;
        self.with_mutation_lock(|| ensure_unlocked(self, manifest))
    }

    /// Resolve the active CDM without performing integrity checks.
    ///
    /// # Errors
    ///
    /// Returns an error if the `current` link cannot be read or resolves to an
    /// invalid cache entry.
    pub fn current(&self) -> Result<Option<CachedCdm>> {
        resolve_cache_link(&self.root, "current")
    }

    /// Resolve the active CDM and check structural layout plus local integrity
    /// drift metadata while holding the cache mutation lock.
    ///
    /// A successful handle is never patch-authoritative: user-writable
    /// `.silvervine-integrity.json` cannot mint [`CachedCdm::verified_library_sha512`]
    /// or [`CachedCdm::verified_manifest_sha512`].
    ///
    /// # Errors
    ///
    /// Returns an error if the active link, CDM layout, metadata, library size,
    /// library digest, or root-manifest digest is missing, malformed, or
    /// inconsistent with the on-disk payload.
    pub fn validated_current(&self) -> Result<Option<CachedCdm>> {
        if !self.root.exists() {
            return Ok(None);
        }
        self.with_mutation_lock(|| self.validated_current_unlocked())
    }

    fn validated_current_unlocked(&self) -> Result<Option<CachedCdm>> {
        let Some(cdm) = self.current()? else {
            return Ok(None);
        };
        // Drift/structural checks only — never elevate metadata into verified_*.
        let _ = verify_cached_integrity(&cdm, self.platform)?;
        Ok(Some(CachedCdm::new(cdm.version, cdm.cdm_dir)))
    }

    /// Atomically swap the active and previous CDM links.
    ///
    /// Rollback is a cache-selection operation. The returned handle is not
    /// patch-authoritative even when previous integrity metadata still matches
    /// the on-disk library and manifest bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no previous CDM, the previous entry fails
    /// structural or integrity validation, or locking or exchanging either
    /// cache link fails.
    pub fn rollback(&self) -> Result<CachedCdm> {
        self.with_mutation_lock(|| {
            let previous = resolve_cache_link(&self.root, "previous")?.ok_or_else(|| {
                Error::state_corrupted("no previous CDM cached — nothing to roll back to")
            })?;
            // Structural/drift gate only; do not mint verified_* from metadata.
            let _ = verify_cached_integrity(&previous, self.platform)?;
            let selected = rollback_unlocked(&self.root)?;
            Ok(CachedCdm::new(selected.version, selected.cdm_dir))
        })
    }

    /// Delete old versions and interrupted staging artifacts.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache cannot be locked, enumerated, or cleaned.
    pub fn prune(&self, keep: usize) -> Result<usize> {
        if !self.root.exists() {
            return Ok(0);
        }
        self.with_mutation_lock(|| prune_unlocked(&self.root, keep))
    }

    /// Recompute the active library hash against persisted cache metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the active CDM or its integrity metadata cannot be
    /// read or locked, or if its library size or SHA-512 digest has changed.
    pub fn verify_integrity(&self) -> Result<()> {
        self.with_mutation_lock(|| {
            let Some(cdm) = self.current()? else {
                return Ok(());
            };
            verify_cached_integrity(&cdm, self.platform)?;
            Ok(())
        })
    }

    fn with_mutation_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        crate::lockfile::with_lock(&self.root.join("download.lock"), operation)
    }
}

/// Ensure the CDM described by `manifest` is present in the cache, then
/// flip the `current` symlink to point at it.
///
/// This is the primary entry point for `silvervine update widevine` and for
/// patch flows when the CDM is missing.
///
/// # Behavior
///
/// 1. Resolve the platform entry from the manifest.
/// 2. Authenticate the vendor CRX against its manifest SHA-512 and pinned
///    Widevine component signature.
/// 3. Derive library and root-manifest digests from the signature-verified ZIP
///    body, extract those exact bytes, then prove the staging output matches.
/// 4. Reuse an existing version only when both current library and root
///    manifest digests match the vendor-authenticated archive values.
/// 5. Otherwise replace the unauthenticated entry with the staged payload.
/// 6. Advance the `current` symlink (and demote the previous one).
/// 7. Return a [`CachedCdm`] handle carrying both archive-derived digests.
///
/// # Errors
///
/// * `NetworkError` / `ManifestFetchFailed` — download chain failed.
/// * `HashMismatch` — the manifest digest or pinned CRX signature does not match.
/// * `UnknownBundleStructure` — the CRX3 envelope or extracted layout is malformed.
/// * `Other` — disk I/O failures.
pub fn ensure_cdm_for(manifest: &Manifest) -> Result<CachedCdm> {
    let root = default_cache_root().ok_or_else(|| {
        Error::state_corrupted(
            "cannot resolve ~/.cache/silvervine/widevine (no \\$HOME / cache dir)",
        )
    })?;
    let platform = crate::widevine::manifest::current_platform_key()?;
    ensure_cdm_for_with(manifest, platform, &root)
}

/// Test- and injection-friendly variant: caller supplies the platform key
/// and the cache root.
///
/// # Errors
///
/// See [`ensure_cdm_for`].
pub fn ensure_cdm_for_with(
    manifest: &Manifest,
    platform: Platform,
    cache_root: &Path,
) -> Result<CachedCdm> {
    CdmCache::new(cache_root, platform).ensure(manifest)
}

fn ensure_unlocked(cache: &CdmCache, manifest: &Manifest) -> Result<CachedCdm> {
    ensure_unlocked_with_authenticator(cache, manifest, crx3::authenticate_widevine_crx)
}

fn ensure_unlocked_with_authenticator(
    cache: &CdmCache,
    manifest: &Manifest,
    authenticate: fn(download::VerifiedCrx) -> Result<crx3::AuthenticatedCrx>,
) -> Result<CachedCdm> {
    let vendor = manifest.widevine()?;
    let version = vendor.version.clone();
    validate_version(&version)?;
    let entry = manifest.resolve_platform(cache.platform)?;
    let target_dir = cache.root.join(&version);
    let cached = CachedCdm::new(version.clone(), target_dir.clone());

    let staging = cache.root.join(format!(".staging-{version}"));
    remove_cache_entry(&staging)?;
    let crx = download::download_verified(entry, &cache.root.join("downloads"))?;
    let authenticated_crx = authenticate(crx)?;
    let archive =
        authenticated_payload_digests_from_zip(authenticated_crx.archive(), cache.platform)?;
    extract::extract_zip_body(authenticated_crx.archive(), &staging)?;
    let staged = CachedCdm::new(version.clone(), staging.clone());
    validate_extracted_cdm(&staged, cache.platform)?;
    prove_extracted_matches_archive(&staged, cache.platform, &archive)?;
    write_cache_metadata(&staged, cache.platform, &archive)?;

    if cached_matches_archive(&cached, cache.platform, &archive) {
        // Payload bytes match the live archive, but colocated diagnostic
        // metadata may still be schema-1 or otherwise stale. Refresh it from
        // the authenticated digests so validated_current/rollback can run
        // structural checks without a full replace.
        write_cache_metadata(&cached, cache.platform, &archive)?;
        remove_cache_entry(&staging)?;
        advance_current(&cache.root, &version)?;
        return Ok(CachedCdm::from_verified_payload(
            version,
            target_dir,
            archive.library_sha512,
            archive.manifest_sha512,
        ));
    }

    remove_cache_entry(&target_dir)?;
    std::fs::rename(&staging, &target_dir).map_err(Error::from)?;
    advance_current(&cache.root, &version)?;
    Ok(CachedCdm::from_verified_payload(
        version,
        target_dir,
        archive.library_sha512,
        archive.manifest_sha512,
    ))
}

/// Resolve the currently-active CDM via the `current` symlink.
///
/// Returns `Ok(None)` if no CDM has been cached yet.
///
/// # Errors
///
/// `Other` if the cache root exists but the `current` link points at
/// something we can't resolve.
pub fn current() -> Result<Option<CachedCdm>> {
    let Some(root) = default_cache_root() else {
        return Ok(None);
    };
    current_in(&root)
}

/// Read the active CDM and run local structural/drift checks without creating a
/// lock or cache path.
///
/// Passive diagnostics use this path so observation cannot mutate XDG state.
/// Like [`CdmCache::validated_current`], success never elevates metadata into
/// verified fields.
pub(crate) fn validated_current_readonly() -> Result<Option<CachedCdm>> {
    let Some(root) = default_cache_root() else {
        return Ok(None);
    };
    if !root.exists() {
        return Ok(None);
    }
    let platform = crate::widevine::manifest::current_platform_key()?;
    CdmCache::new(root, platform).validated_current_unlocked()
}

/// Test-friendly validated-current lookup under an explicit cache root.
#[cfg(test)]
fn validated_current_in(cache_root: &Path, platform: Platform) -> Result<Option<CachedCdm>> {
    CdmCache::new(cache_root, platform).validated_current()
}

/// Test-friendly: resolve `current` under an arbitrary cache root.
///
/// # Errors
///
/// `Other` if the `current` symlink can't be read or its target is missing.
pub fn current_in(cache_root: &Path) -> Result<Option<CachedCdm>> {
    resolve_cache_link(cache_root, "current")
}

/// Roll `current` back to whatever `previous` currently points at.
///
/// After rollback the *previous* `current` becomes the new `previous`,
/// so a second rollback toggles back. This is intentional — rollback
/// is a "swap" operation rather than a stack pop.
///
/// # Errors
///
/// * `StateCorrupted` if there is no `previous` link to roll back to.
pub fn rollback() -> Result<CachedCdm> {
    let root = default_cache_root().ok_or_else(|| {
        Error::state_corrupted("cannot resolve ~/.cache/silvervine/widevine cache root")
    })?;
    let platform = crate::widevine::manifest::current_platform_key()?;
    CdmCache::new(root, platform).rollback()
}

/// Test-friendly: rollback under an arbitrary cache root.
///
/// # Errors
///
/// See [`rollback`].
pub fn rollback_in(cache_root: &Path) -> Result<CachedCdm> {
    crate::lockfile::with_lock(&cache_root.join("download.lock"), || {
        rollback_unlocked(cache_root)
    })
}

fn rollback_unlocked(cache_root: &Path) -> Result<CachedCdm> {
    let previous = resolve_cache_link(cache_root, "previous")?.ok_or_else(|| {
        Error::state_corrupted("no previous CDM cached — nothing to roll back to")
    })?;
    let previous_link = cache_root.join("previous");
    let current_link = cache_root.join("current");
    if resolve_cache_link(cache_root, "current")?.is_some() {
        crate::platform::atomic_rename(&previous_link, &current_link)?;
    } else {
        std::fs::rename(&previous_link, &current_link).map_err(Error::from)?;
    }
    Ok(previous)
}

/// Keep the latest `keep` versions in the cache; remove older ones (and
/// any orphan staging directories from interrupted downloads).
///
/// `keep < 1` is treated as `1` — we never wipe the active CDM.
///
/// # Errors
///
/// `Other` for I/O failures reading the cache root.
pub fn prune(keep: usize) -> Result<usize> {
    let Some(root) = default_cache_root() else {
        return Ok(0);
    };
    let platform = crate::widevine::manifest::current_platform_key()?;
    CdmCache::new(root, platform).prune(keep)
}

/// Test-friendly: prune in an arbitrary cache root.
///
/// # Errors
///
/// See [`prune`].
pub fn prune_in(cache_root: &Path, keep: usize) -> Result<usize> {
    if !cache_root.exists() {
        return Ok(0);
    }
    crate::lockfile::with_lock(&cache_root.join("download.lock"), || {
        prune_unlocked(cache_root, keep)
    })
}

fn prune_unlocked(cache_root: &Path, keep: usize) -> Result<usize> {
    let keep = keep.max(1);
    let mut versions = list_versions(cache_root)?;
    versions.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(b.name.cmp(&a.name)));
    let active = resolve_cache_link(cache_root, "current")?.map(|cdm| cdm.version().to_string());
    let previous = resolve_cache_link(cache_root, "previous")?.map(|cdm| cdm.version().to_string());
    let mut deleted = 0;

    for (index, version) in versions.iter().enumerate() {
        if index < keep
            || active.as_deref() == Some(version.name.as_str())
            || previous.as_deref() == Some(version.name.as_str())
        {
            continue;
        }
        std::fs::remove_dir_all(&version.path).map_err(Error::from)?;
        deleted += 1;
    }

    for entry in std::fs::read_dir(cache_root).map_err(Error::from)? {
        let entry = entry.map_err(Error::from)?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".staging-"))
        {
            remove_cache_entry(&path)?;
        }
    }

    let downloads_dir = cache_root.join("downloads");
    match std::fs::read_dir(&downloads_dir) {
        Ok(entries) => {
            for entry in entries {
                let path = entry.map_err(Error::from)?.path();
                if path.extension().and_then(|extension| extension.to_str()) == Some("crx3") {
                    remove_cache_entry(&path)?;
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::from(error)),
    }
    Ok(deleted)
}

/// Recompute the active library's SHA-512 against metadata persisted when the
/// verified archive entered the cache.
///
/// `against` remains part of the stable API and confirms that the requested
/// platform exists, but integrity no longer depends on a remote manifest.
///
/// # Errors
///
/// `HashMismatch` on content drift; `StateCorrupted` on invalid metadata.
pub fn verify_integrity(against: &Manifest) -> Result<()> {
    let Some(root) = default_cache_root() else {
        return Ok(());
    };
    let platform = crate::widevine::manifest::current_platform_key()?;
    let _ = against.resolve_platform(platform)?;
    CdmCache::new(root, platform).verify_integrity()
}

/// Verify the active CDM using only its persisted local integrity metadata.
///
/// # Errors
///
/// `HashMismatch` on content drift; `StateCorrupted` on invalid metadata.
pub fn verify_current_integrity() -> Result<()> {
    let Some(root) = default_cache_root() else {
        return Ok(());
    };
    let platform = crate::widevine::manifest::current_platform_key()?;
    CdmCache::new(root, platform).verify_integrity()
}

/// Test-friendly variant: caller supplies the platform key and cache root.
///
/// # Errors
///
/// See [`verify_integrity`].
pub fn verify_integrity_with(
    manifest: &Manifest,
    platform: Platform,
    cache_root: &Path,
) -> Result<()> {
    let _ = manifest.resolve_platform(platform)?;
    CdmCache::new(cache_root, platform).verify_integrity()
}

/// Validate the platform directory and non-empty Widevine library.
fn integrity_check_dir(cdm_dir: &Path, platform: Platform) -> Result<()> {
    let platform_root = cdm_dir.join(PLATFORM_SPECIFIC_DIRECTORY);
    let platform_dir = platform_root.join(platform_directory(platform));
    for directory in [cdm_dir, platform_root.as_path(), platform_dir.as_path()] {
        let metadata = bundle_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::unknown_bundle_structure(format!(
                "{} is not a real cache directory",
                directory.display()
            )));
        }
    }

    let library_path = widevine_library_path(cdm_dir, platform);
    let metadata = bundle_metadata(&library_path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::unknown_bundle_structure(format!(
            "{} is not a regular Widevine library",
            library_path.display()
        )));
    }
    if metadata.len() == 0 || metadata.len() > MAX_CACHED_LIBRARY_BYTES {
        return Err(Error::hash_mismatch(format!(
            "{} has an invalid size — cache is corrupt",
            library_path.display()
        )));
    }
    Ok(())
}

fn validate_cached_cdm(cdm: &CachedCdm, platform: Platform) -> Result<CacheMetadata> {
    validate_extracted_cdm(cdm, platform)?;
    read_cache_metadata(cdm, platform)
}

fn validate_extracted_cdm(cdm: &CachedCdm, platform: Platform) -> Result<()> {
    validate_version(cdm.version())?;
    integrity_check_dir(cdm.cdm_dir(), platform)?;
    let manifest_path = cdm.cdm_dir().join(CDM_MANIFEST_FILENAME);
    let manifest_meta = bundle_metadata(&manifest_path)?;
    if !manifest_meta.is_file() || manifest_meta.file_type().is_symlink() {
        return Err(Error::unknown_bundle_structure(format!(
            "{} is not a regular manifest",
            manifest_path.display()
        )));
    }
    let version = crate::widevine::manifest::read_installed_cdm_version(&manifest_path)?;
    if version != cdm.version() {
        return Err(Error::state_corrupted(format!(
            "cached Widevine version {version} does not match cache directory {}",
            cdm.version()
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedPayloadDigests {
    library_sha512: String,
    manifest_sha512: String,
    library_size: u64,
}

/// Hash exactly the ZIP entry size validated during metadata preflight.
///
/// `zip` exposes the central-directory size but may yield more decompressed
/// bytes from a forged stream. Reading at most one byte beyond the declaration
/// makes that mismatch observable without unbounded CPU work.
fn authenticated_zip_entry_digest(
    reader: impl Read,
    expected_size: u64,
    name: &str,
) -> Result<String> {
    let read_limit = expected_size.checked_add(1).ok_or_else(|| {
        Error::unknown_bundle_structure("authenticated ZIP entry size limit overflow")
    })?;
    let mut bounded = reader.take(read_limit);
    let digest = download::sha512_reader(&mut bounded)?;
    let actual_size = read_limit - bounded.limit();
    if actual_size != expected_size {
        return Err(Error::unknown_bundle_structure(format!(
            "authenticated ZIP entry {name} yielded {actual_size} bytes while hashing; declared {expected_size}"
        )));
    }
    Ok(digest)
}

/// Derive library and root-manifest digests from the authenticated in-memory
/// CRX ZIP body before trusting any extracted on-disk bytes.
fn authenticated_payload_digests_from_zip(
    zip_body: &[u8],
    platform: Platform,
) -> Result<AuthenticatedPayloadDigests> {
    extract::validate_zip_entry_count(zip_body)?;
    let cursor = std::io::Cursor::new(zip_body);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|error| {
        Error::unknown_bundle_structure("CRX3 ZIP body is malformed").with_source(error)
    })?;

    let mut declared_total = 0u64;
    let mut archive_paths = std::collections::HashSet::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| {
            Error::unknown_bundle_structure(format!("zip entry {index}")).with_source(error)
        })?;
        let rel = extract::validate_zip_entry_metadata(&entry, &mut declared_total)?;
        if !archive_paths.insert(rel) {
            return Err(Error::unknown_bundle_structure(format!(
                "CRX3 contains duplicate normalized ZIP path {}",
                entry.name()
            )));
        }
    }

    let library_path = PathBuf::from(PLATFORM_SPECIFIC_DIRECTORY)
        .join(platform_directory(platform))
        .join(platform_library(platform));
    let library_name = library_path.display().to_string();
    let mut library_digest = None;
    let mut manifest_digest = None;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| {
            Error::unknown_bundle_structure(format!("zip entry {index}")).with_source(error)
        })?;
        let rel = extract::normalized_zip_entry_path(&entry)?;
        if entry.is_dir() {
            continue;
        }
        if rel == Path::new(CDM_MANIFEST_FILENAME) {
            if manifest_digest.is_some() {
                return Err(Error::unknown_bundle_structure(
                    "CRX3 contains duplicate normalized root manifest.json entries",
                ));
            }
            let size = entry.size();
            if size == 0 || size > MAX_CACHED_MANIFEST_BYTES {
                return Err(Error::unknown_bundle_structure(
                    "CRX3 root manifest.json has an invalid size",
                ));
            }
            manifest_digest = Some(authenticated_zip_entry_digest(
                &mut entry,
                size,
                CDM_MANIFEST_FILENAME,
            )?);
        } else if rel == library_path {
            if library_digest.is_some() {
                return Err(Error::unknown_bundle_structure(format!(
                    "CRX3 contains duplicate normalized library entries for {library_name}"
                )));
            }
            let size = entry.size();
            if size == 0 || size > MAX_CACHED_LIBRARY_BYTES {
                return Err(Error::hash_mismatch(
                    "CRX3 Widevine library entry has an invalid size",
                ));
            }
            library_digest = Some((
                authenticated_zip_entry_digest(&mut entry, size, &library_name)?,
                size,
            ));
        }
    }

    let (library_sha512, library_size) = library_digest.ok_or_else(|| {
        Error::unknown_bundle_structure(format!(
            "CRX3 is missing authenticated library entry {library_name}"
        ))
    })?;
    let manifest_sha512 = manifest_digest.ok_or_else(|| {
        Error::unknown_bundle_structure("CRX3 is missing authenticated root manifest.json")
    })?;

    Ok(AuthenticatedPayloadDigests {
        library_sha512,
        manifest_sha512,
        library_size,
    })
}

fn prove_extracted_matches_archive(
    cdm: &CachedCdm,
    platform: Platform,
    archive: &AuthenticatedPayloadDigests,
) -> Result<()> {
    let library_path = widevine_library_path(cdm.cdm_dir(), platform);
    let library_meta = bundle_metadata(&library_path)?;
    if library_meta.len() != archive.library_size {
        return Err(Error::hash_mismatch(format!(
            "{} size {} does not match authenticated CRX library size {}",
            library_path.display(),
            library_meta.len(),
            archive.library_size
        )));
    }
    let library_hash = download::sha512_file_hex(&library_path)?;
    if !library_hash.eq_ignore_ascii_case(&archive.library_sha512) {
        return Err(Error::hash_mismatch(format!(
            "{} SHA-512 does not match authenticated CRX library bytes",
            library_path.display()
        )));
    }

    let manifest_path = cdm.cdm_dir().join(CDM_MANIFEST_FILENAME);
    let manifest_hash = download::sha512_file_hex(&manifest_path)?;
    if !manifest_hash.eq_ignore_ascii_case(&archive.manifest_sha512) {
        return Err(Error::hash_mismatch(format!(
            "{} SHA-512 does not match authenticated CRX manifest bytes",
            manifest_path.display()
        )));
    }
    Ok(())
}

fn cached_matches_archive(
    cdm: &CachedCdm,
    platform: Platform,
    archive: &AuthenticatedPayloadDigests,
) -> bool {
    if validate_extracted_cdm(cdm, platform).is_err() {
        return false;
    }
    let library_path = widevine_library_path(cdm.cdm_dir(), platform);
    let Ok(library_meta) = bundle_metadata(&library_path) else {
        return false;
    };
    if library_meta.len() != archive.library_size {
        return false;
    }
    let Ok(library_hash) = download::sha512_file_hex(&library_path) else {
        return false;
    };
    if !library_hash.eq_ignore_ascii_case(&archive.library_sha512) {
        return false;
    }
    let manifest_path = cdm.cdm_dir().join(CDM_MANIFEST_FILENAME);
    let Ok(manifest_hash) = download::sha512_file_hex(&manifest_path) else {
        return false;
    };
    manifest_hash.eq_ignore_ascii_case(&archive.manifest_sha512)
}

fn write_cache_metadata(
    cdm: &CachedCdm,
    platform: Platform,
    archive: &AuthenticatedPayloadDigests,
) -> Result<()> {
    let metadata = CacheMetadata {
        schema_version: CACHE_METADATA_SCHEMA,
        version: cdm.version().to_string(),
        platform: platform_identifier(platform).to_string(),
        library_size: archive.library_size,
        library_sha512: archive.library_sha512.clone(),
        manifest_sha512: archive.manifest_sha512.clone(),
    };
    let path = cdm.cdm_dir().join(CACHE_METADATA_FILENAME);
    let mut body = serde_json::to_vec_pretty(&metadata)?;
    body.push(b'\n');
    crate::platform::atomic_write(&path, &body)
}

fn read_cache_metadata(cdm: &CachedCdm, platform: Platform) -> Result<CacheMetadata> {
    let path = cdm.cdm_dir().join(CACHE_METADATA_FILENAME);
    let metadata = bundle_metadata(&path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_CACHE_METADATA_BYTES
    {
        return Err(Error::state_corrupted(format!(
            "{} is not a bounded regular integrity metadata file",
            path.display()
        )));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path).map_err(Error::from)?;
    let mut body = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(0)
            .min(usize::try_from(MAX_CACHE_METADATA_BYTES).unwrap_or(usize::MAX)),
    );
    (&mut file)
        .take(MAX_CACHE_METADATA_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(Error::from)?;
    if body.len() as u64 > MAX_CACHE_METADATA_BYTES {
        return Err(Error::state_corrupted(format!(
            "{} grew beyond the integrity metadata size limit",
            path.display()
        )));
    }
    let metadata: CacheMetadata = serde_json::from_slice(&body).map_err(Error::from)?;
    if metadata.schema_version != CACHE_METADATA_SCHEMA
        || metadata.version != cdm.version()
        || metadata.platform != platform_identifier(platform)
        || metadata.library_size == 0
        || metadata.library_sha512.len() != 128
        || metadata.manifest_sha512.len() != 128
        || !metadata
            .library_sha512
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !metadata
            .manifest_sha512
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::state_corrupted(format!(
            "{} contains invalid integrity metadata",
            path.display()
        )));
    }
    Ok(metadata)
}

/// Recompute library and root-manifest digests against diagnostic cache metadata.
///
/// Returns the current library digest on success. Success is not an authenticity
/// root and never mints `verified_*` fields on [`CachedCdm`].
fn verify_cached_integrity(cdm: &CachedCdm, platform: Platform) -> Result<String> {
    let expected = validate_cached_cdm(cdm, platform)?;
    let library_path = widevine_library_path(cdm.cdm_dir(), platform);
    let actual_size = bundle_metadata(&library_path)?.len();
    if actual_size != expected.library_size {
        return Err(Error::hash_mismatch(format!(
            "{} size changed from {} to {} bytes",
            library_path.display(),
            expected.library_size,
            actual_size
        )));
    }
    let actual_hash = crate::file_memo::sha512_memoized(&library_path)?;
    if !actual_hash.eq_ignore_ascii_case(&expected.library_sha512) {
        return Err(Error::hash_mismatch(format!(
            "{} SHA-512 does not match persisted cache metadata",
            library_path.display()
        )));
    }
    let manifest_path = cdm.cdm_dir().join(CDM_MANIFEST_FILENAME);
    let actual_manifest = download::sha512_file_hex(&manifest_path)?;
    if !actual_manifest.eq_ignore_ascii_case(&expected.manifest_sha512) {
        return Err(Error::hash_mismatch(format!(
            "{} SHA-512 does not match persisted cache metadata",
            manifest_path.display()
        )));
    }
    Ok(actual_hash)
}

fn widevine_library_path(cdm_dir: &Path, platform: Platform) -> PathBuf {
    cdm_dir
        .join(PLATFORM_SPECIFIC_DIRECTORY)
        .join(platform_directory(platform))
        .join(platform_library(platform))
}

fn platform_identifier(platform: Platform) -> &'static str {
    match platform {
        Platform::LinuxX86_64 => "linux-x86_64",
        Platform::DarwinAarch64 => "darwin-aarch64",
        Platform::DarwinX86_64 => "darwin-x86_64",
    }
}

fn bundle_metadata(path: &Path) -> Result<std::fs::Metadata> {
    std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            Error::unknown_bundle_structure(format!("{} is missing", path.display()))
        } else {
            Error::from(error)
        }
    })
}

fn validate_version(version: &str) -> Result<()> {
    if version.is_empty()
        || !version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(Error::state_corrupted(format!(
            "invalid Widevine version {version:?}"
        )));
    }
    Ok(())
}

fn resolve_cache_link(cache_root: &Path, name: &str) -> Result<Option<CachedCdm>> {
    let link = cache_root.join(name);
    let link_meta = match std::fs::symlink_metadata(&link) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::from(error)),
    };
    if !link_meta.file_type().is_symlink() {
        return Err(Error::state_corrupted(format!(
            "{} is not a symlink",
            link.display()
        )));
    }
    let target = std::fs::read_link(&link).map_err(Error::from)?;
    let version = target.to_str().ok_or_else(|| {
        Error::state_corrupted(format!("{} has a non-UTF-8 target", link.display()))
    })?;
    validate_version(version)?;
    let resolved = cache_root.join(version);
    let target_meta = std::fs::symlink_metadata(&resolved).map_err(Error::from)?;
    if !target_meta.is_dir() || target_meta.file_type().is_symlink() {
        return Err(Error::state_corrupted(format!(
            "{} does not target a real cache directory",
            link.display()
        )));
    }
    Ok(Some(CachedCdm::new(version.to_string(), resolved)))
}

fn remove_cache_link(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::from(error)),
    };
    if !metadata.file_type().is_symlink() {
        return Err(Error::state_corrupted(format!(
            "{} is not a cache symlink",
            path.display()
        )));
    }
    std::fs::remove_file(path).map_err(Error::from)
}

fn remove_cache_entry(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(Error::from(error)),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path).map_err(Error::from)
    } else {
        std::fs::remove_file(path).map_err(Error::from)
    }
}

/// Snapshot of one entry under the cache root.
struct VersionEntry {
    name: String,
    path: PathBuf,
    mtime: std::time::SystemTime,
}

/// List all `<version>/` subdirectories under `cache_root` (excluding
/// the symlinks `current` / `previous` and any `.staging-*` orphans).
fn list_versions(cache_root: &Path) -> Result<Vec<VersionEntry>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(cache_root).map_err(Error::from)?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name == "current" || name == "previous" || name == "downloads" {
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        out.push(VersionEntry {
            name: name.to_string(),
            path,
            mtime,
        });
    }
    Ok(out)
}

/// Update `current` and `previous` symlinks to advance to `new_version`.
///
/// * `previous` ← whatever `current` was (deleted if `current` didn't exist).
/// * `current`  ← `new_version`.
/// * Both symlinks are *relative* to the cache root.
fn advance_current(cache_root: &Path, new_version: &str) -> Result<()> {
    validate_version(new_version)?;
    let current = resolve_cache_link(cache_root, "current")?;
    if current
        .as_ref()
        .is_some_and(|cdm| cdm.version() == new_version)
    {
        return Ok(());
    }

    if let Some(current) = current {
        replace_cache_link(cache_root, "previous", current.version())?;
    } else {
        remove_cache_link(&cache_root.join("previous"))?;
    }
    replace_cache_link(cache_root, "current", new_version)
}

fn replace_cache_link(cache_root: &Path, name: &str, target: &str) -> Result<()> {
    validate_version(target)?;
    let link = cache_root.join(name);
    if let Ok(metadata) = std::fs::symlink_metadata(&link) {
        if !metadata.file_type().is_symlink() {
            return Err(Error::state_corrupted(format!(
                "{} is not a cache symlink",
                link.display()
            )));
        }
    }

    let staged = cache_root.join(format!(".{name}.new"));
    remove_cache_entry(&staged)?;
    relative_symlink(target, &staged)?;
    if let Err(error) = std::fs::rename(&staged, &link) {
        let _ = remove_cache_entry(&staged);
        return Err(Error::from(error).with_context(format!(
            "replace cache symlink {} -> {}",
            link.display(),
            target
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn relative_symlink(target: &str, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link).map_err(|e| {
        Error::from(e).with_context(format!("create symlink {} -> {}", link.display(), target))
    })
}

#[cfg(not(unix))]
fn relative_symlink(_target: &str, _link: &Path) -> Result<()> {
    Err(Error::unsupported_platform(
        "symlink creation is only supported on Unix",
    ))
}

#[cfg(test)]
mod tests;
