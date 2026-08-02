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
    download, extract, platform_directory, platform_library, CDM_MANIFEST_FILENAME,
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
/// 2. Authenticate the vendor CRX against its manifest SHA-512 and extract
///    those exact verified bytes into a staging directory.
/// 3. Derive library and root-manifest digests from the in-memory CRX ZIP
///    body, then prove the staged extraction matches those digests.
/// 4. Reuse an existing version only when both current library and root
///    manifest digests match the vendor-authenticated archive values.
/// 5. Otherwise replace the unauthenticated entry with the staged payload.
/// 6. Advance the `current` symlink (and demote the previous one).
/// 7. Return a [`CachedCdm`] handle carrying both archive-derived digests.
///
/// # Errors
///
/// * `NetworkError` / `ManifestFetchFailed` — download chain failed.
/// * `HashMismatch` — bytes verified differently than the manifest claimed.
/// * `UnknownBundleStructure` — extracted CRX3 doesn't have the expected layout.
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
    let vendor = manifest.widevine()?;
    let version = vendor.version.clone();
    validate_version(&version)?;
    let entry = manifest.resolve_platform(cache.platform)?;
    let target_dir = cache.root.join(&version);
    let cached = CachedCdm::new(version.clone(), target_dir.clone());

    let staging = cache.root.join(format!(".staging-{version}"));
    remove_cache_entry(&staging)?;
    let crx = download::download_verified(entry, &cache.root.join("downloads"))?;
    let archive = authenticated_payload_digests_from_crx(crx.bytes(), cache.platform)?;
    extract::extract_crx3_bytes(crx.bytes(), &staging)?;
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

/// Derive library and root-manifest digests from the authenticated in-memory
/// CRX ZIP body before trusting any extracted on-disk bytes.
fn authenticated_payload_digests_from_crx(
    crx_bytes: &[u8],
    platform: Platform,
) -> Result<AuthenticatedPayloadDigests> {
    let zip_offset = extract::parse_crx3_header(crx_bytes)?;
    let zip_body = &crx_bytes[zip_offset..];
    let cursor = std::io::Cursor::new(zip_body);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|error| {
        Error::unknown_bundle_structure("CRX3 ZIP body is malformed").with_source(error)
    })?;

    let library_name = format!(
        "{PLATFORM_SPECIFIC_DIRECTORY}/{}/{}",
        platform_directory(platform),
        platform_library(platform)
    );
    let mut library_digest = None;
    let mut manifest_digest = None;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|error| {
            Error::unknown_bundle_structure(format!("zip entry {index}")).with_source(error)
        })?;
        let Some(rel) = entry.enclosed_name() else {
            return Err(Error::unknown_bundle_structure(format!(
                "zip entry {} has unsafe path",
                entry.name()
            )));
        };
        if entry.is_dir() {
            continue;
        }
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if rel_str == CDM_MANIFEST_FILENAME {
            let size = entry.size();
            if size == 0 || size > MAX_CACHED_MANIFEST_BYTES {
                return Err(Error::unknown_bundle_structure(
                    "CRX3 root manifest.json has an invalid size",
                ));
            }
            manifest_digest = Some(download::sha512_reader(&mut entry)?);
        } else if rel_str == library_name {
            let size = entry.size();
            if size == 0 || size > MAX_CACHED_LIBRARY_BYTES {
                return Err(Error::hash_mismatch(
                    "CRX3 Widevine library entry has an invalid size",
                ));
            }
            library_digest = Some((download::sha512_reader(&mut entry)?, size));
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
    let actual_hash = download::sha512_file_hex(&library_path)?;
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
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    use crate::widevine::manifest::{GmpVendor, PlatformEntry};

    /// Build a synthetic manifest with one Linux entry whose hash matches
    /// `body`.
    fn synthetic_manifest(body: &[u8], version: &str) -> Manifest {
        let hash = download::sha512_hex(body);
        let mut platforms = HashMap::new();
        platforms.insert(
            "Linux_x86_64-gcc3".to_string(),
            PlatformEntry::Concrete {
                file_url: "http://127.0.0.1:1/will-not-be-used".into(),
                mirror_urls: vec![],
                filesize: Some(body.len() as u64),
                hash_value: hash,
            },
        );
        Manifest {
            hash_function: Some("sha512".into()),
            name: Some(format!("Widevine-{version}")),
            vendors: HashMap::from([(
                "gmp-widevinecdm".to_string(),
                GmpVendor {
                    platforms,
                    version: version.to_string(),
                },
            )]),
        }
    }

    /// Write a fake CDM directory layout under `dir/<version>/`.
    fn make_cached_version(cache_root: &Path, version: &str) -> PathBuf {
        make_cached_version_with(cache_root, version, b"non-empty")
    }

    fn make_cached_version_with(cache_root: &Path, version: &str, library: &[u8]) -> PathBuf {
        let dir = cache_root.join(version);
        let plat = dir.join("_platform_specific").join("linux_x64");
        fs::create_dir_all(&plat).expect("mkdir");
        fs::write(plat.join("libwidevinecdm.so"), library).expect("write so");
        let manifest_body = format!(r#"{{"version":"{version}"}}"#);
        fs::write(dir.join("manifest.json"), &manifest_body).expect("write manifest");
        let cdm = CachedCdm::new(version.to_string(), dir.clone());
        let archive = AuthenticatedPayloadDigests {
            library_size: library.len() as u64,
            library_sha512: download::sha512_hex(library),
            manifest_sha512: download::sha512_hex(manifest_body.as_bytes()),
        };
        write_cache_metadata(&cdm, Platform::LinuxX86_64, &archive).expect("write metadata");
        dir
    }

    #[test]
    fn current_in_returns_none_when_no_link() {
        let tmp = TempDir::new().expect("tempdir");
        let cur = current_in(tmp.path()).expect("ok");
        assert!(cur.is_none());
    }

    #[test]
    fn validated_current_accepts_complete_matching_cache() {
        let tmp = TempDir::new().expect("tempdir");
        let expected = make_cached_version(tmp.path(), "1.0.0");
        advance_current(tmp.path(), "1.0.0").expect("advance");

        let current = validated_current_in(tmp.path(), Platform::LinuxX86_64)
            .expect("valid cache")
            .expect("current");

        assert_eq!(current.version(), "1.0.0");
        assert_eq!(current.cdm_dir(), expected);
        // Local integrity metadata is diagnostic only — never patch authority.
        assert!(current.verified_library_sha512().is_none());
        assert!(current.verified_manifest_sha512().is_none());
    }

    #[test]
    fn attacker_rewritten_integrity_metadata_cannot_authorize_patch_marker() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm_dir = make_cached_version(tmp.path(), "1.0.0");
        let evil = b"attacker-controlled-library";
        fs::write(
            cdm_dir.join("_platform_specific/linux_x64/libwidevinecdm.so"),
            evil,
        )
        .expect("rewrite library");
        let poisoned = CachedCdm::new("1.0.0".into(), cdm_dir.clone());
        let archive = AuthenticatedPayloadDigests {
            library_size: evil.len() as u64,
            library_sha512: download::sha512_hex(evil),
            manifest_sha512: download::sha512_hex(br#"{"version":"1.0.0"}"#),
        };
        write_cache_metadata(&poisoned, Platform::LinuxX86_64, &archive)
            .expect("attacker rewrites colocated metadata");
        advance_current(tmp.path(), "1.0.0").expect("advance");

        let current = validated_current_in(tmp.path(), Platform::LinuxX86_64)
            .expect("metadata+bytes agree structurally")
            .expect("current");
        assert!(current.verified_library_sha512().is_none());
        assert!(current.verified_manifest_sha512().is_none());

        let error = crate::widevine::ownership::marker_for_cached(&current)
            .expect_err("metadata-only current must not yield patch marker");
        assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);

        let rolled = CdmCache::new(tmp.path(), Platform::LinuxX86_64);
        // Seed a previous entry so rollback can select it.
        let previous = make_cached_version_with(tmp.path(), "0.9.0", b"previous-lib");
        relative_symlink("0.9.0", &tmp.path().join("previous")).expect("previous");
        let selected = rolled.rollback().expect("rollback is a selection op");
        assert_eq!(selected.version(), "0.9.0");
        assert_eq!(selected.cdm_dir(), previous);
        assert!(selected.verified_library_sha512().is_none());
        assert!(selected.verified_manifest_sha512().is_none());
        let error = crate::widevine::ownership::marker_for_cached(&selected)
            .expect_err("rollback selection is not patch authority");
        assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);
    }

    #[test]
    fn validated_current_rejects_missing_integrity_metadata() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm = make_cached_version(tmp.path(), "1.0.0");
        let metadata_path = cdm.join(CACHE_METADATA_FILENAME);
        fs::remove_file(&metadata_path).expect("remove metadata");
        advance_current(tmp.path(), "1.0.0").expect("advance");

        let error = validated_current_in(tmp.path(), Platform::LinuxX86_64)
            .expect_err("unverified legacy bytes must not be locally re-baselined");

        assert_eq!(error.category, crate::ErrorCategory::UnknownBundleStructure);
        assert!(!metadata_path.exists());
    }

    #[test]
    fn validated_current_rejects_malformed_integrity_metadata() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm = make_cached_version(tmp.path(), "1.0.0");
        fs::write(cdm.join(CACHE_METADATA_FILENAME), b"{}").expect("corrupt metadata");
        advance_current(tmp.path(), "1.0.0").expect("advance");

        let error =
            validated_current_in(tmp.path(), Platform::LinuxX86_64).expect_err("metadata invalid");

        assert_eq!(error.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn validated_current_rejects_empty_library() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm = make_cached_version(tmp.path(), "1.0.0");
        fs::write(
            cdm.join("_platform_specific/linux_x64/libwidevinecdm.so"),
            b"",
        )
        .expect("truncate library");
        advance_current(tmp.path(), "1.0.0").expect("advance");

        let error =
            validated_current_in(tmp.path(), Platform::LinuxX86_64).expect_err("corrupt cache");

        assert_eq!(error.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn validated_current_rejects_manifest_version_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm = make_cached_version(tmp.path(), "1.0.0");
        fs::write(cdm.join("manifest.json"), r#"{"version":"2.0.0"}"#).expect("replace manifest");
        advance_current(tmp.path(), "1.0.0").expect("advance");

        let error =
            validated_current_in(tmp.path(), Platform::LinuxX86_64).expect_err("mismatched cache");

        assert_eq!(error.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn validated_cache_requires_the_requested_platform_layout() {
        let tmp = TempDir::new().expect("tempdir");
        for (version, platform, directory) in [
            ("1.0.0", Platform::DarwinAarch64, "mac_arm64"),
            ("2.0.0", Platform::DarwinX86_64, "mac_x64"),
        ] {
            let cdm = tmp.path().join(version);
            let platform_dir = cdm.join("_platform_specific").join(directory);
            fs::create_dir_all(&platform_dir).expect("platform dir");
            let library = b"non-empty";
            fs::write(platform_dir.join("libwidevinecdm.dylib"), library).expect("library");
            let manifest_body = format!(r#"{{"version":"{version}"}}"#);
            fs::write(cdm.join("manifest.json"), &manifest_body).expect("manifest");
            let cached = CachedCdm::new(version.into(), cdm);
            let archive = AuthenticatedPayloadDigests {
                library_size: library.len() as u64,
                library_sha512: download::sha512_hex(library),
                manifest_sha512: download::sha512_hex(manifest_body.as_bytes()),
            };
            write_cache_metadata(&cached, platform, &archive).expect("metadata");
            validate_cached_cdm(&cached, platform).expect("platform cache");
        }

        let linux = CachedCdm::new("3.0.0".into(), make_cached_version(tmp.path(), "3.0.0"));
        assert!(validate_cached_cdm(&linux, Platform::DarwinX86_64).is_err());
    }

    #[test]
    fn current_in_rejects_absolute_or_symlinked_external_targets() {
        let tmp = TempDir::new().expect("tempdir");
        let external = TempDir::new().expect("external");
        make_cached_version(external.path(), "1.0.0");
        std::os::unix::fs::symlink(external.path().join("1.0.0"), tmp.path().join("current"))
            .expect("absolute current link");
        assert!(current_in(tmp.path()).is_err());

        fs::remove_file(tmp.path().join("current")).expect("remove current");
        std::os::unix::fs::symlink(external.path().join("1.0.0"), tmp.path().join("1.0.0"))
            .expect("external version link");
        relative_symlink("1.0.0", &tmp.path().join("current")).expect("current link");
        assert!(current_in(tmp.path()).is_err());
    }

    #[test]
    fn validated_cache_rejects_symlinked_platform_tree() {
        let tmp = TempDir::new().expect("tempdir");
        let external = TempDir::new().expect("external");
        let cdm = tmp.path().join("1.0.0");
        fs::create_dir_all(&cdm).expect("cache dir");
        fs::write(cdm.join("manifest.json"), r#"{"version":"1.0.0"}"#).expect("manifest");
        let platform = external.path().join("linux_x64");
        fs::create_dir_all(&platform).expect("platform dir");
        fs::write(platform.join("libwidevinecdm.so"), b"non-empty").expect("library");
        std::os::unix::fs::symlink(external.path(), cdm.join("_platform_specific"))
            .expect("platform symlink");

        let cached = CachedCdm::new("1.0.0".into(), cdm);
        assert!(validate_cached_cdm(&cached, Platform::LinuxX86_64).is_err());
    }

    #[test]
    fn advance_current_creates_symlink_chain() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0.0");
        make_cached_version(tmp.path(), "2.0.0");
        advance_current(tmp.path(), "1.0.0").expect("first");
        let cur = current_in(tmp.path()).expect("read").expect("some");
        assert_eq!(cur.version(), "1.0.0");
        // Advance again; previous should now be 1.0.0.
        advance_current(tmp.path(), "2.0.0").expect("second");
        let cur2 = current_in(tmp.path()).expect("read").expect("some");
        assert_eq!(cur2.version(), "2.0.0");
        let prev = std::fs::read_link(tmp.path().join("previous")).expect("read");
        assert_eq!(prev.file_name().and_then(|s| s.to_str()), Some("1.0.0"));
    }

    #[test]
    fn rollback_in_swaps_current_and_previous() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0.0");
        make_cached_version(tmp.path(), "2.0.0");
        advance_current(tmp.path(), "1.0.0").expect("first");
        advance_current(tmp.path(), "2.0.0").expect("second");
        let rolled = rollback_in(tmp.path()).expect("rollback");
        assert_eq!(rolled.version(), "1.0.0");
        let cur = current_in(tmp.path()).expect("read").expect("some");
        assert_eq!(cur.version(), "1.0.0");
        // After rollback, previous now points at 2.0.0.
        let prev = std::fs::read_link(tmp.path().join("previous")).expect("read");
        assert_eq!(prev.file_name().and_then(|s| s.to_str()), Some("2.0.0"));
    }

    #[test]
    fn cache_rollback_rejects_tampered_previous_version() {
        let tmp = TempDir::new().expect("tempdir");
        let previous = make_cached_version(tmp.path(), "1.0.0");
        make_cached_version(tmp.path(), "2.0.0");
        advance_current(tmp.path(), "1.0.0").expect("first");
        advance_current(tmp.path(), "2.0.0").expect("second");
        fs::write(
            previous.join("_platform_specific/linux_x64/libwidevinecdm.so"),
            b"tampered",
        )
        .expect("tamper previous");

        let error = CdmCache::new(tmp.path(), Platform::LinuxX86_64)
            .rollback()
            .expect_err("tampered rollback target must fail");

        assert_eq!(error.category, crate::ErrorCategory::HashMismatch);
        assert_eq!(
            current_in(tmp.path())
                .expect("read current")
                .expect("current")
                .version(),
            "2.0.0"
        );
        let previous_link = fs::read_link(tmp.path().join("previous")).expect("read previous");
        assert_eq!(
            previous_link.file_name().and_then(|name| name.to_str()),
            Some("1.0.0")
        );
    }

    #[test]
    fn rollback_in_errors_when_no_previous() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0.0");
        advance_current(tmp.path(), "1.0.0").expect("first");
        let err = rollback_in(tmp.path()).expect_err("nothing to rollback to");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn prune_in_keeps_latest_n_versions() {
        let tmp = TempDir::new().expect("tempdir");
        // Five versions, ordered by mtime. We touch each in order so the
        // mtime sort is deterministic regardless of FS resolution.
        for v in ["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0"] {
            make_cached_version(tmp.path(), v);
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        advance_current(tmp.path(), "5.0.0").expect("current");
        // Keep latest 3.
        let deleted = prune_in(tmp.path(), 3).expect("prune");
        assert_eq!(deleted, 2);
        // 1.0.0 and 2.0.0 should be gone.
        assert!(!tmp.path().join("1.0.0").exists());
        assert!(!tmp.path().join("2.0.0").exists());
        // 3, 4, 5 remain.
        assert!(tmp.path().join("3.0.0").exists());
        assert!(tmp.path().join("5.0.0").exists());
    }

    #[test]
    fn prune_in_never_deletes_active_or_previous() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0.0");
        make_cached_version(tmp.path(), "2.0.0");
        advance_current(tmp.path(), "1.0.0").expect("a");
        advance_current(tmp.path(), "2.0.0").expect("b"); // prev = 1.0.0
                                                          // keep=1, but neither active nor previous should be deleted.
        let _ = prune_in(tmp.path(), 1).expect("prune");
        assert!(tmp.path().join("1.0.0").exists());
        assert!(tmp.path().join("2.0.0").exists());
    }

    #[test]
    fn prune_in_removes_orphan_staging_dirs() {
        let tmp = TempDir::new().expect("tempdir");
        let staging = tmp.path().join(".staging-9.9.9");
        fs::create_dir_all(&staging).expect("mkdir staging");
        let _ = prune_in(tmp.path(), 3).expect("prune");
        assert!(!staging.exists());
    }

    /// `prune_in` sweeps stale `.crx3` archives from `downloads/`. They
    /// pile up because old silvervine versions didn't remove the downloaded
    /// CRX3 after extracting it. Each is ~5–7 MB and `list_versions`
    /// explicitly skips the `downloads/` subdir, so without this sweep
    /// the disk usage grows unbounded.
    #[test]
    fn prune_in_sweeps_stale_crx3_from_downloads() {
        let tmp = TempDir::new().expect("tempdir");
        let downloads = tmp.path().join("downloads");
        fs::create_dir_all(&downloads).expect("mkdir downloads");
        let stale = downloads.join("4.10.2891.0.crx3");
        let stale2 = downloads.join("4.10.2934.0.crx3");
        let unrelated = downloads.join("README.txt");
        fs::write(&stale, b"old crx").unwrap();
        fs::write(&stale2, b"old crx").unwrap();
        fs::write(&unrelated, b"keep me").unwrap();
        let _ = prune_in(tmp.path(), 3).expect("prune");
        assert!(!stale.exists(), "stale crx3 must be removed");
        assert!(!stale2.exists(), "stale crx3 must be removed");
        assert!(
            unrelated.exists(),
            "non-crx3 files in downloads/ must be left alone"
        );
    }

    #[test]
    fn integrity_check_dir_passes_for_present_so() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm = make_cached_version(tmp.path(), "x");
        integrity_check_dir(&cdm, Platform::LinuxX86_64).expect("integrity ok");
    }

    #[test]
    fn integrity_check_dir_errors_for_missing_so() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("x");
        fs::create_dir_all(dir.join("_platform_specific").join("linux_x64")).expect("mkdir");
        let err = integrity_check_dir(&dir, Platform::LinuxX86_64).expect_err("no so");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn integrity_check_dir_errors_for_empty_so() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("x");
        let plat = dir.join("_platform_specific").join("linux_x64");
        fs::create_dir_all(&plat).expect("mkdir");
        fs::write(plat.join("libwidevinecdm.so"), b"").expect("touch empty");
        let err = integrity_check_dir(&dir, Platform::LinuxX86_64).expect_err("empty so");
        assert_eq!(err.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn verify_integrity_with_passes_when_no_current() {
        let tmp = TempDir::new().expect("tempdir");
        let manifest = synthetic_manifest(b"unused", "1.0");
        // No current symlink yet; should be a no-op rather than an error.
        verify_integrity_with(&manifest, Platform::LinuxX86_64, tmp.path()).expect("no-op");
    }

    #[test]
    fn verify_integrity_with_passes_for_present_so() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0");
        advance_current(tmp.path(), "1.0").expect("advance");
        let manifest = synthetic_manifest(b"unused", "1.0");
        verify_integrity_with(&manifest, Platform::LinuxX86_64, tmp.path()).expect("integrity ok");
    }

    #[test]
    fn persisted_integrity_hash_detects_nonempty_library_tampering() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = make_cached_version(tmp.path(), "1.0");
        advance_current(tmp.path(), "1.0").expect("advance");
        fs::write(
            dir.join("_platform_specific/linux_x64/libwidevinecdm.so"),
            b"different-but-non-empty",
        )
        .expect("tamper");

        let cache = CdmCache::new(tmp.path(), Platform::LinuxX86_64);
        let error = cache
            .verify_integrity()
            .expect_err("non-empty tampering must fail");

        assert_eq!(error.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn list_versions_excludes_symlinks_and_orphan_staging() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0.0");
        make_cached_version(tmp.path(), "2.0.0");
        // Synthetic symlinks (using the helper).
        relative_symlink("1.0.0", &tmp.path().join("current")).expect("link");
        relative_symlink("2.0.0", &tmp.path().join("previous")).expect("link");
        fs::create_dir_all(tmp.path().join(".staging-x")).expect("mkdir staging");
        let versions = list_versions(tmp.path()).expect("list");
        let names: Vec<&str> = versions.iter().map(|v| v.name.as_str()).collect();
        assert!(names.contains(&"1.0.0"));
        assert!(names.contains(&"2.0.0"));
        assert!(!names.contains(&"current"));
        assert!(!names.contains(&"previous"));
        assert!(!names.iter().any(|n| n.starts_with('.')));
    }

    #[test]
    fn ensure_cdm_for_with_reuses_only_vendor_authenticated_cache_bytes() {
        let tmp = TempDir::new().expect("tempdir");
        let crx = build_synthetic_crx3("1.0.0");
        let online_url = spawn_crx_server(crx.clone());
        let online_manifest = manifest_for_crx(&online_url, &crx, "1.0.0");
        ensure_cdm_for_with(&online_manifest, Platform::LinuxX86_64, tmp.path())
            .expect("seed authenticated cache");

        let offline_manifest = manifest_for_crx("http://127.0.0.1:1/not-requested", &crx, "1.0.0");
        let cdm = ensure_cdm_for_with(&offline_manifest, Platform::LinuxX86_64, tmp.path())
            .expect("authenticated archive cache hit");

        assert_eq!(cdm.version(), "1.0.0");
        assert!(cdm.cdm_dir().ends_with("1.0.0"));
        assert!(tmp.path().join("current").exists());
    }

    #[test]
    fn ensure_cdm_for_with_repairs_legacy_schema1_metadata_on_cache_hit() {
        let crx = build_synthetic_crx3("3.3.3");
        let url = spawn_crx_server(crx.clone());
        let manifest = manifest_for_crx(&url, &crx, "3.3.3");
        let tmp = TempDir::new().expect("tempdir");

        // Seed a payload that matches the vendor CRX library+manifest bytes,
        // but only carries legacy schema-1 integrity metadata (no manifest digest).
        let dir = tmp.path().join("3.3.3");
        let plat = dir.join("_platform_specific").join("linux_x64");
        fs::create_dir_all(&plat).expect("mkdir");
        fs::write(plat.join("libwidevinecdm.so"), b"\x7fELF-fake-cdm-content").expect("library");
        let manifest_body = br#"{"name":"WidevineCdm","version":"3.3.3"}"#;
        fs::write(dir.join("manifest.json"), manifest_body).expect("manifest");
        let legacy = serde_json::json!({
            "schema_version": 1,
            "version": "3.3.3",
            "platform": "linux-x86_64",
            "library_size": b"\x7fELF-fake-cdm-content".len(),
            "library_sha512": download::sha512_hex(b"\x7fELF-fake-cdm-content"),
        });
        fs::write(
            dir.join(CACHE_METADATA_FILENAME),
            serde_json::to_vec_pretty(&legacy).expect("json"),
        )
        .expect("legacy metadata");
        advance_current(tmp.path(), "3.3.3").expect("advance");

        // Structural validation must reject schema-1 before repair.
        let before = CachedCdm::new("3.3.3".into(), dir.clone());
        assert!(
            validate_cached_cdm(&before, Platform::LinuxX86_64).is_err(),
            "schema-1 metadata must fail current structural validation"
        );

        let repaired = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect("matching legacy entry must be reused and metadata-repaired");

        assert!(repaired.verified_library_sha512().is_some());
        assert!(repaired.verified_manifest_sha512().is_some());
        validate_cached_cdm(&repaired, Platform::LinuxX86_64)
            .expect("repaired schema-2 metadata must validate");
        let metadata: serde_json::Value = serde_json::from_slice(
            &fs::read(repaired.cdm_dir().join(CACHE_METADATA_FILENAME)).expect("metadata"),
        )
        .expect("metadata json");
        assert_eq!(metadata["schema_version"], 2);
        assert_eq!(
            metadata["manifest_sha512"],
            download::sha512_hex(manifest_body)
        );

        // Local drift checks now succeed without elevating metadata into verified_*.
        let current = validated_current_in(tmp.path(), Platform::LinuxX86_64)
            .expect("validated")
            .expect("current");
        assert!(current.verified_library_sha512().is_none());
        assert!(current.verified_manifest_sha512().is_none());
    }

    #[test]
    fn concurrent_authenticated_cache_hits_preserve_current_and_previous() {
        let tmp = TempDir::new().expect("tempdir");
        let mut fixtures = Vec::new();
        for version in ["1.0.0", "2.0.0"] {
            let crx = build_synthetic_crx3(version);
            let online_url = spawn_crx_server(crx.clone());
            let online_manifest = manifest_for_crx(&online_url, &crx, version);
            ensure_cdm_for_with(&online_manifest, Platform::LinuxX86_64, tmp.path())
                .expect("seed authenticated cache");
            fixtures.push((version.to_string(), crx));
        }

        let root = tmp.path().to_path_buf();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for (version, crx) in fixtures {
            let root = root.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let manifest = manifest_for_crx("http://127.0.0.1:1/not-requested", &crx, &version);
                barrier.wait();
                ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, &root)
            }));
        }
        barrier.wait();
        for handle in handles {
            handle
                .join()
                .expect("thread")
                .expect("authenticated cache hit");
        }

        let current = resolve_cache_link(tmp.path(), "current")
            .expect("current")
            .expect("current target");
        let previous = resolve_cache_link(tmp.path(), "previous")
            .expect("previous")
            .expect("previous target");
        let mut versions = [current.version(), previous.version()];
        versions.sort_unstable();
        assert_eq!(versions, ["1.0.0", "2.0.0"]);
    }

    #[test]
    fn default_cache_root_resolves_under_silvervine_subdir() {
        if let Some(p) = default_cache_root() {
            let suffix = std::path::Path::new("silvervine").join("widevine");
            assert!(p.ends_with(&suffix));
        }
    }

    /// Build a minimal CRX3 wrapping a synthesized ZIP.
    fn build_synthetic_crx3(version: &str) -> Vec<u8> {
        use std::io::{Cursor, Write};
        use zip::write::SimpleFileOptions;
        use zip::ZipWriter;

        let mut zip_bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_bytes);
            let mut zip = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("manifest.json", opts).expect("start");
            zip.write_all(format!(r#"{{"name":"WidevineCdm","version":"{version}"}}"#).as_bytes())
                .expect("write");
            zip.start_file("_platform_specific/linux_x64/libwidevinecdm.so", opts)
                .expect("start");
            zip.write_all(b"\x7fELF-fake-cdm-content").expect("write");
            zip.finish().expect("finish");
        }
        let mut crx = Vec::new();
        crx.extend_from_slice(b"Cr24");
        crx.extend_from_slice(&3u32.to_le_bytes());
        crx.extend_from_slice(&0u32.to_le_bytes());
        crx.extend_from_slice(&zip_bytes);
        crx
    }

    /// Build a manifest for a CRX3 served at `url`.
    fn manifest_for_crx(url: &str, body: &[u8], version: &str) -> Manifest {
        let mut platforms = HashMap::new();
        platforms.insert(
            "Linux_x86_64-gcc3".to_string(),
            PlatformEntry::Concrete {
                file_url: url.to_string(),
                mirror_urls: vec![],
                filesize: Some(body.len() as u64),
                hash_value: download::sha512_hex(body),
            },
        );
        Manifest {
            hash_function: Some("sha512".into()),
            name: Some(format!("Widevine-{version}")),
            vendors: HashMap::from([(
                "gmp-widevinecdm".to_string(),
                GmpVendor {
                    platforms,
                    version: version.to_string(),
                },
            )]),
        }
    }

    /// Spin up a stub server that serves the CRX3 body for one GET.
    fn spawn_crx_server(body: Vec<u8>) -> String {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let local = listener.local_addr().expect("local_addr");
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
        format!("http://{local}/widevine.crx3")
    }

    /// The download-scoped lockfile must be created the first time
    /// `ensure_cdm_for_with` takes its slow path. Two concurrent silvervine
    /// processes (CLI + daemon, double-click installer) used to race
    /// the staging→target rename and corrupt the cache; the lock
    /// serializes them. Verify the lockfile is materialized as
    /// evidence the gate fired.
    #[test]
    fn ensure_cdm_for_with_creates_download_lockfile() {
        let crx = build_synthetic_crx3("4.10.7.1");
        let url = spawn_crx_server(crx.clone());
        let manifest = manifest_for_crx(&url, &crx, "4.10.7.1");

        let tmp = TempDir::new().expect("tempdir");
        let _ = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect("first download must succeed");
        assert!(
            tmp.path().join("download.lock").exists(),
            "lockfile must exist after ensure_cdm_for_with promoted a version"
        );
    }

    /// End-to-end: download → extract → cache promotion → integrity check.
    #[test]
    fn ensure_cdm_for_with_downloads_and_promotes() {
        let crx = build_synthetic_crx3("1.2.3");
        let url = spawn_crx_server(crx.clone());
        let manifest = manifest_for_crx(&url, &crx, "1.2.3");

        let tmp = TempDir::new().expect("tempdir");
        let cdm = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect("download must succeed");
        assert_eq!(cdm.version(), "1.2.3");
        assert!(cdm.cdm_dir().exists());
        assert!(cdm.cdm_dir().join("manifest.json").exists());
        assert!(cdm.cdm_dir().join(CACHE_METADATA_FILENAME).exists());
        let so = cdm
            .cdm_dir()
            .join("_platform_specific")
            .join("linux_x64")
            .join("libwidevinecdm.so");
        assert!(so.exists());
        // current symlink resolves to the new version.
        let cur = current_in(tmp.path()).expect("current").expect("some");
        assert_eq!(cur.version(), "1.2.3");
    }

    /// `verify_integrity_with` flags a corrupted CDM (.so emptied after install).
    #[test]
    fn verify_integrity_with_detects_emptied_so() {
        let tmp = TempDir::new().expect("tempdir");
        let dir = make_cached_version(tmp.path(), "1.0");
        // Empty out the `.so`.
        let so = dir
            .join("_platform_specific")
            .join("linux_x64")
            .join("libwidevinecdm.so");
        fs::write(&so, b"").expect("truncate so");
        advance_current(tmp.path(), "1.0").expect("advance");
        let manifest = synthetic_manifest(b"unused", "1.0");
        let err = verify_integrity_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect_err("emptied so must fail integrity");
        assert_eq!(err.category, crate::ErrorCategory::HashMismatch);
    }

    /// `current_in` returns `StateCorrupted` when the symlink dangles.
    #[test]
    fn current_in_errors_on_dangling_symlink() {
        let tmp = TempDir::new().expect("tempdir");
        relative_symlink("does-not-exist", &tmp.path().join("current")).expect("link");
        let err = current_in(tmp.path()).expect_err("dangling link");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    /// Cache hit with corrupted CDM (`.so` missing) triggers re-download.
    #[test]
    fn ensure_cdm_for_with_redownloads_on_corrupt_cache_hit() {
        let crx = build_synthetic_crx3("9.9.9");
        let url = spawn_crx_server(crx.clone());
        let manifest = manifest_for_crx(&url, &crx, "9.9.9");

        let tmp = TempDir::new().expect("tempdir");
        // Pre-create a half-built version directory with a missing CDM .so.
        let half = tmp.path().join("9.9.9");
        let plat = half.join("_platform_specific").join("linux_x64");
        fs::create_dir_all(&plat).expect("mkdir");
        // No libwidevinecdm.so → integrity_check_dir fails → re-download.
        let cdm = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect("must redownload");
        assert!(cdm
            .cdm_dir()
            .join("_platform_specific")
            .join("linux_x64")
            .join("libwidevinecdm.so")
            .exists());
    }

    #[test]
    fn ensure_cdm_for_with_rejects_self_signed_cache_metadata() {
        let crx = build_synthetic_crx3("9.9.8");
        let url = spawn_crx_server(crx.clone());
        let manifest = manifest_for_crx(&url, &crx, "9.9.8");
        let tmp = TempDir::new().expect("tempdir");
        let cached = make_cached_version(tmp.path(), "9.9.8");
        let library = cached.join("_platform_specific/linux_x64/libwidevinecdm.so");
        let evil = b"evil-code";
        fs::write(&library, evil).expect("replace cached library");
        let poisoned = CachedCdm::new("9.9.8".into(), cached);
        let archive = AuthenticatedPayloadDigests {
            library_size: evil.len() as u64,
            library_sha512: download::sha512_hex(evil),
            manifest_sha512: download::sha512_hex(br#"{"version":"9.9.8"}"#),
        };
        write_cache_metadata(&poisoned, Platform::LinuxX86_64, &archive)
            .expect("attacker rewrites colocated metadata");

        let repaired = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect("digest drift must trigger a verified replacement");

        assert_eq!(
            fs::read(
                repaired
                    .cdm_dir()
                    .join("_platform_specific/linux_x64/libwidevinecdm.so")
            )
            .expect("repaired library"),
            b"\x7fELF-fake-cdm-content"
        );
        assert!(repaired.verified_library_sha512().is_some());
        assert!(repaired.verified_manifest_sha512().is_some());
    }

    #[test]
    fn ensure_cdm_for_with_replaces_same_library_changed_manifest() {
        let crx = build_synthetic_crx3("8.8.7");
        let url = spawn_crx_server(crx.clone());
        let manifest = manifest_for_crx(&url, &crx, "8.8.7");
        let tmp = TempDir::new().expect("tempdir");
        // Same library bytes as the synthetic CRX, but a different root manifest.
        let cached = make_cached_version_with(tmp.path(), "8.8.7", b"\x7fELF-fake-cdm-content");
        fs::write(
            cached.join("manifest.json"),
            br#"{"name":"WidevineCdm","version":"8.8.7","extra":"tampered"}"#,
        )
        .expect("rewrite manifest");
        let poisoned = CachedCdm::new("8.8.7".into(), cached.clone());
        let archive = AuthenticatedPayloadDigests {
            library_size: b"\x7fELF-fake-cdm-content".len() as u64,
            library_sha512: download::sha512_hex(b"\x7fELF-fake-cdm-content"),
            manifest_sha512: download::sha512_hex(
                br#"{"name":"WidevineCdm","version":"8.8.7","extra":"tampered"}"#,
            ),
        };
        write_cache_metadata(&poisoned, Platform::LinuxX86_64, &archive).expect("metadata");

        let repaired = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect("changed manifest must force authenticated replacement");

        let body = fs::read_to_string(repaired.cdm_dir().join("manifest.json")).expect("manifest");
        assert_eq!(body, r#"{"name":"WidevineCdm","version":"8.8.7"}"#);
        assert_eq!(
            repaired.verified_manifest_sha512(),
            Some(download::sha512_hex(body.as_bytes()).as_str())
        );
    }

    #[test]
    fn ensure_cdm_for_with_replaces_mismatched_manifest_cache() {
        let crx = build_synthetic_crx3("8.8.8");
        let url = spawn_crx_server(crx.clone());
        let manifest = manifest_for_crx(&url, &crx, "8.8.8");
        let tmp = TempDir::new().expect("tempdir");
        let cached = make_cached_version(tmp.path(), "8.8.8");
        fs::write(cached.join("manifest.json"), r#"{"version":"7.7.7"}"#)
            .expect("write mismatched manifest");
        advance_current(tmp.path(), "8.8.8").expect("advance");

        let repaired = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect("mismatched cache must be replaced");

        validate_cached_cdm(&repaired, Platform::LinuxX86_64).expect("replacement must validate");
        let body = fs::read_to_string(repaired.cdm_dir().join("manifest.json")).expect("manifest");
        assert!(body.contains(r#""version":"8.8.8""#));
    }

    #[test]
    fn ensure_cdm_for_with_replaces_regular_file_target() {
        let crx = build_synthetic_crx3("6.6.6");
        let url = spawn_crx_server(crx.clone());
        let manifest = manifest_for_crx(&url, &crx, "6.6.6");
        let tmp = TempDir::new().expect("tempdir");
        fs::write(tmp.path().join("6.6.6"), b"not a directory").expect("file target");

        let repaired = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect("file target must be replaced");

        assert!(repaired.cdm_dir().is_dir());
        validate_cached_cdm(&repaired, Platform::LinuxX86_64).expect("replacement validates");
    }

    #[test]
    fn ensure_cdm_for_with_rejects_unsafe_version_before_io() {
        let manifest = synthetic_manifest(b"unused", "../escape");
        let tmp = TempDir::new().expect("tempdir");

        let error = ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
            .expect_err("unsafe version");

        assert_eq!(error.category, crate::ErrorCategory::StateCorrupted);
        assert!(!tmp.path().join("escape").exists());
    }

    /// `prune_in` with `keep == 0` is treated as `keep == 1` (never delete the active).
    #[test]
    fn prune_in_with_keep_zero_treats_as_one() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0");
        make_cached_version(tmp.path(), "2.0");
        std::thread::sleep(std::time::Duration::from_millis(20));
        advance_current(tmp.path(), "2.0").expect("advance");
        let _ = prune_in(tmp.path(), 0).expect("prune");
        // Active must remain; older may be removed.
        assert!(tmp.path().join("2.0").exists());
    }

    /// `prune_in` is a no-op when the cache root doesn't exist.
    #[test]
    fn prune_in_with_missing_root_is_noop() {
        let tmp = TempDir::new().expect("tempdir");
        let phantom = tmp.path().join("does-not-exist");
        let deleted = prune_in(&phantom, 3).expect("missing root ok");
        assert_eq!(deleted, 0);
    }

    /// `default_*` accessors work without panic and produce paths that
    /// end in the expected suffix when `dirs::cache_dir()` resolves.
    #[test]
    fn default_accessors_dont_panic() {
        let _ = default_cache_root();
        // `prune` calls default_cache_root then short-circuits on missing.
        let _ = prune(0);
        let _ = current();
    }
}
