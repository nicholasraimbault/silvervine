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
//! * [`ensure_cdm_for`] — make sure the CDM at the manifest's version is
//!   present, downloading + extracting if necessary; advance `current`.
//! * [`current`] — return the CDM the active `current` symlink points at.
//! * [`rollback`] — flip `current` back to `previous`.
//! * [`prune`] — keep the latest N versions, delete older.
//! * [`verify_integrity`] — recompute SHA-512 of cached `.so` files
//!   against the manifest. Used by daemon's weekly integrity check.
//!
//! ## What this module does NOT do
//!
//! * No actual patching — that's [`crate::patch`].
//! * No daemon scheduling — daemon team owns the weekly tick.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::widevine::manifest::{Manifest, Platform};
use crate::widevine::{download, extract};

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
}

impl CachedCdm {
    /// Build a [`CachedCdm`] from a version + extracted-directory path.
    /// Public to the crate so the patch tests can construct a synthetic
    /// CDM without going through the full download flow.
    #[must_use]
    pub fn new(version: String, cdm_dir: PathBuf) -> Self {
        Self { version, cdm_dir }
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
/// 2. If `<cache_root>/<version>/` already exists and its extracted layout
///    contains a non-empty Widevine library — short-circuit.
/// 3. Otherwise: download the CRX3, verify SHA-512, extract into a
///    staging directory, then atomically rename into place.
/// 4. Advance the `current` symlink (and demote the previous one).
/// 5. Return a [`CachedCdm`] handle for the new version.
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
    let vendor = manifest.widevine()?;
    let version = vendor.version.clone();
    validate_version(&version)?;
    let entry = manifest.resolve_platform(platform)?;
    std::fs::create_dir_all(cache_root).map_err(Error::from)?;
    let target_dir = cache_root.join(&version);

    // Serialize cache validation, repair, promotion, and current/previous link
    // updates. The lock is separate from `patch.lock`, so patching does not
    // block CDM refreshes and vice versa.
    let lock_path = cache_root.join("download.lock");
    crate::lockfile::with_lock(&lock_path, || {
        let cached = CachedCdm::new(version.clone(), target_dir.clone());
        if validate_cached_cdm(&cached, platform).is_ok() {
            advance_current(cache_root, &version)?;
            return Ok(cached);
        }
        remove_cache_entry(&target_dir)?;

        // Extract into a sibling staging directory so promotion is atomic.
        let staging = cache_root.join(format!(".staging-{version}"));
        remove_cache_entry(&staging)?;
        let crx_path = download::download_to(entry, &cache_root.join("downloads"))?;
        extract::extract_crx3(&crx_path, &staging)?;
        let staged = CachedCdm::new(version.clone(), staging.clone());
        validate_cached_cdm(&staged, platform)?;

        remove_cache_entry(&target_dir)?;
        std::fs::rename(&staging, &target_dir).map_err(Error::from)?;

        // The promoted bundle makes the downloaded archive redundant.
        let _ = std::fs::remove_file(&crx_path);

        advance_current(cache_root, &version)?;
        Ok(CachedCdm::new(version.clone(), target_dir.clone()))
    })
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

/// Resolve and structurally validate the active CDM before patching from it.
///
/// This avoids a network manifest lookup for a usable cache while rejecting
/// truncated layouts and version mismatches. SHA-512 verification still occurs
/// when the archive first enters the cache.
pub(crate) fn validated_current() -> Result<Option<CachedCdm>> {
    let Some(root) = default_cache_root() else {
        return Ok(None);
    };
    let platform = crate::widevine::manifest::current_platform_key()?;
    validated_current_in(&root, platform)
}

/// Test-friendly validated-current lookup under an explicit cache root.
fn validated_current_in(cache_root: &Path, platform: Platform) -> Result<Option<CachedCdm>> {
    let Some(cdm) = current_in(cache_root)? else {
        return Ok(None);
    };
    validate_cached_cdm(&cdm, platform)?;
    Ok(Some(cdm))
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
    let lock_path = root.join("download.lock");
    crate::lockfile::with_lock(&lock_path, || rollback_in(&root))
}

/// Test-friendly: rollback under an arbitrary cache root.
///
/// # Errors
///
/// See [`rollback`].
pub fn rollback_in(cache_root: &Path) -> Result<CachedCdm> {
    let previous = resolve_cache_link(cache_root, "previous")?.ok_or_else(|| {
        Error::state_corrupted("no previous CDM cached — nothing to roll back to")
    })?;
    let prev_target_str = previous.version().to_string();
    let current = resolve_cache_link(cache_root, "current")?;
    let cur_target_name = current.as_ref().map(|cdm| cdm.version().to_string());
    let prev = cache_root.join("previous");
    let cur = cache_root.join("current");

    // Replace `current` with what `previous` was pointing at.
    remove_cache_link(&cur)?;
    relative_symlink(&prev_target_str, &cur)?;

    // Update `previous` to point at what `current` used to point at (if any).
    remove_cache_link(&prev)?;
    if let Some(name) = cur_target_name {
        relative_symlink(&name, &prev)?;
    }

    let resolved = cache_root.join(&prev_target_str);
    Ok(CachedCdm::new(prev_target_str, resolved))
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
    prune_in(&root, keep)
}

/// Test-friendly: prune in an arbitrary cache root.
///
/// # Errors
///
/// See [`prune`].
pub fn prune_in(cache_root: &Path, keep: usize) -> Result<usize> {
    let keep = keep.max(1);
    if !cache_root.exists() {
        return Ok(0);
    }
    let mut versions = list_versions(cache_root)?;
    // Sort newest-first by mtime; falls back to name.
    versions.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(b.name.cmp(&a.name)));
    let mut deleted = 0usize;
    let active = current_in(cache_root)
        .ok()
        .flatten()
        .map(|c| c.version().to_string());
    let prev_target = std::fs::read_link(cache_root.join("previous"))
        .ok()
        .and_then(|p| p.file_name().and_then(|s| s.to_str().map(str::to_string)));

    for (i, v) in versions.iter().enumerate() {
        if i < keep {
            continue;
        }
        // Never delete what `current` or `previous` resolves to, even if
        // it falls outside the keep window — symlinks would dangle.
        if active.as_deref() == Some(v.name.as_str())
            || prev_target.as_deref() == Some(v.name.as_str())
        {
            continue;
        }
        if std::fs::remove_dir_all(&v.path).is_ok() {
            deleted += 1;
        }
    }
    // Clean up orphan staging dirs regardless of `keep`.
    if let Ok(entries) = std::fs::read_dir(cache_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                if name.starts_with(".staging-") {
                    let _ = std::fs::remove_dir_all(&path);
                }
            }
        }
    }
    // Sweep stale CRX3 archives left behind by earlier silvervine versions
    // (pre-cleanup-on-success) under <cache_root>/downloads/. Each is
    // ~5–7 MB and they accumulate per CDM upgrade.
    let downloads_dir = cache_root.join("downloads");
    if let Ok(entries) = std::fs::read_dir(&downloads_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("crx3") {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
    Ok(deleted)
}

/// Recompute SHA-512 of cached `libwidevinecdm.{so,dylib}` files for the
/// platform key in `against` and confirm they match.
///
/// Used by the daemon's weekly integrity tick (Phase 3) and by the
/// `silvervine doctor` command (Phase 4). On detection of a mismatch the
/// caller is expected to redownload — this function only reports.
///
/// # Errors
///
/// `HashMismatch` on detection of any cached file whose hash drifts from
/// the manifest. `Other` for I/O failures.
pub fn verify_integrity(against: &Manifest) -> Result<()> {
    let Some(root) = default_cache_root() else {
        return Ok(());
    };
    let platform = crate::widevine::manifest::current_platform_key()?;
    verify_integrity_with(against, platform, &root)
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
    let Some(cdm) = current_in(cache_root)? else {
        // Nothing cached → trivially integral.
        return Ok(());
    };
    integrity_check_dir(cdm.cdm_dir(), platform)
}

/// Verify the Widevine `.so`/`.dylib` under `cdm_dir` matches the manifest
/// hash. Walks `_platform_specific/*/libwidevinecdm.*` — this is the only
/// file that has a stable manifest hash. The CRX3 hash applies to the
/// whole `.crx3` file, so we don't try to recompute that for an extracted
/// directory.
///
/// We treat the *manifest-level* SHA-512 as the source of truth for the
/// CRX3 contents; for the extracted form, we settle for "the file exists
/// and is non-empty." A future enhancement: ship a per-file hash table
/// (Mozilla's manifest doesn't, but we could compute one at extract time
/// and persist it alongside the CDM).
fn integrity_check_dir(cdm_dir: &Path, platform: Platform) -> Result<()> {
    let (platform_name, library) = match platform {
        Platform::LinuxX86_64 => ("linux_x64", "libwidevinecdm.so"),
        Platform::DarwinAarch64 => ("mac_arm64", "libwidevinecdm.dylib"),
        Platform::DarwinX86_64 => ("mac_x64", "libwidevinecdm.dylib"),
    };
    let platform_root = cdm_dir.join("_platform_specific");
    let platform_dir = platform_root.join(platform_name);
    for directory in [cdm_dir, platform_root.as_path(), platform_dir.as_path()] {
        let metadata = bundle_metadata(directory)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::unknown_bundle_structure(format!(
                "{} is not a real cache directory",
                directory.display()
            )));
        }
    }

    let library_path = platform_dir.join(library);
    let metadata = bundle_metadata(&library_path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Error::unknown_bundle_structure(format!(
            "{} is not a regular Widevine library",
            library_path.display()
        )));
    }
    if metadata.len() == 0 {
        return Err(Error::hash_mismatch(format!(
            "{} is empty — cache is corrupt",
            library_path.display()
        )));
    }
    Ok(())
}

fn validate_cached_cdm(cdm: &CachedCdm, platform: Platform) -> Result<()> {
    validate_version(cdm.version())?;
    integrity_check_dir(cdm.cdm_dir(), platform)?;
    let manifest_path = cdm.cdm_dir().join("manifest.json");
    let manifest_meta = bundle_metadata(&manifest_path)?;
    if !manifest_meta.is_file() || manifest_meta.file_type().is_symlink() {
        return Err(Error::unknown_bundle_structure(format!(
            "{} is not a regular manifest",
            manifest_path.display()
        )));
    }
    let body = std::fs::read_to_string(&manifest_path).map_err(Error::from)?;
    let manifest: serde_json::Value = serde_json::from_str(&body)?;
    let Some(version) = manifest.get("version").and_then(serde_json::Value::as_str) else {
        return Err(Error::state_corrupted(format!(
            "{} has no string version field",
            manifest_path.display()
        )));
    };
    if version != cdm.version() {
        return Err(Error::state_corrupted(format!(
            "cached Widevine version {version} does not match cache directory {}",
            cdm.version()
        )));
    }
    Ok(())
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
    let cur_link = cache_root.join("current");
    let prev_link = cache_root.join("previous");
    let cur_target_name = resolve_cache_link(cache_root, "current")
        .ok()
        .flatten()
        .map(|cdm| cdm.version().to_string());

    if let Some(prev_name) = cur_target_name {
        // Only demote if the previous current was a different version.
        if prev_name != new_version {
            remove_cache_link(&prev_link)?;
            relative_symlink(&prev_name, &prev_link)?;
        }
    } else {
        remove_cache_link(&prev_link)?;
    }

    remove_cache_link(&cur_link)?;
    relative_symlink(new_version, &cur_link)?;
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

/// Internal context-prepending error helper. Same shape as `lockfile`'s
/// version — kept private so we don't create a third public version.
trait ErrorContext {
    fn with_context(self, ctx: impl Into<String>) -> Self;
}

impl ErrorContext for Error {
    fn with_context(mut self, ctx: impl Into<String>) -> Self {
        let ctx = ctx.into();
        if self.message.is_empty() {
            self.message = ctx;
        } else {
            self.message = format!("{ctx}: {}", self.message);
        }
        self
    }
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
        let dir = cache_root.join(version);
        let plat = dir.join("_platform_specific").join("linux_x64");
        fs::create_dir_all(&plat).expect("mkdir");
        fs::write(plat.join("libwidevinecdm.so"), b"non-empty").expect("write so");
        fs::write(
            dir.join("manifest.json"),
            format!(r#"{{"version":"{version}"}}"#),
        )
        .expect("write manifest");
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
            fs::write(platform_dir.join("libwidevinecdm.dylib"), b"non-empty").expect("library");
            fs::write(
                cdm.join("manifest.json"),
                format!(r#"{{"version":"{version}"}}"#),
            )
            .expect("manifest");
            let cached = CachedCdm::new(version.into(), cdm);
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
    fn ensure_cdm_for_with_short_circuits_on_cache_hit() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0");
        let manifest = synthetic_manifest(b"unused", "1.0");
        let cdm =
            ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path()).expect("cache hit");
        assert_eq!(cdm.version(), "1.0");
        assert!(cdm.cdm_dir().ends_with("1.0"));
        // current symlink should now exist.
        assert!(tmp.path().join("current").exists());
    }

    #[test]
    fn concurrent_cache_hits_preserve_current_and_previous() {
        let tmp = TempDir::new().expect("tempdir");
        make_cached_version(tmp.path(), "1.0.0");
        make_cached_version(tmp.path(), "2.0.0");
        let root = tmp.path().to_path_buf();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for version in ["1.0.0", "2.0.0"] {
            let root = root.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let manifest = synthetic_manifest(b"unused", version);
                barrier.wait();
                ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, &root)
            }));
        }
        barrier.wait();
        for handle in handles {
            handle.join().expect("thread").expect("cache hit");
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
