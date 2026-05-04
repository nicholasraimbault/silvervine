//! `CdmProvider` trait and the V2 [`LocalFileCdm`] implementation.
//!
//! This module is the **V3 scaffolding seam** that decouples the patch
//! flow from "the CDM is a directory on disk under
//! `~/.cache/neon/widevine/<v>/`." V2 has exactly one implementation
//! ([`LocalFileCdm`]) which is a thin wrapper around the existing
//! [`crate::widevine::cache::CachedCdm`] type. V3's `experimental-bridge`
//! feature will introduce a `BridgeCdm` impl that fetches CDM bytes from
//! a Windows guest VM over a Unix socket / vsock, enabling
//! hardware-attested L1 playback paths.
//!
//! See:
//!
//! * `docs/superpowers/specs/2026-05-04-neon-v3-localhost-bridge-scaffolding-plan.md`
//! * `docs/superpowers/plans/2026-05-04-neon-v3-orchestration-plan.md`
//!
//! ## Object safety
//!
//! [`CdmProvider`] is deliberately object-safe so callers
//! (`patch::patch_browser`, etc.) can take `&dyn CdmProvider` and accept
//! any backend without monomorphizing on the concrete type. The
//! `provider_is_object_safe` test in this file verifies that property at
//! compile time.
//!
//! ## What this module does NOT do
//!
//! * No new I/O of its own — [`LocalFileCdm`] re-uses the directory layout
//!   produced by [`crate::widevine::cache`].
//! * No bridge / VM code — that lives behind the `experimental-bridge`
//!   feature flag in [`crate::bridge`] (V3).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::widevine::cache::CachedCdm;

/// Source of Widevine CDM bytes for the patch flow.
///
/// V2 only ever uses [`LocalFileCdm`] (reads from the cache directory at
/// `~/.cache/neon/widevine/<v>/`). V3's `experimental-bridge` feature
/// will introduce a `BridgeCdm` impl that fetches CDM bytes from a
/// running Windows guest VM.
///
/// Implementations must be `Send + Sync` so the patch flow can hold a
/// `&dyn CdmProvider` across thread boundaries (the daemon's tray
/// callback and the IPC handler both invoke patches from background
/// threads).
///
/// ## Implementation contract
///
/// 1. [`version`](Self::version) returns the CDM version string. For
///    V2's `LocalFileCdm` this matches the `version` field in Mozilla's
///    manifest. V3's `BridgeCdm` would query the guest VM for the
///    installed Edge's bundled CDM version.
///
/// 2. [`populate`](Self::populate) writes the CDM payload into `dest`,
///    which the caller has already created as an empty directory. The
///    expected output layout is:
///
///    ```text
///    <dest>/
///    ├── manifest.json
///    └── _platform_specific/
///        └── <platform>/
///            └── libwidevinecdm.{so,dylib,dll}
///    ```
///
/// 3. [`sha512_hex`](Self::sha512_hex) returns the SHA-512 hash of the
///    primary CDM binary for integrity checks. Returns `None` for
///    providers that don't expose a stable hash (e.g. a remote bridge
///    that re-bundles per-call).
pub trait CdmProvider: Send + Sync {
    /// CDM version string (e.g. `"4.10.2934.0"`).
    ///
    /// For [`LocalFileCdm`] this is whatever was stored in the cache
    /// directory's name. The patch outcome's `cdm_version` field is
    /// copied from this method.
    fn version(&self) -> &str;

    /// Copy the CDM payload into `dest`.
    ///
    /// `dest` must be an empty directory the caller has already created.
    /// Implementations write `manifest.json`, `LICENSE`, and the
    /// platform-specific `_platform_specific/<arch>/libwidevinecdm.{so,dylib,dll}`.
    ///
    /// # Errors
    ///
    /// Surface any I/O or transport failure as a categorized [`Error`].
    /// V2's [`LocalFileCdm`] returns [`crate::ErrorCategory::Other`] for
    /// generic disk failures.
    fn populate(&self, dest: &Path) -> Result<()>;

    /// SHA-512 hash (lowercase hex) of the primary CDM binary, when
    /// known.
    ///
    /// Returns `None` when the provider can't expose a stable hash
    /// (e.g. a remote bridge that re-bundles per-call). V2's
    /// [`LocalFileCdm`] currently always returns `None` because the
    /// extracted CDM directory doesn't ship a per-file hash table; the
    /// download pipeline already verified the CRX3 SHA-512 at extract
    /// time. A future enhancement could persist a per-file hash.
    fn sha512_hex(&self) -> Option<&str>;
}

/// V2 [`CdmProvider`] backed by the on-disk CDM cache.
///
/// Wraps an existing [`CachedCdm`] handle (built by
/// [`crate::widevine::cache`]). [`populate`](CdmProvider::populate)
/// recursively copies the cache directory's contents into the caller's
/// destination directory.
///
/// V3's `BridgeCdm` impl in `src/bridge/cdm.rs` (when implemented) will
/// instead fetch CDM bytes from a guest VM over the bridge socket; until
/// then [`LocalFileCdm`] is the only implementation.
#[derive(Debug, Clone)]
pub struct LocalFileCdm {
    version: String,
    /// Root directory of the extracted CDM. Must contain `manifest.json`
    /// and `_platform_specific/<platform>/libwidevinecdm.{so,dylib}`.
    source: PathBuf,
}

impl LocalFileCdm {
    /// Build a [`LocalFileCdm`] from explicit version and source-directory
    /// parameters.
    ///
    /// Most callers should prefer [`LocalFileCdm::from_cached`] (which
    /// derives both fields from an existing [`CachedCdm`]) or
    /// [`crate::widevine::cache::current_provider`] (the default-cache
    /// version of that).
    #[must_use]
    pub fn new(version: String, source: PathBuf) -> Self {
        Self { version, source }
    }

    /// Build a [`LocalFileCdm`] from an existing [`CachedCdm`].
    ///
    /// This is the primary V2 construction path: the CLI / daemon resolve
    /// a [`CachedCdm`] via [`crate::widevine::cache::ensure_cdm_for`] (or
    /// [`crate::widevine::cache::current`]), then wrap it in a
    /// [`LocalFileCdm`] before passing it to [`crate::patch::patch_browser`].
    ///
    /// The `&CachedCdm` reference is consumed by-value-of-clone — this
    /// keeps callers from accidentally building a long-lived provider
    /// that races against a cache flip.
    #[must_use]
    pub fn from_cached(cached: &CachedCdm) -> Self {
        Self {
            version: cached.version().to_string(),
            source: cached.cdm_dir().to_path_buf(),
        }
    }

    /// Source directory that [`populate`](CdmProvider::populate) will
    /// copy from. Exposed for tests and diagnostics.
    #[must_use]
    pub fn source_dir(&self) -> &Path {
        &self.source
    }
}

impl CdmProvider for LocalFileCdm {
    fn version(&self) -> &str {
        &self.version
    }

    fn populate(&self, dest: &Path) -> Result<()> {
        copy_dir_recursive(&self.source, dest)
    }

    fn sha512_hex(&self) -> Option<&str> {
        // V2 doesn't persist a per-file hash table; the download pipeline
        // already verified the CRX3 SHA-512 at extract time and integrity
        // check happens via `widevine::cache::verify_integrity`. A future
        // enhancement could persist a per-file hash and return it here.
        None
    }
}

/// Recursively copy `src` directory into `dest`. `dest` must already
/// exist; intermediate directories are created as needed. Unix mode bits
/// are preserved (so the CDM `.so` keeps its 0755).
fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<()> {
    if !src.is_dir() {
        return Err(Error::other(format!(
            "CDM source {} is not a directory",
            src.display()
        )));
    }
    std::fs::create_dir_all(dest).map_err(Error::from)?;
    for entry in std::fs::read_dir(src).map_err(Error::from)? {
        let entry = entry.map_err(Error::from)?;
        let from = entry.path();
        let Some(name) = from.file_name() else {
            continue;
        };
        let to = dest.join(name);
        let file_type = entry.file_type().map_err(Error::from)?;
        if file_type.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if file_type.is_file() {
            std::fs::copy(&from, &to).map_err(Error::from)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&from) {
                    let mode = meta.permissions().mode();
                    let _ = std::fs::set_permissions(&to, std::fs::Permissions::from_mode(mode));
                }
            }
        }
        // Symlinks are not expected in the CDM cache layout; skip silently.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// `LocalFileCdm` is `Box<dyn CdmProvider>`-safe (compile-time check).
    /// If [`CdmProvider`] grows a non-object-safe method (generic, `Self`,
    /// etc.), this test fails to compile.
    #[test]
    fn provider_is_object_safe() {
        let tmp = TempDir::new().expect("tempdir");
        let p: Box<dyn CdmProvider> =
            Box::new(LocalFileCdm::new("9.9.9".into(), tmp.path().to_path_buf()));
        assert_eq!(p.version(), "9.9.9");
    }

    /// Wrapping an existing [`CachedCdm`] preserves both `version` and
    /// `source` fields.
    #[test]
    fn from_cached_preserves_fields() {
        let tmp = TempDir::new().expect("tempdir");
        let cached = CachedCdm::new("4.10.2934.0".to_string(), tmp.path().join("4.10.2934.0"));
        let provider = LocalFileCdm::from_cached(&cached);
        assert_eq!(provider.version(), "4.10.2934.0");
        assert_eq!(provider.source_dir(), cached.cdm_dir());
    }

    /// Synthesize a fake CDM cache directory and verify
    /// [`LocalFileCdm::populate`] round-trips its contents (manifest.json
    /// + the platform-specific `.so`) into a fresh dest directory.
    #[test]
    fn populate_round_trips_synthesized_cache() {
        let tmp = TempDir::new().expect("tempdir");
        let src = tmp.path().join("source");
        let plat = src.join("_platform_specific").join("linux_x64");
        fs::create_dir_all(&plat).expect("mkdir source");
        fs::write(src.join("manifest.json"), br#"{"version":"4.10.0"}"#).expect("write manifest");
        fs::write(plat.join("libwidevinecdm.so"), b"\x7fELF-fake-cdm").expect("write so");

        let dest = tmp.path().join("dest");
        let provider = LocalFileCdm::new("4.10.0".into(), src.clone());
        provider.populate(&dest).expect("populate ok");

        // manifest.json round-tripped.
        assert_eq!(
            fs::read(dest.join("manifest.json")).expect("read manifest"),
            br#"{"version":"4.10.0"}"#
        );
        // The .so round-tripped under the same nested layout.
        let dest_so = dest
            .join("_platform_specific")
            .join("linux_x64")
            .join("libwidevinecdm.so");
        assert!(dest_so.exists());
        assert_eq!(fs::read(&dest_so).expect("read so"), b"\x7fELF-fake-cdm");
    }

    /// `populate` errors when the source directory doesn't exist.
    #[test]
    fn populate_errors_when_source_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let provider = LocalFileCdm::new("9.9.9".into(), tmp.path().join("does-not-exist"));
        let err = provider
            .populate(&tmp.path().join("dest"))
            .expect_err("source missing");
        assert_eq!(err.category, crate::ErrorCategory::Other);
    }

    /// `version()` returns the value passed in at construction.
    #[test]
    fn version_returns_construction_string() {
        let tmp = TempDir::new().expect("tempdir");
        let provider = LocalFileCdm::new("1.2.3".into(), tmp.path().to_path_buf());
        assert_eq!(provider.version(), "1.2.3");
    }

    /// `sha512_hex()` returns `None` for V2's [`LocalFileCdm`] (we don't
    /// persist a per-file hash table yet).
    #[test]
    fn sha512_hex_returns_none_for_local_file_cdm() {
        let tmp = TempDir::new().expect("tempdir");
        let provider = LocalFileCdm::new("1.0".into(), tmp.path().to_path_buf());
        assert!(provider.sha512_hex().is_none());
    }

    /// Recursive copy preserves nested directory layout.
    #[test]
    fn populate_preserves_nested_directories() {
        let tmp = TempDir::new().expect("tempdir");
        let src = tmp.path().join("src");
        let nested = src.join("a").join("b").join("c");
        fs::create_dir_all(&nested).expect("mkdir nested");
        fs::write(nested.join("leaf.txt"), b"leaf").expect("write");
        let dest = tmp.path().join("dest");
        let provider = LocalFileCdm::new("v".into(), src);
        provider.populate(&dest).expect("populate");
        assert!(dest.join("a").join("b").join("c").join("leaf.txt").exists());
        assert_eq!(
            fs::read(dest.join("a").join("b").join("c").join("leaf.txt")).expect("read"),
            b"leaf"
        );
    }

    /// Source-dir accessor returns the path passed at construction.
    #[test]
    fn source_dir_returns_construction_path() {
        let tmp = TempDir::new().expect("tempdir");
        let provider = LocalFileCdm::new("v".into(), tmp.path().to_path_buf());
        assert_eq!(provider.source_dir(), tmp.path());
    }
}
