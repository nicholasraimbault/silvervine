//! CRX3 → directory extraction.
//!
//! ## CRX3 file format
//!
//! CRX3 is Chrome's signed extension format. Layout:
//!
//! ```text
//! ┌──────────────────┬───────────┬────────────────┬──────────────────┐
//! │  magic "Cr24"    │ version   │ header_length  │      header      │
//! │   (4 bytes)      │ uint32 LE │   uint32 LE    │   (variable)     │
//! └──────────────────┴───────────┴────────────────┴──────────────────┘
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                              ZIP                                 │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! For Widevine we only care about the **ZIP body** — the header carries
//! Chrome Web Store signatures that we do not verify (we trust the
//! Mozilla manifest's SHA-512 instead).
//!
//! ## Output structure (per spec)
//!
//! ```text
//! <out>/
//! ├── manifest.json
//! └── _platform_specific/
//!     └── <platform>/
//!         ├── libwidevinecdm.{so,dylib}
//!         └── manifest.json
//! ```
//!
//! ## What this module does NOT do
//!
//! * No CRX3 signature verification — by design; the manifest's SHA-512
//!   is our root of trust.
//! * No staging/cache management — that's [`crate::widevine::cache`].

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Magic bytes at the start of every CRX3 file (`"Cr24"`).
pub const CRX3_MAGIC: &[u8; 4] = b"Cr24";

/// CRX3 file version (after the magic). Always 3 in practice; if a
/// future v4 ever ships we'll update.
pub const CRX3_VERSION: u32 = 3;

/// Extract the ZIP body of a CRX3 file at `crx_path` into `out_dir`.
///
/// `out_dir` is created (recursively) if it doesn't exist, and is left
/// empty on entry — callers that want a clean target should remove it
/// first.
///
/// # Errors
///
/// * [`crate::ErrorCategory::UnknownBundleStructure`] if the magic is
///   wrong, the version isn't 3, or the header length is implausible.
/// * [`crate::ErrorCategory::Other`] / `PermissionDenied` for I/O failures.
pub fn extract_crx3(crx_path: &Path, out_dir: &Path) -> Result<()> {
    let bytes = std::fs::read(crx_path).map_err(Error::from)?;
    extract_crx3_bytes(&bytes, out_dir)
}

/// In-memory CRX3 extraction.
///
/// Useful for tests that synthesize a CRX3 byte vector without writing it
/// to disk first.
///
/// # Errors
///
/// See [`extract_crx3`].
pub fn extract_crx3_bytes(bytes: &[u8], out_dir: &Path) -> Result<()> {
    let zip_offset = parse_crx3_header(bytes)?;
    let zip_body = &bytes[zip_offset..];
    extract_zip_body(zip_body, out_dir)
}

/// Parse the CRX3 header and return the byte offset where the ZIP body
/// begins.
///
/// Header layout:
///
/// * bytes  0..4   = magic `"Cr24"`
/// * bytes  4..8   = uint32 LE version (must be 3)
/// * bytes  8..12  = uint32 LE header length (the bytes following these 12)
/// * bytes `12..12+header_length` = signed-header bytes (we skip them)
/// * bytes `12+header_length` .. = ZIP body
///
/// # Errors
///
/// [`crate::ErrorCategory::UnknownBundleStructure`] for any structural
/// problem.
pub fn parse_crx3_header(bytes: &[u8]) -> Result<usize> {
    if bytes.len() < 12 {
        return Err(Error::unknown_bundle_structure(
            "CRX3 file is shorter than 12-byte fixed header",
        ));
    }
    if &bytes[..4] != CRX3_MAGIC {
        return Err(Error::unknown_bundle_structure(format!(
            "CRX3 magic mismatch: expected {:?}, got {:?}",
            CRX3_MAGIC,
            &bytes[..4]
        )));
    }
    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != CRX3_VERSION {
        return Err(Error::unknown_bundle_structure(format!(
            "CRX version {version} unsupported (only v3)"
        )));
    }
    let header_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
    // Sanity: a header longer than the file itself is malformed; a
    // header zero is also weird (signed CRX3 should have at least the
    // proto header). We allow header_len == 0 in tests for synthesized
    // CRX3 fixtures that don't include a signed header — those still
    // need to round-trip.
    let zip_offset = 12usize.checked_add(header_len).ok_or_else(|| {
        Error::unknown_bundle_structure("CRX3 header length overflows pointer arithmetic")
    })?;
    if zip_offset > bytes.len() {
        return Err(Error::unknown_bundle_structure(format!(
            "CRX3 header_length {header_len} extends past end of {}-byte file",
            bytes.len()
        )));
    }
    Ok(zip_offset)
}

/// Extract a ZIP body to `out_dir`.
///
/// We use the `zip` crate. Symlinks inside the ZIP are unsupported
/// (the Widevine CRX3 does not contain any in practice).
fn extract_zip_body(zip: &[u8], out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir).map_err(Error::from)?;
    let cursor = std::io::Cursor::new(zip);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| {
        Error::unknown_bundle_structure("CRX3 ZIP body is malformed").with_source(e)
    })?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            Error::unknown_bundle_structure(format!("zip entry {i}")).with_source(e)
        })?;
        // Reject path-traversal entries. `enclosed_name` is `None` if the
        // entry's name escapes its base directory or contains absolute
        // path components — we treat that as malformed.
        let Some(rel) = entry.enclosed_name() else {
            return Err(Error::unknown_bundle_structure(format!(
                "zip entry {} has unsafe path",
                entry.name()
            )));
        };
        let dest = out_dir.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest).map_err(Error::from)?;
            continue;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(Error::from)?;
        }
        let mut out = std::fs::File::create(&dest).map_err(Error::from)?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = entry.read(&mut buf).map_err(Error::from)?;
            if n == 0 {
                break;
            }
            std::io::Write::write_all(&mut out, &buf[..n]).map_err(Error::from)?;
        }
        // Preserve the executable bit on Unix — the CDM `.so`/`.dylib`
        // is mode 0755 in the CRX3.
        #[cfg(unix)]
        {
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

/// Verify that an extracted directory has the expected Widevine layout.
///
/// Returns the path to the platform-specific subdir (`_platform_specific/<x>/`).
///
/// # Errors
///
/// [`crate::ErrorCategory::UnknownBundleStructure`] if the layout doesn't match.
pub fn verify_widevine_layout(extracted: &Path) -> Result<PathBuf> {
    let manifest = extracted.join("manifest.json");
    if !manifest.exists() {
        return Err(Error::unknown_bundle_structure(format!(
            "extracted CRX3 is missing manifest.json at {}",
            manifest.display()
        )));
    }
    let plat = extracted.join("_platform_specific");
    if !plat.is_dir() {
        return Err(Error::unknown_bundle_structure(format!(
            "extracted CRX3 is missing _platform_specific/ at {}",
            plat.display()
        )));
    }
    // Inside _platform_specific there's exactly one subdir (e.g.
    // linux_x64, mac_arm64). Find the first one and return its path.
    let entries = std::fs::read_dir(&plat).map_err(Error::from)?;
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            // Sanity: must contain a Widevine CDM shared library.
            if has_widevine_so(&p) {
                return Ok(p);
            }
        }
    }
    Err(Error::unknown_bundle_structure(format!(
        "no platform-specific Widevine CDM under {}",
        plat.display()
    )))
}

/// Returns `true` if `dir` contains a `libwidevinecdm.{so,dylib}`.
fn has_widevine_so(dir: &Path) -> bool {
    dir.join("libwidevinecdm.so").exists() || dir.join("libwidevinecdm.dylib").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Build a tiny CRX3 byte vector wrapping a synthesized ZIP with a
    /// `manifest.json` and a `_platform_specific/linux_x64/libwidevinecdm.so`.
    fn build_synthetic_crx3() -> Vec<u8> {
        let mut zip_bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_bytes);
            let mut zip = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("manifest.json", opts)
                .expect("start manifest");
            zip.write_all(br#"{"name":"WidevineCdm","version":"4.10.test"}"#)
                .expect("write manifest");
            zip.start_file("_platform_specific/linux_x64/libwidevinecdm.so", opts)
                .expect("start so");
            zip.write_all(b"\x7fELFsynthetic-widevine-cdm-content")
                .expect("write so");
            zip.start_file("_platform_specific/linux_x64/manifest.json", opts)
                .expect("start inner manifest");
            zip.write_all(br#"{"name":"WidevineCdm","version":"4.10.test","platforms":{}}"#)
                .expect("write inner manifest");
            zip.finish().expect("finish zip");
        }

        let mut crx = Vec::new();
        crx.extend_from_slice(CRX3_MAGIC);
        crx.extend_from_slice(&3u32.to_le_bytes());
        // Empty signed-header — synthesized fixtures don't include one.
        crx.extend_from_slice(&0u32.to_le_bytes());
        crx.extend_from_slice(&zip_bytes);
        crx
    }

    #[test]
    fn parse_crx3_header_returns_zip_offset() {
        let crx = build_synthetic_crx3();
        let off = parse_crx3_header(&crx).expect("ok");
        // Synthetic header: 4 magic + 4 version + 4 header_len + 0 header bytes = 12.
        assert_eq!(off, 12);
    }

    #[test]
    fn parse_crx3_header_rejects_too_short_input() {
        let err = parse_crx3_header(&[1, 2, 3]).expect_err("too short");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn parse_crx3_header_rejects_wrong_magic() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"Wrng");
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let err = parse_crx3_header(&bytes).expect_err("bad magic");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn parse_crx3_header_rejects_wrong_version() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CRX3_MAGIC);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let err = parse_crx3_header(&bytes).expect_err("v2 unsupported");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn parse_crx3_header_rejects_overlong_header_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CRX3_MAGIC);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&999u32.to_le_bytes());
        // Only one extra byte after the 12-byte fixed header — claim 999.
        bytes.push(0);
        let err = parse_crx3_header(&bytes).expect_err("oversized");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn extract_crx3_bytes_writes_expected_layout() {
        let crx = build_synthetic_crx3();
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        extract_crx3_bytes(&crx, &out).expect("extraction must succeed");
        assert!(out.join("manifest.json").exists());
        let so = out
            .join("_platform_specific")
            .join("linux_x64")
            .join("libwidevinecdm.so");
        assert!(so.exists());
        // Verify our layout-checker is happy.
        let plat = verify_widevine_layout(&out).expect("layout ok");
        assert!(plat.ends_with("linux_x64"));
    }

    #[test]
    fn extract_crx3_writes_to_disk() {
        let crx = build_synthetic_crx3();
        let tmp = TempDir::new().expect("tempdir");
        let crx_path = tmp.path().join("widevine.crx3");
        std::fs::write(&crx_path, &crx).expect("write");
        let out = tmp.path().join("extracted");
        extract_crx3(&crx_path, &out).expect("extraction must succeed");
        assert!(out.join("manifest.json").exists());
    }

    #[test]
    fn verify_widevine_layout_errors_when_manifest_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let err = verify_widevine_layout(tmp.path()).expect_err("missing manifest");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn verify_widevine_layout_errors_when_no_platform_dir() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("manifest.json"), b"{}").expect("write");
        let err = verify_widevine_layout(tmp.path()).expect_err("no _platform_specific");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn verify_widevine_layout_errors_when_no_so_in_platform_dir() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::write(tmp.path().join("manifest.json"), b"{}").expect("write");
        let plat = tmp.path().join("_platform_specific").join("linux_x64");
        std::fs::create_dir_all(&plat).expect("mkdir");
        let err = verify_widevine_layout(tmp.path()).expect_err("no .so");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn extract_crx3_rejects_path_traversal_entries() {
        // Synthesize a malformed ZIP whose entry name contains `..`.
        let mut zip_bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_bytes);
            let mut zip = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.start_file("../escape.txt", opts).expect("start");
            zip.write_all(b"x").expect("write");
            zip.finish().expect("finish");
        }
        let mut crx = Vec::new();
        crx.extend_from_slice(CRX3_MAGIC);
        crx.extend_from_slice(&3u32.to_le_bytes());
        crx.extend_from_slice(&0u32.to_le_bytes());
        crx.extend_from_slice(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("traversal must be rejected");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    /// `extract_crx3_bytes` errors when the ZIP body is garbage (not a
    /// valid PKZIP archive).
    #[test]
    fn extract_crx3_rejects_malformed_zip_body() {
        let mut crx = Vec::new();
        crx.extend_from_slice(CRX3_MAGIC);
        crx.extend_from_slice(&3u32.to_le_bytes());
        crx.extend_from_slice(&0u32.to_le_bytes());
        // Garbage instead of a valid ZIP body.
        crx.extend_from_slice(b"this is not a zip file");
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("malformed zip");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    /// CRX3 with explicit directory entries gets the directory created.
    #[test]
    fn extract_crx3_creates_explicit_directory_entries() {
        let mut zip_bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_bytes);
            let mut zip = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.add_directory("just-a-dir/", opts).expect("dir");
            zip.start_file("just-a-dir/inside.txt", opts)
                .expect("start");
            zip.write_all(b"hi").expect("write");
            zip.finish().expect("finish");
        }
        let mut crx = Vec::new();
        crx.extend_from_slice(CRX3_MAGIC);
        crx.extend_from_slice(&3u32.to_le_bytes());
        crx.extend_from_slice(&0u32.to_le_bytes());
        crx.extend_from_slice(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        extract_crx3_bytes(&crx, &out).expect("ok");
        assert!(out.join("just-a-dir").is_dir());
        assert!(out.join("just-a-dir").join("inside.txt").exists());
    }
}
