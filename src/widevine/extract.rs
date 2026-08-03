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
//! This module only parses the envelope and unpacks the bounded ZIP body.
//! The production cache path first verifies the manifest digest and the pinned
//! Widevine component signature in [`crate::widevine::crx3`].
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
//! * No CRX3 signature verification in the public unpack helpers — callers
//!   must authenticate input or treat every extracted file as untrusted.
//! * No staging/cache management — that's [`crate::widevine::cache`].

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::widevine::download::MAX_CRX_BYTES;
use crate::widevine::{
    platform_library, Platform, CDM_MANIFEST_FILENAME, PLATFORM_SPECIFIC_DIRECTORY,
};

/// Magic bytes at the start of every CRX3 file (`"Cr24"`).
pub const CRX3_MAGIC: &[u8; 4] = b"Cr24";

/// CRX3 file version (after the magic). Always 3 in practice; if a
/// future v4 ever ships we'll update.
pub const CRX3_VERSION: u32 = 3;

/// Maximum ZIP central-directory entries accepted from a CRX3 body.
///
/// Widevine bundles contain a handful of files; anything near this ceiling is
/// either malicious or not a CDM package.
const MAX_ZIP_ENTRIES: usize = 256;

/// Maximum uncompressed size accepted for any single regular ZIP entry.
///
/// Kept at the authenticated CRX download ceiling so one entry cannot expand
/// past the largest package we are willing to hold in memory.
const MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES: u64 = MAX_CRX_BYTES;

/// Maximum aggregate uncompressed bytes written while extracting one CRX3.
///
/// Slightly above [`MAX_CRX_BYTES`] to allow modest compression savings across
/// multiple small files without permitting zip-bomb expansion.
const MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES: u64 = MAX_CRX_BYTES.saturating_mul(2);

/// Reused streaming copy buffer for every regular ZIP entry.
const ZIP_COPY_BUFFER_BYTES: usize = 64 * 1024;

/// Unix `S_IFMT` file-type mask.
const UNIX_S_IFMT: u32 = 0o170_000;
/// Regular file type bit in a Unix mode.
const UNIX_S_IFREG: u32 = 0o100_000;
/// Directory type bit in a Unix mode.
const UNIX_S_IFDIR: u32 = 0o040_000;
/// Permission bits preserved when applying Unix modes from ZIP metadata.
const UNIX_PERMISSION_BITS: u32 = 0o777;

/// Extract the ZIP body of a CRX3 file at `crx_path` into `out_dir`.
///
/// `out_dir` is created (recursively) if it doesn't exist, and is left
/// empty on entry — callers that want a clean target should remove it
/// first.
///
/// # Security
///
/// This is an unauthenticated unpack helper. Use
/// [`crate::widevine::cache::ensure_cdm_for`] before executable CDM use.
///
/// # Errors
///
/// * [`crate::ErrorCategory::UnknownBundleStructure`] if the magic is
///   wrong, the version isn't 3, the header length is implausible, or the
///   ZIP body exceeds entry/size bounds or contains unsupported entries.
/// * [`crate::ErrorCategory::Other`] / `PermissionDenied` for I/O failures.
pub fn extract_crx3(crx_path: &Path, out_dir: &Path) -> Result<()> {
    let bytes = std::fs::read(crx_path).map_err(Error::from)?;
    extract_crx3_bytes(&bytes, out_dir)
}

/// In-memory CRX3 extraction.
///
/// Useful for callers that already authenticated an in-memory CRX and for
/// tests that synthesize one. This function does not verify CRX signatures.
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

/// Reject archives whose central-directory entry count can make `zip` allocate
/// beyond Silvervine's package budget before [`zip::ZipArchive::new`] returns.
///
/// Widevine packages do not need multi-disk or ZIP64 entry counts. Requiring a
/// conventional EOCD also lets us validate the count without constructing the
/// third-party parser's eager central-directory index.
pub(super) fn validate_zip_entry_count(zip: &[u8]) -> Result<()> {
    const EOCD_SIGNATURE: [u8; 4] = 0x0605_4b50u32.to_le_bytes();
    const EOCD_FIXED_BYTES: usize = 22;
    const EOCD_MAX_COMMENT_BYTES: usize = 65_535;

    let last_offset = zip.len().checked_sub(EOCD_FIXED_BYTES).ok_or_else(|| {
        Error::unknown_bundle_structure("CRX3 ZIP is too short to contain an entry directory")
    })?;
    let first_offset = zip
        .len()
        .saturating_sub(EOCD_FIXED_BYTES + EOCD_MAX_COMMENT_BYTES);

    for offset in (first_offset..=last_offset).rev() {
        if zip[offset..offset + 4] != EOCD_SIGNATURE {
            continue;
        }
        let comment_len = usize::from(u16::from_le_bytes([zip[offset + 20], zip[offset + 21]]));
        if offset
            .checked_add(EOCD_FIXED_BYTES)
            .and_then(|end| end.checked_add(comment_len))
            != Some(zip.len())
        {
            continue;
        }

        let disk = u16::from_le_bytes([zip[offset + 4], zip[offset + 5]]);
        let central_disk = u16::from_le_bytes([zip[offset + 6], zip[offset + 7]]);
        let disk_entries = u16::from_le_bytes([zip[offset + 8], zip[offset + 9]]);
        let total_entries = u16::from_le_bytes([zip[offset + 10], zip[offset + 11]]);
        if disk != 0 || central_disk != 0 || disk_entries != total_entries {
            return Err(Error::unknown_bundle_structure(
                "CRX3 ZIP uses an unsupported multi-disk entry directory",
            ));
        }
        if usize::from(total_entries) > MAX_ZIP_ENTRIES {
            return Err(Error::unknown_bundle_structure(format!(
                "CRX3 ZIP declares {total_entries} entries, exceeding the {MAX_ZIP_ENTRIES} entry limit"
            )));
        }

        let central_size = u64::from(u32::from_le_bytes([
            zip[offset + 12],
            zip[offset + 13],
            zip[offset + 14],
            zip[offset + 15],
        ]));
        let central_offset = u64::from(u32::from_le_bytes([
            zip[offset + 16],
            zip[offset + 17],
            zip[offset + 18],
            zip[offset + 19],
        ]));
        let expected_eocd_offset = central_offset.checked_add(central_size).ok_or_else(|| {
            Error::unknown_bundle_structure("CRX3 ZIP central-directory offset overflows")
        })?;
        let actual_eocd_offset = u64::try_from(offset).map_err(|_| {
            Error::unknown_bundle_structure("CRX3 ZIP central-directory offset is unsupported")
        })?;
        if expected_eocd_offset != actual_eocd_offset {
            return Err(Error::unknown_bundle_structure(
                "CRX3 ZIP central-directory bounds are inconsistent",
            ));
        }
        return Ok(());
    }

    Err(Error::unknown_bundle_structure(
        "CRX3 ZIP has no valid end-of-central-directory entry count",
    ))
}

fn validate_archive_metadata(archive: &mut zip::ZipArchive<std::io::Cursor<&[u8]>>) -> Result<()> {
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(Error::unknown_bundle_structure(format!(
            "CRX3 ZIP has {} entries, exceeding the {MAX_ZIP_ENTRIES} entry limit",
            archive.len()
        )));
    }

    let mut declared_total = 0u64;
    let mut output_paths = std::collections::HashSet::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|error| {
            Error::unknown_bundle_structure(format!("zip entry {index}")).with_source(error)
        })?;
        let rel = validate_zip_entry_metadata(&entry, &mut declared_total)?;
        if !output_paths.insert(rel) {
            return Err(Error::unknown_bundle_structure(format!(
                "CRX3 ZIP contains duplicate normalized output path {}",
                entry.name()
            )));
        }
    }
    Ok(())
}

/// Extract a ZIP body to `out_dir`.
///
/// Bounds are enforced from central-directory metadata before any output is
/// created, then re-checked while streaming so corrupt local headers cannot
/// bypass the declared limits. Symlinks and non-regular special entries are
/// rejected; path traversal continues to rely on `enclosed_name`.
pub(super) fn extract_zip_body(zip: &[u8], out_dir: &Path) -> Result<()> {
    validate_zip_entry_count(zip)?;
    let cursor = std::io::Cursor::new(zip);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| {
        Error::unknown_bundle_structure("CRX3 ZIP body is malformed").with_source(e)
    })?;
    validate_archive_metadata(&mut archive)?;

    std::fs::create_dir_all(out_dir).map_err(Error::from)?;

    let mut written_total = 0u64;
    let mut buf = vec![0u8; ZIP_COPY_BUFFER_BYTES].into_boxed_slice();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            Error::unknown_bundle_structure(format!("zip entry {i}")).with_source(e)
        })?;
        let rel = normalized_zip_entry_path(&entry)?;
        let dest = out_dir.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&dest).map_err(Error::from)?;
            continue;
        }

        // Metadata was already validated; refuse anything that is not a plain
        // regular file before creating destination paths.
        if !entry_is_regular_file(&entry) {
            return Err(Error::unknown_bundle_structure(format!(
                "zip entry {} is not a regular file",
                entry.name()
            )));
        }

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(Error::from)?;
        }
        let mut out = std::fs::File::create(&dest).map_err(Error::from)?;
        let declared_size = entry.size();
        let mut written = 0u64;
        loop {
            let n = entry.read(&mut buf).map_err(|e| {
                Error::unknown_bundle_structure(format!(
                    "zip entry {} failed while streaming",
                    entry.name()
                ))
                .with_source(e)
            })?;
            if n == 0 {
                break;
            }
            let n_u64 = n as u64;
            written = written.checked_add(n_u64).ok_or_else(|| {
                Error::unknown_bundle_structure(format!(
                    "zip entry {} expanded past the per-entry size limit",
                    entry.name()
                ))
            })?;
            if written > declared_size || written > MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES {
                return Err(Error::unknown_bundle_structure(format!(
                    "zip entry {} expanded past its declared size limit",
                    entry.name()
                )));
            }
            written_total = written_total.checked_add(n_u64).ok_or_else(|| {
                Error::unknown_bundle_structure(
                    "CRX3 ZIP expanded past the aggregate uncompressed size limit",
                )
            })?;
            if written_total > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES {
                return Err(Error::unknown_bundle_structure(format!(
                    "CRX3 ZIP expanded past the {MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES} byte aggregate limit"
                )));
            }
            out.write_all(&buf[..n]).map_err(Error::from)?;
        }
        if written != declared_size {
            return Err(Error::unknown_bundle_structure(format!(
                "zip entry {} expanded to {written} bytes, expected {declared_size}",
                entry.name()
            )));
        }
        // Preserve the executable bit on Unix — the CDM `.so`/`.dylib`
        // is mode 0755 in the CRX3. Only permission bits are applied.
        #[cfg(unix)]
        {
            if let Some(mode) = entry.unix_mode() {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(mode & UNIX_PERMISSION_BITS);
                let _ = std::fs::set_permissions(&dest, perms);
            }
        }
    }
    Ok(())
}

pub(super) fn normalized_zip_entry_path(entry: &zip::read::ZipFile<'_>) -> Result<PathBuf> {
    let Some(enclosed) = entry.enclosed_name() else {
        return Err(Error::unknown_bundle_structure(format!(
            "zip entry {} has unsafe path",
            entry.name()
        )));
    };
    let mut normalized = PathBuf::new();
    for component in enclosed.components() {
        match component {
            std::path::Component::Normal(segment) => normalized.push(segment),
            std::path::Component::CurDir => {}
            _ => {
                return Err(Error::unknown_bundle_structure(format!(
                    "zip entry {} has unsafe path",
                    entry.name()
                )));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(Error::unknown_bundle_structure(format!(
            "zip entry {} has an empty output path",
            entry.name()
        )));
    }
    Ok(normalized)
}

/// Reject unsupported entry kinds, normalize its output path, and accumulate
/// declared uncompressed sizes.
pub(super) fn validate_zip_entry_metadata(
    entry: &zip::read::ZipFile<'_>,
    declared_total: &mut u64,
) -> Result<PathBuf> {
    let normalized = normalized_zip_entry_path(entry)?;
    if entry.is_dir() {
        if let Some(mode) = entry.unix_mode() {
            let file_type = mode & UNIX_S_IFMT;
            if file_type != 0 && file_type != UNIX_S_IFDIR {
                return Err(Error::unknown_bundle_structure(format!(
                    "zip directory entry {} has non-directory unix mode {mode:#o}",
                    entry.name()
                )));
            }
        }
        return Ok(normalized);
    }
    if !entry_is_regular_file(entry) {
        return Err(Error::unknown_bundle_structure(format!(
            "zip entry {} is a symlink or special file",
            entry.name()
        )));
    }

    let size = entry.size();
    if size > MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES {
        return Err(Error::unknown_bundle_structure(format!(
            "zip entry {} declares {size} uncompressed bytes, exceeding the {MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES} byte limit",
            entry.name()
        )));
    }
    *declared_total = declared_total.checked_add(size).ok_or_else(|| {
        Error::unknown_bundle_structure(
            "CRX3 ZIP declared uncompressed size overflows the aggregate limit",
        )
    })?;
    if *declared_total > MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES {
        return Err(Error::unknown_bundle_structure(format!(
            "CRX3 ZIP declares {declared_total} uncompressed bytes, exceeding the {MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES} byte aggregate limit"
        )));
    }
    Ok(normalized)
}

/// Returns true when the entry is a plain regular file (not a dir/symlink/special).
fn entry_is_regular_file(entry: &zip::read::ZipFile<'_>) -> bool {
    if entry.is_dir() || entry.is_symlink() || !entry.is_file() {
        return false;
    }
    match entry.unix_mode() {
        None => true,
        Some(mode) => {
            let file_type = mode & UNIX_S_IFMT;
            file_type == 0 || file_type == UNIX_S_IFREG
        }
    }
}

/// Verify that an extracted directory has the expected Widevine layout.
///
/// Returns the path to the platform-specific subdir (`_platform_specific/<x>/`).
///
/// # Errors
///
/// [`crate::ErrorCategory::UnknownBundleStructure`] if the layout doesn't match.
pub fn verify_widevine_layout(extracted: &Path) -> Result<PathBuf> {
    let manifest = extracted.join(CDM_MANIFEST_FILENAME);
    if !manifest.exists() {
        return Err(Error::unknown_bundle_structure(format!(
            "extracted CRX3 is missing manifest.json at {}",
            manifest.display()
        )));
    }
    let plat = extracted.join(PLATFORM_SPECIFIC_DIRECTORY);
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

/// Returns `true` if `dir` contains a supported Widevine shared library.
fn has_widevine_so(dir: &Path) -> bool {
    [Platform::LinuxX86_64, Platform::DarwinAarch64]
        .into_iter()
        .map(platform_library)
        .any(|library| dir.join(library).exists())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Wrap a ZIP body in a minimal CRX3 container (empty signed header).
    fn wrap_crx(zip_bytes: &[u8]) -> Vec<u8> {
        let mut crx = Vec::with_capacity(12 + zip_bytes.len());
        crx.extend_from_slice(CRX3_MAGIC);
        crx.extend_from_slice(&CRX3_VERSION.to_le_bytes());
        crx.extend_from_slice(&0u32.to_le_bytes());
        crx.extend_from_slice(zip_bytes);
        crx
    }

    fn zip_eocd_with_entry_count(count: u16) -> Vec<u8> {
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk number
        eocd.extend_from_slice(&0u16.to_le_bytes()); // central-directory disk
        eocd.extend_from_slice(&count.to_le_bytes()); // entries on this disk
        eocd.extend_from_slice(&count.to_le_bytes()); // total entries
        eocd.extend_from_slice(&0u32.to_le_bytes()); // central-directory size
        eocd.extend_from_slice(&0u32.to_le_bytes()); // central-directory offset
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment length
        eocd
    }

    /// Build a tiny CRX3 byte vector wrapping a synthesized ZIP with a
    /// `manifest.json` and a `_platform_specific/linux_x64/libwidevinecdm.so`.
    fn build_synthetic_crx3() -> Vec<u8> {
        let mut zip_bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_bytes);
            let mut zip = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
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
        wrap_crx(&zip_bytes)
    }

    /// One stored ZIP entry with a forged uncompressed-size claim.
    ///
    /// Used to exercise metadata bounds without allocating multi-hundred-MB
    /// payloads. Local and central headers both advertise `declared_size`.
    fn stored_zip_with_declared_sizes(entries: &[(&str, &[u8], u32, u32)]) -> Vec<u8> {
        let mut local = Vec::new();
        let mut central = Vec::new();
        for &(name, data, declared_size, external_attrs) in entries {
            let name_bytes = name.as_bytes();
            let name_len = u16::try_from(name_bytes.len()).expect("ZIP entry name length fits u16");
            let offset = u32::try_from(local.len()).expect("zip offset fits u32");
            let compressed_size = u32::try_from(data.len()).expect("data fits u32");
            let crc = crc32_ieee(data);

            local.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // LFH sig
            local.extend_from_slice(&20u16.to_le_bytes()); // version needed
            local.extend_from_slice(&0u16.to_le_bytes()); // flags
            local.extend_from_slice(&0u16.to_le_bytes()); // stored
            local.extend_from_slice(&0u16.to_le_bytes()); // mtime
            local.extend_from_slice(&0u16.to_le_bytes()); // mdate
            local.extend_from_slice(&crc.to_le_bytes());
            local.extend_from_slice(&compressed_size.to_le_bytes());
            local.extend_from_slice(&declared_size.to_le_bytes());
            local.extend_from_slice(&name_len.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes()); // extra len
            local.extend_from_slice(name_bytes);
            local.extend_from_slice(data);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // CDH sig
            central.extend_from_slice(&0x03u8.to_le_bytes()); // version made by (low)
            central.extend_from_slice(&3u8.to_le_bytes()); // system = UNIX
            central.extend_from_slice(&20u16.to_le_bytes()); // version needed
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&0u16.to_le_bytes()); // stored
            central.extend_from_slice(&0u16.to_le_bytes()); // mtime
            central.extend_from_slice(&0u16.to_le_bytes()); // mdate
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&compressed_size.to_le_bytes());
            central.extend_from_slice(&declared_size.to_le_bytes());
            central.extend_from_slice(&name_len.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comment
            central.extend_from_slice(&0u16.to_le_bytes()); // disk start
            central.extend_from_slice(&0u16.to_le_bytes()); // int attrs
            central.extend_from_slice(&external_attrs.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name_bytes);
        }

        let cd_offset = u32::try_from(local.len()).expect("cd offset");
        let cd_size = u32::try_from(central.len()).expect("cd size");
        let count = u16::try_from(entries.len()).expect("entry count");
        let mut out = local;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // EOCD
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out
    }

    fn regular_external_attrs(mode: u32) -> u32 {
        (UNIX_S_IFREG | (mode & UNIX_PERMISSION_BITS)) << 16
    }

    fn special_external_attrs(file_type: u32, mode: u32) -> u32 {
        (file_type | (mode & UNIX_PERMISSION_BITS)) << 16
    }

    fn assert_out_dir_has_no_regular_files(out: &Path) {
        fn walk(path: &Path) {
            let meta = std::fs::symlink_metadata(path).expect("metadata");
            assert!(
                !meta.file_type().is_symlink(),
                "unexpected symlink at {}",
                path.display()
            );
            assert!(
                !meta.is_file(),
                "unexpected regular file written at {}",
                path.display()
            );
            if meta.is_dir() {
                for entry in std::fs::read_dir(path).expect("read_dir") {
                    walk(&entry.expect("entry").path());
                }
            }
        }

        if !out.exists() {
            return;
        }
        walk(out);
    }

    /// IEEE CRC-32 used by ZIP local/central headers.
    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for &byte in data {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
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
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("traversal must be rejected");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
        assert_out_dir_has_no_regular_files(&out);
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
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        extract_crx3_bytes(&crx, &out).expect("ok");
        assert!(out.join("just-a-dir").is_dir());
        assert!(out.join("just-a-dir").join("inside.txt").exists());
    }

    #[test]
    fn extract_crx3_rejects_excessive_entry_count() {
        let mut zip_bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_bytes);
            let mut zip = ZipWriter::new(cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for i in 0..=MAX_ZIP_ENTRIES {
                let name = format!("f{i}.txt");
                zip.start_file(&name, opts).expect("start");
                zip.write_all(b"x").expect("write");
            }
            zip.finish().expect("finish");
        }
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("entry count");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
        assert!(
            err.message.contains("entry"),
            "unexpected message: {}",
            err.message
        );
        assert_out_dir_has_no_regular_files(&out);
    }

    #[test]
    fn extract_crx3_rejects_declared_entry_count_before_zip_parsing() {
        let crx = wrap_crx(&zip_eocd_with_entry_count(
            u16::try_from(MAX_ZIP_ENTRIES + 1).expect("entry limit fits u16"),
        ));
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");

        let err = extract_crx3_bytes(&crx, &out).expect_err("entry count");

        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
        assert!(
            err.message.contains("entry"),
            "unexpected message: {}",
            err.message
        );
        assert!(!out.exists(), "preflight rejection must not create output");
    }

    #[test]
    fn extract_crx3_rejects_oversized_single_uncompressed_entry() {
        let declared = u32::try_from(MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES + 1).expect("fits u32");
        let zip_bytes = stored_zip_with_declared_sizes(&[(
            "huge.bin",
            b"tiny",
            declared,
            regular_external_attrs(0o644),
        )]);
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("per-entry size");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
        assert!(
            err.message.contains("uncompressed"),
            "unexpected message: {}",
            err.message
        );
        assert_out_dir_has_no_regular_files(&out);
    }

    #[test]
    fn extract_crx3_rejects_aggregate_uncompressed_overflow() {
        // Each entry is within the per-entry cap, but the sum exceeds the
        // aggregate expanded-byte budget.
        let per = u32::try_from(MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES).expect("fits u32");
        let zip_bytes = stored_zip_with_declared_sizes(&[
            ("a.bin", b"a", per, regular_external_attrs(0o644)),
            ("b.bin", b"b", per, regular_external_attrs(0o644)),
            ("c.bin", b"c", 1, regular_external_attrs(0o644)),
        ]);
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("aggregate size");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
        assert!(
            err.message.contains("aggregate") || err.message.contains("uncompressed"),
            "unexpected message: {}",
            err.message
        );
        assert_out_dir_has_no_regular_files(&out);
    }

    #[test]
    fn extract_crx3_rejects_symlink_entries() {
        let mut zip_bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_bytes);
            let mut zip = ZipWriter::new(cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zip.add_symlink("link-to-so", "libwidevinecdm.so", opts)
                .expect("symlink");
            zip.finish().expect("finish");
        }
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("symlink");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
        assert!(
            err.message.contains("symlink") || err.message.contains("special"),
            "unexpected message: {}",
            err.message
        );
        assert_out_dir_has_no_regular_files(&out);
        assert!(!out.join("link-to-so").exists());
    }

    #[test]
    fn extract_crx3_rejects_special_file_entries() {
        // Unix FIFO (S_IFIFO = 0o010000) is neither a regular file nor a dir.
        const UNIX_S_IFIFO: u32 = 0o010_000;
        let zip_bytes = stored_zip_with_declared_sizes(&[(
            "service.fifo",
            b"ignored",
            7,
            special_external_attrs(UNIX_S_IFIFO, 0o644),
        )]);
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("special file");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
        assert!(
            err.message.contains("special") || err.message.contains("symlink"),
            "unexpected message: {}",
            err.message
        );
        assert_out_dir_has_no_regular_files(&out);
        assert!(!out.join("service.fifo").exists());
    }

    #[cfg(unix)]
    #[test]
    fn extract_crx3_preserves_unix_executable_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let mut zip_bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_bytes);
            let mut zip = ZipWriter::new(cursor);
            let opts = SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(0o755);
            zip.start_file("libwidevinecdm.so", opts).expect("start");
            zip.write_all(b"\x7fELFexe").expect("write");
            zip.finish().expect("finish");
        }
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        extract_crx3_bytes(&crx, &out).expect("extract");
        let mode = std::fs::metadata(out.join("libwidevinecdm.so"))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn extract_crx3_stream_rejects_expansion_past_declared_size() {
        // Advertise a tiny uncompressed size while shipping more stored
        // bytes. Metadata passes the coarse caps; the streaming copy must
        // still refuse to write past the declared size.
        let zip_bytes = stored_zip_with_declared_sizes(&[(
            "mismatch.bin",
            b"twelve bytes", // 12 bytes payload
            4,               // lie: only 4 uncompressed bytes declared
            regular_external_attrs(0o644),
        )]);
        let crx = wrap_crx(&zip_bytes);
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("out");
        let err = extract_crx3_bytes(&crx, &out).expect_err("stream size");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
        // File may exist but must not retain more than the declared limit.
        if out.join("mismatch.bin").exists() {
            let wrote = std::fs::metadata(out.join("mismatch.bin"))
                .expect("meta")
                .len();
            assert!(
                wrote <= 4,
                "wrote {wrote} bytes past the declared uncompressed limit"
            );
        }
    }
}
