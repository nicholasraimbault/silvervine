use super::*;
use std::collections::HashMap;
use std::fs;
use tempfile::TempDir;

use crate::widevine::manifest::{GmpVendor, PlatformEntry};

fn zip_eocd_with_entry_count(count: u16) -> Vec<u8> {
    let mut eocd = Vec::with_capacity(22);
    eocd.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes());
    eocd.extend_from_slice(&count.to_le_bytes());
    eocd.extend_from_slice(&count.to_le_bytes());
    eocd.extend_from_slice(&0u32.to_le_bytes());
    eocd.extend_from_slice(&0u32.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes());
    eocd
}

#[test]
fn authenticated_digest_rejects_declared_entry_count_before_zip_parsing() {
    let err = authenticated_payload_digests_from_zip(
        &zip_eocd_with_entry_count(257),
        Platform::LinuxX86_64,
    )
    .expect_err("entry count");

    assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    assert!(
        err.message.contains("entry"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn authenticated_digest_rejects_expansion_past_declared_size() {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    let mut body = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut body));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file(CDM_MANIFEST_FILENAME, options)
            .expect("manifest entry");
        zip.write_all(b"{}").expect("manifest bytes");
        zip.start_file(
            format!(
                "{}/{}/{}",
                PLATFORM_SPECIFIC_DIRECTORY,
                platform_directory(Platform::LinuxX86_64),
                platform_library(Platform::LinuxX86_64)
            ),
            options,
        )
        .expect("library entry");
        zip.write_all(b"library").expect("library bytes");
        zip.finish().expect("finish ZIP");
    }

    let local = body
        .windows(4)
        .position(|window| window == 0x0403_4b50u32.to_le_bytes())
        .expect("local header");
    body[local + 22..local + 26].copy_from_slice(&1u32.to_le_bytes());
    let central = body
        .windows(4)
        .position(|window| window == 0x0201_4b50u32.to_le_bytes())
        .expect("central header");
    body[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());

    let error = authenticated_payload_digests_from_zip(&body, Platform::LinuxX86_64)
        .expect_err("entry must not expand past its declared size");

    assert_eq!(error.category, crate::ErrorCategory::UnknownBundleStructure);
}

#[test]
fn authenticated_digest_rejects_duplicate_normalized_targets() {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    let mut body = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut body));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("manifest.json", options).expect("manifest");
        zip.write_all(br#"{"version":"1"}"#).expect("write");
        zip.start_file("./manifest.json", options)
            .expect("duplicate manifest");
        zip.write_all(br#"{"version":"2"}"#).expect("write");
        zip.start_file("_platform_specific/linux_x64/libwidevinecdm.so", options)
            .expect("library");
        zip.write_all(b"\x7fELF-test").expect("write");
        zip.finish().expect("finish");
    }

    let err = authenticated_payload_digests_from_zip(&body, Platform::LinuxX86_64)
        .expect_err("duplicate normalized target");

    assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    assert!(
        err.message.contains("duplicate"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn authenticated_digest_validates_all_entry_metadata_before_hashing() {
    use std::io::{Cursor, Write};
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    let mut body = Vec::new();
    {
        let mut zip = ZipWriter::new(Cursor::new(&mut body));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("manifest.json", options).expect("manifest");
        zip.write_all(br#"{"version":"1"}"#).expect("write");
        zip.start_file("_platform_specific/linux_x64/libwidevinecdm.so", options)
            .expect("library");
        zip.write_all(b"\x7fELF-test").expect("write");
        zip.add_symlink("unrelated-link", "manifest.json", options)
            .expect("symlink");
        zip.finish().expect("finish");
    }

    let err = authenticated_payload_digests_from_zip(&body, Platform::LinuxX86_64)
        .expect_err("unsafe metadata");

    assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    assert!(
        err.message.contains("symlink") || err.message.contains("special"),
        "unexpected message: {}",
        err.message
    );
}

fn ensure_cdm_for_with(
    manifest: &Manifest,
    platform: Platform,
    cache_root: &Path,
) -> Result<CachedCdm> {
    let cache = CdmCache::new(cache_root, platform);
    fs::create_dir_all(cache.root()).map_err(Error::from)?;
    cache.with_mutation_lock(|| {
        ensure_unlocked_with_authenticator(&cache, manifest, crx3::trust_unsigned_crx_for_test)
    })
}

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

    let error = validated_current_in(tmp.path(), Platform::LinuxX86_64).expect_err("corrupt cache");

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
fn production_ensure_rejects_unsigned_manifest_matched_crx() {
    let crx = build_synthetic_crx3("1.0.0");
    let url = spawn_crx_server(crx.clone());
    let manifest = manifest_for_crx(&url, &crx, "1.0.0");
    let tmp = TempDir::new().expect("tempdir");

    let error = super::ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
        .expect_err("manifest SHA-512 alone must not authorize executable CDM bytes");

    assert_eq!(error.category, crate::ErrorCategory::UnknownBundleStructure);
    assert!(!tmp.path().join("current").exists());
    assert!(!tmp.path().join("1.0.0").exists());
}

#[test]
#[ignore = "requires a current vendor CRX3 and matching version in the environment"]
fn production_ensure_accepts_current_vendor_crx() {
    let path =
        std::env::var_os("SILVERVINE_TEST_WIDEVINE_CRX").expect("set SILVERVINE_TEST_WIDEVINE_CRX");
    let version = std::env::var("SILVERVINE_TEST_WIDEVINE_VERSION")
        .expect("set SILVERVINE_TEST_WIDEVINE_VERSION");
    let crx = fs::read(path).expect("read vendor CRX3");
    let url = spawn_crx_server(crx.clone());
    let manifest = manifest_for_crx(&url, &crx, &version);
    let tmp = TempDir::new().expect("tempdir");

    let cdm = super::ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path())
        .expect("pinned signature and bounded extraction must admit the vendor CRX");

    assert_eq!(cdm.version(), version);
    assert!(cdm.cdm_dir().join(CDM_MANIFEST_FILENAME).is_file());
    assert!(cdm
        .cdm_dir()
        .join(PLATFORM_SPECIFIC_DIRECTORY)
        .join(platform_directory(Platform::LinuxX86_64))
        .join(platform_library(Platform::LinuxX86_64))
        .is_file());
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
    let cdm =
        ensure_cdm_for_with(&manifest, Platform::LinuxX86_64, tmp.path()).expect("must redownload");
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
