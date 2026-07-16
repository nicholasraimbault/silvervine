//! Widevine CRX3 download with SHA-512 verification.
//!
//! ## Inputs
//!
//! A [`crate::widevine::manifest::PlatformEntry::Concrete`] from the parsed
//! manifest. Contains:
//!
//! * `file_url` — primary download URL.
//! * `mirror_urls` — Mozilla-supplied mirrors, tried after the primary.
//! * `filesize` — expected size in bytes (advisory only; we trust the hash).
//! * `hash_value` — SHA-512 hex digest the downloaded bytes must match.
//!
//! ## Output
//!
//! A path to the verified `.crx3` file on disk. In production this is
//! typically `~/.cache/silvervine/downloads/<sha-prefix>.crx3`; tests pass a
//! `tempfile::TempDir`.
//!
//! ## Hash mismatch handling
//!
//! On hash mismatch we **delete the file** before returning the error so
//! the caller can retry without an in-progress half-downloaded file
//! lurking. The error category is [`crate::ErrorCategory::HashMismatch`].
//!
//! ## What this module does NOT do
//!
//! * No CRX3 parsing — that's [`crate::widevine::extract`].
//! * No cache management or symlink updates — that's [`crate::widevine::cache`].
//! * No retry policy beyond the URL fallback — Phase 2 deliberately keeps
//!   things simple. A jitter+backoff retry loop is V1.1 work.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha512};

use crate::error::{Error, Result};
use crate::widevine::manifest::PlatformEntry;

/// HTTP transport timeout per URL. Mirrors the manifest fetcher's value.
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);

/// Default download cache directory: `~/.cache/silvervine/downloads/`.
///
/// Returns `None` if `dirs::cache_dir()` is unresolvable.
#[must_use]
pub fn default_download_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("silvervine").join("downloads"))
}

/// Download the CRX3 described by `entry` and verify its SHA-512.
///
/// On success returns the on-disk path to the verified `.crx3` file. The
/// file is named after the first 16 hex characters of the expected hash —
/// stable across re-downloads, so a second call for the same hash short-
/// circuits if the file already exists and verifies.
///
/// # Errors
///
/// * [`crate::ErrorCategory::NetworkError`] — every URL in the chain failed.
/// * [`crate::ErrorCategory::HashMismatch`] — bytes downloaded but their
///   SHA-512 doesn't match `entry.hash_value`. The file is removed.
/// * [`crate::ErrorCategory::Other`] — disk I/O failed (e.g. cache dir
///   creation).
pub fn download_to_cache(entry: &PlatformEntry) -> Result<PathBuf> {
    let dir = default_download_dir().ok_or_else(|| {
        Error::state_corrupted(
            "cannot resolve ~/.cache/silvervine/downloads (no \\$HOME / cache dir)",
        )
    })?;
    download_to(entry, &dir)
}

/// Test- and injection-friendly variant: downloads into `dir`.
///
/// `dir` is created if it doesn't exist. The output filename is
/// `<sha-prefix>.crx3` so multiple platforms (each with a different hash)
/// don't collide.
///
/// # Errors
///
/// See [`download_to_cache`].
pub fn download_to(entry: &PlatformEntry, dir: &Path) -> Result<PathBuf> {
    let (urls, expected_hash, expected_size) = match entry {
        PlatformEntry::Concrete {
            file_url,
            mirror_urls,
            hash_value,
            filesize,
        } => {
            let mut urls = Vec::with_capacity(1 + mirror_urls.len());
            urls.push(file_url.clone());
            urls.extend(mirror_urls.iter().cloned());
            (urls, hash_value.clone(), *filesize)
        }
        PlatformEntry::Alias { alias } => {
            return Err(Error::unknown_bundle_structure(format!(
                "download_to called on an alias entry pointing at '{alias}'; \
                 caller should have followed the alias before invoking this"
            )));
        }
    };

    std::fs::create_dir_all(dir).map_err(Error::from)?;

    // Stable filename per hash so a re-download finds the file by name.
    let prefix = expected_hash
        .get(..16)
        .ok_or_else(|| Error::hash_mismatch("manifest hash too short"))?;
    let path = dir.join(format!("{prefix}.crx3"));

    // Short-circuit: if the file is already on disk and verifies, return it.
    if path.exists() {
        match verify_file(&path, &expected_hash, expected_size) {
            Ok(()) => return Ok(path),
            Err(_) => {
                // Don't return the error directly — try a fresh download.
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| Error::network("failed to construct HTTP client").with_source(e))?;

    let mut last_err: Option<Error> = None;
    for url in &urls {
        match download_one(&client, url, &path) {
            Ok(()) => match verify_file(&path, &expected_hash, expected_size) {
                Ok(()) => return Ok(path),
                Err(e) => {
                    let _ = std::fs::remove_file(&path);
                    return Err(e);
                }
            },
            Err(e) => {
                let _ = std::fs::remove_file(&path);
                last_err = Some(e);
            }
        }
    }

    let mut err = Error::network(format!(
        "every URL in the {}-entry chain failed",
        urls.len()
    ));
    if let Some(prev) = last_err {
        err.source = Some(Box::new(prev));
    }
    Err(err)
}

/// Verify an on-disk file matches the expected SHA-512 (and optional size).
///
/// # Errors
///
/// [`crate::ErrorCategory::HashMismatch`] on size or hash mismatch.
/// [`crate::ErrorCategory::Other`] / `PermissionDenied` if the file
/// cannot be read.
pub fn verify_file(path: &Path, expected_hash: &str, expected_size: Option<u64>) -> Result<()> {
    let mut file = File::open(path).map_err(Error::from)?;
    if let Some(size) = expected_size {
        let actual_size = file.metadata().map_err(Error::from)?.len();
        if actual_size != size {
            return Err(Error::hash_mismatch(format!(
                "{} size {} bytes != manifest {} bytes",
                path.display(),
                actual_size,
                size
            )));
        }
    }
    let mut hasher = Sha512::new();
    // 64 KiB buffer — heap-allocated to keep the stack frame small (clippy
    // `large_stack_arrays` flags >16 KiB locals on certain targets).
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(Error::from)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex_lower(&hasher.finalize());
    if !hashes_equal(&actual, expected_hash) {
        return Err(Error::hash_mismatch(format!(
            "{}: SHA-512 mismatch (expected {}, got {})",
            path.display(),
            expected_hash,
            actual
        )));
    }
    Ok(())
}

/// Compute SHA-512 of `bytes` and return the hex digest.
#[must_use]
pub fn sha512_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

/// Download one URL into `path`, streaming bytes to disk.
fn download_one(client: &reqwest::blocking::Client, url: &str, path: &Path) -> Result<()> {
    let mut response = client
        .get(url)
        .send()
        .map_err(|e| Error::network(format!("GET {url} failed")).with_source(e))?;
    if !response.status().is_success() {
        return Err(Error::network(format!(
            "GET {url} returned HTTP {}",
            response.status()
        )));
    }
    let mut file = File::create(path).map_err(Error::from)?;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = response
            .read(&mut buf)
            .map_err(|e| Error::network(format!("read body from {url}")).with_source(e))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).map_err(Error::from)?;
    }
    file.flush().map_err(Error::from)?;
    Ok(())
}

/// Constant-time hex comparison.
///
/// SHA-512 hex strings are 128 ASCII chars. We compare case-insensitively
/// (the manifest lowercases its digests, but defensive coding doesn't
/// hurt) and in constant time (`==` would short-circuit on the first
/// differing byte; that's fine for hash mismatch detection but a habit
/// we'd rather not pick up).
fn hashes_equal(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= u8::from(!x.eq_ignore_ascii_case(&y));
    }
    diff == 0
}

/// Hex-encode a byte slice as lowercase ASCII.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widevine::manifest::PlatformEntry;
    use std::io::{BufRead, BufReader, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use tempfile::TempDir;

    /// Spin up an in-process HTTP/1.1 stub that serves `body` for any GET.
    /// Returns `(url, attempts)` where `attempts` increments per request.
    /// Mirrors the technique used in the manifest tests.
    fn spawn_stub(body: Vec<u8>) -> (String, Arc<AtomicUsize>) {
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = Arc::clone(&attempts);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let local = listener.local_addr().expect("local_addr");
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                inner.fetch_add(1, Ordering::SeqCst);
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
        (format!("http://{local}/widevine.crx3"), attempts)
    }

    #[test]
    fn sha512_hex_matches_known_vector() {
        // SHA-512("abc") = ddaf...
        let expected =
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
        assert_eq!(sha512_hex(b"abc"), expected);
    }

    #[test]
    fn hashes_equal_is_case_insensitive() {
        assert!(hashes_equal("DEAD", "dead"));
        assert!(hashes_equal("dead", "DEAD"));
        assert!(!hashes_equal("dead", "beef"));
        assert!(!hashes_equal("dead", "deadbeef"));
    }

    #[test]
    fn verify_file_succeeds_for_matching_content() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("fixture.bin");
        std::fs::write(&path, b"abc").expect("write");
        let expected = sha512_hex(b"abc");
        verify_file(&path, &expected, Some(3)).expect("must verify");
    }

    #[test]
    fn verify_file_fails_for_size_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("size.bin");
        std::fs::write(&path, b"abc").expect("write");
        let expected = sha512_hex(b"abc");
        let err = verify_file(&path, &expected, Some(99)).expect_err("size mismatch must fail");
        assert_eq!(err.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn verify_file_fails_for_hash_mismatch() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("hash.bin");
        std::fs::write(&path, b"abc").expect("write");
        let bogus = "0".repeat(128);
        let err = verify_file(&path, &bogus, None).expect_err("hash mismatch");
        assert_eq!(err.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn download_to_with_correct_hash_writes_file() {
        let body = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let expected = sha512_hex(&body);
        let (url, attempts) = spawn_stub(body.clone());
        let entry = PlatformEntry::Concrete {
            file_url: url,
            mirror_urls: vec![],
            filesize: Some(body.len() as u64),
            hash_value: expected,
        };
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("downloads");
        let path = download_to(&entry, &dir).expect("download must succeed");
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).expect("read"), body);
        assert!(attempts.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn download_to_short_circuits_when_file_already_verifies() {
        let body = vec![9u8; 32];
        let expected = sha512_hex(&body);
        let (url, attempts) = spawn_stub(body.clone());
        let entry = PlatformEntry::Concrete {
            file_url: url,
            mirror_urls: vec![],
            filesize: Some(body.len() as u64),
            hash_value: expected,
        };
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("downloads");
        let path1 = download_to(&entry, &dir).expect("first");
        let after_first = attempts.load(Ordering::SeqCst);
        let path2 = download_to(&entry, &dir).expect("second");
        assert_eq!(path1, path2);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            after_first,
            "second call must not re-fetch"
        );
    }

    #[test]
    fn download_to_falls_through_to_mirror_on_first_url_failure() {
        let body = vec![42u8; 64];
        let expected = sha512_hex(&body);
        let (good, _) = spawn_stub(body.clone());
        let entry = PlatformEntry::Concrete {
            file_url: "http://127.0.0.1:1/nope".into(),
            mirror_urls: vec![good],
            filesize: Some(body.len() as u64),
            hash_value: expected,
        };
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("downloads");
        let path = download_to(&entry, &dir).expect("mirror must succeed");
        assert_eq!(std::fs::read(&path).expect("read"), body);
    }

    #[test]
    fn download_to_with_wrong_hash_removes_file_and_errors() {
        let body = vec![1u8, 2, 3, 4];
        let (url, _) = spawn_stub(body.clone());
        let entry = PlatformEntry::Concrete {
            file_url: url,
            mirror_urls: vec![],
            filesize: Some(body.len() as u64),
            hash_value: "0".repeat(128),
        };
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("downloads");
        let err = download_to(&entry, &dir).expect_err("hash mismatch");
        assert_eq!(err.category, crate::ErrorCategory::HashMismatch);
        // File must be removed.
        let leftover: Vec<_> = std::fs::read_dir(&dir)
            .expect("read dir")
            .flatten()
            .collect();
        assert!(leftover.is_empty(), "leftover files: {leftover:?}");
    }

    #[test]
    fn download_to_aliasentry_returns_unknown_bundle_structure() {
        let entry = PlatformEntry::Alias {
            alias: "Linux_x86_64-gcc3".into(),
        };
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("downloads");
        let err = download_to(&entry, &dir).expect_err("alias should error");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn download_to_returns_network_error_when_all_urls_fail() {
        let entry = PlatformEntry::Concrete {
            file_url: "http://127.0.0.1:1/a".into(),
            mirror_urls: vec!["http://127.0.0.1:1/b".into()],
            filesize: None,
            hash_value: sha512_hex(b"unused"),
        };
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("downloads");
        let err = download_to(&entry, &dir).expect_err("all urls fail");
        assert_eq!(err.category, crate::ErrorCategory::NetworkError);
    }

    #[test]
    fn default_download_dir_resolves_under_silvervine_subdir() {
        if let Some(p) = default_download_dir() {
            let suffix = std::path::Path::new("silvervine").join("downloads");
            assert!(p.ends_with(&suffix), "got {}", p.display());
        }
    }

    /// `download_to` errors with `HashMismatch` when the manifest's hash
    /// is too short for our 16-char-prefix filename trick.
    #[test]
    fn download_to_errors_for_short_hash() {
        let entry = PlatformEntry::Concrete {
            file_url: "http://127.0.0.1:1/x".into(),
            mirror_urls: vec![],
            filesize: None,
            hash_value: "abc".into(),
        };
        let tmp = TempDir::new().expect("tempdir");
        let err = download_to(&entry, tmp.path()).expect_err("short hash");
        assert_eq!(err.category, crate::ErrorCategory::HashMismatch);
    }

    /// `download_to_cache` (the public default-path variant) doesn't panic;
    /// it surfaces a categorized error if `dirs::cache_dir()` is None.
    #[test]
    fn download_to_cache_does_not_panic() {
        let entry = PlatformEntry::Concrete {
            file_url: "http://127.0.0.1:1/nope".into(),
            mirror_urls: vec![],
            filesize: None,
            hash_value: "0".repeat(128),
        };
        // Either a network error (URL fails) or a state-corrupted (no cache
        // dir): both are valid outcomes; no panic.
        let outcome = download_to_cache(&entry);
        assert!(outcome.is_err());
    }

    /// The integration-test happy path against the live Mozilla manifest
    /// (gated `--ignored`). Reads the committed fixture's first concrete
    /// Linux entry, downloads the CRX3, verifies the SHA-512.
    ///
    /// Run with: `cargo test --lib widevine::download::tests::download_real_widevine_from_mozilla -- --ignored`
    #[test]
    #[ignore = "hits the live Mozilla manifest URL; gated to keep CI hermetic"]
    fn download_real_widevine_from_mozilla() {
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join("widevinecdm.json"),
        )
        .expect("fixture readable");
        let manifest = crate::widevine::manifest::parse_manifest(&raw).expect("fixture parses");
        let entry = manifest
            .resolve_platform(crate::widevine::manifest::Platform::LinuxX86_64)
            .expect("resolve linux");
        let tmp = TempDir::new().expect("tempdir");
        let dir = tmp.path().join("downloads");
        let path = download_to(entry, &dir).expect("real download");
        assert!(path.exists());
        let meta = std::fs::metadata(&path).expect("metadata");
        assert!(meta.len() > 1024 * 1024, "Widevine CRX is several MB");
    }
}
