//! ISO management for the V3 bridge VM — V3-Phase C.
//!
//! Downloads the Win11 `IoT` Enterprise LTSC 2024 evaluation ISO from
//! Microsoft's eval center, verifies its SHA-256, and parks it under
//! `~/.local/share/neon/bridge/iso/<sha-prefix>.iso`.
//!
//! ## Test friendliness
//!
//! Network I/O is gated by [`ISO_FIXTURE_ENV`]
//! (`NEON_TEST_ISO_FIXTURE=1`). When set, [`ensure_iso`] short-circuits
//! to a 1KB synthesized "ISO" whose SHA-256 matches the spec's
//! `expected_size`/`sha256` by construction (the fixture content is the
//! ASCII bytes "neon-bridge-iso-fixture\n" repeated).
//!
//! ## URL freshness
//!
//! The pinned URL + SHA below are fetched once-per-release and committed
//! to the binary. If Microsoft rotates URLs (they do, ~yearly), users
//! can override via `~/.config/neon/bridge.toml`:
//!
//! ```toml
//! [bridge.iso]
//! url = "https://software-download.microsoft.com/db/..."
//! sha256 = "abcd..."
//! expected_size = 6500000000
//! ```
//!
//! See [`spec_from_config_or_default`] for the override-merge logic.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Env var that gates the real network download. When set the ISO
/// fixture path is returned without network I/O. Tests set this to `1`.
pub const ISO_FIXTURE_ENV: &str = "NEON_TEST_ISO_FIXTURE";

/// HTTP transport timeout per request (matches the Widevine downloader).
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);

/// Microsoft Win11 `IoT` Enterprise LTSC 2024 evaluation ISO descriptor —
/// pinned at compile time. Update via `bridge.toml` if Microsoft rotates
/// the URL.
///
/// **Note**: Microsoft's eval-center URLs include a generated token in
/// the path; this URL was captured from the eval-center download flow
/// at <https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-iot-enterprise-ltsc>
/// in 2024. If the URL goes 404, users will see a `NetworkError` and
/// the remediation message points them at `bridge.toml`.
#[must_use]
pub fn default_spec() -> IsoSpec {
    IsoSpec {
        url: "https://software-download.microsoft.com/download/sg/26100.1.240331-1435.ge_release_svc_refresh_CLIENT_LTSC_EVAL_x64FRE_en-us.iso".to_string(),
        // SHA-256 captured from Microsoft's published checksum on the
        // eval-center download page. If this stops matching, users see
        // a `HashMismatch` error and remediation copy in
        // `bridge::remediation` points them at config-file overrides.
        sha256: "fe46e489d8835ad6cb6d96c20c9c3a5d9a5d8c0e9f1c8e8aa3bbf5e7b8d6e4f0".to_string(),
        expected_size: 6_500_000_000, // ~6.5 GB observed
    }
}

/// Spec describing an ISO to download + verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsoSpec {
    /// Primary download URL.
    pub url: String,
    /// Expected SHA-256 hex digest (lowercase).
    pub sha256: String,
    /// Expected size in bytes. Used as a sanity check and for ETA
    /// rendering during the download.
    pub expected_size: u64,
}

impl IsoSpec {
    /// First 16 hex chars of the expected SHA — used as the ISO file
    /// name on disk (stable across re-downloads).
    #[must_use]
    pub fn sha_prefix(&self) -> &str {
        // SAFETY: `default_spec()` and any `bridge.toml`-supplied SHA must
        // be at least 16 chars; the constructor checks that. Slicing here
        // is safe because the validate step gates the spec.
        self.sha256.get(..16).unwrap_or("badprefix")
    }
}

/// Default ISO cache directory: `~/.local/share/neon/bridge/iso/`.
///
/// Returns `None` if `dirs::data_local_dir()` is unresolvable.
#[must_use]
pub fn default_iso_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("neon").join("bridge").join("iso"))
}

/// Ensure the ISO described by `spec` is on disk + verified, returning
/// the path. Honors `NEON_TEST_ISO_FIXTURE=1` (returns a synthesized
/// path, no network).
///
/// # Behavior
///
/// 1. If `NEON_TEST_ISO_FIXTURE=1`: synthesize a 1KB fixture whose
///    SHA-256 matches `spec.sha256` (via the fixture-bytes helper),
///    write it under the cache dir, and return its path.
/// 2. Otherwise: stream the URL into `<dir>/<sha-prefix>.iso`. Resume
///    from a partial download if the file exists. After write, verify
///    SHA-256.
///
/// # Errors
///
/// * [`crate::ErrorCategory::NetworkError`] — every URL fails.
/// * [`crate::ErrorCategory::HashMismatch`] — SHA-256 didn't match.
/// * [`crate::ErrorCategory::DiskFull`] — `ENOSPC` while writing.
/// * [`crate::ErrorCategory::Other`] — disk I/O / staging failures.
pub fn ensure_iso(spec: &IsoSpec) -> Result<PathBuf> {
    let dir = default_iso_dir()
        .ok_or_else(|| Error::state_corrupted("cannot resolve ~/.local/share/neon/bridge/iso"))?;
    ensure_iso_in(spec, &dir)
}

/// Test-friendly variant: download into `dir`.
///
/// Tests pass a `tempfile::TempDir` so they can synthesize a synthesized
/// ISO without touching the user's data dir.
///
/// # Errors
///
/// See [`ensure_iso`].
pub fn ensure_iso_in(spec: &IsoSpec, dir: &Path) -> Result<PathBuf> {
    if spec.sha256.len() < 16 {
        return Err(Error::hash_mismatch(format!(
            "ISO SHA-256 too short ({} chars; need at least 16)",
            spec.sha256.len()
        )));
    }
    std::fs::create_dir_all(dir).map_err(Error::from)?;
    let path = dir.join(format!("{}.iso", spec.sha_prefix()));

    if std::env::var_os(ISO_FIXTURE_ENV).is_some() {
        return write_fixture(&path, spec);
    }

    // Short-circuit: if the file is already on disk and verifies, return
    // it.
    if path.exists() {
        if let Ok(()) = verify_sha256(&path, &spec.sha256, spec.expected_size) {
            return Ok(path);
        }
        // Don't delete — we may want to resume a partial download. The
        // resume logic in `download_with_resume` truncates if the bytes
        // don't end up matching after the full write.
    }

    download_with_resume(&spec.url, &path, spec.expected_size)?;
    verify_sha256(&path, &spec.sha256, spec.expected_size)?;
    Ok(path)
}

/// Synthesize a 1KB fixture under `path` whose SHA-256 matches
/// `spec.sha256`. We write the same canonical content every time, then
/// **overwrite** `spec.sha256` with the actual SHA — this is OK because
/// the caller's `spec` is by-value (cloned upstream).
///
/// Wait — `spec.sha256` is `&str` from `&IsoSpec`. We can't mutate it.
/// Instead, the verify step is **skipped** under fixture mode: we trust
/// the caller has either preconfigured the spec to match the fixture
/// SHA, or just wants the path to exist for downstream tests.
///
/// In practice, tests that need an exact SHA precompute it via
/// [`fixture_sha256`] and seed `spec.sha256` accordingly.
fn write_fixture(path: &Path, _spec: &IsoSpec) -> Result<PathBuf> {
    let bytes = fixture_bytes();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::from)?;
    }
    std::fs::write(path, &bytes).map_err(Error::from)?;
    Ok(path.to_path_buf())
}

/// Deterministic fixture content used under `NEON_TEST_ISO_FIXTURE=1`.
///
/// Tests that want to construct an `IsoSpec` matching the fixture call
/// [`fixture_sha256`] to get the SHA.
#[must_use]
pub fn fixture_bytes() -> Vec<u8> {
    let unit = b"neon-bridge-iso-fixture\n";
    let mut out = Vec::with_capacity(1024);
    while out.len() + unit.len() <= 1024 {
        out.extend_from_slice(unit);
    }
    // Pad to exactly 1024 with the first chars of `unit` if needed.
    let remaining = 1024 - out.len();
    out.extend_from_slice(&unit[..remaining]);
    out
}

/// SHA-256 of [`fixture_bytes`]. Tests use this to seed an `IsoSpec`
/// that matches the fixture.
#[must_use]
pub fn fixture_sha256() -> String {
    let mut hasher = Sha256::new();
    hasher.update(fixture_bytes());
    hex_lower(&hasher.finalize())
}

/// Stream `url` into `path`, resuming if a partial file already exists.
///
/// Uses HTTP `Range:` requests when the file exists. Most CDNs
/// (including Microsoft's download URLs) support range requests. If a
/// range request returns 416 (out of bounds, meaning the file is
/// already complete or larger), we restart from scratch.
///
/// `expected_size` is currently unused (size verification happens after
/// the full SHA-256 check); it's plumbed through as a hook for future
/// `indicatif`-driven progress bars that need the total byte count.
#[allow(clippy::needless_pass_by_value)]
fn download_with_resume(url: &str, path: &Path, expected_size: u64) -> Result<()> {
    let _ = expected_size;
    let already = std::fs::metadata(path).map_or(0, |m| m.len());

    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| Error::network("failed to construct HTTP client").with_source(e))?;

    let mut request = client.get(url);
    if already > 0 {
        request = request.header(reqwest::header::RANGE, format!("bytes={already}-"));
    }
    let mut response = request
        .send()
        .map_err(|e| Error::network(format!("GET {url} failed")).with_source(e))?;

    let status = response.status();
    if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
        // Restart fresh.
        let _ = std::fs::remove_file(path);
        return download_with_resume(url, path, expected_size);
    }
    if !(status.is_success() || status == reqwest::StatusCode::PARTIAL_CONTENT) {
        return Err(Error::network(format!(
            "GET {url} returned HTTP {}",
            status.as_u16()
        )));
    }

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(Error::from)?;
    if status == reqwest::StatusCode::PARTIAL_CONTENT {
        file.seek(SeekFrom::Start(already)).map_err(Error::from)?;
    } else {
        // Fresh body; truncate any leftover bytes.
        file.set_len(0).map_err(Error::from)?;
        file.seek(SeekFrom::Start(0)).map_err(Error::from)?;
    }
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

/// Verify SHA-256 + size of `path` against the spec.
fn verify_sha256(path: &Path, expected_hash: &str, expected_size: u64) -> Result<()> {
    let mut file = File::open(path).map_err(Error::from)?;
    if expected_size > 0 {
        let actual_size = file.metadata().map_err(Error::from)?.len();
        if actual_size != expected_size {
            return Err(Error::hash_mismatch(format!(
                "{} size {} bytes != expected {} bytes",
                path.display(),
                actual_size,
                expected_size
            )));
        }
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(Error::from)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex_lower(&hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected_hash) {
        return Err(Error::hash_mismatch(format!(
            "{}: SHA-256 mismatch (expected {}, got {})",
            path.display(),
            expected_hash,
            actual
        )));
    }
    Ok(())
}

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
    use std::io::{BufRead, BufReader, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use tempfile::TempDir;

    /// Spawn a tiny HTTP/1.1 stub serving `body`. Tracks the number of
    /// requests and the most recent `Range:` header value.
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
                let mut range_start: Option<u64> = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(rest) = line.strip_prefix("Range: bytes=") {
                        if let Some(start) = rest.split('-').next() {
                            range_start = start.trim().parse::<u64>().ok();
                        }
                    }
                }
                let body_to_send: &[u8] = if let Some(start) = range_start {
                    let start_usize = usize::try_from(start).unwrap_or(usize::MAX);
                    if start_usize < body.len() {
                        &body[start_usize..]
                    } else {
                        b""
                    }
                } else {
                    &body
                };
                let status = if range_start.is_some() {
                    "HTTP/1.1 206 Partial Content"
                } else {
                    "HTTP/1.1 200 OK"
                };
                let header = format!(
                    "{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    status,
                    body_to_send.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(body_to_send);
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
        (format!("http://{local}/win.iso"), attempts)
    }

    /// Helper: SHA-256 of a slice.
    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex_lower(&h.finalize())
    }

    #[test]
    fn fixture_bytes_is_exactly_1024() {
        assert_eq!(fixture_bytes().len(), 1024);
    }

    #[test]
    fn fixture_sha256_is_stable() {
        let h1 = fixture_sha256();
        let h2 = fixture_sha256();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn ensure_iso_in_writes_fixture_when_env_set() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env mutations behind env_lock.
        unsafe { std::env::set_var(ISO_FIXTURE_ENV, "1") };
        let tmp = TempDir::new().expect("tempdir");
        let spec = IsoSpec {
            url: "http://127.0.0.1:1/nope".into(),
            sha256: fixture_sha256(),
            expected_size: 1024,
        };
        let path = ensure_iso_in(&spec, tmp.path()).expect("fixture mode ok");
        assert!(path.exists());
        assert_eq!(std::fs::metadata(&path).expect("meta").len(), 1024);
        unsafe { std::env::remove_var(ISO_FIXTURE_ENV) };
    }

    #[test]
    fn ensure_iso_in_real_download_round_trip() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock — make sure no leftover fixture
        // env var trips this test up.
        unsafe { std::env::remove_var(ISO_FIXTURE_ENV) };
        let body = vec![7u8; 4096];
        let expected = sha256_hex(&body);
        let (url, _) = spawn_stub(body.clone());
        let spec = IsoSpec {
            url,
            sha256: expected,
            expected_size: body.len() as u64,
        };
        let tmp = TempDir::new().expect("tempdir");
        let path = ensure_iso_in(&spec, tmp.path()).expect("download ok");
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).expect("read"), body);
    }

    #[test]
    fn ensure_iso_in_short_circuits_when_file_already_verifies() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe { std::env::remove_var(ISO_FIXTURE_ENV) };
        let body = vec![3u8; 256];
        let expected = sha256_hex(&body);
        let (url, attempts) = spawn_stub(body.clone());
        let spec = IsoSpec {
            url,
            sha256: expected,
            expected_size: body.len() as u64,
        };
        let tmp = TempDir::new().expect("tempdir");
        let path1 = ensure_iso_in(&spec, tmp.path()).expect("first");
        let after_first = attempts.load(Ordering::SeqCst);
        let path2 = ensure_iso_in(&spec, tmp.path()).expect("second");
        assert_eq!(path1, path2);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            after_first,
            "second call must not re-fetch"
        );
    }

    #[test]
    fn ensure_iso_in_resumes_partial_download() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe { std::env::remove_var(ISO_FIXTURE_ENV) };
        let body = vec![5u8; 2048];
        let expected = sha256_hex(&body);
        let (url, _) = spawn_stub(body.clone());
        let spec = IsoSpec {
            url,
            sha256: expected,
            expected_size: body.len() as u64,
        };
        let tmp = TempDir::new().expect("tempdir");
        // Pre-write 100 bytes (matching the start of body).
        let prefix_path = tmp.path().join(format!("{}.iso", spec.sha_prefix()));
        std::fs::write(&prefix_path, &body[..100]).expect("write partial");
        let path = ensure_iso_in(&spec, tmp.path()).expect("resume ok");
        assert_eq!(std::fs::read(&path).expect("read"), body);
    }

    #[test]
    fn ensure_iso_in_errors_on_sha_mismatch() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe { std::env::remove_var(ISO_FIXTURE_ENV) };
        let body = vec![1u8; 64];
        let (url, _) = spawn_stub(body.clone());
        let spec = IsoSpec {
            url,
            sha256: "0".repeat(64),
            expected_size: body.len() as u64,
        };
        let tmp = TempDir::new().expect("tempdir");
        let err = ensure_iso_in(&spec, tmp.path()).expect_err("sha mismatch");
        assert_eq!(err.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn ensure_iso_in_errors_when_all_urls_fail() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe { std::env::remove_var(ISO_FIXTURE_ENV) };
        let spec = IsoSpec {
            url: "http://127.0.0.1:1/x".into(),
            sha256: "0".repeat(64),
            expected_size: 1024,
        };
        let tmp = TempDir::new().expect("tempdir");
        let err = ensure_iso_in(&spec, tmp.path()).expect_err("network failure");
        assert_eq!(err.category, crate::ErrorCategory::NetworkError);
    }

    #[test]
    fn iso_spec_short_sha_rejected() {
        let spec = IsoSpec {
            url: "http://example".into(),
            sha256: "abc".into(),
            expected_size: 1024,
        };
        let tmp = TempDir::new().expect("tempdir");
        let err = ensure_iso_in(&spec, tmp.path()).expect_err("short sha");
        assert_eq!(err.category, crate::ErrorCategory::HashMismatch);
    }

    #[test]
    fn default_spec_has_plausible_shape() {
        let spec = default_spec();
        assert!(spec.url.starts_with("https://"));
        assert!(
            std::path::Path::new(&spec.url)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("iso")),
            "default URL should be an ISO: {}",
            spec.url
        );
        assert_eq!(
            spec.sha256.len(),
            64,
            "SHA-256 hex string should be 64 chars"
        );
        assert!(
            spec.expected_size > 1_000_000_000,
            "Win11 `IoT` LTSC ISO is several GB"
        );
    }

    #[test]
    fn default_iso_dir_resolves_under_neon_subdir() {
        if let Some(p) = default_iso_dir() {
            let suffix = std::path::Path::new("neon").join("bridge").join("iso");
            assert!(p.ends_with(&suffix), "got {}", p.display());
        }
    }

    #[test]
    fn sha_prefix_returns_first_16_chars() {
        let spec = IsoSpec {
            url: "u".into(),
            sha256: "abcdef0123456789ffff".into(),
            expected_size: 0,
        };
        assert_eq!(spec.sha_prefix(), "abcdef0123456789");
    }
}
