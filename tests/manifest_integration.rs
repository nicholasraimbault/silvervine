//! Integration tests for `widevine::manifest` against the real Mozilla
//! manifest fixture committed in `tests/fixtures/widevinecdm.json`.
//!
//! These run on every `cargo test` (no `--ignored` gate). Fixture tests stay
//! offline; release-build transport-policy tests bind a loopback listener and
//! assert that Silvervine rejects it before dispatch. No test contacts an
//! external network.

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use silvervine::widevine::{
    download_to, fetch_manifest_with, parse_manifest, Platform, PlatformEntry,
};
use silvervine::ErrorCategory;
use tempfile::TempDir;
use url::Url;

fn fixture_bytes() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("widevinecdm.json");
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("could not read manifest fixture at {}: {e}", path.display()))
}

fn spawn_loopback_server(body: Vec<u8>) -> (String, Arc<AtomicUsize>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let attempts = Arc::new(AtomicUsize::new(0));
    let server_attempts = Arc::clone(&attempts);
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(250);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    server_attempts.fetch_add(1, Ordering::SeqCst);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).expect("header");
                    stream.write_all(&body).expect("body");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        }
    });
    (format!("http://{address}/fixture"), attempts, handle)
}

#[test]
fn release_build_rejects_loopback_crx_before_dispatch() {
    let body = b"signed-content-placeholder".to_vec();
    let (url, attempts, server) = spawn_loopback_server(body.clone());
    let entry = PlatformEntry::Concrete {
        file_url: url,
        mirror_urls: vec![],
        filesize: Some(body.len() as u64),
        hash_value: silvervine::widevine::sha512_hex(&body),
    };
    let tmp = TempDir::new().expect("tempdir");

    let error = download_to(&entry, tmp.path()).expect_err("loopback must be rejected");

    assert_eq!(error.category, ErrorCategory::NetworkError);
    server.join().expect("server");
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
}

#[test]
fn release_build_rejects_loopback_manifest_before_dispatch() {
    let (raw_url, attempts, server) = spawn_loopback_server(fixture_bytes());
    let url = Url::parse(&raw_url).expect("URL");

    let error =
        fetch_manifest_with(&[url], None, Duration::ZERO).expect_err("loopback must be rejected");

    assert_eq!(error.category, ErrorCategory::ManifestFetchFailed);
    server.join().expect("server");
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
}

#[test]
fn fixture_resolves_all_supported_platforms() {
    let manifest = parse_manifest(&fixture_bytes()).expect("fixture parses");
    for platform in [
        Platform::LinuxX86_64,
        Platform::DarwinAarch64,
        Platform::DarwinX86_64,
    ] {
        let entry = manifest
            .resolve_platform(platform)
            .unwrap_or_else(|e| panic!("could not resolve {}: {e}", platform.as_str()));
        match entry {
            PlatformEntry::Concrete {
                file_url,
                hash_value,
                filesize,
                ..
            } => {
                assert!(
                    file_url.starts_with("https://"),
                    "platform {} fileUrl is not https: {file_url}",
                    platform.as_str()
                );
                assert_eq!(
                    hash_value.len(),
                    128,
                    "platform {} hash is not 128 hex chars",
                    platform.as_str()
                );
                assert!(
                    filesize.is_some_and(|n| n > 0),
                    "platform {} has zero filesize",
                    platform.as_str()
                );
            }
            PlatformEntry::Alias { alias } => {
                panic!(
                    "expected concrete entry for {}, got alias to {alias}",
                    platform.as_str()
                );
            }
        }
    }
}

#[test]
fn fixture_carries_widevine_version() {
    let manifest = parse_manifest(&fixture_bytes()).expect("fixture parses");
    let vendor = manifest.widevine().expect("vendor entry");
    // The fixture is real Mozilla data; version must be a non-empty
    // dot-separated string of integers (e.g. 4.10.2934.0).
    assert!(!vendor.version.is_empty(), "version must be non-empty");
    let parts: Vec<&str> = vendor.version.split('.').collect();
    assert!(
        parts.len() >= 3,
        "expected dotted version, got {}",
        vendor.version
    );
    for p in parts {
        assert!(
            p.chars().all(|c| c.is_ascii_digit()),
            "version part {p} should be all digits"
        );
    }
}
