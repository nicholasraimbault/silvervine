//! Integration tests for `widevine::manifest` against the real Mozilla
//! manifest fixture committed in `tests/fixtures/widevinecdm.json`.
//!
//! These run on every `cargo test` (no `--ignored` gate) because they
//! don't touch the network — they exercise the parser + resolver against
//! a known-good real-shape input.
//!
//! Tests that hit the network (e.g. live download from `hg.mozilla.org`)
//! are intentionally NOT in this file. Phase 2 will add `--ignored`-gated
//! integration tests for those.

use std::path::PathBuf;

use neon::widevine::{parse_manifest, Platform, PlatformEntry};

fn fixture_bytes() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("widevinecdm.json");
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("could not read manifest fixture at {}: {e}", path.display()))
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
