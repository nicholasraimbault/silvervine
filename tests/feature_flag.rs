//! Integration tests for V3-Phase A scaffolding's
//! `experimental-bridge` Cargo feature.
//!
//! Build-matrix verification (feature off vs. feature on) is the
//! responsibility of CI; this file instead asserts on runtime / API
//! behaviour:
//!
//! * `LocalFileCdm` is `Box<dyn CdmProvider>`-safe (compile-time).
//! * `LocalFileCdm::populate` round-trips a synthesized cache directory.
//! * Under `--features experimental-bridge`: the binary's `stream`
//!   subcommand exits non-zero with a stub-error message containing
//!   "V3" and "ROADMAP".
//! * Under default features: the binary's `--help` does not list
//!   `stream` (no feature → no subcommand emitted).

use std::path::Path;
use std::process::Command;

use neon::widevine::provider::{CdmProvider, LocalFileCdm};

/// `LocalFileCdm` is object-safe (i.e. `Box<dyn CdmProvider>` compiles).
///
/// If [`CdmProvider`] grows a non-object-safe method (generic, `Self`,
/// etc.), this test fails to compile.
#[test]
fn local_file_cdm_is_box_dyn_safe() {
    let p: Box<dyn CdmProvider> = Box::new(LocalFileCdm::new(
        "9.9.9".into(),
        Path::new("/tmp").to_path_buf(),
    ));
    assert_eq!(p.version(), "9.9.9");
    assert!(p.sha512_hex().is_none());
}

/// `LocalFileCdm::populate` round-trips a synthesized cache directory:
/// build a fake `<dir>/manifest.json` + `_platform_specific/.../libwidevinecdm.so`
/// in a tempdir, populate into a second tempdir, verify both files
/// arrived intact.
#[test]
fn local_file_cdm_populate_round_trips() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let src = tmp.path().join("source-cache");
    let plat = src.join("_platform_specific").join("linux_x64");
    std::fs::create_dir_all(&plat).expect("mkdir source");
    std::fs::write(src.join("manifest.json"), br#"{"version":"4.10.0"}"#).expect("write manifest");
    std::fs::write(plat.join("libwidevinecdm.so"), b"\x7fELF-stub").expect("write so");

    let dest = tmp.path().join("dest");
    let provider = LocalFileCdm::new("4.10.0".into(), src);
    provider.populate(&dest).expect("populate ok");

    assert_eq!(
        std::fs::read(dest.join("manifest.json")).expect("read manifest"),
        br#"{"version":"4.10.0"}"#
    );
    let dest_so = dest
        .join("_platform_specific")
        .join("linux_x64")
        .join("libwidevinecdm.so");
    assert!(dest_so.exists(), "CDM .so did not round-trip");
    assert_eq!(std::fs::read(&dest_so).expect("read so"), b"\x7fELF-stub");
}

/// V3-Phase A: with the `experimental-bridge` feature on, invoking
/// `neon stream <url>` exits with a non-zero status and prints a
/// stub-error message that mentions V3 and ROADMAP.
///
/// Compiled only under `--features experimental-bridge`. The binary
/// path is provided by Cargo at build time via
/// `env!("CARGO_BIN_EXE_neon")`, which guarantees the binary was built
/// with the same feature set as this test.
#[cfg(feature = "experimental-bridge")]
#[test]
fn stream_subcommand_returns_stub_error() {
    let bin = env!("CARGO_BIN_EXE_neon");
    let output = Command::new(bin)
        .args(["stream", "https://example.com"])
        .output()
        .expect("spawn neon binary");
    assert!(
        !output.status.success(),
        "stream stub must exit non-zero (status was {:?})",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("V3"),
        "stub error must mention V3; got: {stderr}"
    );
    assert!(
        stderr.contains("ROADMAP"),
        "stub error must point at ROADMAP; got: {stderr}"
    );
}

/// V3-Phase A: with the feature on, `neon stream --help` succeeds —
/// the subcommand is visible.
///
/// Compiled only under `--features experimental-bridge`.
#[cfg(feature = "experimental-bridge")]
#[test]
fn stream_subcommand_help_succeeds_with_feature_on() {
    let bin = env!("CARGO_BIN_EXE_neon");
    let output = Command::new(bin)
        .args(["stream", "--help"])
        .output()
        .expect("spawn neon binary");
    assert!(
        output.status.success(),
        "neon stream --help must succeed when feature is on"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("URL"),
        "stream --help should describe the URL argument; got: {stdout}"
    );
}

/// V3-Phase A: with the feature **off**, `neon --help` does not list
/// `stream` (feature gating means the variant is absent).
///
/// Only compiled when the feature is off. Inverse of the feature-on
/// help test above.
#[cfg(not(feature = "experimental-bridge"))]
#[test]
fn stream_subcommand_absent_with_feature_off() {
    let bin = env!("CARGO_BIN_EXE_neon");
    let output = Command::new(bin)
        .args(["--help"])
        .output()
        .expect("spawn neon binary");
    assert!(
        output.status.success(),
        "neon --help must succeed (default features)"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The `stream` subcommand should not appear when the feature is off.
    // We check for the line-prefix to avoid spurious matches against e.g.
    // unrelated documentation text.
    assert!(
        !stdout.contains("stream "),
        "neon --help unexpectedly lists `stream` without the feature flag; got: {stdout}"
    );
}
