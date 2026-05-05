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

/// V3-Phase C: with the feature on, `neon stream --help` succeeds and
/// lists the new subcommand group (init, status, start, stop, repair,
/// uninstall, license).
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
    for sub in &[
        "init",
        "status",
        "start",
        "stop",
        "repair",
        "uninstall",
        "license",
    ] {
        assert!(
            stdout.contains(sub),
            "neon stream --help should list `{sub}`; got: {stdout}"
        );
    }
}

/// V3-Phase D: `neon stream start <url>` against a fresh host
/// (without `bridge.toml`) surfaces the "run `neon stream init`
/// first" remediation. We point `XDG_CONFIG_HOME` at an empty tempdir
/// to guarantee no `bridge.toml` is found regardless of the runner's
/// real `~/.config`.
#[cfg(feature = "experimental-bridge")]
#[test]
fn stream_start_without_bridge_toml_suggests_init() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let bin = env!("CARGO_BIN_EXE_neon");
    let output = Command::new(bin)
        .args(["stream", "start", "https://example.com"])
        .env("XDG_CONFIG_HOME", tmp.path())
        .output()
        .expect("spawn neon binary");
    assert!(
        !output.status.success(),
        "stream start without bridge.toml must exit non-zero (status was {:?})",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bridge.toml") || stderr.contains("neon stream init"),
        "expected bridge.toml not-found remediation; got: {stderr}"
    );
}

/// V3-Phase C: `neon stream init` runs end-to-end under per-step NOOP
/// env vars. The provision flow under `NEON_TEST_PROVISION_NOOP=1`
/// returns success without spawning any libvirt or downloads. We
/// also redirect XDG_CONFIG_HOME so the bridge.toml save lands in a
/// tempdir.
#[cfg(feature = "experimental-bridge")]
#[test]
fn stream_init_under_provision_noop_succeeds() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let bin = env!("CARGO_BIN_EXE_neon");
    let output = Command::new(bin)
        .args(["stream", "init", "--accept-eval"])
        .env("NEON_TEST_PROVISION_NOOP", "1")
        .env("NEON_TEST_CAPS_NOOP", "1")
        .env("XDG_CONFIG_HOME", tmp.path())
        .output()
        .expect("spawn neon binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Either the capability check passes or fails on this host — both
    // are acceptable. We only assert the binary runs without panicking
    // and either prints success or surfaces a categorized error.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        output.status.success() || combined.contains("capability gate FAILED"),
        "expected success or remediation; got status {:?} combined={combined}",
        output.status
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
