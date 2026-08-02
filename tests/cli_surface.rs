//! Regression tests for the supported release CLI surface.

use std::process::{Command, Output};

use silvervine::cli::patch::PatchReport as LegacyPatchReport;
use tempfile::TempDir;

#[test]
fn legacy_patch_report_path_remains_public() {
    assert_eq!(
        std::any::TypeId::of::<LegacyPatchReport>(),
        std::any::TypeId::of::<silvervine::patch::PatchReport>()
    );
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_silvervine"))
        .env("SILVERVINE_TEST_DATA_MIGRATION_NOOP", "1")
        .args(args)
        .output()
        .expect("spawn silvervine binary")
}

fn run_help(args: &[&str]) -> String {
    let output = run(args);
    assert!(output.status.success(), "help command failed: {output:?}");
    String::from_utf8(output.stdout).expect("help output is UTF-8")
}

#[test]
fn binary_reports_silvervine_identity() {
    let version = run(&["--version"]);
    assert!(version.status.success(), "version failed: {version:?}");
    assert_eq!(
        String::from_utf8(version.stdout).unwrap().trim(),
        concat!("silvervine ", env!("CARGO_PKG_VERSION"))
    );
    let help = run_help(&["--help"]);
    assert!(
        help.contains("Usage: silvervine"),
        "unexpected help: {help}"
    );
    assert!(
        !help.contains("Neon"),
        "legacy identity leaked into help: {help}"
    );
}

#[test]
fn root_help_excludes_experimental_stream_command() {
    let help = run_help(&["--help"]);
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("stream ")),
        "release CLI unexpectedly exposes `stream`: {help}"
    );
}

#[test]
fn doctor_help_excludes_experimental_bridge_option() {
    let help = run_help(&["doctor", "--help"]);
    assert!(
        !help.contains("--bridge"),
        "release CLI unexpectedly exposes `doctor --bridge`: {help}"
    );
}

#[test]
fn diagnostics_help_exposes_passive_and_explicit_live_modes() {
    let doctor = run_help(&["doctor", "--help"]);
    assert!(
        doctor.contains("--media-stack"),
        "passive media diagnostics missing from doctor help: {doctor}"
    );
    assert!(
        doctor.contains("--browser"),
        "media-stack browser filter missing from doctor help: {doctor}"
    );

    let test = run_help(&["test", "--help"]);
    assert!(
        test.contains("browser-reported EME capability"),
        "automated EME behavior missing from test help: {test}"
    );
    assert!(
        test.contains("manual test page"),
        "manual --url behavior missing from test help: {test}"
    );
}

#[test]
fn parser_rejects_experimental_stream_command() {
    let output = run(&["stream"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "unexpected result: {output:?}"
    );
}

#[test]
fn parser_rejects_experimental_doctor_bridge_option() {
    let output = run(&["doctor", "--bridge"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "unexpected result: {output:?}"
    );
}

#[test]
fn update_help_excludes_unsigned_self_update() {
    let help = run_help(&["update", "--help"]);
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("self ")),
        "release CLI unexpectedly exposes `update self`: {help}"
    );
}

#[test]
fn parser_rejects_unsigned_self_update() {
    let output = run(&["update", "self"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "unexpected result: {output:?}"
    );
}

#[test]
fn requested_missing_browser_is_an_error_not_empty_success() {
    let output = run(&["patch", "DefinitelyMissingSilvervineBrowser"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("was not found"));
}

#[test]
fn patch_help_exposes_explicit_external_cdm_override() {
    let help = run_help(&["patch", "--help"]);
    assert!(
        help.contains("--replace-external-cdm"),
        "ownership override missing from patch help: {help}"
    );
}

#[test]
fn replace_external_cdm_requires_explicit_browser() {
    let output = run(&["patch", "--replace-external-cdm"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("replace-external-cdm") || stderr.contains("browser"),
        "expected usage/invariant error, got: {stderr}"
    );
}

#[test]
fn malformed_config_is_an_error_not_an_empty_browser_list() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    #[cfg(target_os = "macos")]
    let config = home.join("Library/Application Support/silvervine/config.toml");
    #[cfg(not(target_os = "macos"))]
    let config = tmp.path().join("config/silvervine/config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(&config, "not = [valid toml").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_silvervine"))
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .env("XDG_CACHE_HOME", tmp.path().join("cache"))
        .env("SILVERVINE_TEST_DATA_MIGRATION_NOOP", "1")
        .args(["list-browsers", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("StateCorrupted"));
    assert!(output.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn rollback_json_stdout_is_exactly_one_document() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    #[cfg(target_os = "macos")]
    let cache = home.join("Library/Caches/silvervine/widevine");
    #[cfg(not(target_os = "macos"))]
    let cache = tmp.path().join("cache/silvervine/widevine");
    let previous = cache.join("1.0");
    #[cfg(target_os = "linux")]
    let (platform_dir, library) = ("linux_x64", "libwidevinecdm.so");
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let (platform_dir, library) = ("mac_arm64", "libwidevinecdm.dylib");
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    let (platform_dir, library) = ("mac_x64", "libwidevinecdm.dylib");
    let library_dir = previous.join("_platform_specific").join(platform_dir);
    std::fs::create_dir_all(&library_dir).unwrap();
    std::fs::write(previous.join("manifest.json"), br#"{"version":"1.0"}"#).unwrap();
    let library_bytes = b"fixture";
    std::fs::write(library_dir.join(library), library_bytes).unwrap();
    #[cfg(target_os = "linux")]
    let platform = "linux-x86_64";
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let platform = "darwin-aarch64";
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    let platform = "darwin-x86_64";
    let integrity = serde_json::json!({
        "schema_version": 2,
        "version": "1.0",
        "platform": platform,
        "library_size": library_bytes.len(),
        "library_sha512": silvervine::widevine::sha512_hex(library_bytes),
        "manifest_sha512": silvervine::widevine::sha512_hex(br#"{"version":"1.0"}"#),
    });
    std::fs::write(
        previous.join(".silvervine-integrity.json"),
        serde_json::to_vec(&integrity).unwrap(),
    )
    .unwrap();
    std::fs::create_dir_all(cache.join("2.0")).unwrap();
    symlink("2.0", cache.join("current")).unwrap();
    symlink("1.0", cache.join("previous")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_silvervine"))
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .env("XDG_CACHE_HOME", tmp.path().join("cache"))
        .env("SILVERVINE_TEST_DATA_MIGRATION_NOOP", "1")
        .args(["--json", "update", "widevine", "--rollback"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["current_version"], "1.0");
    assert_eq!(parsed["downloaded"], false);
}

#[test]
fn parser_accepts_doctor_media_stack_and_browser_filter() {
    let output = run(&["doctor", "--media-stack", "--browser", "Chromium", "--help"]);
    // --help always exits 0 after parsing the command path; ensure the options exist.
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

#[test]
fn parser_rejects_doctor_browser_without_media_stack() {
    let output = run(&["doctor", "--browser", "Chromium"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn parser_rejects_doctor_media_stack_with_error_code() {
    let output = run(&["doctor", "--media-stack", "N8156-6024"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn parser_rejects_replace_external_cdm_without_browser() {
    let output = run(&["patch", "--replace-external-cdm"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
}

#[test]
fn passive_media_stack_creates_no_xdg_state() {
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    let root = TempDir::new().expect("tmp");
    let home = root.path().join("home");
    let xdg_config = home.join("config");
    let xdg_cache = home.join("cache");
    let xdg_data = home.join("data");
    let xdg_state = home.join("state");
    for dir in [&xdg_config, &xdg_cache, &xdg_data, &xdg_state] {
        fs::create_dir_all(dir).unwrap();
    }

    let bin = env!("CARGO_BIN_EXE_silvervine");
    let output = Command::new(bin)
        .args(["doctor", "--media-stack", "--json"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg_config)
        .env("XDG_CACHE_HOME", &xdg_cache)
        .env("XDG_DATA_HOME", &xdg_data)
        .env("XDG_STATE_HOME", &xdg_state)
        .output()
        .expect("run doctor");

    assert!(
        output.status.success(),
        "doctor --media-stack failed: status={:?} stderr={} stdout={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    for (label, dir) in [
        ("config", xdg_config.as_path()),
        ("cache", xdg_cache.as_path()),
        ("data", xdg_data.as_path()),
        ("state", xdg_state.as_path()),
    ] {
        let entries: Vec<_> = fs::read_dir(dir)
            .expect("read xdg root")
            .map(|entry| entry.expect("entry").path())
            .collect();
        assert!(
            entries.is_empty(),
            "passive media-stack created {label} paths: {entries:?}"
        );
    }
}
