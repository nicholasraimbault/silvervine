//! Regression tests for the supported release CLI surface.

use std::process::{Command, Output};

use tempfile::TempDir;

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
        "silvervine 2.0.0"
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

#[cfg(unix)]
#[test]
fn rollback_json_stdout_is_exactly_one_document() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let cache = tmp.path().join("cache/silvervine/widevine");
    std::fs::create_dir_all(cache.join("1.0")).unwrap();
    std::fs::create_dir_all(cache.join("2.0")).unwrap();
    symlink("2.0", cache.join("current")).unwrap();
    symlink("1.0", cache.join("previous")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_silvervine"))
        .env("HOME", tmp.path().join("home"))
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
