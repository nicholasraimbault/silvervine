#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn privileged_operation_patches_exact_target_without_child_cache_log_or_hooks() {
    let tmp = TempDir::new().unwrap();
    let parent_root = tmp.path().join("parent");
    let child_root = tmp.path().join("child");
    let install = parent_root.join("custom-browser");
    let decoy = parent_root.join("same-display-name-decoy");
    let cdm = parent_root.join("cache/silvervine/widevine/9.8.7.6");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&decoy).unwrap();
    std::fs::write(install.join("browser-marker"), b"exact").unwrap();
    std::fs::write(decoy.join("browser-marker"), b"decoy").unwrap();
    let platform = cdm.join("_platform_specific/linux_x64");
    std::fs::create_dir_all(&platform).unwrap();
    std::fs::write(platform.join("libwidevinecdm.so"), b"verified-cdm").unwrap();
    std::fs::write(cdm.join("manifest.json"), br#"{"version":"9.8.7.6"}"#).unwrap();

    let hook_marker = child_root.join("hook-ran");
    let hook = child_root.join("config/silvervine/hooks/post-patch");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(
        &hook,
        format!("#!/bin/sh\nprintf ran > '{}'\n", hook_marker.display()),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&hook).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&hook, permissions).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_silvervine"))
        .env("HOME", child_root.join("home"))
        .env("XDG_CONFIG_HOME", child_root.join("config"))
        .env("XDG_CACHE_HOME", child_root.join("cache"))
        .args([
            "__privileged-patch",
            "--install-path",
            install.to_str().unwrap(),
            "--backup-parent",
            parent_root.to_str().unwrap(),
            "--cdm-dir",
            cdm.to_str().unwrap(),
            "--cdm-version",
            "9.8.7.6",
            "--browser-name",
            "ParentOnlyCustom",
            "--force",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(install.join("WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so"))
            .unwrap(),
        b"verified-cdm"
    );
    assert!(!decoy.join("WidevineCdm").exists());
    assert!(
        !child_root.join("cache").exists(),
        "child created cache/log data"
    );
    assert!(
        !hook_marker.exists(),
        "privileged child emitted post-patch hook"
    );
}

#[test]
fn privileged_operation_ignores_preplaced_snapshot_symlink() {
    let tmp = TempDir::new().unwrap();
    let parent = tmp.path().join("parent");
    let install = parent.join("custom-browser");
    let cdm = parent.join("cdm");
    let victim = tmp.path().join("victim");
    std::fs::create_dir_all(&install).unwrap();
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(install.join("sensitive"), b"browser content").unwrap();
    std::fs::write(victim.join("sensitive"), b"original victim").unwrap();
    let platform = cdm.join("_platform_specific/linux_x64");
    std::fs::create_dir_all(&platform).unwrap();
    std::fs::write(platform.join("libwidevinecdm.so"), b"verified-cdm").unwrap();
    std::fs::write(cdm.join("manifest.json"), br#"{"version":"1"}"#).unwrap();

    let malicious_root = parent.join(".silvervine-backups");
    std::os::unix::fs::symlink(&victim, &malicious_root).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_silvervine"))
        .args([
            "__privileged-patch",
            "--install-path",
            install.to_str().unwrap(),
            "--backup-parent",
            parent.to_str().unwrap(),
            "--cdm-dir",
            cdm.to_str().unwrap(),
            "--cdm-version",
            "1",
            "--browser-name",
            "Evil",
            "--force",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(victim.join("sensitive")).unwrap(),
        b"original victim"
    );
    assert!(malicious_root.is_symlink());
}

#[test]
fn privileged_operation_rejects_missing_exact_target() {
    let tmp = TempDir::new().unwrap();
    let cdm = tmp.path().join("cdm");
    std::fs::create_dir_all(&cdm).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_silvervine"))
        .args([
            "__privileged-patch",
            "--install-path",
            tmp.path().join("missing").to_str().unwrap(),
            "--backup-parent",
            tmp.path().to_str().unwrap(),
            "--cdm-dir",
            cdm.to_str().unwrap(),
            "--cdm-version",
            "1",
            "--browser-name",
            "Missing",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
