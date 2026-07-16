//! Integration tests for `browsers::detect_browsers_with` against
//! synthesized Linux + macOS filesystem layouts.
//!
//! These build a temp tree shaped like the real install paths and walk
//! the full detection pipeline (known list + filesystem discovery +
//! custom config), asserting on the merged output.

use std::fs;
use std::path::PathBuf;

use silvervine::browsers::{detect_browsers_with, BrowserKind, FilesystemRoots, Os};
use silvervine::config::{Config, CustomBrowserConfig};
use tempfile::TempDir;

fn make_chrome_sandbox_dir(parent: &std::path::Path, name: &str) -> PathBuf {
    let dir = parent.join(name);
    fs::create_dir_all(&dir).expect("mkdir browser dir");
    fs::write(dir.join("chrome-sandbox"), b"#!/bin/sh\n").expect("touch chrome-sandbox");
    // Real browsers have BOTH chrome-sandbox AND a top-level `chrome` binary
    // (the latter distinguishes them from Electron apps that ship
    // chrome-sandbox but rename their main binary).
    fs::write(dir.join("chrome"), b"\x7fELF").expect("touch chrome binary");
    dir
}

fn make_macos_chrome_app(parent: &std::path::Path, app: &str, framework: &str) -> PathBuf {
    let app_dir = parent.join(format!("{app}.app"));
    fs::create_dir_all(
        app_dir
            .join("Contents")
            .join("Frameworks")
            .join(format!("{framework}.framework"))
            .join("Versions")
            .join("128.0.6613.119"),
    )
    .expect("mkdir framework versions");
    app_dir
}

#[test]
fn linux_full_pipeline_unions_known_detected_and_custom() {
    let tmp = TempDir::new().expect("tempdir");
    // Sandbox-mounted known list lives under <tmp>/opt/...
    let opt_under_sandbox = tmp.path().join("opt");
    fs::create_dir_all(&opt_under_sandbox).expect("mkdir opt");
    let helium_path = make_chrome_sandbox_dir(&opt_under_sandbox, "helium-browser-bin");

    // Auto-discovery walks <tmp>/walk; unknown forks live there.
    let walk = tmp.path().join("walk");
    fs::create_dir_all(&walk).expect("mkdir walk");
    let fork_path = make_chrome_sandbox_dir(&walk, "fork-of-chromium");

    // Custom config points at a third directory that exists nowhere else.
    let custom_path = tmp.path().join("dev-build");
    fs::create_dir_all(&custom_path).expect("mkdir custom");

    let config = Config {
        browsers: vec![CustomBrowserConfig {
            name: "DevBuild".into(),
            bundle_path: None,
            framework_name: None,
            install_path: Some(custom_path.clone()),
        }],
        ..Default::default()
    };
    let roots = FilesystemRoots {
        macos_applications: vec![],
        linux_search: vec![walk.clone()],
        sandbox_root: Some(tmp.path().to_path_buf()),
    };

    let browsers = detect_browsers_with(Os::Linux, &roots, &config);

    let helium = browsers
        .iter()
        .find(|b| b.install_path == helium_path)
        .expect("helium found via known list");
    assert_eq!(helium.name, "Helium");
    assert_eq!(helium.kind, BrowserKind::Known);

    let fork = browsers
        .iter()
        .find(|b| b.install_path == fork_path)
        .expect("fork found via discovery");
    assert_eq!(fork.kind, BrowserKind::Detected);

    let custom = browsers
        .iter()
        .find(|b| b.install_path == custom_path)
        .expect("custom found via config");
    assert_eq!(custom.name, "DevBuild");
    assert_eq!(custom.kind, BrowserKind::Custom);
}

#[test]
fn macos_full_pipeline_finds_apps_in_applications() {
    let tmp = TempDir::new().expect("tempdir");
    let apps = tmp.path().join("Applications");
    fs::create_dir_all(&apps).expect("mkdir apps");
    let helium = make_macos_chrome_app(&apps, "Helium", "Helium Framework");
    let weird = make_macos_chrome_app(&apps, "WeirdChromium", "WeirdChromium Framework");

    let config = Config::default();
    let roots = FilesystemRoots {
        macos_applications: vec![apps],
        linux_search: vec![],
        sandbox_root: None,
    };

    let browsers = detect_browsers_with(Os::Macos, &roots, &config);

    let helium_entry = browsers
        .iter()
        .find(|b| b.name == "Helium")
        .expect("helium");
    assert_eq!(helium_entry.install_path, helium);
    assert_eq!(
        helium_entry.framework_name.as_deref(),
        Some("Helium Framework")
    );
    assert_eq!(helium_entry.kind, BrowserKind::Known);

    let weird_entry = browsers
        .iter()
        .find(|b| b.install_path == weird)
        .expect("weird discovered");
    assert_eq!(weird_entry.kind, BrowserKind::Detected);
}
