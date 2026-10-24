//! Exercise replacement of a running Windows executable without network access
//! or changes to an actual installation, Startup folder, or update receipt.
#![cfg(windows)]

use std::{fs, process::Command};

#[test]
fn windows_update_replaces_a_mapped_executable_and_recovers_failed_installs() {
    let temporary = tempfile::tempdir().unwrap();
    let helper = compile_sidecar(temporary.path());

    for (mode, channel) in [
        ("install", "preview"),
        ("noop", "stable"),
        ("fail", "preview"),
        ("mismatch", "preview"),
    ] {
        let install = temporary
            .path()
            .join(format!("installation with spaces {mode}"));
        fs::create_dir(&install).unwrap();
        let binary_dir = if mode == "noop" {
            install.join("bin")
        } else {
            install.clone()
        };
        fs::create_dir_all(&binary_dir).unwrap();
        let executable = binary_dir.join("silvervine.exe");
        fs::copy(env!("CARGO_BIN_EXE_silvervine"), &executable).unwrap();
        fs::copy(&helper, binary_dir.join("silvervine-update.exe")).unwrap();
        let config = install.join("config");
        fs::create_dir_all(config.join("silvervine")).unwrap();
        let receipt_path = config.join("silvervine/silvervine-receipt.json");
        let prefix = if mode == "mismatch" {
            let other = install.join("other");
            fs::create_dir(&other).unwrap();
            fs::write(other.join("silvervine.exe"), b"other installation").unwrap();
            other
        } else {
            install.clone()
        };
        let layout = if mode == "noop" { "cargo-home" } else { "flat" };
        let receipt = serde_json::to_vec(&serde_json::json!({"install_prefix": prefix, "install_layout": layout, "version": env!("CARGO_PKG_VERSION")})).unwrap();
        fs::write(&receipt_path, &receipt).unwrap();
        let arguments = install.join("arguments.txt");
        let result = Command::new(&executable)
            .args(["--json", "update", "self", "--channel", channel])
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_CACHE_HOME", install.join("cache"))
            .env("SILVERVINE_TEST_DATA_MIGRATION_NOOP", "1")
            .env("SILVERVINE_TEST_LIFECYCLE_NOOP", "1")
            .env_remove("SILVERVINE_TEST_SELF_UPDATE_NOOP")
            .env("TEST_UPDATE_SOURCE", env!("CARGO_BIN_EXE_silvervine"))
            .env("TEST_UPDATE_MODE", mode)
            .env("TEST_UPDATE_RECEIPT", &receipt_path)
            .env("TEST_UPDATE_ARGUMENTS", &arguments)
            .output()
            .unwrap();
        assert_eq!(
            result.status.success(),
            !matches!(mode, "fail" | "mismatch"),
            "{mode}: {result:?}"
        );
        if mode == "mismatch" {
            assert!(
                !arguments.exists(),
                "a mismatched receipt must not invoke the updater"
            );
            assert!(
                String::from_utf8_lossy(&result.stderr).contains("receipt belongs to a different")
            );
        } else {
            assert_eq!(
                fs::read_to_string(arguments).unwrap(),
                if channel == "preview" {
                    "--prerelease"
                } else {
                    ""
                }
            );
        }
        if !matches!(mode, "fail" | "mismatch") {
            let outcome: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(outcome["updated"], mode == "install");
        }
        // Both a no-op and a partial failed install must restore the original;
        // a successful install must leave the replacement runnable in place.
        let version = Command::new(&executable).arg("--version").output().unwrap();
        assert!(version.status.success(), "{mode}: {version:?}");
        assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")));
        if mode != "install" {
            assert_eq!(fs::read(&receipt_path).unwrap(), receipt);
        }
    }
}

fn compile_sidecar(root: &std::path::Path) -> std::path::PathBuf {
    let source = root.join("fake_updater.rs");
    fs::write(&source, r#"
        use std::{env, fs};
        fn main() {
            fs::write(env::var_os("TEST_UPDATE_ARGUMENTS").unwrap(), env::args().skip(1).collect::<Vec<_>>().join(" ")).unwrap();
            let target = env::current_exe().unwrap().parent().unwrap().join("silvervine.exe");
            match env::var("TEST_UPDATE_MODE").unwrap().as_str() {
                "noop" => println!("already up to date"),
                "fail" => { fs::write(target, b"incomplete installation").unwrap(); fs::write(env::var_os("TEST_UPDATE_RECEIPT").unwrap(), b"{\"version\":\"incomplete\"}").unwrap(); eprintln!("simulated failure"); std::process::exit(1); }
                _ => { fs::copy(env::var_os("TEST_UPDATE_SOURCE").unwrap(), target).unwrap(); println!("new release 2.3.0-rc.2 installed"); }
            }
        }
    "#).unwrap();
    let helper = root.join("fake-updater.exe");
    let compiled = Command::new("rustc")
        .args(["--crate-name", "fake_updater", "--edition", "2021"])
        .arg(&source)
        .arg("-o")
        .arg(&helper)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");

    helper
}
