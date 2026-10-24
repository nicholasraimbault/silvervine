//! Exercise replacement of a running Windows executable without network access
//! or changes to an actual installation, Startup folder, or update receipt.
#![cfg(windows)]

use std::{fs, process::Command};

#[test]
fn windows_update_replaces_a_mapped_executable_and_recovers_failed_installs() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("fake_updater.rs");
    fs::write(&source, r#"
        use std::{env, fs};
        fn main() {
            fs::write(env::var_os("TEST_UPDATE_ARGUMENTS").unwrap(), env::args().skip(1).collect::<Vec<_>>().join(" ")).unwrap();
            let target = env::current_exe().unwrap().parent().unwrap().join("silvervine.exe");
            match env::var("TEST_UPDATE_MODE").unwrap().as_str() {
                "noop" => println!("already up to date"),
                "fail" => { fs::write(target, b"incomplete installation").unwrap(); eprintln!("simulated failure"); std::process::exit(1); }
                _ => { fs::copy(env::var_os("TEST_UPDATE_SOURCE").unwrap(), target).unwrap(); println!("new release 2.3.0-rc.2 installed"); }
            }
        }
    "#).unwrap();
    let helper = temporary.path().join("fake-updater.exe");
    let compiled = Command::new("rustc")
        .args(["--crate-name", "fake_updater", "--edition", "2021"])
        .arg(&source)
        .arg("-o")
        .arg(&helper)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");

    for (mode, channel) in [
        ("install", "preview"),
        ("noop", "stable"),
        ("fail", "preview"),
    ] {
        let install = temporary
            .path()
            .join(format!("installation with spaces {mode}"));
        fs::create_dir(&install).unwrap();
        let executable = install.join("silvervine.exe");
        fs::copy(env!("CARGO_BIN_EXE_silvervine"), &executable).unwrap();
        fs::copy(&helper, install.join("silvervine-update.exe")).unwrap();
        let config = install.join("config");
        fs::create_dir_all(config.join("silvervine")).unwrap();
        fs::write(config.join("silvervine/silvervine-receipt.json"), "{}").unwrap();
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
            .env("TEST_UPDATE_ARGUMENTS", &arguments)
            .output()
            .unwrap();
        assert_eq!(
            result.status.success(),
            mode != "fail",
            "{mode}: {result:?}"
        );
        assert_eq!(
            fs::read_to_string(arguments).unwrap(),
            if channel == "preview" {
                "--prerelease"
            } else {
                ""
            }
        );
        if mode != "fail" {
            let outcome: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(outcome["updated"], mode == "install");
        }
        // Both a no-op and a partial failed install must restore the original;
        // a successful install must leave the replacement runnable in place.
        let version = Command::new(&executable).arg("--version").output().unwrap();
        assert!(version.status.success(), "{mode}: {version:?}");
        assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")));
    }
}
