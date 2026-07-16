#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

use tempfile::TempDir;

fn command_with_roots(tmp: &TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_silvervine"));
    command
        .env("HOME", tmp.path().join("home"))
        .env("XDG_CONFIG_HOME", tmp.path().join("config"))
        .env("XDG_CACHE_HOME", tmp.path().join("cache"))
        .env("SILVERVINE_TEST_LIFECYCLE_NOOP", "1")
        .env_remove("SILVERVINE_TEST_DATA_MIGRATION_NOOP");
    command
}

#[test]
fn normal_binary_startup_migrates_neon_data_before_command() {
    let tmp = TempDir::new().unwrap();
    let legacy_config = tmp.path().join("config/neon");
    let legacy_cache = tmp.path().join("cache/neon");
    std::fs::create_dir_all(&legacy_config).unwrap();
    std::fs::create_dir_all(&legacy_cache).unwrap();
    std::fs::write(legacy_config.join("config.toml"), "[notifications]\n").unwrap();
    std::fs::write(legacy_cache.join("marker"), "legacy cache").unwrap();

    let output = command_with_roots(&tmp)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(tmp.path().join("config/silvervine/config.toml").is_file());
    assert!(tmp.path().join("cache/silvervine/marker").is_file());
    assert!(!legacy_config.exists());
    assert!(!legacy_cache.exists());
}

#[test]
fn startup_fails_when_legacy_daemon_cannot_be_stopped() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let legacy_service = tmp.path().join("config/systemd/user/neon.service");
    let legacy_cache = tmp.path().join("cache/neon");
    std::fs::create_dir_all(legacy_service.parent().unwrap()).unwrap();
    std::fs::create_dir_all(&legacy_cache).unwrap();
    std::fs::write(&legacy_service, "legacy service").unwrap();
    std::fs::write(legacy_cache.join("marker"), "must stay").unwrap();
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let systemctl = bin.join("systemctl");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\ncase \"$*\" in\n  *\"show --property ActiveState\"*) echo active; exit 0;;\n  *\"show --property UnitFileState\"*) echo enabled; exit 0;;\nesac\necho stop failed >&2\nexit 1\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&systemctl).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&systemctl, permissions).unwrap();

    let output = command_with_roots(&tmp)
        .env_remove("SILVERVINE_TEST_LIFECYCLE_NOOP")
        .env("PATH", &bin)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("stop failed"));
    assert!(legacy_service.is_file());
    assert!(legacy_cache.join("marker").is_file());
}

#[test]
fn legacy_registration_is_replaced_only_after_successful_migration() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let legacy_service = tmp.path().join("config/systemd/user/neon.service");
    std::fs::create_dir_all(legacy_service.parent().unwrap()).unwrap();
    std::fs::write(&legacy_service, "legacy service").unwrap();
    std::fs::create_dir_all(tmp.path().join("config/neon")).unwrap();
    std::fs::write(tmp.path().join("config/neon/marker"), "legacy").unwrap();
    let calls = tmp.path().join("systemctl-calls");
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let systemctl = bin.join("systemctl");
    std::fs::write(
        &systemctl,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\ncase \"$*\" in\n  *\"show --property ActiveState\"*) echo active;;\n  *\"show --property UnitFileState\"*) echo enabled;;\nesac\nexit 0\n",
            calls.display()
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&systemctl).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&systemctl, permissions).unwrap();

    let output = command_with_roots(&tmp)
        .env_remove("SILVERVINE_TEST_LIFECYCLE_NOOP")
        .env("PATH", &bin)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!legacy_service.exists());
    assert!(tmp
        .path()
        .join("config/systemd/user/silvervine.service")
        .is_file());
    assert!(tmp.path().join("config/silvervine/marker").is_file());
    let calls = std::fs::read_to_string(calls).unwrap();
    assert!(calls.contains("stop neon.service"));
    assert!(calls.contains("enable --now silvervine.service"));
    assert!(calls.contains("disable --now neon.service"));
}

#[test]
fn new_registration_failure_rolls_back_data_and_restarts_neon() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let legacy_service = tmp.path().join("config/systemd/user/neon.service");
    std::fs::create_dir_all(legacy_service.parent().unwrap()).unwrap();
    std::fs::write(&legacy_service, "legacy service").unwrap();
    std::fs::create_dir_all(tmp.path().join("config/neon")).unwrap();
    std::fs::create_dir_all(tmp.path().join("cache/neon")).unwrap();
    std::fs::write(tmp.path().join("config/neon/marker"), "config").unwrap();
    std::fs::write(tmp.path().join("cache/neon/marker"), "cache").unwrap();
    let calls = tmp.path().join("systemctl-calls");
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let systemctl = bin.join("systemctl");
    std::fs::write(
        &systemctl,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\ncase \"$*\" in\n  *\"show --property ActiveState\"*) echo active; exit 0;;\n  *\"show --property UnitFileState\"*) echo enabled; exit 0;;\n  *\"enable --now silvervine.service\"*) exit 1;;\nesac\nexit 0\n",
            calls.display()
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&systemctl).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&systemctl, permissions).unwrap();

    let output = command_with_roots(&tmp)
        .env_remove("SILVERVINE_TEST_LIFECYCLE_NOOP")
        .env("PATH", &bin)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(legacy_service.is_file());
    assert!(tmp.path().join("config/neon/marker").is_file());
    assert!(tmp.path().join("cache/neon/marker").is_file());
    assert!(!tmp.path().join("config/silvervine").exists());
    assert!(!tmp.path().join("cache/silvervine").exists());
    assert!(!tmp
        .path()
        .join("config/systemd/user/silvervine.service")
        .exists());
    assert!(std::fs::read_to_string(calls)
        .unwrap()
        .contains("start neon.service"));
}

#[test]
fn retirement_failure_unregisters_silvervine_and_restores_neon_data() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let legacy_service = tmp.path().join("config/systemd/user/neon.service");
    std::fs::create_dir_all(legacy_service.parent().unwrap()).unwrap();
    std::fs::write(&legacy_service, "legacy service").unwrap();
    std::fs::create_dir_all(tmp.path().join("config/neon")).unwrap();
    std::fs::create_dir_all(tmp.path().join("cache/neon")).unwrap();
    std::fs::write(tmp.path().join("config/neon/marker"), "config").unwrap();
    std::fs::write(tmp.path().join("cache/neon/marker"), "cache").unwrap();
    let calls = tmp.path().join("systemctl-calls");
    let failed_once = tmp.path().join("failed-once");
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let systemctl = bin.join("systemctl");
    std::fs::write(
        &systemctl,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\ncase \"$*\" in\n  *\"show --property ActiveState\"*) echo active; exit 0;;\n  *\"show --property UnitFileState\"*) echo enabled; exit 0;;\n  *\"disable --now neon.service\"*) if [ ! -e '{}' ]; then : > '{}'; exit 1; fi;;\nesac\nexit 0\n",
            calls.display(), failed_once.display(), failed_once.display()
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&systemctl).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&systemctl, permissions).unwrap();

    let output = command_with_roots(&tmp)
        .env_remove("SILVERVINE_TEST_LIFECYCLE_NOOP")
        .env("PATH", &bin)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(legacy_service.is_file());
    assert!(tmp.path().join("config/neon/marker").is_file());
    assert!(tmp.path().join("cache/neon/marker").is_file());
    assert!(!tmp.path().join("config/silvervine").exists());
    assert!(!tmp.path().join("cache/silvervine").exists());
    assert!(!tmp
        .path()
        .join("config/systemd/user/silvervine.service")
        .exists());
    let calls = std::fs::read_to_string(calls).unwrap();
    assert!(calls.contains("disable --now silvervine.service"));
    assert!(calls.contains("start neon.service"));
}

#[test]
fn failed_migration_does_not_start_previously_inactive_neon() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let legacy_service = tmp.path().join("config/systemd/user/neon.service");
    std::fs::create_dir_all(legacy_service.parent().unwrap()).unwrap();
    std::fs::write(&legacy_service, "legacy service").unwrap();
    std::fs::create_dir_all(tmp.path().join("config/neon")).unwrap();
    std::fs::write(tmp.path().join("config/neon/marker"), "config").unwrap();
    let calls = tmp.path().join("systemctl-calls");
    let bin = tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let systemctl = bin.join("systemctl");
    std::fs::write(
        &systemctl,
        format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\ncase \"$*\" in\n  *\"show --property ActiveState\"*) echo inactive; exit 0;;\n  *\"show --property UnitFileState\"*) echo enabled; exit 0;;\n  *\"enable --now silvervine.service\"*) exit 1;;\nesac\nexit 0\n",
            calls.display()
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&systemctl).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&systemctl, permissions).unwrap();

    let output = command_with_roots(&tmp)
        .env_remove("SILVERVINE_TEST_LIFECYCLE_NOOP")
        .env("PATH", &bin)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(tmp.path().join("config/neon/marker").is_file());
    let calls = std::fs::read_to_string(calls).unwrap();
    assert!(!calls
        .lines()
        .any(|line| line.ends_with("start neon.service")));
}

#[test]
fn startup_fails_when_data_migration_errors() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("config")).unwrap();
    std::fs::write(tmp.path().join("config/neon"), "not a directory").unwrap();

    let output = command_with_roots(&tmp)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source is not a directory"));
    assert!(tmp.path().join("config/neon").is_file());
}

#[test]
fn startup_refuses_connectable_unregistered_legacy_socket() {
    let tmp = TempDir::new().unwrap();
    let legacy_cache = tmp.path().join("cache/neon");
    std::fs::create_dir_all(&legacy_cache).unwrap();
    std::fs::write(legacy_cache.join("marker"), "must stay").unwrap();
    let _listener =
        std::os::unix::net::UnixListener::bind(legacy_cache.join("daemon.sock")).unwrap();

    let output = command_with_roots(&tmp)
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("still reachable"));
    assert!(legacy_cache.join("marker").is_file());
    assert!(!tmp.path().join("cache/silvervine").exists());
}

#[test]
fn concurrent_first_launch_is_serialized_and_both_processes_succeed() {
    for iteration in 0..12 {
        let tmp = TempDir::new().unwrap();
        let legacy_config = tmp.path().join("config/neon");
        let legacy_cache = tmp.path().join("cache/neon");
        std::fs::create_dir_all(&legacy_config).unwrap();
        std::fs::create_dir_all(&legacy_cache).unwrap();
        std::fs::write(legacy_config.join("marker"), "config").unwrap();
        std::fs::write(legacy_cache.join("marker"), "cache").unwrap();

        let mut first = command_with_roots(&tmp);
        first.args(["completion", "bash"]).stdout(Stdio::null());
        let mut second = command_with_roots(&tmp);
        second.args(["completion", "bash"]).stdout(Stdio::null());
        let first = first.spawn().unwrap();
        let second = second.spawn().unwrap();
        let first = first.wait_with_output().unwrap();
        let second = second.wait_with_output().unwrap();
        assert!(
            first.status.success() && second.status.success(),
            "iteration {iteration}: first={} {:?}, second={} {:?}",
            first.status,
            String::from_utf8_lossy(&first.stderr),
            second.status,
            String::from_utf8_lossy(&second.stderr)
        );
        assert!(tmp.path().join("config/silvervine/marker").is_file());
        assert!(tmp.path().join("cache/silvervine/marker").is_file());
    }
}
