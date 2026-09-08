use super::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};
use tempfile::TempDir;

fn elevator_output(raw_status: i32, stderr: &str) -> Output {
    Output {
        status: ExitStatus::from_raw(raw_status),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

/// Elevator mock that reports success without touching the filesystem.
fn elevator_success_noop(_script: &str) -> Output {
    elevator_output(0, "")
}

/// Elevator mock that reports a nonzero exit without deleting anything.
fn elevator_nonzero(_script: &str) -> Output {
    elevator_output(256, "permission denied by policy")
}

/// Elevator mock that deletes every quoted path in the script, then
/// returns success — simulates a real elevated `rm` without shelling out.
fn elevator_success_deleting(script: &str) -> Output {
    for segment in script.split('\'') {
        // sh_quote wraps paths in single quotes; odd-indexed split
        // pieces are the quoted contents (with `'\''` already expanded
        // away for simple temp paths without embedded quotes).
        let path = Path::new(segment);
        if path.is_absolute() && path.exists() {
            let _ = fs::remove_file(path);
            let _ = fs::remove_dir_all(path);
        }
    }
    elevator_output(0, "")
}

fn elevated_artifact_paths(install: &LegacyInstall) -> Vec<PathBuf> {
    install
        .artifacts
        .iter()
        .filter(|art| {
            !art.package_managed
                && matches!(
                    art.kind,
                    LegacyKind::MacLaunchDaemon
                        | LegacyKind::LinuxSystemdPath
                        | LegacyKind::LinuxSystemdService
                )
        })
        .map(|art| art.path.clone())
        .collect()
}

fn data_paths(tmp: &Path) -> DataMigrationPaths {
    DataMigrationPaths {
        config: (tmp.join("config/neon"), tmp.join("config/silvervine")),
        cache: (tmp.join("cache/neon"), tmp.join("cache/silvervine")),
        logs: Some((tmp.join("logs/neon"), tmp.join("logs/silvervine"))),
    }
}

#[test]
fn v2_data_migration_atomically_moves_all_directories() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    for (from, marker) in [
        (&paths.config.0, "config.toml"),
        (&paths.cache.0, "widevine/marker"),
        (&paths.logs.as_ref().unwrap().0, "silvervine.log"),
    ] {
        fs::create_dir_all(from.join(Path::new(marker).parent().unwrap())).unwrap();
        fs::write(from.join(marker), b"data").unwrap();
    }

    let result = migrate_v2_data_with(&paths);
    assert!(result
        .iter()
        .all(|entry| entry.status == DataMigrationStatus::Migrated));
    assert!(paths.config.1.join("config.toml").is_file());
    assert!(paths.cache.1.join("widevine/marker").is_file());
    assert!(paths
        .logs
        .as_ref()
        .unwrap()
        .1
        .join("silvervine.log")
        .is_file());
    assert!(!paths.config.0.exists());
    assert!(!paths.cache.0.exists());
}

#[test]
fn v2_data_migration_is_idempotent_when_sources_are_missing() {
    let tmp = TempDir::new().unwrap();
    let result = migrate_v2_data_with(&data_paths(tmp.path()));
    assert!(result
        .iter()
        .all(|entry| entry.status == DataMigrationStatus::MissingSource));
}

#[test]
fn v2_data_migration_preserves_both_sides_on_conflict() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    fs::create_dir_all(&paths.config.0).unwrap();
    fs::create_dir_all(&paths.config.1).unwrap();
    fs::write(paths.config.0.join("old"), b"old").unwrap();
    fs::write(paths.config.1.join("new"), b"new").unwrap();

    let result = migrate_v2_data_with(&paths);
    let config = result.iter().find(|entry| entry.kind == "config").unwrap();
    assert_eq!(config.status, DataMigrationStatus::Conflict);
    assert!(paths.config.0.join("old").is_file());
    assert!(paths.config.1.join("new").is_file());
}

#[test]
fn v2_data_migration_race_preserves_destination_and_source() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    fs::create_dir_all(&paths.config.0).unwrap();
    fs::write(paths.config.0.join("old"), b"old").unwrap();

    let result = migrate_v2_data_with_promoter(&paths, |from, to| {
        if from == paths.config.0 && to == paths.config.1 {
            fs::create_dir_all(to)?;
            fs::write(to.join("racer"), b"new")?;
        }
        no_replace_rename(from, to)
    });

    let config = result.iter().find(|entry| entry.kind == "config").unwrap();
    assert_eq!(config.status, DataMigrationStatus::Conflict);
    assert_eq!(fs::read(paths.config.0.join("old")).unwrap(), b"old");
    assert_eq!(fs::read(paths.config.1.join("racer")).unwrap(), b"new");
}

#[test]
fn v2_data_migration_reports_errors_without_removing_source() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    fs::create_dir_all(paths.config.0.parent().unwrap()).unwrap();
    fs::write(&paths.config.0, b"not a directory").unwrap();

    let result = migrate_v2_data_with(&paths);
    let config = result.iter().find(|entry| entry.kind == "config").unwrap();
    assert!(matches!(config.status, DataMigrationStatus::Error(_)));
    assert!(paths.config.0.is_file());
    assert!(!paths.config.1.exists());
}

/// Build a fully-synthesized legacy install under `tmp` and return
/// the [`FsRoots`] that points at it.
fn synthesize_full_legacy(tmp: &Path) -> FsRoots {
    // System-side artifacts under `tmp/system/`.
    let system_root = tmp.join("system");
    fs::create_dir_all(system_root.join("Library/LaunchDaemons")).unwrap();
    fs::create_dir_all(system_root.join("etc/systemd/system")).unwrap();
    fs::create_dir_all(system_root.join("usr/lib/neon")).unwrap();
    fs::write(
        system_root.join("Library/LaunchDaemons/com.neon.fix-drm.plist"),
        b"<plist></plist>",
    )
    .unwrap();
    fs::write(
        system_root.join("etc/systemd/system/neon-fix-drm.path"),
        b"[Path]\n",
    )
    .unwrap();
    fs::write(
        system_root.join("etc/systemd/system/neon-fix-drm.service"),
        b"[Service]\n",
    )
    .unwrap();
    // The .deb package install dir is just an empty directory.
    // Already created by the create_dir_all above.

    // User-side artifacts under `tmp/home/`.
    let home = tmp.join("home");
    fs::create_dir_all(home.join("Library/LaunchAgents")).unwrap();
    fs::create_dir_all(home.join(".config/autostart")).unwrap();
    fs::create_dir_all(home.join(".local/share/WidevineCdm/4.10.0.0")).unwrap();
    fs::write(
        home.join("Library/LaunchAgents/com.neon.app.plist"),
        b"<plist></plist>",
    )
    .unwrap();
    fs::write(
        home.join(".config/autostart/neon.desktop"),
        b"[Desktop Entry]\n",
    )
    .unwrap();
    fs::write(
        home.join(".local/share/WidevineCdm/4.10.0.0/libwidevinecdm.so"),
        b"fake",
    )
    .unwrap();

    FsRoots {
        system_root,
        home: Some(home),
    }
}

#[test]
fn detect_finds_every_artifact_in_synthesized_install() {
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    let install = detect_legacy_install_in(&roots);
    assert!(!install.is_empty());
    assert_eq!(install.len(), 7);
    let kinds: Vec<LegacyKind> = install.artifacts.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&LegacyKind::MacLaunchDaemon));
    assert!(kinds.contains(&LegacyKind::MacLaunchAgent));
    assert!(kinds.contains(&LegacyKind::LinuxSystemdPath));
    assert!(kinds.contains(&LegacyKind::LinuxSystemdService));
    assert!(kinds.contains(&LegacyKind::LinuxAutostart));
    assert!(kinds.contains(&LegacyKind::LinuxLegacyCdmCache));
    assert!(kinds.contains(&LegacyKind::LinuxDebPackage));
    assert!(install.needs_root());
}

#[test]
fn detect_returns_empty_for_clean_host() {
    let tmp = TempDir::new().unwrap();
    let roots = FsRoots {
        system_root: tmp.path().join("clean-system"),
        home: Some(tmp.path().join("clean-home")),
    };
    // The roots don't exist; detection finds nothing.
    let install = detect_legacy_install_in(&roots);
    assert!(install.is_empty());
    assert!(!install.needs_root());
}

#[test]
fn detect_handles_missing_home() {
    let tmp = TempDir::new().unwrap();
    let roots = FsRoots {
        system_root: tmp.path().to_path_buf(),
        home: None,
    };
    // Without home, only system artifacts can surface.
    let install = detect_legacy_install_in(&roots);
    for a in &install.artifacts {
        assert!(
            matches!(
                a.kind,
                LegacyKind::MacLaunchDaemon
                    | LegacyKind::LinuxSystemdPath
                    | LegacyKind::LinuxSystemdService
                    | LegacyKind::LinuxDebPackage
            ),
            "no user-domain artifacts when home=None"
        );
    }
}

/// When the elevator fails (e.g. user cancels the sudo prompt),
/// elevated artifacts must land in `outcome.skipped` with a reason
/// — NOT in `outcome.removed` (which would falsely tell the user
/// the artifact had been cleaned up when it's still on disk).
#[test]
fn elevator_failure_routes_paths_to_skipped_not_removed() {
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    let install = detect_legacy_install_in(&roots);
    let elevated = elevated_artifact_paths(&install);
    let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");
    // Elevator always fails — simulates the user dismissing the
    // sudo / pkexec / osascript prompt.
    let elevator = |_script: &str| -> Result<Output> {
        Err(crate::error::Error::permission_denied(
            "user cancelled the prompt",
        ))
    };
    let outcome = remove_legacy_with_elevator(install, &cdm_dest, &elevator).expect("returns Ok");

    for path in &elevated {
        assert!(
            !outcome.removed.iter().any(|p| p == path),
            "cancelled elevation must not report removed: {}",
            path.display()
        );
        assert!(
            path.exists(),
            "cancelled elevation must leave artifact on disk: {}",
            path.display()
        );
        let skipped = outcome
            .skipped
            .iter()
            .find(|s| &s.path == path)
            .unwrap_or_else(|| panic!("expected skipped entry for {}", path.display()));
        assert!(
            skipped.reason.contains("elevated cleanup failed"),
            "skipped reason should mention the elevation failure; got {}",
            skipped.reason
        );
        assert!(
            skipped.reason.contains("user cancelled the prompt"),
            "skipped reason should carry the cancel detail; got {}",
            skipped.reason
        );
    }

    // User-level work must still proceed after elevation cancel.
    let home = roots.home.as_ref().unwrap();
    assert!(!home
        .join("Library/LaunchAgents/com.neon.app.plist")
        .exists());
    assert!(!home.join(".config/autostart/neon.desktop").exists());
    assert!(cdm_dest.exists());
}

/// A spawned elevator that exits nonzero is not legacy removal.
#[test]
fn elevator_nonzero_exit_routes_paths_to_skipped_not_removed() {
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    let install = detect_legacy_install_in(&roots);
    let elevated = elevated_artifact_paths(&install);
    let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");

    let elevator = |script: &str| -> Result<Output> { Ok(elevator_nonzero(script)) };
    let outcome = remove_legacy_with_elevator(install, &cdm_dest, &elevator).expect("returns Ok");

    for path in &elevated {
        assert!(
            !outcome.removed.iter().any(|p| p == path),
            "nonzero elevator exit must not report removed: {}",
            path.display()
        );
        assert!(path.exists(), "artifact must remain: {}", path.display());
        let skipped = outcome
            .skipped
            .iter()
            .find(|s| &s.path == path)
            .unwrap_or_else(|| panic!("expected skipped entry for {}", path.display()));
        assert!(
            skipped.reason.contains("elevated cleanup failed"),
            "got {}",
            skipped.reason
        );
        assert!(
            skipped.reason.contains("exit 1"),
            "reason should include exit status; got {}",
            skipped.reason
        );
        assert!(
            skipped.reason.contains("permission denied by policy"),
            "reason should include stderr; got {}",
            skipped.reason
        );
    }

    // Pass 2 still runs.
    let home = roots.home.as_ref().unwrap();
    assert!(!home.join(".config/autostart/neon.desktop").exists());
    assert!(cdm_dest.exists());
}

/// Successful elevation status alone is insufficient: paths that remain
/// on disk after the elevator returns must not be reported as removed.
#[test]
fn elevator_success_without_postcondition_routes_to_skipped() {
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    let install = detect_legacy_install_in(&roots);
    let elevated = elevated_artifact_paths(&install);
    let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");

    let elevator = |script: &str| -> Result<Output> { Ok(elevator_success_noop(script)) };
    let outcome = remove_legacy_with_elevator(install, &cdm_dest, &elevator).expect("returns Ok");

    for path in &elevated {
        assert!(
            !outcome.removed.iter().any(|p| p == path),
            "spawn success without removal must not report removed: {}",
            path.display()
        );
        assert!(path.exists(), "artifact must remain: {}", path.display());
        let skipped = outcome
            .skipped
            .iter()
            .find(|s| &s.path == path)
            .unwrap_or_else(|| panic!("expected skipped entry for {}", path.display()));
        assert_eq!(
            skipped.reason, "elevated cleanup left artifact in place",
            "postcondition mismatch reason; got {}",
            skipped.reason
        );
    }
}

#[test]
fn elevator_success_does_not_report_a_dangling_symlink_removed() {
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    let install = detect_legacy_install_in(&roots);
    let path = elevated_artifact_paths(&install)
        .into_iter()
        .next()
        .expect("elevated artifact");
    fs::remove_file(&path).expect("replace artifact");
    symlink("missing-target", &path).expect("create dangling symlink");
    let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");
    let elevator = |script: &str| -> Result<Output> { Ok(elevator_success_noop(script)) };

    let outcome = remove_legacy_with_elevator(install, &cdm_dest, &elevator).expect("returns Ok");

    assert!(!outcome.removed.contains(&path));
    let skipped = outcome
        .skipped
        .iter()
        .find(|entry| entry.path == path)
        .expect("dangling symlink must remain skipped");
    assert_eq!(skipped.reason, "elevated cleanup left artifact in place");
    assert!(fs::symlink_metadata(&path).is_ok());
}

/// Success requires both a successful elevator exit and the expected
/// filesystem postcondition for each elevated artifact.
#[test]
fn elevator_success_with_postcondition_reports_removed() {
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    let install = detect_legacy_install_in(&roots);
    let elevated = elevated_artifact_paths(&install);
    let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");

    let elevator = |script: &str| -> Result<Output> { Ok(elevator_success_deleting(script)) };
    let outcome = remove_legacy_with_elevator(install, &cdm_dest, &elevator).expect("returns Ok");

    for path in &elevated {
        assert!(
            outcome.removed.iter().any(|p| p == path),
            "verified removal must report removed: {}; removed={:?}",
            path.display(),
            outcome.removed
        );
        assert!(
            !path.exists(),
            "verified removal must delete artifact: {}",
            path.display()
        );
        assert!(
            !outcome.skipped.iter().any(|s| &s.path == path),
            "verified removal must not also skip: {}",
            path.display()
        );
    }

    // User-level migration still runs alongside verified elevated cleanup.
    let home = roots.home.as_ref().unwrap();
    assert!(!home
        .join("Library/LaunchAgents/com.neon.app.plist")
        .exists());
    assert!(!home.join(".config/autostart/neon.desktop").exists());
    assert!(cdm_dest.join("4.10.0.0/libwidevinecdm.so").exists());
    assert!(!home.join(".local/share/WidevineCdm").exists());
    assert!(outcome
        .skipped
        .iter()
        .any(|s| s.path.ends_with("usr/lib/neon")));
    assert!(!outcome.migrated.is_empty());
}

/// `remove_legacy_with` under NOOP elevation still performs user-level
/// cleanup. Elevated paths stay on disk and must not be claimed removed
/// merely because the elevator short-circuited with a successful status.
#[test]
fn remove_legacy_under_noop_short_circuit() {
    let _guard = crate::test_support::env_lock();
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    // SAFETY: env mutations happen in serial test threads; we
    // restore at end-of-test.
    unsafe { std::env::set_var("SILVERVINE_TEST_ESCALATE_NOOP", "1") };
    let install = detect_legacy_install_in(&roots);
    let elevated = elevated_artifact_paths(&install);
    let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");
    let outcome = remove_legacy_with(install, &cdm_dest).expect("ok");

    // User-side artifacts were removed:
    let home = roots.home.as_ref().unwrap();
    assert!(!home
        .join("Library/LaunchAgents/com.neon.app.plist")
        .exists());
    assert!(!home.join(".config/autostart/neon.desktop").exists());

    // The legacy CDM cache was migrated to the V2 destination.
    assert!(cdm_dest.exists());
    assert!(cdm_dest.join("4.10.0.0/libwidevinecdm.so").exists());
    assert!(!home.join(".local/share/WidevineCdm").exists());

    // The .deb package install was reported as skipped.
    assert!(outcome
        .skipped
        .iter()
        .any(|s| s.path.ends_with("usr/lib/neon")));

    // NOOP elevation returns success without deleting system artifacts.
    // Those paths must be skipped for postcondition mismatch — never
    // falsely listed under `removed`.
    for path in &elevated {
        assert!(
            path.exists(),
            "NOOP elevator must leave elevated artifact: {}",
            path.display()
        );
        assert!(
            !outcome.removed.iter().any(|p| p == path),
            "NOOP elevator must not report removed: {}",
            path.display()
        );
        let skipped = outcome
            .skipped
            .iter()
            .find(|s| &s.path == path)
            .unwrap_or_else(|| panic!("expected skipped entry for {}", path.display()));
        assert_eq!(
            skipped.reason, "elevated cleanup left artifact in place",
            "got {}",
            skipped.reason
        );
    }
    assert!(!outcome.migrated.is_empty());

    unsafe { std::env::remove_var("SILVERVINE_TEST_ESCALATE_NOOP") };
}

#[test]
fn remove_legacy_drops_redundant_cdm_when_v2_cache_exists() {
    let _guard = crate::test_support::env_lock();
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    // Pre-create the V2 destination so migrate_legacy_cdm sees it.
    let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");
    fs::create_dir_all(&cdm_dest).unwrap();
    fs::write(cdm_dest.join("v2-marker"), b"v2").unwrap();

    unsafe { std::env::set_var("SILVERVINE_TEST_ESCALATE_NOOP", "1") };
    let install = detect_legacy_install_in(&roots);
    let outcome = remove_legacy_with(install, &cdm_dest).expect("ok");
    unsafe { std::env::remove_var("SILVERVINE_TEST_ESCALATE_NOOP") };

    // Legacy CDM cache is gone; v2 marker is intact.
    let home = roots.home.as_ref().unwrap();
    assert!(!home.join(".local/share/WidevineCdm").exists());
    assert!(cdm_dest.join("v2-marker").exists());
    // It's reported as skipped (with the "v2 cache exists" reason).
    let skip = outcome
        .skipped
        .iter()
        .find(|s| s.path.ends_with(".local/share/WidevineCdm"))
        .expect("skipped entry");
    assert!(skip.reason.contains("V2"));
}

#[test]
fn legacy_cdm_destination_lives_under_silvervine_cache() {
    let p = legacy_cdm_destination();
    assert!(p.ends_with("widevine/legacy"), "{}", p.display());
    let parent = p.parent().expect("has parent").parent().expect("has gp");
    assert!(parent.ends_with("silvervine"));
}

#[test]
fn legacy_kind_as_str_is_stable() {
    // Stable strings used in logs.
    assert_eq!(LegacyKind::MacLaunchDaemon.as_str(), "MacLaunchDaemon");
    assert_eq!(format!("{}", LegacyKind::MacLaunchAgent), "MacLaunchAgent");
    assert_eq!(LegacyKind::LinuxSystemdPath.as_str(), "LinuxSystemdPath");
    assert_eq!(
        LegacyKind::LinuxSystemdService.as_str(),
        "LinuxSystemdService"
    );
    assert_eq!(LegacyKind::LinuxAutostart.as_str(), "LinuxAutostart");
    assert_eq!(
        LegacyKind::LinuxLegacyCdmCache.as_str(),
        "LinuxLegacyCdmCache"
    );
    assert_eq!(LegacyKind::LinuxDebPackage.as_str(), "LinuxDebPackage");
}

#[test]
fn legacy_install_default_is_empty() {
    let li = LegacyInstall::default();
    assert!(li.is_empty());
    assert_eq!(li.len(), 0);
    assert!(!li.needs_root());
}

#[test]
fn fs_roots_host_returns_some_home_on_dev_machines() {
    // dirs::home_dir() returns Some() on every CI / dev system; the
    // call should not panic.
    let r = FsRoots::host();
    assert_eq!(r.system_root, PathBuf::from("/"));
    // home is Some(...) on systems with $HOME set.
    let _ = r.home; // tolerate either branch
}

/// `remove_user_path` returns an error when the path doesn't exist.
#[test]
fn remove_user_path_errors_on_missing_path() {
    let tmp = TempDir::new().unwrap();
    let mut out = MigrationOutcome::default();
    let r = remove_user_path(&tmp.path().join("nope"), &mut out);
    assert!(r.is_err());
}

#[test]
fn migrate_legacy_cdm_creates_parent_dir() {
    let tmp = TempDir::new().unwrap();
    let legacy = tmp.path().join("legacy");
    fs::create_dir_all(&legacy).unwrap();
    fs::write(legacy.join("file"), b"x").unwrap();
    let dest = tmp.path().join("a/b/c/widevine/legacy");
    let mut out = MigrationOutcome::default();
    migrate_legacy_cdm(&legacy, &dest, &mut out).expect("ok");
    assert!(dest.exists());
    assert!(dest.join("file").exists());
    assert_eq!(out.migrated.len(), 1);
}

/// `detect_legacy_install()` (public host-tied entry) must not panic
/// regardless of host state. On a dev machine with no legacy install,
/// it returns an empty list; on a machine with legacy artifacts, it
/// returns whatever's there. Either way: no panic.
#[test]
fn detect_legacy_install_does_not_panic() {
    let _ = detect_legacy_install();
}

/// `remove_legacy(empty)` succeeds with no work. Useful sanity check
/// for callers that always run migration regardless of detection.
#[test]
fn remove_legacy_empty_install_is_noop() {
    let outcome = remove_legacy(LegacyInstall::default()).expect("ok");
    assert!(outcome.removed.is_empty());
    assert!(outcome.migrated.is_empty());
    assert!(outcome.skipped.is_empty());
}

/// `migrate_legacy_cdm` returns an error when `rename` fails (here,
/// because the source doesn't exist).
#[test]
fn migrate_legacy_cdm_errors_when_source_missing() {
    let tmp = TempDir::new().unwrap();
    let legacy = tmp.path().join("not-here");
    let dest = tmp.path().join("dest/widevine");
    let mut out = MigrationOutcome::default();
    let r = migrate_legacy_cdm(&legacy, &dest, &mut out);
    assert!(r.is_err());
}

/// `unload_and_remove_user` removes a plist successfully even when
/// `launchctl` isn't available (common on Linux CI runners).
#[test]
fn unload_and_remove_user_removes_plist() {
    let tmp = TempDir::new().unwrap();
    let plist = tmp.path().join("com.example.plist");
    fs::write(&plist, b"<plist></plist>").unwrap();
    let mut out = MigrationOutcome::default();
    unload_and_remove_user(&plist, &mut out).expect("ok");
    assert!(!plist.exists());
    assert_eq!(out.removed.len(), 1);
}

// --- Packaged-install detection (AUR / RPM systemd units in /usr/lib) ---

#[test]
fn detect_finds_systemd_units_in_usr_lib_systemd() {
    let tmp = TempDir::new().unwrap();
    let system_root = tmp.path().to_path_buf();
    fs::create_dir_all(system_root.join("usr/lib/systemd/system")).unwrap();
    fs::write(
        system_root.join("usr/lib/systemd/system/neon-fix-drm.path"),
        b"[Path]\n",
    )
    .unwrap();
    fs::write(
        system_root.join("usr/lib/systemd/system/neon-fix-drm.service"),
        b"[Service]\n",
    )
    .unwrap();
    let roots = FsRoots {
        system_root,
        home: None,
    };
    let install = detect_legacy_install_in(&roots);
    let kinds: Vec<LegacyKind> = install.artifacts.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&LegacyKind::LinuxSystemdPath), "{kinds:?}");
    assert!(
        kinds.contains(&LegacyKind::LinuxSystemdService),
        "{kinds:?}"
    );
    // Units under /usr/lib are package-managed — removal must defer
    // to the package manager rather than `rm`.
    for art in &install.artifacts {
        if matches!(
            art.kind,
            LegacyKind::LinuxSystemdPath | LegacyKind::LinuxSystemdService
        ) {
            assert!(
                art.package_managed,
                "{:?} at {} should be flagged package_managed",
                art.kind,
                art.path.display()
            );
        }
    }
}

#[test]
fn detect_finds_systemd_units_in_lib_systemd() {
    let tmp = TempDir::new().unwrap();
    let system_root = tmp.path().to_path_buf();
    fs::create_dir_all(system_root.join("lib/systemd/system")).unwrap();
    fs::write(
        system_root.join("lib/systemd/system/neon-fix-drm.path"),
        b"[Path]\n",
    )
    .unwrap();
    let roots = FsRoots {
        system_root,
        home: None,
    };
    let install = detect_legacy_install_in(&roots);
    let kinds: Vec<LegacyKind> = install.artifacts.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&LegacyKind::LinuxSystemdPath), "{kinds:?}");
}

#[test]
fn migration_summary_renders_counts_only_when_clean() {
    let outcome = MigrationOutcome::default();
    let mut buf = Vec::new();
    write_migration_summary(&mut buf, &outcome).expect("write ok");
    let s = std::str::from_utf8(&buf).unwrap();
    assert!(s.contains("removed=0 migrated=0 skipped=0"), "got: {s}");
    assert!(
        !s.contains("→"),
        "no skip-hint arrow without skips, got: {s}"
    );
}

#[test]
fn migration_summary_dedupes_repeated_skip_reasons() {
    // Realistic AUR case: three paths skipped, all under the same
    // pacman uninstall hint. The summary should show the hint once,
    // not three times.
    let reason = "packaged install — run `pacman -R neon-drm` to remove";
    let outcome = MigrationOutcome {
        removed: vec![],
        migrated: vec![],
        skipped: vec![
            SkipReason {
                path: PathBuf::from("/usr/lib/systemd/system/neon-fix-drm.path"),
                reason: reason.into(),
            },
            SkipReason {
                path: PathBuf::from("/usr/lib/systemd/system/neon-fix-drm.service"),
                reason: reason.into(),
            },
            SkipReason {
                path: PathBuf::from("/usr/lib/neon"),
                reason: reason.into(),
            },
        ],
    };
    let mut buf = Vec::new();
    write_migration_summary(&mut buf, &outcome).expect("write ok");
    let s = std::str::from_utf8(&buf).unwrap();
    assert!(s.contains("skipped=3"), "got: {s}");
    assert_eq!(
        s.matches("pacman -R neon-drm").count(),
        1,
        "skip hint should be deduplicated, got: {s}"
    );
}

#[test]
fn migration_summary_lists_distinct_skip_reasons() {
    let outcome = MigrationOutcome {
        removed: vec![],
        migrated: vec![],
        skipped: vec![
            SkipReason {
                path: PathBuf::from("/a"),
                reason: "reason A".into(),
            },
            SkipReason {
                path: PathBuf::from("/b"),
                reason: "reason B".into(),
            },
        ],
    };
    let mut buf = Vec::new();
    write_migration_summary(&mut buf, &outcome).expect("write ok");
    let s = std::str::from_utf8(&buf).unwrap();
    assert!(s.contains("reason A"), "got: {s}");
    assert!(s.contains("reason B"), "got: {s}");
}

#[cfg(unix)]
#[test]
fn detect_dedupes_units_under_merged_usr_symlink() {
    // Reproduce the Arch / Fedora "merged usr" layout where `/lib`
    // is a symlink to `/usr/lib`. Both
    //   <root>/usr/lib/systemd/system/neon-fix-drm.path
    //   <root>/lib/systemd/system/neon-fix-drm.path
    // resolve to the same file. The detector must report it once.
    let tmp = TempDir::new().unwrap();
    let system_root = tmp.path().to_path_buf();
    fs::create_dir_all(system_root.join("usr/lib/systemd/system")).unwrap();
    fs::write(
        system_root.join("usr/lib/systemd/system/neon-fix-drm.path"),
        b"[Path]\n",
    )
    .unwrap();
    fs::write(
        system_root.join("usr/lib/systemd/system/neon-fix-drm.service"),
        b"[Service]\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(system_root.join("usr/lib"), system_root.join("lib")).unwrap();

    let roots = FsRoots {
        system_root,
        home: None,
    };
    let install = detect_legacy_install_in(&roots);
    let path_count = install
        .artifacts
        .iter()
        .filter(|a| a.kind == LegacyKind::LinuxSystemdPath)
        .count();
    let service_count = install
        .artifacts
        .iter()
        .filter(|a| a.kind == LegacyKind::LinuxSystemdService)
        .count();
    assert_eq!(path_count, 1, "merged-usr should yield one path unit");
    assert_eq!(service_count, 1, "merged-usr should yield one service unit");
}

#[test]
fn etc_systemd_units_are_not_package_managed() {
    let tmp = TempDir::new().unwrap();
    let roots = synthesize_full_legacy(tmp.path());
    let install = detect_legacy_install_in(&roots);
    for art in &install.artifacts {
        if matches!(
            art.kind,
            LegacyKind::LinuxSystemdPath | LegacyKind::LinuxSystemdService
        ) {
            assert!(
                !art.package_managed,
                "/etc/-housed unit at {} must not be package_managed",
                art.path.display()
            );
        }
    }
}

// --- /etc/os-release -> PackageManager detection ---

fn write_os_release(system_root: &Path, body: &[u8]) {
    fs::create_dir_all(system_root.join("etc")).unwrap();
    fs::write(system_root.join("etc/os-release"), body).unwrap();
}

#[test]
fn detect_package_manager_pacman_from_id() {
    let tmp = TempDir::new().unwrap();
    write_os_release(tmp.path(), b"ID=arch\n");
    let roots = FsRoots {
        system_root: tmp.path().to_path_buf(),
        home: None,
    };
    assert_eq!(detect_package_manager_in(&roots), PackageManager::Pacman);
}

#[test]
fn detect_package_manager_pacman_via_id_like() {
    let tmp = TempDir::new().unwrap();
    write_os_release(tmp.path(), b"ID=cachyos\nID_LIKE=arch\n");
    let roots = FsRoots {
        system_root: tmp.path().to_path_buf(),
        home: None,
    };
    assert_eq!(detect_package_manager_in(&roots), PackageManager::Pacman);
}

#[test]
fn detect_package_manager_dpkg_from_id_like() {
    let tmp = TempDir::new().unwrap();
    write_os_release(tmp.path(), b"ID=ubuntu\nID_LIKE=debian\n");
    let roots = FsRoots {
        system_root: tmp.path().to_path_buf(),
        home: None,
    };
    assert_eq!(detect_package_manager_in(&roots), PackageManager::Dpkg);
}

#[test]
fn detect_package_manager_rpm_from_id() {
    let tmp = TempDir::new().unwrap();
    write_os_release(tmp.path(), b"ID=fedora\n");
    let roots = FsRoots {
        system_root: tmp.path().to_path_buf(),
        home: None,
    };
    assert_eq!(detect_package_manager_in(&roots), PackageManager::Rpm);
}

#[test]
fn detect_package_manager_unknown_without_os_release() {
    let tmp = TempDir::new().unwrap();
    let roots = FsRoots {
        system_root: tmp.path().to_path_buf(),
        home: None,
    };
    assert_eq!(detect_package_manager_in(&roots), PackageManager::Unknown);
}

#[test]
fn detect_package_manager_handles_quoted_values() {
    let tmp = TempDir::new().unwrap();
    write_os_release(tmp.path(), b"ID=\"arch\"\nID_LIKE=\"\"\n");
    let roots = FsRoots {
        system_root: tmp.path().to_path_buf(),
        home: None,
    };
    assert_eq!(detect_package_manager_in(&roots), PackageManager::Pacman);
}

// --- Uninstall-hint formatting per package manager ---

#[test]
fn uninstall_hint_pacman_mentions_pacman() {
    let h = legacy_package_uninstall_hint(PackageManager::Pacman, "neon-drm");
    assert!(h.contains("pacman -R neon-drm"), "got: {h}");
}

#[test]
fn uninstall_hint_dpkg_mentions_dpkg() {
    let h = legacy_package_uninstall_hint(PackageManager::Dpkg, "neon-drm");
    assert!(h.contains("dpkg -r neon-drm"), "got: {h}");
}

#[test]
fn uninstall_hint_rpm_mentions_rpm_or_dnf() {
    let h = legacy_package_uninstall_hint(PackageManager::Rpm, "neon-drm");
    assert!(
        h.contains("rpm -e neon-drm") || h.contains("dnf remove neon-drm"),
        "got: {h}"
    );
}

#[test]
fn uninstall_hint_unknown_is_generic() {
    let h = legacy_package_uninstall_hint(PackageManager::Unknown, "neon-drm");
    assert!(
        h.to_lowercase().contains("package manager"),
        "expected a generic 'package manager' hint, got: {h}"
    );
}

// --- Integration: packaged systemd units must be skipped, not removed ---

#[test]
fn remove_legacy_skips_package_managed_units_with_pacman_hint() {
    let _guard = crate::test_support::env_lock();
    let tmp = TempDir::new().unwrap();
    let system_root = tmp.path().join("system");
    fs::create_dir_all(system_root.join("usr/lib/systemd/system")).unwrap();
    fs::create_dir_all(system_root.join("usr/lib/neon")).unwrap();
    fs::write(
        system_root.join("usr/lib/systemd/system/neon-fix-drm.path"),
        b"[Path]\n",
    )
    .unwrap();
    fs::write(
        system_root.join("usr/lib/systemd/system/neon-fix-drm.service"),
        b"[Service]\n",
    )
    .unwrap();
    write_os_release(&system_root, b"ID=arch\n");
    let roots = FsRoots {
        system_root,
        home: None,
    };

    unsafe { std::env::set_var("SILVERVINE_TEST_ESCALATE_NOOP", "1") };
    let install = detect_legacy_install_in(&roots);
    assert_eq!(install.package_manager, PackageManager::Pacman);
    let cdm_dest = tmp.path().join("v2-cache/widevine/legacy");
    let outcome = remove_legacy_with(install, &cdm_dest).expect("ok");
    unsafe { std::env::remove_var("SILVERVINE_TEST_ESCALATE_NOOP") };

    // Units under /usr/lib are reported as skipped with a pacman hint.
    let unit_skips: Vec<&SkipReason> = outcome
        .skipped
        .iter()
        .filter(|s| {
            s.path.ends_with("neon-fix-drm.path") || s.path.ends_with("neon-fix-drm.service")
        })
        .collect();
    assert_eq!(unit_skips.len(), 2, "skipped={:?}", outcome.skipped);
    for u in &unit_skips {
        assert!(u.reason.contains("pacman -R neon-drm"), "got: {}", u.reason);
    }
    // /usr/lib/neon/ also gets the pacman-flavored hint.
    let pkg_skip = outcome
        .skipped
        .iter()
        .find(|s| s.path.ends_with("usr/lib/neon"))
        .expect("usr/lib/neon entry");
    assert!(
        pkg_skip.reason.contains("pacman -R neon-drm"),
        "got: {}",
        pkg_skip.reason
    );
    // Packaged units must NOT be in `removed` (we deferred to pacman).
    for p in &outcome.removed {
        assert!(
            !p.starts_with(roots.system_root.join("usr/lib")),
            "packaged unit {} should not be in removed",
            p.display()
        );
    }
}

#[derive(Default)]
struct MockLegacyLifecycle {
    registered: bool,
    running: bool,
    failures: Vec<&'static str>,
    calls: Vec<&'static str>,
}

impl LegacyLifecycle for MockLegacyLifecycle {
    fn is_registered(&mut self) -> Result<bool> {
        self.calls.push("probe");
        Ok(self.registered)
    }
    fn silvervine_is_registered(&mut self) -> Result<bool> {
        self.calls.push("silvervine-probe");
        Ok(false)
    }
    fn stop(&mut self) -> Result<bool> {
        self.calls.push("stop");
        Ok(self.running)
    }
    fn restore(&mut self, was_running: bool) -> Result<()> {
        self.calls.push(if was_running {
            "restore-running"
        } else {
            "restore-inactive"
        });
        Ok(())
    }
    fn register_silvervine(&mut self) -> Result<()> {
        self.calls.push("register");
        if self.failures.contains(&"register") {
            Err(Error::other("new registration failed"))
        } else {
            Ok(())
        }
    }
    fn unregister_silvervine(&mut self) -> Result<()> {
        self.calls.push("unregister");
        if self.failures.contains(&"unregister") {
            Err(Error::other("new unregistration failed"))
        } else {
            Ok(())
        }
    }
    fn remove_registration(&mut self) -> Result<()> {
        self.calls.push("remove");
        if self.failures.contains(&"retire") {
            Err(Error::other("legacy retirement failed"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn startup_without_legacy_registration_migrates_without_registering() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    fs::create_dir_all(&paths.config.0).unwrap();
    fs::write(paths.config.0.join("marker"), b"config").unwrap();
    let mut lifecycle = MockLegacyLifecycle::default();
    startup_transaction(&paths, &mut lifecycle).unwrap();
    assert!(paths.config.1.join("marker").is_file());
    assert_eq!(lifecycle.calls, ["probe"]);
}

#[test]
fn registration_failure_rolls_back_all_moves_and_restarts_neon() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    for from in [&paths.config.0, &paths.cache.0] {
        fs::create_dir_all(from).unwrap();
        fs::write(from.join("marker"), b"legacy").unwrap();
    }
    let mut lifecycle = MockLegacyLifecycle {
        registered: true,
        running: true,
        failures: vec!["register"],
        ..Default::default()
    };
    let result = startup_transaction(&paths, &mut lifecycle);
    assert!(result.is_err());
    assert!(paths.config.0.join("marker").is_file());
    assert!(paths.cache.0.join("marker").is_file());
    assert!(!paths.config.1.exists());
    assert!(!paths.cache.1.exists());
    assert_eq!(
        lifecycle.calls,
        [
            "probe",
            "silvervine-probe",
            "stop",
            "register",
            "unregister",
            "restore-running"
        ]
    );
}

#[test]
fn second_move_failure_rolls_back_first_and_restarts_neon() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    for from in [&paths.config.0, &paths.cache.0] {
        fs::create_dir_all(from).unwrap();
        fs::write(from.join("marker"), b"legacy").unwrap();
    }
    let mut lifecycle = MockLegacyLifecycle {
        registered: true,
        running: true,
        ..Default::default()
    };
    let mut moves = 0;
    let result = startup_transaction_with(&paths, &mut lifecycle, &mut |from, to| {
        moves += 1;
        if moves == 2 {
            Err(std::io::Error::other("injected move failure"))
        } else {
            no_replace_rename(from, to)
        }
    });
    assert!(result.is_err());
    assert!(paths.config.0.join("marker").is_file());
    assert!(paths.cache.0.join("marker").is_file());
    assert!(!paths.config.1.exists());
    assert_eq!(
        lifecycle.calls,
        ["probe", "silvervine-probe", "stop", "restore-running"]
    );
}

#[test]
fn enoent_is_peer_completion_only_for_present_destination_directory() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    fs::create_dir_all(&paths.config.0).unwrap();
    let result = migrate_v2_data_with_promoter(&paths, |from, to| {
        if from == paths.config.0 {
            fs::remove_dir_all(from)?;
            fs::create_dir_all(to)?;
        }
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    });
    let config = result.iter().find(|entry| entry.kind == "config").unwrap();
    assert_eq!(config.status, DataMigrationStatus::Migrated);
    let cache = result
        .iter()
        .find(|entry| entry.kind == "cache/log")
        .unwrap();
    assert_eq!(cache.status, DataMigrationStatus::MissingSource);
}

#[test]
fn retirement_failure_unregisters_new_daemon_then_rolls_back_data() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    fs::create_dir_all(&paths.config.0).unwrap();
    fs::write(paths.config.0.join("marker"), b"legacy").unwrap();
    let mut lifecycle = MockLegacyLifecycle {
        registered: true,
        running: true,
        failures: vec!["retire"],
        ..Default::default()
    };

    let error = startup_transaction(&paths, &mut lifecycle).unwrap_err();
    assert!(error.to_string().contains("legacy retirement failed"));
    assert!(paths.config.0.join("marker").is_file());
    assert!(!paths.config.1.exists());
    assert_eq!(
        lifecycle.calls,
        [
            "probe",
            "silvervine-probe",
            "stop",
            "register",
            "remove",
            "unregister",
            "restore-running"
        ]
    );
}

#[test]
fn failed_transaction_does_not_start_previously_inactive_neon() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    fs::create_dir_all(&paths.config.0).unwrap();
    fs::write(paths.config.0.join("marker"), b"legacy").unwrap();
    let mut lifecycle = MockLegacyLifecycle {
        registered: true,
        running: false,
        failures: vec!["register"],
        ..Default::default()
    };

    startup_transaction(&paths, &mut lifecycle).unwrap_err();
    assert_eq!(
        lifecycle.calls,
        [
            "probe",
            "silvervine-probe",
            "stop",
            "register",
            "unregister",
            "restore-inactive"
        ]
    );
}

#[test]
fn retirement_rollback_failure_keeps_migrated_data_for_active_silvervine() {
    let tmp = TempDir::new().unwrap();
    let paths = data_paths(tmp.path());
    fs::create_dir_all(&paths.config.0).unwrap();
    fs::write(paths.config.0.join("marker"), b"legacy").unwrap();
    let mut lifecycle = MockLegacyLifecycle {
        registered: true,
        running: true,
        failures: vec!["retire", "unregister"],
        ..Default::default()
    };

    let error = startup_transaction(&paths, &mut lifecycle).unwrap_err();
    assert!(error.to_string().contains("rollback failed"));
    assert!(!paths.config.0.exists());
    assert!(paths.config.1.join("marker").is_file());
    assert_eq!(
        lifecycle.calls,
        [
            "probe",
            "silvervine-probe",
            "stop",
            "register",
            "remove",
            "unregister"
        ]
    );
}
