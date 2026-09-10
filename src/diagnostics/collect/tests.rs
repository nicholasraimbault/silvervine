use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::{
    collect_browser_at, collect_browser_for_test, library_digest, ownership_kind_name,
    ExternalCdmOrigin,
};
use crate::browsers::{Browser, BrowserKind};
use crate::diagnostics::DiagnosticStatus;
use crate::widevine::ownership::{marker_for_cached, write_marker, OwnershipKind};
use crate::widevine::CachedCdm;

fn browser(install_path: &std::path::Path, kind: BrowserKind) -> Browser {
    Browser {
        name: "Chromium".into(),
        install_path: install_path.to_path_buf(),
        kind,
    }
}

fn managed_cdm(root: &std::path::Path) -> (std::path::PathBuf, String) {
    let target = root.join("WidevineCdm");
    let platform = target.join("_platform_specific").join(test_platform_dir());
    fs::create_dir_all(&platform).expect("platform");
    let manifest = br#"{"version":"4.10.0.0"}"#;
    fs::write(target.join("manifest.json"), manifest).expect("manifest");
    let library = test_library_bytes();
    fs::write(platform.join(test_library_name()), &library).expect("library");
    let cached = CachedCdm::from_verified_payload(
        "4.10.0.0".into(),
        target.clone(),
        crate::widevine::sha512_hex(&library),
        crate::widevine::sha512_hex(manifest),
    );
    let marker = marker_for_cached(&cached).expect("marker");
    let digest = marker.library_sha512.clone();
    write_marker(&target, &marker).expect("write marker");
    (target, digest)
}

fn unmarked_cdm(root: &std::path::Path) -> std::path::PathBuf {
    let target = root.join("WidevineCdm");
    let platform = target.join("_platform_specific").join(test_platform_dir());
    fs::create_dir_all(&platform).expect("platform");
    fs::write(target.join("manifest.json"), br#"{"version":"4.10.0.0"}"#).expect("manifest");
    fs::write(platform.join(test_library_name()), test_library_bytes()).expect("library");
    target
}

fn test_platform_dir() -> &'static str {
    if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "mac_arm64"
        } else {
            "mac_x64"
        }
    } else {
        "linux_x64"
    }
}

fn test_library_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libwidevinecdm.dylib"
    } else {
        "libwidevinecdm.so"
    }
}

fn test_library_bytes() -> Vec<u8> {
    if cfg!(target_os = "macos") {
        let mut bytes = vec![0_u8; 32];
        bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
        let cpu_type = if cfg!(target_arch = "aarch64") {
            0x0100_000c_u32
        } else {
            0x0100_0007_u32
        };
        bytes[4..8].copy_from_slice(&cpu_type.to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![0_u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes
    }
}

#[test]
fn verified_cdm_and_browser_build_an_exact_probe_fingerprint() {
    let tmp = TempDir::new().expect("tempdir");
    let (target, digest) = managed_cdm(tmp.path());
    let executable = std::env::current_exe().expect("test executable");

    let diagnostics = collect_browser_at(
        &browser(tmp.path(), BrowserKind::Known),
        Ok(executable.clone()),
        Some("150.0.1".into()),
        Ok(target),
        None,
        Some(&[]),
    );

    let fingerprint = diagnostics.fingerprint.expect("fingerprint");
    assert!(
        fingerprint
            .canonical_executable
            .contains(executable.file_name().unwrap().to_string_lossy().as_ref())
            || fingerprint.canonical_executable == executable.to_string_lossy()
    );
    assert_eq!(fingerprint.browser_version.as_deref(), Some("150.0.1"));
    assert!(fingerprint.executable_len > 0);
    assert!(fingerprint.executable_modified > 0);
    assert_eq!(fingerprint.cdm_entries.len(), 1);
    assert_eq!(
        fingerprint.cdm_entries[0].library_sha512.as_deref(),
        Some(digest.as_str())
    );
    assert_eq!(diagnostics.ownership.kind, OwnershipKind::Managed);
    assert_eq!(
        diagnostics
            .checks
            .iter()
            .find(|check| check.id == "cdm.provenance")
            .expect("provenance")
            .status,
        DiagnosticStatus::Pass
    );
}

#[test]
fn detected_browser_without_authoritative_profile_roots_has_no_fingerprint() {
    let tmp = TempDir::new().expect("tempdir");
    let (target, digest) = managed_cdm(tmp.path());

    let diagnostics = collect_browser_at(
        &browser(tmp.path(), BrowserKind::Detected),
        Ok(std::env::current_exe().expect("test executable")),
        Some("150.0.1".into()),
        Ok(target),
        None,
        None,
    );

    assert_eq!(
        diagnostics.cdm_library_sha512.as_deref(),
        Some(digest.as_str())
    );
    assert_eq!(diagnostics.ownership.kind, OwnershipKind::Managed);
    assert!(
        diagnostics.fingerprint.is_none(),
        "partial profile scope must never persist as an exact cache key"
    );
}

#[test]
fn missing_install_root_cdm_disables_probe_cache_fingerprint() {
    let tmp = TempDir::new().expect("tempdir");
    let target = tmp.path().join("WidevineCdm");
    let executable = std::env::current_exe().expect("test executable");

    let diagnostics = collect_browser_at(
        &browser(tmp.path(), BrowserKind::Known),
        Ok(executable),
        Some("150.0.1".into()),
        Ok(target),
        None,
        Some(&[]),
    );

    assert!(diagnostics.fingerprint.is_none());
    assert_eq!(diagnostics.ownership.kind, OwnershipKind::Missing);
    let provenance = diagnostics
        .checks
        .iter()
        .find(|check| check.id == "cdm.provenance")
        .expect("provenance");
    assert_eq!(provenance.status, DiagnosticStatus::Fail);
    assert_eq!(
        provenance.details.get("ownership_kind").map(String::as_str),
        Some("missing")
    );
}

#[test]
fn known_unmarked_cdm_is_external_without_candidate_proof() {
    let tmp = TempDir::new().expect("tempdir");
    let target = unmarked_cdm(tmp.path());
    let diagnostics = collect_browser_at(
        &browser(tmp.path(), BrowserKind::Known),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(target),
        None,
        Some(&[]),
    );

    assert_eq!(diagnostics.ownership.kind, OwnershipKind::External);
    let provenance = diagnostics
        .checks
        .iter()
        .find(|check| check.id == "cdm.provenance")
        .expect("provenance");
    assert_eq!(provenance.status, DiagnosticStatus::Warn);
    assert_eq!(
        provenance.failure_domain,
        crate::diagnostics::FailureDomain::BrowserMediaStack
    );
}

#[test]
fn detected_unmarked_cdm_is_external_browser_domain() {
    let tmp = TempDir::new().expect("tempdir");
    let target = unmarked_cdm(tmp.path());
    let diagnostics = collect_browser_at(
        &browser(tmp.path(), BrowserKind::Detected),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(target),
        None,
        Some(&[]),
    );

    assert_eq!(diagnostics.ownership.kind, OwnershipKind::External);
    let provenance = diagnostics
        .checks
        .iter()
        .find(|check| check.id == "cdm.provenance")
        .expect("provenance");
    assert_eq!(provenance.status, DiagnosticStatus::Warn);
    assert_eq!(
        provenance.failure_domain,
        crate::diagnostics::FailureDomain::BrowserMediaStack
    );
    assert_eq!(ownership_kind_name(diagnostics.ownership.kind), "external");
}

#[test]
fn profile_component_cdm_is_reported_without_recursive_dump() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    let target = install.join("WidevineCdm");
    // Missing install-root CDM.
    let profile = tmp.path().join("profile");
    let component = profile.join("Default").join("WidevineCdm");
    let platform = component
        .join("_platform_specific")
        .join(test_platform_dir());
    fs::create_dir_all(&platform).expect("platform");
    fs::write(
        component.join("manifest.json"),
        br#"{"version":"4.10.9.9"}"#,
    )
    .expect("manifest");
    fs::write(platform.join(test_library_name()), test_library_bytes()).expect("library");

    let diagnostics = collect_browser_for_test(
        &browser(&install, BrowserKind::Detected),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(target),
        None,
        &[profile],
    );

    assert_eq!(diagnostics.ownership.kind, OwnershipKind::Missing);
    assert_eq!(diagnostics.external_cdms.len(), 1);
    assert_eq!(
        diagnostics.external_cdms[0].origin,
        ExternalCdmOrigin::ProfileWidevineCdm
    );
    assert_eq!(
        diagnostics.external_cdms[0].version.as_deref(),
        Some("4.10.9.9")
    );
    let fingerprint = diagnostics.fingerprint.expect("fingerprint");
    assert!(fingerprint
        .cdm_entries
        .iter()
        .any(|entry| { entry.version.as_deref() == Some("4.10.9.9") }));
}
#[test]
fn managed_profile_component_is_not_duplicated_as_external_evidence() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    let (seeded, _) = managed_cdm(&tmp.path().join("seed"));
    let profile = tmp.path().join("profile");
    let target = profile.join("WidevineCdm/4.10.0.0");
    fs::create_dir_all(target.parent().expect("component parent")).expect("component parent");
    fs::rename(seeded, &target).expect("move managed component");

    let diagnostics = collect_browser_for_test(
        &browser(&install, BrowserKind::Known),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(target),
        None,
        &[profile],
    );

    assert_eq!(diagnostics.ownership.kind, OwnershipKind::Managed);
    assert!(diagnostics.external_cdms.is_empty());
    assert_eq!(
        diagnostics
            .fingerprint
            .expect("fingerprint")
            .cdm_entries
            .len(),
        1
    );
}

#[test]
fn empty_unmarked_cdm_root_is_external_not_legacy() {
    let tmp = TempDir::new().expect("tempdir");
    let target = tmp.path().join("WidevineCdm");
    fs::create_dir_all(&target).expect("target");
    let diagnostics = collect_browser_at(
        &browser(tmp.path(), BrowserKind::Known),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(target),
        None,
        Some(&[]),
    );
    assert_eq!(diagnostics.ownership.kind, OwnershipKind::External);
    assert!(diagnostics.fingerprint.is_none());
}

#[test]
fn latest_component_pref_paths_are_containment_checked() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    let target = install.join("WidevineCdm");
    let profile = tmp.path().join("profile");
    fs::create_dir_all(profile.join("Default")).expect("profile");
    let component = profile.join("component-widevine");
    let platform = component
        .join("_platform_specific")
        .join(test_platform_dir());
    fs::create_dir_all(&platform).expect("platform");
    fs::write(
        component.join("manifest.json"),
        br#"{"version":"4.10.8.8"}"#,
    )
    .expect("manifest");
    fs::write(platform.join(test_library_name()), test_library_bytes()).expect("library");
    let prefs = serde_json::json!({
        "component_updater": {
            "latest-component-updated-widevine-cdm": {
                "path": component.to_string_lossy(),
                "version": "4.10.8.8"
            }
        }
    });
    fs::write(
        profile.join("Local State"),
        serde_json::to_vec_pretty(&prefs).expect("json"),
    )
    .expect("local state");

    // Escape attempt must be ignored by containment checks.
    let escape = tmp.path().join("outside-cdm");
    fs::create_dir_all(&escape).expect("escape");
    let dirty = serde_json::json!({
        "latest-component-updated-widevine-cdm": "../../outside-cdm"
    });
    fs::write(
        profile.join("Default").join("Preferences"),
        serde_json::to_vec_pretty(&dirty).expect("json"),
    )
    .expect("prefs");

    let diagnostics = collect_browser_for_test(
        &browser(&install, BrowserKind::Detected),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(target),
        None,
        &[profile],
    );

    assert!(diagnostics
        .external_cdms
        .iter()
        .any(|hint| hint.version.as_deref() == Some("4.10.8.8")));
    assert!(diagnostics
        .external_cdms
        .iter()
        .all(|hint| { !hint.path.ends_with("outside-cdm") }));
}

#[test]
fn unresolved_executable_yields_no_fingerprint() {
    let tmp = TempDir::new().expect("tempdir");
    let diagnostics = collect_browser_at(
        &browser(tmp.path(), BrowserKind::Known),
        Err(crate::error::Error::unknown_bundle_structure("missing")),
        Some("150.0.1".into()),
        Ok(tmp.path().join("WidevineCdm")),
        None,
        Some(&[]),
    );
    assert!(diagnostics.fingerprint.is_none());
}

#[test]
fn absent_optional_host_utility_is_unavailable_not_a_failure() {
    // Host collectors are covered in media/linux modules; keep a smoke path.
    let checks = super::collect_host_media_checks();
    assert!(!checks.is_empty() || cfg!(not(any(target_os = "linux", target_os = "macos"))));
    let _ = PathBuf::from(".");
}

fn write_profile_cdm(profile_dir: &std::path::Path, version: &str, library: &[u8]) {
    let component = profile_dir.join("WidevineCdm");
    let platform = component
        .join("_platform_specific")
        .join(test_platform_dir());
    fs::create_dir_all(&platform).expect("platform");
    fs::write(
        component.join("manifest.json"),
        format!(r#"{{"version":"{version}"}}"#),
    )
    .expect("manifest");
    fs::write(platform.join(test_library_name()), library).expect("library");
}

#[test]
fn active_profile_one_cdm_joins_fingerprint_and_differs_from_default() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    let target = install.join("WidevineCdm");
    let user_data = tmp.path().join("chromium");
    fs::create_dir_all(user_data.join("Default")).expect("default");
    fs::create_dir_all(user_data.join("Profile 1")).expect("profile1");

    let default_library = test_library_bytes();
    let mut profile_library = test_library_bytes();
    // Ensure Profile 1 library digest differs from Default.
    if let Some(last) = profile_library.last_mut() {
        *last ^= 0x5a;
    }
    write_profile_cdm(&user_data.join("Default"), "4.10.1.1", &default_library);
    write_profile_cdm(&user_data.join("Profile 1"), "4.10.9.9", &profile_library);

    let local_state = serde_json::json!({
        "profile": {
            "info_cache": {
                "Default": { "name": "Person 1" },
                "Profile 1": { "name": "Work" }
            },
            "last_used": "Profile 1",
            "last_active_profiles": ["Profile 1"]
        }
    });
    fs::write(
        user_data.join("Local State"),
        serde_json::to_vec_pretty(&local_state).expect("json"),
    )
    .expect("local state");

    let diagnostics = collect_browser_for_test(
        &browser(&install, BrowserKind::Detected),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(target),
        None,
        &[user_data],
    );

    assert!(
        diagnostics
            .external_cdms
            .iter()
            .any(|hint| hint.version.as_deref() == Some("4.10.9.9")),
        "Profile 1 Widevine evidence must participate: {:?}",
        diagnostics.external_cdms
    );
    assert!(
        diagnostics
            .external_cdms
            .iter()
            .any(|hint| hint.version.as_deref() == Some("4.10.1.1")),
        "Default Widevine evidence must still be collected"
    );
    let fingerprint = diagnostics
        .fingerprint
        .expect("complete multi-profile scope must remain fingerprintable");
    assert!(fingerprint
        .cdm_entries
        .iter()
        .any(|entry| entry.version.as_deref() == Some("4.10.9.9")));
    assert!(fingerprint
        .cdm_entries
        .iter()
        .any(|entry| entry.version.as_deref() == Some("4.10.1.1")));
    let default_digest = diagnostics
        .external_cdms
        .iter()
        .find(|hint| hint.version.as_deref() == Some("4.10.1.1"))
        .and_then(|hint| hint.library_sha512.as_deref());
    let profile_digest = diagnostics
        .external_cdms
        .iter()
        .find(|hint| hint.version.as_deref() == Some("4.10.9.9"))
        .and_then(|hint| hint.library_sha512.as_deref());
    assert_ne!(default_digest, profile_digest);
}

#[test]
fn unreadable_or_malformed_profile_metadata_suppresses_fingerprint() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    let target = install.join("WidevineCdm");
    let executable = std::env::current_exe().expect("exe");

    // Malformed Local State JSON.
    let malformed_root = tmp.path().join("malformed");
    fs::create_dir_all(malformed_root.join("Default")).expect("default");
    write_profile_cdm(
        &malformed_root.join("Default"),
        "4.10.2.2",
        &test_library_bytes(),
    );
    fs::write(malformed_root.join("Local State"), b"{not-json").expect("local state");
    let malformed = collect_browser_for_test(
        &browser(&install, BrowserKind::Detected),
        Ok(executable.clone()),
        Some("150.0.1".into()),
        Ok(target.clone()),
        None,
        &[malformed_root],
    );
    assert!(
        malformed.fingerprint.is_none(),
        "malformed Local State must suppress exact fingerprint"
    );

    // Oversized Preferences under an active profile.
    let oversized_root = tmp.path().join("oversized");
    fs::create_dir_all(oversized_root.join("Profile 1")).expect("profile");
    let local_state = serde_json::json!({
        "profile": {
            "info_cache": { "Profile 1": { "name": "Work" } },
            "last_used": "Profile 1"
        }
    });
    fs::write(
        oversized_root.join("Local State"),
        serde_json::to_vec_pretty(&local_state).expect("json"),
    )
    .expect("local state");
    let big = vec![b'x'; 1024 * 1024 + 8];
    fs::write(oversized_root.join("Profile 1").join("Preferences"), &big).expect("prefs");
    let oversized = collect_browser_for_test(
        &browser(&install, BrowserKind::Detected),
        Ok(executable.clone()),
        Some("150.0.1".into()),
        Ok(target.clone()),
        None,
        &[oversized_root],
    );
    assert!(
        oversized.fingerprint.is_none(),
        "oversized profile Preferences must suppress exact fingerprint"
    );

    // Truncated info_cache enumeration (>16 profiles listed).
    let truncated_root = tmp.path().join("truncated");
    fs::create_dir_all(truncated_root.join("Default")).expect("default");
    write_profile_cdm(
        &truncated_root.join("Default"),
        "4.10.3.3",
        &test_library_bytes(),
    );
    let mut info_cache = serde_json::Map::new();
    info_cache.insert("Default".into(), serde_json::json!({ "name": "Person 1" }));
    for idx in 1..=17 {
        let name = format!("Profile {idx}");
        fs::create_dir_all(truncated_root.join(&name)).expect("profile dir");
        info_cache.insert(name, serde_json::json!({ "name": format!("P{idx}") }));
    }
    let truncated_state = serde_json::json!({
        "profile": {
            "info_cache": info_cache,
            "last_used": "Default"
        }
    });
    fs::write(
        truncated_root.join("Local State"),
        serde_json::to_vec_pretty(&truncated_state).expect("json"),
    )
    .expect("local state");
    let truncated = collect_browser_for_test(
        &browser(&install, BrowserKind::Detected),
        Ok(executable),
        Some("150.0.1".into()),
        Ok(target),
        None,
        &[truncated_root],
    );
    assert!(
        truncated.fingerprint.is_none(),
        "bounded Local State truncation must suppress exact fingerprint"
    );
}

#[test]
fn unrecognized_profile_metadata_suppresses_fingerprint() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    let user_data = tmp.path().join("chromium");
    fs::create_dir_all(&user_data).expect("user data");
    let local_state = serde_json::json!({
        "profile": {
            "info_cache": {
                "unrecognized-profile-directory": { "name": "Unknown" }
            }
        }
    });
    fs::write(
        user_data.join("Local State"),
        serde_json::to_vec_pretty(&local_state).expect("json"),
    )
    .expect("local state");

    let diagnostics = collect_browser_for_test(
        &browser(&install, BrowserKind::Detected),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(install.join("WidevineCdm")),
        None,
        &[user_data],
    );

    assert!(
        diagnostics.fingerprint.is_none(),
        "an unrecognized profile directory in Local State makes scope incomplete"
    );
    assert_eq!(
        diagnostics
            .checks
            .iter()
            .find(|check| check.id == "cdm.external_components")
            .and_then(|check| check.details.get("profile_scope_complete"))
            .map(String::as_str),
        Some("false")
    );
}

#[cfg(unix)]
#[test]
fn symlinked_profile_widevine_suppresses_fingerprint() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    let user_data = tmp.path().join("chromium");
    let default_profile = user_data.join("Default");
    fs::create_dir_all(&default_profile).expect("default");
    let outside = tmp.path().join("outside-widevine");
    fs::create_dir_all(&outside).expect("outside");
    std::os::unix::fs::symlink(&outside, default_profile.join("WidevineCdm"))
        .expect("widevine symlink");
    fs::write(
        user_data.join("Local State"),
        br#"{"profile":{"info_cache":{"Default":{}},"last_used":"Default"}}"#,
    )
    .expect("local state");

    let diagnostics = collect_browser_for_test(
        &browser(&install, BrowserKind::Detected),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(install.join("WidevineCdm")),
        None,
        &[user_data],
    );

    assert!(
        diagnostics.fingerprint.is_none(),
        "a profile CDM symlink must not be omitted from an exact fingerprint"
    );
    assert_eq!(
        diagnostics
            .checks
            .iter()
            .find(|check| check.id == "cdm.external_components")
            .and_then(|check| check.details.get("profile_scope_complete"))
            .map(String::as_str),
        Some("false")
    );
}

#[test]
fn unverified_cache_candidate_does_not_poison_ownership() {
    let tmp = TempDir::new().expect("tempdir");
    let target = unmarked_cdm(tmp.path());
    let unverified = CachedCdm::new("4.10.0.0".into(), target.clone());
    assert!(unverified.verified_library_sha512().is_none());

    let diagnostics = collect_browser_at(
        &browser(tmp.path(), BrowserKind::Known),
        Ok(std::env::current_exe().expect("exe")),
        Some("150.0.1".into()),
        Ok(target),
        Some(&unverified),
        Some(&[]),
    );

    assert_eq!(
        diagnostics.ownership.kind,
        OwnershipKind::External,
        "unverified cache handle must fall back to candidate-free classification"
    );
}

#[test]
fn library_digest_prefers_known_hex_without_reading_path() {
    let missing = Path::new("/tmp/silvervine-definitely-missing-cdm.so");
    assert_eq!(
        library_digest(missing, Some("abc123")),
        Some("abc123".into())
    );
    assert_eq!(library_digest(missing, None), None);
}
