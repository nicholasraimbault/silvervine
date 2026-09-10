use std::cell::{Cell, RefCell};
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tempfile::TempDir;

use super::*;
use crate::browsers::BrowserKind;

fn canonical_fixture_root(root: &Path) -> PathBuf {
    fs::create_dir_all(root).expect("create fixture root");
    fs::canonicalize(root).expect("canonical fixture root")
}

/// Build a minimum [`CachedCdm`] on disk for tests.
fn make_cached_cdm(root: &Path, version: &str) -> CachedCdm {
    let root = canonical_fixture_root(root);
    let dir = root.join(version);
    let cdm = dir.join("_platform_specific").join(test_platform_dir());
    fs::create_dir_all(&cdm).expect("mkdir cdm");
    fs::write(cdm.join(test_library_name()), b"fake-so").expect("write library");
    let manifest_body = format!(r#"{{"version":"{version}"}}"#);
    fs::write(dir.join("manifest.json"), &manifest_body).expect("write manifest");
    CachedCdm::from_verified_payload(
        version.to_string(),
        dir,
        crate::widevine::sha512_hex(b"fake-so"),
        crate::widevine::sha512_hex(manifest_body.as_bytes()),
    )
}

fn write_installed_cdm(install: &Path, version: &str, library: &[u8]) {
    let target = install.join("WidevineCdm");
    let platform = target.join("_platform_specific").join(test_platform_dir());
    fs::create_dir_all(&platform).expect("platform");
    fs::write(
        target.join("manifest.json"),
        format!(r#"{{"version":"{version}"}}"#),
    )
    .expect("manifest");
    fs::write(platform.join(test_library_name()), library).expect("library");
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

fn ownership_options(tmp: &TempDir, replace_external_cdm: bool) -> PatchOptions {
    PatchOptions {
        force_while_running: true,
        replace_external_cdm,
        lock_path: Some(tmp.path().join("ownership.lock")),
        backups_dir: Some(tmp.path().join("ownership-backups")),
        ..PatchOptions::default()
    }
}

/// Recording mock implementation of [`PlatformPatcher`].
#[derive(Default)]
struct MockPatcher {
    write_calls: AtomicUsize,
    verify_calls: AtomicUsize,
    verify_saw_marker: AtomicBool,
    version_calls: AtomicUsize,
    version: RefCell<Option<String>>,
    write_should_fail: bool,
    verify_should_fail: bool,
    transactional: bool,
}

impl MockPatcher {
    fn with_version(version: &str) -> Self {
        Self {
            version: RefCell::new(Some(version.to_string())),
            ..Default::default()
        }
    }
}

impl PlatformPatcher for MockPatcher {
    fn write_cdm(&self, target: &Path, cdm_source: &Path) -> Result<()> {
        self.write_calls.fetch_add(1, Ordering::SeqCst);
        if self.write_should_fail {
            return Err(Error::permission_denied(format!(
                "mock failure writing to {}",
                target.display()
            )));
        }
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(cdm_source.join("manifest.json"))?)
                .map_err(Error::from)?;
        let version = manifest
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| Error::state_corrupted("mock manifest has no version"))?;
        let library = fs::read(
            cdm_source
                .join("_platform_specific")
                .join(test_platform_dir())
                .join(test_library_name()),
        )?;
        write_installed_cdm(target, version, &library);
        fs::write(target.join("CDM_WRITTEN"), b"1").map_err(Error::from)?;
        Ok(())
    }

    fn write_authorized_managed_cdm(
        &self,
        target: &Path,
        cdm_target: &Path,
        cdm_source: &Path,
        parent_marker: &ManagedMarker,
        authorization: &TargetAuthorization,
    ) -> Result<ManagedWrite> {
        authorization.validate(cdm_target)?;
        self.write_managed_cdm(target, cdm_target, cdm_source, parent_marker)
    }

    fn verify_post_patch(&self, target: &Path) -> Result<()> {
        self.verify_calls.fetch_add(1, Ordering::SeqCst);
        self.verify_saw_marker.store(
            target
                .join("WidevineCdm")
                .join(ownership::MANAGED_MARKER_FILENAME)
                .is_file(),
            Ordering::SeqCst,
        );
        if self.verify_should_fail {
            return Err(Error::unknown_bundle_structure(format!(
                "mock verify failed for {}",
                target.display()
            )));
        }
        Ok(())
    }

    fn read_browser_version(&self, _target: &Path) -> Option<String> {
        self.version_calls.fetch_add(1, Ordering::SeqCst);
        self.version.borrow().clone()
    }

    fn writes_transactionally(&self) -> bool {
        self.transactional
    }
}

struct IncompleteTransactionalPatcher;
impl PlatformPatcher for IncompleteTransactionalPatcher {
    fn write_cdm(&self, target: &Path, _cdm_source: &Path) -> Result<()> {
        fs::write(target.join("incomplete-write"), b"called").map_err(Error::from)
    }

    fn verify_post_patch(&self, _target: &Path) -> Result<()> {
        Ok(())
    }

    fn read_browser_version(&self, _target: &Path) -> Option<String> {
        None
    }

    fn writes_transactionally(&self) -> bool {
        true
    }
}

#[test]
fn transactional_patcher_must_override_authorized_publication() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir(&install).expect("install");
    let cdm = make_cached_cdm(&tmp.path().join("cache"), "1.0");
    let marker = ownership::marker_for_cached(&cdm).expect("marker");
    let target = install.join("WidevineCdm");
    let authorization = TargetAuthorization::capture(&target).expect("missing target");
    let patcher = IncompleteTransactionalPatcher;

    let error = patcher
        .write_authorized_managed_cdm(&install, &target, cdm.cdm_dir(), &marker, &authorization)
        .expect_err("transactional patchers must own authorized rollback");

    assert_eq!(error.category, crate::ErrorCategory::StateCorrupted);
    assert!(!install.join("incomplete-write").exists());
    assert!(!target.exists());
}

struct MutatingUnknownBundleMock;
impl PlatformPatcher for MutatingUnknownBundleMock {
    fn write_cdm(&self, target: &Path, _source: &Path) -> Result<()> {
        fs::write(target.join("partial-write"), b"damaged").map_err(Error::from)?;
        Err(Error::unknown_bundle_structure("late layout failure"))
    }

    fn verify_post_patch(&self, _target: &Path) -> Result<()> {
        Ok(())
    }

    fn read_browser_version(&self, _target: &Path) -> Option<String> {
        None
    }
}
struct UnknownBundleMock;

impl PlatformPatcher for UnknownBundleMock {
    fn write_cdm(&self, _target: &Path, _source: &Path) -> Result<()> {
        Err(Error::unknown_bundle_structure("unsupported test layout"))
    }

    fn verify_post_patch(&self, _target: &Path) -> Result<()> {
        Ok(())
    }

    fn read_browser_version(&self, _target: &Path) -> Option<String> {
        None
    }
}

struct PartialFailMock;

impl PlatformPatcher for PartialFailMock {
    fn write_cdm(&self, _target: &Path, _source: &Path) -> Result<()> {
        Err(Error::permission_denied("injected partial write failure"))
    }

    fn verify_post_patch(&self, _target: &Path) -> Result<()> {
        Ok(())
    }

    fn read_browser_version(&self, _target: &Path) -> Option<String> {
        None
    }
}

struct MarkerPoisonMock;
impl PlatformPatcher for MarkerPoisonMock {
    fn write_cdm(&self, target: &Path, source: &Path) -> Result<()> {
        MockPatcher::default().write_cdm(target, source)?;
        fs::create_dir(
            target
                .join("WidevineCdm")
                .join(ownership::MANAGED_MARKER_FILENAME),
        )
        .map_err(Error::from)
    }

    fn verify_post_patch(&self, _target: &Path) -> Result<()> {
        Ok(())
    }

    fn read_browser_version(&self, _target: &Path) -> Option<String> {
        None
    }
}
struct FinalizeMutationMock;

impl PlatformPatcher for FinalizeMutationMock {
    fn write_cdm(&self, target: &Path, source: &Path) -> Result<()> {
        MockPatcher::default().write_cdm(target, source)
    }

    fn verify_post_patch(&self, target: &Path) -> Result<()> {
        fs::write(
            target
                .join("WidevineCdm")
                .join("_platform_specific")
                .join(test_platform_dir())
                .join(test_library_name()),
            b"finalizer changed library",
        )
        .map_err(Error::from)
    }

    fn read_browser_version(&self, _target: &Path) -> Option<String> {
        None
    }
}

fn make_browser(install_path: PathBuf) -> Browser {
    Browser {
        name: "TestBrowser".into(),
        install_path,
        kind: BrowserKind::Detected,
    }
}

/// Happy path: snapshot → write → verify → commit; outcome carries
/// versions and timing.
#[test]
fn happy_path_calls_platform_methods_in_order() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    // Pre-populate so snapshot has something to copy.
    fs::write(install.join("placeholder"), b"x").expect("seed");
    let browser = make_browser(install.clone());

    let cache_root = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache_root, "4.10.2934.0");

    let patcher = MockPatcher::with_version("128.0.6613.119");

    let opts = PatchOptions {
        force_while_running: true, // skip is_running check in test env
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        as_root: false,
    };
    let outcome = patch_browser(&browser, &cdm, &patcher, &opts).expect("happy path must succeed");

    assert_eq!(outcome.browser_name, "TestBrowser");
    assert_eq!(outcome.cdm_version, "4.10.2934.0");
    assert_eq!(outcome.version_before.as_deref(), Some("128.0.6613.119"));
    assert_eq!(outcome.version_after.as_deref(), Some("128.0.6613.119"));
    assert!(!outcome.dry_run);
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(patcher.verify_calls.load(Ordering::SeqCst), 1);
    assert!(patcher.verify_saw_marker.load(Ordering::SeqCst));
    // Mock wrote a CDM_WRITTEN marker; confirm it survived.
    assert!(install.join("CDM_WRITTEN").exists());
}

#[test]
fn external_cdm_is_preserved_before_the_platform_writer_runs() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    write_installed_cdm(&install, "9.9.9", b"external");
    let browser = make_browser(install.clone());
    let cdm = make_cached_cdm(&tmp.path().join("cache"), "4.10.0.0");
    let patcher = MockPatcher::default();

    let error = patch_browser(&browser, &cdm, &patcher, &ownership_options(&tmp, false))
        .expect_err("external CDM must be preserved");

    assert_eq!(error.category, crate::ErrorCategory::ExternalCdm);
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(
            install
                .join("WidevineCdm")
                .join("_platform_specific")
                .join(test_platform_dir())
                .join(test_library_name())
        )
        .expect("installed library"),
        b"external"
    );
}

#[test]
fn explicit_external_replacement_commits_a_valid_marker() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    write_installed_cdm(&install, "9.9.9", b"external");
    let browser = make_browser(install.clone());
    let cdm = make_cached_cdm(&tmp.path().join("cache"), "4.10.0.0");
    let patcher = MockPatcher::default();

    patch_browser(&browser, &cdm, &patcher, &ownership_options(&tmp, true))
        .expect("explicit replacement");

    let marker =
        crate::widevine::ownership::validate_installed_marker(&install.join("WidevineCdm"))
            .expect("committed marker");
    assert_eq!(marker.cdm_version, "4.10.0.0");
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn explicit_targeted_replacement_preserves_an_invalid_marker() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    write_installed_cdm(&install, "4.10.0.0", b"candidate");
    let marker_path = install
        .join("WidevineCdm")
        .join(crate::widevine::ownership::MANAGED_MARKER_FILENAME);
    fs::write(&marker_path, b"not json").expect("bad marker");
    let browser = make_browser(install.clone());
    let cdm = make_cached_cdm(&tmp.path().join("cache"), "4.10.0.0");
    let patcher = MockPatcher::default();

    let error = patch_browser(&browser, &cdm, &patcher, &ownership_options(&tmp, true))
        .expect_err("replacement consent must not bypass invalid provenance");

    assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);
    assert_eq!(
        fs::read(marker_path).expect("preserved marker"),
        b"not json"
    );
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn marker_commit_failure_rolls_back_the_browser_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    fs::write(install.join("original"), b"keep").expect("seed");
    let browser = make_browser(install.clone());
    let cdm = make_cached_cdm(&tmp.path().join("cache"), "4.10.0.0");

    let error = patch_browser(
        &browser,
        &cdm,
        &MarkerPoisonMock,
        &ownership_options(&tmp, false),
    )
    .expect_err("marker commit must fail");

    assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);
    assert_eq!(
        fs::read(install.join("original")).expect("original"),
        b"keep"
    );
    assert!(!install.join("WidevineCdm").exists());
}
#[test]
fn finalizer_payload_mutation_rolls_back_before_commit() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("install");
    fs::write(install.join("original"), b"keep").expect("seed");
    let browser = make_browser(install.clone());
    let cdm = make_cached_cdm(&tmp.path().join("cache"), "4.10.0.0");

    let error = patch_browser(
        &browser,
        &cdm,
        &FinalizeMutationMock,
        &ownership_options(&tmp, false),
    )
    .expect_err("finalizer mutation must invalidate the transaction");

    assert_eq!(error.category, crate::ErrorCategory::InvalidMarker);
    assert_eq!(fs::read(install.join("original")).unwrap(), b"keep");
    assert!(!install.join("WidevineCdm").exists());
}

#[test]
fn dry_run_does_not_invoke_write_or_verify() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    let browser = make_browser(install);
    let cache_root = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache_root, "4.10.0.0");

    let patcher = MockPatcher::with_version("v1");
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: true,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        as_root: false,
    };
    let outcome = patch_browser(&browser, &cdm, &patcher, &opts).expect("dry run ok");
    assert!(outcome.dry_run);
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(patcher.verify_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn write_failure_restores_from_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    // Original content we want to see preserved on rollback.
    fs::write(install.join("original.txt"), b"keep me").expect("seed");
    let browser = make_browser(install.clone());
    let cache_root = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache_root, "4.10.0.0");

    let mut patcher = MockPatcher::with_version("v1");
    patcher.write_should_fail = true;
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        as_root: false,
    };
    let err = patch_browser(&browser, &cdm, &patcher, &opts).expect_err("write must fail");
    assert_eq!(err.category, crate::ErrorCategory::PermissionDenied);
    // Original is still intact (the snapshot was restored).
    assert_eq!(
        fs::read(install.join("original.txt")).expect("read"),
        b"keep me"
    );
    // The CDM_WRITTEN marker should NOT be present (the mock errored
    // before writing it).
    assert!(!install.join("CDM_WRITTEN").exists());
}

#[test]
fn unknown_bundle_write_failure_still_restores_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    fs::write(install.join("original.txt"), b"keep me").expect("seed");
    let browser = make_browser(install.clone());
    let cdm = make_cached_cdm(&tmp.path().join("widevine"), "4.10.0.0");
    let options = PatchOptions {
        force_while_running: true,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        ..Default::default()
    };

    let error = patch_browser(&browser, &cdm, &MutatingUnknownBundleMock, &options)
        .expect_err("write must fail");

    assert_eq!(error.category, crate::ErrorCategory::UnknownBundleStructure);
    assert!(!install.join("partial-write").exists());
    assert_eq!(
        fs::read(install.join("original.txt")).expect("read original"),
        b"keep me"
    );
}

#[test]
fn verify_failure_restores_from_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    fs::write(install.join("original.txt"), b"keep me").expect("seed");
    let browser = make_browser(install.clone());
    let cache_root = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache_root, "4.10.0.0");

    let mut patcher = MockPatcher::with_version("v1");
    patcher.verify_should_fail = true;
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        as_root: false,
    };
    let err = patch_browser(&browser, &cdm, &patcher, &opts).expect_err("verify must fail");
    assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    // Snapshot restoration removed the CDM_WRITTEN marker that the
    // mock wrote before verify ran.
    assert!(!install.join("CDM_WRITTEN").exists());
    // Original content is still there.
    assert_eq!(
        fs::read(install.join("original.txt")).expect("read"),
        b"keep me"
    );
}

/// Truth-table pin for [`decide_escalate`]. Escalation is needed
/// **only** when the caller is not already privileged in any form AND
/// the install path is not writable.
#[test]
fn decide_escalate_truth_table() {
    // (as_root, running_as_root, target_writable) → expected
    let cases = [
        ((false, false, false), true),
        ((false, false, true), false),
        ((false, true, false), false), // sudo silvervine: don't re-prompt
        ((false, true, true), false),
        ((true, false, false), false), // privileged child: never recurse
        ((true, false, true), false),
        ((true, true, false), false),
        ((true, true, true), false),
    ];
    for ((as_root, running, writable), expected) in cases {
        assert_eq!(
            decide_escalate(as_root, running, writable),
            expected,
            "decide_escalate({as_root}, {running}, {writable}) expected {expected}"
        );
    }
}

/// `patch_browser` with `as_root = true` must not touch the lockfile
/// path — it's the privileged child of an escalation that already
/// holds the lock (or running standalone under sudo). Re-acquiring
/// would deadlock against the parent (see issue #30).
///
/// We verify by passing a `lock_path` that would fail to open
/// (parent is a regular file). If the function honors `as_root` and
/// skips the lock, the call succeeds without ever touching the path.
#[test]
fn as_root_skips_lockfile_acquisition() {
    let tmp = TempDir::new().expect("tempdir");
    let blocker = tmp.path().join("not-a-dir");
    fs::write(&blocker, b"x").expect("write blocker");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir");
    let browser = make_browser(install);
    let cache_root = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache_root, "4.10.0.0");
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(blocker.join("inside.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        as_root: true,
    };
    let out = patch_browser(&browser, &cdm, &MockPatcher::default(), &opts).expect("must succeed");
    assert_eq!(out.cdm_version, "4.10.0.0");
}

#[test]
fn missing_lock_path_returns_state_corrupted_when_no_default() {
    // Build options that override the default to a path that fails to
    // open: a path whose parent is a regular file.
    let tmp = TempDir::new().expect("tempdir");
    let blocker = tmp.path().join("not-a-dir");
    fs::write(&blocker, b"x").expect("write blocker");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir");
    let browser = make_browser(install);
    let cache_root = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache_root, "4.10.0.0");
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(blocker.join("inside.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        as_root: false,
    };
    let err =
        patch_browser(&browser, &cdm, &MockPatcher::default(), &opts).expect_err("must error");
    // PermissionDenied or Other is acceptable — both come from the
    // lockfile open failure, not the patch logic.
    assert!(matches!(
        err.category,
        crate::ErrorCategory::PermissionDenied | crate::ErrorCategory::Other
    ));
}

#[test]
fn default_patch_lock_path_resolves_to_silvervine_subdir() {
    if let Some(p) = default_patch_lock() {
        let suffix = std::path::Path::new("silvervine").join("patch.lock");
        assert!(p.ends_with(&suffix), "got {}", p.display());
    }
}

/// `host_patcher()` returns an `Ok(Box<dyn PlatformPatcher>)` on
/// supported hosts. We can't assert which impl without re-introducing
/// `cfg`, so we just verify the call doesn't error.
#[test]
fn host_patcher_returns_ok_on_supported_host() {
    let r = host_patcher();
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert!(r.is_ok());
    } else {
        assert!(r.is_err());
    }
}

/// `patch_browser` sets `version_after = version_before` when the
/// platform impl returns the same version both before and after the
/// patch (Phase 2 contract — the patch doesn't change the browser
/// version).
#[test]
fn version_before_equals_version_after_in_phase_2() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir");
    fs::write(install.join("seed"), b"x").expect("seed");
    let browser = make_browser(install);
    let cache_root = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache_root, "4.10.0.0");
    let patcher = MockPatcher::with_version("128.0.6613.119");
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        as_root: false,
    };
    let outcome = patch_browser(&browser, &cdm, &patcher, &opts).expect("ok");
    assert_eq!(outcome.version_before, outcome.version_after);
    assert_eq!(patcher.version_calls.load(Ordering::SeqCst), 1);
}

/// `PatchOptions` uses `Default` to produce sensible "off" values.
#[test]
fn patch_options_defaults_are_safe() {
    let opts = PatchOptions::default();
    assert!(!opts.force_while_running);
    assert!(!opts.replace_external_cdm);
    assert!(!opts.dry_run);
    assert!(opts.lock_path.is_none());
    assert!(opts.backups_dir.is_none());
    assert!(!opts.as_root);
}

/// `target_writable` returns `true` for a directory the current user
/// can write to (any tempdir on a sane system).
#[test]
fn target_writable_returns_true_for_writable_tempdir() {
    let tmp = TempDir::new().expect("tempdir");
    assert!(target_writable(tmp.path()));
}

/// `target_writable` returns `false` when the path is a regular file
/// (not a directory) — the writability check requires a directory.
#[test]
fn target_writable_returns_false_for_regular_file() {
    let tmp = TempDir::new().expect("tempdir");
    let f = tmp.path().join("file");
    fs::write(&f, b"x").expect("write");
    assert!(!target_writable(&f));
}

/// `target_writable` returns `false` when the path doesn't exist.
#[cfg(unix)]
#[test]
fn privileged_snapshot_parent_rejects_symlink() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();
    let root = canonical_fixture_root(tmp.path());
    let install = root.join("install");
    let real_parent = root.join("trusted");
    let linked_parent = root.join("linked");
    fs::create_dir_all(&install).unwrap();
    fs::create_dir_all(&real_parent).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();
    let error = validate_privileged_snapshot_parent(&install, &linked_parent).unwrap_err();
    assert!(error.to_string().contains("exact canonical"));
}

#[test]
fn target_writable_returns_false_for_missing_path() {
    let tmp = TempDir::new().expect("tempdir");
    let missing = tmp.path().join("does-not-exist");
    assert!(!target_writable(&missing));
}

/// `target_writable` returns `false` for a read-only directory (we
/// remove write permission via `chmod 0o555`). Skipped on platforms
/// where the running test happens to be root (rare, but possible in
/// some sandboxes); root bypasses Unix DAC.
#[cfg(unix)]
#[test]
fn target_writable_returns_false_for_readonly_directory() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().expect("tempdir");
    let ro = tmp.path().join("ro");
    fs::create_dir_all(&ro).expect("mkdir ro");
    let perms = fs::Permissions::from_mode(0o555);
    fs::set_permissions(&ro, perms).expect("chmod ro");
    // Effective UID 0 (root) ignores DAC; only assert otherwise.
    // SAFETY: `libc::geteuid` is a leaf syscall returning a uid_t.
    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root {
        assert!(!target_writable(&ro));
    }
    // Restore permissions so TempDir's drop can clean up.
    let perms = fs::Permissions::from_mode(0o755);
    let _ = fs::set_permissions(&ro, perms);
}

/// `take_snapshot` honors an explicit `backups_dir` override even
/// when `as_root` is set — tests/injection always wins.
#[test]
fn take_snapshot_prefers_explicit_backups_dir_over_as_root_default() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    fs::write(install.join("seed"), b"x").expect("seed");
    let browser = make_browser(install.clone());
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(tmp.path().join("explicit-backups")),
        as_root: true,
    };
    let handle = take_snapshot(&browser, &opts, Some("v1")).expect("ok");
    assert!(handle
        .snapshot_path()
        .starts_with(tmp.path().join("explicit-backups")));
    let _ = handle.commit();
}

/// When `as_root` is set and no `backups_dir` is provided, the snapshot
/// uses an exclusively-created random sibling under `<install-parent>` so
/// `atomic_rename` rollback works on a single filesystem.
#[test]
fn take_snapshot_uses_sibling_when_as_root_and_no_override() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("opt").join("helium-browser-bin");
    fs::create_dir_all(&install).expect("mkdir install");
    fs::write(install.join("seed"), b"x").expect("seed");
    let browser = make_browser(install.clone());
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: None,
        as_root: true,
    };
    let handle = take_snapshot(&browser, &opts, Some("v1")).expect("ok");
    let expected_parent = install.parent().expect("install has parent");
    assert_eq!(handle.snapshot_path().parent(), Some(expected_parent));
    assert!(handle.snapshot_path().file_name().is_some_and(|name| name
        .to_string_lossy()
        .starts_with(".silvervine-TestBrowser-v1-")));
    let _ = handle.commit();
}
#[cfg(unix)]
#[test]
fn privileged_snapshot_parent_rejects_group_or_world_writable_directory() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().expect("tempdir");
    let root = canonical_fixture_root(tmp.path());
    let install = root.join("install");
    fs::create_dir(&install).expect("install");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();

    let error = validate_privileged_snapshot_parent(&install, &root)
        .expect_err("writable parent must not be trusted across elevation");

    assert_eq!(error.category, crate::ErrorCategory::PermissionDenied);
}

#[cfg(unix)]
#[test]
fn privileged_snapshot_parent_must_be_install_direct_parent() {
    let tmp = TempDir::new().expect("tempdir");
    let root = canonical_fixture_root(tmp.path());
    let direct_parent = root.join("browser-root");
    let install = direct_parent.join("install");
    fs::create_dir_all(&install).expect("install");

    let error = validate_privileged_snapshot_parent(&install, &root)
        .expect_err("an ancestor leaves intermediate components swappable");

    assert_eq!(error.category, crate::ErrorCategory::PermissionDenied);
}

#[cfg(unix)]
#[test]
fn privileged_snapshot_parent_rejects_writable_install_directory() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().expect("tempdir");
    let root = canonical_fixture_root(tmp.path());
    let install = root.join("install");
    fs::create_dir(&install).expect("install");
    fs::set_permissions(&install, fs::Permissions::from_mode(0o777)).expect("chmod install");

    let error = validate_privileged_snapshot_parent(&install, &root)
        .expect_err("a writable install can be swapped below its trusted parent");

    assert_eq!(error.category, crate::ErrorCategory::PermissionDenied);
}

/// Legacy writers can mutate anywhere inside the browser bundle before
/// returning any error category, so even an `UnknownBundleStructure`
/// failure must trigger the caller's snapshot restore.
#[test]
fn perform_patch_treats_unknown_bundle_as_possibly_modified() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    let browser = make_browser(install.clone());
    let cache = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache, "1.0");
    let marker = ownership::marker_for_cached(&cdm).expect("marker");
    let authorization =
        TargetAuthorization::capture(&install.join("WidevineCdm")).expect("target identity");
    let outcome = perform_patch(
        &browser,
        &cdm,
        &UnknownBundleMock,
        &install.join("WidevineCdm"),
        &marker,
        &authorization,
    );
    assert!(matches!(outcome, PatchAttempt::ModifiedOriginal(_)));
    assert!(!install.join("WidevineCdm").exists());
}

/// The same conservative classification applies when the exact
/// platform-resolved CDM target exists after the failed write.
#[test]
fn perform_patch_classifies_nested_platform_write_as_modified_original() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    let partial = install
        .join("Contents/Frameworks/Test.framework/Versions/1/Libraries")
        .join("WidevineCdm");
    fs::create_dir_all(&partial).expect("mkdir nested WidevineCdm");
    fs::write(partial.join("partial.txt"), b"oops").expect("seed");
    let browser = make_browser(install.clone());
    let cache = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache, "1.0");
    let marker = ownership::marker_for_cached(&cdm).expect("marker");
    let authorization = TargetAuthorization::capture(&partial).expect("target identity");
    let outcome = perform_patch(
        &browser,
        &cdm,
        &PartialFailMock,
        &partial,
        &marker,
        &authorization,
    );
    assert!(matches!(outcome, PatchAttempt::ModifiedOriginal(_)));
}
/// When the install path is not writable AND `as_root` is `false`,
/// `run_patch` escalates via `platform::run_as_root`. With
/// `SILVERVINE_TEST_ESCALATE_NOOP=1` the escalation is a stub that returns
/// success, so we can verify the parent-side flow without actually
/// elevating.
#[cfg(unix)]
#[test]
fn run_patch_escalates_when_install_path_is_not_writable() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = crate::test_support::env_lock();

    let tmp = TempDir::new().expect("tempdir");
    let root = canonical_fixture_root(tmp.path());
    let install = root.join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    // Make install read-only so target_writable returns false.
    let perms = fs::Permissions::from_mode(0o555);
    fs::set_permissions(&install, perms).expect("chmod ro");

    let browser = make_browser(install.clone());
    let cache = root.join("widevine");
    let cdm = make_cached_cdm(&cache, "1.0");
    let patcher = MockPatcher::with_version("v1");

    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: None,
        as_root: false,
    };

    // Skip if running as root (DAC bypass means writable returns true).
    // SAFETY: `libc::geteuid` is a leaf syscall returning a uid_t.
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        // Restore perms so tempdir cleanup can succeed.
        let perms = fs::Permissions::from_mode(0o755);
        let _ = fs::set_permissions(&install, perms);
        return;
    }

    // SAFETY: env mutation under env_lock; restored at end of test.
    unsafe { std::env::set_var("SILVERVINE_TEST_ESCALATE_NOOP", "1") };
    let outcome = patch_browser(&browser, &cdm, &patcher, &opts);
    unsafe { std::env::remove_var("SILVERVINE_TEST_ESCALATE_NOOP") };

    // Restore perms so tempdir cleanup can succeed.
    let perms = fs::Permissions::from_mode(0o755);
    let _ = fs::set_permissions(&install, perms);

    // Under noop, escalation reports success and we get a synthetic
    // outcome without the patcher having been invoked.
    let outcome = outcome.expect("noop escalation reports success");
    assert_eq!(outcome.browser_name, "TestBrowser");
    assert_eq!(outcome.cdm_version, "1.0");
    // The patcher should NOT have been invoked in the parent — the
    // privileged child would do that work in real life.
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
    assert_eq!(patcher.verify_calls.load(Ordering::SeqCst), 0);
}

/// When `as_root` is set, `run_patch` skips the writability check
/// and proceeds normally — the elevated child trusts that it has
/// permission already.
#[test]
fn privileged_handoff_carries_exact_parent_selection() {
    let tmp = TempDir::new().unwrap();
    let root = canonical_fixture_root(tmp.path());
    let install = root.join("exact custom install");
    let cdm_root = root.join("exact cache");
    fs::create_dir_all(&install).unwrap();
    let cdm = make_cached_cdm(&cdm_root, "9.8.7.6");
    let mut browser = make_browser(install.clone());
    browser.name = "Parent Custom".into();
    browser.kind = BrowserKind::Known;
    let marker = ownership::marker_for_cached(&cdm).unwrap();
    let argv = privileged_patch_argv(
        "/bin/silvervine",
        &browser,
        &cdm,
        &marker,
        &PatchOptions {
            force_while_running: true,
            replace_external_cdm: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(argv[0], "/bin/silvervine");
    assert!(argv
        .windows(2)
        .any(|v| v == ["--install-path", install.to_str().unwrap()]));
    assert!(argv
        .windows(2)
        .any(|v| v == ["--cdm-dir", cdm.cdm_dir().to_str().unwrap()]));
    let serialized_marker = argv
        .windows(2)
        .find(|pair| pair[0] == "--managed-marker")
        .map(|pair| &pair[1])
        .expect("managed marker");
    assert_eq!(
        serde_json::from_str::<ManagedMarker>(serialized_marker).unwrap(),
        marker
    );
    assert!(argv
        .windows(2)
        .any(|v| v == ["--browser-name", "Parent Custom"]));
    assert!(argv.windows(2).any(|v| v == ["--browser-kind", "known"]));
    assert!(argv.contains(&"--force".to_string()));
    assert!(argv.contains(&"--replace-external-cdm".to_string()));
}

#[test]
fn privileged_handoff_preserves_known_browser_kind_token() {
    let tmp = TempDir::new().unwrap();
    let root = canonical_fixture_root(tmp.path());
    let install = root.join("helium");
    fs::create_dir_all(&install).unwrap();
    let cdm = make_cached_cdm(&root.join("cache"), "1.2.3");
    let mut browser = make_browser(install);
    browser.kind = BrowserKind::Known;

    let marker = ownership::marker_for_cached(&cdm).unwrap();
    let argv = privileged_patch_argv(
        "/usr/bin/silvervine",
        &browser,
        &cdm,
        &marker,
        &PatchOptions::default(),
    )
    .unwrap();

    assert!(argv
        .windows(2)
        .any(|pair| pair == ["--browser-kind", "known"]));
    assert!(!argv.iter().any(|arg| arg.contains("Known")));
}

#[test]
fn run_patch_with_as_root_skips_escalation_and_invokes_patcher() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("opt").join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    fs::write(install.join("seed"), b"x").expect("seed");
    let browser = make_browser(install.clone());
    let cache = tmp.path().join("widevine");
    let cdm = make_cached_cdm(&cache, "1.0");
    let patcher = MockPatcher::with_version("v1");
    let opts = PatchOptions {
        force_while_running: true,
        replace_external_cdm: false,
        dry_run: false,
        lock_path: Some(tmp.path().join("patch.lock")),
        // Don't override backups_dir so the as_root path uses the
        // sibling default.
        backups_dir: None,
        as_root: true,
    };
    let outcome = patch_browser(&browser, &cdm, &patcher, &opts).expect("ok");
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(patcher.verify_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        patcher.version_calls.load(Ordering::SeqCst),
        0,
        "privileged filesystem-only child must not execute browser binaries"
    );
    assert_eq!(outcome.version_before, None);
    assert_eq!(outcome.version_after, None);
    assert!(!outcome.dry_run);
}
#[test]
fn patch_batch_borrows_selected_browsers_and_resolves_cdm_once() {
    let tmp = TempDir::new().expect("tempdir");
    let mut helium = make_browser(tmp.path().join("helium"));
    helium.name = "Helium".into();
    let mut thorium = make_browser(tmp.path().join("thorium"));
    thorium.name = "Thorium".into();
    for browser in [&helium, &thorium] {
        fs::create_dir_all(browser.install_path()).expect("mkdir install");
        fs::write(browser.install_path().join("seed"), b"x").expect("seed");
    }
    let browsers = vec![helium, thorium];
    let selected = select_browsers(&browsers, Some("hELIum"));
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].name(), "Helium");

    let cdm = make_cached_cdm(&tmp.path().join("widevine"), "4.10.2934.0");
    let patcher = MockPatcher::default();
    let options = PatchOptions {
        force_while_running: true,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(tmp.path().join("backups")),
        ..Default::default()
    };
    let resolver_calls = Cell::new(0);
    let reports = PatchBatch::new(&patcher, &options).execute(&selected, || {
        resolver_calls.set(resolver_calls.get() + 1);
        Ok(cdm.clone())
    });

    assert_eq!(resolver_calls.get(), 1);
    assert_eq!(reports.len(), 1);
    assert!(reports[0].success);
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn patch_batch_refreshes_processes_before_each_browser() {
    let tmp = TempDir::new().expect("tempdir");
    let mut helium = make_browser(tmp.path().join("helium"));
    helium.name = "Helium".into();
    let mut thorium = make_browser(tmp.path().join("thorium"));
    thorium.name = "Thorium".into();
    for browser in [&helium, &thorium] {
        fs::create_dir_all(browser.install_path()).expect("mkdir install");
        fs::write(browser.install_path().join("seed"), b"x").expect("seed");
    }
    let cdm = make_cached_cdm(&tmp.path().join("widevine"), "4.10.2934.0");
    let patcher = MockPatcher {
        transactional: true,
        ..Default::default()
    };
    let options = PatchOptions::default();
    let captures = Cell::new(0);

    let reports = run_batch_with_processes(&[&helium, &thorium], &cdm, &patcher, &options, || {
        let capture = captures.get();
        captures.set(capture + 1);
        if capture == 0 {
            discovery::ProcessSnapshot::from_executables([])
        } else {
            discovery::ProcessSnapshot::from_executables([thorium.install_path().join("thorium")])
        }
    });

    assert_eq!(captures.get(), 2);
    assert!(reports[0].success);
    assert!(!reports[1].success);
    assert!(reports[1]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("currently running")));
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
}
#[test]
fn transactional_patcher_skips_full_bundle_snapshot() {
    let tmp = TempDir::new().expect("tempdir");
    let install = tmp.path().join("install");
    fs::create_dir_all(&install).expect("mkdir install");
    fs::write(install.join("seed"), b"x").expect("seed");
    let browser = make_browser(install);
    let cdm = make_cached_cdm(&tmp.path().join("widevine"), "1.0");
    let unusable_backups = tmp.path().join("not-a-directory");
    fs::write(&unusable_backups, b"x").expect("create file");
    let patcher = MockPatcher {
        transactional: true,
        ..Default::default()
    };
    let options = PatchOptions {
        force_while_running: true,
        lock_path: Some(tmp.path().join("patch.lock")),
        backups_dir: Some(unusable_backups),
        ..Default::default()
    };

    let outcome = patch_browser(&browser, &cdm, &patcher, &options).expect("patch");

    assert!(!outcome.dry_run);
    assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
    assert_eq!(patcher.verify_calls.load(Ordering::SeqCst), 1);
}
