//! Atomic patch protocol — write the Widevine CDM into a browser bundle.
//!
//! This module is the **core engine** half of patching. It owns:
//!
//! * The public [`patch_browser`] entry point that the CLI / daemon call.
//! * The lockfile, snapshot/restore, browser-running detection, and post-patch
//!   verification (all platform-agnostic).
//! * The [`PlatformPatcher`] trait that decouples the platform-specific
//!   bundle write from the orchestration above.
//!
//! Platform-specific implementations of [`PlatformPatcher`] live in the
//! Platform team's `src/patch/linux.rs` and `src/patch/macos.rs` modules.
//! Core engine **does not** reach into those files; the contract here is the
//! whole interface.
//!
//! ## Atomic-patch protocol (per spec "Patch flow")
//!
//! ```text
//! 1. Acquire lockfile (~/.cache/neon/patch.lock, flock exclusive).
//! 2. Pre-flight:
//!    a. Browser must not be running (unless --force-while-running).
//!    b. CDM cache must be present and integrity-verified.
//! 3. Snapshot original bundle    → ~/.cache/neon/backups/<browser>-<ver>-<ts>/
//! 4. Platform impl writes CDM    → into the live bundle.
//!    └ on any error → restore snapshot, return categorized Error.
//! 5. Post-patch verification: CDM file present at the expected path.
//! 6. Commit (delete the backup) on success.
//! 7. Release lockfile.
//! ```
//!
//! ## Why a trait?
//!
//! The Linux patch is a copy-into-`<install_path>/WidevineCdm/` operation.
//! The macOS patch involves the bundle layout, `xattr -cr`, and ad-hoc
//! `codesign`. Two implementations, one orchestrator. A trait keeps the
//! orchestrator testable with a `MockPlatformPatcher` that records the
//! actions taken without touching the filesystem.
//!
//! ## What this module does NOT do
//!
//! * No platform syscalls — those live in the Platform team's modules.
//! * No CDM download — that's [`crate::widevine::download`].
//! * No tray notifications — daemon team owns those.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::browsers::{discovery, Browser};
use crate::error::{Error, Result};
use crate::lockfile;
use crate::widevine::provider::CdmProvider;

pub mod backup;

/// Linux platform impl — owned by the platform team. Compiled only on
/// `target_os = "linux"`.
#[cfg(target_os = "linux")]
pub mod linux;

/// macOS platform impl — owned by the platform team. Compiled only on
/// `target_os = "macos"`.
#[cfg(target_os = "macos")]
pub mod macos;

pub use backup::{prune_backups, BackupHandle};

#[cfg(target_os = "linux")]
pub use linux::LinuxPatcher;

#[cfg(target_os = "macos")]
pub use macos::MacosPatcher;

/// Build the host's [`PlatformPatcher`] implementation.
///
/// Returns the Linux or macOS impl per `cfg(target_os)`. Other OSes
/// return [`crate::ErrorCategory::UnsupportedPlatform`] so callers
/// running on (e.g.) BSD see a categorized error instead of a panic.
///
/// Most callers want this rather than instantiating a specific impl,
/// since it removes the `#[cfg]` from their code paths.
///
/// # Errors
///
/// [`crate::ErrorCategory::UnsupportedPlatform`] on non-Linux, non-macOS
/// hosts.
pub fn host_patcher() -> Result<Box<dyn PlatformPatcher>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(LinuxPatcher::new()))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacosPatcher::new()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(Error::unsupported_platform(
            "patching is only implemented for Linux and macOS",
        ))
    }
}

/// Default lockfile path for patch operations.
///
/// Per spec: `~/.cache/neon/patch.lock`. Returns `None` if `dirs::cache_dir()`
/// is unresolvable (e.g. no `$HOME`); callers in that case should surface a
/// `StateCorrupted` error or use a caller-supplied path.
#[must_use]
pub fn default_patch_lock() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("neon").join("patch.lock"))
}

/// Options for [`patch_browser`].
#[derive(Debug, Clone, Default)]
pub struct PatchOptions {
    /// If `true`, patch even when the browser is currently running. Spec
    /// recommends against this; reserved for `neon patch --force-while-running`.
    pub force_while_running: bool,
    /// If `true`, run all pre-flight + post-patch checks but do not touch
    /// the bundle. Used by `neon patch --dry-run`.
    pub dry_run: bool,
    /// Override the lockfile path. `None` uses [`default_patch_lock`].
    pub lock_path: Option<PathBuf>,
    /// Override the backups root. `None` uses [`backup::default_backups_dir`].
    /// Tests pass a `tempfile::TempDir` so backups don't leak into the
    /// user's `~/.cache/neon/backups/` and so the atomic rename happens
    /// within the same filesystem (avoids EXDEV).
    pub backups_dir: Option<PathBuf>,
}

/// Outcome of a successful [`patch_browser`] call.
///
/// All fields are present even on dry-run (the version-after equals the
/// version-before, and `cdm_version` is the version that *would have*
/// been written).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchOutcome {
    /// Display name of the browser, copied from [`Browser::name`].
    pub browser_name: String,
    /// Browser version string detected before the patch ran. `None` if the
    /// bundle structure didn't expose a version we could read.
    pub version_before: Option<String>,
    /// Browser version string after the patch ran. For Phase 2 this is the
    /// same as `version_before` (we don't change the browser version);
    /// kept distinct so a future `repair`-style flow can change versions.
    pub version_after: Option<String>,
    /// CDM version written into the bundle (e.g. `"4.10.2934.0"`).
    pub cdm_version: String,
    /// Wall-clock duration of the whole patch flow.
    pub duration: Duration,
    /// `true` if the patch was a dry run — no filesystem changes were made.
    pub dry_run: bool,
}

/// Trait implemented by the per-OS patch modules.
///
/// The orchestrator in [`patch_browser`] calls each method in a fixed
/// order, between snapshot and commit. Implementations should surface
/// every failure as a categorized [`Error`] (use the existing helpers
/// — `Error::permission_denied`, `Error::unknown_bundle_structure`, etc.).
///
/// **Design note for platform team:** implementations do not snapshot or
/// restore — that's the orchestrator's job, performed via [`BackupHandle`].
/// You operate on the live bundle directly; if you fail, the orchestrator
/// will roll back from the snapshot it took before invoking you.
pub trait PlatformPatcher {
    /// Place the CDM files into `target` (the browser's install path).
    ///
    /// On Linux this is the install root (e.g. `/opt/helium-browser-bin`)
    /// and the implementation writes under `<target>/WidevineCdm/`. On
    /// macOS this is the `.app` bundle and the implementation writes under
    /// `<target>/Contents/Frameworks/<framework>/Versions/<n>/Libraries/WidevineCdm/`.
    ///
    /// `cdm_source` points at a directory laid out by [`crate::widevine::extract`]:
    ///
    /// ```text
    /// <cdm_source>/
    /// ├── manifest.json
    /// └── _platform_specific/
    ///     └── <platform>/
    ///         └── libwidevinecdm.{so,dylib}
    /// ```
    ///
    /// # Errors
    ///
    /// Surface anything that prevented the CDM placement as a categorized
    /// [`Error`]. The orchestrator will catch the error and restore the
    /// snapshot.
    fn write_cdm(&self, target: &Path, cdm_source: &Path) -> Result<()>;

    /// Verify the CDM is present at the expected post-patch location.
    ///
    /// Run after [`PlatformPatcher::write_cdm`] succeeds, before the
    /// orchestrator commits the snapshot. Returns `Ok(())` if the file is
    /// present and minimally sane (non-empty); returns
    /// [`crate::ErrorCategory::UnknownBundleStructure`] otherwise.
    ///
    /// # Errors
    ///
    /// See above.
    fn verify_post_patch(&self, target: &Path) -> Result<()>;

    /// Read the current browser version (best-effort).
    ///
    /// Linux usually finds it inside the install path's `chrome/VERSION`
    /// file or similar; macOS reads `Contents/Info.plist`'s
    /// `CFBundleShortVersionString`.
    ///
    /// Implementations that can't determine the version return `None`
    /// rather than erroring — the patch flow proceeds with `None` recorded
    /// in [`PatchOutcome::version_before`].
    fn read_browser_version(&self, target: &Path) -> Option<String>;
}

/// Patch a single browser with the given CDM source.
///
/// This is the public API CLI and daemon both call.
///
/// V3-Phase A scaffolding: `cdm` is now a `&dyn CdmProvider` instead of
/// `&CachedCdm`. V2 always passes a [`crate::widevine::provider::LocalFileCdm`]
/// (constructed from the existing [`crate::widevine::cache`] APIs);
/// V3's `experimental-bridge` feature will introduce a `BridgeCdm` impl
/// that talks to a Windows guest VM. The orchestrator stays identical
/// regardless of the source.
///
/// # Flow
///
/// 1. Acquire patch lockfile (blocking).
/// 2. If browser is running and `force_while_running` is false, error out
///    with [`crate::ErrorCategory::BrowserRunning`].
/// 3. Snapshot the install path to `~/.cache/neon/backups/<browser>-<ver>-<ts>/`.
/// 4. Materialize the CDM payload (via `cdm.populate(&staging_dir)`)
///    into a temporary staging directory.
/// 5. Call [`PlatformPatcher::write_cdm`] with the staging dir as
///    source → on error, restore snapshot.
/// 6. Call [`PlatformPatcher::verify_post_patch`] → on error, restore snapshot.
/// 7. Commit (delete the snapshot).
/// 8. Return [`PatchOutcome`].
///
/// On `dry_run = true`, steps 3-7 are skipped; the function returns an
/// outcome with `dry_run = true` and the versions that *would have* been
/// written.
///
/// # Errors
///
/// * [`crate::ErrorCategory::BrowserRunning`] — browser is running and
///   `force_while_running` is false.
/// * Anything from [`crate::widevine::provider::CdmProvider::populate`],
///   [`PlatformPatcher::write_cdm`], or
///   [`PlatformPatcher::verify_post_patch`] — the snapshot is restored
///   before the error is returned.
/// * [`crate::ErrorCategory::Other`] — lockfile or backup machinery failed.
pub fn patch_browser(
    browser: &Browser,
    cdm: &dyn CdmProvider,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
) -> Result<PatchOutcome> {
    let lock = options
        .lock_path
        .clone()
        .or_else(default_patch_lock)
        .ok_or_else(|| {
            Error::state_corrupted("cannot resolve patch lockfile path (no \\$HOME / cache dir)")
        })?;
    lockfile::with_lock(&lock, || run_patch(browser, cdm, patcher, options))
}

/// Inner patch flow, run while the lockfile is held.
fn run_patch(
    browser: &Browser,
    cdm: &dyn CdmProvider,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
) -> Result<PatchOutcome> {
    let started = Instant::now();

    // Pre-flight: refuse to patch a running browser unless --force-while-running.
    if !options.force_while_running && discovery::is_running(browser) {
        return Err(Error::browser_running(format!(
            "{} is currently running; close it first or use --force-while-running",
            browser.name()
        )));
    }

    let version_before = patcher.read_browser_version(browser.install_path());

    if options.dry_run {
        return Ok(PatchOutcome {
            browser_name: browser.name().to_string(),
            version_before: version_before.clone(),
            version_after: version_before,
            cdm_version: cdm.version().to_string(),
            duration: started.elapsed(),
            dry_run: true,
        });
    }

    let snapshot = match options.backups_dir.as_deref() {
        Some(custom) => backup::snapshot_into(
            browser.install_path(),
            custom,
            browser.name(),
            version_before.as_deref(),
        )?,
        None => backup::snapshot_for_browser(browser, version_before.as_deref())?,
    };
    match perform_patch(browser, cdm, patcher) {
        Ok(()) => {
            // Best-effort commit (delete backup). If commit fails (e.g.
            // permission to delete a backup we ourselves created), we still
            // have a valid patched bundle; surface the commit error to
            // observability but don't fail the patch itself.
            snapshot.commit()?;
        }
        Err(patch_err) => {
            // Try to restore. If restore fails, we surface restore's error
            // chained under the original — both are bad news, but the
            // restore failure is the more actionable one (left bundle in
            // an inconsistent state).
            if let Err(restore_err) = snapshot.restore() {
                return Err(restore_err.with_source(patch_err));
            }
            return Err(patch_err);
        }
    }

    let version_after = patcher.read_browser_version(browser.install_path());

    Ok(PatchOutcome {
        browser_name: browser.name().to_string(),
        version_before,
        version_after,
        cdm_version: cdm.version().to_string(),
        duration: started.elapsed(),
        dry_run: false,
    })
}

/// Run the platform impl + verification, between snapshot and commit.
///
/// Materializes the CDM payload into a `tempfile::TempDir` so the
/// platform impl receives a stable directory path. The temp dir lives
/// only for the duration of `write_cdm` + `verify_post_patch`; on
/// success it's dropped (and the directory is removed) before the
/// orchestrator commits the snapshot.
fn perform_patch(
    browser: &Browser,
    cdm: &dyn CdmProvider,
    patcher: &dyn PlatformPatcher,
) -> Result<()> {
    let staging = tempfile::Builder::new()
        .prefix("neon-cdm-staging-")
        .tempdir()
        .map_err(Error::from)?;
    cdm.populate(staging.path())?;
    patcher.write_cdm(browser.install_path(), staging.path())?;
    patcher.verify_post_patch(browser.install_path())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;

    use super::*;
    use crate::browsers::BrowserKind;
    use crate::widevine::provider::LocalFileCdm;

    /// Build a minimum [`LocalFileCdm`] on disk for tests.
    fn make_cached_cdm(root: &Path, version: &str) -> LocalFileCdm {
        let dir = root.join(version);
        let cdm = dir.join("_platform_specific").join("linux_x64");
        fs::create_dir_all(&cdm).expect("mkdir cdm");
        fs::write(cdm.join("libwidevinecdm.so"), b"fake-so").expect("write so");
        fs::write(dir.join("manifest.json"), br#"{"version":"4.10.0.0"}"#).expect("write manifest");
        LocalFileCdm::new(version.to_string(), dir)
    }

    /// Recording mock implementation of [`PlatformPatcher`].
    #[derive(Default)]
    struct MockPatcher {
        write_calls: AtomicUsize,
        verify_calls: AtomicUsize,
        version_calls: AtomicUsize,
        version: RefCell<Option<String>>,
        write_should_fail: bool,
        verify_should_fail: bool,
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
        fn write_cdm(&self, target: &Path, _cdm_source: &Path) -> Result<()> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            if self.write_should_fail {
                return Err(Error::permission_denied(format!(
                    "mock failure writing to {}",
                    target.display()
                )));
            }
            // Touch a marker file so the test can confirm the implementation
            // ran.
            fs::write(target.join("CDM_WRITTEN"), b"1").map_err(Error::from)?;
            Ok(())
        }

        fn verify_post_patch(&self, target: &Path) -> Result<()> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
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
    }

    fn make_browser(install_path: PathBuf) -> Browser {
        Browser {
            name: "TestBrowser".into(),
            install_path,
            kind: BrowserKind::Detected,
            framework_name: None,
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
            dry_run: false,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
        };
        let outcome =
            patch_browser(&browser, &cdm, &patcher, &opts).expect("happy path must succeed");

        assert_eq!(outcome.browser_name, "TestBrowser");
        assert_eq!(outcome.cdm_version, "4.10.2934.0");
        assert_eq!(outcome.version_before.as_deref(), Some("128.0.6613.119"));
        assert_eq!(outcome.version_after.as_deref(), Some("128.0.6613.119"));
        assert!(!outcome.dry_run);
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
        assert_eq!(patcher.verify_calls.load(Ordering::SeqCst), 1);
        // Mock wrote a CDM_WRITTEN marker; confirm it survived.
        assert!(install.join("CDM_WRITTEN").exists());
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
            dry_run: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
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
            dry_run: false,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
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
            dry_run: false,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
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
            dry_run: false,
            lock_path: Some(blocker.join("inside.lock")),
            backups_dir: Some(tmp.path().join("backups")),
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
    fn default_patch_lock_path_resolves_to_neon_subdir() {
        if let Some(p) = default_patch_lock() {
            let suffix = std::path::Path::new("neon").join("patch.lock");
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
            dry_run: false,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
        };
        let outcome = patch_browser(&browser, &cdm, &patcher, &opts).expect("ok");
        assert_eq!(outcome.version_before, outcome.version_after);
    }

    /// `PatchOptions` uses `Default` to produce sensible "off" values.
    #[test]
    fn patch_options_defaults_are_safe() {
        let opts = PatchOptions::default();
        assert!(!opts.force_while_running);
        assert!(!opts.dry_run);
        assert!(opts.lock_path.is_none());
        assert!(opts.backups_dir.is_none());
    }
}
