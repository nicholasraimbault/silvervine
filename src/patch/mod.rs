//! Atomic patch protocol — publish a verified Widevine CDM for a browser.
//!
//! This module is the **core engine** half of patching. It owns:
//!
//! * The public [`patch_browser`] entry point that the CLI / daemon call.
//! * The lockfile, optional snapshot/restore, browser-running detection, and
//!   post-patch verification (all platform-agnostic).
//! * The [`PlatformPatcher`] trait that decouples platform-specific CDM
//!   publication from the orchestration above.
//!
//! Platform-specific implementations of [`PlatformPatcher`] live in the
//! Platform team's `src/patch/linux.rs` and `src/patch/macos.rs` modules.
//! Core engine **does not** reach into those files; the contract here is the
//! whole interface.
//!
//! ## Patch protocol
//!
//! ```text
//! 1. Acquire the exclusive patch lock.
//! 2. Reject a running browser unless --force-while-running is set.
//! 3. For a transactional patcher:
//!    a. The platform implementation stages, verifies, and publishes the update.
//!    b. Core performs the final post-publish verification.
//! 4. For a legacy non-transactional patcher:
//!    a. Core snapshots the browser bundle.
//!    b. The platform implementation writes and core verifies.
//!    c. Core restores on a modified failure or commits on success.
//! 5. Release the lock.
//! ```
//!
//! Callers provide a [`CachedCdm`]; cache resolution and download are outside
//! this orchestrator.
//!
//! ## Why a trait?
//!
//! Linux and macOS each assemble and verify a temporary `WidevineCdm` tree,
//! then atomically exchange it with the platform's active target. Linux targets
//! the browser installation; macOS targets Chromium's per-user component
//! directory. The shared trait keeps orchestration testable.
//!
//! ## What this module does NOT do
//!
//! * No platform syscalls — those live in the Platform team's modules.
//! * No CDM download — that's [`crate::widevine::download`].
//! * No tray notifications — daemon team owns those.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::browsers::{discovery, Browser};
use crate::error::{Error, Result};
use crate::lockfile;
use crate::platform;
use crate::widevine::cache::CachedCdm;
use crate::widevine::ownership::{self, ManagedMarker, OwnershipAssessment, OwnershipKind};

pub mod backup;

/// Linux platform impl — owned by the platform team. Compiled only on
/// `target_os = "linux"`.
#[cfg(target_os = "linux")]
pub mod linux;

/// macOS platform impl. Pure bundle tests also compile it on other hosts.
#[cfg(any(target_os = "macos", test))]
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
/// Per spec: `~/.cache/silvervine/patch.lock`. Returns `None` if `dirs::cache_dir()`
/// is unresolvable (e.g. no `$HOME`); callers in that case should surface a
/// `StateCorrupted` error or use a caller-supplied path.
#[must_use]
pub fn default_patch_lock() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("silvervine").join("patch.lock"))
}

/// Options for [`patch_browser`].
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)] // Independent CLI safety controls.
pub struct PatchOptions {
    /// If `true`, patch even when the browser is currently running. Spec
    /// recommends against this; reserved for `silvervine patch --force-while-running`.
    pub force_while_running: bool,
    /// Permit replacement of an unmarked CDM classified as externally
    /// managed. Invalid Silvervine markers are never bypassed.
    pub replace_external_cdm: bool,
    /// If `true`, run all pre-flight + post-patch checks but do not touch
    /// the bundle. Used by `silvervine patch --dry-run`.
    pub dry_run: bool,
    /// Override the lockfile path. `None` uses [`default_patch_lock`].
    pub lock_path: Option<PathBuf>,
    /// Override the backups root. `None` triggers the writability-aware
    /// default: when the install path is writable by the current process,
    /// backups go under [`backup::default_backups_dir`] (`~/.cache/silvervine/backups/`);
    /// when it isn't, backups use an exclusively-created random sibling under
    /// `<install-parent>` so atomic-swap rollback stays on one filesystem.
    /// Tests pass a `tempfile::TempDir` to bypass both defaults.
    pub backups_dir: Option<PathBuf>,
    /// `true` when this invocation is the privileged child of a previous
    /// `silvervine patch` that escalated via `pkexec` / `sudo` / `osascript`.
    /// Set only by the hidden privileged patch operation. Wires two pieces of
    /// behavior:
    ///
    /// 1. Don't try to escalate again (we're already root); a second
    ///    escalation attempt would loop or surface an extra password prompt.
    /// 2. Default `backups_dir` resolution falls through to
    ///    [`backup::snapshot_into_sibling`] (root-owned, same-filesystem)
    ///    rather than `~/.cache/silvervine/backups/` (which would be the
    ///    elevation user's home).
    pub as_root: bool,
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
/// JSON-friendly outcome record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchReport {
    /// Display name of the browser.
    pub browser: String,
    /// `true` when the patch succeeded (or dry-run completed).
    pub success: bool,
    /// CDM version that was written (or would have been, in dry-run).
    pub cdm_version: Option<String>,
    /// Browser version detected before patching.
    pub version_before: Option<String>,
    /// Browser version reported before the patch; CDM placement does not
    /// change it.
    pub version_after: Option<String>,
    /// Stable error category when `success` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_category: Option<crate::ErrorCategory>,
    /// `true` if dry-run mode was used.
    pub dry_run: bool,
    /// Error message if `success == false`.
    pub error: Option<String>,
}

impl PatchReport {
    pub(crate) fn success(outcome: &PatchOutcome) -> Self {
        Self {
            browser: outcome.browser_name.clone(),
            success: true,
            cdm_version: Some(outcome.cdm_version.clone()),
            version_before: outcome.version_before.clone(),
            version_after: outcome.version_after.clone(),
            error_category: None,
            dry_run: outcome.dry_run,
            error: None,
        }
    }

    pub(crate) fn failure(name: &str, dry_run: bool, error: &Error) -> Self {
        Self {
            browser: name.to_string(),
            success: false,
            cdm_version: None,
            version_before: None,
            version_after: None,
            error_category: Some(error.category),
            dry_run,
            error: Some(error.to_string()),
        }
    }
}
/// Result of a parent-authorized platform write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedWrite {
    /// Only payload bytes were written; core must validate and commit a marker.
    PayloadOnly,
    /// Payload and marker were atomically published and validated at the live
    /// path before the retired payload was discarded.
    MarkerCommitted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TargetIdentity {
    device: u64,
    inode: u64,
}

/// Opaque identity of the candidate target authorized under the patch lock.
///
/// Existing targets retain an open directory handle for the authorization
/// lifetime. Keeping the original inode alive prevents remove-and-recreate
/// races from passing validation through immediate inode-number reuse.
#[derive(Debug)]
pub struct TargetAuthorization {
    identity: Option<TargetIdentity>,
    _handle: Option<fs::File>,
}

impl TargetAuthorization {
    pub(crate) fn capture(target: &Path) -> Result<Self> {
        let handle = match open_target_handle(target) {
            Ok(handle) => Some(handle),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(Error::from(error)),
        };
        let identity = handle
            .as_ref()
            .map(fs::File::metadata)
            .transpose()?
            .map(|metadata| TargetIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            });
        Ok(Self {
            identity,
            _handle: handle,
        })
    }

    pub(crate) fn validate(&self, target: &Path) -> Result<()> {
        let current = Self::capture(target)?;
        if self.identity != current.identity {
            return Err(Error::state_corrupted(
                "CDM target changed after ownership authorization",
            ));
        }
        Ok(())
    }
}

fn open_target_handle(target: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    options.open(target)
}

/// Remove transaction state only while it still has the authorized identity.
///
/// # Errors
///
/// Preserves the entire staging directory and returns `StateCorrupted` when
/// another process replaced the path that cleanup would recursively remove.
pub(crate) fn close_authorized_staging(
    staging: tempfile::TempDir,
    staged: &Path,
    authorization: &TargetAuthorization,
    publication_root: &Path,
) -> Result<()> {
    if let Err(error) = authorization.validate(staged) {
        let recovery = staging.keep();
        return Err(Error::state_corrupted(format!(
            "{}; transaction state was preserved at {}",
            error.message,
            recovery.display()
        ))
        .with_source(error));
    }
    if let Err(error) = staging.close() {
        tracing::warn!(
            path = %publication_root.display(),
            error = %error,
            "could not remove retired CDM transaction state"
        );
    }
    Ok(())
}
enum PatchAttempt {
    Success,
    FailedBeforeModification(Error),
    ModifiedOriginal(Error),
}

/// Trait implemented by the per-OS patch modules.
///
/// The orchestrator reads the browser version, calls [`Self::write_cdm`], then
/// calls [`Self::verify_post_patch`]. Every failure must be a categorized
/// [`Error`].
///
/// Implementations have two modes. A transactional implementation returns
/// `true` from [`Self::writes_transactionally`] and owns staging, publication,
/// and rollback during its write. A legacy implementation uses the default
/// `false`, mutates the live bundle, and is wrapped in the core
/// [`BackupHandle`] snapshot/restore path.
pub trait PlatformPatcher {
    /// Place the CDM files for `target` (the browser's install identity).
    ///
    /// Linux publishes under `<target>/WidevineCdm/`. macOS derives the
    /// browser's user-profile component root from the application bundle and
    /// publishes a versioned `WidevineCdm/<version>/` directory there.
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
    /// Surface anything that prevented CDM placement as a categorized
    /// [`Error`]. Transactional implementations must leave the live target
    /// unchanged or valid; core attempts snapshot restoration for legacy
    /// implementations that modified it.
    fn write_cdm(&self, target: &Path, cdm_source: &Path) -> Result<()>;

    /// Place a parent-verified CDM at the exact target authorized by core and
    /// report whether its marker was committed inside the platform transaction.
    ///
    /// The default rejects a target that no longer matches platform
    /// resolution, writes only the payload, and lets core validate and commit
    /// the marker. A transactional implementation returning `MarkerCommitted`
    /// must validate the live payload, marker, and active target before
    /// discarding rollback state.
    ///
    /// # Errors
    ///
    /// Returns the categorized platform write error when placement fails or
    /// when `cdm_target` no longer matches the candidate target selected under
    /// the patch lock.
    fn write_managed_cdm(
        &self,
        target: &Path,
        cdm_target: &Path,
        cdm_source: &Path,
        parent_marker: &ManagedMarker,
    ) -> Result<ManagedWrite> {
        let expected = self.cdm_target_for_candidate(target, &parent_marker.cdm_version)?;
        if expected != cdm_target {
            return Err(Error::state_corrupted(
                "platform CDM target changed after ownership authorization",
            ));
        }
        self.write_cdm(target, cdm_source)?;
        Ok(ManagedWrite::PayloadOnly)
    }

    /// Publish through a transaction bound to the exact target authorized by
    /// core. Transactional implementations must validate `authorization`
    /// against both the live target before publication and the displaced
    /// target before discarding rollback state.
    ///
    /// # Errors
    ///
    /// Returns a categorized error when the authorized target changed or
    /// platform publication failed.
    fn write_authorized_managed_cdm(
        &self,
        target: &Path,
        cdm_target: &Path,
        cdm_source: &Path,
        parent_marker: &ManagedMarker,
        authorization: &TargetAuthorization,
    ) -> Result<ManagedWrite> {
        if self.writes_transactionally() {
            return Err(Error::state_corrupted(
                "transactional patcher must implement authorized publication",
            ));
        }
        authorization.validate(cdm_target)?;
        self.write_managed_cdm(target, cdm_target, cdm_source, parent_marker)
    }

    /// Resolve the exact CDM directory owned by this platform layout.
    ///
    /// # Errors
    ///
    /// Returns a categorized layout error when the platform-specific CDM
    /// target cannot be resolved safely.
    fn cdm_target(&self, target: &Path) -> Result<PathBuf> {
        Ok(target.join("WidevineCdm"))
    }
    /// Resolve the exact CDM directory for a candidate version.
    ///
    /// Platforms with a versioned component layout override this so ownership
    /// checks and publication address the same version directory. Flat layouts
    /// use [`Self::cdm_target`].
    ///
    /// # Errors
    ///
    /// Returns a categorized layout error when the candidate target cannot be
    /// resolved safely.
    fn cdm_target_for_candidate(&self, target: &Path, _version: &str) -> Result<PathBuf> {
        self.cdm_target(target)
    }

    /// Validate a payload-only write and produce the marker core will commit.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ErrorCategory::InvalidMarker`] when the written payload
    /// no longer matches the parent-authorized identity, or an inspection error.
    fn prepare_managed_payload(
        &self,
        _target: &Path,
        cdm_target: &Path,
        parent_marker: &ManagedMarker,
    ) -> Result<ManagedMarker> {
        let finalized = ownership::marker_for_finalized_payload(cdm_target, parent_marker)?;
        if &finalized != parent_marker {
            return Err(Error::invalid_marker(
                "platform write changed the parent-selected CDM payload",
            ));
        }
        Ok(finalized)
    }

    /// Verify the CDM and ownership marker at their live post-patch location.
    ///
    /// Core calls this after a payload-only marker commit. Transactional
    /// implementations returning `MarkerCommitted` call it, or an equivalent
    /// platform-specific validator, while rollback state is still retained.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ErrorCategory::UnknownBundleStructure`] for an invalid
    /// live layout, or another categorized error when inspection fails.
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

    /// Directory in which patch publication creates, removes, or renames
    /// entries.
    ///
    /// The core probes this path before deciding whether privilege escalation
    /// is required. An owned path allows user-profile patchers to return a
    /// location outside the browser installation.
    ///
    /// # Errors
    ///
    /// Returns a categorized path-resolution error.
    fn write_access_root(&self, target: &Path) -> Result<PathBuf> {
        Ok(target.to_path_buf())
    }

    /// Whether a failed write-access probe may invoke the privileged child.
    ///
    /// User-profile patchers return `false`: escalating would select root's
    /// profile and create incorrectly-owned state instead of fixing access.
    fn supports_elevation(&self) -> bool {
        true
    }

    /// Whether [`PlatformPatcher::write_cdm`] stages, verifies, and atomically
    /// publishes its own update.
    ///
    /// Transactional implementations let the core skip its legacy full-bundle
    /// snapshot. Returning `true` requires every error path to leave the live
    /// browser bundle unchanged or fully valid.
    fn writes_transactionally(&self) -> bool {
        false
    }
}

/// Borrow the detected browsers selected by an optional case-insensitive name.
#[must_use]
pub fn select_browsers<'a>(browsers: &'a [Browser], name_filter: Option<&str>) -> Vec<&'a Browser> {
    browsers
        .iter()
        .filter(|browser| name_filter.is_none_or(|name| browser.name().eq_ignore_ascii_case(name)))
        .collect()
}

/// Executes one coordinated patch transaction across borrowed browsers.
///
/// The batch resolves the CDM once, acquires the patch lock once, and refreshes
/// the process table immediately before each browser's running-state preflight.
pub struct PatchBatch<'a> {
    patcher: &'a dyn PlatformPatcher,
    options: &'a PatchOptions,
}

impl<'a> PatchBatch<'a> {
    #[must_use]
    /// Build a coordinated batch around one patcher and option set.
    pub fn new(patcher: &'a dyn PlatformPatcher, options: &'a PatchOptions) -> Self {
        Self { patcher, options }
    }

    /// Patch every selected browser, preserving per-browser failures.
    pub fn execute<F>(&self, browsers: &[&Browser], cdm_resolver: F) -> Vec<PatchReport>
    where
        F: FnOnce() -> Result<CachedCdm>,
    {
        if browsers.is_empty() {
            return Vec::new();
        }
        if self.options.replace_external_cdm && browsers.len() != 1 {
            let error = Error::other(format!(
                "--replace-external-cdm matched multiple installations ({}); the browser name must identify exactly one installation",
                browsers.len()
            ));
            return reports_for_error(browsers, self.options.dry_run, &error);
        }

        let cdm = match cdm_resolver() {
            Ok(cdm) => cdm,
            Err(error) => return reports_for_error(browsers, self.options.dry_run, &error),
        };

        if self.options.as_root {
            return run_batch(browsers, &cdm, self.patcher, self.options);
        }

        let lock = match patch_lock_path(self.options) {
            Ok(lock) => lock,
            Err(error) => return reports_for_error(browsers, self.options.dry_run, &error),
        };
        match lockfile::with_lock(&lock, || {
            Ok(run_batch(browsers, &cdm, self.patcher, self.options))
        }) {
            Ok(reports) => reports,
            Err(error) => reports_for_error(browsers, self.options.dry_run, &error),
        }
    }
}

fn run_batch(
    browsers: &[&Browser],
    cdm: &CachedCdm,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
) -> Vec<PatchReport> {
    run_batch_with_processes(
        browsers,
        cdm,
        patcher,
        options,
        discovery::ProcessSnapshot::capture,
    )
}

fn run_batch_with_processes<F>(
    browsers: &[&Browser],
    cdm: &CachedCdm,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
    mut capture_processes: F,
) -> Vec<PatchReport>
where
    F: FnMut() -> discovery::ProcessSnapshot,
{
    browsers
        .iter()
        .map(|browser| {
            let processes =
                (!options.as_root && !options.force_while_running).then(&mut capture_processes);
            match run_patch(browser, cdm, patcher, options, processes.as_ref()) {
                Ok(outcome) => PatchReport::success(&outcome),
                Err(error) => PatchReport::failure(browser.name(), options.dry_run, &error),
            }
        })
        .collect()
}

fn reports_for_error(browsers: &[&Browser], dry_run: bool, error: &Error) -> Vec<PatchReport> {
    browsers
        .iter()
        .map(|browser| PatchReport::failure(browser.name(), dry_run, error))
        .collect()
}

fn patch_lock_path(options: &PatchOptions) -> Result<PathBuf> {
    options
        .lock_path
        .clone()
        .or_else(default_patch_lock)
        .ok_or_else(|| {
            Error::state_corrupted("cannot resolve patch lockfile path (no \\$HOME / cache dir)")
        })
}

/// Patch a single browser with the given cached CDM.
///
/// This is the public API CLI and daemon both call.
///
/// # Flow
///
/// 1. Acquire the patch lock, unless this is the elevated child whose parent
///    already holds it.
/// 2. Validate candidate and installed CDM provenance.
/// 3. Reject a running browser unless `force_while_running` is set.
/// 4. Escalate once when the patcher's write-access root is not writable.
/// 5. Transactional patchers seal payload and marker before atomic publish;
///    legacy patchers run under the snapshot/restore protocol.
/// 6. Verify the live payload and marker, then return [`PatchOutcome`].
///
/// With `dry_run = true`, write paths are skipped after provenance preflight.
///
/// # Errors
///
/// * [`crate::ErrorCategory::BrowserRunning`] when the browser is running and
///   `force_while_running` is false.
/// * Any categorized platform write or verification failure. Transactional
///   implementations perform their own write-time recovery; core attempts
///   snapshot restoration for modified legacy writes.
/// * [`crate::ErrorCategory::Other`] for lockfile or backup machinery failures.
pub fn patch_browser(
    browser: &Browser,
    cdm: &CachedCdm,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
) -> Result<PatchOutcome> {
    // Privileged-operation invocations are children of an escalation
    // — the parent process holds the lockfile and is blocked waiting for
    // this child to finish. Re-acquiring would deadlock both (issue #30).
    // Skip the lockfile entirely; the parent's lock covers us.
    if options.as_root {
        return run_patch(browser, cdm, patcher, options, None);
    }
    let lock = patch_lock_path(options)?;
    lockfile::with_lock(&lock, || {
        let processes = (!options.force_while_running).then(discovery::ProcessSnapshot::capture);
        run_patch(browser, cdm, patcher, options, processes.as_ref())
    })
}

/// Decide whether `run_patch` must re-invoke itself under elevated
/// privileges. Pure function so the truth-table is testable without
/// touching geteuid or the filesystem.
///
/// Escalation is needed **only** when none of the privilege paths apply:
///
/// * `as_root` — already the elevated child of an escalation.
/// * `running_as_root` — process started with euid 0 (e.g. `sudo silvervine`).
///   Re-escalating in that case caused issue #30: a redundant osascript
///   prompt followed by a deadlock against the parent's lockfile.
/// * `write_root_writable` — the patcher's publication directory is writable
///   by the current process, so no elevation is needed.
#[must_use]
pub fn decide_escalate(as_root: bool, running_as_root: bool, write_root_writable: bool) -> bool {
    !as_root && !running_as_root && !write_root_writable
}

fn authorize_candidate_target(
    browser: &Browser,
    cdm: &CachedCdm,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
    marker: &ManagedMarker,
) -> Result<(PathBuf, TargetAuthorization)> {
    let active_target = patcher.cdm_target(browser.install_path())?;
    let active_authorization = TargetAuthorization::capture(&active_target)?;
    let active_ownership = ownership::classify(browser, &active_target, cdm, marker)?;
    enforce_ownership(&active_ownership, options)?;
    active_authorization.validate(&active_target)?;

    let candidate_target =
        patcher.cdm_target_for_candidate(browser.install_path(), cdm.version())?;
    if candidate_target == active_target {
        return Ok((candidate_target, active_authorization));
    }

    let candidate_authorization = TargetAuthorization::capture(&candidate_target)?;
    let candidate_ownership = ownership::classify(browser, &candidate_target, cdm, marker)?;
    enforce_ownership(&candidate_ownership, options)?;
    candidate_authorization.validate(&candidate_target)?;
    Ok((candidate_target, candidate_authorization))
}

/// Inner patch flow, run while the lockfile is held.
fn run_patch(
    browser: &Browser,
    cdm: &CachedCdm,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
    processes: Option<&discovery::ProcessSnapshot>,
) -> Result<PatchOutcome> {
    let started = Instant::now();

    let marker = ownership::marker_for_cached(cdm)?;
    let (candidate_target, target_authorization) =
        authorize_candidate_target(browser, cdm, patcher, options, &marker)?;

    // The locked parent performs process inspection once. The elevated child
    // remains filesystem-only and never probes another account's session.
    if !options.as_root
        && !options.force_while_running
        && processes.is_some_and(|snapshot| snapshot.is_running(browser))
    {
        return Err(Error::browser_running(format!(
            "{} is currently running; close it first or use --force-while-running",
            browser.name()
        )));
    }

    let running_as_root = platform::is_running_as_root();
    let version_before = if options.as_root || running_as_root {
        None
    } else {
        patcher.read_browser_version(browser.install_path())
    };
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

    // Escalate only when the patcher's actual publication root is not writable.
    let write_access_root = patcher.write_access_root(browser.install_path())?;
    if decide_escalate(
        options.as_root,
        running_as_root,
        target_writable(&write_access_root),
    ) {
        if !patcher.supports_elevation() {
            return Err(Error::permission_denied(format!(
                "CDM publication directory is not writable: {}",
                write_access_root.display()
            )));
        }
        return run_patch_via_escalation(
            browser,
            cdm,
            patcher,
            options,
            started,
            version_before,
            &marker,
        );
    }
    let direct_root_stage = (running_as_root && !options.as_root)
        .then(|| stage_direct_root_payload(browser, cdm, &marker))
        .transpose()?;
    let direct_root_cdm = direct_root_stage.as_ref().map(|staged| {
        CachedCdm::from_verified_payload(
            cdm.version().to_owned(),
            staged.path().to_owned(),
            marker.library_sha512.clone(),
            marker.manifest_sha512.clone(),
        )
    });
    let write_cdm = direct_root_cdm.as_ref().unwrap_or(cdm);

    let snapshot = (!patcher.writes_transactionally())
        .then(|| take_snapshot(browser, options, version_before.as_deref()))
        .transpose()?;
    match perform_patch(
        browser,
        write_cdm,
        patcher,
        &candidate_target,
        &marker,
        &target_authorization,
    ) {
        PatchAttempt::Success => {
            snapshot.map(BackupHandle::commit).transpose()?;
        }
        PatchAttempt::FailedBeforeModification(error) => {
            if let Some(snapshot) = snapshot {
                let _ = snapshot.commit();
            }
            return Err(error);
        }
        PatchAttempt::ModifiedOriginal(error) => {
            if let Some(snapshot) = snapshot {
                if let Err(restore_error) = snapshot.restore() {
                    return Err(restore_error.with_source(error));
                }
            }
            return Err(error);
        }
    }

    Ok(PatchOutcome {
        browser_name: browser.name().to_string(),
        version_after: version_before.clone(),
        version_before,
        cdm_version: cdm.version().to_string(),
        duration: started.elapsed(),
        dry_run: false,
    })
}

fn stage_direct_root_payload(
    browser: &Browser,
    cdm: &CachedCdm,
    marker: &ManagedMarker,
) -> Result<ownership::StagedPayload> {
    let trusted_parent = select_privileged_snapshot_parent(browser.install_path())?;
    validate_privileged_snapshot_parent(browser.install_path(), &trusted_parent)?;
    ownership::stage_verified_payload(cdm.cdm_dir(), &trusted_parent, marker)
}

fn enforce_ownership(assessment: &OwnershipAssessment, options: &PatchOptions) -> Result<()> {
    let message = match assessment.action.as_deref() {
        Some(action) => format!("{} {action}", assessment.summary),
        None => assessment.summary.clone(),
    };
    match assessment.kind {
        OwnershipKind::InvalidMarker => Err(Error::invalid_marker(message)),
        OwnershipKind::External if !options.replace_external_cdm => {
            Err(Error::external_cdm(message))
        }
        OwnershipKind::Missing
        | OwnershipKind::Managed
        | OwnershipKind::LegacyManaged
        | OwnershipKind::External => Ok(()),
    }
}

/// Choose the snapshot location based on privilege context and filesystem
/// layout:
///
/// 1. If `options.backups_dir` is set, use it verbatim (tests / overrides).
/// 2. Else if running as root **or** the install's parent directory is
///    writable by the current process, place the snapshot in a
///    sibling-of-parent directory of the install path so
///    [`crate::platform::atomic_rename`] rollback stays on a single
///    filesystem (no `EXDEV`).
/// 3. Else fall through to `~/.cache/silvervine/backups/` — the user-controlled
///    install case where the parent dir is typically `~/...` and shares a
///    filesystem with `~/.cache` anyway.
fn take_snapshot(
    browser: &Browser,
    options: &PatchOptions,
    version: Option<&str>,
) -> Result<backup::BackupHandle> {
    if let Some(custom) = options.backups_dir.as_deref() {
        return backup::snapshot_into(browser.install_path(), custom, browser.name(), version);
    }
    let parent_writable = browser.install_path().parent().is_some_and(target_writable);
    if options.as_root || parent_writable {
        return backup::snapshot_into_sibling(browser.install_path(), browser.name(), version);
    }
    backup::snapshot_for_browser(browser, version)
}

/// Detect whether the current process can create files inside `path`.
///
/// Returns `false` if `path` doesn't exist, isn't a directory, or rejects
/// our sentinel-create attempt with `EACCES` / `EROFS`. We probe with
/// `OpenOptions::create_new(true)` so we never clobber an existing file
/// and so the success path actually exercises filesystem permission
/// (vs. `metadata.permissions().readonly()` which doesn't account for
/// effective user/group ownership at the kernel-permission layer).
///
/// The probe filename includes both PID and a per-call atomic counter so
/// concurrent calls from different threads in the same process don't
/// collide on a shared filename and incorrectly report unwritable.
#[must_use]
pub fn target_writable(path: &Path) -> bool {
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU64, Ordering};
    static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);
    if !path.is_dir() {
        return false;
    }
    let n = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe = path.join(format!(
        ".silvervine-write-probe-{}-{n}",
        std::process::id()
    ));
    match OpenOptions::new().create_new(true).write(true).open(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn select_privileged_snapshot_parent(install_path: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    let canonical_install = std::fs::canonicalize(install_path).map_err(|error| {
        Error::other(format!(
            "could not canonicalize browser install {}",
            install_path.display()
        ))
        .with_source(error)
    })?;
    if canonical_install != install_path {
        return Err(Error::unknown_bundle_structure(
            "privileged browser install path must be exact and canonical",
        ));
    }
    let install_metadata = std::fs::symlink_metadata(&canonical_install).map_err(Error::from)?;
    let parent = canonical_install.parent().ok_or_else(|| {
        Error::unknown_bundle_structure("browser install has no parent for secure publication")
    })?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(Error::from)?;
    if install_metadata.dev() != parent_metadata.dev() {
        return Err(Error::permission_denied(
            "privileged browser install and its direct parent must share a filesystem",
        ));
    }

    #[cfg(not(test))]
    validate_privileged_path_ancestry(&canonical_install, 0)?;

    Ok(parent.to_path_buf())
}

fn validate_privileged_path_ancestry(path: &Path, expected_uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(Error::from)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::unknown_bundle_structure(format!(
                "privileged browser path component must be a non-symlink directory: {}",
                ancestor.display()
            )));
        }
        if metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
            return Err(Error::permission_denied(format!(
                "privileged browser path component must be owned by uid {expected_uid} and not group/world-writable: {}",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

/// Validate the exact install directory and direct parent handed to the
/// privileged child.
///
/// # Errors
///
/// Rejects non-canonical, symlinked, writable, differently-owned,
/// non-direct, cross-filesystem, or root-untrusted ancestor paths.
pub fn validate_privileged_snapshot_parent(install_path: &Path, parent: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let canonical_install = std::fs::canonicalize(install_path).map_err(Error::from)?;
    if canonical_install != install_path {
        return Err(Error::unknown_bundle_structure(
            "privileged browser install path must be exact and canonical",
        ));
    }
    let install_metadata = std::fs::symlink_metadata(install_path).map_err(Error::from)?;
    if !install_metadata.is_dir() || install_metadata.file_type().is_symlink() {
        return Err(Error::unknown_bundle_structure(
            "privileged browser install path must be a non-symlink directory",
        ));
    }
    let canonical_parent = std::fs::canonicalize(parent).map_err(Error::from)?;
    if canonical_parent != parent {
        return Err(Error::unknown_bundle_structure(
            "privileged snapshot parent must be an exact canonical directory",
        ));
    }
    if install_path.parent() != Some(parent) {
        return Err(Error::permission_denied(
            "privileged snapshot parent must be the install path's direct parent",
        ));
    }
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(Error::from)?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(Error::unknown_bundle_structure(
            "privileged snapshot parent must be a non-symlink directory",
        ));
    }
    // SAFETY: `geteuid` has no preconditions and does not modify process state.
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid == 0 {
        validate_privileged_path_ancestry(&canonical_install, effective_uid)?;
    } else if install_metadata.uid() != effective_uid
        || parent_metadata.uid() != effective_uid
        || install_metadata.mode() & 0o022 != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(Error::permission_denied(
            "privileged install and direct parent must be elevated-user-owned and not group/world-writable",
        ));
    }
    if install_metadata.dev() != parent_metadata.dev() {
        return Err(Error::unknown_bundle_structure(
            "privileged snapshot parent must share the browser filesystem",
        ));
    }
    Ok(())
}

/// Resolve and hash the exact executable image authorized for elevation.
///
/// Linux uses the kernel-owned `/proc/<pid>/exe` link, which remains bound to
/// the running inode. macOS hashes the current absolute executable path before
/// the authorization prompt; the elevated shell later opens that path once,
/// verifies the digest through its descriptor, and executes the same descriptor.
///
/// # Errors
///
/// Returns [`crate::ErrorCategory::PermissionDenied`] when the running image
/// cannot be resolved to a regular file, or a categorized I/O error when it
/// cannot be hashed.
fn trusted_elevation_executable() -> Result<(PathBuf, String)> {
    #[cfg(target_os = "linux")]
    {
        let executable = PathBuf::from(format!("/proc/{}/exe", std::process::id()));
        let metadata = std::fs::metadata(&executable).map_err(|error| {
            Error::permission_denied(
                "cannot pin the running Silvervine image through /proc for elevation",
            )
            .with_source(error)
        })?;
        if !metadata.is_file() {
            return Err(Error::permission_denied(
                "the /proc elevation executable does not resolve to a regular file",
            ));
        }
        let digest = crate::widevine::download::sha512_file_hex(&executable)?;
        Ok((executable, digest))
    }

    #[cfg(target_os = "macos")]
    {
        let executable = std::env::current_exe().map_err(|error| {
            Error::permission_denied("could not resolve the Silvervine executable")
                .with_source(error)
        })?;
        if !executable.is_absolute() {
            return Err(Error::permission_denied(
                "the Silvervine executable path is not absolute",
            ));
        }
        let metadata = std::fs::symlink_metadata(&executable).map_err(|error| {
            Error::permission_denied("could not inspect the Silvervine executable")
                .with_source(error)
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::permission_denied(
                "the Silvervine executable is not a regular non-symlink file",
            ));
        }
        let digest = crate::widevine::download::sha512_file_hex(&executable)?;
        Ok((executable, digest))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err(Error::unsupported_platform(
        "privileged patching requires Linux or macOS",
    ))
}

/// Copy the parent-authenticated payload into an exclusive, bounded staging
/// tree, then re-invoke the pinned Silvervine image with elevated privileges.
/// The child receives only that staged manifest and host library, never the
/// mutable cache root.
///
/// On `SILVERVINE_TEST_ESCALATE_NOOP=1`, [`platform::run_pinned_as_root`]
/// returns a canned successful [`Output`](std::process::Output). Only test builds skip
/// post-child filesystem validation for that synthetic result.
fn run_patch_via_escalation(
    browser: &Browser,
    cdm: &CachedCdm,
    patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
    started: Instant,
    version_before: Option<String>,
    marker: &ManagedMarker,
) -> Result<PatchOutcome> {
    let staging_parent = tempfile::Builder::new()
        .prefix(".silvervine-elevation-")
        .tempdir()
        .map_err(Error::from)?;
    let staged = ownership::stage_verified_payload(cdm.cdm_dir(), staging_parent.path(), marker)?;
    let staged_cdm = CachedCdm::from_verified_payload(
        cdm.version().to_owned(),
        staged.path().to_owned(),
        marker.library_sha512.clone(),
        marker.manifest_sha512.clone(),
    );
    let (executable, executable_sha512) = trusted_elevation_executable()?;
    let executable = executable
        .to_str()
        .ok_or_else(|| Error::other("trusted executable path is not valid UTF-8"))?;

    let argv = privileged_patch_argv(executable, browser, &staged_cdm, marker, options)?;
    let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let output = platform::run_pinned_as_root(&argv_refs, &executable_sha512)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::permission_denied(format!(
            "elevated patch failed ({}) for {}: {}",
            platform::format_exit_status(output.status),
            browser.install_path().display(),
            stderr.trim()
        )));
    }

    #[cfg(test)]
    let synthetic_noop =
        std::env::var_os("SILVERVINE_TEST_ESCALATE_NOOP").as_deref() == Some("1".as_ref());
    #[cfg(not(test))]
    let synthetic_noop = false;

    if !synthetic_noop {
        let target = patcher.cdm_target_for_candidate(browser.install_path(), cdm.version())?;
        let installed = ownership::validate_installed_cdm(&target).map_err(|error| {
            Error::invalid_marker(format!(
                "elevated patch exited successfully but installed CDM validation failed: {error}"
            ))
        })?;
        #[cfg(target_os = "linux")]
        let expected_payload = installed.marker() == marker;
        #[cfg(target_os = "macos")]
        let expected_payload = installed.matches_candidate(marker);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let expected_payload = false;
        if !expected_payload {
            return Err(Error::invalid_marker(
                "elevated patch installed a different CDM identity than the parent authorized",
            ));
        }
    }

    Ok(PatchOutcome {
        browser_name: browser.name().to_string(),
        version_before: version_before.clone(),
        version_after: version_before,
        cdm_version: cdm.version().to_string(),
        duration: started.elapsed(),
        dry_run: false,
    })
}

fn privileged_patch_argv(
    exe: &str,
    browser: &Browser,
    cdm: &CachedCdm,
    marker: &ManagedMarker,
    options: &PatchOptions,
) -> Result<Vec<String>> {
    let install = browser
        .install_path()
        .to_str()
        .ok_or_else(|| Error::other("browser install path is not valid UTF-8"))?;
    let cdm_dir = cdm
        .cdm_dir()
        .to_str()
        .ok_or_else(|| Error::other("CachedCdm path is not valid UTF-8"))?;
    let backup_parent = select_privileged_snapshot_parent(browser.install_path())?;
    let backup_parent = backup_parent
        .to_str()
        .ok_or_else(|| Error::other("snapshot parent path is not valid UTF-8"))?;
    let marker_json = serde_json::to_string(marker).map_err(Error::from)?;
    let mut argv = vec![
        exe.to_string(),
        "__privileged-patch".into(),
        "--install-path".into(),
        install.into(),
        "--backup-parent".into(),
        backup_parent.into(),
        "--cdm-dir".into(),
        cdm_dir.into(),
        "--managed-marker".into(),
        marker_json,
        "--browser-name".into(),
        browser.name().into(),
        "--browser-kind".into(),
        browser.kind.as_str().into(),
    ];
    if options.force_while_running {
        argv.push("--force".into());
    }
    if options.replace_external_cdm {
        argv.push("--replace-external-cdm".into());
    }
    Ok(argv)
}

fn perform_patch(
    browser: &Browser,
    cdm: &CachedCdm,
    patcher: &dyn PlatformPatcher,
    cdm_target: &Path,
    marker: &ManagedMarker,
    authorization: &TargetAuthorization,
) -> PatchAttempt {
    let managed_write = match patcher.write_authorized_managed_cdm(
        browser.install_path(),
        cdm_target,
        cdm.cdm_dir(),
        marker,
        authorization,
    ) {
        Ok(outcome) => outcome,
        Err(error) if patcher.writes_transactionally() => {
            return PatchAttempt::FailedBeforeModification(error);
        }
        Err(error) => return PatchAttempt::ModifiedOriginal(error),
    };

    match managed_write {
        ManagedWrite::PayloadOnly => {
            let finalized =
                match patcher.prepare_managed_payload(browser.install_path(), cdm_target, marker) {
                    Ok(marker) => marker,
                    Err(error) => return PatchAttempt::ModifiedOriginal(error),
                };
            if let Err(error) = ownership::write_marker(cdm_target, &finalized) {
                return PatchAttempt::ModifiedOriginal(error);
            }
            if let Err(error) = patcher.verify_post_patch(browser.install_path()) {
                return PatchAttempt::ModifiedOriginal(error);
            }
            match ownership::validate_installed_cdm(cdm_target) {
                Ok(installed) if installed.marker() == &finalized => PatchAttempt::Success,
                Ok(_) => PatchAttempt::ModifiedOriginal(Error::invalid_marker(
                    "finalized CDM marker changed after platform verification",
                )),
                Err(error) => PatchAttempt::ModifiedOriginal(error),
            }
        }
        ManagedWrite::MarkerCommitted => PatchAttempt::Success,
    }
}

#[cfg(test)]
mod tests;
