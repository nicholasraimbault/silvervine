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
//! Linux assembles and verifies a temporary `WidevineCdm` tree before
//! exchanging it with the live directory. macOS clones the application bundle,
//! updates and signs the clone, then exchanges whole bundles. A shared trait
//! keeps orchestration testable while each platform owns its publish semantics.
//!
//! ## What this module does NOT do
//!
//! * No platform syscalls — those live in the Platform team's modules.
//! * No CDM download — that's [`crate::widevine::download`].
//! * No tray notifications — daemon team owns those.

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

/// Build the host patcher while preserving exact parent-selected macOS
/// framework and version components for the privileged child. Linux ignores
/// both values.
///
/// # Errors
///
/// Returns `UnknownBundleStructure` for missing/unsafe macOS components and
/// `UnsupportedPlatform` outside Linux and macOS.
pub fn host_patcher_for_layout(
    framework_name: Option<&str>,
    framework_version: Option<&str>,
) -> Result<Box<dyn PlatformPatcher>> {
    #[cfg(target_os = "linux")]
    {
        let _ = (framework_name, framework_version);
        Ok(Box::new(LinuxPatcher::new()))
    }
    #[cfg(target_os = "macos")]
    {
        let framework_name = framework_name.ok_or_else(|| {
            Error::unknown_bundle_structure(
                "privileged macOS patch requires an exact parent-selected framework",
            )
        })?;
        let framework_version = framework_version.ok_or_else(|| {
            Error::unknown_bundle_structure(
                "privileged macOS patch requires an exact parent-selected framework version",
            )
        })?;
        macos::validate_layout_component("framework", framework_name)?;
        macos::validate_layout_component("framework version", framework_version)?;
        Ok(Box::new(MacosPatcher::for_layout(
            framework_name,
            framework_version,
        )))
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
    /// Surface anything that prevented CDM placement as a categorized
    /// [`Error`]. Transactional implementations must leave the live bundle
    /// unchanged or valid; core attempts snapshot restoration for legacy
    /// implementations that modified it.
    fn write_cdm(&self, target: &Path, cdm_source: &Path) -> Result<()>;

    /// Place a parent-verified CDM and report whether its marker was committed
    /// inside the platform transaction.
    ///
    /// The default writes only the payload; core then validates and commits the
    /// marker. A transactional implementation returning `MarkerCommitted` must
    /// validate the live payload and marker before discarding rollback state.
    ///
    /// # Errors
    ///
    /// Returns the categorized platform write error when placement fails.
    fn write_managed_cdm(
        &self,
        target: &Path,
        cdm_source: &Path,
        _parent_marker: &ManagedMarker,
    ) -> Result<ManagedWrite> {
        self.write_cdm(target, cdm_source)?;
        Ok(ManagedWrite::PayloadOnly)
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
    /// is required. Linux stages inside the install root and uses the default;
    /// macOS overrides this with the application bundle's parent directory.
    #[must_use]
    fn write_access_root<'a>(&self, target: &'a Path) -> &'a Path {
        target
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
    let cdm_target = patcher.cdm_target(browser.install_path())?;
    let ownership = ownership::classify(browser, &cdm_target, cdm, &marker)?;
    enforce_ownership(&ownership, options)?;

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
    if decide_escalate(
        options.as_root,
        running_as_root,
        target_writable(patcher.write_access_root(browser.install_path())),
    ) {
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
    let direct_root_stage = if running_as_root && !options.as_root {
        let trusted_parent = select_privileged_snapshot_parent(browser.install_path())?;
        validate_privileged_snapshot_parent(browser.install_path(), &trusted_parent)?;
        Some(ownership::stage_verified_payload(
            cdm.cdm_dir(),
            &trusted_parent,
            &marker,
        )?)
    } else {
        None
    };
    let direct_root_cdm = direct_root_stage.as_ref().map(|staged| {
        CachedCdm::from_verified_payload(
            cdm.version().to_owned(),
            staged.path().to_owned(),
            marker.library_sha512.clone(),
            marker.manifest_sha512.clone(),
        )
    });
    let write_cdm = direct_root_cdm.as_ref().unwrap_or(cdm);

    if patcher.writes_transactionally() {
        match perform_patch(browser, write_cdm, patcher, &cdm_target, &marker) {
            PatchAttempt::Success => {}
            PatchAttempt::FailedBeforeModification(error)
            | PatchAttempt::ModifiedOriginal(error) => return Err(error),
        }
    } else {
        let snapshot = take_snapshot(browser, options, version_before.as_deref())?;
        match perform_patch(browser, write_cdm, patcher, &cdm_target, &marker) {
            PatchAttempt::Success => {}
            PatchAttempt::FailedBeforeModification(patch_err) => {
                let _ = snapshot.commit();
                return Err(patch_err);
            }
            PatchAttempt::ModifiedOriginal(patch_err) => {
                if let Err(restore_err) = snapshot.restore() {
                    return Err(restore_err.with_source(patch_err));
                }
                return Err(patch_err);
            }
        }
        snapshot.commit()?;
    }

    let version_after = version_before.clone();
    Ok(PatchOutcome {
        browser_name: browser.name().to_string(),
        version_before,
        version_after,
        cdm_version: cdm.version().to_string(),
        duration: started.elapsed(),
        dry_run: false,
    })
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
        let target = patcher.cdm_target(browser.install_path())?;
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
    #[cfg(target_os = "macos")]
    {
        let (framework, version) = macos::resolve_privileged_layout(
            browser.install_path(),
            browser.framework_name.as_deref(),
        )?;
        argv.push("--framework-name".into());
        argv.push(framework);
        argv.push("--framework-version".into());
        argv.push(version);
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(framework) = &browser.framework_name {
        argv.push("--framework-name".into());
        argv.push(framework.clone());
    }
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
) -> PatchAttempt {
    let managed_write =
        match patcher.write_managed_cdm(browser.install_path(), cdm.cdm_dir(), marker) {
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
mod tests {
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
            replace_external_cdm: false,
            dry_run: false,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            as_root: false,
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
        let out =
            patch_browser(&browser, &cdm, &MockPatcher::default(), &opts).expect("must succeed");
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
        let outcome = perform_patch(
            &browser,
            &cdm,
            &UnknownBundleMock,
            &install.join("WidevineCdm"),
            &marker,
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
        let outcome = perform_patch(&browser, &cdm, &PartialFailMock, &partial, &marker);
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
        #[cfg(target_os = "macos")]
        fs::create_dir_all(
            install.join("Contents/Frameworks/Test Framework.framework/Versions/1.0/Libraries"),
        )
        .expect("create synthetic macOS framework layout");
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
        #[cfg(target_os = "macos")]
        fs::create_dir_all(
            install.join("Contents/Frameworks/Exact Framework.framework/Versions/2.0/Libraries"),
        )
        .unwrap();
        let cdm = make_cached_cdm(&cdm_root, "9.8.7.6");
        let mut browser = make_browser(install.clone());
        browser.name = "Parent Custom".into();
        browser.kind = BrowserKind::Known;
        browser.framework_name = Some("Exact Framework".into());
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
        assert!(argv
            .windows(2)
            .any(|v| v == ["--framework-name", "Exact Framework"]));
        #[cfg(target_os = "macos")]
        assert!(argv.windows(2).any(|v| v == ["--framework-version", "2.0"]));
        assert!(argv.contains(&"--force".to_string()));
        assert!(argv.contains(&"--replace-external-cdm".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn privileged_handoff_resolves_missing_custom_framework_in_parent() {
        let tmp = TempDir::new().unwrap();
        let root = canonical_fixture_root(tmp.path());
        let install = root.join("Custom.app");
        fs::create_dir_all(
            install.join("Contents/Frameworks/Selected Framework.framework/Versions/1.0/Libraries"),
        )
        .unwrap();
        let cdm = make_cached_cdm(&root.join("cache"), "1.0");
        let mut browser = make_browser(install);
        browser.framework_name = None;

        let marker = ownership::marker_for_cached(&cdm).unwrap();
        let argv = privileged_patch_argv(
            "/usr/local/bin/silvervine",
            &browser,
            &cdm,
            &marker,
            &PatchOptions::default(),
        )
        .unwrap();
        assert!(argv
            .windows(2)
            .any(|args| args == ["--framework-name", "Selected Framework"]));
        assert!(argv
            .windows(2)
            .any(|args| args == ["--framework-version", "1.0"]));
    }

    #[test]
    fn privileged_handoff_preserves_known_browser_kind_token() {
        let tmp = TempDir::new().unwrap();
        let root = canonical_fixture_root(tmp.path());
        let install = root.join("helium");
        fs::create_dir_all(&install).unwrap();
        #[cfg(target_os = "macos")]
        fs::create_dir_all(
            install.join("Contents/Frameworks/Test Framework.framework/Versions/1.0/Libraries"),
        )
        .unwrap();
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

        let reports =
            run_batch_with_processes(&[&helium, &thorium], &cdm, &patcher, &options, || {
                let capture = captures.get();
                captures.set(capture + 1);
                if capture == 0 {
                    discovery::ProcessSnapshot::from_executables([])
                } else {
                    discovery::ProcessSnapshot::from_executables([thorium
                        .install_path()
                        .join("thorium")])
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
}
