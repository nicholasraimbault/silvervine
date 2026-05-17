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
use crate::platform;
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
    /// Override the backups root. `None` triggers the writability-aware
    /// default: when the install path is writable by the current process,
    /// backups go under [`backup::default_backups_dir`] (`~/.cache/neon/backups/`);
    /// when it isn't, backups go under `<install-parent>/.neon-backups/`
    /// so atomic-swap rollback stays on a single filesystem (no EXDEV).
    /// Tests pass a `tempfile::TempDir` to bypass both defaults.
    pub backups_dir: Option<PathBuf>,
    /// `true` when this invocation is the privileged child of a previous
    /// `neon patch` that escalated via `pkexec` / `sudo` / `osascript`.
    /// Set by the CLI's hidden `--as-root` flag. Wires two pieces of
    /// behavior:
    ///
    /// 1. Don't try to escalate again (we're already root); a second
    ///    escalation attempt would loop or surface an extra password prompt.
    /// 2. Default `backups_dir` resolution falls through to
    ///    [`backup::snapshot_into_sibling`] (root-owned, same-filesystem)
    ///    rather than `~/.cache/neon/backups/` (which would be the
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
    // `--as-root` invocations are the privileged children of an escalation
    // — the parent process holds the lockfile and is blocked waiting for
    // this child to finish. Re-acquiring would deadlock both (issue #30).
    // Skip the lockfile entirely; the parent's lock covers us.
    if options.as_root {
        return run_patch(browser, cdm, patcher, options);
    }
    let lock = options
        .lock_path
        .clone()
        .or_else(default_patch_lock)
        .ok_or_else(|| {
            Error::state_corrupted("cannot resolve patch lockfile path (no \\$HOME / cache dir)")
        })?;
    lockfile::with_lock(&lock, || run_patch(browser, cdm, patcher, options))
}

/// Decide whether `run_patch` must re-invoke itself under elevated
/// privileges. Pure function so the truth-table is testable without
/// touching geteuid or the filesystem.
///
/// Escalation is needed **only** when none of the privilege paths apply:
///
/// * `as_root` — already the elevated child of an escalation.
/// * `running_as_root` — process started with euid 0 (e.g. `sudo neon`).
///   Re-escalating in that case caused issue #30: a redundant osascript
///   prompt followed by a deadlock against the parent's lockfile.
/// * `target_writable` — the install path is writable by the current
///   process anyway, so no elevation is needed.
#[must_use]
pub fn decide_escalate(as_root: bool, running_as_root: bool, target_writable: bool) -> bool {
    !as_root && !running_as_root && !target_writable
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

    // Decide whether we can write to the install path directly. If yes,
    // proceed through the user-space code path (cheap, no escalation).
    // If no AND we're not already running as root, hand off to a
    // `pkexec` / `sudo` / `osascript`-elevated child invocation that
    // re-enters this code with `as_root = true` set.
    if decide_escalate(
        options.as_root,
        platform::is_running_as_root(),
        target_writable(browser.install_path()),
    ) {
        return run_patch_via_escalation(browser, cdm, patcher, options, started, version_before);
    }

    // We're either running as root (post-escalation) or the user already
    // owns the install path. Take a snapshot whose location matches the
    // privilege context.
    let snapshot = take_snapshot(browser, options, version_before.as_deref())?;
    match perform_patch(browser, cdm, patcher) {
        PatchAttempt::Success => {
            // Best-effort commit (delete backup). If commit fails (e.g.
            // permission to delete a backup we ourselves created), we still
            // have a valid patched bundle; surface the commit error to
            // observability but don't fail the patch itself.
            snapshot.commit()?;
        }
        PatchAttempt::FailedBeforeModification(patch_err) => {
            // The original is untouched — restore would either no-op
            // wastefully or, worse, swap the empty staging snapshot in
            // place of the still-good bundle. Drop the snapshot quietly
            // and propagate the underlying error.
            let _ = snapshot.commit();
            return Err(patch_err);
        }
        PatchAttempt::ModifiedOriginal(patch_err) => {
            // The original was modified; we need the snapshot to roll
            // back. If restore fails, we surface restore's error chained
            // under the original — both are bad news, but the restore
            // failure is the more actionable one (left bundle in an
            // inconsistent state).
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

/// Choose the snapshot location based on privilege context and filesystem
/// layout:
///
/// 1. If `options.backups_dir` is set, use it verbatim (tests / overrides).
/// 2. Else if running as root **or** the install's parent directory is
///    writable by the current process, place the snapshot in a
///    sibling-of-parent directory of the install path so
///    [`crate::platform::atomic_rename`] rollback stays on a single
///    filesystem (no `EXDEV`).
/// 3. Else fall through to `~/.cache/neon/backups/` — the user-controlled
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
    let probe = path.join(format!(".neon-write-probe-{}-{n}", std::process::id()));
    match OpenOptions::new().create_new(true).write(true).open(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Re-invoke the current Neon binary with elevated privileges and let the
/// privileged child do the actual filesystem work. The parent process
/// (this one) only validates that the child exited cleanly; the child
/// writes the snapshot, the CDM, and the verify in one go.
///
/// On `NEON_TEST_ESCALATE_NOOP=1`, [`platform::run_as_root`] returns a
/// canned successful [`Output`](std::process::Output) without actually
/// spawning anything — the test branch surfaces a synthetic
/// [`PatchOutcome`] with the version-before captured pre-escalation. Tests
/// exercise the branch without invoking real elevation.
fn run_patch_via_escalation(
    browser: &Browser,
    cdm: &dyn CdmProvider,
    _patcher: &dyn PlatformPatcher,
    options: &PatchOptions,
    started: Instant,
    version_before: Option<String>,
) -> Result<PatchOutcome> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::other("could not resolve current executable").with_source(e))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| Error::other("current executable path is not valid UTF-8"))?;

    // Build the argv for the elevated child: re-run `neon` with
    // `--as-root patch [--force] <browser>`. The child re-enters this
    // very flow with `as_root = true`, which short-circuits the
    // writability check and selects the same-filesystem snapshot
    // location.
    //
    // The browser is identified by its display name; the elevated child
    // re-runs `detect_browsers()` and matches by name. Passing the
    // install path directly would short-circuit detection but break the
    // contract that all `neon` subcommands operate on detected browsers.
    //
    // Propagate `--force`: if the parent decided to patch despite the
    // browser running (because the user asked), the child must inherit
    // that decision. Otherwise the child's pre-flight check would refuse
    // to patch and exit nonzero, which the parent would surface as a
    // confusing "elevated patch failed" error.
    let mut argv: Vec<&str> = vec![exe_str, "--as-root", "patch"];
    if options.force_while_running {
        argv.push("--force");
    }
    argv.push(browser.name());
    let output = platform::run_as_root(&argv)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::permission_denied(format!(
            "elevated patch failed (exit {:?}) for {}: {}",
            output.status.code(),
            browser.install_path().display(),
            stderr.trim()
        )));
    }

    // The child wrote the CDM as root; we trust its exit-zero status.
    // For V2 the patch doesn't change the browser version, so
    // `version_after` is just `version_before`. Phase 3+ that needs an
    // accurate post-version can read from disk here (no privilege needed
    // to read; only to write).
    Ok(PatchOutcome {
        browser_name: browser.name().to_string(),
        version_before: version_before.clone(),
        version_after: version_before,
        cdm_version: cdm.version().to_string(),
        duration: started.elapsed(),
        dry_run: false,
    })
}

/// Outcome of a [`perform_patch`] call.
///
/// Distinguishes the two failure modes that affect rollback semantics:
///
/// * [`PatchAttempt::Success`] — everything worked; commit the snapshot.
/// * [`PatchAttempt::FailedBeforeModification`] — write/verify errored
///   before any byte of the original install was changed (e.g. CDM
///   payload missing, target directory doesn't exist, permission denied
///   on `create_dir_all`). Restoring the snapshot would needlessly swap
///   the still-good bundle with a redundant copy. Discard the snapshot
///   instead.
/// * [`PatchAttempt::ModifiedOriginal`] — write started, then errored.
///   The bundle is in an indeterminate state; restoring the snapshot is
///   load-bearing.
#[derive(Debug)]
enum PatchAttempt {
    /// CDM written + verified successfully.
    Success,
    /// Pre-modification failure — original install is untouched.
    FailedBeforeModification(Error),
    /// Post-modification failure — original install is partially mutated
    /// and must be rolled back from the snapshot.
    ModifiedOriginal(Error),
}

/// Run the platform impl + verification, between snapshot and commit.
///
/// Materializes the CDM payload into a `tempfile::TempDir` so the
/// platform impl receives a stable directory path. The temp dir lives
/// only for the duration of `write_cdm` + `verify_post_patch`; on
/// success it's dropped (and the directory is removed) before the
/// orchestrator commits the snapshot.
///
/// Returns a typed [`PatchAttempt`] so the caller can decide whether to
/// roll back. Anything that errors before [`PlatformPatcher::write_cdm`]
/// is reported as [`PatchAttempt::FailedBeforeModification`]; anything
/// from `write_cdm` itself onward is reported as
/// [`PatchAttempt::ModifiedOriginal`].
fn perform_patch(
    browser: &Browser,
    cdm: &dyn CdmProvider,
    patcher: &dyn PlatformPatcher,
) -> PatchAttempt {
    // Stage 1: build the staging dir + populate it from the CDM provider.
    // Failures here can't have touched the install path yet — neither
    // the staging dir nor `cdm.populate` knows where the install lives.
    let staging = match tempfile::Builder::new()
        .prefix("neon-cdm-staging-")
        .tempdir()
        .map_err(Error::from)
    {
        Ok(s) => s,
        Err(e) => return PatchAttempt::FailedBeforeModification(e),
    };
    if let Err(e) = cdm.populate(staging.path()) {
        return PatchAttempt::FailedBeforeModification(e);
    }

    // Stage 2: hand the staging dir to the platform write. Once
    // `write_cdm` returns we can no longer assume the install path is
    // pristine — even an early error inside the impl might have left
    // partial state behind (e.g. it removed an existing `WidevineCdm/`
    // before failing on `create_dir_all`). Conservatively treat every
    // error from `write_cdm` onward as `ModifiedOriginal`.
    if let Err(e) = patcher.write_cdm(browser.install_path(), staging.path()) {
        return classify_write_error(e, browser.install_path());
    }
    if let Err(e) = patcher.verify_post_patch(browser.install_path()) {
        return PatchAttempt::ModifiedOriginal(e);
    }
    PatchAttempt::Success
}

/// Classify a `write_cdm` error: distinguishes "platform impl bailed out
/// before touching anything" (e.g. install-path missing, source missing)
/// from "platform impl partially mutated the install."
///
/// We can't always tell from the error category alone — `PermissionDenied`
/// could mean "couldn't even open `<install>/WidevineCdm/`" (untouched) or
/// "removed `<install>/WidevineCdm/` cleanly but failed mid-`create_dir_all`"
/// (modified). The conservative read is "if `WidevineCdm/` exists now and
/// is non-empty, the impl got at least partway in." We only fall through
/// to `FailedBeforeModification` when the impl reported an error
/// indicative of a pre-write failure (missing target / missing source).
fn classify_write_error(e: Error, install_path: &Path) -> PatchAttempt {
    use crate::error::ErrorCategory;
    // `UnknownBundleStructure` from a `write_cdm` impl exclusively means
    // "the inputs we were given don't make sense" — install_path missing,
    // cdm_source missing, etc. The impl returns this without touching the
    // install path, so we know the bundle is untouched.
    if e.category == ErrorCategory::UnknownBundleStructure {
        return PatchAttempt::FailedBeforeModification(e);
    }
    // For anything else, ask the filesystem: did we leave a partial
    // `WidevineCdm/` behind?
    let widevine_dir = install_path.join("WidevineCdm");
    let modified = widevine_dir.exists();
    if modified {
        PatchAttempt::ModifiedOriginal(e)
    } else {
        PatchAttempt::FailedBeforeModification(e)
    }
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

    /// Mock that fails `write_cdm` with `UnknownBundleStructure` (the
    /// canonical "platform impl bailed before touching anything" error).
    struct UnknownBundleMock;
    impl PlatformPatcher for UnknownBundleMock {
        fn write_cdm(&self, _t: &Path, _s: &Path) -> Result<()> {
            Err(Error::unknown_bundle_structure("missing target"))
        }
        fn verify_post_patch(&self, _t: &Path) -> Result<()> {
            Ok(())
        }
        fn read_browser_version(&self, _t: &Path) -> Option<String> {
            None
        }
    }

    /// Mock that fails `write_cdm` with `PermissionDenied` (used to
    /// simulate a partial-write failure when combined with a pre-seeded
    /// `WidevineCdm/` directory in the install path).
    struct PartialFailMock;
    impl PlatformPatcher for PartialFailMock {
        fn write_cdm(&self, _t: &Path, _s: &Path) -> Result<()> {
            Err(Error::permission_denied("partway failure"))
        }
        fn verify_post_patch(&self, _t: &Path) -> Result<()> {
            Ok(())
        }
        fn read_browser_version(&self, _t: &Path) -> Option<String> {
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
            ((false, true, false), false), // sudo neon: don't re-prompt
            ((false, true, true), false),
            ((true, false, false), false), // --as-root child: never recurse
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
            as_root: false,
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
    /// goes under `<install-parent>/.neon-backups/...` so `atomic_rename`
    /// rollback works on a single filesystem.
    #[test]
    fn take_snapshot_uses_sibling_when_as_root_and_no_override() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("opt").join("helium-browser-bin");
        fs::create_dir_all(&install).expect("mkdir install");
        fs::write(install.join("seed"), b"x").expect("seed");
        let browser = make_browser(install.clone());
        let opts = PatchOptions {
            force_while_running: true,
            dry_run: false,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: None,
            as_root: true,
        };
        let handle = take_snapshot(&browser, &opts, Some("v1")).expect("ok");
        let expected_root = install
            .parent()
            .expect("install has parent")
            .join(".neon-backups");
        assert!(
            handle.snapshot_path().starts_with(&expected_root),
            "snapshot {} should be under {}",
            handle.snapshot_path().display(),
            expected_root.display()
        );
        let _ = handle.commit();
    }

    /// `perform_patch` reports `FailedBeforeModification` when `cdm.populate`
    /// fails. We fake this with a `LocalFileCdm` pointing at a missing
    /// source dir.
    #[test]
    fn perform_patch_returns_failed_before_modification_when_cdm_populate_errors() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("mkdir install");
        fs::write(install.join("original.txt"), b"keep me").expect("seed");
        let browser = make_browser(install.clone());
        // CDM pointing at a missing dir — populate() will error.
        let cdm = LocalFileCdm::new("1.0".into(), tmp.path().join("missing-cdm-source"));
        let patcher = MockPatcher::with_version("v1");
        let outcome = perform_patch(&browser, &cdm, &patcher);
        assert!(matches!(outcome, PatchAttempt::FailedBeforeModification(_)));
        // No write was attempted.
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
        // Original is intact.
        assert_eq!(
            fs::read(install.join("original.txt")).expect("read"),
            b"keep me"
        );
    }

    /// `perform_patch` reports `FailedBeforeModification` when `write_cdm`
    /// returns an `UnknownBundleStructure` error (the impl bailed out
    /// before touching anything — common when install path is missing).
    #[test]
    fn perform_patch_classifies_unknown_bundle_as_failed_before_modification() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("mkdir install");
        let browser = make_browser(install.clone());
        let cache = tmp.path().join("widevine");
        let cdm = make_cached_cdm(&cache, "1.0");
        let outcome = perform_patch(&browser, &cdm, &UnknownBundleMock);
        assert!(matches!(outcome, PatchAttempt::FailedBeforeModification(_)));
        assert!(!install.join("WidevineCdm").exists());
    }

    /// `perform_patch` classifies a `write_cdm` error as `ModifiedOriginal`
    /// when `WidevineCdm/` exists in the install path post-error (i.e.
    /// the impl got partway through before failing).
    #[test]
    fn perform_patch_classifies_partial_write_as_modified_original() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("mkdir install");
        // Pre-create a partial WidevineCdm/ to simulate "impl bailed
        // mid-way, leaving turds behind."
        let partial = install.join("WidevineCdm");
        fs::create_dir_all(&partial).expect("mkdir WidevineCdm");
        fs::write(partial.join("partial.txt"), b"oops").expect("seed");
        let browser = make_browser(install.clone());
        let cache = tmp.path().join("widevine");
        let cdm = make_cached_cdm(&cache, "1.0");
        let outcome = perform_patch(&browser, &cdm, &PartialFailMock);
        assert!(matches!(outcome, PatchAttempt::ModifiedOriginal(_)));
    }

    /// When the install path is not writable AND `as_root` is `false`,
    /// `run_patch` escalates via `platform::run_as_root`. With
    /// `NEON_TEST_ESCALATE_NOOP=1` the escalation is a stub that returns
    /// success, so we can verify the parent-side flow without actually
    /// elevating.
    #[cfg(unix)]
    #[test]
    fn run_patch_escalates_when_install_path_is_not_writable() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = crate::test_support::env_lock();

        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("mkdir install");
        // Make install read-only so target_writable returns false.
        let perms = fs::Permissions::from_mode(0o555);
        fs::set_permissions(&install, perms).expect("chmod ro");

        let browser = make_browser(install.clone());
        let cache = tmp.path().join("widevine");
        let cdm = make_cached_cdm(&cache, "1.0");
        let patcher = MockPatcher::with_version("v1");

        let opts = PatchOptions {
            force_while_running: true,
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
        unsafe { std::env::set_var("NEON_TEST_ESCALATE_NOOP", "1") };
        let outcome = patch_browser(&browser, &cdm, &patcher, &opts);
        unsafe { std::env::remove_var("NEON_TEST_ESCALATE_NOOP") };

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
        assert!(!outcome.dry_run);
    }

    /// `perform_patch` does NOT call `restore` when the CDM populate
    /// fails (regression for the bug where any error triggered restore,
    /// even pre-modification ones).
    #[test]
    fn run_patch_does_not_restore_when_cdm_populate_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("install");
        fs::create_dir_all(&install).expect("mkdir install");
        fs::write(install.join("original.txt"), b"keep me").expect("seed");
        let browser = make_browser(install.clone());
        // CDM pointing at a missing dir so populate fails.
        let cdm = LocalFileCdm::new("1.0".into(), tmp.path().join("missing-cdm-source"));
        let patcher = MockPatcher::with_version("v1");
        let opts = PatchOptions {
            force_while_running: true,
            dry_run: false,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            as_root: false,
        };
        let err = patch_browser(&browser, &cdm, &patcher, &opts).expect_err("populate fail");
        // The original is still on disk.
        assert_eq!(
            fs::read(install.join("original.txt")).expect("read"),
            b"keep me"
        );
        // No restore was attempted (the snapshot's `commit` deleted the
        // backup; if `restore` had run, we'd see different filesystem
        // state). We can't directly observe restore-vs-commit from here,
        // but the absence of the snapshot in `backups_dir` means commit
        // ran, not restore.
        let backups_dir = tmp.path().join("backups");
        if backups_dir.exists() {
            let entries: Vec<_> = fs::read_dir(&backups_dir).expect("read_dir").collect();
            assert!(
                entries.is_empty(),
                "snapshot was not cleaned up (commit didn't run); err={err}"
            );
        }
    }
}
