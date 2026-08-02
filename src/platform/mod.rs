//! Platform-specific paths, privilege escalation, and root-execution helpers.
//!
//! This module is the **single source of truth** for anything that varies
//! between Linux and macOS at the OS level. Other modules (browsers,
//! patch, daemon, migration) consume the abstractions defined here so they
//! never need their own `#[cfg]` ladders.
//!
//! ## What lives here
//!
//! * [`PlatformPaths`] — XDG / Apple-conventional cache + config + apps roots.
//! * [`run_as_root`] — execute an arbitrary command with elevated privileges.
//!   Returns the captured [`Output`] regardless of exit status; callers
//!   inspect `status.success()` and the stderr text for diagnostics.
//! * [`atomic_rename`] — APFS / ext4-aware directory swap with a two-step
//!   fallback on filesystems without native exchange support.
//! * `atomic_write` — same-directory temporary-file replacement for internal
//!   state and registration files.
//!
//! ## What does NOT live here
//!
//! * Bundle write semantics, `xattr -cr`, `codesign` — those are
//!   patch-flow concerns and live in `crate::patch::macos`.
//! * Daemon registration (`LaunchAgent` / systemd-user) — Phase 3.
//! * Sleep/wake hooks — Phase 3.
//!
//! ## Test strategy
//!
//! Every public function here either takes injectable arguments (so tests
//! pass `tempfile`-synthesized paths) or returns information that does
//! not require real privilege. The function that genuinely shells out
//! ([`run_as_root`]) is gated by an env var
//! (`SILVERVINE_TEST_ESCALATE_NOOP=1`) so CI never actually prompts for a
//! password.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::error::{Error, Result};

pub mod process;

#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use unsupported as imp;

/// Cross-platform "where do I put files" trait.
///
/// Implementations:
///
/// * Linux (`LinuxPaths`): XDG-compliant.
/// * macOS (`MacosPaths`): `~/Library/...`.
///
/// Tests that need to assert against the trait without a real `$HOME` use
/// the per-platform impl directly, since the methods are pure (no I/O).
pub trait PlatformPaths {
    /// Cache directory — Silvervine's CDM cache + backups + lockfiles live here.
    /// Equivalent to `~/.cache/silvervine/` on Linux, `~/Library/Caches/silvervine/` on macOS.
    fn cache_dir() -> PathBuf;

    /// Config directory — `~/.config/silvervine/` (Linux) or
    /// `~/Library/Application Support/silvervine/` (macOS). State files and
    /// the user-edited `config.toml` live here.
    fn config_dir() -> PathBuf;

    /// One or more roots where applications are typically installed.
    /// Used by browser auto-discovery.
    ///
    /// * macOS: `["/Applications"]`.
    /// * Linux: `["/opt", "/usr/lib", "/usr/lib64", "/usr/local/lib"]`.
    fn applications_dirs() -> Vec<PathBuf>;
}

/// Private struct used as the trait carrier for the active platform impl.
///
/// Other modules that want to read paths import [`cache_dir`] /
/// [`config_dir`] / [`applications_dirs`] directly rather than naming
/// this type.
#[doc(hidden)]
pub struct ActivePlatform;

impl PlatformPaths for ActivePlatform {
    fn cache_dir() -> PathBuf {
        imp::cache_dir()
    }
    fn config_dir() -> PathBuf {
        imp::config_dir()
    }
    fn applications_dirs() -> Vec<PathBuf> {
        imp::applications_dirs()
    }
}

/// Cache directory for the host platform. Equivalent to
/// `<ActivePlatform as PlatformPaths>::cache_dir()` but exposed as a
/// free function for ergonomics.
#[must_use]
pub fn cache_dir() -> PathBuf {
    <ActivePlatform as PlatformPaths>::cache_dir()
}

/// Config directory for the host platform.
#[must_use]
pub fn config_dir() -> PathBuf {
    <ActivePlatform as PlatformPaths>::config_dir()
}

/// Applications directories for the host platform.
#[must_use]
pub fn applications_dirs() -> Vec<PathBuf> {
    <ActivePlatform as PlatformPaths>::applications_dirs()
}

/// Execute `command` with elevated privileges and capture its output.
///
/// `command` is the full argv of the program to run (`command[0]` is
/// the executable, `command[1..]` are its arguments). The function does
/// **not** quote or shell-escape — it spawns the elevation tool with
/// the args directly, so any user-controlled input must already be
/// sanitized by the caller.
///
/// On success the captured [`Output`] is returned regardless of
/// `output.status` — callers inspect `status.success()` for the
/// underlying command's success.
///
/// # Errors
///
/// * [`crate::ErrorCategory::UnsupportedPlatform`] on platforms with no
///   known elevation path.
/// * [`crate::ErrorCategory::Other`] if the elevation tool itself fails
///   to spawn (e.g. neither `pkexec` nor `sudo` are installed on Linux).
///
/// # Test mode
///
/// If `SILVERVINE_TEST_ESCALATE_NOOP=1` is set, this function returns a fake
/// "successful" [`Output`] with empty stdout/stderr without spawning a
/// subprocess.
pub fn run_as_root(command: &[&str]) -> Result<Output> {
    // Precondition: reject empty command before considering test-mode
    // short-circuiting. Empty argv is always a programmer error.
    if command.is_empty() {
        return Err(Error::other("run_as_root called with empty command"));
    }
    if std::env::var_os("SILVERVINE_TEST_ESCALATE_NOOP").is_some() {
        return Ok(noop_output());
    }
    imp::run_as_root(command)
}

/// Run a shell script under a single elevated invocation.
///
/// Use this when you have multiple privileged operations to perform —
/// it batches them all into one `pkexec` / `sudo` / `osascript` prompt
/// instead of prompting per operation. Critical for UX: a flow that
/// needs to remove three systemd units and reload should not fire four
/// password dialogs.
///
/// `script` is passed to `sh -c` (Linux) or to `osascript`'s shell-out
/// (macOS), so it must be POSIX-shell-safe. Caller is responsible for
/// quoting paths that may contain whitespace or shell metacharacters.
///
/// Honors `SILVERVINE_TEST_ESCALATE_NOOP=1` like [`run_as_root`].
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] if `script` is empty after trimming.
/// * [`crate::ErrorCategory::UnsupportedPlatform`] on platforms with no
///   known elevation path.
/// * [`crate::ErrorCategory::Other`] if the elevation tool itself fails
///   to spawn (e.g. neither `pkexec` nor `sudo` are installed on Linux).
pub fn run_as_root_script(script: &str) -> Result<Output> {
    if script.trim().is_empty() {
        return Err(Error::other("run_as_root_script called with empty script"));
    }
    if std::env::var_os("SILVERVINE_TEST_ESCALATE_NOOP").is_some() {
        return Ok(noop_output());
    }
    imp::run_as_root(&["sh", "-c", script])
}

/// Exchange two existing filesystem entries.
///
/// Linux uses `renameat2(RENAME_EXCHANGE)` and macOS uses
/// `renameatx_np(RENAME_SWAP)`. On filesystems without native exchange support,
/// a recoverable three-rename fallback preserves the same successful result:
///
/// 1. `dst` moves to an exclusively-created sibling scratch directory.
/// 2. `src` moves to `dst`.
/// 3. the saved destination moves to `src`.
///
/// The fallback is not crash-atomic. Errors trigger best-effort restoration;
/// if restoration itself fails, the returned error identifies the preserved
/// scratch path.
///
/// If `dst` does not exist, this performs a plain `rename(src, dst)`.
///
/// # Errors
///
/// * [`crate::ErrorCategory::PermissionDenied`] if writes to either path
///   are rejected.
/// * [`crate::ErrorCategory::Other`] for any other I/O failure.
pub fn atomic_rename(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    imp::atomic_rename(src, dst)
}

fn fallback_exchange(src: &Path, dst: &Path) -> Result<()> {
    let parent = dst
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let scratch = tempfile::Builder::new()
        .prefix(".silvervine-swap-")
        .tempdir_in(parent)
        .map_err(|error| {
            Error::from(error).with_context(format!(
                "could not create exchange scratch directory beside {}",
                dst.display()
            ))
        })?
        .keep();
    let backup = scratch.join("destination");

    if let Err(error) = std::fs::rename(dst, &backup) {
        cleanup_exchange_scratch(&scratch);
        return Err(Error::from(error).with_context(format!(
            "fallback exchange could not move {} aside",
            dst.display()
        )));
    }

    if let Err(exchange_error) = std::fs::rename(src, dst) {
        return match std::fs::rename(&backup, dst) {
            Ok(()) => {
                cleanup_exchange_scratch(&scratch);
                Err(Error::from(exchange_error).with_context(format!(
                    "fallback exchange could not move {} into {}",
                    src.display(),
                    dst.display()
                )))
            }
            Err(restore_error) => Err(Error::from(restore_error)
                .with_context(format!(
                    "fallback exchange failed and could not restore {}; the original remains at {}",
                    dst.display(),
                    backup.display()
                ))
                .with_source(exchange_error)),
        };
    }

    if let Err(finish_error) = std::fs::rename(&backup, src) {
        if let Err(rollback_error) = std::fs::rename(dst, src) {
            return Err(Error::from(rollback_error)
                .with_context(format!(
                    "fallback exchange could not roll back; the original destination remains at {} and the new destination at {}",
                    backup.display(),
                    dst.display()
                ))
                .with_source(finish_error));
        }

        return match std::fs::rename(&backup, dst) {
            Ok(()) => {
                cleanup_exchange_scratch(&scratch);
                Err(Error::from(finish_error).with_context(format!(
                    "fallback exchange could not move the original destination into {}; original paths were restored",
                    src.display()
                )))
            }
            Err(restore_error) => {
                if let Err(republish_error) = std::fs::rename(src, dst) {
                    return Err(Error::from(republish_error)
                        .with_context(format!(
                            "fallback exchange recovery failed; the original destination remains at {}, the new source at {}, and {} is missing",
                            backup.display(),
                            src.display(),
                            dst.display()
                        ))
                        .with_source(restore_error));
                }
                Err(Error::from(restore_error)
                    .with_context(format!(
                        "fallback exchange could not restore the original destination; it remains at {}, while the new destination is valid at {}",
                        backup.display(),
                        dst.display()
                    ))
                    .with_source(finish_error))
            }
        };
    }

    cleanup_exchange_scratch(&scratch);
    Ok(())
}

fn cleanup_exchange_scratch(path: &Path) {
    if let Err(error) = std::fs::remove_dir(path) {
        tracing::warn!(
            target: "silvervine::platform",
            path = %path.display(),
            error = %error,
            "could not remove empty exchange scratch directory"
        );
    }
}

/// Replace a file from a same-directory temporary file.
///
/// The parent directory is created when needed. Writing and syncing happen
/// before the atomic rename, so readers never observe a partially written
/// state file.
pub(crate) fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| {
        Error::from(error).with_context(format!("could not create {}", parent.display()))
    })?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        Error::from(error).with_context(format!(
            "could not create temporary file beside {}",
            path.display()
        ))
    })?;
    temporary.write_all(body).map_err(|error| {
        Error::from(error).with_context(format!("could not write {}", path.display()))
    })?;
    temporary.as_file_mut().sync_all().map_err(|error| {
        Error::from(error).with_context(format!("could not sync {}", path.display()))
    })?;
    temporary.persist(path).map_err(|error| {
        Error::from(error.error).with_context(format!("could not replace {}", path.display()))
    })?;
    Ok(())
}

/// Whether the current process is already running with effective UID 0
/// (e.g. invoked under `sudo`). Used by [`crate::patch`] to short-circuit
/// the re-escalation decision — escalating again would spawn an osascript
/// / pkexec dialog redundantly, and on macOS the child blocks indefinitely
/// on the parent's lockfile (issue #30).
///
/// Returns `false` on non-Unix platforms (no concept of euid).
#[must_use]
pub fn is_running_as_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` is a thread-safe POSIX syscall with no
        // arguments; it never fails per its spec.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Format an [`ExitStatus`](std::process::ExitStatus) as a short
/// human-readable string for error messages. Prefers the Unix exit
/// code; falls back to a signal description when the child was killed
/// (e.g. the user cancelled an `osascript` admin dialog, which the OS
/// surfaces as a signal rather than an exit code).
///
/// Without this, format strings using `{:?}` on `status.code()` print
/// `"None"` for signal-killed children, which is what issue-#30-style
/// debugging needs to avoid.
#[must_use]
pub fn format_exit_status(status: std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exit {code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return format!("killed by signal {sig}");
        }
    }
    "terminated".to_string()
}

/// Construct a no-op [`Output`] used when `SILVERVINE_TEST_ESCALATE_NOOP=1`.
fn noop_output() -> Output {
    use std::os::unix::process::ExitStatusExt;
    Output {
        status: std::process::ExitStatus::from_raw(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::LinuxPaths;

#[cfg(target_os = "macos")]
pub use macos::MacosPaths;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported {
    //! Stub implementation for platforms outside V1's scope (e.g. Windows,
    //! BSD). All operations return `UnsupportedPlatform` errors.

    use std::path::{Path, PathBuf};
    use std::process::Output;

    use crate::error::{Error, Result};

    pub(super) fn cache_dir() -> PathBuf {
        PathBuf::new()
    }
    pub(super) fn config_dir() -> PathBuf {
        PathBuf::new()
    }
    pub(super) fn applications_dirs() -> Vec<PathBuf> {
        Vec::new()
    }
    pub(super) fn run_as_root(_command: &[&str]) -> Result<Output> {
        Err(Error::unsupported_platform(
            "run_as_root is only implemented on Linux and macOS",
        ))
    }
    pub(super) fn atomic_rename(_src: &Path, _dst: &Path) -> Result<()> {
        Err(Error::unsupported_platform(
            "atomic_rename is only implemented on Linux and macOS",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SILVERVINE_TEST_ESCALATE_NOOP=1` short-circuits both elevation entry
    /// points so CI never prompts for a password.
    #[test]
    fn noop_short_circuit_in_test_mode() {
        // SAFETY: setting an env var is a process-wide mutation; this
        // test takes a small risk of interfering with parallel tests in
        // the same module, but `cargo test` runs each `#[test]` in its
        // own thread with no other escalate calls.
        // SAFETY: env mutations are permitted in a single-threaded test
        // section; we restore the previous value below.
        unsafe { std::env::set_var("SILVERVINE_TEST_ESCALATE_NOOP", "1") };
        let out = run_as_root(&["echo", "hi"]).expect("noop ok");
        assert!(out.status.success());
        // SAFETY: restore the env to its prior unset state so other tests
        // (or future test runs in the same process) aren't affected.
        unsafe { std::env::remove_var("SILVERVINE_TEST_ESCALATE_NOOP") };
    }

    /// `run_as_root` rejects an empty command without elevating.
    #[test]
    fn run_as_root_rejects_empty_command() {
        let r = run_as_root(&[]);
        assert!(r.is_err(), "empty command must error");
    }

    #[test]
    fn format_exit_status_normal_exit() {
        use std::os::unix::process::ExitStatusExt;
        let s = std::process::ExitStatus::from_raw(0);
        assert_eq!(format_exit_status(s), "exit 0");
    }

    #[test]
    fn format_exit_status_nonzero_exit() {
        use std::os::unix::process::ExitStatusExt;
        // raw 256 = exit code 1 on Linux (status >> 8).
        let s = std::process::ExitStatus::from_raw(256);
        assert_eq!(format_exit_status(s), "exit 1");
    }

    #[test]
    fn format_exit_status_signal_killed() {
        use std::os::unix::process::ExitStatusExt;
        // raw 9 = SIGKILL on both Linux and macOS (low 7 bits, no core).
        let s = std::process::ExitStatus::from_raw(9);
        assert_eq!(format_exit_status(s), "killed by signal 9");
    }

    /// Smoke test the path accessors — they must return non-empty paths
    /// on a host with `$HOME` set (which is true on every developer
    /// machine and CI runner).
    #[test]
    fn path_accessors_return_non_empty_paths_on_supported_oses() {
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            // The result depends on $HOME being set, which it is in
            // CI and dev. The cache/config dirs end with `silvervine`.
            let cache = cache_dir();
            let config = config_dir();
            assert!(
                cache.ends_with("silvervine"),
                "cache_dir = {}",
                cache.display()
            );
            assert!(
                config.ends_with("silvervine"),
                "config_dir = {}",
                config.display()
            );
            let apps = applications_dirs();
            assert!(!apps.is_empty(), "applications_dirs must not be empty");
        }
    }
}
