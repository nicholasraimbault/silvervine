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
//! * [`escalate_for_patch`] — runs an `osascript` (macOS) or `pkexec` /
//!   `sudo` (Linux) wrapper that re-invokes the current `neon` binary with
//!   elevated privileges. The same binary handles the privileged
//!   sub-operation when it sees `--as-root` (resolved by the CLI team).
//! * [`run_as_root`] — execute an arbitrary command with elevated privileges.
//!   Returns the captured [`Output`] regardless of exit status; callers
//!   inspect `status.success()` and the stderr text for diagnostics.
//! * [`atomic_rename`] — APFS / ext4-aware swap (uses the `nix` crate
//!   internally; falls back to two-step rename on filesystems that don't
//!   support `RENAME_EXCHANGE` / `RENAME_SWAP`). This is the helper that
//!   `core-engine`'s `patch::backup` uses; living here keeps the syscall
//!   gating out of cross-cutting modules.
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
//! not require real privilege. The two functions that genuinely shell out
//! ([`escalate_for_patch`] and [`run_as_root`]) are gated by an env var
//! (`NEON_TEST_ESCALATE_NOOP=1`) so CI never actually prompts for a
//! password.

use std::path::PathBuf;
use std::process::Output;

use crate::error::{Error, Result};

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
/// * Linux ([`linux::LinuxPaths`](self::linux::LinuxPaths)): XDG-compliant.
/// * macOS ([`macos::MacosPaths`](self::macos::MacosPaths)): `~/Library/...`.
///
/// Tests that need to assert against the trait without a real `$HOME` use
/// the per-platform impl directly, since the methods are pure (no I/O).
pub trait PlatformPaths {
    /// Cache directory — Neon's CDM cache + backups + lockfiles live here.
    /// Equivalent to `~/.cache/neon/` on Linux, `~/Library/Caches/neon/` on macOS.
    fn cache_dir() -> PathBuf;

    /// Config directory — `~/.config/neon/` (Linux) or
    /// `~/Library/Application Support/neon/` (macOS). State files and
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

/// Re-invoke the current Neon binary with elevated privileges to patch
/// `target`.
///
/// On macOS the command runs through `osascript -e "do shell script ...
/// with administrator privileges"`, which surfaces a system-wide GUI
/// password prompt. On Linux the command tries `pkexec` first (preferred,
/// GUI prompt) and falls back to `sudo` (terminal prompt) if `pkexec` is
/// not on `$PATH`.
///
/// The caller is responsible for telling the elevated child what to do
/// — typically by passing CLI flags like `--as-root patch <target>`. This
/// function takes the target path so the underlying script can echo
/// "Neon needs administrator access to patch <target>" in the prompt
/// dialog.
///
/// # Errors
///
/// * [`crate::ErrorCategory::PermissionDenied`] if the user cancels the
///   prompt or the elevation tool fails to authenticate.
/// * [`crate::ErrorCategory::UnsupportedPlatform`] on platforms with no
///   known elevation path.
/// * [`crate::ErrorCategory::Other`] for any other spawn failure.
///
/// # Test mode
///
/// If `NEON_TEST_ESCALATE_NOOP=1` is set, this function returns `Ok(())`
/// without spawning a subprocess. CI uses this to verify call sites
/// without prompting for a password.
pub fn escalate_for_patch(target: &std::path::Path) -> Result<()> {
    if std::env::var_os("NEON_TEST_ESCALATE_NOOP").is_some() {
        return Ok(());
    }
    imp::escalate_for_patch(target)
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
/// If `NEON_TEST_ESCALATE_NOOP=1` is set, this function returns a fake
/// "successful" [`Output`] with empty stdout/stderr without spawning a
/// subprocess.
pub fn run_as_root(command: &[&str]) -> Result<Output> {
    // Precondition: reject empty command before considering test-mode
    // short-circuiting. Empty argv is always a programmer error.
    if command.is_empty() {
        return Err(Error::other("run_as_root called with empty command"));
    }
    if std::env::var_os("NEON_TEST_ESCALATE_NOOP").is_some() {
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
/// Honors `NEON_TEST_ESCALATE_NOOP=1` like [`run_as_root`].
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
    if std::env::var_os("NEON_TEST_ESCALATE_NOOP").is_some() {
        return Ok(noop_output());
    }
    imp::run_as_root(&["sh", "-c", script])
}

/// Atomic rename helper used by [`crate::patch`] (via core-engine's
/// `patch::backup`).
///
/// On Linux this uses `renameat2(RENAME_EXCHANGE)`; on macOS it uses
/// `renameatx_np(RENAME_SWAP)`. If the underlying syscall returns
/// `EINVAL` (i.e. the filesystem doesn't support atomic swap, e.g.
/// non-APFS macOS volumes) the function falls back to a two-step
/// `rename` sequence:
///
/// 1. `rename(dst, dst.tmp)`
/// 2. `rename(src, dst)`
/// 3. remove `dst.tmp`
///
/// The fallback is atomic in the typical case but not perfectly
/// crash-safe — documented as a known limitation in the spec.
///
/// Both `src` and `dst` must already exist for the atomic-swap path. The
/// fallback path requires `dst` to exist; if it doesn't, the function
/// performs a plain `rename(src, dst)`.
///
/// # Errors
///
/// * [`crate::ErrorCategory::PermissionDenied`] if writes to either path
///   are rejected.
/// * [`crate::ErrorCategory::Other`] for any other I/O failure.
pub fn atomic_rename(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    imp::atomic_rename(src, dst)
}

/// Construct a no-op [`Output`] used when `NEON_TEST_ESCALATE_NOOP=1`.
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
    pub(super) fn escalate_for_patch(_target: &Path) -> Result<()> {
        Err(Error::unsupported_platform(
            "privilege escalation is only implemented on Linux and macOS",
        ))
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

    /// `NEON_TEST_ESCALATE_NOOP=1` short-circuits both elevation entry
    /// points so CI never prompts for a password.
    #[test]
    fn noop_short_circuit_in_test_mode() {
        // SAFETY: setting an env var is a process-wide mutation; this
        // test takes a small risk of interfering with parallel tests in
        // the same module, but `cargo test` runs each `#[test]` in its
        // own thread with no other escalate calls.
        // SAFETY: env mutations are permitted in a single-threaded test
        // section; we restore the previous value below.
        unsafe { std::env::set_var("NEON_TEST_ESCALATE_NOOP", "1") };
        let r = escalate_for_patch(std::path::Path::new("/opt/whatever"));
        assert!(r.is_ok());
        let out = run_as_root(&["echo", "hi"]).expect("noop ok");
        assert!(out.status.success());
        // SAFETY: restore the env to its prior unset state so other tests
        // (or future test runs in the same process) aren't affected.
        unsafe { std::env::remove_var("NEON_TEST_ESCALATE_NOOP") };
    }

    /// `run_as_root` rejects an empty command without elevating.
    #[test]
    fn run_as_root_rejects_empty_command() {
        let r = run_as_root(&[]);
        assert!(r.is_err(), "empty command must error");
    }

    /// Smoke test the path accessors — they must return non-empty paths
    /// on a host with `$HOME` set (which is true on every developer
    /// machine and CI runner).
    #[test]
    fn path_accessors_return_non_empty_paths_on_supported_oses() {
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            // The result depends on $HOME being set, which it is in
            // CI and dev. The cache/config dirs end with `neon`.
            let cache = cache_dir();
            let config = config_dir();
            assert!(cache.ends_with("neon"), "cache_dir = {}", cache.display());
            assert!(
                config.ends_with("neon"),
                "config_dir = {}",
                config.display()
            );
            let apps = applications_dirs();
            assert!(!apps.is_empty(), "applications_dirs must not be empty");
        }
    }
}
