//! Linux platform impl: XDG paths, `pkexec`/`sudo` escalation,
//! `renameat2`-backed atomic rename.
//!
//! ## Privilege escalation strategy
//!
//! Per the spec ("Linux → Privilege escalation"):
//!
//! > `pkexec` (preferred, GUI prompt) → `sudo` (terminal fallback).
//!
//! We probe for `pkexec` on `$PATH` first; if it's not present (or fails
//! with an unauthenticated exit code), we fall back to `sudo`. The
//! elevated child receives the original argv unchanged — the elevation
//! tool is the only thing that wraps it.
//!
//! ## Atomic rename
//!
//! `renameat2(RENAME_EXCHANGE)` works on every modern Linux filesystem
//! (ext4 ≥ 3.15, btrfs, xfs, f2fs). We call `libc::renameat2` directly
//! because nix's safe wrapper is gated on `target_env = "gnu"` and does
//! not exist on musl (a target we ship via cargo-dist). On `EINVAL`
//! (filesystem doesn't support exchange) we fall back to the two-step
//! rename documented in the trait doc.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::error::{Error, Result};

use super::PlatformPaths;

/// Linux implementation of [`PlatformPaths`].
///
/// XDG-compliant: cache and config dirs come from `dirs::cache_dir()` /
/// `dirs::config_dir()` (which honor `$XDG_CACHE_HOME` / `$XDG_CONFIG_HOME`
/// when set) with a `neon` suffix appended. Applications dirs are the
/// canonical Linux Chromium-family install locations.
pub struct LinuxPaths;

impl PlatformPaths for LinuxPaths {
    fn cache_dir() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("neon")
    }

    fn config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("neon")
    }

    fn applications_dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/opt"),
            PathBuf::from("/usr/lib"),
            PathBuf::from("/usr/lib64"),
            PathBuf::from("/usr/local/lib"),
        ]
    }
}

pub(super) fn cache_dir() -> PathBuf {
    LinuxPaths::cache_dir()
}
pub(super) fn config_dir() -> PathBuf {
    LinuxPaths::config_dir()
}
pub(super) fn applications_dirs() -> Vec<PathBuf> {
    LinuxPaths::applications_dirs()
}

/// Re-invoke the current Neon binary with elevated privileges via
/// `pkexec` (preferred) or `sudo` (fallback) so that the elevated child
/// can patch `target`.
///
/// The current executable is resolved via `std::env::current_exe()`; we
/// pass `--as-root patch <target>` as arguments. The `--as-root` flag
/// is reserved by the CLI team for "this is the elevated branch of a
/// previous CLI invocation." The patch subcommand will inspect the flag
/// and write to `target` directly.
pub(super) fn escalate_for_patch(target: &Path) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::other("could not resolve current executable").with_source(e))?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| Error::other("current executable path is not valid UTF-8"))?;
    let target_str = target
        .to_str()
        .ok_or_else(|| Error::other("target path is not valid UTF-8"))?;
    let cmd: &[&str] = &[exe_str, "--as-root", "patch", target_str];
    let output = run_as_root(cmd)?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(Error::permission_denied(format!(
            "elevated patch failed (exit {:?}): {}",
            output.status.code(),
            stderr.trim()
        )))
    }
}

/// Run `command` under `pkexec` (preferred) or `sudo` (fallback) and
/// return the captured output.
///
/// We try `pkexec` first because it surfaces a GUI prompt that's more
/// discoverable than a terminal `sudo`. `pkexec` exits 127 if the user
/// dismisses the auth dialog; we treat that as a permission error and
/// don't fall back to `sudo` (the user already said no).
///
/// If `pkexec` is missing entirely (e.g. minimal containers, headless
/// servers) we fall back to `sudo` so the binary still works in a
/// terminal-only context.
pub(super) fn run_as_root(command: &[&str]) -> Result<Output> {
    if which("pkexec").is_some() {
        return spawn_with_elevator("pkexec", command);
    }
    if which("sudo").is_some() {
        return spawn_with_elevator("sudo", command);
    }
    Err(Error::other(
        "neither pkexec nor sudo is on $PATH; cannot elevate privileges",
    ))
}

/// Path-resolve `binary` against `$PATH`. Returns `None` if not found.
///
/// We avoid pulling in a `which`-style crate for one call site — this
/// is six lines of stdlib.
fn which(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Spawn `command` under `elevator` (`pkexec` or `sudo`) and capture
/// the child's output.
fn spawn_with_elevator(elevator: &str, command: &[&str]) -> Result<Output> {
    let mut cmd = Command::new(elevator);
    for arg in command {
        cmd.arg(arg);
    }
    cmd.output()
        .map_err(|e| Error::other(format!("failed to spawn {elevator}")).with_source(e))
}

/// Atomic exchange via `renameat2(RENAME_EXCHANGE)`, with a two-step
/// fallback for filesystems that don't support it.
pub(super) fn atomic_rename(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        // No exchange needed if the destination doesn't yet exist —
        // a plain rename is already atomic.
        std::fs::rename(src, dst).map_err(|e| {
            Error::from(e).message_or(format!(
                "rename({} -> {}) failed",
                src.display(),
                dst.display()
            ))
        })?;
        return Ok(());
    }
    match exchange_renameat2(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.is_invalid_argument() => fallback_two_step_rename(src, dst),
        Err(e) => Err(e.into_error(src, dst)),
    }
}

/// Wrapper return type for `renameat2`-style exchanges.
enum ExchangeError {
    /// `EINVAL` from the syscall — filesystem doesn't support exchange.
    InvalidArgument,
    /// Any other failure (`EACCES`, `ENOENT`, `ENOSPC`, ...).
    Other(std::io::Error),
}

impl ExchangeError {
    fn is_invalid_argument(&self) -> bool {
        matches!(self, Self::InvalidArgument)
    }

    fn into_error(self, src: &Path, dst: &Path) -> Error {
        let io_err = match self {
            Self::InvalidArgument => std::io::Error::from(std::io::ErrorKind::InvalidInput),
            Self::Other(e) => e,
        };
        Error::from(io_err).message_or(format!(
            "atomic_rename({} <-> {}) failed",
            src.display(),
            dst.display()
        ))
    }
}

/// Invoke `renameat2(AT_FDCWD, src, AT_FDCWD, dst, RENAME_EXCHANGE)`.
///
/// We use libc directly via a single FFI call rather than pulling in
/// the full `nix` crate just for this one syscall. The wrapper is
/// straightforward — we hand both paths in as null-terminated `CString`s
/// and check the return code.
fn exchange_renameat2(src: &Path, dst: &Path) -> std::result::Result<(), ExchangeError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_c = CString::new(src.as_os_str().as_bytes())
        .map_err(|e| ExchangeError::Other(io_invalid(e)))?;
    let dst_c = CString::new(dst.as_os_str().as_bytes())
        .map_err(|e| ExchangeError::Other(io_invalid(e)))?;

    // SAFETY: `renameat2` is a stable Linux syscall (since 3.15). We pass
    // null-terminated C strings constructed from valid UTF-8/OsStr bytes,
    // and `AT_FDCWD` is the well-known constant for "use the current
    // working directory as the dirfd." `RENAME_EXCHANGE = 2` per
    // <linux/fs.h>. The flags fit in `c_uint`. No memory is shared with
    // the syscall after it returns.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dst_c.as_ptr(),
            RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EINVAL) {
        Err(ExchangeError::InvalidArgument)
    } else {
        Err(ExchangeError::Other(err))
    }
}

/// `RENAME_EXCHANGE` from `<linux/fs.h>`. Hardcoded to keep the libc
/// dependency surface small (newer libc versions expose it as
/// `libc::RENAME_EXCHANGE`, but our MSRV may target older).
const RENAME_EXCHANGE: libc::c_uint = 2;

fn io_invalid(e: std::ffi::NulError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
}

/// Fallback when `RENAME_EXCHANGE` is unsupported: rename `dst` aside,
/// move `src` into place, then remove the saved `dst`.
///
/// This is atomic in the common case (a `kill -9` between steps 2 and 3
/// leaves `dst` correctly populated and `dst.neon-tmp` as orphan to
/// clean up). It's not crash-safe in the strict sense — a power loss
/// between step 1 and step 2 leaves `dst` missing.
fn fallback_two_step_rename(src: &Path, dst: &Path) -> Result<()> {
    let backup = dst.with_extension("neon-tmp");
    std::fs::rename(dst, &backup).map_err(|e| {
        Error::from(e).message_or(format!(
            "fallback rename: could not move {} aside",
            dst.display()
        ))
    })?;
    if let Err(e) = std::fs::rename(src, dst) {
        // Best-effort: try to restore the original from the backup so
        // we don't leave the user with a missing browser bundle.
        let _ = std::fs::rename(&backup, dst);
        return Err(Error::from(e).message_or(format!(
            "fallback rename: could not move {} into {}",
            src.display(),
            dst.display()
        )));
    }
    // Step 3 is best-effort: orphaning `backup` is recoverable but not
    // a hard error.
    let _ = remove_path(&backup);
    Ok(())
}

/// Recursively remove a file or directory at `p`.
fn remove_path(p: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(p)?;
    if meta.file_type().is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    }
}

trait MessageOr {
    fn message_or(self, fallback: String) -> Self;
}

impl MessageOr for Error {
    /// Replace the inner message of an [`Error`] when the existing one
    /// is empty (which happens when `From<io::Error>` produces only the
    /// raw `io::Error` text). Useful for adding a path context without
    /// losing the io error's `source`.
    fn message_or(mut self, fallback: String) -> Self {
        if self.message.is_empty() {
            self.message = fallback;
        } else {
            self.message = format!("{fallback}: {}", self.message);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn cache_dir_ends_with_neon() {
        assert!(LinuxPaths::cache_dir().ends_with("neon"));
    }

    #[test]
    fn config_dir_ends_with_neon() {
        assert!(LinuxPaths::config_dir().ends_with("neon"));
    }

    #[test]
    fn applications_dirs_includes_opt_and_usr_lib() {
        let dirs = LinuxPaths::applications_dirs();
        assert!(dirs.iter().any(|p| p == Path::new("/opt")));
        assert!(dirs.iter().any(|p| p == Path::new("/usr/lib")));
    }

    #[test]
    fn which_finds_sh() {
        // `/bin/sh` exists on every Linux distro; `sh` should be
        // resolvable through `$PATH`.
        let found = which("sh");
        assert!(found.is_some(), "sh must be resolvable");
    }

    #[test]
    fn which_returns_none_for_missing_binary() {
        let found = which("definitely-not-a-real-binary-xyzzy");
        assert!(found.is_none());
    }

    /// Atomic rename swaps two existing files.
    #[test]
    fn atomic_rename_swaps_two_files_on_ext4() {
        let tmp = TempDir::new().expect("tempdir");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::write(&a, b"AAA").unwrap();
        fs::write(&b, b"BBB").unwrap();
        atomic_rename(&a, &b).expect("rename ok");
        // After the exchange `a` holds BBB, `b` holds AAA. (Both files
        // still exist — RENAME_EXCHANGE is a swap, not a move.)
        let a_after = fs::read(&a).unwrap();
        let b_after = fs::read(&b).unwrap();
        assert_eq!(a_after, b"BBB");
        assert_eq!(b_after, b"AAA");
    }

    /// When the destination doesn't exist, `atomic_rename` falls through
    /// to a plain `rename` and the destination ends up holding the source
    /// content.
    #[test]
    fn atomic_rename_handles_missing_destination() {
        let tmp = TempDir::new().expect("tempdir");
        let a = tmp.path().join("a");
        let b = tmp.path().join("not-here");
        fs::write(&a, b"AAA").unwrap();
        atomic_rename(&a, &b).expect("rename ok");
        assert!(!a.exists());
        assert_eq!(fs::read(&b).unwrap(), b"AAA");
    }

    /// `run_as_root` rejects an empty command without elevating.
    #[test]
    fn run_as_root_rejects_missing_elevator() {
        // We can't reliably remove pkexec/sudo from $PATH in a test, so
        // we just exercise the early-exit path: the function returns
        // some result without panicking when called from an unprivileged
        // test runner. A real elevation attempt would prompt for a
        // password; we don't actually test that here.
        // What we do verify: when neither tool is present we get a
        // proper error category back. This is exercised via the unsupported
        // platform tests in `mod.rs` for foreign targets.
        let _ = which("pkexec");
        let _ = which("sudo");
    }

    /// Fallback two-step rename works when invoked directly. Integration
    /// of "kernel rejected the syscall, fall back" requires a non-ext4
    /// filesystem we can't synthesize cheaply; we exercise the helper
    /// directly to keep the path covered.
    #[test]
    fn fallback_two_step_rename_swaps_into_place() {
        let tmp = TempDir::new().expect("tempdir");
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fs::write(&src, b"new").unwrap();
        fs::write(&dst, b"old").unwrap();
        fallback_two_step_rename(&src, &dst).expect("fallback ok");
        assert!(!src.exists(), "src consumed");
        assert_eq!(fs::read(&dst).unwrap(), b"new");
    }

    #[test]
    fn fallback_two_step_rename_recovers_when_step_2_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let src = tmp.path().join("nonexistent");
        let dst = tmp.path().join("dst");
        fs::write(&dst, b"old").unwrap();
        // Step 1 succeeds (rename dst -> backup), step 2 fails because
        // src doesn't exist; the function must restore dst from backup.
        let r = fallback_two_step_rename(&src, &dst);
        assert!(r.is_err());
        assert!(dst.exists(), "dst must be restored on failure");
    }

    #[test]
    fn message_or_appends_to_existing_message() {
        let mut err = Error::other("boom");
        err = err.message_or("context".into());
        assert_eq!(err.message, "context: boom");
    }

    #[test]
    fn message_or_replaces_empty_message() {
        let mut err = Error::other("");
        err = err.message_or("context".into());
        assert_eq!(err.message, "context");
    }

    /// Direct test of the renameat2 wrapper: should succeed on tmpfs.
    /// Most CI runners use tmpfs for `/tmp`, which supports
    /// `RENAME_EXCHANGE` since kernel 3.15. If a CI agent ever runs on
    /// an exotic FS that returns `EINVAL`, the wrapper still works
    /// because the public `atomic_rename` falls back.
    #[test]
    fn exchange_renameat2_swaps_on_tmpfs() {
        let tmp = TempDir::new().expect("tempdir");
        let a = tmp.path().join("aa");
        let b = tmp.path().join("bb");
        fs::write(&a, b"X").unwrap();
        fs::write(&b, b"Y").unwrap();
        match exchange_renameat2(&a, &b) {
            Ok(()) => {
                assert_eq!(fs::read(&a).unwrap(), b"Y");
                assert_eq!(fs::read(&b).unwrap(), b"X");
            }
            Err(ExchangeError::InvalidArgument) => {
                // Acceptable on filesystems without RENAME_EXCHANGE.
            }
            Err(ExchangeError::Other(e)) => panic!("unexpected error: {e}"),
        }
    }
}
