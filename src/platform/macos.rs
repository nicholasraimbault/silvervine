//! macOS platform impl: `~/Library/...` paths, `osascript`-based
//! escalation, `renameatx_np`-backed atomic rename.
//!
//! ## Privilege escalation strategy
//!
//! Per the spec ("macOS → Privilege escalation"):
//!
//! > `osascript -e "do shell script ... with administrator privileges"`
//!
//! Surfaces a system-wide GUI password prompt. The shell-script body is
//! kept short and is built by quoting the elevated command's argv with
//! AppleScript-safe escapes (only `\\` and `"` need to be escaped; we
//! reject anything containing a literal NUL).
//!
//! ## Atomic rename
//!
//! `renameatx_np(RENAME_SWAP)` is the macOS-equivalent of Linux's
//! `renameat2(RENAME_EXCHANGE)`. It works on APFS volumes (which is
//! every macOS install since 10.13). HFS+ volumes — rare but not
//! impossible — return `ENOTSUP`, in which case the wrapper falls back
//! to the same two-step rename pattern as Linux.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::error::{Error, Result};

use super::PlatformPaths;

/// macOS implementation of [`PlatformPaths`].
///
/// Cache and config live under `~/Library` per Apple convention rather
/// than the XDG paths Linux uses.
pub struct MacosPaths;

impl PlatformPaths for MacosPaths {
    fn cache_dir() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("neon")
    }

    fn config_dir() -> PathBuf {
        // `dirs::config_dir()` returns `~/Library/Application Support`
        // on macOS — that's where Neon's `config.toml` and `state.json`
        // live.
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("neon")
    }

    fn applications_dirs() -> Vec<PathBuf> {
        vec![PathBuf::from("/Applications")]
    }
}

pub(super) fn cache_dir() -> PathBuf {
    MacosPaths::cache_dir()
}
pub(super) fn config_dir() -> PathBuf {
    MacosPaths::config_dir()
}
pub(super) fn applications_dirs() -> Vec<PathBuf> {
    MacosPaths::applications_dirs()
}

/// Re-invoke the current Neon binary with elevated privileges via
/// `osascript do shell script ... with administrator privileges`.
///
/// The current binary is resolved via `std::env::current_exe()`. The
/// elevated child receives `--as-root patch <target>` so the CLI's
/// `--as-root` branch can do the privileged write.
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
            "elevated patch failed ({}): {}",
            super::format_exit_status(output.status),
            stderr.trim()
        )))
    }
}

/// Run `command` under `osascript do shell script ...` and return the
/// captured output.
///
/// We construct an AppleScript expression of the form:
///
/// ```text
/// do shell script "<escaped argv>" with administrator privileges
/// ```
///
/// where `<escaped argv>` is built by space-joining each argument after
/// AppleScript-escaping it (backslash and double-quote get backslashed).
/// Arguments containing NUL bytes are rejected — they can't be passed
/// through a shell anyway.
pub(super) fn run_as_root(command: &[&str]) -> Result<Output> {
    let script = build_osa_script(command)?;
    Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .map_err(|e| Error::other("failed to spawn osascript").with_source(e))
}

/// Build the AppleScript expression that runs `command` as administrator.
///
/// We use `quoted form of` for safety: AppleScript's `quoted form of`
/// returns a single-quote-wrapped string with internal single quotes
/// safely escaped, producing a shell-safe form. We pre-escape backslashes
/// and double quotes for AppleScript, then wrap the whole expression in
/// the `do shell script ... with administrator privileges` template.
fn build_osa_script(command: &[&str]) -> Result<String> {
    if command.is_empty() {
        return Err(Error::other("build_osa_script called with empty command"));
    }
    // Construct a shell-quoted argv: each argument wrapped in
    // single-quotes with internal single-quotes properly escaped.
    let mut shell = String::new();
    for (i, arg) in command.iter().enumerate() {
        if arg.contains('\0') {
            return Err(Error::other(
                "command argument contains NUL byte; cannot escalate",
            ));
        }
        if i > 0 {
            shell.push(' ');
        }
        shell.push_str(&shell_quote(arg));
    }
    // Escape backslashes and double-quotes for the AppleScript string
    // literal that wraps `shell`.
    let mut osa = String::from("do shell script \"");
    for c in shell.chars() {
        match c {
            '\\' => osa.push_str("\\\\"),
            '"' => osa.push_str("\\\""),
            other => osa.push(other),
        }
    }
    osa.push_str("\" with administrator privileges");
    Ok(osa)
}

/// Wrap a shell argument in single quotes, escaping any internal single
/// quotes via the standard `'\''` trick.
fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Atomic exchange via `renameatx_np(RENAME_SWAP)`, with a two-step
/// fallback for filesystems that don't support it (e.g. legacy HFS+).
pub(super) fn atomic_rename(src: &Path, dst: &Path) -> Result<()> {
    if !dst.exists() {
        std::fs::rename(src, dst).map_err(|e| {
            Error::from(e).message_or(format!(
                "rename({} -> {}) failed",
                src.display(),
                dst.display()
            ))
        })?;
        return Ok(());
    }
    match swap_renameatx_np(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.is_unsupported() => fallback_two_step_rename(src, dst),
        Err(e) => Err(e.into_error(src, dst)),
    }
}

enum SwapError {
    Unsupported,
    Other(std::io::Error),
}

impl SwapError {
    fn is_unsupported(&self) -> bool {
        matches!(self, Self::Unsupported)
    }
    fn into_error(self, src: &Path, dst: &Path) -> Error {
        let io_err = match self {
            Self::Unsupported => std::io::Error::from(std::io::ErrorKind::Unsupported),
            Self::Other(e) => e,
        };
        Error::from(io_err).message_or(format!(
            "atomic_rename({} <-> {}) failed",
            src.display(),
            dst.display()
        ))
    }
}

/// Invoke `renameatx_np(AT_FDCWD, src, AT_FDCWD, dst, RENAME_SWAP)`.
fn swap_renameatx_np(src: &Path, dst: &Path) -> std::result::Result<(), SwapError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let src_c =
        CString::new(src.as_os_str().as_bytes()).map_err(|e| SwapError::Other(io_invalid(e)))?;
    let dst_c =
        CString::new(dst.as_os_str().as_bytes()).map_err(|e| SwapError::Other(io_invalid(e)))?;

    // SAFETY: `renameatx_np` is a macOS syscall available since 10.12. We
    // pass null-terminated C strings constructed from valid OS strings,
    // and `AT_FDCWD` resolves both paths against the current working
    // directory. `RENAME_SWAP = 2` per `<sys/stdio.h>`. The flags fit in
    // `c_uint`. No memory is shared with the syscall after it returns.
    let rc = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            src_c.as_ptr(),
            libc::AT_FDCWD,
            dst_c.as_ptr(),
            RENAME_SWAP,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    // `ENOTSUP` is the canonical "this filesystem doesn't support
    // RENAME_SWAP" code on macOS. Some kernels also return `EINVAL`
    // for the same condition; both are treated as "fall back."
    let code = err.raw_os_error();
    if code == Some(libc::ENOTSUP) || code == Some(libc::EINVAL) {
        Err(SwapError::Unsupported)
    } else {
        Err(SwapError::Other(err))
    }
}

/// `RENAME_SWAP` from `<sys/stdio.h>`. Hardcoded for the same reason as
/// the Linux constant: smaller libc surface.
const RENAME_SWAP: libc::c_uint = 2;

fn io_invalid(e: std::ffi::NulError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
}

/// Fallback when `RENAME_SWAP` is unsupported: rename `dst` aside,
/// move `src` into place, then remove the saved `dst`.
fn fallback_two_step_rename(src: &Path, dst: &Path) -> Result<()> {
    let backup = dst.with_extension("neon-tmp");
    std::fs::rename(dst, &backup).map_err(|e| {
        Error::from(e).message_or(format!(
            "fallback rename: could not move {} aside",
            dst.display()
        ))
    })?;
    if let Err(e) = std::fs::rename(src, dst) {
        let _ = std::fs::rename(&backup, dst);
        return Err(Error::from(e).message_or(format!(
            "fallback rename: could not move {} into {}",
            src.display(),
            dst.display()
        )));
    }
    let _ = remove_path(&backup);
    Ok(())
}

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
        assert!(MacosPaths::cache_dir().ends_with("neon"));
    }

    #[test]
    fn config_dir_ends_with_neon() {
        assert!(MacosPaths::config_dir().ends_with("neon"));
    }

    #[test]
    fn applications_dirs_is_just_applications() {
        let dirs = MacosPaths::applications_dirs();
        assert_eq!(dirs, vec![PathBuf::from("/Applications")]);
    }

    #[test]
    fn shell_quote_handles_simple_arg() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_escapes_internal_single_quote() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn build_osa_script_wraps_args_with_admin_privileges() {
        let s = build_osa_script(&["echo", "hi"]).expect("ok");
        assert!(s.starts_with("do shell script \""));
        assert!(s.ends_with("\" with administrator privileges"));
        assert!(s.contains("'echo' 'hi'"));
    }

    #[test]
    fn build_osa_script_escapes_doublequote_for_applescript() {
        // Argument containing a double-quote must end up as `\"` inside
        // the AppleScript string literal.
        let s = build_osa_script(&["say", "\"hi\""]).expect("ok");
        // The inner double-quote is escaped for AppleScript via `\\"`.
        assert!(s.contains("\\\""));
    }

    #[test]
    fn build_osa_script_rejects_empty_command() {
        let r = build_osa_script(&[]);
        assert!(r.is_err());
    }

    #[test]
    fn build_osa_script_rejects_nul_byte() {
        let r = build_osa_script(&["nul\0"]);
        assert!(r.is_err());
    }

    /// Atomic rename swaps two files on APFS — but in CI we just verify
    /// the wrapper handles the `tempfile`-backed default filesystem.
    /// Most macOS tmp dirs are APFS-backed so the swap path runs; if a
    /// runner is HFS+ the fallback runs and the test still passes.
    #[test]
    fn atomic_rename_swaps_two_files() {
        let tmp = TempDir::new().expect("tempdir");
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::write(&a, b"AAA").unwrap();
        fs::write(&b, b"BBB").unwrap();
        atomic_rename(&a, &b).expect("rename ok");
        let a_after = fs::read(&a).unwrap();
        let b_after = fs::read(&b).unwrap();
        // Either the swap succeeded (both files exist with swapped
        // content) or the fallback ran (only `b` exists with `a`'s
        // content).
        let swapped = a_after == b"BBB" && b_after == b"AAA";
        let fell_back = !a.exists() && b_after == b"AAA";
        assert!(
            swapped || fell_back,
            "neither swap nor fallback worked: a={a_after:?}, b={b_after:?}"
        );
    }

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

    #[test]
    fn fallback_two_step_rename_swaps_into_place() {
        let tmp = TempDir::new().expect("tempdir");
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fs::write(&src, b"new").unwrap();
        fs::write(&dst, b"old").unwrap();
        fallback_two_step_rename(&src, &dst).expect("fallback ok");
        assert!(!src.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"new");
    }

    #[test]
    fn fallback_two_step_rename_recovers_when_step_2_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let src = tmp.path().join("nonexistent");
        let dst = tmp.path().join("dst");
        fs::write(&dst, b"old").unwrap();
        let r = fallback_two_step_rename(&src, &dst);
        assert!(r.is_err());
        assert!(dst.exists());
    }

    #[test]
    fn message_or_appends_or_replaces() {
        let err1 = Error::other("boom").message_or("ctx".into());
        assert_eq!(err1.message, "ctx: boom");
        let err2 = Error::other("").message_or("ctx".into());
        assert_eq!(err2.message, "ctx");
    }
}
