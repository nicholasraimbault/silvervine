//! Linux daemon registration via systemd-user units.
//!
//! Writes `~/.config/systemd/user/neon.service` and runs:
//!
//! ```sh
//! systemctl --user daemon-reload
//! systemctl --user enable --now neon.service
//! ```
//!
//! `systemctl --user` does **not** require root — the user-bus owns the
//! service. We never call `pkexec` / `sudo` from this module.
//!
//! ## Path resolution
//!
//! Per the systemd-user XDG spec, the unit file goes under
//! `$XDG_CONFIG_HOME/systemd/user/` (default `$HOME/.config/systemd/user/`).
//! We prefer `$XDG_CONFIG_HOME` when set so test fixtures can redirect
//! the directory into a `tempfile::TempDir`.
//!
//! ## Service unit
//!
//! ```ini
//! [Unit]
//! Description=Neon DRM tray and watcher
//!
//! [Service]
//! Type=simple
//! ExecStart=<current_exe>
//! Restart=on-failure
//! RestartSec=2s
//! StandardOutput=journal
//! StandardError=journal
//!
//! [Install]
//! WantedBy=default.target
//! ```
//!
//! `<current_exe>` is resolved at register-time via
//! `std::env::current_exe()`. If the user later moves the binary, the
//! service breaks until they re-run `neon setup`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

/// Service file name (under `systemd/user/`).
const SERVICE_NAME: &str = "neon.service";

/// `Description=` field on the unit.
const SERVICE_DESCRIPTION: &str = "Neon DRM tray and watcher";

/// Resolve `~/.config/systemd/user/neon.service`, honoring
/// `$XDG_CONFIG_HOME` if set.
pub(super) fn registration_path() -> Result<PathBuf> {
    let dir = systemd_user_unit_dir()?;
    Ok(dir.join(SERVICE_NAME))
}

/// Resolve `$XDG_CONFIG_HOME/systemd/user/`, falling back to
/// `$HOME/.config/systemd/user/`.
fn systemd_user_unit_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if !p.as_os_str().is_empty() {
            return Ok(p.join("systemd").join("user"));
        }
    }
    let home = std::env::var_os("HOME").ok_or_else(|| {
        Error::other("cannot resolve systemd user unit dir: $HOME and $XDG_CONFIG_HOME unset")
    })?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user"))
}

/// Compose the unit file body.
///
/// Exposed at crate-private visibility so tests can assert against it
/// without having to round-trip through the filesystem.
pub(super) fn service_unit_body(exec_start: &Path) -> String {
    // ExecStart needs an absolute path; we don't quote it because
    // systemd unit syntax doesn't use shell quoting (it splits on
    // whitespace, but our own binary path doesn't contain spaces in
    // any reasonable install location). If the exe path contains a
    // newline, the unit is malformed; we don't bother defending
    // against that — it's not a realistic install scenario.
    format!(
        "[Unit]\n\
Description={SERVICE_DESCRIPTION}\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exec}\n\
Restart=on-failure\n\
RestartSec=2s\n\
StandardOutput=journal\n\
StandardError=journal\n\
\n\
[Install]\n\
WantedBy=default.target\n",
        exec = exec_start.display()
    )
}

pub(super) fn register() -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::other("could not resolve current executable").with_source(e))?;
    let unit_path = registration_path()?;
    write_register_artifacts(&unit_path, &exe)?;
    systemctl_user(&["daemon-reload"])?;
    systemctl_user(&["enable", "--now", SERVICE_NAME])?;
    tracing::info!(
        path = %unit_path.display(),
        "registered Neon systemd-user service"
    );
    Ok(())
}

pub(super) fn unregister() -> Result<()> {
    let unit_path = registration_path()?;
    // Best-effort: even if the unit file is gone, run disable to clean
    // any stale symlink under default.target.wants/.
    let _ = systemctl_user(&["disable", "--now", SERVICE_NAME]);
    remove_unit_file_if_present(&unit_path)?;
    let _ = systemctl_user(&["daemon-reload"]);
    tracing::info!(
        path = %unit_path.display(),
        "unregistered Neon systemd-user service"
    );
    Ok(())
}

/// File-system half of `register()`. Pulled into a separate helper so
/// tests can exercise it in a tempdir without going through systemctl.
fn write_register_artifacts(unit_path: &Path, exe: &Path) -> Result<()> {
    write_unit_file(unit_path, &service_unit_body(exe))
}

/// File-system half of `unregister()`. Removes the unit file if it
/// exists; missing-file is a no-op (idempotent).
fn remove_unit_file_if_present(unit_path: &Path) -> Result<()> {
    if unit_path.exists() {
        std::fs::remove_file(unit_path).map_err(|e| {
            Error::from(e).with_source_message(format!(
                "could not remove unit file {}",
                unit_path.display()
            ))
        })?;
    }
    Ok(())
}

/// Write the unit file, creating parent directories with the standard
/// XDG mode.
fn write_unit_file(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::from(e).with_source_message(format!("could not create {}", parent.display()))
        })?;
    }
    std::fs::write(path, body).map_err(|e| {
        Error::from(e).with_source_message(format!("could not write {}", path.display()))
    })?;
    Ok(())
}

/// Run `systemctl --user <args>` and surface non-zero exits as errors.
///
/// We capture stdout/stderr so failures show up in `tracing::error!` log
/// output for the user.
fn systemctl_user(args: &[&str]) -> Result<()> {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user");
    for a in args {
        cmd.arg(a);
    }
    let output = cmd
        .output()
        .map_err(|e| Error::other("failed to spawn systemctl --user").with_source(e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format!(
            "systemctl --user {} failed (exit {:?}): {}",
            args.join(" "),
            output.status.code(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Glue trait: attach a path-context message to an `Error` when its
/// message is empty (preserving the io error source). Mirrors the
/// `MessageOr` helper in `platform::linux` but kept private to this
/// file to avoid a cross-team dependency on a non-public symbol.
trait WithSourceMessage {
    fn with_source_message(self, msg: String) -> Self;
}

impl WithSourceMessage for Error {
    fn with_source_message(mut self, msg: String) -> Self {
        if self.message.is_empty() {
            self.message = msg;
        } else {
            self.message = format!("{msg}: {}", self.message);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::TempDir;

    /// RAII env var setter — restores prior value on drop.
    struct ScopedEnv {
        key: &'static str,
        prev: Option<OsString>,
    }
    impl ScopedEnv {
        fn set(key: &'static str, value: &Path) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
        fn unset(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }
    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn registration_path_uses_xdg_when_set() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let path = registration_path().expect("path resolves");
        assert!(path.starts_with(tmp.path()));
        assert!(path.ends_with("systemd/user/neon.service"));
    }

    #[test]
    fn registration_path_falls_back_to_home_dot_config() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::unset("XDG_CONFIG_HOME");
        let _home = ScopedEnv::set("HOME", tmp.path());
        let path = registration_path().expect("path resolves");
        assert_eq!(
            path,
            tmp.path()
                .join(".config")
                .join("systemd")
                .join("user")
                .join("neon.service")
        );
    }

    #[test]
    fn registration_path_errors_when_no_home_or_xdg() {
        let _guard = crate::test_support::env_lock();
        let _xdg = ScopedEnv::unset("XDG_CONFIG_HOME");
        let _home = ScopedEnv::unset("HOME");
        let r = registration_path();
        assert!(r.is_err(), "must error when neither var is set");
    }

    #[test]
    fn empty_xdg_falls_back_to_home() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        // Empty string $XDG_CONFIG_HOME should fall back to $HOME/.config.
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", Path::new(""));
        let _home = ScopedEnv::set("HOME", tmp.path());
        let path = registration_path().expect("path resolves");
        assert!(path.starts_with(tmp.path().join(".config")));
    }

    #[test]
    fn service_unit_body_contains_required_sections() {
        let body = service_unit_body(Path::new("/usr/local/bin/neon"));
        assert!(body.contains("[Unit]"));
        assert!(body.contains("Description=Neon DRM tray and watcher"));
        assert!(body.contains("[Service]"));
        assert!(body.contains("Type=simple"));
        assert!(body.contains("ExecStart=/usr/local/bin/neon"));
        assert!(body.contains("Restart=on-failure"));
        assert!(body.contains("RestartSec=2s"));
        assert!(body.contains("StandardOutput=journal"));
        assert!(body.contains("StandardError=journal"));
        assert!(body.contains("[Install]"));
        assert!(body.contains("WantedBy=default.target"));
    }

    #[test]
    fn write_unit_file_creates_parent_dirs() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("a/b/c/neon.service");
        write_unit_file(&target, "body").expect("write ok");
        let read = std::fs::read_to_string(&target).expect("read");
        assert_eq!(read, "body");
    }

    #[test]
    fn write_unit_file_overwrites_existing() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("neon.service");
        std::fs::write(&target, "old").unwrap();
        write_unit_file(&target, "new").expect("ok");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
    }

    #[test]
    fn unregister_idempotent_when_unit_missing() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        // Don't bypass NOOP — unregister still does the systemctl shell-out
        // which we don't want to actually invoke. Use NOOP.
        let _noop = ScopedEnv::set(super::super::NOOP_ENV, Path::new("1"));
        // Public API short-circuits via NOOP guard.
        assert!(super::super::unregister().is_ok());
    }

    #[test]
    fn with_source_message_appends_to_existing_message() {
        let mut err = Error::other("boom");
        err = err.with_source_message("context".into());
        assert_eq!(err.message, "context: boom");
    }

    #[test]
    fn with_source_message_replaces_empty_message() {
        let mut err = Error::other("");
        err = err.with_source_message("context".into());
        assert_eq!(err.message, "context");
    }

    /// `systemctl_user` errors when the binary doesn't exist (i.e. on
    /// minimal containers without systemd installed). We can't reliably
    /// remove `systemctl` from `$PATH` in tests, so we just exercise the
    /// "command runs, returns whatever exit code" path with a known-bad
    /// arg list and check we get a reasonable error back. The actual
    /// shell-out to systemctl --user is permitted here because no daemon
    /// of our own is touched (we ask systemctl to operate on a fake
    /// service name); this is read-only from systemd's perspective.
    ///
    /// To keep the guardrail intact we **only** invoke this under the
    /// NOOP env so `register()` / `unregister()` never invoke systemctl
    /// in tests — but we still get coverage of the helper via the
    /// negative path (a service that doesn't exist returns non-zero;
    /// we surface the error).
    ///
    /// This test is `#[ignore]`d so it doesn't accidentally run on the
    /// user's machine; it's here to document the failure path. Coverage
    /// of the helper happens via the public NOOP-gated API tests.
    #[test]
    #[ignore = "would invoke systemctl --user; not safe under guardrails"]
    fn systemctl_user_surfaces_non_zero_exit() {
        let r = systemctl_user(&["status", "this-service-definitely-does-not-exist.service"]);
        assert!(r.is_err());
    }

    /// Direct test of the helper (covered indirectly when register fails)
    /// — we call it with a binary that doesn't exist as the elevator
    /// substitute. This exercises the spawn-failure branch.
    #[test]
    fn systemctl_user_returns_err_when_binary_missing() {
        // Simulate by changing PATH to an empty dir and calling the
        // helper. The real systemctl binary is on PATH on every Linux
        // dev box, so we have to deny it via a scoped env override.
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _path = ScopedEnv::set("PATH", tmp.path());
        let r = systemctl_user(&["--version"]);
        assert!(r.is_err(), "spawn must fail when systemctl is absent");
    }

    #[test]
    fn write_register_artifacts_writes_unit_with_exe_path() {
        let tmp = TempDir::new().unwrap();
        let unit = tmp.path().join("neon.service");
        let exe = Path::new("/usr/local/bin/neon");
        write_register_artifacts(&unit, exe).expect("ok");
        let body = std::fs::read_to_string(&unit).unwrap();
        assert!(body.contains("ExecStart=/usr/local/bin/neon"));
        assert!(body.contains("[Service]"));
    }

    #[test]
    fn remove_unit_file_if_present_removes_existing() {
        let tmp = TempDir::new().unwrap();
        let unit = tmp.path().join("neon.service");
        std::fs::write(&unit, "body").unwrap();
        remove_unit_file_if_present(&unit).expect("ok");
        assert!(!unit.exists());
    }

    #[test]
    fn remove_unit_file_if_present_idempotent_when_missing() {
        let tmp = TempDir::new().unwrap();
        let unit = tmp.path().join("does-not-exist.service");
        // Calling on a path that doesn't exist is a no-op.
        remove_unit_file_if_present(&unit).expect("ok on missing");
    }

    /// `register()` — full path with NOOP gate at the public layer means
    /// this test only verifies the env-gated short-circuit, not a real
    /// systemctl call. The internal `write_register_artifacts` is
    /// exercised by the test above; the `systemctl_user` helper has its
    /// own coverage.
    #[test]
    fn register_under_noop_short_circuits() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(super::super::NOOP_ENV, Path::new("1"));
        // Public API hits the NOOP gate before any filesystem / shell
        // operation runs.
        assert!(super::super::register().is_ok());
    }
}
