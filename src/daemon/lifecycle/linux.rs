//! Linux daemon registration via systemd-user units.
//!
//! Writes `~/.config/systemd/user/silvervine.service` and runs:
//!
//! ```sh
//! systemctl --user daemon-reload
//! systemctl --user enable --now silvervine.service
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
//! Description=Silvervine DRM tray and watcher
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
//! service breaks until they re-run `silvervine setup`.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

/// Service file name (under `systemd/user/`).
const SERVICE_NAME: &str = "silvervine.service";

/// Neon V2 registration retired when Silvervine is registered.
const LEGACY_SERVICE_NAME: &str = "neon.service";

/// `Description=` field on the unit.
const SERVICE_DESCRIPTION: &str = "Silvervine DRM tray and watcher";

/// Resolve `~/.config/systemd/user/silvervine.service`, honoring
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ServiceState {
    active: bool,
    enabled: bool,
}

pub(super) fn register() -> Result<()> {
    register_with(&mut systemctl_user, &mut systemctl_state)
}

fn register_with(
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<ServiceState>,
) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::other("could not resolve current executable").with_source(e))?;
    let unit_path = registration_path()?;
    register_transaction(
        &unit_path,
        service_unit_body(&exe).as_bytes(),
        run,
        probe,
        &mut atomic_write,
    )
}

fn register_transaction(
    unit_path: &Path,
    new_body: &[u8],
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<ServiceState>,
    write: &mut dyn FnMut(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    let previous = match std::fs::read(unit_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(Error::from(error)),
    };
    let previous_state = if previous.is_some() {
        probe(SERVICE_NAME)?
    } else {
        ServiceState::default()
    };
    if previous_state.active {
        run(&["stop", SERVICE_NAME])?;
    }

    let mut enable_attempted = false;
    let attempt = (|| {
        write(unit_path, new_body)?;
        run(&["daemon-reload"])?;
        enable_attempted = true;
        run(&["enable", "--now", SERVICE_NAME])
    })();
    if let Err(error) = attempt {
        let mut failures = Vec::new();
        if enable_attempted {
            record_failure(
                &mut failures,
                "stop and disable the attempted service",
                run(&["disable", "--now", SERVICE_NAME]),
            );
        }
        record_failure(
            &mut failures,
            "restore the previous unit file",
            restore_unit(unit_path, previous.as_deref(), write),
        );
        record_failure(
            &mut failures,
            "reload restored systemd units",
            run(&["daemon-reload"]),
        );
        if previous.is_some() {
            record_failure(
                &mut failures,
                "restore the previous service state",
                restore_service_state(SERVICE_NAME, previous_state, run),
            );
        }
        return Err(with_rollback_failures(error, &failures));
    }
    tracing::info!(path = %unit_path.display(), "registered Silvervine systemd-user service");
    Ok(())
}

fn restore_unit(
    path: &Path,
    previous: Option<&[u8]>,
    write: &mut dyn FnMut(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    match previous {
        Some(bytes) => write(path, bytes),
        None => remove_unit_file_if_present(path),
    }
}

fn restore_service_state(
    service_name: &str,
    state: ServiceState,
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
) -> Result<()> {
    let mut failures = Vec::new();
    if state.enabled {
        record_failure(
            &mut failures,
            "enable service",
            run(&["enable", service_name]),
        );
    } else {
        record_failure(
            &mut failures,
            "disable service",
            run(&["disable", service_name]),
        );
    }
    if state.active {
        record_failure(
            &mut failures,
            "start service",
            run(&["start", service_name]),
        );
    } else {
        record_failure(&mut failures, "stop service", run(&["stop", service_name]));
    }
    failures_to_result("could not restore systemd service state", &failures)
}

fn record_failure(
    failures: &mut Vec<(&'static str, Error)>,
    action: &'static str,
    result: Result<()>,
) {
    if let Err(error) = result {
        failures.push((action, error));
    }
}

fn failures_to_result(context: &str, failures: &[(&'static str, Error)]) -> Result<()> {
    if failures.is_empty() {
        return Ok(());
    }
    let details = failures
        .iter()
        .map(|(action, error)| format!("{action}: {error}"))
        .collect::<Vec<_>>()
        .join("; ");
    Err(Error::other(format!("{context}: {details}")))
}

fn with_rollback_failures(primary: Error, failures: &[(&'static str, Error)]) -> Error {
    if failures.is_empty() {
        return primary;
    }
    let category = primary.category;
    let details = failures
        .iter()
        .map(|(action, error)| format!("{action}: {error}"))
        .collect::<Vec<_>>()
        .join("; ");
    Error::new(category, format!("{primary}; rollback failed: {details}")).with_source(primary)
}

pub(super) fn legacy_is_registered() -> Result<bool> {
    registration_file_exists(&registration_path()?.with_file_name(LEGACY_SERVICE_NAME))
}

pub(super) fn stop_legacy() -> Result<bool> {
    if !legacy_is_registered()? {
        return Ok(false);
    }
    let was_active = systemctl_state(LEGACY_SERVICE_NAME)?.active;
    if was_active {
        systemctl_user(&["stop", LEGACY_SERVICE_NAME])?;
    }
    Ok(was_active)
}

pub(super) fn restore_legacy(was_running: bool) -> Result<()> {
    if !was_running {
        return Ok(());
    }
    if !legacy_is_registered()? {
        return Err(Error::other(
            "cannot restore the previously running Neon service: registration is missing",
        ));
    }
    systemctl_user(&["start", LEGACY_SERVICE_NAME])
}

pub(super) fn remove_legacy_registration() -> Result<()> {
    let path = registration_path()?.with_file_name(LEGACY_SERVICE_NAME);
    retire_unit_transaction(
        &path,
        LEGACY_SERVICE_NAME,
        &mut systemctl_user,
        &mut systemctl_state,
        &mut atomic_write,
    )
}

pub(super) fn unregister() -> Result<()> {
    let unit_path = registration_path()?;
    if !unit_path.try_exists().map_err(Error::from)? {
        return Ok(());
    }
    unregister_with(&mut systemctl_user, &mut systemctl_state)
}

pub(super) fn unregister_for_rollback() -> Result<()> {
    unregister_with(&mut systemctl_user, &mut systemctl_state)
}

fn unregister_with(
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<ServiceState>,
) -> Result<()> {
    let unit_path = registration_path()?;
    retire_unit_transaction(&unit_path, SERVICE_NAME, run, probe, &mut atomic_write)?;
    tracing::info!(
        path = %unit_path.display(),
        "unregistered Silvervine systemd-user service"
    );
    Ok(())
}

fn retire_unit_transaction(
    path: &Path,
    service_name: &str,
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<ServiceState>,
    write: &mut dyn FnMut(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    let previous = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A failed earlier rollback can leave a loaded job after its unit
            // file was removed. Clean that transient state before callers move
            // data back; a genuinely absent service remains a no-op.
            let state = probe(service_name)?;
            if state.active || state.enabled {
                run(&["disable", "--now", service_name])?;
            }
            return Ok(());
        }
        Err(error) => return Err(Error::from(error)),
    };
    let previous_state = probe(service_name)?;
    let attempt = (|| {
        run(&["disable", "--now", service_name])?;
        remove_unit_file_if_present(path)?;
        run(&["daemon-reload"])
    })();
    if let Err(error) = attempt {
        let mut failures = Vec::new();
        record_failure(
            &mut failures,
            "restore the retired unit file",
            write(path, &previous),
        );
        record_failure(
            &mut failures,
            "reload restored systemd units",
            run(&["daemon-reload"]),
        );
        record_failure(
            &mut failures,
            "restore the retired service state",
            restore_service_state(service_name, previous_state, run),
        );
        return Err(with_rollback_failures(error, &failures));
    }
    Ok(())
}

/// File-system half of `unregister()`. Removes the unit file if it
/// exists; missing-file is a no-op (idempotent).
fn registration_file_exists(path: &Path) -> Result<bool> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(Error::other(format!(
            "daemon registration path is not a file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::from(error).with_source_message(format!(
            "could not inspect daemon registration {}",
            path.display()
        ))),
    }
}

fn remove_unit_file_if_present(unit_path: &Path) -> Result<()> {
    match std::fs::remove_file(unit_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::from(error).with_source_message(format!(
            "could not remove unit file {}",
            unit_path.display()
        ))),
    }
}

/// Write the unit file, creating parent directories with the standard
/// XDG mode.
#[cfg(test)]
fn write_unit_file(path: &Path, body: &str) -> Result<()> {
    atomic_write(path, body.as_bytes())
}

fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::from(e).with_source_message(format!("could not create {}", parent.display()))
        })?;
    }
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&temp, body).map_err(|e| {
        Error::from(e).with_source_message(format!("could not write {}", temp.display()))
    })?;
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        Error::from(e).with_source_message(format!("could not replace {}", path.display()))
    })
}

/// Run `systemctl --user <args>` and surface non-zero exits as errors.
///
/// We capture stdout/stderr so failures show up in `tracing::error!` log
/// output for the user.
fn systemctl_state(service: &str) -> Result<ServiceState> {
    let active = systemctl_property(service, "ActiveState")?;
    let enabled = systemctl_property(service, "UnitFileState")?;
    let active = match active.as_str() {
        "active" | "activating" | "reloading" => true,
        "inactive" | "failed" | "deactivating" => false,
        value => {
            return Err(Error::other(format!(
                "unexpected ActiveState '{value}' for {service}"
            )));
        }
    };
    let enabled = match enabled.as_str() {
        "enabled" | "enabled-runtime" => true,
        "disabled" | "static" | "indirect" | "generated" | "transient" | "linked"
        | "linked-runtime" | "alias" | "masked" | "masked-runtime" | "bad" | "not-found" => false,
        value => {
            return Err(Error::other(format!(
                "unexpected UnitFileState '{value}' for {service}"
            )));
        }
    };
    Ok(ServiceState { active, enabled })
}

fn systemctl_property(service: &str, property: &str) -> Result<String> {
    let output = Command::new("systemctl")
        .arg("--user")
        .args(["show", "--property", property, "--value", service])
        .output()
        .map_err(|e| Error::other("failed to spawn systemctl --user").with_source(e))?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "systemctl --user show {property} for {service} failed (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|error| Error::other("systemctl returned non-UTF-8 state").with_source(error))?;
    let value = value.trim();
    if value.is_empty() {
        if property == "UnitFileState" {
            // `systemctl show` succeeds with an empty UnitFileState when a
            // stale on-disk unit has not yet been loaded by the manager.
            return Ok("not-found".to_string());
        }
        return Err(Error::other(format!(
            "systemctl returned an empty {property} for {service}"
        )));
    }
    Ok(value.to_string())
}

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
        assert!(path.ends_with("systemd/user/silvervine.service"));
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
                .join("silvervine.service")
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
        let body = service_unit_body(Path::new("/usr/local/bin/silvervine"));
        assert!(body.contains("[Unit]"));
        assert!(body.contains("Description=Silvervine DRM tray and watcher"));
        assert!(body.contains("[Service]"));
        assert!(body.contains("Type=simple"));
        assert!(body.contains("ExecStart=/usr/local/bin/silvervine"));
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
        let target = tmp.path().join("a/b/c/silvervine.service");
        write_unit_file(&target, "body").expect("write ok");
        let read = std::fs::read_to_string(&target).expect("read");
        assert_eq!(read, "body");
    }

    #[test]
    fn write_unit_file_overwrites_existing() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("silvervine.service");
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
    fn register_with_absent_legacy_does_not_stop_legacy() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let mut calls = Vec::new();
        register_with(
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| Ok(ServiceState::default()),
        )
        .unwrap();
        assert!(!calls.iter().any(|call| call.contains(LEGACY_SERVICE_NAME)));
    }

    #[test]
    fn legacy_stop_failure_preserves_artifact() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let legacy = registration_path()
            .unwrap()
            .with_file_name(LEGACY_SERVICE_NAME);
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "legacy").unwrap();
        let result = retire_unit_transaction(
            &legacy,
            LEGACY_SERVICE_NAME,
            &mut |_| Err(Error::other("stop failed")),
            &mut |_| {
                Ok(ServiceState {
                    active: true,
                    enabled: true,
                })
            },
            &mut atomic_write,
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(legacy).unwrap(), "legacy");
    }

    #[test]
    fn current_stop_failure_preserves_artifact() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let unit = registration_path().unwrap();
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(&unit, "current").unwrap();
        let result = unregister_with(&mut |_| Err(Error::other("stop failed")), &mut |_| {
            Ok(ServiceState {
                active: true,
                enabled: true,
            })
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(unit).unwrap(), "current");
    }

    #[test]
    fn unregister_success_stops_before_removing_artifact() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let unit = registration_path().unwrap();
        std::fs::create_dir_all(unit.parent().unwrap()).unwrap();
        std::fs::write(&unit, "current").unwrap();
        let mut saw_artifact_during_stop = false;
        unregister_with(
            &mut |args| {
                if args == ["disable", "--now", SERVICE_NAME] {
                    saw_artifact_during_stop = unit.is_file();
                }
                Ok(())
            },
            &mut |_| {
                Ok(ServiceState {
                    active: true,
                    enabled: true,
                })
            },
        )
        .unwrap();
        assert!(saw_artifact_during_stop);
        assert!(!unit.exists());
    }

    #[test]
    fn retirement_reload_failure_restores_unit_and_service_state() {
        let tmp = TempDir::new().unwrap();
        let unit = tmp.path().join(LEGACY_SERVICE_NAME);
        std::fs::write(&unit, "legacy").unwrap();
        let mut reloads = 0;
        let mut calls = Vec::new();
        let error = retire_unit_transaction(
            &unit,
            LEGACY_SERVICE_NAME,
            &mut |args| {
                let call = args.join(" ");
                calls.push(call.clone());
                if call == "daemon-reload" {
                    reloads += 1;
                    if reloads == 1 {
                        return Err(Error::other("retirement reload failed"));
                    }
                }
                Ok(())
            },
            &mut |_| {
                Ok(ServiceState {
                    active: false,
                    enabled: true,
                })
            },
            &mut atomic_write,
        )
        .unwrap_err();
        assert!(error.to_string().contains("retirement reload failed"));
        assert_eq!(std::fs::read_to_string(unit).unwrap(), "legacy");
        assert!(calls.contains(&"enable neon.service".into()));
        assert!(calls.contains(&"stop neon.service".into()));
    }

    #[test]
    fn unregister_stops_loaded_service_even_when_unit_file_is_missing() {
        let tmp = TempDir::new().unwrap();
        let unit = tmp.path().join(SERVICE_NAME);
        let mut calls = Vec::new();
        retire_unit_transaction(
            &unit,
            SERVICE_NAME,
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| {
                Ok(ServiceState {
                    active: true,
                    enabled: false,
                })
            },
            &mut atomic_write,
        )
        .unwrap();
        assert_eq!(calls, ["disable --now silvervine.service"]);
    }

    #[test]
    fn remove_unit_file_if_present_removes_existing() {
        let tmp = TempDir::new().unwrap();
        let unit = tmp.path().join("silvervine.service");
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
        assert!(super::super::register().is_ok());
    }

    fn transactional_fixture(tmp: &TempDir) -> PathBuf {
        let unit = tmp.path().join("silvervine.service");
        std::fs::write(&unit, b"old unit").unwrap();
        unit
    }

    #[test]
    fn transactional_register_success_replaces_and_starts() {
        let tmp = TempDir::new().unwrap();
        let unit = transactional_fixture(&tmp);
        let mut calls = Vec::new();
        register_transaction(
            &unit,
            b"new unit",
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| {
                Ok(ServiceState {
                    active: true,
                    enabled: true,
                })
            },
            &mut atomic_write,
        )
        .unwrap();
        assert_eq!(std::fs::read(&unit).unwrap(), b"new unit");
        assert_eq!(calls[0], "stop silvervine.service");
        assert!(calls.contains(&"enable --now silvervine.service".into()));
    }

    #[test]
    fn transactional_register_stop_failure_leaves_old_unit() {
        let tmp = TempDir::new().unwrap();
        let unit = transactional_fixture(&tmp);
        let result = register_transaction(
            &unit,
            b"new unit",
            &mut |_| Err(Error::other("stop failed")),
            &mut |_| {
                Ok(ServiceState {
                    active: true,
                    enabled: true,
                })
            },
            &mut atomic_write,
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(&unit).unwrap(), b"old unit");
    }

    #[test]
    fn transactional_register_write_failure_restores_and_restarts() {
        let tmp = TempDir::new().unwrap();
        let unit = transactional_fixture(&tmp);
        let mut calls = Vec::new();
        let mut writes = 0;
        let result = register_transaction(
            &unit,
            b"new unit",
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| {
                Ok(ServiceState {
                    active: true,
                    enabled: true,
                })
            },
            &mut |path, bytes| {
                writes += 1;
                if writes == 1 {
                    Err(Error::other("write failed"))
                } else {
                    atomic_write(path, bytes)
                }
            },
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(&unit).unwrap(), b"old unit");
        assert!(calls.contains(&"enable silvervine.service".into()));
        assert!(calls.contains(&"start silvervine.service".into()));
    }

    #[test]
    fn transactional_register_surfaces_rollback_failure() {
        let tmp = TempDir::new().unwrap();
        let unit = transactional_fixture(&tmp);
        let mut disable_attempts = 0;
        let error = register_transaction(
            &unit,
            b"new unit",
            &mut |args| {
                let call = args.join(" ");
                if call == "enable --now silvervine.service" {
                    return Err(Error::other("initial enable failed"));
                }
                if call == "disable --now silvervine.service" {
                    disable_attempts += 1;
                    return Err(Error::other("rollback disable failed"));
                }
                Ok(())
            },
            &mut |_| {
                Ok(ServiceState {
                    active: false,
                    enabled: false,
                })
            },
            &mut atomic_write,
        )
        .unwrap_err();
        assert_eq!(disable_attempts, 1);
        assert!(error.to_string().contains("initial enable failed"));
        assert!(error.to_string().contains("rollback disable failed"));
    }

    #[test]
    fn transactional_register_reload_and_enable_failures_roll_back() {
        for failed in ["daemon-reload", "enable --now silvervine.service"] {
            let tmp = TempDir::new().unwrap();
            let unit = transactional_fixture(&tmp);
            let mut failed_once = false;
            let result = register_transaction(
                &unit,
                b"new unit",
                &mut |args| {
                    let call = args.join(" ");
                    if call == failed && !failed_once {
                        failed_once = true;
                        Err(Error::other("injected failure"))
                    } else {
                        Ok(())
                    }
                },
                &mut |_| {
                    Ok(ServiceState {
                        active: true,
                        enabled: true,
                    })
                },
                &mut atomic_write,
            );
            assert!(result.is_err(), "{failed}");
            assert_eq!(std::fs::read(&unit).unwrap(), b"old unit", "{failed}");
        }
    }
}
