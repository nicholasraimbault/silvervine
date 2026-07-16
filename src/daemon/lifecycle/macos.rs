//! macOS daemon registration via `LaunchAgent` plist.
//!
//! Writes `~/Library/LaunchAgents/com.nicholasraimbault.silvervine.tray.plist` and runs:
//!
//! ```sh
//! launchctl bootstrap gui/<uid> ~/Library/LaunchAgents/com.nicholasraimbault.silvervine.tray.plist
//! ```
//!
//! `launchctl bootstrap gui/<uid>` is **user-domain** — it doesn't need
//! root. (System-domain agents would need `launchctl bootstrap system/`,
//! which does require root, but we deliberately use user-domain so the
//! tray runs in the user's GUI session with full notification / window-
//! server access.)
//!
//! ## Plist contents
//!
//! ```xml
//! <?xml version="1.0" encoding="UTF-8"?>
//! <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
//!   "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
//! <plist version="1.0">
//! <dict>
//!     <key>Label</key>
//!     <string>com.nicholasraimbault.silvervine.tray</string>
//!     <key>ProgramArguments</key>
//!     <array>
//!         <string><current_exe></string>
//!     </array>
//!     <key>RunAtLoad</key>
//!     <true/>
//!     <key>KeepAlive</key>
//!     <dict>
//!         <key>SuccessfulExit</key>
//!         <false/>
//!     </dict>
//!     <key>StandardOutPath</key>
//!     <string>~/Library/Logs/silvervine/tray.log</string>
//!     <key>StandardErrorPath</key>
//!     <string>~/Library/Logs/silvervine/tray.log</string>
//!     <key>ProcessType</key>
//!     <string>Interactive</string>
//! </dict>
//! </plist>
//! ```
//!
//! `ProcessType=Interactive` is the right choice for tray UI on Apple
//! Silicon (lets the agent get window-server attention without being
//! throttled). `KeepAlive.SuccessfulExit=false` means: if Silvervine exits
//! cleanly, don't auto-restart it; if it crashes, do.
//!
//! ## Path resolution
//!
//! `~/Library/LaunchAgents/` (per-user). Tests redirect `$HOME` to a
//! tempdir so writes never land in the real home directory.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

/// `Label=` value embedded in the plist; also used by `launchctl bootout`.
const LABEL: &str = "com.nicholasraimbault.silvervine.tray";

/// Plist file name (under `~/Library/LaunchAgents/`).
const PLIST_NAME: &str = "com.nicholasraimbault.silvervine.tray.plist";

/// Neon V2 registration retired when Silvervine is registered.
const LEGACY_LABEL: &str = "com.neon.tray";
const LEGACY_PLIST_NAME: &str = "com.neon.tray.plist";

/// Resolve `~/Library/LaunchAgents/com.nicholasraimbault.silvervine.tray.plist`.
pub(super) fn registration_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Error::other("cannot resolve LaunchAgents path: $HOME unset"))?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(PLIST_NAME))
}

/// Resolve `~/Library/Logs/silvervine/tray.log` for stdout/stderr redirect.
fn log_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Error::other("cannot resolve log path: $HOME unset"))?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Logs")
        .join("silvervine")
        .join("tray.log"))
}

/// Compose the plist body. Exposed at crate-private visibility so tests
/// can assert against it.
pub(super) fn plist_body(exec_path: &Path, log: &Path) -> String {
    // We hand-write the XML; the `plist` crate would pull in ~50KB of
    // serialization machinery for what is effectively a six-key dict.
    // The format is fixed by Apple's DTD; no field needs escaping in the
    // realistic install path (no XML metacharacters in our binary or log
    // paths). If a user's $HOME contains `<` or `&` we'd produce
    // malformed XML, but that's not a realistic scenario.
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
        exe = exec_path.display(),
        log = log.display(),
    )
}

pub(super) fn register() -> Result<()> {
    register_with(&mut launchctl_required, &mut launchctl_loaded)
}

fn register_with(
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<bool>,
) -> Result<()> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::other("could not resolve current executable").with_source(e))?;
    let plist_path = registration_path()?;
    let log = log_path()?;
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::from(e).with_source_message(format!("could not create {}", parent.display()))
        })?;
    }
    register_transaction(
        &plist_path,
        plist_body(&exe, &log).as_bytes(),
        current_uid(),
        run,
        probe,
        &mut atomic_write,
    )
}

fn register_transaction(
    plist_path: &Path,
    new_body: &[u8],
    uid: u32,
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<bool>,
    write: &mut dyn FnMut(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    let previous = match std::fs::read(plist_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(Error::from(error)),
    };
    let target = gui_target(uid);
    let was_loaded = previous.is_some() && probe(&target)?;
    if was_loaded {
        run(&["bootout", &target])?;
    }
    let attempt = (|| {
        write(plist_path, new_body)?;
        run(&[
            "bootstrap",
            &gui_domain(uid),
            plist_path.to_string_lossy().as_ref(),
        ])
    })();
    if let Err(error) = attempt {
        let mut failures = Vec::new();
        // A failed bootstrap can still have partially loaded the job. Probe
        // instead of treating a normal "not loaded" bootout failure as a
        // rollback failure.
        match probe(&target) {
            Ok(true) => record_failure(
                &mut failures,
                "boot out the attempted LaunchAgent",
                run(&["bootout", &target]),
            ),
            Ok(false) => {}
            Err(probe_error) => {
                failures.push(("probe attempted LaunchAgent during rollback", probe_error))
            }
        }
        record_failure(
            &mut failures,
            "restore the previous plist",
            restore_plist(plist_path, previous.as_deref(), write),
        );
        if was_loaded {
            record_failure(
                &mut failures,
                "reload the previous LaunchAgent",
                run(&[
                    "bootstrap",
                    &gui_domain(uid),
                    plist_path.to_string_lossy().as_ref(),
                ]),
            );
        }
        return Err(with_rollback_failures(error, &failures));
    }
    tracing::info!(path = %plist_path.display(), "registered Silvervine LaunchAgent");
    Ok(())
}

fn restore_plist(
    path: &Path,
    previous: Option<&[u8]>,
    write: &mut dyn FnMut(&Path, &[u8]) -> Result<()>,
) -> Result<()> {
    match previous {
        Some(bytes) => write(path, bytes),
        None => remove_plist_if_present(path),
    }
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
    registration_file_exists(&registration_path()?.with_file_name(LEGACY_PLIST_NAME))
}

pub(super) fn stop_legacy() -> Result<bool> {
    let path = registration_path()?.with_file_name(LEGACY_PLIST_NAME);
    let target = gui_target_for(current_uid(), LEGACY_LABEL);
    stop_legacy_with(
        &path,
        &target,
        &mut launchctl_required,
        &mut launchctl_loaded,
    )
}

fn stop_legacy_with(
    path: &Path,
    target: &str,
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<bool>,
) -> Result<bool> {
    if !registration_file_exists(path)? {
        return Ok(false);
    }
    let was_loaded = probe(target)?;
    if was_loaded {
        run(&["bootout", target])?;
    }
    Ok(was_loaded)
}

pub(super) fn restore_legacy(was_running: bool) -> Result<()> {
    if !was_running {
        return Ok(());
    }
    let path = registration_path()?.with_file_name(LEGACY_PLIST_NAME);
    if !registration_file_exists(&path)? {
        return Err(Error::other(
            "cannot restore the previously loaded Neon LaunchAgent: registration is missing",
        ));
    }
    launchctl_required(&[
        "bootstrap",
        &gui_domain(current_uid()),
        path.to_string_lossy().as_ref(),
    ])
}

pub(super) fn remove_legacy_registration() -> Result<()> {
    remove_plist_if_present(&registration_path()?.with_file_name(LEGACY_PLIST_NAME))
}

pub(super) fn unregister() -> Result<()> {
    let plist_path = registration_path()?;
    if !plist_path.try_exists().map_err(Error::from)? {
        return Ok(());
    }
    unregister_with(&mut launchctl_required, &mut launchctl_loaded)
}

pub(super) fn unregister_for_rollback() -> Result<()> {
    unregister_with(&mut launchctl_required, &mut launchctl_loaded)
}

fn unregister_with(
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<bool>,
) -> Result<()> {
    let plist_path = registration_path()?;
    let target = gui_target(current_uid());
    unregister_transaction(&plist_path, &target, current_uid(), run, probe)?;
    tracing::info!(
        path = %plist_path.display(),
        "unregistered Silvervine LaunchAgent"
    );
    Ok(())
}

fn unregister_transaction(
    plist_path: &Path,
    target: &str,
    uid: u32,
    run: &mut dyn FnMut(&[&str]) -> Result<()>,
    probe: &mut dyn FnMut(&str) -> Result<bool>,
) -> Result<()> {
    if !registration_file_exists(plist_path)? {
        // A failed earlier rollback can leave a loaded job after its plist was
        // removed. Boot it out before callers move data back; a genuinely
        // absent job remains a no-op.
        if probe(target)? {
            run(&["bootout", target])?;
        }
        return Ok(());
    }
    let was_loaded = probe(target)?;
    if was_loaded {
        run(&["bootout", target])?;
    }
    if let Err(error) = remove_plist_if_present(plist_path) {
        if was_loaded {
            let rollback = run(&[
                "bootstrap",
                &gui_domain(uid),
                plist_path.to_string_lossy().as_ref(),
            ]);
            if let Err(rollback) = rollback {
                return Err(with_rollback_failures(
                    error,
                    &[("reload LaunchAgent after plist removal failure", rollback)],
                ));
            }
        }
        return Err(error);
    }
    Ok(())
}

/// File-system half of `unregister()`: remove the plist if present.
/// Idempotent — missing-file is `Ok(())`.
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

fn remove_plist_if_present(plist_path: &Path) -> Result<()> {
    match std::fs::remove_file(plist_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::from(error)
            .with_source_message(format!("could not remove {}", plist_path.display()))),
    }
}

/// Write `body` to `path`, creating parent directories.
#[cfg(test)]
fn write_plist(path: &Path, body: &str) -> Result<()> {
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

/// Current user's effective UID. We use `libc::geteuid()` which is
/// stable and never fails.
fn current_uid() -> u32 {
    // SAFETY: `geteuid` is async-signal-safe on every macOS / POSIX
    // system and takes no arguments. It always returns a valid uid.
    unsafe { libc::geteuid() }
}

/// `gui/<uid>` — the launchd domain string for `bootstrap`.
fn gui_domain(uid: u32) -> String {
    format!("gui/{uid}")
}

/// `gui/<uid>/<label>` — the per-service target string for `bootout`.
fn gui_target(uid: u32) -> String {
    gui_target_for(uid, LABEL)
}

fn gui_target_for(uid: u32, label: &str) -> String {
    format!("gui/{uid}/{label}")
}

/// Best-effort launchctl: returns the captured output regardless of
/// exit code. Used for `bootout` where missing service is fine.
fn launchctl(args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new("launchctl");
    for a in args {
        cmd.arg(a);
    }
    cmd.output()
        .map_err(|e| Error::other("failed to spawn launchctl").with_source(e))
}

/// `launchctl` that surfaces a non-zero exit as an error. Used for
/// `bootstrap` where failure means the LaunchAgent isn't registered.
fn launchctl_loaded(target: &str) -> Result<bool> {
    let output = launchctl(&["print", target])?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let normalized = stderr.to_ascii_lowercase();
    if normalized.contains("could not find service")
        || normalized.contains("service not found")
        || normalized.contains("no such process")
    {
        return Ok(false);
    }
    Err(Error::other(format!(
        "launchctl print {target} failed (exit {:?}): {}",
        output.status.code(),
        stderr.trim()
    )))
}

fn launchctl_required(args: &[&str]) -> Result<()> {
    let output = launchctl(args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format!(
            "launchctl {} failed (exit {:?}): {}",
            args.join(" "),
            output.status.code(),
            stderr.trim()
        )));
    }
    Ok(())
}

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
    fn registration_path_uses_home() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _home = ScopedEnv::set("HOME", tmp.path());
        let path = registration_path().expect("ok");
        assert_eq!(
            path,
            tmp.path()
                .join("Library")
                .join("LaunchAgents")
                .join("com.nicholasraimbault.silvervine.tray.plist")
        );
    }

    #[test]
    fn registration_path_errors_without_home() {
        let _guard = crate::test_support::env_lock();
        let _home = ScopedEnv::unset("HOME");
        let r = registration_path();
        assert!(r.is_err());
    }

    #[test]
    fn log_path_resolves_under_home_library_logs() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _home = ScopedEnv::set("HOME", tmp.path());
        let p = log_path().expect("ok");
        assert_eq!(
            p,
            tmp.path()
                .join("Library")
                .join("Logs")
                .join("silvervine")
                .join("tray.log")
        );
    }

    #[test]
    fn plist_body_contains_required_keys() {
        let body = plist_body(
            Path::new("/usr/local/bin/silvervine"),
            Path::new("/var/log/silvervine.log"),
        );
        assert!(body.contains("<key>Label</key>"));
        assert!(body.contains("<string>com.nicholasraimbault.silvervine.tray</string>"));
        assert!(body.contains("<key>ProgramArguments</key>"));
        assert!(body.contains("<string>/usr/local/bin/silvervine</string>"));
        assert!(body.contains("<key>RunAtLoad</key>"));
        assert!(body.contains("<true/>"));
        assert!(body.contains("<key>KeepAlive</key>"));
        assert!(body.contains("<key>SuccessfulExit</key>"));
        assert!(body.contains("<false/>"));
        assert!(body.contains("<key>StandardOutPath</key>"));
        assert!(body.contains("<key>StandardErrorPath</key>"));
        assert!(body.contains("<string>/var/log/silvervine.log</string>"));
        assert!(body.contains("<key>ProcessType</key>"));
        assert!(body.contains("<string>Interactive</string>"));
    }

    #[test]
    fn plist_body_starts_with_xml_declaration() {
        let body = plist_body(Path::new("/x"), Path::new("/y"));
        assert!(body.starts_with("<?xml version=\"1.0\""));
        assert!(body.contains("<!DOCTYPE plist"));
        assert!(body.contains("<plist version=\"1.0\">"));
    }

    #[test]
    fn write_plist_creates_parent_dirs() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("a/b/c/test.plist");
        write_plist(&p, "body").expect("write ok");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "body");
    }

    #[test]
    fn write_plist_overwrites_existing() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("test.plist");
        std::fs::write(&p, "old").unwrap();
        write_plist(&p, "new").expect("ok");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new");
    }

    #[test]
    fn current_uid_returns_some_uid() {
        let uid = current_uid();
        // On a real system this is non-zero unless we're root, but we
        // only assert "the function runs and returns something."
        let _ = uid;
    }

    #[test]
    fn gui_domain_format() {
        assert_eq!(gui_domain(501), "gui/501");
    }

    #[test]
    fn gui_target_format() {
        assert_eq!(
            gui_target(501),
            "gui/501/com.nicholasraimbault.silvervine.tray"
        );
    }

    #[test]
    fn unregister_idempotent_under_noop() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(super::super::NOOP_ENV, Path::new("1"));
        // Public API short-circuits, so no shell-out happens.
        assert!(super::super::unregister().is_ok());
    }

    #[test]
    fn with_source_message_appends_to_existing() {
        let mut err = Error::other("boom");
        err = err.with_source_message("context".into());
        assert_eq!(err.message, "context: boom");
    }

    #[test]
    fn with_source_message_replaces_empty() {
        let mut err = Error::other("");
        err = err.with_source_message("context".into());
        assert_eq!(err.message, "context");
    }

    #[test]
    fn launchctl_required_returns_err_on_missing_binary() {
        // Force PATH to an empty dir so the spawn fails.
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _path = ScopedEnv::set("PATH", tmp.path());
        let r = launchctl_required(&["help"]);
        assert!(r.is_err());
    }

    #[test]
    fn launchctl_returns_err_on_missing_binary() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _path = ScopedEnv::set("PATH", tmp.path());
        let r = launchctl(&["help"]);
        assert!(r.is_err());
    }

    #[test]
    fn register_with_absent_legacy_does_not_bootout_legacy() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _home = ScopedEnv::set("HOME", tmp.path());
        let mut calls = Vec::new();
        register_with(
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| Ok(false),
        )
        .unwrap();
        assert!(!calls.iter().any(|call| call.contains(LEGACY_LABEL)));
    }

    #[test]
    fn legacy_stop_failure_preserves_plist() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _home = ScopedEnv::set("HOME", tmp.path());
        let legacy = registration_path()
            .unwrap()
            .with_file_name(LEGACY_PLIST_NAME);
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        std::fs::write(&legacy, "legacy").unwrap();
        let result = stop_legacy_with(
            &legacy,
            "gui/1/legacy",
            &mut |_| Err(Error::other("stop failed")),
            &mut |_| Ok(true),
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(legacy).unwrap(), "legacy");
    }

    #[test]
    fn current_stop_failure_preserves_plist() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _home = ScopedEnv::set("HOME", tmp.path());
        let plist = registration_path().unwrap();
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "current").unwrap();
        let result = unregister_with(&mut |_| Err(Error::other("stop failed")), &mut |_| Ok(true));
        assert!(result.is_err());
        assert_eq!(std::fs::read_to_string(plist).unwrap(), "current");
    }

    #[test]
    fn unregister_success_stops_before_removing_plist() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _home = ScopedEnv::set("HOME", tmp.path());
        let plist = registration_path().unwrap();
        std::fs::create_dir_all(plist.parent().unwrap()).unwrap();
        std::fs::write(&plist, "current").unwrap();
        let mut saw_plist_during_stop = false;
        unregister_with(
            &mut |_| {
                saw_plist_during_stop = plist.is_file();
                Ok(())
            },
            &mut |_| Ok(true),
        )
        .unwrap();
        assert!(saw_plist_during_stop);
        assert!(!plist.exists());
    }

    #[test]
    fn unregister_boots_out_loaded_job_even_when_plist_is_missing() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join(PLIST_NAME);
        let mut calls = Vec::new();
        unregister_transaction(
            &plist,
            "gui/501/com.example.silvervine",
            501,
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| Ok(true),
        )
        .unwrap();
        assert_eq!(calls, ["bootout gui/501/com.example.silvervine"]);
    }

    #[test]
    fn unregister_removes_stale_unloaded_plist_without_bootout() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join(PLIST_NAME);
        std::fs::write(&plist, "stale").unwrap();
        let mut calls = Vec::new();
        unregister_transaction(
            &plist,
            "gui/501/com.example.silvervine",
            501,
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| Ok(false),
        )
        .unwrap();
        assert!(calls.is_empty());
        assert!(!plist.exists());
    }

    #[test]
    fn remove_plist_if_present_removes_existing() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp
            .path()
            .join("com.nicholasraimbault.silvervine.tray.plist");
        std::fs::write(&plist, "body").unwrap();
        remove_plist_if_present(&plist).expect("ok");
        assert!(!plist.exists());
    }

    #[test]
    fn remove_plist_if_present_idempotent_when_missing() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join("does-not-exist.plist");
        remove_plist_if_present(&plist).expect("ok on missing");
    }

    /// `register()` under NOOP short-circuits (public API gate).
    #[test]
    fn register_under_noop_short_circuits() {
        let _guard = crate::test_support::env_lock();
        let _noop = ScopedEnv::set(super::super::NOOP_ENV, Path::new("1"));
        assert!(super::super::register().is_ok());
    }

    #[test]
    fn stale_unloaded_legacy_plist_does_not_bootout() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join(LEGACY_PLIST_NAME);
        std::fs::write(&plist, b"legacy").unwrap();
        let mut calls = Vec::new();
        stop_legacy_with(
            &plist,
            "gui/501/com.neon.tray",
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| Ok(false),
        )
        .unwrap();
        assert!(calls.is_empty());
        assert!(plist.is_file());
    }

    #[test]
    fn transactional_register_success_replaces_loaded_plist() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join(PLIST_NAME);
        std::fs::write(&plist, b"old plist").unwrap();
        let mut calls = Vec::new();
        register_transaction(
            &plist,
            b"new plist",
            501,
            &mut |args| {
                calls.push(args.join(" "));
                Ok(())
            },
            &mut |_| Ok(true),
            &mut atomic_write,
        )
        .unwrap();
        assert_eq!(std::fs::read(&plist).unwrap(), b"new plist");
        assert!(calls[0].starts_with("bootout "));
        assert!(calls[1].starts_with("bootstrap "));
    }

    #[test]
    fn transactional_register_stop_failure_preserves_old_plist() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join(PLIST_NAME);
        std::fs::write(&plist, b"old plist").unwrap();
        let result = register_transaction(
            &plist,
            b"new plist",
            501,
            &mut |_| Err(Error::other("stop failed")),
            &mut |_| Ok(true),
            &mut atomic_write,
        );
        assert!(result.is_err());
        assert_eq!(std::fs::read(&plist).unwrap(), b"old plist");
    }

    #[test]
    fn transactional_register_surfaces_rollback_failure() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join(PLIST_NAME);
        std::fs::write(&plist, b"old plist").unwrap();
        let mut bootouts = 0;
        let mut bootstraps = 0;
        let error = register_transaction(
            &plist,
            b"new plist",
            501,
            &mut |args| match args.first().copied() {
                Some("bootout") => {
                    bootouts += 1;
                    if bootouts == 2 {
                        Err(Error::other("rollback bootout failed"))
                    } else {
                        Ok(())
                    }
                }
                Some("bootstrap") => {
                    bootstraps += 1;
                    if bootstraps == 1 {
                        Err(Error::other("initial bootstrap failed"))
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            },
            &mut |_| Ok(true),
            &mut atomic_write,
        )
        .unwrap_err();
        assert!(error.to_string().contains("initial bootstrap failed"));
        assert!(error.to_string().contains("rollback bootout failed"));
    }

    #[test]
    fn transactional_register_write_and_bootstrap_failures_restore() {
        for fail_write in [true, false] {
            let tmp = TempDir::new().unwrap();
            let plist = tmp.path().join(PLIST_NAME);
            std::fs::write(&plist, b"old plist").unwrap();
            let mut writes = 0;
            let mut bootstraps = 0;
            let result = register_transaction(
                &plist,
                b"new plist",
                501,
                &mut |args| {
                    if args.first() == Some(&"bootstrap") {
                        bootstraps += 1;
                        if !fail_write && bootstraps == 1 {
                            return Err(Error::other("bootstrap failed"));
                        }
                    }
                    Ok(())
                },
                &mut |_| Ok(true),
                &mut |path, bytes| {
                    writes += 1;
                    if fail_write && writes == 1 {
                        Err(Error::other("write failed"))
                    } else {
                        atomic_write(path, bytes)
                    }
                },
            );
            assert!(result.is_err());
            assert_eq!(std::fs::read(&plist).unwrap(), b"old plist");
            assert!(bootstraps >= 1, "old loaded service must be restarted");
        }
    }
}
