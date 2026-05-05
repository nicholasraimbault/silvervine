//! macOS daemon registration via `LaunchAgent` plist.
//!
//! Writes `~/Library/LaunchAgents/com.neon.tray.plist` and runs:
//!
//! ```sh
//! launchctl bootstrap gui/<uid> ~/Library/LaunchAgents/com.neon.tray.plist
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
//!     <string>com.neon.tray</string>
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
//!     <string>~/Library/Logs/neon/tray.log</string>
//!     <key>StandardErrorPath</key>
//!     <string>~/Library/Logs/neon/tray.log</string>
//!     <key>ProcessType</key>
//!     <string>Interactive</string>
//! </dict>
//! </plist>
//! ```
//!
//! `ProcessType=Interactive` is the right choice for tray UI on Apple
//! Silicon (lets the agent get window-server attention without being
//! throttled). `KeepAlive.SuccessfulExit=false` means: if Neon exits
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
const LABEL: &str = "com.neon.tray";

/// Plist file name (under `~/Library/LaunchAgents/`).
const PLIST_NAME: &str = "com.neon.tray.plist";

/// Resolve `~/Library/LaunchAgents/com.neon.tray.plist`.
pub(super) fn registration_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Error::other("cannot resolve LaunchAgents path: $HOME unset"))?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("LaunchAgents")
        .join(PLIST_NAME))
}

/// Resolve `~/Library/Logs/neon/tray.log` for stdout/stderr redirect.
fn log_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| Error::other("cannot resolve log path: $HOME unset"))?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Logs")
        .join("neon")
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
    let exe = std::env::current_exe()
        .map_err(|e| Error::other("could not resolve current executable").with_source(e))?;
    let plist_path = registration_path()?;
    let log = log_path()?;
    write_register_artifacts(&plist_path, &exe, &log)?;
    let uid = current_uid();
    // bootout is best-effort: if we never bootstrapped before, this
    // returns "service not found", which is fine.
    let _ = launchctl(&["bootout", &gui_target(uid)]);
    launchctl_required(&[
        "bootstrap",
        &gui_domain(uid),
        plist_path.to_string_lossy().as_ref(),
    ])?;
    tracing::info!(
        path = %plist_path.display(),
        "registered Neon LaunchAgent"
    );
    Ok(())
}

pub(super) fn unregister() -> Result<()> {
    let plist_path = registration_path()?;
    let uid = current_uid();
    // Best-effort bootout: even if the agent isn't loaded, the rm step
    // below is what actually un-registers.
    let _ = launchctl(&["bootout", &gui_target(uid)]);
    remove_plist_if_present(&plist_path)?;
    tracing::info!(
        path = %plist_path.display(),
        "unregistered Neon LaunchAgent"
    );
    Ok(())
}

/// File-system half of `register()`: ensure the log directory exists
/// then write the plist. Pulled into a helper so tests can exercise it
/// without invoking `launchctl`.
fn write_register_artifacts(plist_path: &Path, exe: &Path, log: &Path) -> Result<()> {
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::from(e).with_source_message(format!("could not create {}", parent.display()))
        })?;
    }
    write_plist(plist_path, &plist_body(exe, log))
}

/// File-system half of `unregister()`: remove the plist if present.
/// Idempotent — missing-file is `Ok(())`.
fn remove_plist_if_present(plist_path: &Path) -> Result<()> {
    if plist_path.exists() {
        std::fs::remove_file(plist_path).map_err(|e| {
            Error::from(e).with_source_message(format!("could not remove {}", plist_path.display()))
        })?;
    }
    Ok(())
}

/// Write `body` to `path`, creating parent directories.
fn write_plist(path: &Path, body: &str) -> Result<()> {
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
    format!("gui/{uid}/{LABEL}")
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
                .join("com.neon.tray.plist")
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
                .join("neon")
                .join("tray.log")
        );
    }

    #[test]
    fn plist_body_contains_required_keys() {
        let body = plist_body(
            Path::new("/usr/local/bin/neon"),
            Path::new("/var/log/neon.log"),
        );
        assert!(body.contains("<key>Label</key>"));
        assert!(body.contains("<string>com.neon.tray</string>"));
        assert!(body.contains("<key>ProgramArguments</key>"));
        assert!(body.contains("<string>/usr/local/bin/neon</string>"));
        assert!(body.contains("<key>RunAtLoad</key>"));
        assert!(body.contains("<true/>"));
        assert!(body.contains("<key>KeepAlive</key>"));
        assert!(body.contains("<key>SuccessfulExit</key>"));
        assert!(body.contains("<false/>"));
        assert!(body.contains("<key>StandardOutPath</key>"));
        assert!(body.contains("<key>StandardErrorPath</key>"));
        assert!(body.contains("<string>/var/log/neon.log</string>"));
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
        assert_eq!(gui_target(501), "gui/501/com.neon.tray");
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
    fn write_register_artifacts_creates_log_dir_and_writes_plist() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join("Library/LaunchAgents/com.neon.tray.plist");
        let log = tmp.path().join("Library/Logs/neon/tray.log");
        let exe = Path::new("/usr/local/bin/neon");
        write_register_artifacts(&plist, exe, &log).expect("ok");
        // Plist exists with the right exe path.
        assert!(plist.exists(), "plist must be written");
        let body = std::fs::read_to_string(&plist).unwrap();
        assert!(body.contains("<string>/usr/local/bin/neon</string>"));
        // Log directory was created (the file itself doesn't exist
        // yet — that's the daemon's job at runtime).
        assert!(log.parent().unwrap().is_dir(), "log dir must be created");
    }

    #[test]
    fn remove_plist_if_present_removes_existing() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join("com.neon.tray.plist");
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
}
