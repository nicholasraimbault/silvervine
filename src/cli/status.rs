//! `silvervine status` — show patch state for every detected browser.
//!
//! Default: human-friendly table. `--json`: structured output.
//! `--watch`: TUI-style refresh every 2 seconds; Ctrl-C exits.
//!
//! ## Watch mode
//!
//! Uses `crossterm` for cursor positioning + clear-screen. The
//! refresh loop runs until interrupted (the user hits Ctrl-C, or a
//! `SIGINT`/`SIGTERM` arrives).
//!
//! Tests don't drive watch mode directly — the test surface is
//! [`build_status`] (pure function over a snapshot of detected
//! browsers + IPC heartbeat). Watch mode itself is gated behind a
//! runtime flag.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::browsers::{self, Browser};
use crate::cli::OutputOptions;
use crate::error::{Error, Result};

/// Args for `silvervine status`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Args {
    /// `--watch`: continuously refresh in a TUI-style loop.
    pub watch: bool,
    /// Output flags.
    pub output: OutputOptions,
}

/// Per-browser status entry. Public so the daemon (Phase 4 IPC
/// `GetState`) can reuse the same shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserStatus {
    /// Display name.
    pub name: String,
    /// Absolute install path.
    pub install_path: String,
    /// `true` if the browser has been patched at all.
    pub patched: bool,
    /// CDM version currently bundled with the browser, if known.
    pub cdm_version: Option<String>,
    /// Last patch timestamp (Unix seconds), if recorded.
    pub last_patched_at: Option<u64>,
}

/// Top-level status report rendered by `silvervine status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusReport {
    /// Per-browser entries, in detection order.
    pub browsers: Vec<BrowserStatus>,
    /// Heartbeat timestamp (Unix seconds) — `None` if no daemon
    /// heartbeat file exists.
    pub heartbeat_at: Option<u64>,
    /// Currently-cached CDM version, if any.
    pub current_cdm_version: Option<String>,
}

/// Build the status report from a snapshot of browsers + heartbeat
/// timestamp + CDM version.
///
/// Pure function — tests pass synthetic inputs and assert against the
/// returned struct without touching the filesystem. Production callers
/// (`run`) wire the inputs from the real detection / cache resolvers.
#[must_use]
pub fn build_status(
    detected: &[Browser],
    heartbeat_at: Option<u64>,
    current_cdm_version: Option<String>,
) -> StatusReport {
    let browsers = detected
        .iter()
        .map(|b| BrowserStatus {
            name: b.name().to_string(),
            install_path: b.install_path().display().to_string(),
            patched: b.is_patched(),
            cdm_version: b.installed_cdm_version(),
            last_patched_at: None,
        })
        .collect();
    StatusReport {
        browsers,
        heartbeat_at,
        current_cdm_version,
    }
}

/// Read the daemon heartbeat file (Unix timestamp in seconds).
///
/// Returns `None` if the file is missing or unreadable. Production
/// `silvervine status` calls this; tests use [`build_status`] directly.
#[must_use]
pub fn read_heartbeat() -> Option<u64> {
    let path = crate::daemon::default_heartbeat_path()?;
    let s = std::fs::read_to_string(&path).ok()?;
    s.trim().parse::<u64>().ok()
}

/// Read the currently-cached CDM version, if any.
#[must_use]
pub fn current_cdm_version() -> Option<String> {
    let cdm = crate::widevine::current_cdm().ok().flatten()?;
    Some(cdm.version().to_string())
}

/// Render the report as a friendly text table.
fn render_text(report: &StatusReport, out: &mut dyn Write) -> std::io::Result<()> {
    if report.browsers.is_empty() {
        writeln!(out, "No browsers detected.")?;
    } else {
        let name_w = report
            .browsers
            .iter()
            .map(|b| b.name.len())
            .max()
            .unwrap_or(0)
            .max(8);
        writeln!(
            out,
            "{:name_w$}  {:8}  {:18}  PATH",
            "BROWSER",
            "PATCHED",
            "CDM VERSION",
            name_w = name_w,
        )?;
        for b in &report.browsers {
            let patched = if b.patched { "yes" } else { "no" };
            let cdm = b.cdm_version.as_deref().unwrap_or("-");
            writeln!(
                out,
                "{:name_w$}  {:8}  {:18}  {}",
                b.name,
                patched,
                cdm,
                b.install_path,
                name_w = name_w,
            )?;
        }
    }
    writeln!(out)?;
    if let Some(version) = &report.current_cdm_version {
        writeln!(out, "Cached Widevine CDM: {version}")?;
    } else {
        writeln!(
            out,
            "Cached Widevine CDM: (none — run `silvervine update widevine`)"
        )?;
    }
    match report.heartbeat_at {
        Some(ts) => writeln!(out, "Daemon heartbeat: {ts} (Unix seconds)")?,
        None => writeln!(out, "Daemon heartbeat: not running")?,
    }
    Ok(())
}

/// Render as a JSON object.
fn render_json(report: &StatusReport, out: &mut dyn Write) -> Result<()> {
    let s = serde_json::to_string_pretty(report)?;
    writeln!(out, "{s}").map_err(Error::from)?;
    Ok(())
}

/// CLI entry point.
///
/// # Errors
///
/// * `Other` if `--watch` and `--json` are combined (incompatible).
pub fn run(args: &Args) -> Result<()> {
    if args.watch && args.output.json {
        return Err(Error::other(
            "--watch is incompatible with --json (watch is human-targeted)",
        ));
    }
    if args.watch {
        return run_watch();
    }
    let detected = browsers::detect_browsers().unwrap_or_default();
    let report = build_status(&detected, read_heartbeat(), current_cdm_version());

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if args.output.json {
        render_json(&report, &mut handle)?;
    } else {
        render_text(&report, &mut handle).map_err(Error::from)?;
    }
    Ok(())
}

/// Watch loop. Refreshes every 2s; honors Ctrl-C via a flag set by a
/// signal handler.
fn run_watch() -> Result<()> {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    // Hide the cursor for the duration of watch mode.
    let _ = crossterm::execute!(handle, crossterm::cursor::Hide);
    let interval = std::time::Duration::from_secs(2);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    install_ctrlc_handler(&stop);
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        let detected = browsers::detect_browsers().unwrap_or_default();
        let report = build_status(&detected, read_heartbeat(), current_cdm_version());
        let _ = crossterm::execute!(
            handle,
            crossterm::cursor::MoveTo(0, 0),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::FromCursorDown),
        );
        render_text(&report, &mut handle).map_err(Error::from)?;
        let _ = handle.flush();
        // Sleep in small increments so Ctrl-C is observed promptly.
        let mut slept = std::time::Duration::ZERO;
        let granularity = std::time::Duration::from_millis(100);
        while slept < interval && !stop.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(granularity);
            slept += granularity;
        }
    }
    let _ = crossterm::execute!(handle, crossterm::cursor::Show);
    let _ = writeln!(handle);
    Ok(())
}

/// Best-effort Ctrl-C handler for watch mode. We don't pull in the
/// `ctrlc` crate just for this; a simple `signal-hook`-style handler
/// works for our purposes. If signal registration fails (unlikely on
/// Unix), the loop will run until the process is killed externally.
fn install_ctrlc_handler(stop: &std::sync::Arc<std::sync::atomic::AtomicBool>) {
    #[cfg(unix)]
    {
        // SAFETY: signal handlers must only call async-signal-safe
        // functions. `AtomicBool::store` is safe; tracing isn't, so we
        // don't log from inside the handler.
        unsafe {
            // Use the raw libc signal API to avoid a dependency.
            extern "C" fn handler(_sig: libc::c_int) {
                FLAG.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            static FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            // Ensure our user-side stop flag mirrors FLAG.
            std::thread::spawn({
                let stop = std::sync::Arc::clone(stop);
                move || loop {
                    if FLAG.load(std::sync::atomic::Ordering::SeqCst) {
                        stop.store(true, std::sync::atomic::Ordering::SeqCst);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            });
            libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = stop;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::BrowserKind;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn fake_browser(name: &str, install: PathBuf) -> Browser {
        Browser {
            name: name.into(),
            install_path: install,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    #[test]
    fn build_status_with_no_browsers_yields_empty_list() {
        let report = build_status(&[], None, None);
        assert!(report.browsers.is_empty());
        assert!(report.heartbeat_at.is_none());
        assert!(report.current_cdm_version.is_none());
    }

    #[test]
    fn build_status_includes_each_detected_browser() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![
            fake_browser("Helium", tmp.path().join("h")),
            fake_browser("Thorium", tmp.path().join("t")),
        ];
        let report = build_status(&detected, Some(1_700_000_000), Some("4.10.0".into()));
        assert_eq!(report.browsers.len(), 2);
        assert_eq!(report.browsers[0].name, "Helium");
        assert_eq!(report.heartbeat_at, Some(1_700_000_000));
        assert_eq!(report.current_cdm_version.as_deref(), Some("4.10.0"));
    }

    #[test]
    fn build_status_marks_unpatched_browsers() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![fake_browser("Helium", tmp.path().join("h"))];
        let report = build_status(&detected, None, None);
        // is_patched() is the Phase-1 stub that returns false.
        assert!(!report.browsers[0].patched);
    }

    #[test]
    fn render_text_no_browsers_says_none_detected() {
        let report = StatusReport {
            browsers: vec![],
            heartbeat_at: None,
            current_cdm_version: None,
        };
        let mut buf = Vec::new();
        render_text(&report, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("No browsers"));
        assert!(s.contains("not running"));
        assert!(s.contains("none"));
    }

    #[test]
    fn render_text_includes_browser_rows_and_heartbeat() {
        let report = StatusReport {
            browsers: vec![BrowserStatus {
                name: "Helium".into(),
                install_path: "/opt/helium".into(),
                patched: true,
                cdm_version: Some("4.10.0".into()),
                last_patched_at: Some(1_700_000_000),
            }],
            heartbeat_at: Some(1_700_000_500),
            current_cdm_version: Some("4.10.0".into()),
        };
        let mut buf = Vec::new();
        render_text(&report, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("BROWSER"));
        assert!(s.contains("Helium"));
        assert!(s.contains("yes"));
        assert!(s.contains("4.10.0"));
        assert!(s.contains("Daemon heartbeat: 1700000500"));
    }

    #[test]
    fn render_json_round_trips() {
        let report = StatusReport {
            browsers: vec![BrowserStatus {
                name: "Helium".into(),
                install_path: "/opt/helium".into(),
                patched: false,
                cdm_version: None,
                last_patched_at: None,
            }],
            heartbeat_at: None,
            current_cdm_version: None,
        };
        let mut buf = Vec::new();
        render_json(&report, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let parsed: StatusReport = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn run_with_watch_and_json_returns_error() {
        let args = Args {
            watch: true,
            output: OutputOptions {
                json: true,
                ..Default::default()
            },
        };
        let r = run(&args);
        assert!(r.is_err());
    }
}
