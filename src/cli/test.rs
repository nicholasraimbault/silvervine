//! `neon test` — EME (Widevine) playback health check.
//!
//! Designed to spawn a headless Chromium-family browser against a known
//! EME test page (e.g. Shaka Player demo). Verifies whether the patched
//! browser can actually play Widevine-protected content end-to-end.
//!
//! ## Critical guardrail
//!
//! The actual browser launch is gated behind a runtime path that is
//! **only triggered when the user invokes `neon test` from the
//! command line** — never from tests. Inside `cargo test`, every
//! [`Plan::execute`] short-circuits via `NEON_TEST_BROWSER_TEST_NOOP=1`
//! (set by the test harness when it doesn't want the real browser
//! launched).
//!
//! A second, env-var-independent safety: tests never call `Plan::
//! execute_real_browser`. They drive the wholly-pure [`Plan::dry_run`]
//! method to verify the orchestration logic.

use std::io::Write;
use std::path::PathBuf;

use crate::browsers::{self, Browser};
use crate::cli::OutputOptions;
use crate::error::{Error, Result};

/// Env var that, when set, makes [`Plan::execute_real_browser`] return
/// `Ok(())` without actually spawning a browser. Used by integration
/// tests + by the `cargo test` harness for safety.
pub const NOOP_ENV: &str = "NEON_TEST_BROWSER_TEST_NOOP";

/// URL of the default EME test page. Shaka Player's demo is the
/// canonical "does Widevine work?" page on the open web; it serves an
/// MPEG-DASH manifest with Widevine-encrypted segments.
pub const DEFAULT_TEST_URL: &str = "https://shaka-player-demo.appspot.com/demo/";

/// Args for `neon test`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Optional positional: which browser to use. Defaults to the
    /// first detected browser.
    pub browser: Option<String>,
    /// Override the test URL (for staging-environment QA, etc.).
    pub url: Option<String>,
    /// Output flags.
    pub output: OutputOptions,
}

/// Plan describing what `neon test` would do.
///
/// Tests build a [`Plan`] from synthetic input and assert against its
/// fields directly. Production code calls [`Plan::execute_real_browser`]
/// to actually run the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Browser to launch.
    pub browser_name: String,
    /// Absolute path to the browser binary that would be spawned.
    pub browser_executable: PathBuf,
    /// URL to navigate to.
    pub url: String,
}

impl Plan {
    /// Build the launch plan from a snapshot of detected browsers + the
    /// args.
    ///
    /// # Errors
    ///
    /// * `Other` if no detected browser matches the filter.
    /// * `UnknownBundleStructure` if the matched browser's install path
    ///   doesn't yield a runnable executable.
    pub fn build(detected: &[Browser], args: &Args) -> Result<Self> {
        let candidate = match &args.browser {
            Some(name) => detected
                .iter()
                .find(|b| b.name().eq_ignore_ascii_case(name))
                .ok_or_else(|| Error::other(format!("no detected browser named '{name}'")))?,
            None => detected
                .first()
                .ok_or_else(|| Error::other("no browsers detected to run EME test against"))?,
        };
        let browser_executable = browser_executable_path(candidate)?;
        Ok(Self {
            browser_name: candidate.name().to_string(),
            browser_executable,
            url: args.url.clone().unwrap_or_else(|| DEFAULT_TEST_URL.into()),
        })
    }

    /// Render this plan to a human-readable description (no side effects).
    /// Used by tests + by the runtime "what would happen" path when the
    /// user passes `--dry-run` (currently unsupported but on the spec
    /// roadmap).
    #[must_use]
    pub fn dry_run(&self) -> String {
        format!(
            "Would launch: {} ({}) → {}",
            self.browser_name,
            self.browser_executable.display(),
            self.url,
        )
    }

    /// Actually spawn the browser. **Only callable from the user's
    /// runtime command path** — short-circuits if `NEON_TEST_BROWSER_TEST_NOOP=1`.
    ///
    /// # Errors
    ///
    /// * `Other` if the browser binary isn't executable or the spawn
    ///   itself fails.
    pub fn execute_real_browser(&self) -> Result<()> {
        if std::env::var_os(NOOP_ENV).is_some() {
            return Ok(());
        }
        let mut cmd = std::process::Command::new(&self.browser_executable);
        cmd.arg(&self.url);
        // Detach: we're not awaiting the browser's lifetime. The user
        // will close it manually.
        cmd.spawn().map_err(|e| {
            Error::other(format!(
                "failed to spawn {}: {e}",
                self.browser_executable.display()
            ))
        })?;
        Ok(())
    }
}

/// Resolve the executable path for `browser`.
///
/// On Linux this looks for a `chrome`, `chromium`, or
/// `<lower-case-name>` binary inside the install path. On macOS it
/// returns `<bundle>/Contents/MacOS/<bundle stem>`.
fn browser_executable_path(browser: &Browser) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let app = browser.install_path();
        let stem = app.file_stem().and_then(|s| s.to_str()).ok_or_else(|| {
            Error::unknown_bundle_structure(format!("no bundle name for {}", app.display()))
        })?;
        Ok(app.join("Contents").join("MacOS").join(stem))
    }
    #[cfg(target_os = "linux")]
    {
        // Try the most common Chromium-family binary names. Prefer the
        // browser's lowercase name, then `chrome`, `chromium`, etc.
        let install = browser.install_path();
        let candidates = [
            browser.name().to_lowercase(),
            "chrome".into(),
            "chromium".into(),
            "chromium-browser".into(),
        ];
        for name in &candidates {
            let p = install.join(name);
            if p.is_file() {
                return Ok(p);
            }
        }
        Err(Error::unknown_bundle_structure(format!(
            "could not locate browser executable in {}",
            install.display()
        )))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = browser;
        Err(Error::unsupported_platform(
            "browser-launch resolution is only implemented on Linux and macOS",
        ))
    }
}

/// CLI entry point.
///
/// # Errors
///
/// * `Other` if no browsers are detected.
/// * Any error from `browser_executable_path`.
pub fn run(args: &Args) -> Result<()> {
    let detected = browsers::detect_browsers().unwrap_or_default();
    let plan = Plan::build(&detected, args)?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if args.output.json {
        let body = serde_json::json!({
            "browser": plan.browser_name,
            "executable": plan.browser_executable.display().to_string(),
            "url": plan.url,
        });
        writeln!(handle, "{}", serde_json::to_string_pretty(&body)?).map_err(Error::from)?;
    } else {
        writeln!(handle, "{}", plan.dry_run()).map_err(Error::from)?;
        writeln!(
            handle,
            "(network + display dependent — pass --noop to skip browser launch)",
        )
        .map_err(Error::from)?;
    }
    plan.execute_real_browser()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::BrowserKind;
    use std::fs;
    use tempfile::TempDir;

    /// Create a fake Linux browser install directory with the given
    /// executable name.
    #[cfg(target_os = "linux")]
    fn make_linux_browser(tmp: &Path, name: &str, exe: &str) -> Browser {
        let install = tmp.join(name);
        fs::create_dir_all(&install).unwrap();
        let exe_path = install.join(exe);
        fs::write(&exe_path, "#!/bin/sh\nexit 0").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&exe_path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&exe_path, perms).unwrap();
        }
        Browser {
            name: name.into(),
            install_path: install,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    #[cfg(target_os = "macos")]
    fn make_macos_browser(tmp: &Path, name: &str) -> Browser {
        let app = tmp.join(format!("{name}.app"));
        fs::create_dir_all(app.join("Contents").join("MacOS")).unwrap();
        fs::write(app.join("Contents").join("MacOS").join(name), "fake").unwrap();
        Browser {
            name: name.into(),
            install_path: app,
            kind: BrowserKind::Detected,
            framework_name: None,
        }
    }

    use std::path::Path;

    #[test]
    fn plan_build_with_no_browsers_errors() {
        let r = Plan::build(&[], &Args::default());
        assert!(r.is_err());
    }

    #[test]
    fn plan_build_unknown_filter_name_errors() {
        let tmp = TempDir::new().unwrap();
        #[cfg(target_os = "linux")]
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        #[cfg(target_os = "macos")]
        let detected = vec![make_macos_browser(tmp.path(), "Helium")];
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let detected: Vec<Browser> = vec![];
        let args = Args {
            browser: Some("DoesNotExist".into()),
            ..Default::default()
        };
        let r = Plan::build(&detected, &args);
        assert!(r.is_err());
        let _ = tmp;
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_default_uses_first_detected_with_lowercase_exe() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        assert_eq!(plan.browser_name, "Helium");
        assert!(plan.browser_executable.ends_with("helium"));
        assert_eq!(plan.url, DEFAULT_TEST_URL);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_falls_back_to_chrome_binary() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "chrome")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        assert!(plan.browser_executable.ends_with("chrome"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_filter_is_case_insensitive() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let args = Args {
            browser: Some("HELIUM".into()),
            ..Default::default()
        };
        let plan = Plan::build(&detected, &args).expect("ok");
        assert_eq!(plan.browser_name, "Helium");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_url_override_takes_effect() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let args = Args {
            url: Some("https://example.com/test".into()),
            ..Default::default()
        };
        let plan = Plan::build(&detected, &args).expect("ok");
        assert_eq!(plan.url, "https://example.com/test");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_build_with_no_executable_errors() {
        let tmp = TempDir::new().unwrap();
        // Browser exists but has no recognizable executable.
        let install = tmp.path().join("Helium");
        fs::create_dir_all(&install).unwrap();
        let detected = vec![Browser {
            name: "Helium".into(),
            install_path: install,
            kind: BrowserKind::Detected,
            framework_name: None,
        }];
        let r = Plan::build(&detected, &Args::default());
        assert!(r.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_dry_run_includes_browser_path_and_url() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        let s = plan.dry_run();
        assert!(s.contains("Helium"));
        assert!(s.contains("helium"));
        assert!(s.contains(DEFAULT_TEST_URL));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn plan_execute_real_browser_short_circuits_under_noop() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_linux_browser(tmp.path(), "Helium", "helium")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        // SAFETY: env mutations happen in serial test threads; we restore
        // at end-of-test.
        unsafe { std::env::set_var(NOOP_ENV, "1") };
        plan.execute_real_browser().expect("noop short-circuits");
        unsafe { std::env::remove_var(NOOP_ENV) };
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn plan_build_macos_resolves_app_bundle() {
        let tmp = TempDir::new().unwrap();
        let detected = vec![make_macos_browser(tmp.path(), "Helium")];
        let plan = Plan::build(&detected, &Args::default()).expect("ok");
        assert!(plan.browser_executable.ends_with("MacOS/Helium"));
    }
}
