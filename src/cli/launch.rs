//! `neon launch <browser>` — verify-and-launch flow.
//!
//! 1. Detect the named browser.
//! 2. If not patched at the current CDM version, run `patch_browser`.
//! 3. Spawn the browser as a detached process.
//!
//! ## Test guardrail
//!
//! Step 3 is gated behind `NEON_TEST_LAUNCH_NOOP=1`. Tests cover the
//! verify-and-decide logic; the actual `Command::spawn` is never
//! invoked from `cargo test`.

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;

use crate::browsers::{self, Browser};
use crate::cli::OutputOptions;
use crate::error::{Error, Result};

/// Env var that, when set, makes [`spawn_detached`] return `Ok(())`
/// without actually calling `Command::spawn`. Used by tests.
pub const NOOP_ENV: &str = "NEON_TEST_LAUNCH_NOOP";

/// Args for `neon launch`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Required positional: name of the browser to launch.
    pub browser: String,
    /// Output flags.
    pub output: OutputOptions,
}

/// Action the launch flow decided to take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchDecision {
    /// Browser is already patched; spawn directly.
    AlreadyPatched,
    /// Browser is not patched; run patch first, then spawn.
    PatchAndSpawn,
}

/// Decide whether the named browser needs patching before launch.
///
/// Pure function — `browser.is_patched()` is the source of truth.
/// (For Phase 2 the `is_patched()` stub returns `false`; once the
/// patch module's "is patched" check is real, this function picks
/// it up automatically.)
#[must_use]
pub fn decide(browser: &Browser) -> LaunchDecision {
    if browser.is_patched() {
        LaunchDecision::AlreadyPatched
    } else {
        LaunchDecision::PatchAndSpawn
    }
}

/// Resolve the browser executable path. Mirrors `cli::test`'s logic
/// — kept here as well so a `Plan`/`launch` round-trip doesn't require
/// importing across submodules.
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
            "browser launch is only implemented on Linux and macOS",
        ))
    }
}

/// Spawn `executable` as a detached process. Honors `NOOP_ENV`.
///
/// Stdin/stdout/stderr are sent to /dev/null so the browser doesn't
/// block on the spawning shell.
///
/// # Errors
///
/// * `Other` if the spawn fails.
pub fn spawn_detached(executable: &std::path::Path) -> Result<()> {
    if std::env::var_os(NOOP_ENV).is_some() {
        return Ok(());
    }
    std::process::Command::new(executable)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| Error::other(format!("failed to spawn {}: {e}", executable.display())))?;
    Ok(())
}

/// CLI entry point.
///
/// # Errors
///
/// * `Other` if the named browser isn't detected.
/// * Any error from `patch_browser` (when patching is needed).
pub fn run(args: &Args) -> Result<()> {
    let detected = browsers::detect_browsers().unwrap_or_default();
    let browser = detected
        .iter()
        .find(|b| b.name().eq_ignore_ascii_case(&args.browser))
        .ok_or_else(|| Error::other(format!("no detected browser named '{}'", args.browser)))?
        .clone();
    let decision = decide(&browser);

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if matches!(decision, LaunchDecision::PatchAndSpawn) {
        writeln!(
            handle,
            "{} is not yet patched; running patch flow…",
            browser.name()
        )
        .map_err(Error::from)?;
        let manifest = crate::widevine::fetch_manifest()?;
        let cdm = crate::widevine::cache::ensure_cdm_for(&manifest)?;
        let patcher = crate::patch::host_patcher()?;
        let _ = crate::patch::patch_browser(
            &browser,
            &cdm,
            patcher.as_ref(),
            &crate::patch::PatchOptions::default(),
        )?;
    }
    let exe = browser_executable_path(&browser)?;
    writeln!(handle, "Launching {} ({})", browser.name(), exe.display()).map_err(Error::from)?;
    spawn_detached(&exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::BrowserKind;
    use std::fs;
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
    fn decide_unpatched_returns_patch_and_spawn() {
        let tmp = TempDir::new().unwrap();
        let b = fake_browser("Helium", tmp.path().join("h"));
        // is_patched() is the Phase-1 stub that returns false.
        assert_eq!(decide(&b), LaunchDecision::PatchAndSpawn);
    }

    #[test]
    fn spawn_detached_short_circuits_under_noop() {
        let tmp = TempDir::new().unwrap();
        let exe = tmp.path().join("nonexistent");
        // SAFETY: env mutations happen in serial test threads; we restore
        // at end-of-test.
        unsafe { std::env::set_var(NOOP_ENV, "1") };
        spawn_detached(&exe).expect("noop short-circuits");
        unsafe { std::env::remove_var(NOOP_ENV) };
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn browser_executable_path_resolves_lowercase_name() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("Helium");
        fs::create_dir_all(&install).unwrap();
        fs::write(install.join("helium"), "").unwrap();
        let b = fake_browser("Helium", install);
        let p = browser_executable_path(&b).expect("ok");
        assert!(p.ends_with("helium"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn browser_executable_path_falls_back_to_chrome() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("Helium");
        fs::create_dir_all(&install).unwrap();
        fs::write(install.join("chrome"), "").unwrap();
        let b = fake_browser("Helium", install);
        let p = browser_executable_path(&b).expect("ok");
        assert!(p.ends_with("chrome"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn browser_executable_path_no_executable_errors() {
        let tmp = TempDir::new().unwrap();
        let install = tmp.path().join("Helium");
        fs::create_dir_all(&install).unwrap();
        let b = fake_browser("Helium", install);
        let r = browser_executable_path(&b);
        assert!(r.is_err());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn browser_executable_path_macos_resolves_app_bundle() {
        let tmp = TempDir::new().unwrap();
        let app = tmp.path().join("Helium.app");
        fs::create_dir_all(app.join("Contents").join("MacOS")).unwrap();
        fs::write(app.join("Contents").join("MacOS").join("Helium"), "").unwrap();
        let b = fake_browser("Helium", app);
        let p = browser_executable_path(&b).expect("ok");
        assert!(p.ends_with("MacOS/Helium"));
    }

    #[test]
    fn launch_decision_clone_eq() {
        let a = LaunchDecision::AlreadyPatched;
        assert_eq!(a, a.clone());
    }
}
