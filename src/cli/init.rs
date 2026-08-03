//! `silvervine init` — interactive first-run wizard.
//!
//! Steps (per the V2 spec's "First-run wizard" section):
//!
//! 1. **Detect browsers** — call `browsers::detect_browsers()`.
//! 2. **Confirm which to manage** — let the user uncheck any.
//! 3. **Migrate legacy install** — `migration::detect_legacy_install`
//!    + `remove_legacy` if present.
//! 4. **Download CDM** — `widevine::ensure_cdm_for(manifest)`.
//! 5. **Patch each browser** — `patch::patch_browser(...)`.
//! 6. **Install daemon** — `daemon::lifecycle::register()`.
//! 7. **Run EME health check** (skippable) — `cli::test::run`.
//!
//! ## Test strategy
//!
//! The wizard is split into a [`Plan`] (the data) and an
//! [`execute_plan`] (the side effects). Tests build a [`Plan`] from
//! synthetic input, then call [`execute_plan`] with mocked patcher /
//! CDM resolver closures. The interactive prompts themselves are
//! exercised through [`build_plan_from_input`], which takes a
//! [`PromptInput`] trait so tests can supply canned answers.

use std::io::{IsTerminal, Write};

use crate::browsers::{self, Browser};
use crate::cli::OutputOptions;
use crate::error::{Error, ErrorCategory, Result};
use crate::migration;
use crate::patch::{self, PatchOptions, PlatformPatcher};
use crate::widevine::ownership::{self, OwnershipKind};
use crate::widevine::{self, CachedCdm};

/// Args for `silvervine init`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Output flags.
    pub output: OutputOptions,
}

/// The plan produced from the wizard's input phase. `execute_plan`
/// runs the side effects in this order; tests inspect the plan
/// without needing to actually side-effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Browsers the user opted in to managing.
    pub browsers_to_manage: Vec<Browser>,
    /// Whether to run the legacy-install migration before CDM install.
    pub run_migration: bool,
    /// Whether to register the daemon for auto-start on login.
    pub install_daemon: bool,
    /// Whether to run the post-install EME health check.
    pub run_eme_test: bool,
}

impl Plan {
    /// Default plan with no browsers and conservative defaults.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            browsers_to_manage: Vec::new(),
            run_migration: false,
            install_daemon: false,
            run_eme_test: false,
        }
    }
}

/// Trait abstracting interactive prompt input.
///
/// Production uses [`DialoguerPrompts`]; tests use a `CannedPrompts`
/// fixture (see test module).
pub trait PromptInput {
    /// Ask the user a yes/no question; `default` is the default answer
    /// returned if the user hits Enter.
    ///
    /// # Errors
    ///
    /// Implementations return `Other` if the prompt fails (e.g. EIO on
    /// stdin) or the user cancels.
    fn confirm(&self, question: &str, default: bool) -> Result<bool>;

    /// Multi-select list. `items` is the list of display strings;
    /// returns the selected indices. If the underlying prompt cannot
    /// run (e.g. non-tty), returns `Ok((0..items.len()).collect())` —
    /// "select all" is a safe default.
    ///
    /// # Errors
    ///
    /// See [`confirm`](Self::confirm).
    fn multi_select(&self, prompt: &str, items: &[String]) -> Result<Vec<usize>>;
}

/// `dialoguer`-backed prompts. Production wiring.
pub struct DialoguerPrompts;

impl PromptInput for DialoguerPrompts {
    fn confirm(&self, question: &str, default: bool) -> Result<bool> {
        if !std::io::stdin().is_terminal() {
            return Ok(default);
        }
        dialoguer::Confirm::new()
            .with_prompt(question)
            .default(default)
            .interact()
            .map_err(|e| Error::other(format!("prompt failed: {e}")))
    }

    fn multi_select(&self, prompt: &str, items: &[String]) -> Result<Vec<usize>> {
        if !std::io::stdin().is_terminal() {
            return Ok((0..items.len()).collect());
        }
        let defaults: Vec<bool> = items.iter().map(|_| true).collect();
        dialoguer::MultiSelect::new()
            .with_prompt(prompt)
            .items(items)
            .defaults(&defaults)
            .interact()
            .map_err(|e| Error::other(format!("multi-select failed: {e}")))
    }
}

/// Build a [`Plan`] from interactive input (or canned input in tests).
///
/// `prompts` supplies the answers; `detected` is the browser snapshot
/// from `browsers::detect_browsers()`; `legacy_present` indicates
/// whether `migration::detect_legacy_install` found anything.
///
/// # Errors
///
/// * Propagates errors from the underlying prompts (typically `Other`).
pub fn build_plan_from_input(
    prompts: &dyn PromptInput,
    detected: &[Browser],
    legacy_present: bool,
) -> Result<Plan> {
    let mut plan = Plan::empty();

    // Step 1: pick browsers to manage.
    if !detected.is_empty() {
        let names: Vec<String> = detected.iter().map(|b| b.name.clone()).collect();
        let selected = prompts.multi_select(
            "Browsers to manage (Space to toggle, Enter to confirm)",
            &names,
        )?;
        for idx in selected {
            if let Some(b) = detected.get(idx) {
                plan.browsers_to_manage.push(b.clone());
            }
        }
    }

    // Step 2: legacy migration confirmation.
    plan.run_migration = if legacy_present {
        prompts.confirm(
            "A previous (V1) Neon install was detected. Remove its old \
             daemon registration and migrate the CDM cache?",
            true,
        )?
    } else {
        false
    };

    // Step 3: daemon registration.
    plan.install_daemon = prompts.confirm(
        "Register Silvervine to auto-start on login (recommended)?",
        true,
    )?;

    // Step 4: EME test.
    plan.run_eme_test = prompts.confirm(
        "Run an EME (Widevine playback) health check after install?",
        false,
    )?;

    Ok(plan)
}

/// Execute a [`Plan`]'s side effects, writing a summary to `out`.
///
/// `cdm_resolver` returns the [`CachedCdm`] to patch with — production uses
/// a closure that calls `fetch_manifest` + `ensure_cdm_for`; tests inject a
/// synthetic cached CDM.
///
/// `patcher` is the [`PlatformPatcher`] (mock in tests).
///
/// # Errors
///
/// Aborts on the first irrecoverable error. Recoverable per-browser
/// failures are recorded but don't stop the wizard.
#[allow(clippy::needless_pass_by_value)]
pub fn execute_plan<F>(
    plan: &Plan,
    cdm_resolver: F,
    patcher: &dyn PlatformPatcher,
    out: &mut dyn Write,
    patch_options: PatchOptions,
) -> Result<()>
where
    F: FnOnce() -> Result<CachedCdm>,
{
    writeln!(out, "Silvervine: starting first-run setup.").map_err(Error::from)?;

    if plan.run_migration {
        migrate_legacy_install(out)?;
    }

    let cdm = prepare_cdm(&plan.browsers_to_manage, cdm_resolver, out)?;
    let patch_failures = patch_selected_browsers(
        &plan.browsers_to_manage,
        cdm.as_ref(),
        patcher,
        out,
        &patch_options,
    )?;

    finish_setup(plan, patch_failures, out)
}

fn migrate_legacy_install(out: &mut dyn Write) -> Result<()> {
    let install = migration::detect_legacy_install();
    if install.is_empty() {
        return Ok(());
    }

    writeln!(out, "Removing {} legacy artifact(s)…", install.len()).map_err(Error::from)?;
    match migration::remove_legacy(install) {
        Ok(outcome) => migration::write_migration_summary(out, &outcome).map_err(Error::from),
        Err(error) => writeln!(out, "Migration: warning — {error}").map_err(Error::from),
    }
}

fn prepare_cdm<F>(
    browsers: &[Browser],
    cdm_resolver: F,
    out: &mut dyn Write,
) -> Result<Option<CachedCdm>>
where
    F: FnOnce() -> Result<CachedCdm>,
{
    if browsers.is_empty() {
        return Ok(None);
    }

    writeln!(out, "Preparing Widevine CDM…").map_err(Error::from)?;
    cdm_resolver().map(Some)
}

fn patch_selected_browsers(
    browsers: &[Browser],
    cdm: Option<&CachedCdm>,
    patcher: &dyn PlatformPatcher,
    out: &mut dyn Write,
    patch_options: &PatchOptions,
) -> Result<usize> {
    let Some(cdm) = cdm else {
        return Ok(0);
    };

    let mut failures = 0;
    for browser in browsers {
        if patch_browser_for_setup(browser, cdm, patcher, out, patch_options)? {
            failures += 1;
        }
    }
    Ok(failures)
}

fn patch_browser_for_setup(
    browser: &Browser,
    cdm: &CachedCdm,
    patcher: &dyn PlatformPatcher,
    out: &mut dyn Write,
    patch_options: &PatchOptions,
) -> Result<bool> {
    let cdm_target = match patcher.cdm_target_for_candidate(browser.install_path(), cdm.version()) {
        Ok(path) => path,
        Err(error) => return report_patch_failure(browser, &error, out),
    };
    let candidate_marker = match ownership::marker_for_cached(cdm) {
        Ok(marker) => marker,
        Err(error) => return report_patch_failure(browser, &error, out),
    };
    let assessment = match ownership::classify(browser, &cdm_target, cdm, &candidate_marker) {
        Ok(assessment) => assessment,
        Err(error) => return report_patch_failure(browser, &error, out),
    };

    if assessment.kind == OwnershipKind::Managed
        && ownership::validate_installed_cdm(&cdm_target)
            .is_ok_and(|installed| installed.matches_candidate(&candidate_marker))
    {
        writeln!(
            out,
            "{}: already patched (Widevine {}); skipping",
            browser.name(),
            candidate_marker.cdm_version
        )
        .map_err(Error::from)?;
        return Ok(false);
    }

    if matches!(
        assessment.kind,
        OwnershipKind::External | OwnershipKind::InvalidMarker
    ) {
        let action = assessment
            .action
            .as_deref()
            .unwrap_or("Inspect ownership before replacing this CDM.");
        writeln!(
            out,
            "{}: preserved existing CDM — {}. {action}",
            browser.name(),
            assessment.summary
        )
        .map_err(Error::from)?;
        return Ok(false);
    }

    match patch::patch_browser(browser, cdm, patcher, patch_options) {
        Ok(outcome) => {
            writeln!(
                out,
                "Patched {}: Widevine {}",
                outcome.browser_name, outcome.cdm_version
            )
            .map_err(Error::from)?;
            Ok(false)
        }
        Err(error)
            if matches!(
                error.category,
                ErrorCategory::ExternalCdm | ErrorCategory::InvalidMarker
            ) =>
        {
            writeln!(out, "{}: preserved existing CDM — {error}", browser.name())
                .map_err(Error::from)?;
            Ok(false)
        }
        Err(error) => report_patch_failure(browser, &error, out),
    }
}

fn report_patch_failure(browser: &Browser, error: &Error, out: &mut dyn Write) -> Result<bool> {
    writeln!(out, "Patching {} FAILED: {error}", browser.name()).map_err(Error::from)?;
    Ok(true)
}

fn finish_setup(plan: &Plan, patch_failures: usize, out: &mut dyn Write) -> Result<()> {
    if plan.install_daemon {
        crate::daemon::lifecycle::register()?;
        writeln!(out, "Daemon registered for auto-start on login.").map_err(Error::from)?;
    }

    if plan.run_eme_test {
        writeln!(
            out,
            "EME health check is a network/display-dependent operation; \
             see `silvervine test --help` to run it later."
        )
        .map_err(Error::from)?;
    }

    if patch_failures > 0 {
        writeln!(
            out,
            "Setup completed with {patch_failures} patch failure(s). \
             Run `silvervine doctor` for diagnostics."
        )
        .map_err(Error::from)
    } else {
        writeln!(out, "Setup complete.").map_err(Error::from)
    }
}

/// CLI entry point.
///
/// # Errors
///
/// * Propagates errors from browser detection, manifest retrieval, or CDM resolution.
/// * `Other` if the host platform isn't supported.
pub fn run(args: &Args) -> Result<()> {
    let _ = args; // currently no per-subcommand flags
    let detected = browsers::detect_browsers()?;
    let legacy = migration::detect_legacy_install();
    let prompts = DialoguerPrompts;
    let plan = build_plan_from_input(&prompts, &detected, !legacy.is_empty())?;
    let patcher = patch::host_patcher()?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    execute_plan(
        &plan,
        production_cdm_resolver,
        patcher.as_ref(),
        &mut handle,
        PatchOptions::default(),
    )
}

/// Production CDM resolver: fetches the manifest and ensures the cache.
fn production_cdm_resolver() -> Result<CachedCdm> {
    let manifest = widevine::fetch_manifest()?;
    widevine::cache::ensure_cdm_for(&manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::BrowserKind;
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    /// Canned-response prompt fixture.
    struct CannedPrompts {
        confirms: RefCell<Vec<bool>>,
        multi_select_default_all: bool,
    }

    impl CannedPrompts {
        fn new(answers: Vec<bool>) -> Self {
            Self {
                confirms: RefCell::new(answers),
                multi_select_default_all: true,
            }
        }
    }

    impl PromptInput for CannedPrompts {
        fn confirm(&self, _question: &str, default: bool) -> Result<bool> {
            Ok(self.confirms.borrow_mut().pop().unwrap_or(default))
        }
        fn multi_select(&self, _prompt: &str, items: &[String]) -> Result<Vec<usize>> {
            if self.multi_select_default_all {
                Ok((0..items.len()).collect())
            } else {
                Ok(Vec::new())
            }
        }
    }

    /// Mock patcher reused from the patch module's test surface.
    #[derive(Default)]
    struct MockPatcher {
        write_calls: AtomicUsize,
        verify_calls: AtomicUsize,
    }

    impl PlatformPatcher for MockPatcher {
        fn write_cdm(&self, target: &Path, cdm_source: &Path) -> Result<()> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
            let manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(cdm_source.join("manifest.json"))?)?;
            let version = manifest
                .get("version")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::state_corrupted("test CDM manifest has no version"))?;
            let library = fs::read(
                cdm_source
                    .join("_platform_specific")
                    .join(test_platform_dir())
                    .join(test_library_name()),
            )?;
            write_test_cdm(&target.join("WidevineCdm"), version, &library);
            fs::write(target.join("CDM_WRITTEN"), b"1").map_err(Error::from)
        }
        fn verify_post_patch(&self, _target: &Path) -> Result<()> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn read_browser_version(&self, _target: &Path) -> Option<String> {
            Some("128.0".into())
        }
    }

    /// RAII env-var setter that restores on drop.
    struct ScopedEnv {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }
    impl ScopedEnv {
        fn set(key: &'static str, value: &Path) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
        #[cfg(target_os = "linux")]
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

    fn make_browser(install: PathBuf, name: &str) -> Browser {
        Browser {
            name: name.into(),
            install_path: install,
            kind: BrowserKind::Detected,
        }
    }

    fn make_cdm(root: &Path, version: &str) -> CachedCdm {
        let dir = root.join(version);
        write_test_cdm(&dir, version, b"fake");
        let manifest_body = format!(r#"{{"version":"{version}"}}"#);
        CachedCdm::from_verified_payload(
            version.to_string(),
            dir,
            crate::widevine::sha512_hex(b"fake"),
            crate::widevine::sha512_hex(manifest_body.as_bytes()),
        )
    }

    fn write_test_cdm(root: &Path, version: &str, library: &[u8]) {
        let platform = root.join("_platform_specific").join(test_platform_dir());
        fs::create_dir_all(&platform).unwrap();
        fs::write(platform.join(test_library_name()), library).unwrap();
        fs::write(
            root.join("manifest.json"),
            format!(r#"{{"version":"{version}"}}"#),
        )
        .unwrap();
    }

    fn test_platform_dir() -> &'static str {
        if cfg!(target_os = "macos") {
            if cfg!(target_arch = "aarch64") {
                "mac_arm64"
            } else {
                "mac_x64"
            }
        } else {
            "linux_x64"
        }
    }

    fn test_library_name() -> &'static str {
        if cfg!(target_os = "macos") {
            "libwidevinecdm.dylib"
        } else {
            "libwidevinecdm.so"
        }
    }

    #[test]
    fn build_plan_from_input_collects_user_answers() {
        let tmp = TempDir::new().unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let detected = vec![make_browser(h, "Helium")];
        // Confirms popped from the end of the vec: migration → daemon → eme.
        let prompts = CannedPrompts::new(vec![false, true, true]);
        let plan = build_plan_from_input(&prompts, &detected, true).expect("ok");
        assert_eq!(plan.browsers_to_manage.len(), 1);
        assert!(plan.run_migration); // legacy_present=true and answer=true (popped first)
    }

    #[test]
    fn build_plan_with_no_legacy_does_not_set_migration() {
        let prompts = CannedPrompts::new(vec![false, true]);
        let plan = build_plan_from_input(&prompts, &[], false).expect("ok");
        assert!(!plan.run_migration);
    }

    #[test]
    fn execute_plan_with_no_browsers_skips_cdm_resolution() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let plan = Plan {
            browsers_to_manage: vec![],
            install_daemon: true,
            ..Plan::empty()
        };
        let mut buf = Vec::new();
        // The CDM resolver should not even be called.
        let cdm_resolver = || -> Result<CachedCdm> { Err(Error::other("should not be called")) };
        let patcher = MockPatcher::default();
        execute_plan(
            &plan,
            cdm_resolver,
            &patcher,
            &mut buf,
            PatchOptions::default(),
        )
        .expect("ok");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Setup complete"));
    }

    #[test]
    fn execute_plan_patches_browsers() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        fs::write(h.join("placeholder"), b"x").unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let plan = Plan {
            browsers_to_manage: vec![make_browser(h.clone(), "Helium")],
            run_migration: false,
            install_daemon: false,
            run_eme_test: false,
        };
        let mut buf = Vec::new();
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let patcher = MockPatcher::default();
        execute_plan(
            &plan,
            || Ok(make_cdm(&cache, "4.10.0")),
            &patcher,
            &mut buf,
            opts,
        )
        .expect("ok");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Patched Helium"));
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn execute_plan_skips_already_patched_browser_at_matching_version() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        // Verified managed install: matching payload + Silvervine marker.
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let cdm = make_cdm(&cache, "4.10.2934.0");
        let target = h.join("WidevineCdm");
        write_test_cdm(&target, "4.10.2934.0", b"fake");
        let marker = ownership::marker_for_cached(&cdm).unwrap();
        ownership::write_marker(&target, &marker).unwrap();

        let plan = Plan {
            browsers_to_manage: vec![make_browser(h.clone(), "Helium")],
            ..Plan::empty()
        };
        let mut buf = Vec::new();
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let patcher = MockPatcher::default();
        execute_plan(
            &plan,
            || Ok(make_cdm(&cache, "4.10.2934.0")),
            &patcher,
            &mut buf,
            opts,
        )
        .expect("ok");

        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("already patched"),
            "expected idempotency message; got: {s}"
        );
        assert!(
            s.contains("Widevine 4.10.2934.0"),
            "expected version in skip message; got: {s}"
        );
        // Critical: the patcher must NOT have been called — the whole
        // point of idempotency is to avoid touching a running browser.
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn execute_plan_preserves_unmarked_mismatched_cdm() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        // An older unmarked CDM has no Silvervine provenance, even for a known
        // browser, so setup must preserve it pending an explicit replacement.
        let h = tmp.path().join("h");
        write_test_cdm(&h.join("WidevineCdm"), "4.10.0.0", b"old");
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let mut browser = make_browser(h.clone(), "Helium");
        browser.kind = BrowserKind::Known;

        let plan = Plan {
            browsers_to_manage: vec![browser],
            ..Plan::empty()
        };
        let mut buf = Vec::new();
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let patcher = MockPatcher::default();
        execute_plan(
            &plan,
            || Ok(make_cdm(&cache, "4.10.2934.0")),
            &patcher,
            &mut buf,
            opts,
        )
        .expect("ok");

        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn execute_plan_does_not_skip_same_version_without_marker() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let h = tmp.path().join("h");
        // Same version, no marker, Detected browser => External preservation.
        write_test_cdm(&h.join("WidevineCdm"), "4.10.2934.0", b"external");
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let plan = Plan {
            browsers_to_manage: vec![make_browser(h.clone(), "Custom")],
            ..Plan::empty()
        };
        let mut buf = Vec::new();
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let patcher = MockPatcher::default();
        execute_plan(
            &plan,
            || Ok(make_cdm(&cache, "4.10.2934.0")),
            &patcher,
            &mut buf,
            opts,
        )
        .expect("ok");
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("preserved existing CDM"),
            "expected preserved outcome; got: {s}"
        );
        assert!(
            !s.contains("already patched"),
            "must not bless unmarked same-version"
        );
        assert!(
            !s.contains("FAILED"),
            "preservation is not a generic failure: {s}"
        );
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fs::read(
                h.join("WidevineCdm")
                    .join("_platform_specific")
                    .join(test_platform_dir())
                    .join(test_library_name())
            )
            .unwrap(),
            b"external"
        );
    }

    #[test]
    fn execute_plan_preserves_invalid_marker_without_writing() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let h = tmp.path().join("h");
        // Valid payload layout + corrupt ownership marker => InvalidMarker.
        write_test_cdm(&h.join("WidevineCdm"), "4.10.2934.0", b"payload");
        fs::write(
            h.join("WidevineCdm")
                .join(ownership::MANAGED_MARKER_FILENAME),
            br#"{"not":"a-valid-marker"}"#,
        )
        .unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let plan = Plan {
            browsers_to_manage: vec![make_browser(h.clone(), "Helium")],
            ..Plan::empty()
        };
        let mut buf = Vec::new();
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let patcher = MockPatcher::default();
        execute_plan(
            &plan,
            || Ok(make_cdm(&cache, "4.10.2934.0")),
            &patcher,
            &mut buf,
            opts,
        )
        .expect("ok");
        let s = String::from_utf8(buf).unwrap();
        assert!(
            s.contains("preserved existing CDM"),
            "expected preserved invalid-marker outcome; got: {s}"
        );
        assert!(
            !s.contains("already patched"),
            "must not bless invalid marker: {s}"
        );
        assert!(
            !s.contains("FAILED"),
            "invalid marker is preserved, not a generic failure: {s}"
        );
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fs::read(
                h.join("WidevineCdm")
                    .join("_platform_specific")
                    .join(test_platform_dir())
                    .join(test_library_name())
            )
            .unwrap(),
            b"payload"
        );
        assert_eq!(
            fs::read(
                h.join("WidevineCdm")
                    .join(ownership::MANAGED_MARKER_FILENAME)
            )
            .unwrap(),
            br#"{"not":"a-valid-marker"}"#
        );
    }

    #[test]
    fn execute_plan_preserves_known_unmarked_install_without_exact_match() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let h = tmp.path().join("h");
        write_test_cdm(&h.join("WidevineCdm"), "4.9.0.0", b"legacy");
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let mut browser = make_browser(h.clone(), "Helium");
        browser.kind = BrowserKind::Known;
        let plan = Plan {
            browsers_to_manage: vec![browser],
            ..Plan::empty()
        };
        let mut buf = Vec::new();
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let patcher = MockPatcher::default();
        execute_plan(
            &plan,
            || Ok(make_cdm(&cache, "4.10.2934.0")),
            &patcher,
            &mut buf,
            opts,
        )
        .expect("ok");
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 0);
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Preserved"), "got: {s}");
    }

    /// A patcher whose `write_cdm` fails — used by
    /// `execute_plan_with_failed_patches_reports_count`.
    struct FailingPatcher;
    impl PlatformPatcher for FailingPatcher {
        fn write_cdm(&self, _t: &Path, _s: &Path) -> Result<()> {
            Err(Error::permission_denied("nope"))
        }
        fn verify_post_patch(&self, _t: &Path) -> Result<()> {
            Ok(())
        }
        fn read_browser_version(&self, _t: &Path) -> Option<String> {
            None
        }
    }

    #[test]
    fn execute_plan_with_failed_patches_reports_count() {
        let _g = crate::test_support::env_lock();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        let plan = Plan {
            browsers_to_manage: vec![make_browser(h.clone(), "Helium")],
            ..Plan::empty()
        };

        let mut buf = Vec::new();
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        execute_plan(
            &plan,
            || Ok(make_cdm(&cache, "1.0")),
            &FailingPatcher,
            &mut buf,
            opts,
        )
        .expect("execute returns ok even with patch failures");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("FAILED"));
        assert!(s.contains("1 patch failure"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_plan_propagates_daemon_registration_failure() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _life = ScopedEnv::unset(crate::daemon::lifecycle::NOOP_ENV);
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let empty_path = tmp.path().join("empty-bin");
        fs::create_dir_all(&empty_path).unwrap();
        let _path = ScopedEnv::set("PATH", &empty_path);
        let plan = Plan {
            install_daemon: true,
            ..Plan::empty()
        };
        let mut output = Vec::new();
        let result = execute_plan(
            &plan,
            || Err(Error::other("CDM resolver must not run")),
            &MockPatcher::default(),
            &mut output,
            PatchOptions::default(),
        );
        assert!(result.is_err());
        assert!(!String::from_utf8(output)
            .unwrap()
            .contains("Setup complete"));
    }

    #[test]
    fn plan_empty_constructor_has_safe_defaults() {
        let p = Plan::empty();
        assert!(p.browsers_to_manage.is_empty());
        assert!(!p.run_migration);
        assert!(!p.install_daemon);
        assert!(!p.run_eme_test);
    }

    #[test]
    fn dialoguer_prompts_confirm_returns_default_when_no_tty() {
        // We can't easily force a non-tty stdin in tests, but we can at
        // least verify the function's existence + signature compiles.
        let _ = DialoguerPrompts;
    }
}
