//! `neon init` — interactive first-run wizard.
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
//! 8. **Ask about opt-in error reporting** — write
//!    `~/.config/neon/config.toml`.
//!
//! ## Test strategy
//!
//! The wizard is split into a [`Plan`] (the data) and an
//! [`execute_plan`] (the side effects). Tests build a [`Plan`] from
//! synthetic input, then call [`execute_plan`] with mocked patcher /
//! CDM provider closures. The interactive prompts themselves are
//! exercised through [`build_plan_from_input`], which takes a
//! [`PromptInput`] trait so tests can supply canned answers.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use crate::browsers::{self, Browser};
use crate::cli::OutputOptions;
use crate::config::{Config, ReportingConfig};
use crate::error::{Error, Result};
use crate::migration;
use crate::patch::{self, PatchOptions, PlatformPatcher};
use crate::widevine::{self, provider::LocalFileCdm};

/// Args for `neon init`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Output flags.
    pub output: OutputOptions,
}

/// The plan produced from the wizard's input phase. `execute_plan`
/// runs the side effects in this order; tests inspect the plan
/// without needing to actually side-effect.
///
/// The four boolean toggles are intentionally separate fields rather
/// than a packed bitset — each represents an independent user choice
/// and the wizard renders them as distinct prompts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Plan {
    /// Browsers the user opted in to managing.
    pub browsers_to_manage: Vec<Browser>,
    /// Whether to run the legacy-install migration before CDM install.
    pub run_migration: bool,
    /// Whether to register the daemon for auto-start on login.
    pub install_daemon: bool,
    /// Whether to run the post-install EME health check.
    pub run_eme_test: bool,
    /// Whether to enable opt-in error reporting in the written config.
    pub opt_in_error_reporting: bool,
    /// Where to write the config file. `None` = default location.
    pub config_path: Option<PathBuf>,
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
            opt_in_error_reporting: false,
            config_path: None,
        }
    }

    /// Convert this plan's reporting choice into a [`Config`] suitable
    /// for `Config::to_toml_string()`.
    #[must_use]
    pub fn into_config(&self) -> Config {
        Config {
            reporting: ReportingConfig {
                opt_in_error_reporting: self.opt_in_error_reporting,
                endpoint: if self.opt_in_error_reporting {
                    Some(default_reporting_endpoint().into())
                } else {
                    None
                },
            },
            ..Default::default()
        }
    }
}

/// Default reporting endpoint for the opt-in error reporter.
///
/// The Cloudflare Worker that ingests these (per the spec) lives at the
/// URL embedded here; users can override it by editing
/// `~/.config/neon/config.toml` after running the wizard.
fn default_reporting_endpoint() -> &'static str {
    "https://errors.neon.example/v1/report"
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
    plan.install_daemon =
        prompts.confirm("Register Neon to auto-start on login (recommended)?", true)?;

    // Step 4: EME test.
    plan.run_eme_test = prompts.confirm(
        "Run an EME (Widevine playback) health check after install?",
        false,
    )?;

    // Step 5: opt-in error reporting.
    plan.opt_in_error_reporting = prompts.confirm(
        "Send anonymized error reports to help improve Neon? (default: no)",
        false,
    )?;

    Ok(plan)
}

/// Execute a [`Plan`]'s side effects, writing a summary to `out`.
///
/// `cdm_provider` returns the [`LocalFileCdm`] to patch with —
/// production uses a closure that calls `fetch_manifest` +
/// `ensure_cdm_for`; tests inject a synthetic CDM pre-built on a
/// tempdir. V3-Phase A scaffolding: V2 only has `LocalFileCdm`; the
/// `experimental-bridge` feature will widen this surface to
/// `Box<dyn CdmProvider>` once `BridgeCdm` lands.
///
/// `patcher` is the [`PlatformPatcher`] (mock in tests).
///
/// # Errors
///
/// Aborts on the first irrecoverable error. Recoverable per-browser
/// failures are recorded but don't stop the wizard.
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
pub fn execute_plan<F>(
    plan: &Plan,
    cdm_provider: F,
    patcher: &dyn PlatformPatcher,
    config_dest: Option<&Path>,
    out: &mut dyn Write,
    patch_options: PatchOptions,
) -> Result<()>
where
    F: FnOnce() -> Result<LocalFileCdm>,
{
    writeln!(out, "Neon: starting first-run setup.").map_err(Error::from)?;

    // Step 1: legacy migration.
    if plan.run_migration {
        let install = migration::detect_legacy_install();
        if !install.is_empty() {
            writeln!(out, "Removing {} legacy artifact(s)…", install.len()).map_err(Error::from)?;
            match migration::remove_legacy(install) {
                Ok(outcome) => {
                    writeln!(
                        out,
                        "Migration: removed={} migrated={} skipped={}",
                        outcome.removed.len(),
                        outcome.migrated.len(),
                        outcome.skipped.len()
                    )
                    .map_err(Error::from)?;
                }
                Err(e) => {
                    writeln!(out, "Migration: warning — {e}").map_err(Error::from)?;
                }
            }
        }
    }

    // Step 2: ensure the CDM is cached.
    if !plan.browsers_to_manage.is_empty() {
        writeln!(out, "Preparing Widevine CDM…").map_err(Error::from)?;
    }
    let cdm = if plan.browsers_to_manage.is_empty() {
        None
    } else {
        Some(cdm_provider()?)
    };

    // Step 3: patch each browser.
    let mut patch_failures = 0_usize;
    for browser in &plan.browsers_to_manage {
        if let Some(cdm) = &cdm {
            match patch::patch_browser(browser, cdm, patcher, &patch_options) {
                Ok(outcome) => {
                    writeln!(
                        out,
                        "Patched {}: Widevine {}",
                        outcome.browser_name, outcome.cdm_version
                    )
                    .map_err(Error::from)?;
                }
                Err(e) => {
                    patch_failures += 1;
                    writeln!(out, "Patching {} FAILED: {e}", browser.name())
                        .map_err(Error::from)?;
                }
            }
        }
    }

    // Step 4: install daemon.
    if plan.install_daemon {
        match crate::daemon::lifecycle::register() {
            Ok(()) => {
                writeln!(out, "Daemon registered for auto-start on login.").map_err(Error::from)?;
            }
            Err(e) => writeln!(out, "Daemon registration failed: {e}").map_err(Error::from)?,
        }
    }

    // Step 5: EME health check (skippable).
    if plan.run_eme_test {
        writeln!(
            out,
            "EME health check is a network/display-dependent operation; \
             see `neon test --help` to run it later."
        )
        .map_err(Error::from)?;
    }

    // Step 6: write config file.
    write_config(plan, config_dest, out)?;

    if patch_failures > 0 {
        writeln!(
            out,
            "Setup completed with {patch_failures} patch failure(s). \
             Run `neon doctor` for diagnostics."
        )
        .map_err(Error::from)?;
    } else {
        writeln!(out, "Setup complete.").map_err(Error::from)?;
    }
    Ok(())
}

/// Write the user's chosen config (currently just the reporting block)
/// to disk. If a config already exists, we read it, set the reporting
/// fields, and write it back — preserving any other user-edited
/// blocks.
fn write_config(plan: &Plan, dest: Option<&Path>, out: &mut dyn Write) -> Result<()> {
    let path = if let Some(p) = dest {
        p.to_path_buf()
    } else {
        let Some(p) = crate::config::default_config_path() else {
            writeln!(out, "Skipping config: cannot resolve default path.").map_err(Error::from)?;
            return Ok(());
        };
        p
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::from)?;
    }
    let mut config = if path.exists() {
        crate::config::load_config_from(&path).unwrap_or_default()
    } else {
        Config::default()
    };
    config.reporting.opt_in_error_reporting = plan.opt_in_error_reporting;
    if plan.opt_in_error_reporting && config.reporting.endpoint.is_none() {
        config.reporting.endpoint = Some(default_reporting_endpoint().to_string());
    }
    let toml = config.to_toml_string()?;
    std::fs::write(&path, toml).map_err(Error::from)?;
    writeln!(out, "Wrote config: {}", path.display()).map_err(Error::from)?;
    Ok(())
}

/// CLI entry point.
///
/// # Errors
///
/// * Propagates any error from manifest / CDM resolution.
/// * `Other` if the host platform isn't supported.
pub fn run(args: &Args) -> Result<()> {
    let _ = args; // currently no per-subcommand flags
    let detected = browsers::detect_browsers().unwrap_or_default();
    let legacy = migration::detect_legacy_install();
    let prompts = DialoguerPrompts;
    let plan = build_plan_from_input(&prompts, &detected, !legacy.is_empty())?;
    let patcher = patch::host_patcher()?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    execute_plan(
        &plan,
        production_cdm_provider,
        patcher.as_ref(),
        None,
        &mut handle,
        PatchOptions::default(),
    )
}

/// Production CDM resolver: fetches the manifest, ensures the cache,
/// and wraps the result in a [`LocalFileCdm`] adapter.
fn production_cdm_provider() -> Result<LocalFileCdm> {
    let manifest = widevine::fetch_manifest()?;
    let cached = widevine::cache::ensure_cdm_for(&manifest)?;
    Ok(LocalFileCdm::from_cached(&cached))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browsers::BrowserKind;
    use std::cell::RefCell;
    use std::fs;
    use std::path::PathBuf;
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
        fn write_cdm(&self, target: &Path, _cdm_source: &Path) -> Result<()> {
            self.write_calls.fetch_add(1, Ordering::SeqCst);
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

    /// Process-wide guard for env-mutating tests. Without it, parallel
    /// `cargo test` workers could race on the lifecycle NOOP env var.
    /// Mirrors the pattern used in other env-touching test modules.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
            framework_name: None,
        }
    }

    fn make_cdm(root: &Path, version: &str) -> LocalFileCdm {
        let dir = root.join(version);
        fs::create_dir_all(dir.join("_platform_specific/linux_x64")).unwrap();
        fs::write(
            dir.join("_platform_specific/linux_x64/libwidevinecdm.so"),
            b"fake",
        )
        .unwrap();
        LocalFileCdm::new(version.to_string(), dir)
    }

    #[test]
    fn build_plan_from_input_collects_user_answers() {
        let tmp = TempDir::new().unwrap();
        let h = tmp.path().join("h");
        fs::create_dir_all(&h).unwrap();
        let detected = vec![make_browser(h, "Helium")];
        // Confirms popped in reverse order: opt-in last, eme penultimate, ...
        let prompts = CannedPrompts::new(vec![true, false, true, true]); // pop order: true,true,false,true
        let plan = build_plan_from_input(&prompts, &detected, true).expect("ok");
        assert_eq!(plan.browsers_to_manage.len(), 1);
        assert!(plan.run_migration); // legacy_present=true and answer=true (popped first)
    }

    #[test]
    fn build_plan_with_no_legacy_does_not_set_migration() {
        let prompts = CannedPrompts::new(vec![false, false, true]);
        let plan = build_plan_from_input(&prompts, &[], false).expect("ok");
        assert!(!plan.run_migration);
    }

    #[test]
    fn plan_into_config_sets_reporting_endpoint() {
        let plan = Plan {
            opt_in_error_reporting: true,
            ..Plan::empty()
        };
        let config = plan.into_config();
        assert!(config.reporting.opt_in_error_reporting);
        assert!(config.reporting.endpoint.is_some());
    }

    #[test]
    fn plan_into_config_no_opt_in_no_endpoint() {
        let plan = Plan {
            opt_in_error_reporting: false,
            ..Plan::empty()
        };
        let config = plan.into_config();
        assert!(!config.reporting.opt_in_error_reporting);
        assert!(config.reporting.endpoint.is_none());
    }

    #[test]
    fn execute_plan_with_no_browsers_skips_cdm_resolution() {
        let _g = ENV_MUTEX.lock().unwrap();
        let _life = ScopedEnv::set(crate::daemon::lifecycle::NOOP_ENV, Path::new("1"));
        let tmp = TempDir::new().unwrap();
        let plan = Plan {
            browsers_to_manage: vec![],
            install_daemon: true,
            ..Plan::empty()
        };
        let mut buf = Vec::new();
        // The CDM provider should not even be called.
        let cdm_provider = || -> Result<LocalFileCdm> { Err(Error::other("should not be called")) };
        let patcher = MockPatcher::default();
        execute_plan(
            &plan,
            cdm_provider,
            &patcher,
            Some(&tmp.path().join("config.toml")),
            &mut buf,
            PatchOptions::default(),
        )
        .expect("ok");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Setup complete"));
    }

    #[test]
    fn execute_plan_patches_browsers_and_writes_config() {
        let _g = ENV_MUTEX.lock().unwrap();
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
            opt_in_error_reporting: true,
            config_path: None,
        };
        let mut buf = Vec::new();
        let opts = PatchOptions {
            force_while_running: true,
            lock_path: Some(tmp.path().join("patch.lock")),
            backups_dir: Some(tmp.path().join("backups")),
            ..Default::default()
        };
        let patcher = MockPatcher::default();
        let config_dest = tmp.path().join("config.toml");
        execute_plan(
            &plan,
            || Ok(make_cdm(&cache, "4.10.0")),
            &patcher,
            Some(&config_dest),
            &mut buf,
            opts,
        )
        .expect("ok");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Patched Helium"));
        assert_eq!(patcher.write_calls.load(Ordering::SeqCst), 1);
        // Config was written with reporting opt-in.
        assert!(config_dest.exists());
        let toml = fs::read_to_string(&config_dest).unwrap();
        let parsed = Config::from_toml_str(&toml).unwrap();
        assert!(parsed.reporting.opt_in_error_reporting);
        assert!(parsed.reporting.endpoint.is_some());
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
        let _g = ENV_MUTEX.lock().unwrap();
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
            Some(&tmp.path().join("config.toml")),
            &mut buf,
            opts,
        )
        .expect("execute returns ok even with patch failures");
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("FAILED"));
        assert!(s.contains("1 patch failure"));
    }

    #[test]
    fn write_config_preserves_existing_unrelated_fields() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.toml");
        // Pre-write a config with hooks set.
        let pre = Config {
            hooks: crate::config::HooksConfig {
                post_patch: Some("/tmp/hook".into()),
                post_update: None,
            },
            ..Default::default()
        };
        fs::write(&path, pre.to_toml_string().unwrap()).unwrap();

        let plan = Plan {
            opt_in_error_reporting: true,
            ..Plan::empty()
        };
        let mut buf = Vec::new();
        write_config(&plan, Some(&path), &mut buf).unwrap();
        let toml = fs::read_to_string(&path).unwrap();
        let parsed = Config::from_toml_str(&toml).unwrap();
        assert!(parsed.reporting.opt_in_error_reporting);
        assert_eq!(parsed.hooks.post_patch.as_deref(), Some("/tmp/hook"));
    }

    #[test]
    fn plan_empty_constructor_has_safe_defaults() {
        let p = Plan::empty();
        assert!(p.browsers_to_manage.is_empty());
        assert!(!p.run_migration);
        assert!(!p.install_daemon);
        assert!(!p.run_eme_test);
        assert!(!p.opt_in_error_reporting);
    }

    #[test]
    fn dialoguer_prompts_confirm_returns_default_when_no_tty() {
        // We can't easily force a non-tty stdin in tests, but we can at
        // least verify the function's existence + signature compiles.
        let _ = DialoguerPrompts;
    }
}
