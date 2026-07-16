//! User-defined hook script runner.
//!
//! After certain daemon events (a successful patch, a CDM update, etc.) the
//! daemon shells out to user-supplied scripts in the platform config directory,
//! passing context as environment variables. The contract with the user is:
//!
//! * Hook scripts live at the path configured via `[hooks]` in the Silvervine config,
//!   defaulting to `~/.config/silvervine/hooks/` on Linux and
//!   `~/Library/Application Support/silvervine/hooks/` on macOS when no explicit
//!   path is set.
//! * Scripts must be **executable files** (`chmod +x`). Non-executable or
//!   missing files are not an error — they're [`HookOutcome::NotConfigured`]
//!   so a user who never wired up hooks doesn't get spurious daemon errors.
//! * Scripts receive the event context via environment variables:
//!   * `SILVERVINE_BROWSER` — display name of the affected browser, when relevant
//!   * `SILVERVINE_VERSION` — browser version, when known
//!   * `SILVERVINE_CDM_VERSION` — Widevine CDM version, when relevant
//!   * `SILVERVINE_OUTCOME` — `"success"` or `"failure"`
//!
//!   During 2.x, matching deprecated `NEON_*` aliases are exported as well.
//!   If callers explicitly provide both names, neither value is overwritten.
//!
//!   Callers populate the [`HashMap`](std::collections::HashMap) passed to
//!   [`run_hook`] with whichever keys apply to the event; missing keys are
//!   simply not exported.
//! * Standard out / standard error are captured into [`HookOutcome::Ran`]
//!   so the daemon can include them in its tracing output. We do **not**
//!   forward the script's exit code back to the caller for control-flow
//!   purposes — a non-zero exit is logged but does not fail the daemon.
//!
//! ## What this module does NOT do
//!
//! * No hook discovery — callers (daemon team's `mod.rs`) decide which named
//!   hook under the platform config directory to invoke.
//! * No `tracing` subscriber configuration — the daemon installs one in
//!   `daemon::run()`. The hook runner uses `tracing::warn!`/`info!` calls
//!   that are no-ops without a subscriber installed.
//!
//! ## Public API
//!
//! ```ignore
//! pub enum HookOutcome { NotConfigured, Ran { exit_status, stdout, stderr } }
//! pub fn run_hook(name: &str, env: &HashMap<String, String>) -> Result<HookOutcome>;
//! pub fn run_hook_at(path: &Path, env: &HashMap<String, String>) -> Result<HookOutcome>;
//! ```
//!
//! The first form resolves `name` against the platform config directory's
//! `silvervine/hooks/<name>` path (honoring the `[hooks]` config block); the second
//! form takes an explicit path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::patch::PatchReport;
use crate::config::{load_config, Config};
use crate::error::{Error, Result};

/// Outcome of a [`run_hook`] / [`run_hook_at`] call.
#[derive(Debug)]
pub enum HookOutcome {
    /// No hook configured (or the resolved path doesn't exist / isn't
    /// executable). This is the **expected** state for the majority of
    /// users who don't wire up hooks; callers should treat it as success.
    NotConfigured,
    /// Hook script ran. `exit_status` is the script's exit code (or `None`
    /// if it was killed by a signal). `stdout` / `stderr` are the captured
    /// outputs, which the daemon includes in its tracing log.
    Ran {
        /// Exit status of the hook process. `None` indicates the process
        /// was terminated by a signal.
        exit_status: Option<i32>,
        /// Captured stdout from the hook process.
        stdout: String,
        /// Captured stderr from the hook process.
        stderr: String,
    },
}

/// Build the documented post-patch environment from a patch report.
#[must_use]
pub fn post_patch_context(report: &PatchReport) -> HashMap<String, String> {
    let mut env = HashMap::from([
        ("SILVERVINE_BROWSER".into(), report.browser.clone()),
        (
            "SILVERVINE_OUTCOME".into(),
            if report.success { "success" } else { "failure" }.into(),
        ),
    ]);
    if let Some(version) = report
        .version_after
        .as_ref()
        .or(report.version_before.as_ref())
    {
        env.insert("SILVERVINE_VERSION".into(), version.clone());
    }
    if let Some(version) = &report.cdm_version {
        env.insert("SILVERVINE_CDM_VERSION".into(), version.clone());
    }
    env
}

/// Build the documented post-update environment.
#[must_use]
pub fn post_update_context(cdm_version: Option<&str>, success: bool) -> HashMap<String, String> {
    let mut env = HashMap::from([(
        "SILVERVINE_OUTCOME".into(),
        if success { "success" } else { "failure" }.into(),
    )]);
    if let Some(version) = cdm_version {
        env.insert("SILVERVINE_CDM_VERSION".into(), version.into());
    }
    env
}

/// Emit a post-patch hook without changing the patch result on hook failure.
pub fn emit_post_patch(report: &PatchReport) {
    emit("post-patch", &post_patch_context(report));
}

/// Emit a post-update hook without changing the update result on hook failure.
pub fn emit_post_update(cdm_version: Option<&str>, success: bool) {
    emit("post-update", &post_update_context(cdm_version, success));
}

fn emit(name: &str, env: &HashMap<String, String>) {
    if let Err(error) = run_hook(name, env) {
        tracing::warn!(
            target: "silvervine::hooks",
            hook = name,
            error = %error,
            "hook configuration or spawn failed; completed operation is unchanged"
        );
    }
}

impl HookOutcome {
    /// `true` if no hook script was found / configured. Useful in tracing
    /// output: `if outcome.is_not_configured() { skip; }`.
    #[must_use]
    pub fn is_not_configured(&self) -> bool {
        matches!(self, Self::NotConfigured)
    }

    /// `true` if a hook ran (regardless of exit status).
    #[must_use]
    pub fn is_ran(&self) -> bool {
        matches!(self, Self::Ran { .. })
    }
}

/// Run a named hook (e.g. `"post-patch"`, `"post-update"`).
///
/// The hook path is resolved against the user's config:
///
/// 1. If `[hooks]` in the Silvervine config sets `post_patch =` or
///    `post_update =` for the named event, that path is used (with `~`
///    expansion).
/// 2. Otherwise `silvervine/hooks/<name>` under the platform config directory is
///    tried.
/// 3. If neither resolves to an executable file, returns
///    [`HookOutcome::NotConfigured`] without an error.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] if the script itself fails to spawn
///   for unexpected reasons (e.g. interpreter line points at a missing
///   binary).
/// * Other categories propagated from [`load_config`] when the config file
///   is malformed.
///
/// # Example
///
/// ```no_run
/// use std::collections::HashMap;
/// let mut env = HashMap::new();
/// env.insert("SILVERVINE_BROWSER".to_string(), "Helium".to_string());
/// env.insert("SILVERVINE_VERSION".to_string(), "128.0.6613.119".to_string());
/// env.insert("SILVERVINE_OUTCOME".to_string(), "success".to_string());
/// let _ = silvervine::hooks::run_hook("post-patch", &env);
/// ```
pub fn run_hook<S: std::hash::BuildHasher>(
    name: &str,
    env: &HashMap<String, String, S>,
) -> Result<HookOutcome> {
    let config = load_config()?;
    let path = resolve_hook_path(name, &config);
    match path {
        Some(p) => run_hook_at(&p, env),
        None => Ok(HookOutcome::NotConfigured),
    }
}

/// Run a hook from an explicit path.
///
/// Returns [`HookOutcome::NotConfigured`] if `path` doesn't exist or isn't
/// executable; [`HookOutcome::Ran`] otherwise.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] if the spawn itself fails (e.g. the
///   hook's `#!/usr/bin/env something` interpreter is missing).
pub fn run_hook_at<S: std::hash::BuildHasher>(
    path: &Path,
    env: &HashMap<String, String, S>,
) -> Result<HookOutcome> {
    if !is_executable_file(path) {
        tracing::debug!(
            target: "silvervine::hooks",
            hook_path = %path.display(),
            "hook not configured (missing or non-executable)"
        );
        return Ok(HookOutcome::NotConfigured);
    }

    let hook_env = with_compat_aliases(env);
    tracing::info!(
        target: "silvervine::hooks",
        hook_path = %path.display(),
        env_count = hook_env.len(),
        "running hook"
    );

    let mut cmd = Command::new(path);
    for (key, value) in hook_env {
        cmd.env(key, value);
    }
    let output = cmd.output().map_err(|e| {
        Error::other(format!("failed to spawn hook at {}: {e}", path.display())).with_source(e)
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_status = output.status.code();

    if !output.status.success() {
        tracing::warn!(
            target: "silvervine::hooks",
            hook_path = %path.display(),
            exit_status = ?exit_status,
            stderr_len = stderr.len(),
            "hook exited non-zero"
        );
    }

    Ok(HookOutcome::Ran {
        exit_status,
        stdout,
        stderr,
    })
}

fn with_compat_aliases<S: std::hash::BuildHasher>(
    env: &HashMap<String, String, S>,
) -> HashMap<String, String> {
    let mut expanded: HashMap<String, String> = env
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    for suffix in ["BROWSER", "VERSION", "CDM_VERSION", "OUTCOME"] {
        let current = format!("SILVERVINE_{suffix}");
        let legacy = format!("NEON_{suffix}");
        match (
            expanded.get(&current).cloned(),
            expanded.get(&legacy).cloned(),
        ) {
            (Some(value), None) => {
                expanded.insert(legacy, value);
            }
            (None, Some(value)) => {
                expanded.insert(current, value);
            }
            _ => {}
        }
    }
    expanded
}

/// Look up the script path for a named hook in the user's config, falling
/// back to the conventional default location.
///
/// `name` must be one of `"post-patch"` / `"post-update"` to map to a
/// `[hooks]` config entry; any other name uses the default-path branch.
fn resolve_hook_path(name: &str, config: &Config) -> Option<PathBuf> {
    // 1. Look in [hooks] for a named entry.
    let configured = match name {
        "post-patch" => config.post_patch_hook(),
        "post-update" => config.post_update_hook(),
        _ => None,
    };
    if let Some(p) = configured {
        return Some(p);
    }
    // 2. Default: <platform-config-dir>/silvervine/hooks/<name>
    let cfg = dirs::config_dir()?;
    Some(cfg.join("silvervine").join("hooks").join(name))
}

/// Returns `true` if `path` is a regular file with at least one execute bit
/// set. On non-Unix the `mode` check is skipped (we just verify the file
/// exists) but Phase 1 only targets Unix-y platforms anyway.
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        // Any of u/g/o execute bits.
        (mode & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        // On non-Unix targets we can't check the execute bit, so we
        // optimistically assume regular files are runnable.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::TempDir;

    /// RAII env-var setter that restores on drop.
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
    }
    impl Drop for ScopedEnv {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    /// Write a small executable shell script to `path`.
    #[cfg(unix)]
    fn write_executable_script(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn post_patch_context_covers_success_and_failure() {
        let success = PatchReport {
            browser: "Helium".into(),
            success: true,
            cdm_version: Some("4.10".into()),
            version_before: Some("127".into()),
            version_after: Some("128".into()),
            dry_run: false,
            error: None,
        };
        let context = post_patch_context(&success);
        assert_eq!(context["SILVERVINE_BROWSER"], "Helium");
        assert_eq!(context["SILVERVINE_VERSION"], "128");
        assert_eq!(context["SILVERVINE_CDM_VERSION"], "4.10");
        assert_eq!(context["SILVERVINE_OUTCOME"], "success");

        let failure = PatchReport {
            browser: "Thorium".into(),
            success: false,
            cdm_version: None,
            version_before: None,
            version_after: None,
            dry_run: false,
            error: Some("failed".into()),
        };
        let context = post_patch_context(&failure);
        assert_eq!(context["SILVERVINE_OUTCOME"], "failure");
        assert!(!context.contains_key("SILVERVINE_CDM_VERSION"));
    }

    #[test]
    fn post_update_context_covers_success_and_failure() {
        let success = post_update_context(Some("4.10"), true);
        assert_eq!(success["SILVERVINE_CDM_VERSION"], "4.10");
        assert_eq!(success["SILVERVINE_OUTCOME"], "success");
        let failure = post_update_context(None, false);
        assert_eq!(failure["SILVERVINE_OUTCOME"], "failure");
        assert!(!failure.contains_key("SILVERVINE_CDM_VERSION"));
    }

    /// Missing path → `NotConfigured`.
    #[test]
    fn run_hook_at_missing_returns_not_configured() {
        let tmp = TempDir::new().unwrap();
        let outcome = run_hook_at(&tmp.path().join("nope"), &HashMap::new()).unwrap();
        assert!(outcome.is_not_configured());
    }

    /// Non-executable file → `NotConfigured` (we don't fall through to
    /// `Ran` and silently fail; we treat it as if the user opted out).
    #[test]
    #[cfg(unix)]
    fn run_hook_at_non_executable_returns_not_configured() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("not-exec.sh");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        let outcome = run_hook_at(&path, &HashMap::new()).unwrap();
        assert!(outcome.is_not_configured());
    }

    /// Executable hook runs and the env vars are visible to it.
    #[test]
    #[cfg(unix)]
    fn run_hook_at_runs_with_env_vars() {
        let tmp = TempDir::new().unwrap();
        let hook = tmp.path().join("post-patch");
        let log = tmp.path().join("hook.log");
        write_executable_script(
            &hook,
            &format!(
                r#"#!/bin/sh
echo "browser=${{SILVERVINE_BROWSER:-unset}}" > {log}
echo "version=${{SILVERVINE_VERSION:-unset}}" >> {log}
echo "outcome=${{SILVERVINE_OUTCOME:-unset}}" >> {log}
echo "cdm=${{SILVERVINE_CDM_VERSION:-unset}}" >> {log}
echo "legacy_browser=${{NEON_BROWSER:-unset}}" >> {log}
echo "legacy_version=${{NEON_VERSION:-unset}}" >> {log}
echo "legacy_cdm=${{NEON_CDM_VERSION:-unset}}" >> {log}
echo "legacy_outcome=${{NEON_OUTCOME:-unset}}" >> {log}
echo "extra=${{SILVERVINE_EXTRA:-unset}}" >> {log}
echo "ran"
exit 0
"#,
                log = log.display()
            ),
        );

        let mut env = HashMap::new();
        env.insert("SILVERVINE_BROWSER".into(), "Helium".into());
        env.insert("SILVERVINE_VERSION".into(), "128.0.6613.119".into());
        env.insert("SILVERVINE_CDM_VERSION".into(), "4.10.0.0".into());
        env.insert("SILVERVINE_OUTCOME".into(), "success".into());

        let outcome = run_hook_at(&hook, &env).unwrap();
        assert!(outcome.is_ran());
        let HookOutcome::Ran {
            exit_status,
            stdout,
            stderr,
        } = outcome
        else {
            unreachable!()
        };
        assert_eq!(exit_status, Some(0));
        assert!(stdout.contains("ran"), "stdout was: {stdout:?}");
        assert!(stderr.is_empty());

        let log_contents = std::fs::read_to_string(&log).unwrap();
        assert!(log_contents.contains("browser=Helium"), "{log_contents}");
        assert!(
            log_contents.contains("version=128.0.6613.119"),
            "{log_contents}"
        );
        assert!(log_contents.contains("outcome=success"), "{log_contents}");
        assert!(log_contents.contains("cdm=4.10.0.0"), "{log_contents}");
        assert!(
            log_contents.contains("legacy_browser=Helium"),
            "{log_contents}"
        );
        assert!(
            log_contents.contains("legacy_version=128.0.6613.119"),
            "{log_contents}"
        );
        assert!(
            log_contents.contains("legacy_cdm=4.10.0.0"),
            "{log_contents}"
        );
        assert!(
            log_contents.contains("legacy_outcome=success"),
            "{log_contents}"
        );
        // Variable not in env should be the script's default.
        assert!(log_contents.contains("extra=unset"), "{log_contents}");
    }

    #[test]
    fn compatibility_aliases_do_not_overwrite_explicit_values() {
        let env = HashMap::from([
            ("SILVERVINE_BROWSER".into(), "current".into()),
            ("NEON_BROWSER".into(), "legacy".into()),
            ("NEON_OUTCOME".into(), "old-only".into()),
        ]);
        let expanded = with_compat_aliases(&env);
        assert_eq!(expanded["SILVERVINE_BROWSER"], "current");
        assert_eq!(expanded["NEON_BROWSER"], "legacy");
        assert_eq!(expanded["SILVERVINE_OUTCOME"], "old-only");
        assert_eq!(expanded["NEON_OUTCOME"], "old-only");
    }

    /// A hook that exits non-zero is reported with its exit code, not as
    /// an error result.
    #[test]
    #[cfg(unix)]
    fn run_hook_at_non_zero_exit_is_not_an_error() {
        let tmp = TempDir::new().unwrap();
        let hook = tmp.path().join("hook");
        write_executable_script(&hook, "#!/bin/sh\necho oops 1>&2\nexit 7\n");

        let outcome = run_hook_at(&hook, &HashMap::new()).unwrap();
        let HookOutcome::Ran {
            exit_status,
            stderr,
            ..
        } = outcome
        else {
            panic!("expected Ran")
        };
        assert_eq!(exit_status, Some(7));
        assert!(stderr.contains("oops"));
    }

    /// `is_executable_file` returns `false` for a directory and for missing
    /// paths.
    #[test]
    fn is_executable_file_false_for_directories_and_missing() {
        let tmp = TempDir::new().unwrap();
        assert!(!is_executable_file(tmp.path()));
        assert!(!is_executable_file(&tmp.path().join("does-not-exist")));
    }

    #[test]
    #[cfg(unix)]
    fn is_executable_file_false_for_non_executable_regular_file() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("plain.txt");
        std::fs::write(&p, "hello").unwrap();
        assert!(!is_executable_file(&p));
    }

    #[test]
    #[cfg(unix)]
    fn is_executable_file_true_for_executable_file() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("script.sh");
        write_executable_script(&p, "#!/bin/sh\nexit 0\n");
        assert!(is_executable_file(&p));
    }

    /// `resolve_hook_path` honors `[hooks]` config when set.
    #[test]
    fn resolve_hook_path_uses_config_post_patch() {
        let mut config = Config::default();
        config.hooks.post_patch = Some("/tmp/configured-post-patch".into());
        let path = resolve_hook_path("post-patch", &config);
        assert_eq!(
            path.as_deref(),
            Some(Path::new("/tmp/configured-post-patch"))
        );
    }

    #[test]
    fn resolve_hook_path_uses_config_post_update() {
        let mut config = Config::default();
        config.hooks.post_update = Some("/tmp/configured-post-update".into());
        let path = resolve_hook_path("post-update", &config);
        assert_eq!(
            path.as_deref(),
            Some(Path::new("/tmp/configured-post-update"))
        );
    }

    /// Default fallback path when no config entry is set: under the user's
    /// config dir.
    #[test]
    fn resolve_hook_path_default_falls_back_to_silvervine_hooks_dir() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        // Override $XDG_CONFIG_HOME (Linux) / $HOME (anything dirs uses).
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        // For macOS-style fallbacks: also redirect $HOME.
        let _home = ScopedEnv::set("HOME", tmp.path());

        let config = Config::default();
        let path = resolve_hook_path("post-patch", &config).expect("default path resolves");
        let expected = dirs::config_dir()
            .expect("config dir")
            .join("silvervine")
            .join("hooks")
            .join("post-patch");
        assert_eq!(path, expected);
    }

    /// `run_hook(name, env)` returns `NotConfigured` when no script exists
    /// at the resolved path.
    #[test]
    fn run_hook_with_no_script_returns_not_configured() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let _home = ScopedEnv::set("HOME", tmp.path());

        let outcome = run_hook("post-patch", &HashMap::new()).unwrap();
        assert!(outcome.is_not_configured());
    }

    /// `run_hook` finds a script at the default path when one is present.
    #[test]
    #[cfg(unix)]
    fn run_hook_runs_default_path_script() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let _home = ScopedEnv::set("HOME", tmp.path());

        let hook_path = dirs::config_dir()
            .expect("config dir")
            .join("silvervine")
            .join("hooks")
            .join("post-patch");
        write_executable_script(&hook_path, "#!/bin/sh\necho yo\nexit 0\n");

        let outcome = run_hook("post-patch", &HashMap::new()).unwrap();
        let HookOutcome::Ran {
            exit_status,
            stdout,
            ..
        } = outcome
        else {
            panic!("expected Ran")
        };
        assert_eq!(exit_status, Some(0));
        assert!(stdout.contains("yo"));
    }

    /// `HookOutcome::is_not_configured` and `is_ran` are mutually
    /// exclusive.
    #[test]
    fn hook_outcome_predicates_are_mutually_exclusive() {
        let nc = HookOutcome::NotConfigured;
        let r = HookOutcome::Ran {
            exit_status: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(nc.is_not_configured() && !nc.is_ran());
        assert!(!r.is_not_configured() && r.is_ran());
    }

    /// Unknown hook name → no `[hooks]` match, fallback to default path.
    #[test]
    fn resolve_hook_path_unknown_name_falls_back() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let _xdg = ScopedEnv::set("XDG_CONFIG_HOME", tmp.path());
        let _home = ScopedEnv::set("HOME", tmp.path());
        let path = resolve_hook_path("custom-hook-name", &Config::default()).unwrap();
        assert!(path.ends_with(
            std::path::Path::new("silvervine")
                .join("hooks")
                .join("custom-hook-name")
        ));
    }
}
