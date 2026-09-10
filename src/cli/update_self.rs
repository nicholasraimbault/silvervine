//! `silvervine update self` — prompted GitHub-installed binary swap.
//!
//! This command never downloads a replacement in-process and never writes
//! over `/proc/self/exe`. It locates the cargo-dist `silvervine-update`
//! sidecar next to the running binary plus a matching install receipt,
//! then runs that sidecar with captured stdout/stderr (never inherited).
//! cargo-dist's axoupdater exits 0 when already current, so `updated` is
//! true only when captured output shows an install. After a real swap the
//! user (or systemd/LaunchAgent) must restart the daemon.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use crate::cli::OutputOptions;
use crate::error::{Error, Result};

/// Env var that, when set, makes [`run`] return a no-op outcome.
pub const NOOP_ENV: &str = "SILVERVINE_TEST_SELF_UPDATE_NOOP";

const SIDECAR_NAME: &str = "silvervine-update";
const RECEIPT_NAME: &str = "silvervine-receipt.json";
const MISSING_SIDECAR: &str =
    "silvervine-update sidecar not installed; re-run the GitHub installer";
const MISSING_RECEIPT: &str =
    "install receipt not found; re-run the GitHub installer to obtain a cargo-dist receipt";
const RESTART_NOTE: &str =
    "Restart the user daemon (systemd user unit or LaunchAgent) to load the new binary.";

/// Args for `silvervine update self`.
#[derive(Debug, Clone, Default)]
pub struct SelfArgs {
    /// `--dry-run`: confirm sidecar + receipt without invoking the updater.
    pub dry_run: bool,
    /// Output flags.
    pub output: OutputOptions,
}

/// Outcome record for `silvervine update self`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SelfUpdateOutcome {
    /// Version of the currently running binary.
    pub current_version: String,
    /// Version the updater reported or would install.
    pub latest_version: String,
    /// `true` when the sidecar replaced the on-disk binary.
    pub updated: bool,
    /// Why the command stopped where it did.
    pub reason: String,
}

/// Run the `silvervine update self` flow.
///
/// # Errors
///
/// * `Other` if the cargo-dist sidecar is missing next to this binary.
/// * `Other` if the install receipt is missing.
/// * `Other` if the sidecar cannot be started or exits non-zero.
pub fn run(args: &SelfArgs) -> Result<SelfUpdateOutcome> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    run_with(args, None, None, &mut handle)
}

fn run_with(
    args: &SelfArgs,
    sidecar_override: Option<&Path>,
    receipt_override: Option<&Path>,
    out: &mut dyn Write,
) -> Result<SelfUpdateOutcome> {
    if std::env::var_os(NOOP_ENV).is_some() {
        let outcome = noop_outcome();
        render(args, &outcome, "", out)?;
        return Ok(outcome);
    }

    let sidecar = match sidecar_override {
        Some(path) => path.to_path_buf(),
        None => sidecar_beside_current_exe()?,
    };
    if !sidecar.is_file() {
        return Err(Error::other(MISSING_SIDECAR));
    }

    let receipt = match receipt_override {
        Some(path) => path.to_path_buf(),
        None => receipt_path(),
    };
    if !receipt.is_file() {
        return Err(Error::other(MISSING_RECEIPT));
    }

    if args.dry_run {
        let outcome = SelfUpdateOutcome {
            current_version: running_version(),
            latest_version: running_version(),
            updated: false,
            reason: "dry-run".into(),
        };
        render(args, &outcome, "", out)?;
        return Ok(outcome);
    }

    let captured = invoke_sidecar(&sidecar)?;
    let outcome = outcome_from_sidecar(&captured);
    render(args, &outcome, &captured, out)?;
    Ok(outcome)
}

fn noop_outcome() -> SelfUpdateOutcome {
    SelfUpdateOutcome {
        current_version: running_version(),
        latest_version: running_version(),
        updated: false,
        reason: "test-noop".into(),
    }
}

fn running_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn sidecar_beside_current_exe() -> Result<PathBuf> {
    let exe = std::env::current_exe()
        .map_err(|e| Error::other(format!("cannot resolve current executable: {e}")))?;
    let Some(dir) = exe.parent() else {
        return Err(Error::other("cannot resolve current executable directory"));
    };
    Ok(dir.join(SIDECAR_NAME))
}

fn receipt_path() -> PathBuf {
    let config_home = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(|| dirs::home_dir().map(|home| home.join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    config_home.join("silvervine").join(RECEIPT_NAME)
}

fn invoke_sidecar(sidecar: &Path) -> Result<String> {
    let output = spawn_sidecar(sidecar)?;
    let captured = combine_captured(&output.stdout, &output.stderr);
    if output.status.success() {
        Ok(captured)
    } else if captured.trim().is_empty() {
        Err(Error::other(format!(
            "{SIDECAR_NAME} exited with {}",
            output.status
        )))
    } else {
        Err(Error::other(format!(
            "{SIDECAR_NAME} exited with {}: {}",
            output.status,
            captured.trim()
        )))
    }
}

fn spawn_sidecar(sidecar: &Path) -> Result<Output> {
    let mut last_error = None;
    for delay_ms in [0_u64, 1, 2, 5, 10, 20, 50] {
        if delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
        match Command::new(sidecar).output() {
            Ok(output) => return Ok(output),
            Err(error) if is_etxtbsy(&error) => last_error = Some(error),
            Err(error) => {
                return Err(Error::other(format!(
                    "failed to run {SIDECAR_NAME}: {error}"
                )));
            }
        }
    }
    Err(Error::other(format!(
        "failed to run {SIDECAR_NAME}: {}",
        last_error.expect("ETXTBSY retry loop always records the last error")
    )))
}

fn is_etxtbsy(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ETXTBSY)
}

fn combine_captured(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    if stdout.is_empty() {
        return stderr.into_owned();
    }
    if stderr.is_empty() {
        return stdout.into_owned();
    }
    let mut combined = String::with_capacity(stdout.len() + stderr.len() + 1);
    combined.push_str(&stdout);
    if !stdout.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(&stderr);
    combined
}

fn outcome_from_sidecar(captured: &str) -> SelfUpdateOutcome {
    let current_version = running_version();
    if sidecar_performed_install(captured) {
        let latest_version =
            parse_installed_version(captured).unwrap_or_else(|| current_version.clone());
        SelfUpdateOutcome {
            current_version,
            latest_version,
            updated: true,
            reason: format!("sidecar; {RESTART_NOTE}"),
        }
    } else {
        SelfUpdateOutcome {
            current_version: current_version.clone(),
            latest_version: current_version,
            updated: false,
            reason: "already up to date".into(),
        }
    }
}

/// axoupdater exits 0 when already current; only install phrasing counts.
fn sidecar_performed_install(captured: &str) -> bool {
    let lower = captured.to_ascii_lowercase();
    (lower.contains("new release") && lower.contains("installed"))
        || lower.contains("everything's installed")
}

fn parse_installed_version(captured: &str) -> Option<String> {
    let lower = captured.to_ascii_lowercase();
    let prefix = "new release ";
    let suffix = " installed";
    let start = lower.find(prefix)?;
    let version_start = start + prefix.len();
    let rest_lower = &lower[version_start..];
    let version_len = rest_lower.find(suffix)?;
    let version = captured
        .get(version_start..version_start + version_len)?
        .trim()
        .trim_end_matches('!')
        .trim();
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

fn render(
    args: &SelfArgs,
    outcome: &SelfUpdateOutcome,
    sidecar_output: &str,
    out: &mut dyn Write,
) -> Result<()> {
    if args.output.json {
        return super::write_json(out, outcome);
    }
    if args.output.quiet {
        return Ok(());
    }
    match outcome.reason.as_str() {
        "test-noop" => Ok(()),
        "dry-run" => writeln!(
            out,
            "Would run {SIDECAR_NAME} (dry-run). Sidecar and install receipt are present."
        )
        .map_err(Error::from),
        _ => {
            write_captured(out, sidecar_output)?;
            if outcome.updated {
                writeln!(out, "{RESTART_NOTE}").map_err(Error::from)
            } else {
                Ok(())
            }
        }
    }
}

fn write_captured(out: &mut dyn Write, captured: &str) -> Result<()> {
    if captured.is_empty() {
        return Ok(());
    }
    write!(out, "{captured}").map_err(Error::from)?;
    if !captured.ends_with('\n') {
        writeln!(out).map_err(Error::from)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        // Close+fsync before exec: Linux returns ETXTBSY if the file is still
        // open for write when `Command` runs it (seen under `cargo test -jN`).
        let mut file = fs::File::create(path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn invoke_sidecar_retries_etxtbsy() {
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join("sidecar.sh");
        write_executable(&sidecar, "#!/bin/sh\nprintf ok\nexit 0\n");
        let hold = fs::OpenOptions::new().write(true).open(&sidecar).unwrap();
        let sidecar_for_thread = sidecar.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(15));
            drop(hold);
            sidecar_for_thread
        });
        let captured = super::invoke_sidecar(&sidecar).expect("retry past ETXTBSY");
        worker.join().unwrap();
        assert!(captured.contains("ok"), "captured: {captured:?}");
    }

    fn args() -> SelfArgs {
        SelfArgs {
            output: OutputOptions {
                quiet: true,
                ..OutputOptions::default()
            },
            ..SelfArgs::default()
        }
    }

    /// Hold the crate env lock and clear the self-update noop flag.
    ///
    /// Sidecar tests that skip this can observe `SILVERVINE_TEST_SELF_UPDATE_NOOP`
    /// while [`run_honors_noop_env`] is running (tarpaulin hits that race).
    fn isolate_self_update() -> (
        std::sync::MutexGuard<'static, ()>,
        crate::test_support::ScopedEnv,
    ) {
        (
            crate::test_support::env_lock(),
            crate::test_support::ScopedEnv::unset(NOOP_ENV),
        )
    }

    #[test]
    fn run_honors_noop_env() {
        let _guard = crate::test_support::env_lock();
        let previous = std::env::var_os(NOOP_ENV);
        unsafe { std::env::set_var(NOOP_ENV, "1") };
        let outcome = run(&args());
        match previous {
            Some(value) => unsafe { std::env::set_var(NOOP_ENV, value) },
            None => unsafe { std::env::remove_var(NOOP_ENV) },
        }
        let outcome = outcome.expect("noop");
        assert!(!outcome.updated);
        assert_eq!(outcome.reason, "test-noop");
        assert_eq!(outcome.current_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn run_without_sidecar_errors() {
        let _iso = isolate_self_update();
        let err = run(&args()).unwrap_err();
        assert!(
            err.message.contains("silvervine-update") || err.message.contains("install receipt"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn missing_sidecar_errors_even_when_receipt_exists() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join(SIDECAR_NAME);
        let receipt = tmp.path().join(RECEIPT_NAME);
        fs::write(&receipt, "{}").unwrap();
        let err = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap_err();
        assert!(err.message.contains("silvervine-update"));
    }

    #[test]
    fn missing_receipt_errors_when_sidecar_exists() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join(SIDECAR_NAME);
        write_executable(&sidecar, "#!/bin/sh\nexit 0\n");
        let receipt = tmp.path().join(RECEIPT_NAME);
        let err = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap_err();
        assert!(err.message.contains("install receipt"));
    }

    #[test]
    fn dry_run_does_not_invoke_sidecar() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join(SIDECAR_NAME);
        let marker = tmp.path().join("ran");
        write_executable(
            &sidecar,
            &format!("#!/bin/sh\ntouch {}\nexit 0\n", marker.display()),
        );
        let receipt = tmp.path().join(RECEIPT_NAME);
        fs::write(&receipt, "{}").unwrap();
        let mut dry = args();
        dry.dry_run = true;
        let outcome = run_with(&dry, Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap();
        assert!(!outcome.updated);
        assert_eq!(outcome.reason, "dry-run");
        assert!(!marker.exists());
    }

    #[test]
    fn successful_sidecar_does_not_overwrite_a_running_binary() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let running = tmp.path().join("silvervine");
        fs::write(&running, b"running-daemon-bytes").unwrap();
        let sidecar = tmp.path().join(SIDECAR_NAME);
        let args_log = tmp.path().join("args");
        write_executable(
            &sidecar,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\" > {}\nexit 0\n",
                args_log.display()
            ),
        );
        let receipt = tmp.path().join(RECEIPT_NAME);
        fs::write(&receipt, "{}").unwrap();
        let outcome = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap();
        assert!(!outcome.updated);
        assert_eq!(outcome.latest_version, outcome.current_version);
        assert!(!outcome.reason.contains("Restart the user daemon"));
        assert_eq!(fs::read(&running).unwrap(), b"running-daemon-bytes");
        let logged = fs::read_to_string(&args_log).unwrap();
        assert_eq!(
            logged.lines().collect::<Vec<_>>(),
            [sidecar.to_str().unwrap()],
            "sidecar must be invoked with no extra args: {logged}"
        );
    }

    #[test]
    fn sidecar_nonzero_exit_is_an_error() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join(SIDECAR_NAME);
        write_executable(&sidecar, "#!/bin/sh\nexit 3\n");
        let receipt = tmp.path().join(RECEIPT_NAME);
        fs::write(&receipt, "{}").unwrap();
        let err = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap_err();
        assert!(err.message.contains("silvervine-update"));
    }

    #[test]
    fn receipt_path_prefers_xdg_config_home() {
        let _guard = crate::test_support::env_lock();
        let tmp = TempDir::new().unwrap();
        let xdg = tmp.path().join("xdg-config");
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &xdg) };
        let path = receipt_path();
        match previous {
            Some(value) => unsafe { std::env::set_var("XDG_CONFIG_HOME", value) },
            None => unsafe { std::env::remove_var("XDG_CONFIG_HOME") },
        }
        assert_eq!(path, xdg.join("silvervine").join(RECEIPT_NAME));
    }

    #[test]
    fn json_outcome_is_one_parseable_document() {
        let outcome = SelfUpdateOutcome {
            current_version: "2.1.3".into(),
            latest_version: "2.1.3".into(),
            updated: false,
            reason: "dry-run".into(),
        };
        let mut output = Vec::new();
        let args = SelfArgs {
            output: OutputOptions {
                json: true,
                ..OutputOptions::default()
            },
            ..SelfArgs::default()
        };
        render(&args, &outcome, "", &mut output).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(parsed["updated"], false);
        assert_eq!(parsed["reason"], "dry-run");
    }

    fn json_args() -> SelfArgs {
        SelfArgs {
            output: OutputOptions {
                json: true,
                ..OutputOptions::default()
            },
            ..SelfArgs::default()
        }
    }

    fn human_args() -> SelfArgs {
        SelfArgs::default()
    }

    fn seeded(tmp: &TempDir, script: &str) -> (PathBuf, PathBuf) {
        let sidecar = tmp.path().join(SIDECAR_NAME);
        write_executable(&sidecar, script);
        let receipt = tmp.path().join(RECEIPT_NAME);
        fs::write(&receipt, "{}").unwrap();
        (sidecar, receipt)
    }

    #[test]
    fn sidecar_already_up_to_date_is_not_updated() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let (sidecar, receipt) = seeded(
            &tmp,
            "#!/bin/sh\necho 'Already up to date; not upgrading' >&2\nexit 0\n",
        );
        let outcome = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap();
        assert!(!outcome.updated);
        assert_eq!(outcome.latest_version, outcome.current_version);
        assert_eq!(outcome.reason, "already up to date");
    }

    #[test]
    fn sidecar_empty_success_is_not_updated() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let (sidecar, receipt) = seeded(&tmp, "#!/bin/sh\nexit 0\n");
        let outcome = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap();
        assert!(!outcome.updated);
        assert_eq!(outcome.latest_version, outcome.current_version);
        assert_eq!(outcome.reason, "already up to date");
    }

    #[test]
    fn sidecar_install_phrasing_is_updated() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let (sidecar, receipt) = seeded(
            &tmp,
            "#!/bin/sh\necho 'New release 3.1.4 installed!' >&2\nexit 0\n",
        );
        let outcome = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap();
        assert!(outcome.updated);
        assert_eq!(outcome.latest_version, "3.1.4");
        assert!(outcome.reason.contains("Restart the user daemon"));
    }

    #[test]
    fn json_path_does_not_include_sidecar_stdout() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let (sidecar, receipt) = seeded(
            &tmp,
            "#!/bin/sh\necho 'SIDECAR_STDOUT_MARKER'\necho 'New release 9.9.9 installed!' >&2\nexit 0\n",
        );
        let mut output = Vec::new();
        let outcome = run_with(&json_args(), Some(&sidecar), Some(&receipt), &mut output).unwrap();
        assert!(outcome.updated);
        assert_eq!(outcome.latest_version, "9.9.9");
        let text = String::from_utf8(output).unwrap();
        assert!(
            !text.contains("SIDECAR_STDOUT_MARKER"),
            "json mixed with sidecar stdout: {text}"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(text.trim()).expect("json path must be one parseable document");
        assert_eq!(parsed["updated"], true);
        assert_eq!(parsed["latest_version"], "9.9.9");
        assert_eq!(parsed["current_version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn human_path_prints_sidecar_then_restart_only_when_updated() {
        let _iso = isolate_self_update();
        let tmp = TempDir::new().unwrap();
        let (sidecar, receipt) = seeded(
            &tmp,
            "#!/bin/sh\necho 'Already up to date; not upgrading' >&2\nexit 0\n",
        );
        let mut current = Vec::new();
        let outcome =
            run_with(&human_args(), Some(&sidecar), Some(&receipt), &mut current).unwrap();
        assert!(!outcome.updated);
        let current_text = String::from_utf8(current).unwrap();
        assert!(current_text.contains("Already up to date; not upgrading"));
        assert!(!current_text.contains(RESTART_NOTE));

        let tmp = TempDir::new().unwrap();
        let (sidecar, receipt) = seeded(
            &tmp,
            "#!/bin/sh\necho 'New release 4.0.0 installed!' >&2\nexit 0\n",
        );
        let mut swapped = Vec::new();
        let outcome =
            run_with(&human_args(), Some(&sidecar), Some(&receipt), &mut swapped).unwrap();
        assert!(outcome.updated);
        let swapped_text = String::from_utf8(swapped).unwrap();
        assert!(swapped_text.contains("New release 4.0.0 installed!"));
        assert!(swapped_text.contains(RESTART_NOTE));
    }

    #[test]
    fn install_phrasing_detects_axoupdater_success() {
        assert!(sidecar_performed_install(
            "Checking for updates...\nNew release 2.2.0 installed!\n"
        ));
        assert!(sidecar_performed_install("everything's installed!"));
        assert!(!sidecar_performed_install(
            "Checking for updates...\nAlready up to date; not upgrading\n"
        ));
        assert!(!sidecar_performed_install(""));
        assert!(!sidecar_performed_install("Checking for updates...\n"));
    }

    #[test]
    fn parse_installed_version_from_axoupdater_line() {
        assert_eq!(
            parse_installed_version("New release 2.2.0 installed!"),
            Some("2.2.0".into())
        );
        assert_eq!(
            parse_installed_version("Already up to date; not upgrading"),
            None
        );
        assert_eq!(parse_installed_version("New release installed"), None);
    }
}
