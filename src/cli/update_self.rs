//! `silvervine update self` — prompted GitHub-installed binary swap.
//!
//! This command never downloads a replacement in-process and never writes
//! over `/proc/self/exe`. It locates the cargo-dist `silvervine-update`
//! sidecar next to the running binary plus a matching install receipt,
//! then runs that sidecar with inherited stdio. After a successful swap
//! the user (or systemd/LaunchAgent) must restart the daemon.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

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
        render(args, &outcome, out)?;
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
        render(args, &outcome, out)?;
        return Ok(outcome);
    }

    invoke_sidecar(&sidecar)?;

    let outcome = SelfUpdateOutcome {
        current_version: running_version(),
        latest_version: running_version(),
        updated: true,
        reason: format!("sidecar; {RESTART_NOTE}"),
    };
    render(args, &outcome, out)?;
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

fn invoke_sidecar(sidecar: &Path) -> Result<()> {
    let status = Command::new(sidecar)
        .status()
        .map_err(|e| Error::other(format!("failed to run {SIDECAR_NAME}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::other(format!("{SIDECAR_NAME} exited with {status}")))
    }
}

fn render(args: &SelfArgs, outcome: &SelfUpdateOutcome, out: &mut dyn Write) -> Result<()> {
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
            if outcome.updated {
                writeln!(out, "Updated via {SIDECAR_NAME}.").map_err(Error::from)?;
            }
            writeln!(out, "{RESTART_NOTE}").map_err(Error::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[cfg(unix)]
    fn write_executable(path: &Path, contents: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
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
        let _guard = crate::test_support::env_lock();
        let previous = std::env::var_os(NOOP_ENV);
        unsafe { std::env::remove_var(NOOP_ENV) };
        let err = run(&args()).unwrap_err();
        match previous {
            Some(value) => unsafe { std::env::set_var(NOOP_ENV, value) },
            None => unsafe { std::env::remove_var(NOOP_ENV) },
        }
        assert!(
            err.message.contains("silvervine-update") || err.message.contains("install receipt"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn missing_sidecar_errors_even_when_receipt_exists() {
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join(SIDECAR_NAME);
        let receipt = tmp.path().join(RECEIPT_NAME);
        fs::write(&receipt, "{}").unwrap();
        let err = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap_err();
        assert!(err.message.contains("silvervine-update"));
    }

    #[test]
    fn missing_receipt_errors_when_sidecar_exists() {
        let tmp = TempDir::new().unwrap();
        let sidecar = tmp.path().join(SIDECAR_NAME);
        write_executable(&sidecar, "#!/bin/sh\nexit 0\n");
        let receipt = tmp.path().join(RECEIPT_NAME);
        let err = run_with(&args(), Some(&sidecar), Some(&receipt), &mut Vec::new()).unwrap_err();
        assert!(err.message.contains("install receipt"));
    }

    #[test]
    fn dry_run_does_not_invoke_sidecar() {
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
        assert!(outcome.updated);
        assert!(outcome.reason.contains("Restart the user daemon"));
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
        render(&args, &outcome, &mut output).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(parsed["updated"], false);
        assert_eq!(parsed["reason"], "dry-run");
    }
}
