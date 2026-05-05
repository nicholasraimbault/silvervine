//! `neon stream license` — V3-Phase F license-posture management.
//!
//! Subcommands:
//!
//! * `neon stream license show` — print the current posture from
//!   `~/.config/neon/bridge.toml` (matches `cli::stream::status`'s
//!   license fields, reformatted as a standalone view).
//! * `neon stream license set --eval` — opt into the 90-day eval (resets
//!   `accepted_at` to now).
//! * `neon stream license set --key XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` —
//!   replace with a Windows product key.
//! * `neon stream license set --key-file PATH` — replace with a key file
//!   pointer.
//! * `neon stream license rearm` — eval-mode only; surface the
//!   PowerShell command the guest runs to re-arm the trial.
//!
//! Apple-UX guarantees:
//!
//! * No interactive prompts — the user provides flags or gets a clear
//!   error.
//! * `set` validates the new posture before writing (key format, file
//!   existence).
//! * `rearm` is documented + clear about needing the guest to run it
//!   (we can't reach into the VM from the host).

use std::io::Write;
use std::path::PathBuf;

use crate::bridge::license::{self, LicensePosture};
use crate::cli::OutputOptions;
use crate::error::{Error, Result};

/// Args for `neon stream license`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Subcommand.
    pub action: Action,
    /// Output flags.
    pub output: OutputOptions,
}

/// Subcommand under `neon stream license`.
#[derive(Debug, Clone, Default)]
pub enum Action {
    /// `neon stream license show` (default).
    #[default]
    Show,
    /// `neon stream license set --eval | --key K | --key-file P`.
    Set {
        /// `--eval`.
        eval: bool,
        /// `--key`.
        key: Option<String>,
        /// `--key-file`.
        key_file: Option<PathBuf>,
    },
    /// `neon stream license rearm` — print the rearm command the guest
    /// must run.
    Rearm,
}

/// Run `neon stream license`.
///
/// # Errors
///
/// * Propagates errors from `bridge::license` save / load.
pub fn run(args: &Args) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    run_with(args, &mut out)
}

/// Test-friendly variant.
///
/// # Errors
///
/// See [`run`].
pub fn run_with(args: &Args, out: &mut dyn Write) -> Result<()> {
    match &args.action {
        Action::Show => run_show(args, out),
        Action::Set {
            eval,
            key,
            key_file,
        } => run_set(args, out, *eval, key.clone(), key_file.clone()),
        Action::Rearm => run_rearm(args, out),
    }
}

fn run_show(args: &Args, out: &mut dyn Write) -> Result<()> {
    let posture = license::current_posture()?;
    if args.output.json {
        let body = serde_json::json!({
            "license": match &posture {
                Some(LicensePosture::Eval { accepted_at }) => serde_json::json!({
                    "mode": "trial",
                    "accepted_at": accepted_at,
                    "days_remaining": posture.as_ref().and_then(LicensePosture::days_until_expiry),
                }),
                Some(LicensePosture::Key(_)) => serde_json::json!({
                    "mode": "key",
                }),
                Some(LicensePosture::KeyFile(p)) => serde_json::json!({
                    "mode": "key_file",
                    "key_file": p.display().to_string(),
                }),
                None => serde_json::Value::Null,
            }
        });
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&body)
                .map_err(|e| Error::other(format!("license JSON: {e}")))?
        )
        .map_err(Error::from)?;
        return Ok(());
    }
    match posture {
        Some(LicensePosture::Eval { .. }) => {
            let days = posture.as_ref().and_then(LicensePosture::days_until_expiry);
            writeln!(out, "License mode: Microsoft 90-day evaluation").map_err(Error::from)?;
            if let Some(d) = days {
                if d >= 0 {
                    writeln!(out, "Days remaining: {d}").map_err(Error::from)?;
                } else {
                    writeln!(out, "Status: expired ({} days ago)", -d).map_err(Error::from)?;
                    writeln!(out).map_err(Error::from)?;
                    writeln!(
                        out,
                        "Run `neon stream license rearm` to extend (eval supports up to 3 \
                         additional 90-day cycles before a real key is required)."
                    )
                    .map_err(Error::from)?;
                }
            }
        }
        Some(LicensePosture::Key(_)) => {
            writeln!(out, "License mode: Windows product key (set)").map_err(Error::from)?;
        }
        Some(LicensePosture::KeyFile(p)) => {
            writeln!(out, "License mode: key file ({})", p.display()).map_err(Error::from)?;
        }
        None => {
            writeln!(out, "License mode: (not configured)").map_err(Error::from)?;
            writeln!(out).map_err(Error::from)?;
            writeln!(
                out,
                "Run `neon stream init --accept-eval` to opt into the 90-day trial, \
                 or `neon stream license set --key XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` to \
                 supply a product key."
            )
            .map_err(Error::from)?;
        }
    }
    Ok(())
}

fn run_set(
    args: &Args,
    out: &mut dyn Write,
    eval: bool,
    key: Option<String>,
    key_file: Option<PathBuf>,
) -> Result<()> {
    let n_set = u8::from(eval) + u8::from(key.is_some()) + u8::from(key_file.is_some());
    if n_set == 0 {
        return Err(Error::other(
            "no posture supplied. Pass --eval, --key XXXXX-XXXXX-XXXXX-XXXXX-XXXXX, or --key-file PATH.",
        ));
    }
    if n_set > 1 {
        return Err(Error::other(
            "pass exactly one of --eval / --key / --key-file (they are mutually exclusive).",
        ));
    }
    let new_posture = if eval {
        LicensePosture::eval_now()
    } else if let Some(k) = key {
        if !license::validate_product_key(&k) {
            return Err(Error::other(format!(
                "license key {k:?} fails the X-X-X-X-X format check"
            )));
        }
        LicensePosture::Key(k)
    } else if let Some(p) = key_file {
        if !p.exists() {
            return Err(Error::other(format!(
                "license file {} does not exist",
                p.display()
            )));
        }
        LicensePosture::KeyFile(p)
    } else {
        unreachable!("exhausted by n_set count check above")
    };
    license::save_posture(&new_posture)?;
    if !args.output.quiet {
        writeln!(out, "License posture saved.").map_err(Error::from)?;
        match &new_posture {
            LicensePosture::Eval { .. } => {
                writeln!(out, "Mode: Microsoft 90-day evaluation (now active)")
                    .map_err(Error::from)?;
            }
            LicensePosture::Key(_) => {
                writeln!(out, "Mode: Windows product key").map_err(Error::from)?;
            }
            LicensePosture::KeyFile(p) => {
                writeln!(out, "Mode: key file ({})", p.display()).map_err(Error::from)?;
            }
        }
    }
    Ok(())
}

fn run_rearm(args: &Args, out: &mut dyn Write) -> Result<()> {
    let posture = license::current_posture()?;
    let Some(LicensePosture::Eval { .. }) = posture else {
        return Err(Error::other(
            "rearm only applies to eval mode. Current posture is not `Eval`.",
        ));
    };
    if !args.output.quiet {
        writeln!(
            out,
            "Run this PowerShell command inside the bridge VM (Looking Glass window):"
        )
        .map_err(Error::from)?;
        writeln!(out).map_err(Error::from)?;
        writeln!(out, "  {}", license::rearm_command_for_guest()).map_err(Error::from)?;
        writeln!(out).map_err(Error::from)?;
        writeln!(
            out,
            "Microsoft's slmgr supports up to 3 additional 90-day cycles. Once \
             exhausted, `neon stream license set --key XXXXX-...` is required."
        )
        .map_err(Error::from)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn redirect_xdg(tmp: &std::path::Path) -> std::path::PathBuf {
        let cfg = tmp.join("config");
        std::fs::create_dir_all(&cfg).expect("mkdir");
        cfg
    }

    fn write_trial(cfg_root: &std::path::Path) {
        let path = cfg_root.join("neon").join("bridge.toml");
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        license::save_posture_to(&LicensePosture::eval_now(), &path).expect("save");
    }

    #[test]
    fn show_with_no_posture_emits_helpful_message() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args::default();
        run_with(&args, &mut buf).expect("show");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("not configured"));
        assert!(body.contains("--accept-eval") || body.contains("license set"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn show_with_trial_posture_emits_days_remaining() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        write_trial(&cfg);
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args::default();
        run_with(&args, &mut buf).expect("show");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("evaluation"));
        assert!(body.contains("Days remaining"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn show_json_emits_structured_output() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        write_trial(&cfg);
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Show,
            output: OutputOptions {
                json: true,
                ..Default::default()
            },
        };
        run_with(&args, &mut buf).expect("json show");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("\"mode\""));
        assert!(body.contains("\"trial\""));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn set_eval_writes_trial_posture() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Set {
                eval: true,
                key: None,
                key_file: None,
            },
            ..Default::default()
        };
        run_with(&args, &mut buf).expect("set eval");
        // Verify on disk.
        let posture = license::current_posture().expect("load").expect("some");
        assert!(matches!(posture, LicensePosture::Eval { .. }));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn set_with_no_flags_returns_error() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Set {
                eval: false,
                key: None,
                key_file: None,
            },
            ..Default::default()
        };
        let err = run_with(&args, &mut buf).expect_err("no posture");
        assert!(err.to_string().contains("no posture"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn set_with_two_flags_returns_error() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Set {
                eval: true,
                key: Some("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".into()),
                key_file: None,
            },
            ..Default::default()
        };
        let err = run_with(&args, &mut buf).expect_err("conflicting flags");
        assert!(err.to_string().contains("mutually exclusive"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn set_with_invalid_key_format_rejected() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Set {
                eval: false,
                key: Some("garbage".into()),
                key_file: None,
            },
            ..Default::default()
        };
        let err = run_with(&args, &mut buf).expect_err("bad key");
        assert!(err.to_string().contains("X-X-X-X-X"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn set_with_missing_key_file_rejected() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Set {
                eval: false,
                key: None,
                key_file: Some(PathBuf::from("/dev/null/nope")),
            },
            ..Default::default()
        };
        let err = run_with(&args, &mut buf).expect_err("missing file");
        assert!(err.to_string().contains("does not exist"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn rearm_in_trial_mode_emits_powershell_command() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        write_trial(&cfg);
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Rearm,
            ..Default::default()
        };
        run_with(&args, &mut buf).expect("rearm");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("powershell"));
        assert!(body.contains("slmgr"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn rearm_in_key_mode_returns_error() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        let path = cfg.join("neon").join("bridge.toml");
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
        license::save_posture_to(
            &LicensePosture::Key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".into()),
            &path,
        )
        .expect("save");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Rearm,
            ..Default::default()
        };
        let err = run_with(&args, &mut buf).expect_err("not eval");
        assert!(err.to_string().contains("eval"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn rearm_with_no_posture_returns_error() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let cfg = redirect_xdg(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &cfg);
        }
        let mut buf = Vec::new();
        let args = Args {
            action: Action::Rearm,
            ..Default::default()
        };
        let err = run_with(&args, &mut buf).expect_err("no posture");
        assert!(err.to_string().contains("Eval") || err.to_string().contains("eval"));
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }
}
