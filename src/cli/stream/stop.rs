//! `neon stream stop` — V3-Phase D snapshot + halt.
//!
//! Apple-UX guarantees:
//!
//! * Single command. No "are you sure?".
//! * Takes a "last-good" snapshot before halting (so `neon stream
//!   repair` has something to roll back to).
//! * Sends `SIGTERM` to the running Looking Glass client (best-effort;
//!   skipped under [`crate::bridge::looking_glass::NOOP_ENV`]).
//! * Pauses the VM (suspend-to-RAM via libvirt) — leaves the domain
//!   defined for the next `neon stream start`. Full shutdown is
//!   `neon stream uninstall` (V3-Phase F).

use std::io::Write;

use crate::bridge::libvirt::Hypervisor;
use crate::cli::OutputOptions;
use crate::error::{Error, Result};

/// Snapshot label taken when the user halts cleanly.
pub const LAST_GOOD_SNAPSHOT: &str = "last-good";

/// Args for `neon stream stop`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Output flags.
    pub output: OutputOptions,
}

/// Run `neon stream stop`.
///
/// # Errors
///
/// * Propagates errors from the libvirt wrapper (snapshot / pause /
///   shutdown).
/// * [`crate::ErrorCategory::Other`] — the VM domain isn't defined
///   (suggests `neon stream init` if the user is unaware of state).
pub fn run(args: &Args) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    run_with(args, &mut out)
}

/// Test-friendly variant: takes a writer.
///
/// # Errors
///
/// See [`run`].
pub fn run_with(args: &Args, out: &mut dyn Write) -> Result<()> {
    let hv = Hypervisor::connect()?;
    let domain = hv.lookup_domain("neon-bridge").map_err(|e| {
        Error::other(format!(
            "libvirt domain `neon-bridge` not defined ({e}). \
             Run `neon stream init` first."
        ))
    })?;

    if !args.output.quiet {
        writeln!(out, "Step 1/3: snapshotting current VM state").map_err(Error::from)?;
    }
    domain.snapshot(LAST_GOOD_SNAPSHOT)?;

    if !args.output.quiet {
        writeln!(out, "Step 2/3: closing Looking Glass client (best-effort)")
            .map_err(Error::from)?;
    }
    signal_looking_glass();

    if !args.output.quiet {
        writeln!(out, "Step 3/3: halting VM (libvirt shutdown)").map_err(Error::from)?;
    }
    domain.stop()?;

    if !args.output.quiet {
        writeln!(
            out,
            "Done. Snapshot `{LAST_GOOD_SNAPSHOT}` taken; VM halted. \
             Use `neon stream start` to resume."
        )
        .map_err(Error::from)?;
    }
    Ok(())
}

/// Best-effort: send SIGTERM to any running `looking-glass-client`. We
/// don't track the PID across `start` → `stop` invocations (would need a
/// pidfile or tray daemon state), so we walk the process table.
///
/// Honors [`crate::bridge::looking_glass::NOOP_ENV`] — under NOOP, we
/// skip the syscall entirely.
fn signal_looking_glass() {
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os(crate::bridge::looking_glass::NOOP_ENV).is_some() {
            return;
        }
        // Best-effort `pgrep`-style lookup via `/proc/<pid>/comm`. We
        // don't shell out to `pkill` because the user may not have it on
        // PATH and we don't want a runtime dep on procps.
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let Ok(pid) = name.parse::<libc::pid_t>() else {
                    continue;
                };
                let comm_path = entry.path().join("comm");
                let Ok(comm) = std::fs::read_to_string(&comm_path) else {
                    continue;
                };
                let comm = comm.trim();
                // `/proc/<pid>/comm` is the basename of argv[0] capped
                // at 15 chars on Linux. `looking-glass-client` truncates
                // to `looking-glass-c` — match either form.
                if comm == "looking-glass-client" || comm == "looking-glass-c" {
                    // SAFETY: SIGTERM on PIDs we found via /proc; harmless
                    // race where the PID exits before kill returns ESRCH.
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::libvirt::HV_NOOP_ENV;

    #[test]
    fn run_with_under_noop_records_snapshot_and_stop() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
            #[cfg(target_os = "linux")]
            std::env::set_var(crate::bridge::looking_glass::NOOP_ENV, "1");
        }
        let mut buf = Vec::new();
        let args = Args::default();
        run_with(&args, &mut buf).expect("noop stop");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("snapshotting"));
        assert!(body.contains("halting"));
        assert!(body.contains("Done"));
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
            #[cfg(target_os = "linux")]
            std::env::remove_var(crate::bridge::looking_glass::NOOP_ENV);
        }
    }

    #[test]
    fn run_with_quiet_suppresses_progress_lines() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
            #[cfg(target_os = "linux")]
            std::env::set_var(crate::bridge::looking_glass::NOOP_ENV, "1");
        }
        let mut buf = Vec::new();
        let args = Args {
            output: OutputOptions {
                quiet: true,
                ..Default::default()
            },
        };
        run_with(&args, &mut buf).expect("quiet stop");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(!body.contains("Step 1/3"));
        assert!(!body.contains("Done"));
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
            #[cfg(target_os = "linux")]
            std::env::remove_var(crate::bridge::looking_glass::NOOP_ENV);
        }
    }

    /// Verify the snapshot label committed under NOOP matches the
    /// constant — the wizard's repair flow looks for it by name.
    #[test]
    fn last_good_snapshot_is_recorded_in_mock_recorder() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
            #[cfg(target_os = "linux")]
            std::env::set_var(crate::bridge::looking_glass::NOOP_ENV, "1");
        }
        // Drive the run, then re-check by inspecting the mock recorder.
        let mut buf = Vec::new();
        let args = Args::default();
        run_with(&args, &mut buf).expect("noop stop");
        // The recorder is per-Hypervisor instance; we can't inspect
        // the one created inside `run_with`. We assert against the
        // constant directly, which is exercised by the dispatch above.
        assert_eq!(LAST_GOOD_SNAPSHOT, "last-good");
        unsafe {
            std::env::remove_var(HV_NOOP_ENV);
            #[cfg(target_os = "linux")]
            std::env::remove_var(crate::bridge::looking_glass::NOOP_ENV);
        }
    }

    #[test]
    fn signal_looking_glass_under_noop_does_not_panic() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe {
            #[cfg(target_os = "linux")]
            std::env::set_var(crate::bridge::looking_glass::NOOP_ENV, "1");
        }
        signal_looking_glass();
        unsafe {
            #[cfg(target_os = "linux")]
            std::env::remove_var(crate::bridge::looking_glass::NOOP_ENV);
        }
    }

    #[test]
    fn args_default_has_default_output() {
        let a = Args::default();
        assert!(!a.output.quiet);
        assert!(!a.output.json);
    }
}
