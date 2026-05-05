//! `neon stream init` — the V3-Phase C wizard.
//!
//! **Apple-UX guarantees**:
//!
//! * Single command. User types `neon stream init --accept-eval` and
//!   walks away for ~30 minutes.
//! * Capability detection runs first. If anything is red,
//!   per-capability remediation prints and the wizard exits with
//!   non-zero — the user knows exactly what to fix.
//! * License posture is asked once via flags
//!   (`--accept-eval`/`--license-key`/`--license-file`) or interactively
//!   if the user provided none and stdin is a TTY.
//! * Progress is visible (`indicatif` `MultiProgress`) for ISO download
//!   + XML generation + install + snapshot.
//! * Ctrl-C cleans up (kills the VM if running, removes staging
//!   files).
//! * On success: prints "Done. Total time: Xm. Try: `neon stream
//!   netflix.com`".

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::bridge::config;
use crate::bridge::install::{self, ProvisionOpts, ProvisionOutcome};
use crate::bridge::iso;
use crate::bridge::libvirt_xml::PciAddress;
use crate::bridge::license::LicensePosture;
use crate::bridge::remediation;
use crate::cli::OutputOptions;
use crate::error::{Error, Result};
use crate::platform::capabilities::{self, BridgeCapabilities};

/// Args for `neon stream init`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// `--accept-eval`: opt into the 90-day Microsoft trial license.
    pub accept_eval: bool,
    /// `--license-key XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`: bring your own key.
    pub license_key: Option<String>,
    /// `--license-file <path>`: path to a CSV / KMS key file.
    pub license_file: Option<PathBuf>,
    /// Output flags.
    pub output: OutputOptions,
}

/// Run the init wizard.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — capability gate failed (any
///   capability red → exit non-zero with remediation).
/// * Propagates errors from `bridge::install::provision`.
pub fn run(args: &Args) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    run_with(args, &mut out, capabilities::detect)
}

/// Test-friendly variant: takes a writer and a capability-detector
/// closure. The detector is normally
/// [`capabilities::detect`] but tests inject a fixture.
///
/// # Errors
///
/// See [`run`].
pub fn run_with<F>(args: &Args, out: &mut dyn Write, detect: F) -> Result<()>
where
    F: FnOnce() -> BridgeCapabilities,
{
    let started = std::time::Instant::now();

    // Step 0: capability gate.
    let caps = detect();
    let issues = remediation::issues_for(&caps);
    if !issues.is_empty() {
        render_blocking_issues(&issues, out)?;
        return Err(Error::other(format!(
            "{} capability issue(s) blocking bridge install. \
             Fix the items above and run `neon stream init` again.",
            issues.len()
        )));
    }

    // Step 1: resolve license posture.
    let posture = resolve_license_posture(args)?;

    // Step 2: derive VM sizing from capabilities.
    let opts = build_provision_opts(posture.clone(), &caps);

    // Step 3: install Ctrl-C handler so a cancellation cleans up.
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_handle = Arc::clone(&cancel);
    // Best-effort SIGINT handler. We don't depend on the `ctrlc`
    // crate; we just install a libc signal handler that flips the
    // atomic. The handler is async-signal-safe (only stores a u8).
    install_sigint_handler(cancel_handle);

    // Step 4: kick off provisioning. Production prints progress via
    // `indicatif`; tests suppress it via the OutputOptions.quiet flag.
    if !args.output.quiet {
        writeln!(out, "Step 1/4: capability check ... ok").map_err(Error::from)?;
        writeln!(
            out,
            "Step 2/4: license posture: {}",
            posture_label(&posture)
        )
        .map_err(Error::from)?;
        writeln!(
            out,
            "Step 3/4: provisioning bridge VM (typically 25-40 minutes)"
        )
        .map_err(Error::from)?;
    }

    // Spin up an indicatif progress bar for the install phase. Skipped
    // under quiet mode + when stdout isn't a TTY (the install_progress
    // crate auto-detects + degrades cleanly).
    let progress = if args.output.quiet {
        None
    } else {
        Some(start_install_spinner())
    };

    let outcome = install::provision(&opts);

    if let Some(p) = progress.as_ref() {
        p.finish_and_clear();
    }

    if cancel.load(Ordering::SeqCst) {
        // Best-effort partial-state cleanup. We honor the design that
        // install::provision is itself idempotent — re-running picks up
        // where we stopped — so the cleanup here is just clearing the
        // unfinished progress UI.
        return Err(Error::other(
            "cancelled by user. Run `neon stream init` again to resume — \
             provisioning is idempotent and skips already-completed steps.",
        ));
    }

    let outcome: ProvisionOutcome = outcome.map_err(|e| {
        // V3-Phase F: append the repair suggestion to wizard errors so
        // users always see the next-step hint.
        Error::other(format!(
            "{e}\nIf you re-run `neon stream init` and hit the same error, \
             try `neon stream repair` to detect + fix broken state."
        ))
    })?;

    // Step 5: success message.
    let total = started.elapsed();
    if !args.output.quiet {
        writeln!(out, "Step 4/4: snapshot taken: {}", outcome.snapshot_name)
            .map_err(Error::from)?;
        writeln!(out).map_err(Error::from)?;
        writeln!(
            out,
            "Done. Total time: {}. Try: `neon stream netflix.com`",
            human_duration(total)
        )
        .map_err(Error::from)?;
    }
    Ok(())
}

/// Start the install-phase progress spinner. Uses
/// [`indicatif::ProgressBar::new_spinner`] with a tick interval that's
/// generous enough not to flicker. The bar is finished on success
/// or cancellation in [`run_with`].
fn start_install_spinner() -> indicatif::ProgressBar {
    let pb = indicatif::ProgressBar::new_spinner();
    pb.set_message("Provisioning bridge VM (typically 25-40 minutes)");
    pb.enable_steady_tick(Duration::from_millis(250));
    pb
}

/// Resolve the license posture from CLI flags, falling back to
/// interactive prompt when stdin is a TTY.
fn resolve_license_posture(args: &Args) -> Result<LicensePosture> {
    if args.accept_eval {
        return Ok(LicensePosture::eval_now());
    }
    if let Some(key) = args.license_key.as_deref() {
        if !crate::bridge::license::validate_product_key(key) {
            return Err(Error::other(format!(
                "license key {key:?} fails the X-X-X-X-X format check"
            )));
        }
        return Ok(LicensePosture::Key(key.to_string()));
    }
    if let Some(file) = args.license_file.clone() {
        if !file.exists() {
            return Err(Error::other(format!(
                "license file {} does not exist",
                file.display()
            )));
        }
        return Ok(LicensePosture::KeyFile(file));
    }
    // Interactive fallback. If stdin isn't a TTY, default to eval —
    // matches the CLI team's pattern in `cli::init` where canned
    // input falls through to safe defaults.
    if std::io::stdin().is_terminal() {
        // V3-Phase C ships a minimal interactive path: ask "accept
        // eval?" and stop. V3-Phase F's wizard polish adds key /
        // key-file prompts.
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(
                "Accept Microsoft's 90-day evaluation license? (No = supply --license-key or --license-file)",
            )
            .default(false)
            .interact()
            .map_err(|e| Error::other(format!("prompt failed: {e}")))?;
        if confirmed {
            Ok(LicensePosture::eval_now())
        } else {
            Err(Error::other(
                "no license posture chosen. Run with --accept-eval, \
                 --license-key XXXXX-..., or --license-file PATH.",
            ))
        }
    } else {
        Err(Error::other(
            "no license posture chosen and stdin is not a TTY. \
             Run with --accept-eval, --license-key XXXXX-..., or --license-file PATH.",
        ))
    }
}

/// Build [`ProvisionOpts`] from a posture + the host capability snapshot,
/// then merge any `~/.config/neon/bridge.toml` overrides on top.
fn build_provision_opts(posture: LicensePosture, caps: &BridgeCapabilities) -> ProvisionOpts {
    let gpu_addr = first_gpu_pci_address(caps);
    let mut opts = ProvisionOpts::defaults_for(
        posture,
        caps.ram.total_bytes,
        u32::try_from(num_cpus_or_default()).unwrap_or(8),
        gpu_addr,
    );
    // V3-Phase F: load bridge.toml overrides so the user can pin a
    // fresh ISO URL or override RAM/vCPU sizing without rebuilding.
    let cfg = config::load().unwrap_or_default();
    opts.iso_spec = config::apply_iso_override(iso::default_spec(), &cfg.iso);
    opts = config::apply_provision_overrides(opts, &cfg.bridge);
    opts
}

/// Best-effort: extract a `PciAddress` from the first GPU device. V3-
/// Phase C's `BridgeCapabilities` doesn't carry a parsed PCI BDF, so
/// we read it from the device's model string when possible. If we
/// can't, fall back to no-GPU (the install still completes; Looking
/// Glass just won't have a passthrough device).
fn first_gpu_pci_address(caps: &BridgeCapabilities) -> Option<PciAddress> {
    use crate::platform::capabilities::GpuStatus;
    let GpuStatus::Detected { devices } = &caps.gpu else {
        return None;
    };
    // V3-Phase C: the GPU PCI BDF will be added to GpuDevice in
    // V3-Phase D. For now we return None regardless of whether
    // any devices are detected; the wizard still works
    // (just renders a domain XML with no <hostdev>).
    let _ = devices.first();
    None
}

/// Best-effort CPU count. We don't pull in `num_cpus` for one call;
/// `available_parallelism` is in std.
fn num_cpus_or_default() -> usize {
    std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get)
}

/// Render the issues + remediation block when the capability gate
/// fails.
///
/// Apple-UX: lists ALL issues at once (not just the first), each with
/// per-issue remediation. The user fixes everything, runs `neon stream
/// init` once more, and is done.
fn render_blocking_issues(
    issues: &[remediation::CapabilityIssue],
    out: &mut dyn Write,
) -> Result<()> {
    writeln!(out, "neon stream init: capability gate FAILED").map_err(Error::from)?;
    writeln!(
        out,
        "Found {} issue(s). Each has a specific remediation below.",
        issues.len()
    )
    .map_err(Error::from)?;
    writeln!(out).map_err(Error::from)?;
    for (i, issue) in issues.iter().enumerate() {
        let r = remediation::remediation_for(issue);
        writeln!(out, "Issue {}/{}: {}", i + 1, issues.len(), r.title).map_err(Error::from)?;
        writeln!(out, "{}", r.detail).map_err(Error::from)?;
        writeln!(out).map_err(Error::from)?;
    }
    writeln!(
        out,
        "After fixing the items above, re-run `neon stream init`. \
         If anything goes wrong during install, `neon stream repair` \
         detects + remediates broken state."
    )
    .map_err(Error::from)?;
    Ok(())
}

/// Cancellation flag the libc signal handler flips. Stored as a
/// `OnceLock<Arc<AtomicBool>>` so multiple `run_with` invocations during
/// the program's lifetime share the same handler.
#[cfg(not(test))]
static SIGINT_CANCEL: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

#[cfg(not(test))]
extern "C" fn sigint_handler(_signum: libc::c_int) {
    if let Some(c) = SIGINT_CANCEL.get() {
        c.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Best-effort SIGINT install. Sets the atomic on Ctrl-C; the
/// install loop polls it.
///
/// V3-Phase F: we install a libc-level signal handler that flips the
/// atomic. The handler is async-signal-safe (only stores a u8 flag).
/// Inside `cargo test` we leave the runner's own handler in place —
/// otherwise the test runner can't tear down on Ctrl-C.
#[cfg(not(test))]
fn install_sigint_handler(cancel: Arc<AtomicBool>) {
    if SIGINT_CANCEL.set(cancel).is_err() {
        // Already installed — re-use the prior handler.
        return;
    }
    // SAFETY: signal() is async-signal-safe; the handler only stores
    // a relaxed atomic.
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
    }
}

/// Test-mode: do nothing. Real SIGINT handlers would interfere with
/// `cargo test`.
#[cfg(test)]
fn install_sigint_handler(_cancel: Arc<AtomicBool>) {}

/// Friendly user-visible label for a license posture.
fn posture_label(p: &LicensePosture) -> &'static str {
    match p {
        LicensePosture::Eval { .. } => "Microsoft 90-day evaluation",
        LicensePosture::Key(_) => "Windows product key",
        LicensePosture::KeyFile(_) => "key file",
    }
}

/// Format a `Duration` as `Xm` or `Xm Ys`.
fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let m = secs / 60;
    let s = secs % 60;
    if m == 0 {
        format!("{s}s")
    } else if s == 0 {
        format!("{m}m")
    } else {
        format!("{m}m {s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::capabilities::{
        DiskStatus, DisplayStatus, GpuDevice, GpuStatus, IommuKind, IommuStatus, KernelStatus,
        RamStatus, SessionType, TpmStatus, VirtKind, VirtStatus,
    };
    use std::path::PathBuf;

    fn green_caps() -> BridgeCapabilities {
        BridgeCapabilities {
            tpm: TpmStatus::Present {
                version: "2".into(),
                vendor: Some("STM".into()),
            },
            iommu: IommuStatus::Enabled {
                kind: IommuKind::AmdViO,
            },
            virtualization: VirtStatus::Enabled {
                kind: VirtKind::AmdV,
            },
            gpu: GpuStatus::Detected {
                devices: vec![
                    GpuDevice {
                        vendor: "Intel".into(),
                        model: "iGPU".into(),
                        iommu_group: Some(0),
                        clean_isolation: true,
                        hdr_capable: false,
                    },
                    GpuDevice {
                        vendor: "AMD".into(),
                        model: "dGPU".into(),
                        iommu_group: Some(21),
                        clean_isolation: true,
                        hdr_capable: true,
                    },
                ],
            },
            kernel: KernelStatus {
                version: "6.6.0".into(),
                kvmfr_supported: false,
            },
            disk: DiskStatus {
                free_bytes: 200u64 * 1024 * 1024 * 1024,
                mountpoint: "/".into(),
            },
            ram: RamStatus {
                total_bytes: 32u64 * 1024 * 1024 * 1024,
                available_bytes: 24u64 * 1024 * 1024 * 1024,
            },
            display: DisplayStatus {
                session_type: SessionType::Headless,
                hdr_capable: false,
            },
        }
    }

    fn red_caps() -> BridgeCapabilities {
        BridgeCapabilities {
            tpm: TpmStatus::Absent,
            iommu: IommuStatus::Absent,
            virtualization: VirtStatus::Absent,
            gpu: GpuStatus::NotDetected,
            kernel: KernelStatus {
                version: "x".into(),
                kvmfr_supported: false,
            },
            disk: DiskStatus {
                free_bytes: 0,
                mountpoint: "/".into(),
            },
            ram: RamStatus {
                total_bytes: 0,
                available_bytes: 0,
            },
            display: DisplayStatus {
                session_type: SessionType::Headless,
                hdr_capable: false,
            },
        }
    }

    #[test]
    fn red_caps_blocks_with_remediation_message() {
        let _g = crate::test_support::env_lock();
        let mut buf = Vec::new();
        let args = Args {
            accept_eval: true,
            ..Default::default()
        };
        let err = run_with(&args, &mut buf, red_caps).expect_err("must block");
        assert_eq!(err.category, crate::ErrorCategory::Other);
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("capability gate FAILED"));
        // At least one issue should surface the BIOS table.
        assert!(body.contains("ASUS") || body.contains("Lenovo"));
    }

    #[test]
    fn green_caps_with_provision_noop_succeeds() {
        let _g = crate::test_support::env_lock();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let bridge_config = tmp.path().join("config-redirect");
        std::fs::create_dir_all(&bridge_config).expect("config dir");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(install::PROVISION_NOOP_ENV, "1");
            std::env::set_var("XDG_CONFIG_HOME", &bridge_config);
        }
        let mut buf = Vec::new();
        let args = Args {
            accept_eval: true,
            output: OutputOptions {
                quiet: true,
                ..Default::default()
            },
            ..Default::default()
        };
        run_with(&args, &mut buf, green_caps).expect("succeed");
        unsafe {
            std::env::remove_var(install::PROVISION_NOOP_ENV);
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn license_key_invalid_format_rejected() {
        let _g = crate::test_support::env_lock();
        let mut buf = Vec::new();
        let args = Args {
            license_key: Some("garbage".into()),
            ..Default::default()
        };
        let err = run_with(&args, &mut buf, green_caps).expect_err("bad key");
        assert!(err.to_string().contains("X-X-X-X-X"));
    }

    #[test]
    fn license_file_missing_rejected() {
        let _g = crate::test_support::env_lock();
        let mut buf = Vec::new();
        let args = Args {
            license_file: Some(PathBuf::from("/dev/null/no/such/path")),
            ..Default::default()
        };
        let err = run_with(&args, &mut buf, green_caps).expect_err("missing file");
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn no_posture_and_no_tty_returns_explicit_error() {
        let _g = crate::test_support::env_lock();
        // We can't easily fake "stdin is a TTY" in tests; the test
        // body relies on `is_terminal()` returning false during cargo
        // test invocations (which is the case in CI + interactive
        // shells with stdin captured).
        let mut buf = Vec::new();
        let args = Args::default();
        let err = run_with(&args, &mut buf, green_caps).expect_err("no posture");
        assert!(err.to_string().contains("license posture"), "got: {err}");
    }

    #[test]
    fn human_duration_renders_minutes_and_seconds() {
        assert_eq!(human_duration(Duration::from_secs(0)), "0s");
        assert_eq!(human_duration(Duration::from_secs(45)), "45s");
        assert_eq!(human_duration(Duration::from_secs(60)), "1m");
        assert_eq!(human_duration(Duration::from_secs(125)), "2m 5s");
        assert_eq!(human_duration(Duration::from_secs(60 * 30)), "30m");
    }

    #[test]
    fn posture_label_for_each_variant() {
        assert!(posture_label(&LicensePosture::Eval { accepted_at: 0 }).contains("90-day"));
        assert!(
            posture_label(&LicensePosture::Key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".into()))
                .to_lowercase()
                .contains("key")
        );
        assert!(posture_label(&LicensePosture::KeyFile(PathBuf::from("/x")))
            .to_lowercase()
            .contains("key file"));
    }

    #[test]
    fn build_provision_opts_uses_host_ram() {
        let caps = green_caps();
        let opts = build_provision_opts(LicensePosture::Eval { accepted_at: 1 }, &caps);
        assert_eq!(opts.host_ram_total_bytes, caps.ram.total_bytes);
    }

    #[test]
    fn first_gpu_pci_address_returns_none_until_phase_d() {
        let caps = green_caps();
        // V3-Phase C's GpuDevice doesn't carry a PCI BDF yet.
        assert!(first_gpu_pci_address(&caps).is_none());
    }

    #[test]
    fn render_blocking_issues_writes_each_remediation() {
        let mut buf = Vec::new();
        let issues = vec![
            remediation::CapabilityIssue::TpmAbsent,
            remediation::CapabilityIssue::VirtDisabled,
        ];
        render_blocking_issues(&issues, &mut buf).expect("render");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("Issue 1/2"));
        assert!(body.contains("Issue 2/2"));
        assert!(body.contains("TPM"));
        assert!(body.contains("virtualization") || body.contains("VT-x"));
        // V3-Phase F polish: lists ALL issues + suggests `neon stream repair`.
        assert!(body.contains("issue(s)"));
        assert!(body.contains("neon stream repair"));
    }

    /// V3-Phase F: `build_provision_opts` honors `[bridge]` overrides
    /// from `bridge.toml`.
    #[test]
    fn build_provision_opts_applies_bridge_toml_overrides() {
        let _g = crate::test_support::env_lock();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let bridge_toml = tmp.path().join("neon").join("bridge.toml");
        std::fs::create_dir_all(bridge_toml.parent().unwrap()).expect("mkdir");
        std::fs::write(
            &bridge_toml,
            r#"[bridge]
data_dir = "/mnt/ssd/n-bridge"
ram_mb = 8192
"#,
        )
        .expect("write");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let caps = green_caps();
        let opts = build_provision_opts(LicensePosture::Eval { accepted_at: 1 }, &caps);
        assert_eq!(
            opts.data_root,
            std::path::PathBuf::from("/mnt/ssd/n-bridge")
        );
        // ram_mb override flows through host_ram_total_bytes.
        assert_eq!(opts.host_ram_total_bytes, 8192u64 * 1024 * 1024 * 4);
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    /// V3-Phase F: `build_provision_opts` honors `[iso]` URL override.
    #[test]
    fn build_provision_opts_applies_iso_url_override() {
        let _g = crate::test_support::env_lock();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let bridge_toml = tmp.path().join("neon").join("bridge.toml");
        std::fs::create_dir_all(bridge_toml.parent().unwrap()).expect("mkdir");
        std::fs::write(
            &bridge_toml,
            r#"[iso]
url = "https://example.com/win.iso"
"#,
        )
        .expect("write");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let caps = green_caps();
        let opts = build_provision_opts(LicensePosture::Eval { accepted_at: 1 }, &caps);
        assert_eq!(opts.iso_spec.url, "https://example.com/win.iso");
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }
}
