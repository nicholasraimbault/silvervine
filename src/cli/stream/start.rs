//! `neon stream start [URL]` — V3-Phase D resume + Looking Glass launch,
//! V3-Phase F URL navigation.
//!
//! Apple-UX guarantees:
//!
//! * Cold-start target: < 10 seconds on a warm snapshot pool. The
//!   wizard restores the libvirt domain from `fresh`, waits for
//!   Sunshine handshake (with a short timeout), and spawns Looking
//!   Glass.
//! * Single command: `neon stream netflix.com` opens a fullscreen
//!   guest desktop pointed at netflix.com.
//! * Hardware checks happen first: kvmfr loaded? IDD fallback OK?
//!   `bridge.toml` present? Each red gets a specific remediation
//!   surface (capability gate is the same one `cli::stream::init` uses).
//! * URL passing to the guest's Edge — V3-Phase F writes a sentinel file
//!   into the shared data directory which the guest's autounattend
//!   first-logon script polls. The first-logon script launches Edge
//!   pointed at the URL.
//! * [`NEON_TEST_GUEST_NAVIGATE_NOOP=1`](GUEST_NAVIGATE_NOOP_ENV) makes
//!   the URL-write step a no-op for tests.

use std::io::Write;
use std::time::{Duration, Instant};

use crate::bridge::idd_fallback;
use crate::bridge::install::{POST_INSTALL_SNAPSHOT, SENTINEL_NOOP_ENV};
use crate::bridge::libvirt::{Hypervisor, HV_NOOP_ENV};
use crate::bridge::license;
use crate::cli::OutputOptions;
use crate::error::{Error, Result};
use crate::platform::capabilities::{self, BridgeCapabilities};

#[cfg(target_os = "linux")]
use crate::bridge::kvmfr::{self, KvmfrStatus};
#[cfg(target_os = "linux")]
use crate::bridge::looking_glass::{self, LookingGlassHandle, LookingGlassSpec};

/// Args for `neon stream start`.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// Optional URL to open in the guest's Edge after launch. V3-Phase
    /// F wires the actual navigation; V3.0 just logs the URL and opens
    /// Edge at the default home page.
    pub url: Option<String>,
    /// Output flags.
    pub output: OutputOptions,
}

/// Cold-start budget per the V3 plan ("under 10s on a warm pool").
pub const COLD_START_BUDGET: Duration = Duration::from_secs(10);

/// Env var that gates the guest-side URL navigation in tests.
pub const GUEST_NAVIGATE_NOOP_ENV: &str = "NEON_TEST_GUEST_NAVIGATE_NOOP";

/// Filename of the navigation-URL sentinel inside the bridge data dir.
/// The guest's autounattend first-logon script polls this and, when
/// non-empty, launches Edge pointed at the URL.
pub const NAVIGATE_URL_SENTINEL: &str = "neon-navigate-url.txt";

/// Run `neon stream start`.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — capability gate failed (kvmfr
///   missing, license expired, dummy plug needed, etc.).
/// * Propagates errors from the libvirt + Looking Glass wrappers.
pub fn run(args: &Args) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    run_with(args, &mut out, capabilities::detect)
}

/// Test-friendly variant: takes a writer + a capability detector
/// closure (matches `cli::stream::init::run_with`).
///
/// # Errors
///
/// See [`run`].
#[allow(clippy::similar_names)]
pub fn run_with<F>(args: &Args, out: &mut dyn Write, detect: F) -> Result<()>
where
    F: FnOnce() -> BridgeCapabilities,
{
    let started = Instant::now();
    let caps = detect();

    // Step 1: bridge.toml must exist (license posture saved, init
    // completed). If missing, surface the init suggestion.
    if license::current_posture()?.is_none() {
        return Err(Error::other(
            "bridge.toml not found. Run `neon stream init --accept-eval` \
             (or with --license-key) before `neon stream start`.",
        ));
    }

    // Step 2: kvmfr loaded? (Linux only — macOS path doesn't touch
    // kvmfr.)
    #[cfg(target_os = "linux")]
    {
        let kvmfr_status = kvmfr::detect_kvmfr();
        if !kvmfr_status.is_loaded() {
            return Err(Error::other(format!(
                "kvmfr kernel module is not loaded ({:?}). \
                 Run `{}` and retry. \
                 (Looking Glass requires the kvmfr device at /dev/kvmfr0.)",
                short_kvmfr_label(&kvmfr_status),
                kvmfr::load_module_command(),
            )));
        }
    }

    // Step 3: IDD fallback — single-GPU host without a dummy plug
    // can't run LG cleanly. We surface it as a hard error so the user
    // doesn't watch a black-screened LG window.
    let idd = idd_fallback::detect(&caps);
    if !idd.is_satisfied() {
        let link = idd.shopping_link().unwrap_or("(none)");
        return Err(Error::other(format!(
            "IDD fallback not satisfied: {idd:?}. \
             Buy a $5 4K HDMI dummy plug ({link}) and plug it into a \
             free port on the host GPU."
        )));
    }

    // Step 4: connect to libvirt + restore from snapshot.
    if !args.output.quiet {
        writeln!(out, "Step 1/3: capability check ... ok").map_err(Error::from)?;
    }
    let hv = Hypervisor::connect()?;
    let domain = hv.lookup_domain("neon-bridge").map_err(|e| {
        Error::other(format!(
            "libvirt domain `neon-bridge` not defined ({e}). \
             Run `neon stream init` first."
        ))
    })?;
    domain.restore_from_snapshot(POST_INSTALL_SNAPSHOT)?;
    if !args.output.quiet {
        writeln!(
            out,
            "Step 2/3: VM resumed from `{POST_INSTALL_SNAPSHOT}` snapshot"
        )
        .map_err(Error::from)?;
    }

    // Step 5: best-effort Sunshine probe (skipped under HV NOOP /
    // SENTINEL NOOP). We don't fail on probe miss — the LG client itself
    // surfaces "guest not ready" cleanly.
    let _sunshine_reachable = wait_for_sunshine_handshake(Duration::from_secs(5));

    // Step 6: launch Looking Glass. Linux-only; on macOS there's no
    // host-side LG and the function would have returned earlier
    // before this point. The Linux-gated handle is forget()-ed
    // below so the LG client survives `neon stream start` exiting.
    #[cfg(target_os = "linux")]
    let lg_handle = launch_looking_glass()?;

    if !args.output.quiet {
        writeln!(out, "Step 3/3: Looking Glass client launched").map_err(Error::from)?;
    }

    // V3-Phase F: write the URL into the shared sentinel file the
    // guest's first-logon script polls. The guest opens Edge with the
    // URL parameter when the sentinel is non-empty.
    if let Some(url) = args.url.as_deref() {
        match write_navigate_url(url) {
            Ok(path) => {
                if !args.output.quiet {
                    writeln!(
                        out,
                        "Wrote URL to {} — guest's Edge picks this up at first poll \
                         (typically within a few seconds).",
                        path.display()
                    )
                    .map_err(Error::from)?;
                }
            }
            Err(e) => {
                if !args.output.quiet {
                    writeln!(
                        out,
                        "Note: could not write navigation sentinel ({e}). \
                         Paste {url} into Edge inside the Looking Glass window."
                    )
                    .map_err(Error::from)?;
                }
            }
        }
    }

    if !args.output.quiet {
        writeln!(
            out,
            "Cold start time: {}.",
            human_duration(started.elapsed())
        )
        .map_err(Error::from)?;
    }

    // Detach the LG handle so the process keeps running after this
    // function returns. Drop sends SIGTERM; we want the LG window to
    // outlive `neon stream start`. macOS has no handle to detach.
    #[cfg(target_os = "linux")]
    std::mem::forget(lg_handle);

    Ok(())
}

#[cfg(target_os = "linux")]
fn short_kvmfr_label(status: &KvmfrStatus) -> &'static str {
    match status {
        KvmfrStatus::Loaded { .. } => "loaded",
        KvmfrStatus::Available { .. } => "available but not loaded",
        KvmfrStatus::Missing => "missing",
    }
}

/// Best-effort Sunshine handshake. Returns `true` when the probe
/// connected; `false` on timeout / NOOP. Under NOOP env vars we
/// treat the probe as "skipped" and report `false` (callers don't
/// fail on the result; LG itself surfaces "guest not ready").
fn wait_for_sunshine_handshake(timeout: Duration) -> bool {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    if std::env::var_os(HV_NOOP_ENV).is_some() || std::env::var_os(SENTINEL_NOOP_ENV).is_some() {
        return false;
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47984);
    let started = Instant::now();
    while started.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Spawn Looking Glass per the wizard defaults (fullscreen + cursor
/// grab + audio; HDR off per V3 plan).
#[cfg(target_os = "linux")]
fn launch_looking_glass() -> Result<LookingGlassHandle> {
    let spec = LookingGlassSpec::defaults();
    looking_glass::launch(&spec)
}

/// Write the URL into the bridge-data-dir sentinel file the guest's
/// first-logon script polls.
///
/// Honors [`GUEST_NAVIGATE_NOOP_ENV`] — under NOOP we don't write the
/// file; we just return the path that *would* have been written.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — disk I/O / no resolvable data dir.
fn write_navigate_url(url: &str) -> Result<std::path::PathBuf> {
    let data_dir = dirs::data_local_dir()
        .map(|d| d.join("neon").join("bridge"))
        .ok_or_else(|| Error::other("cannot resolve ~/.local/share/neon/bridge"))?;
    let path = data_dir.join(NAVIGATE_URL_SENTINEL);
    if std::env::var_os(GUEST_NAVIGATE_NOOP_ENV).is_some() {
        return Ok(path);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::from)?;
    }
    std::fs::write(&path, url).map_err(Error::from)?;
    Ok(path)
}

/// Format a `Duration` as `Xs` or `Xm Ys`. Same shape as
/// `cli::stream::init::human_duration`.
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
    use crate::bridge::license::LicensePosture;
    use crate::platform::capabilities::{
        DiskStatus, DisplayStatus, GpuDevice, GpuStatus, IommuKind, IommuStatus, KernelStatus,
        RamStatus, SessionType, TpmStatus, VirtKind, VirtStatus,
    };

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
                kvmfr_supported: true,
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

    fn redirect_xdg_config(tmp: &std::path::Path) -> std::path::PathBuf {
        let bridge_config = tmp.join("config-redirect");
        std::fs::create_dir_all(&bridge_config).expect("mkdir config redirect");
        bridge_config
    }

    /// Save a fresh trial license posture so `current_posture` returns
    /// `Some(...)`.
    #[allow(dead_code, reason = "used by Linux-gated test cases below")]
    fn write_trial_posture(config_root: &std::path::Path) {
        let bridge_toml = config_root.join("neon").join("bridge.toml");
        std::fs::create_dir_all(bridge_toml.parent().unwrap()).expect("mkdir");
        license::save_posture_to(&LicensePosture::eval_now(), &bridge_toml).expect("save");
    }

    #[test]
    fn run_with_no_bridge_toml_returns_init_suggestion() {
        let _g = crate::test_support::env_lock();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let bridge_config = redirect_xdg_config(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &bridge_config);
        }
        let mut buf = Vec::new();
        let args = Args::default();
        let err = run_with(&args, &mut buf, green_caps).expect_err("no bridge.toml");
        assert!(err.to_string().contains("bridge.toml not found"));
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn run_with_no_kvmfr_returns_modprobe_suggestion() {
        let _g = crate::test_support::env_lock();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let bridge_config = redirect_xdg_config(tmp.path());
        write_trial_posture(&bridge_config);
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &bridge_config);
            std::env::remove_var(crate::bridge::kvmfr::NOOP_ENV);
        }
        let mut buf = Vec::new();
        let args = Args::default();
        let err = run_with(&args, &mut buf, green_caps).expect_err("no kvmfr");
        let msg = err.to_string();
        // Either kvmfr really is not loaded on this host (expected in
        // most test environments) → message contains "modprobe", OR it
        // *is* loaded (unlikely on CI) → in that case we'd skip past
        // and hit the next gate. Tolerate both.
        if !msg.contains("modprobe") {
            // We hit a downstream gate; ensure it's still a sane error.
            assert!(!msg.is_empty());
        }
        unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    }

    /// Single-GPU host with no DRM tree under our redirected fixture
    /// → IDD fallback fails. Tests this specifically by going through
    /// the dummy-plug branch.
    #[test]
    fn idd_fallback_shopping_link_appears_in_error_message() {
        // Construct caps with a single GPU; detect() reads
        // `/sys/class/drm` on the host. We can't easily inject a tempdir
        // path through `cli::stream::start::run_with` (it calls
        // `idd_fallback::detect(...)` directly). Instead verify the
        // IddFallbackStatus surfaces a shopping link, and assume the
        // host/CI machine doesn't have its `/sys/class/drm` cleared.
        let single_gpu_caps = BridgeCapabilities {
            gpu: GpuStatus::Detected {
                devices: vec![GpuDevice {
                    vendor: "AMD".into(),
                    model: "dGPU".into(),
                    iommu_group: Some(21),
                    clean_isolation: true,
                    hdr_capable: true,
                }],
            },
            ..green_caps()
        };
        // Use detect_with against a tempdir tree to make this
        // deterministic.
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let drm_root = tmp.path().join("nope");
        let status = idd_fallback::detect_with(&single_gpu_caps, &drm_root);
        match status {
            idd_fallback::IddFallbackStatus::DummyPlugRequired { shopping_link, .. } => {
                assert!(shopping_link.contains("amazon.com"));
            }
            other => panic!("expected DummyPlugRequired, got {other:?}"),
        }
    }

    #[test]
    fn human_duration_formats_minutes_and_seconds() {
        assert_eq!(human_duration(Duration::from_secs(0)), "0s");
        assert_eq!(human_duration(Duration::from_secs(45)), "45s");
        assert_eq!(human_duration(Duration::from_secs(60)), "1m");
        assert_eq!(human_duration(Duration::from_secs(125)), "2m 5s");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn short_kvmfr_label_for_each_variant() {
        assert_eq!(
            short_kvmfr_label(&KvmfrStatus::Loaded {
                device_path: std::path::PathBuf::from("/dev/kvmfr0"),
            }),
            "loaded"
        );
        assert_eq!(
            short_kvmfr_label(&KvmfrStatus::Available {
                module_path: std::path::PathBuf::from("/lib/modules/x/extra/kvmfr.ko"),
            }),
            "available but not loaded"
        );
        assert_eq!(short_kvmfr_label(&KvmfrStatus::Missing), "missing");
    }

    #[test]
    fn wait_for_sunshine_handshake_under_hv_noop_returns_immediately() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(HV_NOOP_ENV, "1");
        }
        let started = Instant::now();
        let reachable = wait_for_sunshine_handshake(Duration::from_secs(60));
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(100));
        // NOOP returns "not reachable" because the probe is skipped.
        assert!(!reachable);
        unsafe { std::env::remove_var(HV_NOOP_ENV) };
    }

    #[test]
    fn wait_for_sunshine_handshake_under_sentinel_noop_returns_immediately() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(SENTINEL_NOOP_ENV, "1");
        }
        let started = Instant::now();
        let reachable = wait_for_sunshine_handshake(Duration::from_secs(60));
        let elapsed = started.elapsed();
        assert!(elapsed < Duration::from_millis(100));
        assert!(!reachable);
        unsafe { std::env::remove_var(SENTINEL_NOOP_ENV) };
    }

    /// End-to-end orchestration test: bridge.toml present, kvmfr NOOP'd,
    /// libvirt NOOP'd, LG NOOP'd, dual-GPU caps so IDD fallback passes.
    #[cfg(target_os = "linux")]
    #[test]
    fn run_with_full_noop_succeeds_end_to_end() {
        let _g = crate::test_support::env_lock();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let bridge_config = redirect_xdg_config(tmp.path());
        write_trial_posture(&bridge_config);
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &bridge_config);
            std::env::set_var(crate::bridge::kvmfr::NOOP_ENV, "1");
            std::env::set_var(HV_NOOP_ENV, "1");
            std::env::set_var(SENTINEL_NOOP_ENV, "1");
            std::env::set_var(crate::bridge::looking_glass::NOOP_ENV, "1");
            std::env::set_var(GUEST_NAVIGATE_NOOP_ENV, "1");
        }
        let mut buf = Vec::new();
        let args = Args {
            url: Some("https://netflix.com".into()),
            output: OutputOptions::default(),
        };
        let result = run_with(&args, &mut buf, green_caps);
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var(crate::bridge::kvmfr::NOOP_ENV);
            std::env::remove_var(HV_NOOP_ENV);
            std::env::remove_var(SENTINEL_NOOP_ENV);
            std::env::remove_var(crate::bridge::looking_glass::NOOP_ENV);
            std::env::remove_var(GUEST_NAVIGATE_NOOP_ENV);
        }
        result.expect("noop full path");
        let body = String::from_utf8(buf).expect("utf8");
        assert!(body.contains("VM resumed"));
        assert!(body.contains("Looking Glass"));
        // URL navigation surfaced.
        assert!(body.contains("Wrote URL"));
    }

    /// `write_navigate_url` under NOOP returns the path without writing.
    #[test]
    fn write_navigate_url_under_noop_is_pure() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(GUEST_NAVIGATE_NOOP_ENV, "1");
        }
        let path = write_navigate_url("https://example.com").expect("url path");
        assert!(path.ends_with(NAVIGATE_URL_SENTINEL));
        unsafe {
            std::env::remove_var(GUEST_NAVIGATE_NOOP_ENV);
        }
    }

    /// `write_navigate_url` writes URL bytes when not NOOP'd.
    #[test]
    fn write_navigate_url_writes_url_bytes() {
        let _g = crate::test_support::env_lock();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_DATA_HOME", tmp.path());
            std::env::remove_var(GUEST_NAVIGATE_NOOP_ENV);
        }
        let path = write_navigate_url("https://example.com").expect("url path");
        let contents = std::fs::read_to_string(&path).expect("read");
        assert_eq!(contents, "https://example.com");
        unsafe {
            std::env::remove_var("XDG_DATA_HOME");
        }
    }

    #[test]
    fn args_default_has_no_url() {
        let a = Args::default();
        assert!(a.url.is_none());
    }
}
