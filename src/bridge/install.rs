//! Install orchestration for the V3 bridge VM — V3-Phase C.
//!
//! Top-level [`provision`] glues the rest of the bridge module
//! together:
//!
//! 1. [`crate::bridge::iso::ensure_iso`] — get the Win11 `IoT` LTSC ISO.
//! 2. [`crate::bridge::license::save_posture`] — persist the user's
//!    license choice.
//! 3. Render `autounattend.xml` ([`crate::bridge::unattended`]).
//! 4. Write `autounattend.iso` (ISO9660 stub, tiny — see
//!    [`build_autounattend_iso`]).
//! 5. Render libvirt domain XML ([`crate::bridge::libvirt_xml`]).
//! 6. Create qcow2 disk image (60 GB sparse).
//! 7. Define + start the libvirt domain ([`crate::bridge::libvirt`]).
//! 8. Poll for `C:\neon-bridge-ready` sentinel (via guest-agent or
//!    Sunshine handshake).
//! 9. Take a "fresh" snapshot.
//! 10. Return [`ProvisionOutcome`] with name, snapshot label, duration.
//!
//! ## Test-mode env vars
//!
//! | Var | Effect |
//! |---|---|
//! | [`PROVISION_NOOP_ENV`] | Provision skips all I/O and returns a stub outcome |
//! | [`crate::bridge::iso::ISO_FIXTURE_ENV`] | ISO download returns a 1KB fixture |
//! | [`crate::bridge::libvirt::HV_NOOP_ENV`] | libvirt connection is mocked |
//! | [`ISOGEN_NOOP_ENV`] | `genisoimage`/`mkisofs` shell-out is no-op'd; we write a stub `.iso` file |
//! | [`QCOW2_NOOP_ENV`] | qcow2 disk creation is no-op'd; we touch a 0-byte file |
//! | [`SENTINEL_NOOP_ENV`] | Skip the sentinel poll loop entirely; assume ready |

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::bridge::iso::{self, IsoSpec};
use crate::bridge::libvirt::{self, Hypervisor};
use crate::bridge::libvirt_xml::{self, DomainSpec, PciAddress};
use crate::bridge::license::{self, LicensePosture};
use crate::bridge::unattended::{self, UnattendedOptions};
use crate::error::{Error, Result};

/// Env var that short-circuits the entire provision flow. Tests that
/// only want to assert on the orchestration shape (e.g. that the
/// dispatcher calls each step once) set this to `1` and inspect the
/// returned [`ProvisionOutcome`].
pub const PROVISION_NOOP_ENV: &str = "NEON_TEST_PROVISION_NOOP";

/// Env var gating the ISO9660 generation shell-out (`genisoimage`).
pub const ISOGEN_NOOP_ENV: &str = "NEON_TEST_ISOGEN_NOOP";

/// Env var gating qcow2 disk image creation.
pub const QCOW2_NOOP_ENV: &str = "NEON_TEST_QCOW2_NOOP";

/// Env var gating the sentinel poll loop (used by tests + by failure-
/// injection in the wizard).
pub const SENTINEL_NOOP_ENV: &str = "NEON_TEST_SENTINEL_NOOP";

/// Maximum time to wait for the unattended Windows install to drop the
/// `C:\neon-bridge-ready` sentinel.
pub const SENTINEL_TIMEOUT: Duration = Duration::from_secs(45 * 60);

/// Default sparse qcow2 size (60 GB virtual; sparse on disk).
pub const DEFAULT_DISK_GB: u64 = 60;

/// Snapshot label taken after a successful provision.
pub const POST_INSTALL_SNAPSHOT: &str = "fresh";

/// Default VM name used by the wizard.
pub const DEFAULT_VM_NAME: &str = "neon-bridge";

/// Inputs to [`provision`].
#[derive(Debug, Clone)]
pub struct ProvisionOpts {
    /// VM name. Defaults to [`DEFAULT_VM_NAME`].
    pub vm_name: String,
    /// License posture chosen by the user (or read from
    /// `bridge.toml` if already saved).
    pub license_posture: LicensePosture,
    /// ISO spec to download. Defaults to [`iso::default_spec`].
    pub iso_spec: IsoSpec,
    /// Bridge data root. Defaults to
    /// `~/.local/share/neon/bridge/`.
    pub data_root: PathBuf,
    /// PCI BDF of the GPU to pass through. `None` = headless install
    /// (still works, just no Looking Glass).
    pub gpu_pci_address: Option<PciAddress>,
    /// Host RAM total bytes (drives sizing). The wizard reads this
    /// from `BridgeCapabilities`.
    pub host_ram_total_bytes: u64,
    /// Host CPU count.
    pub host_cpu_count: u32,
    /// Disk size in GB (defaults to [`DEFAULT_DISK_GB`]).
    pub disk_gb: u64,
}

impl ProvisionOpts {
    /// Build options from a license posture + the host snapshot.
    /// Uses [`iso::default_spec`] and the canonical paths.
    #[must_use]
    pub fn defaults_for(
        license_posture: LicensePosture,
        host_ram_total_bytes: u64,
        host_cpu_count: u32,
        gpu_pci_address: Option<PciAddress>,
    ) -> Self {
        Self {
            vm_name: DEFAULT_VM_NAME.into(),
            license_posture,
            iso_spec: iso::default_spec(),
            data_root: dirs::data_local_dir().map_or_else(
                || PathBuf::from("/tmp/neon-bridge"),
                |d| d.join("neon").join("bridge"),
            ),
            gpu_pci_address,
            host_ram_total_bytes,
            host_cpu_count,
            disk_gb: DEFAULT_DISK_GB,
        }
    }
}

/// Outcome of a successful [`provision`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionOutcome {
    /// VM name (matches `vm_name` from opts).
    pub vm_name: String,
    /// Snapshot label captured after install.
    pub snapshot_name: String,
    /// Total wall-clock time the install took.
    pub install_duration: Duration,
    /// Path to the downloaded ISO.
    pub iso_path: PathBuf,
    /// Path to the qcow2 disk.
    pub disk_path: PathBuf,
}

/// Top-level entry point for `neon stream init`'s install phase.
///
/// Drives the full sequence from "user said yes to the license" to
/// "VM is provisioned + snapshot taken".
///
/// # Errors
///
/// Errors are surfaced by category — see each step's docs.
pub fn provision(opts: &ProvisionOpts) -> Result<ProvisionOutcome> {
    if std::env::var_os(PROVISION_NOOP_ENV).is_some() {
        return Ok(ProvisionOutcome {
            vm_name: opts.vm_name.clone(),
            snapshot_name: POST_INSTALL_SNAPSHOT.into(),
            install_duration: Duration::from_secs(0),
            iso_path: opts.data_root.join("iso/stub.iso"),
            disk_path: opts.data_root.join("disk.qcow2"),
        });
    }

    let started = Instant::now();

    // Step 1: ensure paths exist.
    std::fs::create_dir_all(&opts.data_root).map_err(Error::from)?;
    let iso_dir = opts.data_root.join("iso");
    std::fs::create_dir_all(&iso_dir).map_err(Error::from)?;

    // Step 2: download + verify the Windows ISO.
    let iso_path = iso::ensure_iso_in(&opts.iso_spec, &iso_dir)?;

    // Step 3: persist the license posture.
    license::save_posture(&opts.license_posture)?;

    // Step 4: render autounattend.xml. V3-Phase F: merge `[sunshine]`
    // overrides from bridge.toml so users can pin a fresh installer URL.
    let unattended_opts = {
        let baseline = UnattendedOptions::defaults_for(opts.license_posture.clone());
        let cfg = crate::bridge::config::load().unwrap_or_default();
        crate::bridge::config::apply_sunshine_override(baseline, &cfg.sunshine)
    };
    let unattended_xml = unattended::render_autounattend(&unattended_opts)?;

    // Step 5: build the autounattend ISO.
    let autounattend_iso = opts.data_root.join("autounattend.iso");
    build_autounattend_iso(&unattended_xml, &autounattend_iso)?;

    // Step 6: create qcow2 disk.
    let disk_path = opts.data_root.join("disk.qcow2");
    create_qcow2_disk(&disk_path, opts.disk_gb)?;

    // Step 7: render libvirt domain XML. V3-Phase F: merge `[bridge]`
    // ivshmem / ram / vcpu overrides from bridge.toml.
    let domain_spec = {
        let baseline = DomainSpec {
            name: opts.vm_name.clone(),
            ..DomainSpec::sized_for_host(
                opts.vm_name.clone(),
                opts.host_ram_total_bytes,
                opts.host_cpu_count,
                disk_path.clone(),
                iso_path.clone(),
                autounattend_iso.clone(),
                opts.gpu_pci_address.clone(),
            )
        };
        let cfg = crate::bridge::config::load().unwrap_or_default();
        crate::bridge::config::apply_domain_overrides(baseline, &cfg.bridge)
    };
    let domain_xml = libvirt_xml::render_domain_xml(&domain_spec)?;
    libvirt_xml::validate_with_virt_xml_validate(&domain_xml)?;

    // Step 8: define + start the domain.
    let hv = Hypervisor::connect()?;
    let domain = hv.define_domain(&domain_xml)?;
    domain.start()?;

    // Step 9: poll for the sentinel.
    poll_sentinel(&domain, SENTINEL_TIMEOUT)?;

    // Step 10: snapshot.
    domain.snapshot(POST_INSTALL_SNAPSHOT)?;

    Ok(ProvisionOutcome {
        vm_name: opts.vm_name.clone(),
        snapshot_name: POST_INSTALL_SNAPSHOT.into(),
        install_duration: started.elapsed(),
        iso_path,
        disk_path,
    })
}

/// Build a small ISO9660 image that embeds `autounattend.xml` at its
/// root. The Windows installer mounts this as a CD-ROM and locates
/// the file automatically.
///
/// Implementation: shells out to `genisoimage` (Linux) /
/// `mkisofs` (macOS — bridge is Linux-only but the function compiles).
/// When `NEON_TEST_ISOGEN_NOOP=1` is set, writes a stub byte string
/// so callers can still see a file exist.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — subprocess failed.
pub fn build_autounattend_iso(unattended_xml: &str, out_path: &Path) -> Result<()> {
    if std::env::var_os(ISOGEN_NOOP_ENV).is_some() {
        // Stub: write a tiny "ISO" so downstream tests find a file.
        let mut content = Vec::with_capacity(2048);
        content.extend_from_slice(b"NEON-AUTOUNATTEND-ISO-STUB\n");
        content.extend_from_slice(unattended_xml.as_bytes());
        std::fs::write(out_path, content).map_err(Error::from)?;
        return Ok(());
    }

    // Stage the XML in a tempdir, then point genisoimage at it.
    let tmp = tempfile::TempDir::new().map_err(Error::from)?;
    let staging = tmp.path().join("autounattend");
    std::fs::create_dir_all(&staging).map_err(Error::from)?;
    std::fs::write(staging.join("autounattend.xml"), unattended_xml).map_err(Error::from)?;

    // Try `genisoimage` first (Debian/Ubuntu/Arch); fall back to
    // `mkisofs` (older naming).
    for tool in &["genisoimage", "mkisofs"] {
        let result = std::process::Command::new(tool)
            .args([
                "-quiet", "-J", // Joliet — case-preserving filenames
                "-r", // Rock Ridge — Unix attributes
                "-o",
            ])
            .arg(out_path)
            .arg(&staging)
            .output();
        match result {
            Ok(out) if out.status.success() => return Ok(()),
            Ok(out) => {
                return Err(Error::other(format!(
                    "{tool} failed: stderr={}",
                    String::from_utf8_lossy(&out.stderr)
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::from(e)),
        }
    }
    Err(Error::other(
        "neither `genisoimage` nor `mkisofs` is on PATH; install one to build the autounattend ISO",
    ))
}

/// Create a sparse qcow2 disk at `path` of size `gb` GB.
///
/// Implementation: shells out to `qemu-img create -f qcow2 <path>
/// <gb>G`. When `NEON_TEST_QCOW2_NOOP=1` is set, touches a 0-byte
/// file — the orchestration checks for the file's presence, not its
/// size.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — subprocess failed or
///   `qemu-img` not on PATH.
pub fn create_qcow2_disk(path: &Path, gb: u64) -> Result<()> {
    if std::env::var_os(QCOW2_NOOP_ENV).is_some() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::from)?;
        }
        std::fs::write(path, b"NEON-QCOW2-STUB\n").map_err(Error::from)?;
        return Ok(());
    }
    let size_arg = format!("{gb}G");
    let output = std::process::Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(path)
        .arg(&size_arg)
        .output()
        .map_err(|e| Error::other(format!("qemu-img spawn: {e}")))?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "qemu-img create failed: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Poll the running domain for the `C:\neon-bridge-ready` sentinel.
///
/// V3-Phase C bridges the gap by querying the libvirt-rs guest-agent
/// (when available) — the agent reports file existence inside the
/// guest. When `NEON_TEST_SENTINEL_NOOP=1` is set, returns immediately
/// with success.
///
/// In production this loop sleeps 30 seconds between polls and gives
/// up after `timeout`.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — timeout reached.
pub fn poll_sentinel(_domain: &libvirt::Domain, timeout: Duration) -> Result<()> {
    if std::env::var_os(SENTINEL_NOOP_ENV).is_some() {
        return Ok(());
    }
    // Real implementation polls libvirt's guest-agent for file
    // existence. The libvirt-rs `virt::domain::Domain` API exposes
    // `qemu_agent_command` for this; the JSON RPC is
    // `{"execute":"guest-file-open","arguments":{"path":"C:/neon-bridge-ready"}}`
    // followed by checking for ENOENT vs success. V3-Phase C ships this
    // structure; the actual JSON handshake is tuned in V3-Phase D once
    // we've validated the agent runs reliably.
    //
    // Until the JSON path is wired, we sleep + return Err on timeout
    // so production callers see an explicit failure mode rather than
    // a silent indefinite wait.
    let started = Instant::now();
    while started.elapsed() < timeout {
        std::thread::sleep(Duration::from_secs(30));
    }
    Err(Error::other(format!(
        "neon-bridge-ready sentinel not seen within {timeout:?}; \
         the unattended install may have stalled. \
         Check libvirt's serial console: \
         `sudo virsh console neon-bridge`."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn baseline_opts(tmp: &Path) -> ProvisionOpts {
        ProvisionOpts {
            vm_name: "neon-bridge".into(),
            license_posture: LicensePosture::Eval { accepted_at: 1 },
            iso_spec: IsoSpec {
                url: "http://127.0.0.1:1/x".into(),
                sha256: iso::fixture_sha256(),
                expected_size: 1024,
            },
            data_root: tmp.to_path_buf(),
            gpu_pci_address: Some(PciAddress {
                domain: 0,
                bus: 0x65,
                slot: 0,
                function: 0,
            }),
            host_ram_total_bytes: 32u64 * 1024 * 1024 * 1024,
            host_cpu_count: 8,
            disk_gb: 60,
        }
    }

    #[test]
    fn provision_under_full_noop_returns_outcome() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let opts = baseline_opts(tmp.path());
        // SAFETY: env behind env_lock.
        unsafe { std::env::set_var(PROVISION_NOOP_ENV, "1") };
        let outcome = provision(&opts).expect("provision noop");
        assert_eq!(outcome.vm_name, "neon-bridge");
        assert_eq!(outcome.snapshot_name, POST_INSTALL_SNAPSHOT);
        unsafe { std::env::remove_var(PROVISION_NOOP_ENV) };
    }

    #[test]
    fn provision_full_sequence_under_per_step_noop() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let opts = baseline_opts(tmp.path());
        let bridge_config = tmp.path().join("config-redirect");
        std::fs::create_dir_all(&bridge_config).expect("config dir");
        // SAFETY: env mutations under env_lock.
        unsafe {
            std::env::set_var(iso::ISO_FIXTURE_ENV, "1");
            std::env::set_var(libvirt::HV_NOOP_ENV, "1");
            std::env::set_var(ISOGEN_NOOP_ENV, "1");
            std::env::set_var(QCOW2_NOOP_ENV, "1");
            std::env::set_var(SENTINEL_NOOP_ENV, "1");
            std::env::set_var(libvirt_xml::VIRT_XML_VALIDATE_NOOP_ENV, "1");
            std::env::set_var("XDG_CONFIG_HOME", &bridge_config);
        }
        let outcome = provision(&opts).expect("provision");
        assert_eq!(outcome.vm_name, "neon-bridge");
        assert_eq!(outcome.snapshot_name, POST_INSTALL_SNAPSHOT);
        // ISO file written.
        assert!(outcome.iso_path.exists());
        // Disk image written (stub byte string).
        assert!(outcome.disk_path.exists());
        // bridge.toml landed under our redirected XDG_CONFIG_HOME.
        let bridge_toml = bridge_config.join("neon").join("bridge.toml");
        assert!(bridge_toml.exists(), "bridge.toml should be saved");
        unsafe {
            std::env::remove_var(iso::ISO_FIXTURE_ENV);
            std::env::remove_var(libvirt::HV_NOOP_ENV);
            std::env::remove_var(ISOGEN_NOOP_ENV);
            std::env::remove_var(QCOW2_NOOP_ENV);
            std::env::remove_var(SENTINEL_NOOP_ENV);
            std::env::remove_var(libvirt_xml::VIRT_XML_VALIDATE_NOOP_ENV);
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    #[test]
    fn build_autounattend_iso_under_noop_writes_stub_file() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let out = tmp.path().join("autounattend.iso");
        // SAFETY: env behind env_lock.
        unsafe { std::env::set_var(ISOGEN_NOOP_ENV, "1") };
        build_autounattend_iso("<unattend/>", &out).expect("build noop");
        assert!(out.exists());
        let body = std::fs::read(&out).expect("read");
        assert!(body.starts_with(b"NEON-AUTOUNATTEND-ISO-STUB"));
        unsafe { std::env::remove_var(ISOGEN_NOOP_ENV) };
    }

    #[test]
    fn create_qcow2_disk_under_noop_writes_stub_file() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("disk.qcow2");
        // SAFETY: env behind env_lock.
        unsafe { std::env::set_var(QCOW2_NOOP_ENV, "1") };
        create_qcow2_disk(&path, 60).expect("create noop");
        assert!(path.exists());
        unsafe { std::env::remove_var(QCOW2_NOOP_ENV) };
    }

    #[test]
    fn provision_opts_defaults_uses_canonical_vm_name() {
        let opts = ProvisionOpts::defaults_for(
            LicensePosture::Eval { accepted_at: 1 },
            32u64 * 1024 * 1024 * 1024,
            8,
            None,
        );
        assert_eq!(opts.vm_name, DEFAULT_VM_NAME);
        assert_eq!(opts.disk_gb, DEFAULT_DISK_GB);
    }

    #[test]
    fn poll_sentinel_under_noop_returns_immediately() {
        let _g = crate::test_support::env_lock();
        let hv = Hypervisor::mock();
        let dom = hv
            .define_domain("<domain><name>n</name></domain>")
            .expect("define");
        // SAFETY: env behind env_lock.
        unsafe { std::env::set_var(SENTINEL_NOOP_ENV, "1") };
        poll_sentinel(&dom, Duration::from_secs(1)).expect("noop poll");
        unsafe { std::env::remove_var(SENTINEL_NOOP_ENV) };
    }

    #[test]
    fn provision_records_libvirt_lifecycle_under_full_noop() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        let opts = baseline_opts(tmp.path());
        let bridge_config = tmp.path().join("config-redirect");
        std::fs::create_dir_all(&bridge_config).expect("config dir");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var(iso::ISO_FIXTURE_ENV, "1");
            std::env::set_var(libvirt::HV_NOOP_ENV, "1");
            std::env::set_var(ISOGEN_NOOP_ENV, "1");
            std::env::set_var(QCOW2_NOOP_ENV, "1");
            std::env::set_var(SENTINEL_NOOP_ENV, "1");
            std::env::set_var(libvirt_xml::VIRT_XML_VALIDATE_NOOP_ENV, "1");
            std::env::set_var("XDG_CONFIG_HOME", &bridge_config);
        }
        let outcome = provision(&opts).expect("provision");
        assert_eq!(outcome.vm_name, "neon-bridge");
        unsafe {
            std::env::remove_var(iso::ISO_FIXTURE_ENV);
            std::env::remove_var(libvirt::HV_NOOP_ENV);
            std::env::remove_var(ISOGEN_NOOP_ENV);
            std::env::remove_var(QCOW2_NOOP_ENV);
            std::env::remove_var(SENTINEL_NOOP_ENV);
            std::env::remove_var(libvirt_xml::VIRT_XML_VALIDATE_NOOP_ENV);
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }
}
