//! Hardware capability detection — V3-Phase B.
//!
//! Builds a [`BridgeCapabilities`] snapshot consumed by:
//!
//! * `neon doctor --bridge` — render capabilities + remediation.
//! * `crate::bridge::HardwareCapabilities::detect()` — V3 wizard input.
//! * `crate::bridge::remediation::remediation_for(...)` — actionable
//!   per-vendor advice keyed off the missing-capability shape.
//!
//! ## Design
//!
//! All probes go through a [`CapabilityRoots`] struct that hands tests
//! injectable filesystem roots (`/sys`, `/proc`, `/dev`, `$HOME`). The
//! [`detect_with`] entry point takes a `&CapabilityRoots`; tests
//! synthesize directory trees in `tempfile::TempDir` so they never touch
//! the real `/sys`. Same pattern as [`crate::migration::FsRoots`].
//!
//! Subprocess shell-outs (e.g. `system_profiler` on macOS) are gated by
//! `NEON_TEST_CAPS_NOOP=1`. When the env var is set the probes return
//! synthesized fixture data so tests are reproducible.
//!
//! ## What this module does NOT do
//!
//! * No remediation advice — that lives in [`crate::bridge::remediation`].
//! * No wire-up to the bridge VM — that's V3-Phase C.
//! * No subprocess execution beyond what's strictly necessary
//!   (`system_profiler` on macOS only).

use std::path::PathBuf;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(test)]
mod tests;

/// Env var that short-circuits subprocess shell-outs in capability
/// detection. Tests that don't want to invoke `system_profiler` etc. set
/// this to `1` and the probes return canned fixture data.
pub const NOOP_ENV: &str = "NEON_TEST_CAPS_NOOP";

/// Filesystem roots used by every Linux probe. Tests construct one
/// pointing at a `tempfile::TempDir` so they can synthesize a fake
/// `/sys` and assert the expected detections surface.
///
/// The trailing-underscore on `proc_` avoids the `proc` keyword.
#[derive(Debug, Clone)]
pub struct CapabilityRoots {
    /// `/sys` on the host; tests use a tempdir.
    pub sys: PathBuf,
    /// `/proc` on the host; tests use a tempdir.
    pub proc_: PathBuf,
    /// `/dev` on the host; tests use a tempdir.
    pub dev: PathBuf,
    /// `$HOME` on the host; tests pass `Some(tempdir)` or `None` to
    /// exercise the missing-home branch.
    pub home: Option<PathBuf>,
}

impl CapabilityRoots {
    /// Build the host-default roots from the real filesystem.
    #[must_use]
    pub fn host() -> Self {
        Self {
            sys: PathBuf::from("/sys"),
            proc_: PathBuf::from("/proc"),
            dev: PathBuf::from("/dev"),
            home: dirs::home_dir(),
        }
    }
}

/// TPM 2.0 (or equivalent) presence + version information.
///
/// V3-Phase B fills three states:
///
/// * `Present` — `/sys/class/tpm/tpm0/` exists with a parseable
///   `tpm_version_major`. Vendor is best-effort from the manufacturer
///   ID file.
/// * `Absent` — the device file doesn't exist on Linux, or
///   `system_profiler` on macOS reports neither Secure Enclave nor T2.
/// * `NotChecked` — the host doesn't expose a TPM probing surface
///   (e.g. running inside a VM that doesn't pass the TPM through).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TpmStatus {
    /// TPM 2.0 (or equivalent) is present and reachable.
    Present {
        /// Major version string (e.g. "2" for TPM 2.0).
        version: String,
        /// Manufacturer ID, when readable from sysfs.
        vendor: Option<String>,
    },
    /// No TPM detected on the host.
    Absent,
    /// Detection wasn't attempted (e.g. unsupported probing surface).
    NotChecked,
}

/// IOMMU enablement state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IommuStatus {
    /// IOMMU is enabled and groups are populated.
    Enabled {
        /// Vendor-specific IOMMU kind.
        kind: IommuKind,
    },
    /// IOMMU is supported by the CPU but not enabled in BIOS or kernel
    /// command line.
    Disabled,
    /// CPU does not support IOMMU at all.
    Absent,
}

/// IOMMU vendor kind. Detected from CPU vendor and kernel cmdline flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IommuKind {
    /// Intel VT-d.
    IntelVtD,
    /// AMD-Vi (also called IOMMU on AMD).
    AmdViO,
}

/// CPU virtualization extension state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VirtStatus {
    /// Virtualization extensions are exposed by the CPU and (where
    /// detectable) enabled in BIOS.
    Enabled {
        /// Vendor-specific kind.
        kind: VirtKind,
    },
    /// CPU has the virt feature flags but it appears to be disabled in
    /// BIOS — typically detectable on Linux when no IOMMU groups are
    /// populated despite `vmx`/`svm` being present.
    Disabled,
    /// CPU does not expose `vmx` or `svm` in `/proc/cpuinfo` flags.
    Absent,
}

/// CPU virtualization extension kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtKind {
    /// Intel VT-x (`vmx` flag in `/proc/cpuinfo`).
    VtX,
    /// AMD-V (`svm` flag in `/proc/cpuinfo`).
    AmdV,
}

/// GPU detection result. Carries zero-or-more discovered devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpuStatus {
    /// One or more GPUs were detected.
    Detected {
        /// Per-device snapshot. Order matches sysfs walk order.
        devices: Vec<GpuDevice>,
    },
    /// No GPU could be enumerated. Not all hosts have a discrete or
    /// integrated GPU mounted as a DRM card (e.g. headless servers or
    /// VMs without GPU passthrough).
    NotDetected,
}

/// Single discovered GPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuDevice {
    /// Vendor display name ("Intel", "NVIDIA", "AMD", "Apple", or
    /// "Unknown" with hex vendor ID).
    pub vendor: String,
    /// Device model string. Best-effort: PCI device ID hex on Linux,
    /// `system_profiler` model name on macOS.
    pub model: String,
    /// IOMMU group number on Linux. `None` on macOS (DART is
    /// always-on and not user-numbered).
    pub iommu_group: Option<u32>,
    /// `true` if the device's IOMMU group contains only the GPU itself
    /// (and any sibling `PCIe` bridges). False indicates the device is
    /// grouped with other functions and would need ACS-override or
    /// similar workarounds for VFIO.
    pub clean_isolation: bool,
    /// Best-effort indication that the device can drive an HDR display.
    /// Detected by looking for any `hdr_output_metadata` connector
    /// attribute under the card's DRM tree.
    pub hdr_capable: bool,
}

/// Kernel + module support snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelStatus {
    /// `uname -r` style kernel version string.
    pub version: String,
    /// `true` if the host shows signs of supporting the kvmfr module
    /// (Looking Glass shared-memory transport). Best-effort: looks under
    /// `/lib/modules/<ver>/extra/` and DKMS for any kvmfr listing.
    pub kvmfr_supported: bool,
}

/// Disk space at the bridge default location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskStatus {
    /// Free bytes at the bridge data path.
    pub free_bytes: u64,
    /// Mount point that backs the bridge data path.
    pub mountpoint: PathBuf,
}

/// RAM snapshot from `/proc/meminfo` (Linux) or `system_profiler` (macOS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RamStatus {
    /// Total physical RAM, in bytes.
    pub total_bytes: u64,
    /// Currently available RAM (Linux: `MemAvailable`).
    pub available_bytes: u64,
}

/// Display / session-type snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayStatus {
    /// Wayland, X11, or headless.
    pub session_type: SessionType,
    /// Best-effort: any DRM connector advertises HDR metadata.
    pub hdr_capable: bool,
}

/// Display session type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionType {
    /// Wayland session. `compositor` carries the desktop ID from
    /// `XDG_CURRENT_DESKTOP` when available.
    Wayland {
        /// Compositor name (e.g. "niri", "GNOME", "KDE").
        compositor: Option<String>,
    },
    /// Legacy X11 session.
    X11,
    /// No graphical session detected.
    Headless,
}

/// Top-level capability snapshot returned from [`detect`] / [`detect_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeCapabilities {
    /// TPM 2.0 (or Secure Enclave) state.
    pub tpm: TpmStatus,
    /// IOMMU state.
    pub iommu: IommuStatus,
    /// CPU virtualization extension state.
    pub virtualization: VirtStatus,
    /// GPU enumeration.
    pub gpu: GpuStatus,
    /// Kernel + module support.
    pub kernel: KernelStatus,
    /// Free disk at the bridge data path.
    pub disk: DiskStatus,
    /// System RAM.
    pub ram: RamStatus,
    /// Display / session type.
    pub display: DisplayStatus,
}

/// Detect host capabilities from real filesystem roots.
///
/// Equivalent to `detect_with(&CapabilityRoots::host())`.
#[must_use]
pub fn detect() -> BridgeCapabilities {
    detect_with(&CapabilityRoots::host())
}

/// Detect host capabilities against the given roots.
///
/// Tests use this to point detection at a tempdir tree.
#[must_use]
pub fn detect_with(roots: &CapabilityRoots) -> BridgeCapabilities {
    #[cfg(target_os = "linux")]
    {
        linux::detect_with(roots)
    }
    #[cfg(target_os = "macos")]
    {
        macos::detect_with(roots)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = roots;
        unsupported_capabilities()
    }
}

/// `true` if subprocess gating env var [`NOOP_ENV`] is set.
#[must_use]
pub fn noop_enabled() -> bool {
    std::env::var_os(NOOP_ENV).is_some()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(dead_code)]
fn unsupported_capabilities() -> BridgeCapabilities {
    BridgeCapabilities {
        tpm: TpmStatus::NotChecked,
        iommu: IommuStatus::Absent,
        virtualization: VirtStatus::Absent,
        gpu: GpuStatus::NotDetected,
        kernel: KernelStatus {
            version: String::from("unsupported"),
            kvmfr_supported: false,
        },
        disk: DiskStatus {
            free_bytes: 0,
            mountpoint: PathBuf::new(),
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
