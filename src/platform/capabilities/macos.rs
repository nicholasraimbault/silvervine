//! macOS-specific capability probes.
//!
//! macOS V3 path is much smaller than Linux:
//!
//! * No QEMU/libvirt. Users are expected to use Parallels Desktop or UTM
//!   for the Windows guest; `neon doctor --bridge` reports capability
//!   and points them at that flow.
//! * TPM-equivalent → Apple Silicon Secure Enclave (or T2 chip on Intel
//!   Macs from 2018+).
//! * IOMMU → Apple's DART is always on; report Enabled with a vendor
//!   marker the wizard treats as "not user-configurable".
//! * GPU → `system_profiler SPDisplaysDataType -json`.
//! * Virt → `sysctl machdep.cpu.features` / `sysctl hw.optional.arm.FEAT_*`.
//!
//! All shell-outs are gated by `NEON_TEST_CAPS_NOOP=1` returning canned
//! fixture data — production runs would otherwise fork `system_profiler`
//! and `sysctl`. CI invocations and tests leave the env var set.

use std::path::PathBuf;
use std::process::Command;

use serde::Deserialize;

use super::{
    BridgeCapabilities, CapabilityRoots, DiskStatus, DisplayStatus, GpuDevice, GpuStatus,
    IommuKind, IommuStatus, KernelStatus, RamStatus, SessionType, TpmStatus, VirtKind, VirtStatus,
};

/// macOS entry point — composes per-capability probes.
#[must_use]
pub fn detect_with(roots: &CapabilityRoots) -> BridgeCapabilities {
    let hardware = system_profiler_hardware();
    let displays = system_profiler_displays();
    BridgeCapabilities {
        tpm: detect_secure_enclave(&hardware),
        iommu: detect_iommu_macos(),
        virtualization: detect_virt_macos(&hardware),
        gpu: detect_gpu_macos(&displays),
        kernel: detect_kernel_macos(),
        disk: detect_disk_macos(roots),
        ram: detect_ram_macos(&hardware),
        display: detect_display_macos(&displays),
    }
}

/* ------------------------ system_profiler --------------------------- */

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct HardwareReport {
    #[serde(rename = "SPHardwareDataType", default)]
    pub hardware: Vec<HardwareItem>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct HardwareItem {
    #[serde(default)]
    pub chip_type: Option<String>,
    #[serde(default)]
    pub cpu_type: Option<String>,
    #[serde(default)]
    pub machine_model: Option<String>,
    #[serde(default)]
    pub physical_memory: Option<String>,
    #[serde(default, rename = "platform_UUID")]
    pub platform_uuid: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct DisplaysReport {
    #[serde(rename = "SPDisplaysDataType", default)]
    pub gpus: Vec<DisplayItem>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct DisplayItem {
    #[serde(rename = "_name", default)]
    pub name: Option<String>,
    #[serde(default)]
    pub sppci_model: Option<String>,
    #[serde(default)]
    pub spdisplays_vendor: Option<String>,
    #[serde(default, rename = "spdisplays_ndrvs")]
    pub displays: Vec<ConnectedDisplay>,
}

#[derive(Deserialize, Debug, Clone, Default)]
pub(super) struct ConnectedDisplay {
    #[serde(default)]
    pub spdisplays_display_type: Option<String>,
    #[serde(default)]
    pub spdisplays_pixels: Option<String>,
}

/// Run `system_profiler SPHardwareDataType -json`. When the noop env var
/// is set, return an empty default. The fixture-driven tests parse a
/// committed JSON file at `tests/fixtures/macos_system_profiler.json`
/// independently; this function is the *runtime* path only.
pub(super) fn system_profiler_hardware() -> HardwareReport {
    if super::noop_enabled() {
        return HardwareReport::default();
    }
    let out = Command::new("system_profiler")
        .args(["SPHardwareDataType", "-json"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            serde_json::from_slice::<HardwareReport>(&o.stdout).unwrap_or_default()
        }
        _ => HardwareReport::default(),
    }
}

pub(super) fn system_profiler_displays() -> DisplaysReport {
    if super::noop_enabled() {
        return DisplaysReport::default();
    }
    let out = Command::new("system_profiler")
        .args(["SPDisplaysDataType", "-json"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            serde_json::from_slice::<DisplaysReport>(&o.stdout).unwrap_or_default()
        }
        _ => DisplaysReport::default(),
    }
}

/* ------------------------- per-capability --------------------------- */

#[must_use]
pub(super) fn detect_secure_enclave(hardware: &HardwareReport) -> TpmStatus {
    let Some(item) = hardware.hardware.first() else {
        return TpmStatus::NotChecked;
    };
    if let Some(chip) = &item.chip_type {
        // Apple Silicon: chip_type starts with "Apple M".
        if chip.starts_with("Apple M") {
            return TpmStatus::Present {
                version: String::from("SecureEnclave (Apple Silicon)"),
                vendor: Some(chip.clone()),
            };
        }
    }
    if let Some(model) = &item.machine_model {
        // Intel Macs from 2018+ ship the T2 security chip. Models like
        // "MacBookPro15,1" through "MacPro7,1". Best-effort: look for
        // newer machine_model identifiers.
        let known_t2 = ["MacBookPro15", "MacBookPro16", "MacBookAir9", "MacPro7"];
        if known_t2.iter().any(|p| model.starts_with(p)) {
            return TpmStatus::Present {
                version: String::from("T2 Security Chip"),
                vendor: Some(String::from("Apple T2")),
            };
        }
    }
    TpmStatus::Absent
}

#[must_use]
pub(super) fn detect_iommu_macos() -> IommuStatus {
    // DART (Device Address Resolution Table) is always on. Surface the
    // appropriate vendor kind based on architecture.
    if cfg!(target_arch = "aarch64") {
        IommuStatus::Enabled {
            kind: IommuKind::AmdViO,
        } // arbitrary; treat
          // as a marker. The wizard uses this only to know "yes, IOMMU
          // available" — it doesn't differentiate Apple from x86.
    } else {
        IommuStatus::Enabled {
            kind: IommuKind::IntelVtD,
        }
    }
}

#[must_use]
pub(super) fn detect_virt_macos(hardware: &HardwareReport) -> VirtStatus {
    let Some(item) = hardware.hardware.first() else {
        return VirtStatus::Absent;
    };
    if item
        .chip_type
        .as_deref()
        .is_some_and(|c| c.starts_with("Apple M"))
    {
        // Apple Silicon supports virtualization (Apple Hypervisor Framework).
        return VirtStatus::Enabled {
            kind: VirtKind::AmdV,
        };
    }
    if let Some(cpu) = &item.cpu_type {
        if cpu.contains("Intel") {
            // Intel Macs all support VT-x.
            return VirtStatus::Enabled {
                kind: VirtKind::VtX,
            };
        }
    }
    VirtStatus::Absent
}

#[must_use]
pub(super) fn detect_gpu_macos(displays: &DisplaysReport) -> GpuStatus {
    let mut devices: Vec<GpuDevice> = Vec::new();
    for gpu in &displays.gpus {
        let vendor = gpu
            .spdisplays_vendor
            .clone()
            .unwrap_or_else(|| String::from("Apple"));
        let model = gpu
            .sppci_model
            .clone()
            .or_else(|| gpu.name.clone())
            .unwrap_or_else(|| String::from("Unknown GPU"));
        let hdr_capable = gpu.displays.iter().any(|d| {
            let t = d.spdisplays_display_type.as_deref().unwrap_or("");
            t.contains("Reference") || t.contains("HDR")
        });
        devices.push(GpuDevice {
            vendor: humanize_vendor(&vendor),
            model,
            iommu_group: None,
            clean_isolation: true, // DART always isolates devices.
            hdr_capable,
        });
    }
    if devices.is_empty() {
        GpuStatus::NotDetected
    } else {
        GpuStatus::Detected { devices }
    }
}

fn humanize_vendor(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("apple") {
        "Apple".to_string()
    } else if lower.contains("intel") {
        "Intel".to_string()
    } else if lower.contains("amd") || lower.contains("ati") {
        "AMD".to_string()
    } else if lower.contains("nvidia") {
        "NVIDIA".to_string()
    } else {
        raw.to_string()
    }
}

#[must_use]
pub(super) fn detect_kernel_macos() -> KernelStatus {
    let version = if super::noop_enabled() {
        String::from("23.0.0")
    } else {
        let out = Command::new("uname").arg("-r").output();
        match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => String::from("unknown"),
        }
    };
    KernelStatus {
        version,
        kvmfr_supported: false, // No kvmfr on macOS — Looking Glass not used.
    }
}

#[must_use]
pub(super) fn detect_disk_macos(roots: &CapabilityRoots) -> DiskStatus {
    let path = roots
        .home
        .as_ref()
        .map(|h| h.join(".local/share/neon/bridge"))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    DiskStatus {
        free_bytes: 0, // statvfs would need a real path; defer to wizard.
        mountpoint: path,
    }
}

#[must_use]
pub(super) fn detect_ram_macos(hardware: &HardwareReport) -> RamStatus {
    let Some(item) = hardware.hardware.first() else {
        return RamStatus {
            total_bytes: 0,
            available_bytes: 0,
        };
    };
    let total_bytes = item
        .physical_memory
        .as_deref()
        .and_then(parse_macos_memory)
        .unwrap_or(0);
    RamStatus {
        total_bytes,
        // macOS doesn't expose MemAvailable easily; defer to the wizard.
        available_bytes: 0,
    }
}

/// Parse macOS `system_profiler` memory strings like "32 GB" or "16 GB".
pub(super) fn parse_macos_memory(s: &str) -> Option<u64> {
    let mut parts = s.split_whitespace();
    let value: f64 = parts.next()?.parse().ok()?;
    let unit = parts.next()?.to_ascii_lowercase();
    let bytes = match unit.as_str() {
        "kb" => value * 1024.0,
        "mb" => value * 1024.0 * 1024.0,
        "gb" => value * 1024.0 * 1024.0 * 1024.0,
        "tb" => value * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some(bytes as u64)
}

#[must_use]
pub(super) fn detect_display_macos(displays: &DisplaysReport) -> DisplayStatus {
    let hdr_capable = displays
        .gpus
        .iter()
        .flat_map(|g| g.displays.iter())
        .any(|d| {
            let t = d.spdisplays_display_type.as_deref().unwrap_or("");
            t.contains("Reference") || t.contains("HDR")
        });
    DisplayStatus {
        // macOS is always Cocoa; report as Wayland-like with the desktop
        // marker "macOS". Downstream consumers branch on the variant
        // discriminant only; the compositor string is informational.
        session_type: SessionType::Wayland {
            compositor: Some(String::from("macOS")),
        },
        hdr_capable,
    }
}
