//! Capability → remediation lookup table.
//!
//! When `neon doctor --bridge` finds a missing or disabled capability,
//! it asks this module for actionable advice. Output is shaped for both
//! human-readable rendering ([`RemediationStep::title`] +
//! [`RemediationStep::detail`]) and JSON consumption.
//!
//! Per-vendor tables (BIOS keys, dummy plug links) live here; we
//! deliberately bundle the most common 5-10 per vendor rather than ship
//! a giant database. If a user's vendor isn't covered, the message
//! degrades gracefully ("consult your motherboard manual").

use crate::platform::capabilities::{
    BridgeCapabilities, GpuStatus, IommuStatus, SessionType, TpmStatus, VirtStatus,
};

/// Categorized capability issue surfaced to the user.
///
/// Matches the shape of the missing/disabled fields in
/// [`BridgeCapabilities`]. The wizard walks the snapshot and emits an
/// `Issue` for each red item; [`remediation_for`] turns each issue into
/// a [`RemediationStep`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityIssue {
    /// TPM 2.0 not detected at all on the host.
    TpmAbsent,
    /// TPM 2.0 surface present but couldn't read version.
    TpmUnknownVersion,
    /// IOMMU disabled in BIOS or kernel command line.
    IommuDisabled,
    /// CPU doesn't support IOMMU (very old hosts).
    IommuAbsent,
    /// CPU virt extensions not present at all.
    VirtAbsent,
    /// CPU virt extensions present but disabled in BIOS.
    VirtDisabled,
    /// No GPU detected at all.
    GpuAbsent,
    /// GPU detected but not in a clean IOMMU group.
    GpuIsolationDirty,
    /// Disk free below the bridge minimum (60GB default).
    DiskTooSmall {
        /// Free bytes at the bridge data path.
        free_bytes: u64,
        /// Required minimum (60GB by default).
        required_bytes: u64,
    },
    /// RAM below recommended minimum (12GB).
    RamLow {
        /// Total physical RAM, bytes.
        total_bytes: u64,
        /// Recommended minimum (12GB).
        recommended_bytes: u64,
    },
    /// Single-GPU host that needs a dummy display plug for VFIO.
    NeedsDummyPlug,
}

/// Title + detail body for a remediation step.
#[derive(Debug, Clone)]
pub struct RemediationStep {
    /// Single-line summary (e.g. "Enable VT-d in BIOS").
    pub title: String,
    /// Multi-line body with vendor-specific guidance + links.
    pub detail: String,
}

impl RemediationStep {
    fn new(title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            detail: detail.into(),
        }
    }
}

/// Compute the [`CapabilityIssue`]s for a [`BridgeCapabilities`] snapshot.
///
/// Returns issues in display priority order — TPM/IOMMU/Virt are the
/// "hard" gates the bridge can't run without; disk + RAM are softer
/// (warnings).
#[must_use]
pub fn issues_for(caps: &BridgeCapabilities) -> Vec<CapabilityIssue> {
    let mut out = Vec::new();
    match &caps.tpm {
        TpmStatus::Absent => out.push(CapabilityIssue::TpmAbsent),
        TpmStatus::Present { version, .. } if version == "?" => {
            out.push(CapabilityIssue::TpmUnknownVersion);
        }
        _ => (),
    }
    match &caps.virtualization {
        VirtStatus::Absent => out.push(CapabilityIssue::VirtAbsent),
        VirtStatus::Disabled => out.push(CapabilityIssue::VirtDisabled),
        VirtStatus::Enabled { .. } => (),
    }
    match &caps.iommu {
        IommuStatus::Absent => out.push(CapabilityIssue::IommuAbsent),
        IommuStatus::Disabled => out.push(CapabilityIssue::IommuDisabled),
        IommuStatus::Enabled { .. } => (),
    }
    match &caps.gpu {
        GpuStatus::NotDetected => out.push(CapabilityIssue::GpuAbsent),
        GpuStatus::Detected { devices } => {
            // Single-GPU hosts where the GPU's IOMMU group isn't clean
            // benefit from a dummy plug on the second display output.
            if devices.len() == 1 && !devices[0].clean_isolation {
                out.push(CapabilityIssue::GpuIsolationDirty);
            }
            if devices.len() == 1 {
                out.push(CapabilityIssue::NeedsDummyPlug);
            }
        }
    }
    let required_disk: u64 = 60 * 1024 * 1024 * 1024;
    if caps.disk.free_bytes < required_disk {
        out.push(CapabilityIssue::DiskTooSmall {
            free_bytes: caps.disk.free_bytes,
            required_bytes: required_disk,
        });
    }
    let recommended_ram: u64 = 12 * 1024 * 1024 * 1024;
    if caps.ram.total_bytes > 0 && caps.ram.total_bytes < recommended_ram {
        out.push(CapabilityIssue::RamLow {
            total_bytes: caps.ram.total_bytes,
            recommended_bytes: recommended_ram,
        });
    }
    let _ = SessionType::Headless; // exhaustiveness reminder; not surfaced today
    out
}

/// Return the remediation step for a capability issue.
///
/// The output is deliberately specific — every red item in a doctor
/// run gets a concrete next step, not "consult your manufacturer's
/// manual". When we don't have a per-vendor table we fall back to a
/// generic body that still names the thing the user should look for.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn remediation_for(issue: &CapabilityIssue) -> RemediationStep {
    match issue {
        CapabilityIssue::TpmAbsent => RemediationStep::new(
            "Enable TPM 2.0 in your BIOS",
            format!(
                "Windows 11 IoT LTSC requires a TPM 2.0 device. Modern motherboards expose this \
                 as fTPM (AMD) or PTT (Intel). Reboot, enter BIOS, and look for one of the \
                 settings below for your vendor:\n\n{}\n\nAfter enabling, save and reboot. \
                 `neon doctor --bridge` should then report TPM as Present.",
                bios_keys_table()
            ),
        ),
        CapabilityIssue::TpmUnknownVersion => RemediationStep::new(
            "TPM detected, version uncertain",
            "A TPM device file exists but the kernel didn't expose its version major. \
             This sometimes happens on older kernels or with non-standard TPM drivers. \
             Run `cat /sys/class/tpm/tpm0/tpm_version_major` to see what your kernel reports; \
             if it's 2, the bridge will work."
                .to_string(),
        ),
        CapabilityIssue::IommuDisabled => RemediationStep::new(
            "Enable IOMMU in BIOS + kernel cmdline",
            format!(
                "IOMMU groups are not populated, but your CPU supports the feature. Two things \
                 to check:\n\n\
                 1. BIOS toggle (varies by vendor):\n{}\n\
                 2. Kernel boot parameter. Add `intel_iommu=on iommu=pt` (Intel) or `amd_iommu=on` (AMD) \
                 to `/etc/default/grub`'s GRUB_CMDLINE_LINUX_DEFAULT line, then run \
                 `sudo update-grub` (Debian/Ubuntu) or `sudo grub-mkconfig -o /boot/grub/grub.cfg` (Arch).",
                bios_keys_table()
            ),
        ),
        CapabilityIssue::IommuAbsent => RemediationStep::new(
            "CPU does not support IOMMU",
            "Your CPU does not expose virtualization or IOMMU instructions. The bridge requires \
             a host with VT-x/AMD-V and VT-d/AMD-Vi. Most CPUs from 2015 onward have this, but \
             very old or low-end CPUs may not. Consider running the bridge on a different host."
                .to_string(),
        ),
        CapabilityIssue::VirtAbsent => RemediationStep::new(
            "CPU virtualization extensions missing",
            "Your CPU does not expose `vmx` (Intel VT-x) or `svm` (AMD-V) flags in /proc/cpuinfo. \
             The bridge requires hardware virtualization. Without it, KVM cannot run a guest VM. \
             You will need a host with a more recent CPU."
                .to_string(),
        ),
        CapabilityIssue::VirtDisabled => RemediationStep::new(
            "Enable virtualization (VT-x / AMD-V) in BIOS",
            format!(
                "Your CPU has the virtualization feature but it appears to be disabled in BIOS. \
                 Reboot, enter BIOS, and toggle on virtualization for your vendor:\n\n{}",
                bios_keys_table()
            ),
        ),
        CapabilityIssue::GpuAbsent => RemediationStep::new(
            "No GPU detected",
            "No DRM card was found under /sys/class/drm. The bridge requires either a discrete \
             or integrated GPU available for VFIO passthrough. If you're on a server/headless \
             host this is expected; the bridge needs a physical GPU on the host."
                .to_string(),
        ),
        CapabilityIssue::GpuIsolationDirty => RemediationStep::new(
            "GPU is in a shared IOMMU group",
            "The GPU shares its IOMMU group with other devices. To pass it through to a guest, \
             you'll need either:\n\n\
             1. A motherboard with cleaner IOMMU groupings (most modern X570 / TRX40 / Z690 \
             boards qualify). Lookup your board's IOMMU groups at https://reddit.com/r/VFIO.\n\n\
             2. ACS Override patch on your kernel (proxmox-kernel ships with this; mainline does \
             not). This is a more involved workaround; consult /r/VFIO before attempting."
                .to_string(),
        ),
        CapabilityIssue::DiskTooSmall {
            free_bytes,
            required_bytes,
        } => RemediationStep::new(
            "Bridge data path needs more disk space",
            format!(
                "Bridge needs {:.1} GB free at the data path; {:.1} GB available. Either:\n\n\
                 1. Free disk space at ~/.local/share/neon/bridge/.\n\
                 2. Move the bridge data path by editing ~/.config/neon/bridge.toml:\n\n\
                 ```toml\n[bridge]\ndata_path = \"/mnt/external/neon-bridge\"\n```\n\n\
                 Restart `neon stream init` after the path change.",
                bytes_to_gib(*required_bytes),
                bytes_to_gib(*free_bytes)
            ),
        ),
        CapabilityIssue::RamLow {
            total_bytes,
            recommended_bytes,
        } => RemediationStep::new(
            "Host RAM below recommended minimum",
            format!(
                "Total RAM: {:.1} GB; recommended {:.1} GB. The bridge will still run but the \
                 guest will be limited to a smaller allocation, which may cause Edge to swap during \
                 streaming. Close other applications during streaming for the best experience.",
                bytes_to_gib(*total_bytes),
                bytes_to_gib(*recommended_bytes)
            ),
        ),
        CapabilityIssue::NeedsDummyPlug => RemediationStep::new(
            "Single-GPU host: dummy display plug recommended",
            "On a single-GPU host the GPU is in use by the desktop session. Once it's passed \
             through to the guest, the host loses display output and Looking Glass needs a \
             second display surface to work cleanly.\n\n\
             Recommended fix: a $5 4K HDMI dummy plug. Search Amazon for \"4K HDMI Display \
             Emulator Dummy Plug 4096x2160\" or pick this commonly-tested model:\n\n\
             https://www.amazon.com/dp/B07YFF3JGL  (4K@60Hz HDMI Dummy Plug)\n\n\
             Plug it into a free port on your GPU; the bridge will use that connector for \
             Looking Glass output. (When Looking Glass IDD-host ships upstream this won't be \
             needed.)"
                .to_string(),
        ),
    }
}

#[allow(clippy::cast_precision_loss)]
fn bytes_to_gib(b: u64) -> f64 {
    b as f64 / (1024.0 * 1024.0 * 1024.0)
}

/// Hardcoded BIOS-key table for common motherboard / OEM vendors.
///
/// Bundling this directly avoids shipping a 50-vendor lookup; the
/// most-common 9 cover ~95% of users.
fn bios_keys_table() -> String {
    let entries: &[(&str, &str)] = &[
        (
            "ASUS",
            "F2 / Delete on boot. Look under Advanced > CPU Configuration for \
             SVM/Intel VT, and Advanced > AMD CBS or System Agent for IOMMU.",
        ),
        (
            "Gigabyte",
            "Delete on boot. BIOS Features > AMD CBS / Intel CPU > SVM Mode + IOMMU.",
        ),
        (
            "MSI",
            "Delete on boot. OC > CPU Features > SVM Mode (AMD) or VT-d (Intel).",
        ),
        (
            "ASRock",
            "F2 / Delete on boot. Advanced > CPU Configuration > SVM Mode + IOMMU.",
        ),
        (
            "Lenovo (ThinkPad / desktop)",
            "F1 (laptops) / Enter (desktops) on boot. Security > Virtualization > both \
             Intel(R) VT and Intel(R) VT-d Feature.",
        ),
        (
            "Dell (XPS / Precision / OptiPlex)",
            "F2 on boot. Settings > Virtualization Support > Virtualization + VT for Direct I/O.",
        ),
        (
            "HP (Pavilion / EliteBook / Z workstation)",
            "Esc then F10 on boot. Security > System Security > VTx + VTd.",
        ),
        (
            "Apple (Mac running Linux via boot loader)",
            "Apple Macs running Linux do not have a user-accessible BIOS in the traditional \
             sense; virtualization is always on. The bridge's macOS path uses Parallels / UTM \
             (`neon doctor --bridge` reports macOS specifics).",
        ),
        (
            "Framework Laptop",
            "F2 on boot. Advanced > CPU Configuration > Intel(R) VT for Directed I/O.",
        ),
    ];
    let mut buf = String::new();
    for (vendor, body) in entries {
        buf.push_str("  - ");
        buf.push_str(vendor);
        buf.push_str(": ");
        buf.push_str(body);
        buf.push('\n');
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::capabilities::{
        DiskStatus, DisplayStatus, GpuDevice, IommuKind, KernelStatus, RamStatus, SessionType,
        VirtKind,
    };

    fn caps_with(
        tpm: TpmStatus,
        iommu: IommuStatus,
        virt: VirtStatus,
        gpu: GpuStatus,
        disk_free: u64,
        ram_total: u64,
    ) -> BridgeCapabilities {
        BridgeCapabilities {
            tpm,
            iommu,
            virtualization: virt,
            gpu,
            kernel: KernelStatus {
                version: "6.6.0".into(),
                kvmfr_supported: false,
            },
            disk: DiskStatus {
                free_bytes: disk_free,
                mountpoint: "/tmp".into(),
            },
            ram: RamStatus {
                total_bytes: ram_total,
                available_bytes: 0,
            },
            display: DisplayStatus {
                session_type: SessionType::Headless,
                hdr_capable: false,
            },
        }
    }

    fn one_clean_gpu() -> GpuStatus {
        GpuStatus::Detected {
            devices: vec![GpuDevice {
                vendor: "AMD".into(),
                model: "0x1002:0x1234".into(),
                iommu_group: Some(21),
                clean_isolation: true,
                hdr_capable: true,
            }],
        }
    }

    fn dual_gpu() -> GpuStatus {
        GpuStatus::Detected {
            devices: vec![
                GpuDevice {
                    vendor: "Intel".into(),
                    model: "0x8086:0x1234".into(),
                    iommu_group: Some(0),
                    clean_isolation: true,
                    hdr_capable: false,
                },
                GpuDevice {
                    vendor: "NVIDIA".into(),
                    model: "0x10de:0x1234".into(),
                    iommu_group: Some(21),
                    clean_isolation: true,
                    hdr_capable: true,
                },
            ],
        }
    }

    #[test]
    fn issues_clean_dual_gpu_has_no_hardware_blockers() {
        let caps = caps_with(
            TpmStatus::Present {
                version: "2".into(),
                vendor: Some("STM".into()),
            },
            IommuStatus::Enabled {
                kind: IommuKind::IntelVtD,
            },
            VirtStatus::Enabled {
                kind: VirtKind::VtX,
            },
            dual_gpu(),
            100u64 * 1024 * 1024 * 1024, // 100GB
            32u64 * 1024 * 1024 * 1024,  // 32GB
        );
        let i = issues_for(&caps);
        assert!(
            i.is_empty(),
            "clean dual-GPU host should have no issues: {i:?}"
        );
    }

    #[test]
    fn issues_tpm_absent_surfaces() {
        let caps = caps_with(
            TpmStatus::Absent,
            IommuStatus::Enabled {
                kind: IommuKind::IntelVtD,
            },
            VirtStatus::Enabled {
                kind: VirtKind::VtX,
            },
            dual_gpu(),
            100u64 * 1024 * 1024 * 1024,
            32u64 * 1024 * 1024 * 1024,
        );
        let i = issues_for(&caps);
        assert!(i.contains(&CapabilityIssue::TpmAbsent));
    }

    #[test]
    fn issues_single_gpu_emits_dummy_plug_advice() {
        let caps = caps_with(
            TpmStatus::Present {
                version: "2".into(),
                vendor: None,
            },
            IommuStatus::Enabled {
                kind: IommuKind::AmdViO,
            },
            VirtStatus::Enabled {
                kind: VirtKind::AmdV,
            },
            one_clean_gpu(),
            200u64 * 1024 * 1024 * 1024,
            64u64 * 1024 * 1024 * 1024,
        );
        let i = issues_for(&caps);
        assert!(i.contains(&CapabilityIssue::NeedsDummyPlug));
    }

    #[test]
    fn issues_disk_too_small_surfaces_with_thresholds() {
        let caps = caps_with(
            TpmStatus::Present {
                version: "2".into(),
                vendor: None,
            },
            IommuStatus::Enabled {
                kind: IommuKind::IntelVtD,
            },
            VirtStatus::Enabled {
                kind: VirtKind::VtX,
            },
            dual_gpu(),
            10u64 * 1024 * 1024 * 1024, // 10GB only
            32u64 * 1024 * 1024 * 1024,
        );
        let i = issues_for(&caps);
        assert!(i
            .iter()
            .any(|x| matches!(x, CapabilityIssue::DiskTooSmall { .. })));
    }

    #[test]
    fn issues_ram_low_surfaces_below_threshold() {
        let caps = caps_with(
            TpmStatus::Present {
                version: "2".into(),
                vendor: None,
            },
            IommuStatus::Enabled {
                kind: IommuKind::IntelVtD,
            },
            VirtStatus::Enabled {
                kind: VirtKind::VtX,
            },
            dual_gpu(),
            100u64 * 1024 * 1024 * 1024,
            8u64 * 1024 * 1024 * 1024, // 8GB < 12 recommended
        );
        let i = issues_for(&caps);
        assert!(i
            .iter()
            .any(|x| matches!(x, CapabilityIssue::RamLow { .. })));
    }

    #[test]
    fn issues_iommu_disabled_when_present_but_no_groups() {
        let caps = caps_with(
            TpmStatus::Present {
                version: "2".into(),
                vendor: None,
            },
            IommuStatus::Disabled,
            VirtStatus::Enabled {
                kind: VirtKind::VtX,
            },
            dual_gpu(),
            100u64 * 1024 * 1024 * 1024,
            32u64 * 1024 * 1024 * 1024,
        );
        let i = issues_for(&caps);
        assert!(i.contains(&CapabilityIssue::IommuDisabled));
    }

    #[test]
    fn remediation_messages_are_actionable() {
        let cases = [
            CapabilityIssue::TpmAbsent,
            CapabilityIssue::TpmUnknownVersion,
            CapabilityIssue::IommuDisabled,
            CapabilityIssue::IommuAbsent,
            CapabilityIssue::VirtAbsent,
            CapabilityIssue::VirtDisabled,
            CapabilityIssue::GpuAbsent,
            CapabilityIssue::GpuIsolationDirty,
            CapabilityIssue::NeedsDummyPlug,
            CapabilityIssue::DiskTooSmall {
                free_bytes: 0,
                required_bytes: 60u64 * 1024 * 1024 * 1024,
            },
            CapabilityIssue::RamLow {
                total_bytes: 0,
                recommended_bytes: 12u64 * 1024 * 1024 * 1024,
            },
        ];
        for issue in cases {
            let r = remediation_for(&issue);
            assert!(!r.title.is_empty(), "issue {issue:?} title empty");
            assert!(!r.detail.is_empty(), "issue {issue:?} detail empty");
            // Sanity: detail should be more than just the title.
            assert!(r.detail.len() > r.title.len());
        }
    }

    #[test]
    fn bios_keys_table_lists_common_vendors() {
        let table = bios_keys_table();
        for vendor in &[
            "ASUS",
            "Gigabyte",
            "MSI",
            "ASRock",
            "Lenovo",
            "Dell",
            "HP",
            "Framework",
        ] {
            assert!(
                table.contains(vendor),
                "BIOS-key table should mention {vendor}"
            );
        }
    }

    #[test]
    fn dummy_plug_message_includes_amazon_link() {
        let r = remediation_for(&CapabilityIssue::NeedsDummyPlug);
        assert!(r.detail.contains("amazon.com"));
        assert!(r.detail.contains("4K"));
    }

    #[test]
    fn iommu_remediation_lists_grub_command() {
        let r = remediation_for(&CapabilityIssue::IommuDisabled);
        assert!(r.detail.contains("intel_iommu=on"));
        assert!(r.detail.contains("amd_iommu=on"));
        assert!(r.detail.contains("update-grub") || r.detail.contains("grub-mkconfig"));
    }
}
