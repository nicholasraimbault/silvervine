//! Single-GPU IDD fallback detection — V3-Phase D.
//!
//! On a single-GPU host, the GPU is in use by the running desktop
//! session. Once the bridge passes the GPU through to the guest, the
//! host loses display output and Looking Glass (running on the host)
//! has no surface to render to. The fix is one of:
//!
//! 1. **A second GPU.** The host keeps its iGPU/secondary while the
//!    guest gets the dGPU. Common on desktops with both an iGPU + dGPU,
//!    or on workstations with two `PCIe` GPUs.
//! 2. **A dummy display plug.** A $5 HDMI/DP plug that emulates a
//!    monitor (EDID payload). Tricks the OS into thinking a second
//!    display exists; LG can then render to that virtual head.
//! 3. **Looking Glass IDD-host** (Indirect Display Driver). Replaces
//!    (2) with a software solution; ships in upcoming LG releases. As
//!    of B7 it's not yet available; the dummy plug is the workaround.
//!
//! [`detect`] inspects the [`crate::platform::capabilities::BridgeCapabilities`]
//! snapshot + the host's `/sys/class/drm/<output>/status` files to
//! decide which of the three states the user is in:
//!
//! * [`IddFallbackStatus::NotRequired`] — the host has 2+ GPUs (or 1 GPU
//!   with 2+ already-connected outputs, e.g. someone plugged in a real
//!   second monitor + dummy plug already).
//! * [`IddFallbackStatus::DummyPlugRequired`] — single GPU, single
//!   connected output → user buys a dummy plug.
//! * [`IddFallbackStatus::IddHostAvailable`] — Looking Glass IDD-host
//!   detected (forward-compat for V3.x once upstream ships it).

use std::path::{Path, PathBuf};

use crate::platform::capabilities::{BridgeCapabilities, GpuStatus};

/// Known-good 4K HDMI dummy plug Amazon listing.
///
/// Format: 4K@60Hz HDMI Display Emulator Dummy Plug. This is the same
/// listing surfaced in [`crate::bridge::remediation`]'s `NeedsDummyPlug`
/// detail body — keeping them in lockstep means the user sees the same
/// link from two surfaces (capability gate + IDD fallback).
pub const DUMMY_PLUG_SHOPPING_LINK: &str = "https://www.amazon.com/dp/B07YFF3JGL";

/// Detection result — what kind of secondary surface the host has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IddFallbackStatus {
    /// Host has a usable secondary display surface (2+ GPUs, or
    /// multiple connected outputs).
    NotRequired,
    /// Single-GPU host with no second connected output → user needs
    /// a dummy plug.
    DummyPlugRequired {
        /// Human-readable reason explaining the detection result.
        reason: String,
        /// Hardcoded shopping link (same as the BIOS-table
        /// remediation).
        shopping_link: &'static str,
    },
    /// Forward-compat: Looking Glass IDD-host driver was detected.
    /// V3.0 always returns `NotRequired` or `DummyPlugRequired`; this
    /// variant exists so V3.x can surface it without a breaking change.
    IddHostAvailable,
}

impl IddFallbackStatus {
    /// `true` if we don't need a dummy plug (either real second
    /// surface or IDD-host).
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        matches!(self, Self::NotRequired | Self::IddHostAvailable)
    }

    /// Human-readable shopping link for the dummy-plug variant.
    /// Returns `None` for the other variants.
    #[must_use]
    pub fn shopping_link(&self) -> Option<&'static str> {
        match self {
            Self::DummyPlugRequired { shopping_link, .. } => Some(shopping_link),
            _ => None,
        }
    }
}

/// Decide whether the host needs a dummy plug.
///
/// Inputs:
/// * `caps.gpu` — number of GPUs on the host (multi-GPU hosts pass
///   trivially).
/// * `/sys/class/drm/<output>/status` — count of *currently-connected*
///   display outputs. Real monitor counts; dummy plug counts;
///   disconnected ports don't.
///
/// Single GPU + single connected output → dummy plug recommended.
#[must_use]
pub fn detect(caps: &BridgeCapabilities) -> IddFallbackStatus {
    detect_with(caps, Path::new("/sys/class/drm"))
}

/// Decide using a custom DRM root. Tests synthesize `/sys/class/drm`
/// trees in a tempdir and pass the path here.
#[must_use]
pub fn detect_with(caps: &BridgeCapabilities, drm_root: &Path) -> IddFallbackStatus {
    let gpu_count = match &caps.gpu {
        GpuStatus::Detected { devices } => devices.len(),
        GpuStatus::NotDetected => 0,
    };

    // Multi-GPU host: never need a dummy plug. The bridge passes one
    // GPU through; host keeps the other.
    if gpu_count >= 2 {
        return IddFallbackStatus::NotRequired;
    }

    let connected = count_connected_outputs(drm_root);

    // Single-GPU host with 2+ connected outputs (real monitor + dummy
    // plug already, or dual-monitor setup). The user is already covered.
    if gpu_count == 1 && connected >= 2 {
        return IddFallbackStatus::NotRequired;
    }

    // Single GPU + zero or one output — needs a dummy plug. The reason
    // varies slightly based on whether we counted any output at all.
    let reason = if gpu_count == 0 {
        "no GPU detected on the host (this is unusual; see capability \
         remediation)"
            .to_string()
    } else if connected == 0 {
        "single GPU with no currently-connected display outputs".to_string()
    } else {
        "single GPU with one currently-connected display output. \
         Once the GPU is passed through to the guest, the host has no \
         remaining display surface for Looking Glass to render to."
            .to_string()
    };

    IddFallbackStatus::DummyPlugRequired {
        reason,
        shopping_link: DUMMY_PLUG_SHOPPING_LINK,
    }
}

/// Walk `/sys/class/drm/<output>/status`, count entries that read
/// `connected\n`. Best-effort: missing root or unreadable files
/// contribute 0.
fn count_connected_outputs(drm_root: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(drm_root) else {
        return 0;
    };
    let mut count = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // `card0` is a parent directory; the per-output entries are
        // named like `card0-HDMI-A-1`, `card0-DP-1`, `card1-eDP-1`.
        if !name.contains('-') {
            continue;
        }
        let status_path: PathBuf = path.join("status");
        let Ok(s) = std::fs::read_to_string(&status_path) else {
            continue;
        };
        if s.trim() == "connected" {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::capabilities::{
        DiskStatus, DisplayStatus, GpuDevice, IommuKind, IommuStatus, KernelStatus, RamStatus,
        SessionType, TpmStatus, VirtKind, VirtStatus,
    };
    use tempfile::TempDir;

    fn caps_with_gpu(gpu: GpuStatus) -> BridgeCapabilities {
        BridgeCapabilities {
            tpm: TpmStatus::Present {
                version: "2".into(),
                vendor: None,
            },
            iommu: IommuStatus::Enabled {
                kind: IommuKind::IntelVtD,
            },
            virtualization: VirtStatus::Enabled {
                kind: VirtKind::VtX,
            },
            gpu,
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
                available_bytes: 16u64 * 1024 * 1024 * 1024,
            },
            display: DisplayStatus {
                session_type: SessionType::Headless,
                hdr_capable: false,
            },
        }
    }

    fn one_gpu() -> GpuStatus {
        GpuStatus::Detected {
            devices: vec![GpuDevice {
                vendor: "AMD".into(),
                model: "0x1002:0xabcd".into(),
                iommu_group: Some(21),
                clean_isolation: true,
                hdr_capable: true,
            }],
        }
    }

    fn two_gpus() -> GpuStatus {
        GpuStatus::Detected {
            devices: vec![
                GpuDevice {
                    vendor: "Intel".into(),
                    model: "iGPU".into(),
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

    /// Synthesize a `/sys/class/drm` tree with the given outputs.
    /// Each entry is a tuple of (`output_name`, `status_value`).
    fn synth_drm_tree(tmp: &Path, outputs: &[(&str, &str)]) -> PathBuf {
        let drm = tmp.join("sys/class/drm");
        std::fs::create_dir_all(&drm).expect("mkdir drm");
        for (name, status) in outputs {
            let dir = drm.join(name);
            std::fs::create_dir_all(&dir).expect("mkdir output");
            std::fs::write(dir.join("status"), status).expect("write status");
        }
        // Add a `card0` parent dir (name has no hyphen → skipped).
        std::fs::create_dir_all(drm.join("card0")).expect("mkdir card0");
        drm
    }

    #[test]
    fn dual_gpu_host_does_not_need_dummy_plug() {
        let tmp = TempDir::new().expect("tempdir");
        let drm = synth_drm_tree(
            tmp.path(),
            &[("card0-eDP-1", "connected"), ("card1-DP-1", "disconnected")],
        );
        let caps = caps_with_gpu(two_gpus());
        let status = detect_with(&caps, &drm);
        assert_eq!(status, IddFallbackStatus::NotRequired);
    }

    #[test]
    fn single_gpu_with_two_connected_outputs_does_not_need_dummy_plug() {
        let tmp = TempDir::new().expect("tempdir");
        let drm = synth_drm_tree(
            tmp.path(),
            &[("card0-HDMI-A-1", "connected"), ("card0-DP-1", "connected")],
        );
        let caps = caps_with_gpu(one_gpu());
        let status = detect_with(&caps, &drm);
        assert_eq!(status, IddFallbackStatus::NotRequired);
    }

    #[test]
    fn single_gpu_with_one_connected_output_needs_dummy_plug() {
        let tmp = TempDir::new().expect("tempdir");
        let drm = synth_drm_tree(
            tmp.path(),
            &[
                ("card0-eDP-1", "connected"),
                ("card0-HDMI-A-1", "disconnected"),
                ("card0-DP-1", "disconnected"),
            ],
        );
        let caps = caps_with_gpu(one_gpu());
        let status = detect_with(&caps, &drm);
        match status {
            IddFallbackStatus::DummyPlugRequired {
                reason,
                shopping_link,
            } => {
                assert!(reason.to_lowercase().contains("single gpu"));
                assert_eq!(shopping_link, DUMMY_PLUG_SHOPPING_LINK);
            }
            other => panic!("expected DummyPlugRequired, got {other:?}"),
        }
    }

    #[test]
    fn single_gpu_with_zero_outputs_needs_dummy_plug() {
        let tmp = TempDir::new().expect("tempdir");
        let drm = synth_drm_tree(tmp.path(), &[]);
        let caps = caps_with_gpu(one_gpu());
        let status = detect_with(&caps, &drm);
        match status {
            IddFallbackStatus::DummyPlugRequired { reason, .. } => {
                assert!(reason.contains("no currently-connected"));
            }
            other => panic!("expected DummyPlugRequired, got {other:?}"),
        }
    }

    #[test]
    fn no_gpu_detected_returns_dummy_plug_required_with_specific_reason() {
        let tmp = TempDir::new().expect("tempdir");
        let drm = synth_drm_tree(tmp.path(), &[]);
        let caps = caps_with_gpu(GpuStatus::NotDetected);
        let status = detect_with(&caps, &drm);
        match status {
            IddFallbackStatus::DummyPlugRequired { reason, .. } => {
                assert!(reason.contains("no GPU"));
            }
            other => panic!("expected DummyPlugRequired, got {other:?}"),
        }
    }

    #[test]
    fn missing_drm_root_treated_as_zero_outputs() {
        let tmp = TempDir::new().expect("tempdir");
        let bogus = tmp.path().join("nope/sys/class/drm");
        let caps = caps_with_gpu(one_gpu());
        let status = detect_with(&caps, &bogus);
        // No DRM, single GPU → still need dummy plug (we report
        // "no currently-connected" reason since count is 0).
        assert!(matches!(
            status,
            IddFallbackStatus::DummyPlugRequired { .. }
        ));
    }

    #[test]
    fn count_connected_skips_card_parent_entry() {
        let tmp = TempDir::new().expect("tempdir");
        let drm = synth_drm_tree(
            tmp.path(),
            &[
                ("card0-HDMI-A-1", "connected"),
                ("card0-DP-1", "disconnected"),
            ],
        );
        // Sanity: only the connected one should count.
        assert_eq!(count_connected_outputs(&drm), 1);
    }

    #[test]
    fn count_connected_handles_unreadable_status_file() {
        let tmp = TempDir::new().expect("tempdir");
        let drm = tmp.path().join("sys/class/drm");
        let dir = drm.join("card0-DP-1");
        std::fs::create_dir_all(&dir).expect("mkdir output");
        // No status file.
        assert_eq!(count_connected_outputs(&drm), 0);
    }

    #[test]
    fn count_connected_skips_status_with_unknown_value() {
        let tmp = TempDir::new().expect("tempdir");
        let drm = synth_drm_tree(tmp.path(), &[("card0-DP-1", "unknown")]);
        assert_eq!(count_connected_outputs(&drm), 0);
    }

    #[test]
    fn idd_fallback_status_is_satisfied_predicates() {
        assert!(IddFallbackStatus::NotRequired.is_satisfied());
        assert!(IddFallbackStatus::IddHostAvailable.is_satisfied());
        assert!(!IddFallbackStatus::DummyPlugRequired {
            reason: "x".into(),
            shopping_link: DUMMY_PLUG_SHOPPING_LINK,
        }
        .is_satisfied());
    }

    #[test]
    fn shopping_link_returned_only_for_dummy_plug_variant() {
        assert!(IddFallbackStatus::NotRequired.shopping_link().is_none());
        assert!(IddFallbackStatus::IddHostAvailable
            .shopping_link()
            .is_none());
        let s = IddFallbackStatus::DummyPlugRequired {
            reason: "x".into(),
            shopping_link: DUMMY_PLUG_SHOPPING_LINK,
        };
        assert_eq!(s.shopping_link(), Some(DUMMY_PLUG_SHOPPING_LINK));
    }

    #[test]
    fn dummy_plug_link_is_an_amazon_listing() {
        assert!(DUMMY_PLUG_SHOPPING_LINK.contains("amazon.com"));
    }
}
