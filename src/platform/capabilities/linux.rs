//! Linux-specific hardware capability probes.
//!
//! All probes take a [`CapabilityRoots`] so tests can synthesize a
//! `/sys` / `/proc` / `/dev` tree under a `tempfile::TempDir`. Real
//! detection on the host calls [`crate::platform::capabilities::detect_with`]
//! with [`CapabilityRoots::host()`].

use std::fs;
use std::path::{Path, PathBuf};

use super::{
    BridgeCapabilities, CapabilityRoots, DiskStatus, DisplayStatus, GpuDevice, GpuStatus,
    IommuKind, IommuStatus, KernelStatus, RamStatus, SessionType, TpmStatus, VirtKind, VirtStatus,
};

/// Linux entry point. Composes per-capability probes into a snapshot.
#[must_use]
pub fn detect_with(roots: &CapabilityRoots) -> BridgeCapabilities {
    let virt = detect_virt(roots);
    let iommu = detect_iommu(roots, &virt);
    BridgeCapabilities {
        tpm: detect_tpm(roots),
        iommu,
        virtualization: virt,
        gpu: detect_gpu(roots),
        kernel: detect_kernel(roots),
        disk: detect_disk(roots),
        ram: detect_ram(roots),
        display: detect_display(roots),
    }
}

/// Read TPM presence + version from `/sys/class/tpm/tpm0/`.
///
/// Sources, in order:
///
/// 1. `/sys/class/tpm/tpm0/tpm_version_major` → `version` field
/// 2. `/sys/class/tpm/tpm0/device/manufacturer_id` → `vendor`
/// 3. fallback: `/dev/tpm0` existence → `version="?"`, `vendor=None`
#[must_use]
pub fn detect_tpm(roots: &CapabilityRoots) -> TpmStatus {
    let tpm0 = roots.sys.join("class/tpm/tpm0");
    let dev_tpm0 = roots.dev.join("tpm0");
    let version = read_first_line(&tpm0.join("tpm_version_major"));
    let has_dev = dev_tpm0.exists();
    let has_sys = tpm0.exists();

    if let Some(version) = version {
        let vendor = read_first_line(&tpm0.join("device/manufacturer_id"));
        return TpmStatus::Present { version, vendor };
    }
    if has_sys || has_dev {
        // We saw the surface but couldn't parse the version major. Best-
        // effort: report present with "?" version so the wizard can still
        // surface "TPM detected, version uncertain".
        let vendor = read_first_line(&tpm0.join("device/manufacturer_id"));
        return TpmStatus::Present {
            version: String::from("?"),
            vendor,
        };
    }
    TpmStatus::Absent
}

/// Detect CPU virtualization extensions from `/proc/cpuinfo` flags.
#[must_use]
pub fn detect_virt(roots: &CapabilityRoots) -> VirtStatus {
    let flags = read_cpuinfo_flags(&roots.proc_.join("cpuinfo"));
    if flags.iter().any(|s| s == "vmx") {
        VirtStatus::Enabled {
            kind: VirtKind::VtX,
        }
    } else if flags.iter().any(|s| s == "svm") {
        VirtStatus::Enabled {
            kind: VirtKind::AmdV,
        }
    } else {
        VirtStatus::Absent
    }
}

/// Detect IOMMU enablement.
///
/// Combines:
///
/// * `/proc/cmdline` for `intel_iommu=on` / `amd_iommu=on` / `iommu=pt`
/// * `/sys/kernel/iommu_groups/` populated (>= 1 group dir present)
/// * The vendor kind is inferred from the [`VirtStatus`] passed in
///   (`vmx` → `IntelVtD`, `svm` → `AmdViO`).
#[must_use]
pub fn detect_iommu(roots: &CapabilityRoots, virt: &VirtStatus) -> IommuStatus {
    let cmdline = fs::read_to_string(roots.proc_.join("cmdline")).unwrap_or_default();
    let groups_dir = roots.sys.join("kernel/iommu_groups");
    let groups_present = groups_dir
        .read_dir()
        .ok()
        .is_some_and(|it| it.flatten().any(|e| e.path().is_dir()));

    let cmdline_says_on = cmdline.contains("intel_iommu=on")
        || cmdline.contains("amd_iommu=on")
        || cmdline.contains("iommu=on")
        || cmdline.contains("iommu=pt");

    // Determine kind from virt kind when we can.
    let kind = match virt {
        VirtStatus::Enabled {
            kind: VirtKind::VtX,
        } => Some(IommuKind::IntelVtD),
        VirtStatus::Enabled {
            kind: VirtKind::AmdV,
        } => Some(IommuKind::AmdViO),
        _ => None,
    };

    match (groups_present, kind) {
        (true, Some(k)) => IommuStatus::Enabled { kind: k },
        // Groups populated but virt absent → still report enabled with a
        // best-effort kind. AMD desktops without `svm` don't really
        // exist; default to Intel since that's the more common host.
        (true, None) => IommuStatus::Enabled {
            kind: IommuKind::IntelVtD,
        },
        // No groups but cmdline asserts the toggle and CPU has virt → IOMMU
        // is configured but didn't init (e.g. BIOS toggle off).
        (false, Some(_)) if cmdline_says_on => IommuStatus::Disabled,
        // No groups + no cmdline + CPU lacks virt → not supported at all.
        (false, None) => IommuStatus::Absent,
        // Default fallback: disabled (CPU supports it, but it's not active).
        _ => IommuStatus::Disabled,
    }
}

/// Walk `/sys/class/drm/card*/` and collect GPU devices.
#[must_use]
pub fn detect_gpu(roots: &CapabilityRoots) -> GpuStatus {
    let drm = roots.sys.join("class/drm");
    let mut devices: Vec<GpuDevice> = Vec::new();
    let Ok(entries) = drm.read_dir() else {
        return GpuStatus::NotDetected;
    };
    let mut card_dirs: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        // Match `card<N>` exactly (skip card1-DP-1 etc.).
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("card") && !name.contains('-') {
                card_dirs.push(p);
            }
        }
    }
    card_dirs.sort();

    for card in card_dirs {
        let device_dir = card.join("device");
        let Some(vendor_hex) = read_first_line(&device_dir.join("vendor")) else {
            continue;
        };
        let model_hex = read_first_line(&device_dir.join("device")).unwrap_or_default();
        let vendor = vendor_name_for(&vendor_hex);
        let model = format!("{vendor_hex}:{model_hex}");
        let iommu_group = read_iommu_group(&device_dir);
        let clean_isolation = match iommu_group {
            Some(group) => is_group_clean(&roots.sys, group, &device_dir),
            None => false,
        };
        let hdr_capable = card_has_hdr_connector(&card);
        devices.push(GpuDevice {
            vendor,
            model,
            iommu_group,
            clean_isolation,
            hdr_capable,
        });
    }

    if devices.is_empty() {
        GpuStatus::NotDetected
    } else {
        GpuStatus::Detected { devices }
    }
}

/// Read kernel version + check kvmfr module surface.
#[must_use]
pub fn detect_kernel(roots: &CapabilityRoots) -> KernelStatus {
    // The kernel `release` field lives under `/proc/sys/kernel/osrelease`
    // in real `/proc`. Use that path so test fixtures can mock it. When
    // the fixture is absent, fall back to `uname(2)`.
    let version = fs::read_to_string(roots.proc_.join("sys/kernel/osrelease"))
        .ok()
        .map_or_else(read_uname_release, |s| s.trim().to_string());

    let kvmfr_supported = kvmfr_module_visible(&version);
    KernelStatus {
        version,
        kvmfr_supported,
    }
}

/// Read kernel release via `uname(2)`. This only fires when the
/// `/proc/sys/kernel/osrelease` fixture isn't set, which on the real
/// host means we're reading the same value through a different syscall.
fn read_uname_release() -> String {
    // Use libc directly — nix would pull additional features. The crate
    // already depends on libc.
    use std::ffi::CStr;
    use std::mem::MaybeUninit;
    // SAFETY: utsname is a C struct with no padding requirements; uname()
    // populates every field. We immediately read the release CStr and
    // copy it into an owned String.
    unsafe {
        let mut un: MaybeUninit<libc::utsname> = MaybeUninit::uninit();
        if libc::uname(un.as_mut_ptr()) != 0 {
            return String::from("unknown");
        }
        let un = un.assume_init();
        let release_ptr = un.release.as_ptr();
        let cstr = CStr::from_ptr(release_ptr);
        cstr.to_string_lossy().into_owned()
    }
}

/// Best-effort kvmfr module presence check.
///
/// Looks at `/lib/modules/<ver>/extra/` and `/lib/modules/<ver>/updates/dkms/`.
/// Both paths are common locations for out-of-tree modules.
fn kvmfr_module_visible(version: &str) -> bool {
    if version == "unknown" || version == "unsupported" {
        return false;
    }
    let candidates = [
        PathBuf::from(format!("/lib/modules/{version}/extra")),
        PathBuf::from(format!("/lib/modules/{version}/updates/dkms")),
        PathBuf::from(format!("/lib/modules/{version}/extra/kvmfr")),
        PathBuf::from(format!(
            "/lib/modules/{version}/kernel/drivers/misc/kvmfr.ko"
        )),
    ];
    for c in &candidates {
        if let Ok(rd) = c.read_dir() {
            for entry in rd.flatten() {
                let n = entry.file_name();
                let n = n.to_string_lossy();
                if n.contains("kvmfr") {
                    return true;
                }
            }
        }
        if c.exists()
            && c.file_name()
                .is_some_and(|n| n.to_string_lossy().contains("kvmfr"))
        {
            return true;
        }
    }
    false
}

/// Determine free disk space at the bridge data path.
///
/// Bridge default: `<home>/.local/share/neon/bridge/`. Falls back to
/// `<home>/.cache/neon/` and finally `/tmp` when the home root isn't
/// reachable.
#[must_use]
pub fn detect_disk(roots: &CapabilityRoots) -> DiskStatus {
    let mut path = roots.home.as_ref().map_or_else(
        || PathBuf::from("/tmp"),
        |h| h.join(".local/share/neon/bridge"),
    );
    if !path.exists() {
        // Walk up to the first ancestor that does exist; statvfs requires
        // a real path.
        while !path.exists() {
            match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => path = p.to_path_buf(),
                _ => {
                    path = PathBuf::from("/");
                    break;
                }
            }
        }
    }
    let free_bytes = statvfs_free(&path).unwrap_or(0);
    DiskStatus {
        free_bytes,
        mountpoint: path,
    }
}

/// Wrap `statvfs(2)` to read free bytes from a path.
fn statvfs_free(path: &Path) -> Option<u64> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    let cpath = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    // SAFETY: statvfs takes an owned C string + zero-init buffer; the
    // syscall populates every field on success and we copy the values
    // into owned types before returning.
    unsafe {
        let mut buf: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
        if libc::statvfs(cpath.as_ptr(), buf.as_mut_ptr()) != 0 {
            return None;
        }
        let buf = buf.assume_init();
        // `f_bavail` and `f_frsize` are `c_ulong` on Linux/macOS — both
        // u64 on 64-bit targets. Promote and saturating-multiply.
        #[allow(clippy::useless_conversion)]
        let bavail: u64 = u64::try_from(buf.f_bavail).unwrap_or(0);
        #[allow(clippy::useless_conversion)]
        let frsize: u64 = u64::try_from(buf.f_frsize).unwrap_or(0);
        Some(bavail.saturating_mul(frsize))
    }
}

/// Read `MemTotal` + `MemAvailable` from `/proc/meminfo`.
#[must_use]
pub fn detect_ram(roots: &CapabilityRoots) -> RamStatus {
    let meminfo = fs::read_to_string(roots.proc_.join("meminfo")).unwrap_or_default();
    let mut total_bytes = 0u64;
    let mut available_bytes = 0u64;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_bytes = parse_meminfo_kib(rest).unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available_bytes = parse_meminfo_kib(rest).unwrap_or(0);
        }
    }
    RamStatus {
        total_bytes,
        available_bytes,
    }
}

fn parse_meminfo_kib(rest: &str) -> Option<u64> {
    // `MemTotal:    30382844 kB` → 30382844 * 1024.
    let kib: u64 = rest.split_whitespace().next()?.parse().ok()?;
    Some(kib.saturating_mul(1024))
}

/// Detect display session type + best-effort HDR.
#[must_use]
pub fn detect_display(roots: &CapabilityRoots) -> DisplayStatus {
    let session_type = detect_session_type();
    let hdr_capable = any_drm_hdr(&roots.sys.join("class/drm"));
    DisplayStatus {
        session_type,
        hdr_capable,
    }
}

fn detect_session_type() -> SessionType {
    let xdg = std::env::var("XDG_SESSION_TYPE").ok();
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let x11 = std::env::var_os("DISPLAY").is_some();
    let compositor = std::env::var("XDG_CURRENT_DESKTOP").ok();
    if xdg.as_deref() == Some("wayland") || wayland {
        SessionType::Wayland { compositor }
    } else if xdg.as_deref() == Some("x11") || x11 {
        SessionType::X11
    } else {
        SessionType::Headless
    }
}

/// Walk every `card*/<connector>/hdr_output_metadata` looking for one.
fn any_drm_hdr(drm_root: &Path) -> bool {
    let Ok(entries) = drm_root.read_dir() else {
        return false;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with("card") && name.contains('-') {
            // It's a connector subdir. Probe `hdr_output_metadata`.
            if p.join("hdr_output_metadata").exists() {
                return true;
            }
        }
    }
    false
}

/* ----------------------------- helpers ------------------------------ */

fn read_first_line(p: &Path) -> Option<String> {
    let s = fs::read_to_string(p).ok()?;
    let line = s.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}

fn read_cpuinfo_flags(p: &Path) -> Vec<String> {
    let s = fs::read_to_string(p).unwrap_or_default();
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("flags") {
            // "flags\t\t: fpu vme ..."
            if let Some(idx) = rest.find(':') {
                let body = &rest[idx + 1..];
                return body.split_whitespace().map(str::to_string).collect();
            }
        }
    }
    Vec::new()
}

fn vendor_name_for(hex: &str) -> String {
    // PCI vendor IDs are stable; the four common GPU vendors are:
    let normalized = hex.trim().to_lowercase();
    match normalized.as_str() {
        "0x10de" => "NVIDIA".to_string(),
        "0x1002" | "0x1022" => "AMD".to_string(),
        "0x8086" => "Intel".to_string(),
        "0x106b" => "Apple".to_string(),
        _ => format!("Unknown ({normalized})"),
    }
}

fn read_iommu_group(device_dir: &Path) -> Option<u32> {
    // device/iommu_group is a symlink → ../../../kernel/iommu_groups/<N>.
    let link = device_dir.join("iommu_group");
    let target = fs::read_link(&link).ok()?;
    target
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|s| s.parse().ok())
}

/// A GPU's IOMMU group is "clean" when every other PCI device sharing
/// the group is either a `PCIe` bridge or a sibling function of the GPU
/// (e.g. the audio companion at function .1).
fn is_group_clean(sys_root: &Path, group: u32, gpu_device_dir: &Path) -> bool {
    let group_devices_dir = sys_root.join(format!("kernel/iommu_groups/{group}/devices"));
    let Ok(entries) = group_devices_dir.read_dir() else {
        return false;
    };
    let gpu_pci_root = gpu_device_dir
        .canonicalize()
        .ok()
        .and_then(|p| pci_address_root_of(&p))
        .unwrap_or_default();
    for entry in entries.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Resolve the symlink to find the real device dir.
        let class_path = p.join("class");
        let class = read_first_line(&class_path).unwrap_or_default();
        let class_norm = class.trim().to_lowercase();
        let is_bridge = class_norm.starts_with("0x06");
        let pci_root = pci_address_root_of(Path::new(name));
        let same_function_root = pci_root
            .as_ref()
            .is_some_and(|r| r.eq_ignore_ascii_case(&gpu_pci_root));
        if !is_bridge && !same_function_root {
            return false;
        }
    }
    true
}

/// Strip the `.fnN` suffix from a PCI address to compare across functions.
///
/// `0000:67:00.0` and `0000:67:00.1` both share root `0000:67:00`.
fn pci_address_root_of(p: &Path) -> Option<String> {
    let last = p.file_name()?.to_str()?;
    // Format: `0000:67:00.0` or `0000:67:00.1`.
    let dot = last.rfind('.')?;
    Some(last[..dot].to_string())
}

fn card_has_hdr_connector(card_dir: &Path) -> bool {
    let Some(parent) = card_dir.parent() else {
        return false;
    };
    let Some(card_name) = card_dir.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Ok(entries) = parent.read_dir() else {
        return false;
    };
    let prefix = format!("{card_name}-");
    for entry in entries.flatten() {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with(&prefix) && p.join("hdr_output_metadata").exists() {
            return true;
        }
    }
    false
}
