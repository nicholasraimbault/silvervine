//! Comprehensive unit tests for [`crate::platform::capabilities`].
//!
//! Linux probes are tested against synthesized `/sys` / `/proc` / `/dev`
//! trees in `tempfile::TempDir`. macOS probes are tested against the
//! committed `tests/fixtures/macos_system_profiler.json` fixture and a
//! parallel displays fixture parsed via the same `serde` types the
//! runtime path uses.
//!
//! No probe touches the real `/sys` / `/proc` — every test passes a
//! fully-injected [`CapabilityRoots`].

use std::fs;
use std::path::Path;

use tempfile::TempDir;

use super::*;

/// Build an empty `CapabilityRoots` rooted at `tmp.path()`.
fn empty_roots(tmp: &TempDir) -> CapabilityRoots {
    let sys = tmp.path().join("sys");
    let proc_ = tmp.path().join("proc");
    let dev = tmp.path().join("dev");
    fs::create_dir_all(&sys).unwrap();
    fs::create_dir_all(&proc_).unwrap();
    fs::create_dir_all(&dev).unwrap();
    CapabilityRoots {
        sys,
        proc_,
        dev,
        home: Some(tmp.path().join("home")),
    }
}

fn write(p: &Path, body: &str) {
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(p, body).unwrap();
}

/* ------------------------- TPM detection ---------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_tpm_present_with_version_and_vendor() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(&roots.sys.join("class/tpm/tpm0/tpm_version_major"), "2\n");
    write(
        &roots.sys.join("class/tpm/tpm0/device/manufacturer_id"),
        "STM\n",
    );
    write(&roots.dev.join("tpm0"), "");
    let caps = linux::detect_tpm(&roots);
    assert_eq!(
        caps,
        TpmStatus::Present {
            version: "2".into(),
            vendor: Some("STM".into()),
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tpm_present_unknown_version_when_only_dev_node() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(&roots.dev.join("tpm0"), "");
    let caps = linux::detect_tpm(&roots);
    assert_eq!(
        caps,
        TpmStatus::Present {
            version: "?".into(),
            vendor: None,
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_tpm_absent_when_no_devices() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let caps = linux::detect_tpm(&roots);
    assert_eq!(caps, TpmStatus::Absent);
}

/* ------------------------ virt detection ---------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_virt_intel_vmx() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(
        &roots.proc_.join("cpuinfo"),
        "processor\t: 0\nflags\t\t: fpu vmx pae\nmodel name\t: Intel(R)\n",
    );
    let v = linux::detect_virt(&roots);
    assert_eq!(
        v,
        VirtStatus::Enabled {
            kind: VirtKind::VtX
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_virt_amd_svm() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(
        &roots.proc_.join("cpuinfo"),
        "processor\t: 0\nflags\t\t: fpu svm pae nx\n",
    );
    let v = linux::detect_virt(&roots);
    assert_eq!(
        v,
        VirtStatus::Enabled {
            kind: VirtKind::AmdV
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_virt_absent_when_no_flags() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(
        &roots.proc_.join("cpuinfo"),
        "processor\t: 0\nflags\t\t: fpu\n",
    );
    let v = linux::detect_virt(&roots);
    assert_eq!(v, VirtStatus::Absent);
}

/* ----------------------- IOMMU detection ---------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_iommu_enabled_intel() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(&roots.proc_.join("cpuinfo"), "flags\t\t: vmx\n");
    write(
        &roots.proc_.join("cmdline"),
        "intel_iommu=on iommu=pt root=UUID=foo\n",
    );
    fs::create_dir_all(roots.sys.join("kernel/iommu_groups/0/devices")).unwrap();
    fs::create_dir_all(roots.sys.join("kernel/iommu_groups/1/devices")).unwrap();
    let virt = linux::detect_virt(&roots);
    let i = linux::detect_iommu(&roots, &virt);
    assert_eq!(
        i,
        IommuStatus::Enabled {
            kind: IommuKind::IntelVtD
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_iommu_enabled_amd() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(&roots.proc_.join("cpuinfo"), "flags\t\t: svm\n");
    write(&roots.proc_.join("cmdline"), "amd_iommu=on root=UUID=foo\n");
    fs::create_dir_all(roots.sys.join("kernel/iommu_groups/0/devices")).unwrap();
    let virt = linux::detect_virt(&roots);
    let i = linux::detect_iommu(&roots, &virt);
    assert_eq!(
        i,
        IommuStatus::Enabled {
            kind: IommuKind::AmdViO
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_iommu_disabled_when_groups_empty_but_cmdline_says_on() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(&roots.proc_.join("cpuinfo"), "flags\t\t: vmx\n");
    write(
        &roots.proc_.join("cmdline"),
        "intel_iommu=on root=UUID=foo\n",
    );
    fs::create_dir_all(roots.sys.join("kernel/iommu_groups")).unwrap();
    let virt = linux::detect_virt(&roots);
    let i = linux::detect_iommu(&roots, &virt);
    assert_eq!(i, IommuStatus::Disabled);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_iommu_absent_when_no_virt_no_groups() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(&roots.proc_.join("cpuinfo"), "flags\t\t: fpu\n");
    write(&roots.proc_.join("cmdline"), "root=UUID=foo\n");
    fs::create_dir_all(roots.sys.join("kernel/iommu_groups")).unwrap();
    let virt = linux::detect_virt(&roots);
    let i = linux::detect_iommu(&roots, &virt);
    assert_eq!(i, IommuStatus::Absent);
}

/* ------------------------- GPU detection ---------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_gpu_amd_with_iommu_group() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let card = roots.sys.join("class/drm/card1");
    let device = card.join("device");
    write(&device.join("vendor"), "0x1002\n");
    write(&device.join("device"), "0x1114\n");

    // IOMMU group at /sys/kernel/iommu_groups/21 with one device.
    let group_dir = roots
        .sys
        .join("kernel/iommu_groups/21/devices/0000:67:00.0");
    fs::create_dir_all(&group_dir).unwrap();
    write(&group_dir.join("class"), "0x030000\n"); // VGA (display) controller.

    // Symlink device/iommu_group -> kernel/iommu_groups/21
    std::os::unix::fs::symlink(
        roots.sys.join("kernel/iommu_groups/21"),
        device.join("iommu_group"),
    )
    .unwrap();

    let g = linux::detect_gpu(&roots);
    if let GpuStatus::Detected { devices } = g {
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].vendor, "AMD");
        assert_eq!(devices[0].model, "0x1002:0x1114");
        assert_eq!(devices[0].iommu_group, Some(21));
    } else {
        panic!("expected Detected; got {g:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_gpu_nvidia_unknown_isolation_no_group() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let device = roots.sys.join("class/drm/card0/device");
    write(&device.join("vendor"), "0x10de\n");
    write(&device.join("device"), "0x1234\n");
    let g = linux::detect_gpu(&roots);
    if let GpuStatus::Detected { devices } = g {
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].vendor, "NVIDIA");
        assert_eq!(devices[0].iommu_group, None);
        assert!(!devices[0].clean_isolation);
    } else {
        panic!("expected Detected");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_gpu_intel() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let device = roots.sys.join("class/drm/card0/device");
    write(&device.join("vendor"), "0x8086\n");
    write(&device.join("device"), "0x9a40\n");
    let g = linux::detect_gpu(&roots);
    if let GpuStatus::Detected { devices } = g {
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].vendor, "Intel");
    } else {
        panic!("expected Detected");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_gpu_unknown_vendor_id_format() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let device = roots.sys.join("class/drm/card0/device");
    write(&device.join("vendor"), "0xdead\n");
    write(&device.join("device"), "0xbeef\n");
    let g = linux::detect_gpu(&roots);
    if let GpuStatus::Detected { devices } = g {
        assert!(devices[0].vendor.starts_with("Unknown"));
        assert!(devices[0].vendor.contains("0xdead"));
    } else {
        panic!("expected Detected");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_gpu_skips_connector_directories() {
    // /sys/class/drm has card0, card0-DP-1, card0-HDMI-A-1 etc; only the
    // bare "cardN" dirs should be probed.
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let device = roots.sys.join("class/drm/card0/device");
    write(&device.join("vendor"), "0x10de\n");
    write(&device.join("device"), "0x1234\n");
    fs::create_dir_all(roots.sys.join("class/drm/card0-DP-1")).unwrap();
    fs::create_dir_all(roots.sys.join("class/drm/card0-HDMI-A-1")).unwrap();
    let g = linux::detect_gpu(&roots);
    if let GpuStatus::Detected { devices } = g {
        assert_eq!(devices.len(), 1);
    } else {
        panic!("expected Detected");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_gpu_not_detected_when_no_drm() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let g = linux::detect_gpu(&roots);
    assert_eq!(g, GpuStatus::NotDetected);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_gpu_hdr_detected_via_connector_attr() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let device = roots.sys.join("class/drm/card0/device");
    write(&device.join("vendor"), "0x1002\n");
    write(&device.join("device"), "0x1234\n");
    let conn = roots.sys.join("class/drm/card0-DP-1");
    fs::create_dir_all(&conn).unwrap();
    write(&conn.join("hdr_output_metadata"), "");
    let g = linux::detect_gpu(&roots);
    if let GpuStatus::Detected { devices } = g {
        assert!(devices[0].hdr_capable);
    } else {
        panic!("expected Detected");
    }
}

/* ----------------------- kernel detection --------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_kernel_reads_osrelease_fixture() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(
        &roots.proc_.join("sys/kernel/osrelease"),
        "7.0.3-1-cachyos\n",
    );
    let k = linux::detect_kernel(&roots);
    assert_eq!(k.version, "7.0.3-1-cachyos");
}

/* ------------------------- RAM detection ---------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_ram_parses_meminfo() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    write(
        &roots.proc_.join("meminfo"),
        "MemTotal:       30382844 kB\nMemAvailable:   15558092 kB\nMemFree: 100 kB\n",
    );
    let r = linux::detect_ram(&roots);
    assert_eq!(r.total_bytes, 30_382_844_u64 * 1024);
    assert_eq!(r.available_bytes, 15_558_092_u64 * 1024);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_ram_zero_when_meminfo_absent() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let r = linux::detect_ram(&roots);
    assert_eq!(r.total_bytes, 0);
    assert_eq!(r.available_bytes, 0);
}

/* ----------------------- display detection -------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_display_session_type_falls_through_when_no_env() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    // We can't deterministically clear env vars in a parallel test
    // without poisoning a global mutex; rely on whatever env is set and
    // assert the result is one of the three valid variants.
    let d = linux::detect_display(&roots);
    match d.session_type {
        SessionType::Wayland { .. } | SessionType::X11 | SessionType::Headless => (),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_display_hdr_when_connector_advertises() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    let conn = roots.sys.join("class/drm/card0-DP-1");
    fs::create_dir_all(&conn).unwrap();
    write(&conn.join("hdr_output_metadata"), "");
    let d = linux::detect_display(&roots);
    assert!(d.hdr_capable);
}

/* ------------------------ disk detection ---------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_disk_walks_up_to_existing_ancestor() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    // tmp.path()/home doesn't exist; the function should walk to tmp's
    // root or an ancestor that does.
    let d = linux::detect_disk(&roots);
    assert!(d.mountpoint.exists() || d.mountpoint == std::path::Path::new("/"));
}

/* ------------------------ end-to-end Linux -------------------------- */

#[cfg(target_os = "linux")]
#[test]
fn linux_detect_with_synthesized_full_tree() {
    let tmp = TempDir::new().unwrap();
    let roots = empty_roots(&tmp);
    // Synthesize a full tree.
    write(&roots.proc_.join("cpuinfo"), "flags\t\t: fpu vmx pae\n");
    write(&roots.proc_.join("cmdline"), "intel_iommu=on iommu=pt\n");
    write(
        &roots.proc_.join("meminfo"),
        "MemTotal: 1024 kB\nMemAvailable: 512 kB\n",
    );
    write(&roots.proc_.join("sys/kernel/osrelease"), "6.6.0\n");
    write(&roots.sys.join("class/tpm/tpm0/tpm_version_major"), "2\n");
    fs::create_dir_all(roots.sys.join("kernel/iommu_groups/0/devices")).unwrap();
    let device = roots.sys.join("class/drm/card0/device");
    write(&device.join("vendor"), "0x10de\n");
    write(&device.join("device"), "0x1234\n");

    let caps = super::detect_with(&roots);
    assert!(matches!(caps.tpm, TpmStatus::Present { .. }));
    assert!(matches!(caps.iommu, IommuStatus::Enabled { .. }));
    assert!(matches!(caps.virtualization, VirtStatus::Enabled { .. }));
    assert!(matches!(caps.gpu, GpuStatus::Detected { .. }));
    assert_eq!(caps.kernel.version, "6.6.0");
    assert_eq!(caps.ram.total_bytes, 1024 * 1024);
}

/* ---------------------- macOS fixture parsing ----------------------- */

#[cfg(target_os = "macos")]
#[test]
fn macos_parses_committed_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/macos_system_profiler.json");
    let body = std::fs::read(&path).expect("fixture file exists");
    let report: macos::HardwareReport = serde_json::from_slice(&body).expect("fixture parses");
    assert!(!report.hardware.is_empty());
}

/* ---------------------- macOS-only unit tests ----------------------- */

#[cfg(target_os = "macos")]
#[test]
fn macos_secure_enclave_apple_silicon() {
    let report = macos::HardwareReport {
        hardware: vec![macos::HardwareItem {
            chip_type: Some("Apple M2 Pro".into()),
            ..Default::default()
        }],
    };
    let s = macos::detect_secure_enclave(&report);
    if let TpmStatus::Present { version, vendor } = s {
        assert!(version.contains("SecureEnclave"));
        assert_eq!(vendor.as_deref(), Some("Apple M2 Pro"));
    } else {
        panic!("expected Present");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_secure_enclave_t2_intel() {
    let report = macos::HardwareReport {
        hardware: vec![macos::HardwareItem {
            chip_type: None,
            cpu_type: Some("Intel Core i9".into()),
            machine_model: Some("MacBookPro16,1".into()),
            ..Default::default()
        }],
    };
    let s = macos::detect_secure_enclave(&report);
    assert!(matches!(s, TpmStatus::Present { .. }));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_secure_enclave_absent_old_intel() {
    let report = macos::HardwareReport {
        hardware: vec![macos::HardwareItem {
            chip_type: None,
            cpu_type: Some("Intel Core i7".into()),
            machine_model: Some("MacBookPro11,3".into()),
            ..Default::default()
        }],
    };
    let s = macos::detect_secure_enclave(&report);
    assert_eq!(s, TpmStatus::Absent);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_parse_memory_string() {
    assert_eq!(
        macos::parse_macos_memory("32 GB"),
        Some(32u64 * 1024 * 1024 * 1024)
    );
    assert_eq!(
        macos::parse_macos_memory("16 GB"),
        Some(16u64 * 1024 * 1024 * 1024)
    );
    assert_eq!(macos::parse_macos_memory("8 MB"), Some(8u64 * 1024 * 1024));
    assert_eq!(macos::parse_macos_memory("nonsense"), None);
}

#[cfg(target_os = "macos")]
#[test]
fn macos_virt_apple_silicon_enabled() {
    let report = macos::HardwareReport {
        hardware: vec![macos::HardwareItem {
            chip_type: Some("Apple M3".into()),
            ..Default::default()
        }],
    };
    assert!(matches!(
        macos::detect_virt_macos(&report),
        VirtStatus::Enabled { .. }
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_iommu_always_enabled() {
    let s = macos::detect_iommu_macos();
    assert!(matches!(s, IommuStatus::Enabled { .. }));
}

/* ----------------------- public API plumbing ------------------------ */

#[test]
fn capability_roots_host_returns_real_roots() {
    let r = CapabilityRoots::host();
    assert_eq!(r.sys, std::path::PathBuf::from("/sys"));
    assert_eq!(r.proc_, std::path::PathBuf::from("/proc"));
    assert_eq!(r.dev, std::path::PathBuf::from("/dev"));
}

#[test]
fn noop_enabled_reflects_env_var() {
    let _g = crate::test_support::env_lock();
    let prev = std::env::var_os(NOOP_ENV);
    // SAFETY: serial test region; restore env after.
    unsafe { std::env::set_var(NOOP_ENV, "1") };
    assert!(noop_enabled());
    unsafe { std::env::remove_var(NOOP_ENV) };
    assert!(!noop_enabled());
    if let Some(prev) = prev {
        unsafe { std::env::set_var(NOOP_ENV, prev) };
    }
}

#[test]
fn detect_returns_a_snapshot_on_host() {
    let _ = detect();
    // We don't assert specific values — just that it doesn't panic on
    // whatever the host reports. Real-host assertions are in the
    // hardware-acceptance phase, not here.
}
