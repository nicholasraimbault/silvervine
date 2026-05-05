# V3 Hardware Compatibility

**Audience:** Linux desktop / laptop users who want to run the Neon
localhost-bridge for premium 4K HDR streaming.

This document is a living, observation-driven matrix. If your hardware
is not listed, run `neon doctor --bridge` and open an issue with the
output — every confirmed config helps the next user.

## Minimum requirements

- **CPU**: x86_64 with VT-x (Intel) or AMD-V (AMD). Verify with
  `neon doctor --bridge`.
- **TPM 2.0** discrete or fTPM. Required for Windows 11 IoT LTSC
  (Microsoft hard-gates Win11 install on TPM presence).
- **IOMMU**: VT-d (Intel) or AMD-Vi enabled in BIOS. Required for
  GPU/PCI passthrough.
- **GPU**: any discrete Radeon / NVIDIA / Intel Arc card with a clean
  IOMMU group (see "Group isolation" below).
- **RAM**: 16 GB minimum, 32 GB recommended. Bridge VM uses ~25% of
  host RAM (4-16 GB).
- **Disk**: ~80 GB free for the qcow2 disk + Win11 ISO + snapshots.
  External SSD is fine — set `[bridge].data_dir` in `bridge.toml`.
- **Linux kernel**: 5.10+ for kvmfr DKMS. 6.x recommended.

## Known-good configurations

### Desktop class (dual-GPU recommended)

| Vendor       | Motherboard / Chipset       | CPU              | dGPU              | iGPU       | Status |
|--------------|-----------------------------|------------------|-------------------|------------|--------|
| ASUS         | TUF Gaming X670E-Plus       | Ryzen 7 7700X    | RX 7900 XT        | (none)     | tested OK with dummy plug |
| ASUS         | ROG Strix B550-F            | Ryzen 5 5600X    | RX 6700 XT        | (none)     | dummy plug needed |
| MSI          | MAG B650 Tomahawk           | Ryzen 7 7800X3D  | RTX 4070          | (none)     | dummy plug needed |
| Gigabyte     | Z790 Aorus Elite            | i7-13700K        | RTX 4080          | UHD 770    | dual-GPU clean |
| ASRock       | X570 Taichi                 | Ryzen 9 5950X    | RX 6900 XT        | (none)     | tested OK |

### Laptop class (single-GPU, dummy plug required)

| Vendor       | Model                       | CPU                | dGPU              | Status |
|--------------|-----------------------------|--------------------|-------------------|--------|
| Framework 13 | AMD AI 9 HX 370             | Ryzen AI 9 HX 370  | Radeon 890M (iGPU)| tested with dummy plug |
| Lenovo       | ThinkPad P1 Gen 6           | i7-13700H          | RTX A1000         | dummy plug needed |
| Lenovo       | Legion Pro 7i               | i9-13900HX         | RTX 4080 mobile   | tested OK |
| Razer        | Blade 16                    | i9-13950HX         | RTX 4090 mobile   | tested with dummy plug |

### Confirmed incompatible

| Configuration | Reason | Workaround |
|---|---|---|
| Single-GPU host without dummy plug | Looking Glass needs a "real" display target | Plug in $5 4K HDMI dummy plug |
| ARM64 (Apple Silicon, Asahi, Pi) | KVM/QEMU x86 guest emulation is too slow | Use Parallels Desktop on macOS; no V3 path on Linux ARM yet |
| Hosts without TPM 2.0 | Win11 install hard-fails | Install Win10 LTSC; modify autounattend.xml manually |
| Hosts without IOMMU | No GPU/TPM passthrough possible | None for V3.0; CPU-only RDP queued for V3.1 stretch |

## BIOS settings per vendor

The single most common failure mode is "IOMMU enabled in /proc/cmdline
but the BIOS toggle is off." Each vendor names this slightly differently.

### ASUS
- `Advanced > AMD CBS > IOMMU = Enabled`
- `Advanced > CPU Configuration > SVM Mode = Enabled`
- Optional but improves passthrough: `Advanced > AMD CBS > Above 4G Decoding = Enabled`

### Gigabyte
- `Tweaker > Advanced CPU Settings > IOMMU = Enabled`
- `Settings > Miscellaneous > IOMMU = Enabled`
- For Intel boards: `Settings > VT-d = Enabled`

### MSI
- `OC > CPU Features > IOMMU = Enabled`
- `Settings > Advanced > Integrated Graphics Configuration = Disabled` (if dual-GPU)
- `Settings > Advanced > Above 4G memory/Crypto Currency mining = Enabled` (improves passthrough)

### ASRock
- `Advanced > CPU Configuration > SVM Mode = Enabled`
- `Advanced > AMD CBS > IOMMU = Enabled`

### Lenovo (ThinkPad)
- `Configuration > CPU > Intel Virtualization Technology = Enabled`
- `Configuration > CPU > VT-d = Enabled`
- `Security > Security Chip > TPM Reset = Yes` (one-time, if Windows refuses)

### Dell (Precision / XPS)
- `Virtualization Support > VT for Direct I/O = Enabled`
- `Virtualization Support > Trusted Execution = Enabled` (if available)

### HP (EliteBook / ProBook)
- `System Configuration > Virtualization Technology = Enabled`
- `System Configuration > VT-d = Enabled`

### Framework
- `CPU > Intel VMX = Enabled` (Intel) / `AMD CPU > SVM = Enabled` (AMD)
- `CPU > Intel VT-d = Enabled` (Intel) / `AMD CPU > IOMMU = Enabled` (AMD)

If you don't see one of these names, search your motherboard manual for
"IOMMU", "VT-d", or "AMD-Vi" and toggle whatever shows up.

## GPU IOMMU group isolation

For passthrough to work, the GPU must be in its own IOMMU group (or
share only with its audio companion device on the same multi-function
PCI slot). Run:

```sh
neon doctor --bridge
```

The output includes a per-GPU `iommu_group`. If two GPUs share a group,
or if your GPU's group includes USB controllers / chipset devices,
passthrough won't work cleanly without an ACS-override patch (out of
scope for V3.0).

## Dummy HDMI plug

Single-GPU hosts need a passive HDMI dummy plug to make Windows think
there's a "real" display attached. Recommended:

- Amazon: <https://www.amazon.com/dp/B07YFF3JGL> (~$5)
- Any 4K-capable HDMI EDID emulator works.

Plug into a free HDMI port on the GPU before running `neon stream init`.

## Looking Glass IDD-host status

Upstream Looking Glass IDD-host (Indirect Display Driver) replaces the
dummy-plug requirement on single-GPU hosts. **Status: paused upstream**
as of 2026-05-04. When it ships, V3.x will detect + use it
automatically.

Track:
- <https://github.com/gnif/LookingGlass/issues/...> (project status)
- Neon ROADMAP "Watch list" section.

## Performance expectations

| Host class            | Cold-start time | Latency (host → guest → host) | 4K HDR plays at |
|-----------------------|-----------------|-------------------------------|-----------------|
| Modern desktop (8C+)  | <8 s            | ~3-5 ms                       | Native 60 Hz    |
| Modern laptop (single-GPU + dummy plug) | <12 s | ~5-8 ms              | Native 60 Hz    |
| Older desktop (6C, 16 GB) | ~15 s       | ~8-10 ms                      | 1080p HDR (4K possible but might frame-skip) |
| Older laptop          | ~20 s           | ~15-25 ms                     | 1080p HDR        |

## Got a working config not listed?

Run:

```sh
neon doctor --bridge --json > my-host.json
```

Open an issue with `my-host.json` attached. Confirmed working configs
flow into this matrix in subsequent releases.
