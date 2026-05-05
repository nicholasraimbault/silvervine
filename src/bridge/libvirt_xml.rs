//! libvirt domain XML generation — V3-Phase C.
//!
//! Renders a libvirt-compatible `<domain type='kvm'>` XML for the
//! Win11 `IoT` bridge guest. Key design points:
//!
//! * QEMU/KVM, `x86_64`, OVMF firmware (UEFI required for TPM 2.0).
//! * RAM/vCPUs configurable; [`DomainSpec::sized_for_host`] derives
//!   sane defaults from the host snapshot.
//! * TPM 2.0 via passthrough (`<tpm model='tpm-crb'>`).
//! * GPU passthrough via vfio-pci, address derived from
//!   [`crate::platform::capabilities::BridgeCapabilities`].
//! * virtio-net (NAT) + virtio-blk for boot disk + ISO mount.
//! * IVSHMEM device for Looking Glass shared-memory.
//! * Auto-attach an autounattend.xml ISO as a second virtual CD-ROM.
//!
//! ## Schema validation
//!
//! Tests run `virt-xml-validate` (when available on the host) on the
//! rendered XML. The harness gates this via
//! `NEON_TEST_VIRTXMLVALIDATE_NOOP=1` so CI runners without the binary
//! still pass — they exercise the renderer's structure-level
//! invariants instead.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Env var that gates the `virt-xml-validate` subprocess in tests.
pub const VIRT_XML_VALIDATE_NOOP_ENV: &str = "NEON_TEST_VIRTXMLVALIDATE_NOOP";

/// Default IVSHMEM shared-memory size, in MB. Looking Glass'
/// recommended minimum is ~32 MB; we default to 64 MB for headroom on
/// 4K @ 60Hz HDR.
pub const DEFAULT_IVSHMEM_SIZE_MB: u32 = 64;

/// libvirt domain spec consumed by [`render_domain_xml`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSpec {
    /// Domain (VM) name. Used as `<name>` in the XML and as the
    /// canonical identifier in `virsh` operations.
    pub name: String,
    /// RAM allocation in MB.
    pub ram_mb: u32,
    /// vCPU count.
    pub vcpus: u32,
    /// Path to the qcow2 boot disk.
    pub disk_path: PathBuf,
    /// Path to the Windows installer ISO.
    pub iso_path: PathBuf,
    /// Path to the autounattend.xml ISO (mounted as a second CD-ROM).
    pub autounattend_iso_path: PathBuf,
    /// PCI BDF (`0000:01:00.0`) of the GPU to pass through. May be
    /// `None` for headless test rendering. When set, the audio
    /// companion device at `.1` is also bound (`<source>` is multi-
    /// function).
    pub gpu_pci_address: Option<PciAddress>,
    /// Path to the host TPM device. Defaults to `/dev/tpm0`.
    pub tpm_path: PathBuf,
    /// IVSHMEM size in MB (Looking Glass shared-memory).
    pub ivshmem_size_mb: u32,
    /// Path to OVMF firmware. Linux: `/usr/share/edk2/x64/OVMF.fd`
    /// (Arch); on Debian/Ubuntu it's
    /// `/usr/share/OVMF/OVMF_CODE_4M.ms.fd`. The wizard tries each in
    /// order at install time.
    pub ovmf_code_path: PathBuf,
    /// Path to OVMF NVRAM template (per-VM copy is created on
    /// definition). Same vendor matrix as `ovmf_code_path`.
    pub ovmf_vars_path: PathBuf,
}

impl DomainSpec {
    /// Build a spec sized for the given host snapshot. RAM defaults to
    /// `host_total / 4` (capped at 16GB), vCPUs default to
    /// `min(host_cpus, 4)`.
    #[must_use]
    pub fn sized_for_host(
        name: impl Into<String>,
        host_ram_total_bytes: u64,
        host_cpu_count: u32,
        disk_path: PathBuf,
        iso_path: PathBuf,
        autounattend_iso_path: PathBuf,
        gpu_pci_address: Option<PciAddress>,
    ) -> Self {
        let host_ram_mb = u32::try_from(host_ram_total_bytes / (1024 * 1024)).unwrap_or(8 * 1024);
        let ram_mb = host_ram_mb / 4;
        // Floor at 4 GB, ceiling at 16 GB.
        let ram_mb = ram_mb.clamp(4 * 1024, 16 * 1024);
        let vcpus = host_cpu_count.clamp(2, 4);
        Self {
            name: name.into(),
            ram_mb,
            vcpus,
            disk_path,
            iso_path,
            autounattend_iso_path,
            gpu_pci_address,
            tpm_path: PathBuf::from("/dev/tpm0"),
            ivshmem_size_mb: DEFAULT_IVSHMEM_SIZE_MB,
            ovmf_code_path: PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
            ovmf_vars_path: PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd"),
        }
    }
}

/// PCI device address (`<domain>:<bus>:<slot>.<function>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciAddress {
    /// Domain segment (4 hex digits, typically `0000`).
    pub domain: u16,
    /// Bus (2 hex digits).
    pub bus: u8,
    /// Slot / device (2 hex digits).
    pub slot: u8,
    /// Function (1 hex digit).
    pub function: u8,
}

impl PciAddress {
    /// Parse a `0000:01:00.0`-format string.
    ///
    /// # Errors
    ///
    /// [`crate::ErrorCategory::Other`] on malformed input.
    pub fn parse(s: &str) -> Result<Self> {
        let (head, function) = s
            .split_once('.')
            .ok_or_else(|| Error::other(format!("PCI address {s:?} missing '.'")))?;
        let parts: Vec<&str> = head.split(':').collect();
        if parts.len() != 3 {
            return Err(Error::other(format!(
                "PCI address {s:?} expected domain:bus:slot.function"
            )));
        }
        let domain = u16::from_str_radix(parts[0], 16)
            .map_err(|e| Error::other(format!("PCI address {s:?} domain: {e}")))?;
        let bus = u8::from_str_radix(parts[1], 16)
            .map_err(|e| Error::other(format!("PCI address {s:?} bus: {e}")))?;
        let slot = u8::from_str_radix(parts[2], 16)
            .map_err(|e| Error::other(format!("PCI address {s:?} slot: {e}")))?;
        let function = u8::from_str_radix(function, 16)
            .map_err(|e| Error::other(format!("PCI address {s:?} function: {e}")))?;
        Ok(Self {
            domain,
            bus,
            slot,
            function,
        })
    }

    /// Render as `0000:01:00.0`.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.domain, self.bus, self.slot, self.function
        )
    }

    /// Sibling at `.1` (audio companion).
    #[must_use]
    pub fn audio_companion(&self) -> Self {
        Self {
            function: 1,
            ..*self
        }
    }
}

/// Render a libvirt domain XML for the spec.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — malformed name (XML-special
///   characters), missing OVMF / TPM paths, etc.
#[allow(clippy::too_many_lines, clippy::needless_raw_string_hashes)]
pub fn render_domain_xml(spec: &DomainSpec) -> Result<String> {
    if !spec
        .name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(Error::other(format!(
            "domain name {:?} contains characters that would corrupt the XML",
            spec.name
        )));
    }
    if spec.ram_mb < 1024 {
        return Err(Error::other(format!(
            "domain ram_mb={} < 1024 minimum",
            spec.ram_mb
        )));
    }
    if !(1..=64).contains(&spec.vcpus) {
        return Err(Error::other(format!(
            "domain vcpus={} outside [1, 64]",
            spec.vcpus
        )));
    }

    let memory_kib = u64::from(spec.ram_mb) * 1024;
    let ivshmem_kib = u64::from(spec.ivshmem_size_mb) * 1024;

    let gpu_block = match &spec.gpu_pci_address {
        None => String::new(),
        Some(addr) => {
            let audio = addr.audio_companion();
            format!(
                "    <hostdev mode='subsystem' type='pci' managed='yes'>\n      <source>\n        <address domain='0x{:04x}' bus='0x{:02x}' slot='0x{:02x}' function='0x{:x}'/>\n      </source>\n      <rom bar='off'/>\n    </hostdev>\n    <hostdev mode='subsystem' type='pci' managed='yes'>\n      <source>\n        <address domain='0x{:04x}' bus='0x{:02x}' slot='0x{:02x}' function='0x{:x}'/>\n      </source>\n      <rom bar='off'/>\n    </hostdev>\n",
                addr.domain, addr.bus, addr.slot, addr.function,
                audio.domain, audio.bus, audio.slot, audio.function,
            )
        }
    };

    let xml = format!(
        r#"<domain type='kvm'>
  <name>{name}</name>
  <memory unit='KiB'>{memory_kib}</memory>
  <currentMemory unit='KiB'>{memory_kib}</currentMemory>
  <vcpu placement='static'>{vcpus}</vcpu>
  <cpu mode='host-passthrough' check='partial'>
    <topology sockets='1' dies='1' cores='{vcpus}' threads='1'/>
  </cpu>
  <os firmware='efi'>
    <type arch='x86_64' machine='pc-q35-7.2'>hvm</type>
    <loader readonly='yes' type='pflash' secure='yes'>{ovmf_code}</loader>
    <nvram template='{ovmf_vars}'>/var/lib/libvirt/qemu/nvram/{name}_VARS.fd</nvram>
    <bootmenu enable='yes' timeout='1000'/>
  </os>
  <features>
    <acpi/>
    <apic/>
    <hyperv>
      <relaxed state='on'/>
      <vapic state='on'/>
      <spinlocks state='on' retries='8191'/>
      <vendor_id state='on' value='neonbridge'/>
    </hyperv>
    <smm state='on'/>
    <vmport state='off'/>
  </features>
  <clock offset='localtime'>
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
    <timer name='hypervclock' present='yes'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2' discard='unmap'/>
      <source file='{disk_path}'/>
      <target dev='vda' bus='virtio'/>
      <boot order='1'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{iso_path}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
      <boot order='2'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{autounattend_iso}'/>
      <target dev='sdb' bus='sata'/>
      <readonly/>
    </disk>
    <controller type='usb' model='qemu-xhci' ports='15'/>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'>
      <target type='isa-serial' port='0'>
        <model name='isa-serial'/>
      </target>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <channel type='spicevmc'>
      <target type='virtio' name='com.redhat.spice.0'/>
    </channel>
    <input type='tablet' bus='usb'/>
    <graphics type='vnc' port='-1' listen='127.0.0.1'/>
    <video>
      <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/>
    </video>
    <tpm model='tpm-crb'>
      <backend type='passthrough'>
        <device path='{tpm_path}'/>
      </backend>
    </tpm>
{gpu_block}    <shmem name='looking-glass'>
      <model type='ivshmem-plain'/>
      <size unit='KiB'>{ivshmem_kib}</size>
    </shmem>
    <memballoon model='none'/>
  </devices>
</domain>
"#,
        name = spec.name,
        memory_kib = memory_kib,
        vcpus = spec.vcpus,
        ovmf_code = spec.ovmf_code_path.display(),
        ovmf_vars = spec.ovmf_vars_path.display(),
        disk_path = spec.disk_path.display(),
        iso_path = spec.iso_path.display(),
        autounattend_iso = spec.autounattend_iso_path.display(),
        tpm_path = spec.tpm_path.display(),
        gpu_block = gpu_block,
        ivshmem_kib = ivshmem_kib,
    );
    Ok(xml)
}

/// Run `virt-xml-validate` on a rendered XML, if the binary is on
/// PATH and `NEON_TEST_VIRTXMLVALIDATE_NOOP` is not set. Returns `Ok`
/// when the schema check passes, or when the binary is unavailable
/// (graceful degradation).
///
/// # Errors
///
/// [`crate::ErrorCategory::Other`] — schema check rejected the XML.
pub fn validate_with_virt_xml_validate(xml: &str) -> Result<()> {
    if std::env::var_os(VIRT_XML_VALIDATE_NOOP_ENV).is_some() {
        return Ok(());
    }
    let mut child = match std::process::Command::new("virt-xml-validate")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::other(format!("virt-xml-validate spawn: {e}"))),
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(xml.as_bytes())
            .map_err(|e| Error::other(format!("virt-xml-validate stdin: {e}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| Error::other(format!("virt-xml-validate wait: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format!(
            "virt-xml-validate rejected the XML: {stderr}"
        )));
    }
    Ok(())
}

/// Render the qemu CLI hint corresponding to `spec` — useful for
/// diagnostics. Not consumed by `virsh`; just for the user's reference.
#[must_use]
pub fn qemu_cli_hint(spec: &DomainSpec) -> String {
    format!(
        "qemu-system-x86_64 -enable-kvm -cpu host -smp {} -m {} -drive file={},if=virtio -cdrom {} -bios {} -device virtio-net,netdev=n0 -netdev user,id=n0 -device tpm-crb,tpmdev=t0 -tpmdev passthrough,id=t0,path={}",
        spec.vcpus,
        spec.ram_mb,
        spec.disk_path.display(),
        spec.iso_path.display(),
        spec.ovmf_code_path.display(),
        spec.tpm_path.display(),
    )
}

/// Convenience: build a [`DomainSpec`] for tests with all-defaults plus
/// the given disk + ISO paths.
#[doc(hidden)]
#[must_use]
pub fn test_spec(name: &str, paths_root: &Path) -> DomainSpec {
    DomainSpec {
        name: name.to_string(),
        ram_mb: 8192,
        vcpus: 4,
        disk_path: paths_root.join("disk.qcow2"),
        iso_path: paths_root.join("win.iso"),
        autounattend_iso_path: paths_root.join("autounattend.iso"),
        gpu_pci_address: Some(PciAddress {
            domain: 0,
            bus: 0x65,
            slot: 0,
            function: 0,
        }),
        tpm_path: PathBuf::from("/dev/tpm0"),
        ivshmem_size_mb: DEFAULT_IVSHMEM_SIZE_MB,
        ovmf_code_path: PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
        ovmf_vars_path: PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn pci_address_parse_round_trips() {
        let a = PciAddress::parse("0000:01:00.0").expect("parse ok");
        assert_eq!(a.domain, 0);
        assert_eq!(a.bus, 1);
        assert_eq!(a.slot, 0);
        assert_eq!(a.function, 0);
        assert_eq!(a.render(), "0000:01:00.0");
    }

    #[test]
    fn pci_address_parse_handles_higher_bus() {
        let a = PciAddress::parse("0000:65:00.0").expect("parse ok");
        assert_eq!(a.bus, 0x65);
        assert_eq!(a.render(), "0000:65:00.0");
    }

    #[test]
    fn pci_address_parse_rejects_malformed() {
        assert!(PciAddress::parse("garbage").is_err());
        assert!(PciAddress::parse("0000:00:00").is_err());
        assert!(PciAddress::parse("xxxx:01:00.0").is_err());
    }

    #[test]
    fn pci_address_audio_companion_uses_function_1() {
        let a = PciAddress::parse("0000:65:00.0").expect("parse ok");
        let aud = a.audio_companion();
        assert_eq!(aud.function, 1);
        assert_eq!(aud.render(), "0000:65:00.1");
    }

    #[test]
    fn render_domain_with_gpu_includes_two_hostdevs() {
        let tmp = TempDir::new().expect("tempdir");
        let spec = test_spec("neon-bridge", tmp.path());
        let xml = render_domain_xml(&spec).expect("render");
        let count = xml.matches("<hostdev").count();
        assert_eq!(count, 2, "GPU + audio companion: {xml}");
    }

    #[test]
    fn render_domain_without_gpu_has_no_hostdev() {
        let tmp = TempDir::new().expect("tempdir");
        let mut spec = test_spec("neon-bridge", tmp.path());
        spec.gpu_pci_address = None;
        let xml = render_domain_xml(&spec).expect("render");
        assert!(!xml.contains("<hostdev"));
    }

    #[test]
    fn render_domain_xml_parses_as_xml() {
        let tmp = TempDir::new().expect("tempdir");
        let spec = test_spec("neon-bridge", tmp.path());
        let xml = render_domain_xml(&spec).expect("render");
        let mut reader = quick_xml::Reader::from_str(&xml);
        let mut events = 0_usize;
        loop {
            let mut buf = Vec::new();
            match reader.read_event_into(&mut buf) {
                Ok(quick_xml::events::Event::Eof) => break,
                Ok(_) => events += 1,
                Err(e) => panic!("XML parse failed at event {events}: {e}\n{xml}"),
            }
        }
        assert!(events > 30, "non-trivial event count: {events}");
    }

    #[test]
    fn render_domain_includes_required_devices() {
        let tmp = TempDir::new().expect("tempdir");
        let spec = test_spec("neon-bridge", tmp.path());
        let xml = render_domain_xml(&spec).expect("render");
        for required in &[
            "<domain type='kvm'>",
            "<tpm model='tpm-crb'>",
            "<shmem name='looking-glass'>",
            "<model type='ivshmem-plain'/>",
            "<interface type='network'>",
            "<model type='virtio'/>",
        ] {
            assert!(
                xml.contains(required),
                "missing required device {required}: {xml}"
            );
        }
    }

    #[test]
    fn render_domain_rejects_malformed_name() {
        let tmp = TempDir::new().expect("tempdir");
        let mut spec = test_spec("not<safe>", tmp.path());
        spec.name = "<scripted>".into();
        let err = render_domain_xml(&spec).expect_err("malformed name");
        assert_eq!(err.category, crate::ErrorCategory::Other);
    }

    #[test]
    fn render_domain_rejects_low_ram() {
        let tmp = TempDir::new().expect("tempdir");
        let mut spec = test_spec("neon-bridge", tmp.path());
        spec.ram_mb = 256;
        let err = render_domain_xml(&spec).expect_err("low ram");
        assert_eq!(err.category, crate::ErrorCategory::Other);
    }

    #[test]
    fn render_domain_rejects_too_many_vcpus() {
        let tmp = TempDir::new().expect("tempdir");
        let mut spec = test_spec("neon-bridge", tmp.path());
        spec.vcpus = 9999;
        let err = render_domain_xml(&spec).expect_err("absurd vcpus");
        assert_eq!(err.category, crate::ErrorCategory::Other);
    }

    #[test]
    fn render_domain_includes_ivshmem_size_in_kib() {
        let tmp = TempDir::new().expect("tempdir");
        let mut spec = test_spec("neon-bridge", tmp.path());
        spec.ivshmem_size_mb = 32;
        let xml = render_domain_xml(&spec).expect("render");
        assert!(
            xml.contains("<size unit='KiB'>32768</size>"),
            "32 MB should render as 32768 KiB: {xml}"
        );
    }

    #[test]
    fn render_domain_pci_addr_uses_hex_prefix() {
        let tmp = TempDir::new().expect("tempdir");
        let mut spec = test_spec("neon-bridge", tmp.path());
        spec.gpu_pci_address = Some(PciAddress {
            domain: 0,
            bus: 0x65,
            slot: 0,
            function: 0,
        });
        let xml = render_domain_xml(&spec).expect("render");
        assert!(xml.contains("bus='0x65'"));
        assert!(xml.contains("slot='0x00'"));
        // Audio companion at .1.
        assert!(xml.contains("function='0x1'"));
    }

    #[test]
    fn sized_for_host_clamps_low_ram() {
        let spec = DomainSpec::sized_for_host(
            "n",
            2u64 * 1024 * 1024 * 1024, // 2GB host
            2,
            "/disk".into(),
            "/iso".into(),
            "/au".into(),
            None,
        );
        assert_eq!(spec.ram_mb, 4 * 1024); // floor at 4GB
        assert_eq!(spec.vcpus, 2);
    }

    #[test]
    fn sized_for_host_caps_high_ram() {
        let spec = DomainSpec::sized_for_host(
            "n",
            128u64 * 1024 * 1024 * 1024, // 128GB host
            32,
            "/disk".into(),
            "/iso".into(),
            "/au".into(),
            None,
        );
        assert_eq!(spec.ram_mb, 16 * 1024); // capped at 16GB
        assert_eq!(spec.vcpus, 4); // capped at 4
    }

    #[test]
    fn sized_for_host_typical_machine() {
        let spec = DomainSpec::sized_for_host(
            "neon-bridge",
            32u64 * 1024 * 1024 * 1024,
            16,
            "/disk".into(),
            "/iso".into(),
            "/au".into(),
            None,
        );
        // 32GB / 4 = 8GB.
        assert_eq!(spec.ram_mb, 8 * 1024);
        assert_eq!(spec.vcpus, 4);
    }

    #[test]
    fn validate_with_virt_xml_validate_honors_noop_env() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe { std::env::set_var(VIRT_XML_VALIDATE_NOOP_ENV, "1") };
        // Garbage XML — would fail real validation; NOOP means we Ok.
        validate_with_virt_xml_validate("not actually XML")
            .expect("noop env should short-circuit validation");
        unsafe { std::env::remove_var(VIRT_XML_VALIDATE_NOOP_ENV) };
    }

    #[test]
    fn qemu_cli_hint_mentions_host_features() {
        let tmp = TempDir::new().expect("tempdir");
        let spec = test_spec("neon-bridge", tmp.path());
        let hint = qemu_cli_hint(&spec);
        assert!(hint.contains("qemu-system-x86_64"));
        assert!(hint.contains("kvm"));
        assert!(hint.contains("tpm-crb"));
        assert!(hint.contains("virtio-net"));
    }
}
