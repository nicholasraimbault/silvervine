//! Minimal ELF and Mach-O architecture inspection.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Executable container format recognized by the inspector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryFormat {
    /// Executable and Linkable Format.
    Elf,
    /// Thin or universal Mach object.
    MachO,
}

/// CPU architecture declared by a binary slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryArchitecture {
    /// AMD64 / Intel 64.
    X86_64,
    /// 64-bit Arm.
    Aarch64,
    /// A recognized container carrying another numeric machine identifier.
    Other(u32),
}

/// Architecture metadata read directly from a shared-library header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// Container format.
    pub format: BinaryFormat,
    /// Word size of the represented slice or slices.
    pub bits: u8,
    /// Architectures carried by the file, in header order without duplicates.
    pub architectures: Vec<BinaryArchitecture>,
}

/// Inspect an ELF or Mach-O header without loading the binary.
///
/// # Errors
///
/// Returns `UnknownBundleStructure` for truncated or unrecognized headers and
/// a categorized I/O error when the file cannot be read.
pub fn inspect(path: &Path) -> Result<BinaryInfo> {
    let mut file = File::open(path).map_err(Error::from)?;
    let mut header = [0_u8; 4096];
    let count = file.read(&mut header).map_err(Error::from)?;
    inspect_header(&header[..count]).map_err(|message| {
        Error::unknown_bundle_structure(format!(
            "could not inspect binary header at {}: {message}",
            path.display()
        ))
    })
}

fn inspect_header(bytes: &[u8]) -> std::result::Result<BinaryInfo, &'static str> {
    if bytes.starts_with(b"\x7fELF") {
        return inspect_elf(bytes);
    }
    inspect_mach_o(bytes)
}

fn inspect_elf(bytes: &[u8]) -> std::result::Result<BinaryInfo, &'static str> {
    if bytes.len() < 20 {
        return Err("truncated ELF header");
    }
    let bits = match bytes[4] {
        1 => 32,
        2 => 64,
        _ => return Err("unknown ELF class"),
    };
    let machine = match bytes[5] {
        1 => u16::from_le_bytes([bytes[18], bytes[19]]),
        2 => u16::from_be_bytes([bytes[18], bytes[19]]),
        _ => return Err("unknown ELF byte order"),
    };
    Ok(BinaryInfo {
        format: BinaryFormat::Elf,
        bits,
        architectures: vec![architecture(u32::from(machine))],
    })
}

fn inspect_mach_o(bytes: &[u8]) -> std::result::Result<BinaryInfo, &'static str> {
    if bytes.len() < 8 {
        return Err("unrecognized binary header");
    }
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let (little_endian, bits) = match magic {
        [0xce, 0xfa, 0xed, 0xfe] => (true, 32),
        [0xcf, 0xfa, 0xed, 0xfe] => (true, 64),
        [0xfe, 0xed, 0xfa, 0xce] => (false, 32),
        [0xfe, 0xed, 0xfa, 0xcf] => (false, 64),
        [0xca, 0xfe, 0xba, 0xbe] => return inspect_fat_mach_o(bytes, false, false),
        [0xbe, 0xba, 0xfe, 0xca] => return inspect_fat_mach_o(bytes, true, false),
        [0xca, 0xfe, 0xba, 0xbf] => return inspect_fat_mach_o(bytes, false, true),
        [0xbf, 0xba, 0xfe, 0xca] => return inspect_fat_mach_o(bytes, true, true),
        _ => return Err("unrecognized binary header"),
    };
    let cpu_type = read_u32(&bytes[4..8], little_endian);
    Ok(BinaryInfo {
        format: BinaryFormat::MachO,
        bits,
        architectures: vec![architecture(cpu_type)],
    })
}

fn inspect_fat_mach_o(
    bytes: &[u8],
    little_endian: bool,
    is_64_bit_header: bool,
) -> std::result::Result<BinaryInfo, &'static str> {
    let count = read_u32(&bytes[4..8], little_endian) as usize;
    if count == 0 || count > 128 {
        return Err("invalid Mach-O slice count");
    }
    let stride = if is_64_bit_header { 32 } else { 20 };
    let required = 8_usize
        .checked_add(count.checked_mul(stride).ok_or("Mach-O header overflow")?)
        .ok_or("Mach-O header overflow")?;
    if bytes.len() < required {
        return Err("truncated universal Mach-O header");
    }
    let mut architectures = Vec::with_capacity(count);
    let mut bits = 32;
    for index in 0..count {
        let offset = 8 + index * stride;
        let cpu_type = read_u32(&bytes[offset..offset + 4], little_endian);
        if cpu_type & 0x0100_0000 != 0 {
            bits = 64;
        }
        let architecture = architecture(cpu_type);
        if !architectures.contains(&architecture) {
            architectures.push(architecture);
        }
    }
    Ok(BinaryInfo {
        format: BinaryFormat::MachO,
        bits,
        architectures,
    })
}

fn read_u32(bytes: &[u8], little_endian: bool) -> u32 {
    let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if little_endian {
        u32::from_le_bytes(value)
    } else {
        u32::from_be_bytes(value)
    }
}

fn architecture(machine: u32) -> BinaryArchitecture {
    match machine {
        62 | 0x0100_0007 => BinaryArchitecture::X86_64,
        183 | 0x0100_000c => BinaryArchitecture::Aarch64,
        other => BinaryArchitecture::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{inspect, BinaryArchitecture, BinaryFormat};

    fn elf64(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    fn mach64(cpu_type: u32) -> Vec<u8> {
        let mut bytes = vec![0_u8; 32];
        bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&cpu_type.to_le_bytes());
        bytes
    }

    fn fat_mach(cpu_types: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + cpu_types.len() * 20);
        bytes.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
        let count = u32::try_from(cpu_types.len()).expect("fixture architecture count");
        bytes.extend_from_slice(&count.to_be_bytes());
        for cpu in cpu_types {
            bytes.extend_from_slice(&cpu.to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_be_bytes());
            bytes.extend_from_slice(&0_u32.to_be_bytes());
        }
        bytes
    }

    fn inspect_bytes(bytes: &[u8]) -> crate::Result<super::BinaryInfo> {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("library");
        fs::write(&path, bytes).expect("fixture");
        inspect(&path)
    }

    #[test]
    fn inspects_x86_64_elf() {
        let info = inspect_bytes(&elf64(62)).expect("ELF");
        assert_eq!(info.format, BinaryFormat::Elf);
        assert_eq!(info.bits, 64);
        assert_eq!(info.architectures, vec![BinaryArchitecture::X86_64]);
    }

    #[test]
    fn inspects_aarch64_elf() {
        let info = inspect_bytes(&elf64(183)).expect("ELF");
        assert_eq!(info.architectures, vec![BinaryArchitecture::Aarch64]);
    }

    #[test]
    fn inspects_thin_mach_o() {
        let info = inspect_bytes(&mach64(0x0100_0007)).expect("Mach-O");
        assert_eq!(info.format, BinaryFormat::MachO);
        assert_eq!(info.bits, 64);
        assert_eq!(info.architectures, vec![BinaryArchitecture::X86_64]);
    }

    #[test]
    fn inspects_universal_mach_o() {
        let info = inspect_bytes(&fat_mach(&[0x0100_0007, 0x0100_000c])).expect("fat Mach-O");
        assert_eq!(info.format, BinaryFormat::MachO);
        assert_eq!(
            info.architectures,
            vec![BinaryArchitecture::X86_64, BinaryArchitecture::Aarch64]
        );
    }

    #[test]
    fn rejects_truncated_or_unknown_headers() {
        let truncated = inspect_bytes(b"\x7fELF").expect_err("truncated");
        assert_eq!(
            truncated.category,
            crate::ErrorCategory::UnknownBundleStructure
        );

        let unknown = inspect_bytes(b"not a shared library").expect_err("unknown");
        assert_eq!(
            unknown.category,
            crate::ErrorCategory::UnknownBundleStructure
        );
    }
}
