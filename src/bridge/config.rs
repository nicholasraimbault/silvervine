//! Bridge configuration overrides — V3-Phase F.
//!
//! Loads `~/.config/neon/bridge.toml` (when present) and merges its
//! per-section override values with the compiled-in defaults from V3
//! sub-phases. Anything the user puts under `[iso]`, `[sunshine]`, or
//! `[bridge]` wins over the defaults; missing sections fall back to
//! whatever V3-Phase C / D pinned at compile time.
//!
//! ## Why this exists
//!
//! V3-Phase C pinned a Microsoft Win11 `IoT` LTSC ISO URL + SHA-256 + a
//! Sunshine installer URL + SHA-256. Microsoft rotates the eval-center
//! URL ~yearly; users who hit the failure (a `NetworkError` or
//! `HashMismatch`) need a way to fix it without rebuilding `neon` from
//! source. `bridge.toml` is that escape hatch — point at the latest URL,
//! supply the new SHA, run `neon stream init` again.
//!
//! ## File location
//!
//! `~/.config/neon/bridge.toml` (XDG-aware; honors
//! `XDG_CONFIG_HOME`). The same file already stores the
//! [`crate::bridge::license::LicensePosture`] under `[license]`. Phase F
//! adds three new sections that are all optional:
//!
//! ```toml
//! [iso]
//! url = "https://software-download.microsoft.com/db/..."
//! sha256 = "abcd..."
//! expected_size = 6500000000   # bytes; optional
//!
//! [sunshine]
//! url = "https://github.com/LizardByte/Sunshine/releases/download/.../sunshine-windows-installer.exe"
//! sha256 = "0000..."
//!
//! [bridge]
//! data_dir = "/mnt/external-ssd/neon-bridge"   # override default ~/.local/share/neon/bridge/
//! ram_mb = 8192                                 # override VM RAM
//! vcpus = 4                                     # override VM CPU count
//! ivshmem_size_mb = 64                          # Looking Glass IVSHMEM size
//! ```
//!
//! ## Public API
//!
//! [`load`] returns a [`BridgeConfig`] (all fields `Option`) that callers
//! merge into their compiled-in defaults via [`apply_iso_override`],
//! [`apply_sunshine_override`], [`apply_provision_overrides`] etc.
//!
//! ## Test mode
//!
//! Tests pass a tempdir-resident `bridge.toml` via [`load_from`] to
//! exercise the round-trip without touching the user's real config dir.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bridge::iso::IsoSpec;
use crate::bridge::unattended::UnattendedOptions;
use crate::error::{Error, Result};

/// `[iso]` block — overrides for the Win11 `IoT` LTSC ISO descriptor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct IsoOverride {
    /// Override the pinned download URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Override the expected SHA-256 hex digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Override the expected size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
}

/// `[sunshine]` block — overrides for the Sunshine installer descriptor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SunshineOverride {
    /// Override the Sunshine installer URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Override the expected SHA-256 hex digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// `[bridge]` block — VM sizing + storage overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BridgeOverride {
    /// Override the VM data directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<PathBuf>,
    /// Override the VM RAM allocation in MB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ram_mb: Option<u32>,
    /// Override the VM vCPU count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcpus: Option<u32>,
    /// Override the Looking Glass IVSHMEM size in MB.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ivshmem_size_mb: Option<u32>,
}

/// Top-level shape of `~/.config/neon/bridge.toml` for V3-Phase F.
///
/// Merges with [`crate::bridge::license`]'s `[license]` block (license
/// reads ignore the override sections; this module ignores `[license]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct BridgeConfig {
    /// `[iso]` overrides.
    #[serde(skip_serializing_if = "is_default_iso")]
    pub iso: IsoOverride,
    /// `[sunshine]` overrides.
    #[serde(skip_serializing_if = "is_default_sunshine")]
    pub sunshine: SunshineOverride,
    /// `[bridge]` overrides.
    #[serde(skip_serializing_if = "is_default_bridge")]
    pub bridge: BridgeOverride,
}

fn is_default_iso(o: &IsoOverride) -> bool {
    o == &IsoOverride::default()
}
fn is_default_sunshine(o: &SunshineOverride) -> bool {
    o == &SunshineOverride::default()
}
fn is_default_bridge(o: &BridgeOverride) -> bool {
    o == &BridgeOverride::default()
}

/// Default `bridge.toml` path. Returns `None` if the XDG config directory
/// is unresolvable (essentially never on Unix).
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    crate::bridge::license::default_bridge_config_path()
}

/// Load `bridge.toml` from the canonical XDG path. Returns
/// [`BridgeConfig::default`] when the file does not exist.
///
/// # Errors
///
/// * [`crate::ErrorCategory::StateCorrupted`] — the file exists but is
///   malformed or contains unknown fields under `[iso]` / `[sunshine]` /
///   `[bridge]`.
pub fn load() -> Result<BridgeConfig> {
    let Some(path) = default_path() else {
        return Ok(BridgeConfig::default());
    };
    load_from(&path)
}

/// Like [`load`] but reads from an explicit path. Tests point this at a
/// tempdir-resident `bridge.toml`.
///
/// # Errors
///
/// See [`load`].
pub fn load_from(path: &Path) -> Result<BridgeConfig> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BridgeConfig::default()),
        Err(e) => return Err(Error::from(e)),
    };
    // We deliberately tolerate unknown top-level keys (the `[license]`
    // block lives in this same file). Each *section* uses
    // `deny_unknown_fields` so a typo'd key inside `[iso]` does still
    // fail loudly.
    let cfg: BridgeConfig = toml::from_str(&raw).map_err(|e| {
        Error::state_corrupted(format!(
            "bridge.toml at {} is malformed: {e}",
            path.display()
        ))
    })?;
    Ok(cfg)
}

/// Apply `[iso]` override values to a baseline [`IsoSpec`]. Fields the
/// user didn't set keep the baseline value.
#[must_use]
pub fn apply_iso_override(baseline: IsoSpec, ov: &IsoOverride) -> IsoSpec {
    IsoSpec {
        url: ov.url.clone().unwrap_or(baseline.url),
        sha256: ov.sha256.clone().unwrap_or(baseline.sha256),
        expected_size: ov.expected_size.unwrap_or(baseline.expected_size),
    }
}

/// Apply `[sunshine]` override values to a baseline
/// [`UnattendedOptions`]. Fields the user didn't set keep the baseline
/// value.
#[must_use]
pub fn apply_sunshine_override(
    mut baseline: UnattendedOptions,
    ov: &SunshineOverride,
) -> UnattendedOptions {
    if let Some(u) = ov.url.clone() {
        baseline.sunshine_url = u;
    }
    if let Some(s) = ov.sha256.clone() {
        baseline.sunshine_sha256 = s;
    }
    baseline
}

/// Apply `[bridge]` overrides to install [`crate::bridge::install::ProvisionOpts`].
/// Fields the user didn't set keep the baseline value. Returns the
/// updated opts.
#[must_use]
pub fn apply_provision_overrides(
    mut opts: crate::bridge::install::ProvisionOpts,
    ov: &BridgeOverride,
) -> crate::bridge::install::ProvisionOpts {
    if let Some(dir) = ov.data_dir.clone() {
        opts.data_root = dir;
    }
    // RAM / vCPU / IVSHMEM are wired through the libvirt domain XML
    // renderer; ProvisionOpts only carries `host_ram_total_bytes` +
    // `host_cpu_count` (which size the VM via DomainSpec::sized_for_host).
    // We convert "user wants 8192 MB of guest RAM" into "tell sized_for_host
    // that the host has 4× that, so its host/4 division yields 8192".
    // Same for CPU count.
    if let Some(ram_mb) = ov.ram_mb {
        // sized_for_host clamps result between 4096..=16384; pick a host total
        // that lands inside that range when divided by 4. We deliberately
        // expose the override even when the requested value is outside the
        // clamp range — the wizard's downstream sizing will then clamp it,
        // and the user sees a clean value in `neon stream status`.
        opts.host_ram_total_bytes = u64::from(ram_mb) * 1024 * 1024 * 4;
    }
    if let Some(vcpus) = ov.vcpus {
        opts.host_cpu_count = vcpus;
    }
    let _ = ov.ivshmem_size_mb; // wired into DomainSpec via apply_domain_overrides
    opts
}

/// Apply `[bridge]` IVSHMEM override to a baseline
/// [`crate::bridge::libvirt_xml::DomainSpec`]. Other knobs in
/// `[bridge]` are applied at the [`apply_provision_overrides`] level
/// (they go through `ProvisionOpts` → `sized_for_host`).
#[must_use]
pub fn apply_domain_overrides(
    mut spec: crate::bridge::libvirt_xml::DomainSpec,
    ov: &BridgeOverride,
) -> crate::bridge::libvirt_xml::DomainSpec {
    if let Some(size) = ov.ivshmem_size_mb {
        spec.ivshmem_size_mb = size;
    }
    if let Some(ram_mb) = ov.ram_mb {
        spec.ram_mb = ram_mb;
    }
    if let Some(vcpus) = ov.vcpus {
        spec.vcpus = vcpus;
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Empty file → all-defaults config.
    #[test]
    fn missing_file_returns_default() {
        let tmp = TempDir::new().expect("tempdir");
        let cfg = load_from(&tmp.path().join("nope.toml")).expect("load");
        assert_eq!(cfg, BridgeConfig::default());
    }

    /// File exists with only `[license]` (V3-Phase C posture) → load
    /// returns defaults for the V3-Phase F sections.
    #[test]
    fn license_only_file_returns_defaults_for_iso_sunshine_bridge() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(
            &path,
            "[license]\nmode = \"trial\"\naccepted_at = 1700000000\n",
        )
        .expect("write");
        let cfg = load_from(&path).expect("load");
        assert_eq!(cfg.iso, IsoOverride::default());
        assert_eq!(cfg.sunshine, SunshineOverride::default());
        assert_eq!(cfg.bridge, BridgeOverride::default());
    }

    /// Round-trip `[iso]` overrides through TOML.
    #[test]
    fn iso_override_round_trip() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(
            &path,
            r#"[iso]
url = "https://example.com/win.iso"
sha256 = "deadbeefcafebabe1234567890abcdef0123456789abcdef0123456789abcdef"
expected_size = 7000000000
"#,
        )
        .expect("write");
        let cfg = load_from(&path).expect("load");
        assert_eq!(cfg.iso.url.as_deref(), Some("https://example.com/win.iso"));
        assert!(cfg.iso.sha256.as_deref().unwrap().starts_with("deadbeef"));
        assert_eq!(cfg.iso.expected_size, Some(7_000_000_000));
    }

    /// Round-trip `[sunshine]` overrides through TOML.
    #[test]
    fn sunshine_override_round_trip() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(
            &path,
            r#"[sunshine]
url = "https://github.com/LizardByte/Sunshine/releases/download/v0.24.0/sunshine-windows-installer.exe"
sha256 = "0011223344556677889900112233445566778899001122334455667788990011"
"#,
        )
        .expect("write");
        let cfg = load_from(&path).expect("load");
        assert_eq!(
            cfg.sunshine.url.as_deref(),
            Some(
                "https://github.com/LizardByte/Sunshine/releases/download/v0.24.0/sunshine-windows-installer.exe"
            )
        );
        assert!(cfg.sunshine.sha256.is_some());
    }

    /// Round-trip `[bridge]` overrides through TOML.
    #[test]
    fn bridge_override_round_trip() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(
            &path,
            r#"[bridge]
data_dir = "/mnt/ssd/neon-bridge"
ram_mb = 16384
vcpus = 8
ivshmem_size_mb = 128
"#,
        )
        .expect("write");
        let cfg = load_from(&path).expect("load");
        assert_eq!(
            cfg.bridge.data_dir.as_deref(),
            Some(Path::new("/mnt/ssd/neon-bridge"))
        );
        assert_eq!(cfg.bridge.ram_mb, Some(16384));
        assert_eq!(cfg.bridge.vcpus, Some(8));
        assert_eq!(cfg.bridge.ivshmem_size_mb, Some(128));
    }

    /// Malformed TOML routes to `StateCorrupted` with the path in the
    /// error message.
    #[test]
    fn malformed_toml_routes_to_state_corrupted() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(&path, "[iso\nthis is not valid").expect("write");
        let err = load_from(&path).expect_err("malformed");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
        assert!(err.to_string().contains("bridge.toml"));
    }

    /// Unknown field inside `[iso]` is rejected (catches typos).
    #[test]
    fn unknown_iso_field_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(&path, "[iso]\nfoobar = 1\n").expect("write");
        let err = load_from(&path).expect_err("typo");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    /// `apply_iso_override` keeps baseline values when override is empty.
    #[test]
    fn apply_iso_override_empty_keeps_baseline() {
        let baseline = IsoSpec {
            url: "https://baseline".into(),
            sha256: "00".repeat(32),
            expected_size: 1024,
        };
        let result = apply_iso_override(baseline.clone(), &IsoOverride::default());
        assert_eq!(result, baseline);
    }

    /// `apply_iso_override` replaces only the fields the user set.
    #[test]
    fn apply_iso_override_partial_replacement() {
        let baseline = IsoSpec {
            url: "https://baseline".into(),
            sha256: "00".repeat(32),
            expected_size: 1024,
        };
        let ov = IsoOverride {
            url: Some("https://override".into()),
            sha256: None,
            expected_size: None,
        };
        let result = apply_iso_override(baseline, &ov);
        assert_eq!(result.url, "https://override");
        assert_eq!(result.sha256, "00".repeat(32));
        assert_eq!(result.expected_size, 1024);
    }

    /// `apply_sunshine_override` empty → baseline unchanged.
    #[test]
    fn apply_sunshine_override_empty_keeps_baseline() {
        let baseline =
            UnattendedOptions::defaults_for(crate::bridge::license::LicensePosture::Eval {
                accepted_at: 1,
            });
        let baseline_url = baseline.sunshine_url.clone();
        let result = apply_sunshine_override(baseline, &SunshineOverride::default());
        assert_eq!(result.sunshine_url, baseline_url);
    }

    /// `apply_sunshine_override` replaces fields user set.
    #[test]
    fn apply_sunshine_override_replaces_url_and_sha() {
        let baseline =
            UnattendedOptions::defaults_for(crate::bridge::license::LicensePosture::Eval {
                accepted_at: 1,
            });
        let ov = SunshineOverride {
            url: Some("https://example.com/sun.exe".into()),
            sha256: Some("ff".repeat(32)),
        };
        let result = apply_sunshine_override(baseline, &ov);
        assert_eq!(result.sunshine_url, "https://example.com/sun.exe");
        assert_eq!(result.sunshine_sha256, "ff".repeat(32));
    }

    /// `apply_provision_overrides` overrides `data_dir`.
    #[test]
    fn apply_provision_overrides_data_dir() {
        let opts = crate::bridge::install::ProvisionOpts::defaults_for(
            crate::bridge::license::LicensePosture::Eval { accepted_at: 1 },
            32u64 * 1024 * 1024 * 1024,
            8,
            None,
        );
        let ov = BridgeOverride {
            data_dir: Some(PathBuf::from("/mnt/ssd/n-bridge")),
            ..BridgeOverride::default()
        };
        let result = apply_provision_overrides(opts, &ov);
        assert_eq!(result.data_root, PathBuf::from("/mnt/ssd/n-bridge"));
    }

    /// `apply_domain_overrides` plumbs ivshmem + ram + vcpus.
    #[test]
    fn apply_domain_overrides_plumb_ivshmem_ram_vcpus() {
        let spec = crate::bridge::libvirt_xml::DomainSpec::sized_for_host(
            "neon-bridge",
            32u64 * 1024 * 1024 * 1024,
            8,
            PathBuf::from("/x/disk.qcow2"),
            PathBuf::from("/x/win.iso"),
            PathBuf::from("/x/aux.iso"),
            None,
        );
        let original_ram = spec.ram_mb;
        let ov = BridgeOverride {
            ivshmem_size_mb: Some(128),
            ram_mb: Some(original_ram + 1024),
            vcpus: Some(2),
            ..BridgeOverride::default()
        };
        let result = apply_domain_overrides(spec, &ov);
        assert_eq!(result.ivshmem_size_mb, 128);
        assert_eq!(result.ram_mb, original_ram + 1024);
        assert_eq!(result.vcpus, 2);
    }

    /// Combined `[license]` + `[iso]` blocks parse cleanly.
    #[test]
    fn license_plus_iso_blocks_load_correctly() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(
            &path,
            r#"[license]
mode = "trial"
accepted_at = 1700000000

[iso]
url = "https://example.com/win.iso"
"#,
        )
        .expect("write");
        let cfg = load_from(&path).expect("load");
        assert_eq!(cfg.iso.url.as_deref(), Some("https://example.com/win.iso"));
    }

    /// `default_path` ends with `neon/bridge.toml`.
    #[test]
    fn default_path_ends_with_neon_bridge_toml() {
        if let Some(p) = default_path() {
            let suffix = std::path::Path::new("neon").join("bridge.toml");
            assert!(p.ends_with(&suffix), "got {}", p.display());
        }
    }

    /// `expected_size` defaults to baseline when override is None.
    #[test]
    fn iso_override_size_falls_back_to_baseline() {
        let baseline = IsoSpec {
            url: "u".into(),
            sha256: "00".repeat(32),
            expected_size: 6_500_000_000,
        };
        let result = apply_iso_override(baseline.clone(), &IsoOverride::default());
        assert_eq!(result.expected_size, 6_500_000_000);
    }

    /// `load` (no path arg) returns `Ok(default)` when no XDG config home set.
    #[test]
    fn load_with_unset_xdg_returns_default() {
        let _g = crate::test_support::env_lock();
        let tmp = TempDir::new().expect("tempdir");
        // SAFETY: env behind env_lock.
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        }
        let cfg = load().expect("load");
        // No file present at XDG_CONFIG_HOME/neon/bridge.toml → defaults.
        assert_eq!(cfg, BridgeConfig::default());
        unsafe {
            std::env::remove_var("XDG_CONFIG_HOME");
        }
    }

    /// `apply_provision_overrides` ram override actually impacts `host_ram_total_bytes`.
    #[test]
    fn apply_provision_overrides_ram_mb_replaces_host_total() {
        let opts = crate::bridge::install::ProvisionOpts::defaults_for(
            crate::bridge::license::LicensePosture::Eval { accepted_at: 1 },
            32u64 * 1024 * 1024 * 1024,
            8,
            None,
        );
        let ov = BridgeOverride {
            ram_mb: Some(8192),
            ..BridgeOverride::default()
        };
        let result = apply_provision_overrides(opts, &ov);
        // 8192 MB requested → set host_ram_total to 4× that so sized_for_host
        // yields exactly 8192 (within the 4..=16 clamp range).
        assert_eq!(result.host_ram_total_bytes, 8192u64 * 1024 * 1024 * 4);
    }
}
