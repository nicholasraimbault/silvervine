//! Widevine acquisition.
//!
//! The [`manifest`], [`download`], [`extract`], and [`cache`] modules acquire
//! and verify the CDM consumed by the patch flow.
//!
//! Public surface re-exports the most-used types so consumers can
//! `use silvervine::widevine::{Manifest, fetch_manifest};` without reaching into
//! the submodule.

pub mod cache;
pub mod download;
pub mod extract;
pub mod manifest;
pub mod ownership;

/// CDM directory installed into a Chromium-family browser.
pub(crate) const CDM_BUNDLE_DIRECTORY: &str = "WidevineCdm";
/// Manifest filename at the root of an extracted or installed CDM.
pub(crate) const CDM_MANIFEST_FILENAME: &str = "manifest.json";
/// Parent directory for architecture-specific CDM libraries.
pub(crate) const PLATFORM_SPECIFIC_DIRECTORY: &str = "_platform_specific";

/// Architecture directory used by Chromium's extracted CDM layout.
pub(crate) const fn platform_directory(platform: Platform) -> &'static str {
    match platform {
        Platform::LinuxX86_64 => "linux_x64",
        Platform::DarwinAarch64 => "mac_arm64",
        Platform::DarwinX86_64 => "mac_x64",
    }
}

/// Shared-library filename used by Chromium for a platform.
pub(crate) const fn platform_library(platform: Platform) -> &'static str {
    match platform {
        Platform::LinuxX86_64 => "libwidevinecdm.so",
        Platform::DarwinAarch64 | Platform::DarwinX86_64 => "libwidevinecdm.dylib",
    }
}

pub use cache::{
    current as current_cdm, default_cache_root, ensure_cdm_for, prune as prune_cache,
    rollback as rollback_cdm, verify_current_integrity, verify_integrity, CachedCdm, CdmCache,
};
pub use download::{default_download_dir, download_to, download_to_cache, sha512_hex, verify_file};
pub use extract::{extract_crx3, extract_crx3_bytes, parse_crx3_header, verify_widevine_layout};
pub use manifest::{
    cached_manifest_path, current_platform_key, fetch_manifest, fetch_manifest_with,
    parse_manifest, GmpVendor, Manifest, Platform, PlatformEntry,
};
