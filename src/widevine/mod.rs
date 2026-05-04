//! Widevine acquisition.
//!
//! Phase 1 shipped [`manifest`]. Phase 2 adds [`download`], [`extract`],
//! and [`cache`].
//!
//! Public surface re-exports the most-used types so consumers can
//! `use neon::widevine::{Manifest, fetch_manifest};` without reaching into
//! the submodule.

pub mod cache;
pub mod download;
pub mod extract;
pub mod manifest;

pub use cache::{
    current as current_cdm, default_cache_root, ensure_cdm_for, prune as prune_cache,
    rollback as rollback_cdm, verify_integrity, CachedCdm,
};
pub use download::{default_download_dir, download_to, download_to_cache, sha512_hex, verify_file};
pub use extract::{extract_crx3, extract_crx3_bytes, parse_crx3_header, verify_widevine_layout};
pub use manifest::{
    cached_manifest_path, current_platform_key, fetch_manifest, fetch_manifest_with,
    parse_manifest, GmpVendor, Manifest, Platform, PlatformEntry,
};
