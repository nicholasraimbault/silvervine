//! Widevine acquisition.
//!
//! Phase 1 ships [`manifest`] only. Phase 2 will add `download`, `extract`,
//! and `cache` submodules per the spec's module layout.
//!
//! Public surface re-exports the most-used types so consumers can
//! `use neon::widevine::{Manifest, fetch_manifest};` without reaching into
//! the submodule.

pub mod manifest;

pub use manifest::{
    cached_manifest_path, current_platform_key, fetch_manifest, fetch_manifest_with,
    parse_manifest, GmpVendor, Manifest, Platform, PlatformEntry,
};
