//! Silvervine — single-binary cross-platform DRM (Widevine) helper for Chromium-family browsers.
//!
//! This is the library crate. The binary entrypoint lives in [`main.rs`](../src/main.rs).
//!
//! Module layout:
//!
//! * [`error`] — categorized [`Error`] / [`Result`] used everywhere.
//! * [`browsers`] — known-list constants, auto-discovery, custom-config TOML.
//! * [`widevine`] — Mozilla manifest fetch + (in Phase 2) CRX3 download/extract.
//! * [`config`] — global `~/.config/silvervine/config.toml` schema.
//! * [`lockfile`] — `flock`-based exclusive lock helper.
//! * [`platform`] — XDG/Apple paths, privilege escalation, atomic-rename.
//! * [`migration`] — migrate Neon V2 data and detect/remove legacy Neon V1 installs.
//!
//! The library exposes browser discovery, Widevine retrieval, atomic patching,
//! platform integration, and daemon support used by the `silvervine` binary.
//!
//! # Public API contracts
//!
//! | Module | Function / Type | Stability |
//! |---|---|---|
//! | `error` | `Error`, `ErrorCategory`, `Result<T>` | Stable — adding categories ok, renaming is breaking |
//! | `widevine` | `fetch_manifest(&[Url]) -> Result<Manifest>` | Stable |
//! | `widevine` | `Manifest`, `Platform`, `PLATFORM_KEY` | Stable |
//! | `browsers` | `detect_browsers() -> Vec<Browser>` | Stable |
//! | `browsers` | `Browser`, `BrowserKind`, `Platform` | Stable |
//! | `config` | `Config`, `load_config() -> Result<Config>` | Stable |
//! | `lockfile` | `with_lock(&Path, FnOnce) -> Result<T>` | Stable |

#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
// macOS FFI prose references Apple framework names (`AppKit`,
// `NSWorkspace`, `NSNotificationCenter`, …) too densely for the
// doc_markdown lint to be useful — backticking every instance in
// every doc paragraph is busywork that obscures the prose. Linux
// clippy never flagged this lint (cross-platform code doesn't trip
// it); keeping it on globally only created macOS-specific failures.
#![allow(clippy::doc_markdown)]

pub mod browsers;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod eme;
pub mod error;
pub mod hooks;
pub mod lockfile;
pub mod log;
pub mod migration;
pub mod notify;
pub mod patch;
pub mod platform;
pub mod widevine;

/// Test-only helpers — only exposed in test/dev builds. See module docs
/// for the env-mutation locking story.
#[cfg(any(test, debug_assertions))]
pub mod test_support;

pub use error::{Error, ErrorCategory, Result};
