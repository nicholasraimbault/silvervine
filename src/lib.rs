//! Neon — single-binary cross-platform DRM (Widevine) helper for Chromium-family browsers.
//!
//! This is the library crate. The binary entrypoint lives in [`main.rs`](../src/main.rs).
//!
//! Module layout (per `docs/superpowers/specs/2026-05-04-neon-rust-rewrite-design.md`):
//!
//! * [`error`] — categorized [`Error`] / [`Result`] used everywhere.
//! * [`browsers`] — known-list constants, auto-discovery, custom-config TOML.
//! * [`widevine`] — Mozilla manifest fetch + (in Phase 2) CRX3 download/extract.
//! * [`config`] — global `~/.config/neon/config.toml` schema.
//! * [`lockfile`] — `flock`-based exclusive lock helper.
//! * [`platform`] — XDG/Apple paths, privilege escalation, atomic-rename.
//! * [`migration`] — detect + remove legacy (V1) Neon installs.
//!
//! Phase 1 scope is the public API surface that Phase 2 (download + atomic
//! patching) will consume. Phase 1 deliberately ships **no platform syscalls**
//! and **no daemon code** — that lives in the Platform and Daemon teams'
//! modules.
//!
//! # Public API contracts (Phase 1)
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

/// V3 localhost-bridge — experimental, gated on `experimental-bridge`.
///
/// Default builds compile no V3 code. Activate with:
///
/// ```sh
/// cargo install neon --features experimental-bridge
/// ```
///
/// See [`bridge`] for the full module documentation.
#[cfg(feature = "experimental-bridge")]
pub mod bridge;

pub use error::{Error, ErrorCategory, Result};
