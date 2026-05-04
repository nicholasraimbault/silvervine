# V3 Localhost-Bridge: Scaffolding Plan

**Date:** 2026-05-04
**Status:** Plan — awaiting user approval before implementation
**Relates to:** [V2 design spec](./2026-05-04-neon-rust-rewrite-design.md), [ROADMAP](../../../ROADMAP.md), [orchestrator status (V3 decisions)](../teams/orchestrator/status.md)

## Summary

Land minimal architectural hooks in V2 codebase that make a future V3 `neon localhost-bridge` feature trivial to plug in, **without committing any V3 implementation now**. The scaffolding is:

1. Cargo feature flag `experimental-bridge` (off by default)
2. Empty `src/bridge/mod.rs` module gated behind that feature
3. Hidden `neon stream <url>` subcommand that returns "not yet implemented" when the feature is on; doesn't appear in `--help` when feature is off
4. A `CdmProvider` trait abstraction that lets the patch flow consume CDM bytes from any source (local cache today; remote bridge in V3)
5. ROADMAP + spec cross-references documenting what V3 will do

The goal: when V3 work begins (after V1.0 ships and stabilizes), the developer doesn't refactor working V2 code — they fill in stubs behind an existing feature flag.

## Motivation

Two reasons to scaffold now rather than defer entirely:

1. **Avoid future refactors.** The CdmProvider trait converts `widevine::cache::current()` from "returns local file path" to "returns CDM bytes from any source." V2 patch flow already calls a single function for this; introducing the trait now is ~50 lines of refactor and avoids a much bigger one in V3.

2. **Set user expectations.** ROADMAP.md already promises V3 stretch goal; having a real `experimental-bridge` flag in `cargo install --features ...` documentation gives users a concrete artifact to track. Even if it's only a stub, it signals "this is planned and structurally ready, not vapor."

## Non-goals

V3 scaffolding deliberately does NOT do:

- Add any QEMU/libvirt/Looking Glass dependency
- Add any Windows VM provisioning logic
- Add hardware capability detection (TPM/IOMMU/GPU) — that's queued for V1.1's `neon doctor --media-stack`
- Add the full `neon stream` orchestration logic
- Bundle any Win11 IoT LTSC artifacts
- Implement remote CDM serialization protocol
- Touch the cargo-dist release pipeline (the experimental feature won't be in the default build)

## Architecture

### Cargo feature flag plumbing

```toml
# Cargo.toml additions

[features]
default = []
# Umbrella for all experimental features. Future flags can require this.
experimental = []
# V3 stretch: localhost-bridge for premium 4K HDR streaming.
# Activates the `bridge` module + `neon stream` subcommand.
experimental-bridge = ["experimental"]
```

`cargo install neon` (or the curl|sh installer) builds with default features only — a lean V2 binary identical to today's.

`cargo install neon --features experimental-bridge` enables the bridge module. Documentation in CONTRIBUTING.md and ROADMAP.md.

### `src/bridge/mod.rs` skeleton

```rust
// src/bridge/mod.rs — only compiled when `experimental-bridge` feature is on.

//! V3 localhost-bridge — experimental.
//!
//! Automates the QEMU/KVM + Win11 IoT LTSC + Looking Glass + GPU/TPM
//! passthrough setup that delivers premium 4K HDR streaming
//! (Netflix, Disney+, etc.) on Linux Chromium-family browsers.
//!
//! See `docs/superpowers/specs/2026-05-04-neon-v3-localhost-bridge-scaffolding-plan.md`
//! for the gap analysis and architecture.
//!
//! Currently only contains type stubs and the [`stream`] entry point
//! which returns `Error::other("not yet implemented")`. The real V3
//! implementation lands after V1.0 ships and stabilizes.

use crate::error::{Error, Result};

/// Top-level entry from `cli::stream::run`. Provisions the bridge VM
/// (idempotent), boots Edge in the guest pointed at `target_url`, and
/// connects the Linux host's Looking Glass client.
pub fn stream(_target_url: &str) -> Result<()> {
    Err(Error::other(
        "neon stream is queued for V3; current build is a stub. \
         Track ROADMAP.md and the localhost-bridge scaffolding plan."
    ))
}

/// Hardware capability snapshot consumed by the wizard.
///
/// **Stub.** V3 fills in TPM 2.0, IOMMU, GPU model, RAM checks.
#[derive(Debug, Clone)]
pub struct HardwareCapabilities;

impl HardwareCapabilities {
    /// Detect host capabilities. Stub returns an empty struct.
    #[must_use]
    pub fn detect() -> Self {
        Self
    }
}
```

### `src/cli/stream.rs` subcommand stub

```rust
// src/cli/stream.rs — only compiled when `experimental-bridge` feature is on.

use crate::error::Result;

/// Args for `neon stream <target_url>`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// URL to open in the bridged browser (e.g. `https://netflix.com`).
    pub target_url: String,
}

pub fn run(args: &Args) -> Result<()> {
    crate::bridge::stream(&args.target_url)
}
```

### `src/main.rs` integration

```rust
// Inside the Subcommand enum:

#[cfg(feature = "experimental-bridge")]
/// Bridge a URL to a guest VM with hardware-backed Widevine
/// (experimental; requires --features experimental-bridge).
Stream(crate::cli::stream::Args),

// Inside the dispatcher:

#[cfg(feature = "experimental-bridge")]
Some(Command::Stream(args)) => crate::cli::stream::run(&args),
```

When the feature is **off**, `Stream` doesn't exist as a variant — `neon --help` doesn't list it. When **on**, `neon stream --help` works, but invoking it returns the stub error.

### CdmProvider trait abstraction

This is the load-bearing piece — adds optionality to the patch flow without changing V2 behavior.

```rust
// src/widevine/provider.rs (new file)

use std::path::Path;
use crate::error::Result;

/// Source of Widevine CDM bytes for the patch flow.
///
/// V2 only ever uses [`LocalFileCdm`] (reads from `~/.cache/neon/widevine/<v>/`).
/// V3 will introduce a `BridgeCdm` impl that fetches CDM bytes from a
/// running localhost-bridge VM over a Unix socket / vsock, enabling
/// hardware-attested L1 playback paths.
///
/// The patch flow calls [`provider`](current_provider) once, then uses
/// the returned trait object to populate the target browser's
/// `WidevineCdm/` directory.
pub trait CdmProvider: Send + Sync {
    /// CDM version string (matches the `version` field in Mozilla's manifest).
    fn version(&self) -> &str;

    /// Copy CDM payload into `dest`. `dest` is an empty directory the
    /// caller has already created. Implementations write `manifest.json`,
    /// `LICENSE`, and the platform-specific `_platform_specific/<arch>/libwidevinecdm.{so,dylib,dll}`.
    fn populate(&self, dest: &Path) -> Result<()>;

    /// Optional: SHA-512 of the primary CDM binary (for integrity checks).
    /// Returns `None` for providers that don't expose a stable hash
    /// (e.g. a remote bridge that re-bundles per-call).
    fn sha512_hex(&self) -> Option<&str>;
}
```

V2 implementation (lifted from `widevine::cache`):

```rust
pub struct LocalFileCdm {
    /* version + path to ~/.cache/neon/widevine/<v>/ */
}

impl CdmProvider for LocalFileCdm {
    fn version(&self) -> &str { /* ... */ }
    fn populate(&self, dest: &Path) -> Result<()> { /* cp -R the existing dir */ }
    fn sha512_hex(&self) -> Option<&str> { /* read from manifest */ }
}
```

V3 implementation (future, in `src/bridge/cdm.rs`):

```rust
#[cfg(feature = "experimental-bridge")]
pub struct BridgeCdm {
    socket_path: PathBuf,  // ~/.cache/neon/bridge.sock
}

#[cfg(feature = "experimental-bridge")]
impl CdmProvider for BridgeCdm {
    fn version(&self) -> &str { /* query bridge VM */ }
    fn populate(&self, dest: &Path) -> Result<()> { /* ... */ }
    fn sha512_hex(&self) -> Option<&str> { None }  // bridge re-bundles
}
```

The patch flow (`patch::patch_browser`) takes `&dyn CdmProvider` instead of `&CachedCdm`. V2 always passes `&LocalFileCdm`; V3 can pass either.

### ROADMAP cross-reference

Update `ROADMAP.md`'s V3 section to point at this plan:

```markdown
### V3 — `neon localhost-bridge` (experimental Cargo feature)

Architecture and scaffolding plan: [V3 scaffolding plan](docs/superpowers/specs/2026-05-04-neon-v3-localhost-bridge-scaffolding-plan.md).

Activated by:
```sh
cargo install neon --features experimental-bridge
```

V2 ships only the scaffolding (feature flag, stub subcommand, CdmProvider
trait abstraction). The real implementation lands after V1.0 stabilizes.
```

## Deliverables

| # | File | Action | Owner |
|---|---|---|---|
| 1 | `Cargo.toml` | Add `[features]` block with `experimental-bridge` | infra/orchestrator |
| 2 | `src/widevine/provider.rs` | New file — `CdmProvider` trait + `LocalFileCdm` impl | core-engine |
| 3 | `src/widevine/mod.rs` | Re-export `CdmProvider`, `LocalFileCdm` | core-engine |
| 4 | `src/widevine/cache.rs` | Add adapter that returns `LocalFileCdm` from `current()` | core-engine |
| 5 | `src/patch/mod.rs` | Change `patch_browser` to take `&dyn CdmProvider` | core-engine |
| 6 | `src/bridge/mod.rs` | New file — gated `#[cfg(feature = "experimental-bridge")]`; stub `stream()` + `HardwareCapabilities` | infra/orchestrator |
| 7 | `src/cli/stream.rs` | New file — gated; `Args` struct + `run()` | cli |
| 8 | `src/cli/mod.rs` | Conditionally re-export `stream` module | cli |
| 9 | `src/main.rs` | Conditionally add `Stream` variant + dispatch | cli |
| 10 | `src/lib.rs` | Conditionally `pub mod bridge;` | infra/orchestrator |
| 11 | `ROADMAP.md` | Update V3 section to point at this plan | infra/orchestrator |
| 12 | `CONTRIBUTING.md` | Add "experimental features" section explaining the flag | infra/orchestrator |
| 13 | `tests/feature_flag.rs` | Integration test verifying `cargo build` works with and without the flag | infra/orchestrator |

## Test strategy

### Unit tests

- `widevine::provider::tests` — verify `LocalFileCdm::populate` round-trips correctly using `tempfile::TempDir`
- `widevine::provider::tests` — verify `version()` and `sha512_hex()` match the values in the synthesized manifest
- `widevine::provider::tests` — verify `CdmProvider` is object-safe (compile-time test: `let _: Box<dyn CdmProvider> = Box::new(LocalFileCdm::stub());`)

### Integration tests

- `tests/feature_flag.rs` — run as a build-time check:
  - `cargo check` (default) passes
  - `cargo check --features experimental-bridge` passes
  - With feature enabled, `neon --help` shows `stream`
  - With feature enabled, `neon stream https://example.com` returns the stub error message

### Refactor verification

The CdmProvider refactor is the load-bearing change. After applying it:
- All 456 existing tests must still pass
- No new failed tests
- `cargo clippy --all-targets -- -D warnings` clean
- `cargo build --release` produces a binary the same size ±1% as before (sanity check that LTO/inlining still works through the trait)

## Acceptance criteria

- [ ] `cargo check` passes with default features (no V3 code compiled)
- [ ] `cargo check --features experimental-bridge` passes
- [ ] `cargo test --lib --jobs 2` reports 460+ tests passing (456 existing + 4-6 new)
- [ ] `cargo fmt --check` clean
- [ ] `cargo clippy --all-targets --jobs 2 -- -D warnings` clean
- [ ] With feature enabled, `./target/debug/neon stream https://netflix.com` exits with the stub error (non-zero) and a message pointing at ROADMAP
- [ ] With feature disabled, `./target/debug/neon --help` does not list `stream`
- [ ] Default `cargo build --release` produces a binary within 1% of pre-scaffolding size
- [ ] ROADMAP.md updated with cross-link to this plan
- [ ] CONTRIBUTING.md documents the experimental feature flag

## Estimated effort

~3-4 hours of focused work, single team:
- Cargo feature flag plumbing: 30 min
- CdmProvider trait + LocalFileCdm impl: 1 hour
- Refactor patch::patch_browser to take &dyn CdmProvider: 30 min
- Bridge module + stream subcommand stubs: 30 min
- Tests: 30 min
- ROADMAP/CONTRIBUTING updates: 15 min
- Verification + commit: 15 min

This is small enough to be one PR or one orchestrator-driven series of commits without needing to spawn additional agents.

## Out of scope (deferred to V3 implementation proper)

- libvirt domain XML generation
- Looking Glass IVSHMEM device configuration
- Windows IoT LTSC ISO download + verification
- Unattended Windows installation XML
- TPM/IOMMU/GPU hardware detection (queued for V1.1's `doctor --media-stack`)
- Bridge socket protocol (Unix socket / vsock)
- BridgeCdm implementation
- Wizard UX (`neon stream init`)
- Looking Glass IDD-host integration (waits on upstream IDD GA)
- HEVC Video Extension auto-install (it ships with IoT LTSC; just verify presence)

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| CdmProvider refactor introduces a regression | Low-medium | Existing 456-test suite catches; feature-flag-only changes are isolated |
| Trait object overhead measurably hurts patch performance | Very low | Patch is I/O-bound (file copy), not CPU-bound; trait dispatch is one indirection per browser |
| Feature flag adds complexity for V2 users | Negligible | Default build doesn't compile any V3 code; users see no change |
| Trait API has to break in V3 | Medium | Mitigation: keep V2 trait minimal; expand by adding new methods (default impls) rather than changing signatures |

## Why now vs. later

Doing this now (before V1.0 ships) costs ~3-4 hours and locks in a clean architectural seam. Doing it later (during V3 work) would mean:

- Refactoring `patch::patch_browser` while shipping a new feature → bigger blast radius
- Possibly already shipped V1.0 binaries that break compatibility with V3 (if we change the patch flow's public API)
- Higher risk of "let me just make the V3 implementation work without the trait" shortcuts that produce coupling

The CdmProvider trait specifically is what makes this scaffolding worthwhile. Without it, "V3 just adds a new subcommand" is the same as "V3 ships a fork." With it, V3 is "swap in BridgeCdm, the rest of the codebase doesn't care."

## Approval and handoff

After user approves this plan:

1. Orchestrator creates feature branch from `v2-rust-rewrite` (e.g. `feature/v3-scaffolding`) — keeps the scaffold isolated until merged
2. Orchestrator (or a single agent with the same guardrails as Phase 5) executes deliverables 1-13
3. Verify all acceptance criteria
4. Open PR to `v2-rust-rewrite`; merge after review
5. ROADMAP and CONTRIBUTING reflect the new flag
6. V3 scaffolding ships with V1.0 release as a "documented but inactive" feature
