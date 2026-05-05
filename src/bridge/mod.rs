//! V3 localhost-bridge — experimental.
//!
//! Automates the QEMU/KVM + Win11 IoT LTSC + Looking Glass + GPU/TPM
//! passthrough setup that delivers premium 4K HDR streaming
//! (Netflix, Disney+, etc.) on Linux Chromium-family browsers.
//!
//! See `docs/superpowers/specs/2026-05-04-neon-v3-localhost-bridge-scaffolding-plan.md`
//! and `docs/superpowers/plans/2026-05-04-neon-v3-orchestration-plan.md`
//! for the gap analysis and architecture.
//!
//! This module is **only compiled when the `experimental-bridge`
//! feature is enabled**. Default builds of `neon` do not include any of
//! this code; users opt in via:
//!
//! ```sh
//! cargo install neon --features experimental-bridge
//! ```
//!
//! ## Status: stub-only
//!
//! V3-Phase A (this module's scaffolding phase) ships only:
//!
//! * The [`stream`] entry point that returns an
//!   [`crate::ErrorCategory::Other`] error pointing at ROADMAP.md.
//! * The [`HardwareCapabilities`] type stub (V3-Phase B will fill it
//!   with real TPM 2.0 / IOMMU / GPU / RAM / disk detection).
//!
//! The actual VM provisioning, libvirt domain XML generation, Looking
//! Glass integration, and CDM forwarding all land in V3-Phase C / D /
//! E / F. None of that code exists yet.

use crate::error::{Error, Result};
use crate::platform::capabilities::BridgeCapabilities;

pub mod remediation;

/// Top-level entry from `cli::stream::run`. Provisions the bridge VM
/// (idempotent), boots Edge in the guest pointed at `target_url`, and
/// connects the Linux host's Looking Glass client.
///
/// V3-Phase A scaffolding: this is a stub that returns an error
/// pointing the user at ROADMAP.md. The real V3 implementation lands
/// after V1.0 ships and stabilizes.
///
/// # Errors
///
/// Always returns [`crate::ErrorCategory::Other`] in V2 — the
/// localhost-bridge feature is not yet implemented.
pub fn stream(_target_url: &str) -> Result<()> {
    Err(Error::other(
        "neon stream is queued for V3; current build is a stub. \
         Track ROADMAP.md and the localhost-bridge scaffolding plan \
         (docs/superpowers/specs/2026-05-04-neon-v3-localhost-bridge-scaffolding-plan.md).",
    ))
}

/// Hardware capability snapshot consumed by the V3 bridge wizard.
///
/// V3-Phase B wires this to [`crate::platform::capabilities::detect`],
/// which probes the host's TPM, IOMMU, CPU virtualization, GPU, kernel
/// modules, free disk, RAM, and display surface. The wrapper exists so
/// future V3 phases can attach bridge-specific helpers (e.g. "is the
/// guest VM compatible with this snapshot?") without widening the
/// `platform::capabilities` API surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareCapabilities {
    /// Underlying capability snapshot from
    /// [`crate::platform::capabilities`].
    pub inner: BridgeCapabilities,
}

impl HardwareCapabilities {
    /// Detect host capabilities. V3-Phase B uses
    /// [`crate::platform::capabilities::detect`] — the real probe path.
    /// Tests can construct a [`HardwareCapabilities`] directly via
    /// [`Self::with`] passing a synthesized [`BridgeCapabilities`].
    #[must_use]
    pub fn detect() -> Self {
        Self {
            inner: crate::platform::capabilities::detect(),
        }
    }

    /// Construct from a known [`BridgeCapabilities`]. Used by tests and
    /// by future V3 phases that have a snapshot from elsewhere.
    #[must_use]
    pub fn with(inner: BridgeCapabilities) -> Self {
        Self { inner }
    }

    /// Compute outstanding capability issues for this snapshot.
    ///
    /// Convenience wrapper around [`remediation::issues_for`].
    #[must_use]
    pub fn issues(&self) -> Vec<remediation::CapabilityIssue> {
        remediation::issues_for(&self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `stream` returns the stub error pointing at ROADMAP.md.
    #[test]
    fn stream_returns_stub_error() {
        let err = stream("https://example.com").expect_err("must error");
        assert_eq!(err.category, crate::ErrorCategory::Other);
        assert!(err.to_string().contains("V3"));
        assert!(err.to_string().contains("ROADMAP"));
    }

    /// `HardwareCapabilities::detect` builds a non-stub snapshot.
    #[test]
    fn hardware_capabilities_detect_returns_real_snapshot() {
        let caps = HardwareCapabilities::detect();
        // We don't assert specific values — host hardware varies.
        // Smoke-test: kernel.version is non-empty on every supported OS.
        assert!(!caps.inner.kernel.version.is_empty());
    }

    /// `with` constructs from a synthesized snapshot and `issues()`
    /// runs without panic.
    #[test]
    fn hardware_capabilities_with_synthesized_snapshot() {
        use crate::platform::capabilities::{
            DiskStatus, DisplayStatus, GpuStatus, IommuStatus, KernelStatus, RamStatus,
            SessionType, TpmStatus, VirtStatus,
        };
        let snapshot = BridgeCapabilities {
            tpm: TpmStatus::Absent,
            iommu: IommuStatus::Absent,
            virtualization: VirtStatus::Absent,
            gpu: GpuStatus::NotDetected,
            kernel: KernelStatus {
                version: "6.6.0".into(),
                kvmfr_supported: false,
            },
            disk: DiskStatus {
                free_bytes: 0,
                mountpoint: "/tmp".into(),
            },
            ram: RamStatus {
                total_bytes: 0,
                available_bytes: 0,
            },
            display: DisplayStatus {
                session_type: SessionType::Headless,
                hdr_capable: false,
            },
        };
        let caps = HardwareCapabilities::with(snapshot);
        let issues = caps.issues();
        // Empty hardware → many issues surfaced.
        assert!(!issues.is_empty());
    }
}
