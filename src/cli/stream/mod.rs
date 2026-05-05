//! `neon stream <subcommand>` — V3 experimental localhost-bridge.
//!
//! Only compiled when the `experimental-bridge` Cargo feature is on.
//! V3-Phase C shipped `init` + `status`. V3-Phase D adds `start` +
//! `stop`. V3-Phase F adds `repair`, `uninstall`, `license` (stubbed
//! until then).

use crate::cli::OutputOptions;
use crate::error::{Error, Result};

pub mod init;
pub mod start;
pub mod status;
pub mod stop;

/// `neon stream init` Args (top-level CLI subcommand).
pub use init::Args as InitArgs;
/// `neon stream start` Args (V3-Phase D).
pub use start::Args as StartArgs;
/// `neon stream status` Args.
pub use status::Args as StatusArgs;
/// `neon stream stop` Args (V3-Phase D).
pub use stop::Args as StopArgs;

/// Subcommand variants under `neon stream`. Mapped 1:1 from
/// the `StreamSubcommand` enum in `src/main.rs`.
#[derive(Debug)]
pub enum Subcommand {
    /// `neon stream init [--accept-eval | --license-key K | --license-file P]`.
    Init(InitArgs),
    /// `neon stream status [--json]`.
    Status(StatusArgs),
    /// `neon stream start [URL]` — V3-Phase D.
    Start(StartArgs),
    /// `neon stream stop` — V3-Phase D.
    Stop(StopArgs),
    /// `neon stream repair` — V3-Phase F (stubbed).
    Repair {
        /// Output flags.
        output: OutputOptions,
    },
    /// `neon stream uninstall` — V3-Phase F (stubbed).
    Uninstall {
        /// `--purge`: also remove `~/.config/neon/bridge.toml`.
        purge: bool,
        /// Output flags.
        output: OutputOptions,
    },
    /// `neon stream license` — V3-Phase F (stubbed).
    License {
        /// Output flags.
        output: OutputOptions,
    },
}

/// Dispatcher from `main.rs`'s `Stream` variant.
///
/// # Errors
///
/// * Propagates errors from each subcommand.
/// * V3-Phase F-stubbed subcommands return `Error::other("queued for
///   V3-Phase F")` pointing at ROADMAP.md.
pub fn run(sub: Subcommand) -> Result<()> {
    match sub {
        Subcommand::Init(args) => init::run(&args),
        Subcommand::Status(args) => status::run(&args),
        Subcommand::Start(args) => start::run(&args),
        Subcommand::Stop(args) => stop::run(&args),
        Subcommand::Repair { .. } => Err(Error::other(
            "neon stream repair is queued for V3-Phase F. \
             Track ROADMAP.md and the V3 orchestration plan.",
        )),
        Subcommand::Uninstall { .. } => Err(Error::other(
            "neon stream uninstall is queued for V3-Phase F. \
             Track ROADMAP.md and the V3 orchestration plan.",
        )),
        Subcommand::License { .. } => Err(Error::other(
            "neon stream license is queued for V3-Phase F. \
             Track ROADMAP.md and the V3 orchestration plan.",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_returns_phase_f_stub() {
        let err = run(Subcommand::Repair {
            output: OutputOptions::default(),
        })
        .expect_err("stub");
        assert!(err.to_string().contains("V3-Phase F"));
    }

    #[test]
    fn uninstall_returns_phase_f_stub() {
        let err = run(Subcommand::Uninstall {
            purge: false,
            output: OutputOptions::default(),
        })
        .expect_err("stub");
        assert!(err.to_string().contains("V3-Phase F"));
    }

    #[test]
    fn license_returns_phase_f_stub() {
        let err = run(Subcommand::License {
            output: OutputOptions::default(),
        })
        .expect_err("stub");
        assert!(err.to_string().contains("V3-Phase F"));
    }
}
