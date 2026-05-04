//! `neon stream <url>` — V3 experimental subcommand stub.
//!
//! Only compiled when the `experimental-bridge` Cargo feature is on.
//! V3-Phase A scaffolding ships only this stub; calling it dispatches
//! into [`crate::bridge::stream`] which returns a "queued for V3"
//! error pointing at ROADMAP.md.
//!
//! When the feature is **off**, this module does not exist and the
//! `Stream` variant of the [`Command`](crate::cli) enum is not
//! generated, so `neon --help` does not list `stream`.

use crate::error::Result;

/// Args for `neon stream <target_url>`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// URL to open in the bridged browser (e.g. `https://netflix.com`).
    pub target_url: String,
}

/// CLI entry point for `neon stream`.
///
/// Delegates to [`crate::bridge::stream`]. In V3-Phase A the bridge
/// module returns the stub error; V3-Phase C onward fills in the real
/// implementation.
///
/// # Errors
///
/// V3-Phase A always returns [`crate::ErrorCategory::Other`] — the
/// stub error from [`crate::bridge::stream`].
pub fn run(args: &Args) -> Result<()> {
    crate::bridge::stream(&args.target_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `run` propagates the bridge stub error.
    #[test]
    fn run_returns_bridge_stub_error() {
        let args = Args {
            target_url: "https://example.com".to_string(),
        };
        let err = run(&args).expect_err("stub error");
        assert_eq!(err.category, crate::ErrorCategory::Other);
    }
}
