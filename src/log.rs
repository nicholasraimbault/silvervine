//! Tracing setup: stderr formatter + rolling file appender.
//!
//! `init()` is the canonical CLI entry point. It composes a `tracing-
//! subscriber` from:
//!
//! * The verbosity counter (`-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE).
//! * The `--quiet` flag (suppresses non-WARN output).
//! * The `--no-color` flag (also honors the `NO_COLOR` env convention).
//! * The `RUST_LOG` env var for an `EnvFilter` override (this is what
//!   `tracing-subscriber` uses upstream; we delegate to it).
//!
//! The file appender writes to `~/.cache/silvervine/logs/silvervine.log` with daily
//! rotation. The `tracing-appender` crate's `Rotation::DAILY` is the
//! closest fit to "weekly with 5 MB cap"; we accept the daily rotation
//! and rely on the cache cleanup pass in `daemon::run()` to enforce the
//! retention policy. (A genuine size-based rotator is a Nice-To-Have —
//! `tracing-appender` doesn't ship one in its 0.2 line.)
//!
//! ## Public API
//!
//! ```ignore
//! pub fn init(verbosity: u8, quiet: bool, no_color: bool) -> Result<()>;
//! pub fn log_dir() -> Option<PathBuf>;
//! ```
//!
//! `init` is idempotent — calling it twice in the same process is a
//! no-op (subsequent calls return `Ok(())` without trying to install a
//! second subscriber).
//!
//! ## What this module does NOT do
//!
//! * No JSON output — we emit human-readable text. JSON is a V2.1 add.
//! * No log shipping. Silvervine doesn't transmit logs anywhere — bug reports
//!   go through GitHub Issues, full stop.

use std::path::PathBuf;
use std::sync::OnceLock;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::error::{Error, Result};

/// Guard returned by `tracing-appender` to keep the background flush
/// thread alive for the duration of the program. We stash one in a
/// `OnceLock` so tests / repeat-init calls don't panic on duplicate
/// installation.
static GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

/// Default log directory: `<cache_dir>/silvervine/logs/`.
///
/// Returns `None` if `dirs::cache_dir()` is unresolvable.
#[must_use]
pub fn log_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("silvervine").join("logs"))
}

/// Initialize the global tracing subscriber.
///
/// `verbosity` follows the conventional CLI counter:
///
/// | `-v` count | Level threshold |
/// |-----------:|----------------|
/// | 0          | WARN            |
/// | 1          | INFO            |
/// | 2          | DEBUG           |
/// | 3+         | TRACE           |
///
/// `quiet` overrides the threshold to ERROR. `no_color` disables ANSI
/// colors on stderr (also honored: `NO_COLOR` env var).
///
/// Honors `RUST_LOG` — if set, it overrides the verbosity-derived
/// filter (so power users keep their existing workflow).
///
/// Idempotent: a second call is a no-op.
///
/// # Errors
///
/// * `Other` if the log directory can't be created.
pub fn init(verbosity: u8, quiet: bool, no_color: bool) -> Result<()> {
    if GUARD.get().is_some() {
        // Already installed; second call is a no-op.
        return Ok(());
    }
    let level = level_for(verbosity, quiet);
    let env_filter = match std::env::var("RUST_LOG") {
        Ok(s) => EnvFilter::try_new(s)
            .unwrap_or_else(|_| EnvFilter::default().add_directive(level.into())),
        Err(_) => EnvFilter::default().add_directive(level.into()),
    };
    let use_color = !no_color && std::env::var_os("NO_COLOR").is_none();

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(use_color)
        .with_target(false)
        .with_filter(env_filter)
        .boxed();

    // File appender. Best-effort: if log_dir resolution or directory
    // creation fails, we install only the stderr layer.
    let file_layer = setup_file_layer().ok();

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync>> = vec![stderr_layer];
    if let Some(file) = file_layer {
        layers.push(file);
    }
    tracing_subscriber::registry()
        .with(layers)
        .try_init()
        .map_err(|e| Error::other(format!("failed to install tracing subscriber: {e}")))?;
    Ok(())
}

/// Map verbosity + quiet to a `tracing` level filter.
fn level_for(verbosity: u8, quiet: bool) -> LevelFilter {
    if quiet {
        return LevelFilter::ERROR;
    }
    match verbosity {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    }
}

/// Build the rolling-file layer pointed at `<cache_dir>/silvervine/logs/silvervine.log`.
///
/// Returned as a boxed `Layer<Registry>` so it composes uniformly with
/// the stderr layer in [`init`].
fn setup_file_layer() -> Result<Box<dyn Layer<Registry> + Send + Sync>> {
    let dir = log_dir().ok_or_else(|| Error::other("cannot resolve silvervine log dir"))?;
    std::fs::create_dir_all(&dir).map_err(Error::from)?;
    let file_appender = tracing_appender::rolling::daily(&dir, "silvervine.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    // Stash the guard in OnceLock so it isn't dropped on return.
    let _ = GUARD.set(guard);
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false)
        .boxed();
    Ok(layer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_for_quiet_yields_error() {
        assert_eq!(level_for(0, true), LevelFilter::ERROR);
        assert_eq!(level_for(3, true), LevelFilter::ERROR);
    }

    #[test]
    fn level_for_verbosity_levels() {
        assert_eq!(level_for(0, false), LevelFilter::WARN);
        assert_eq!(level_for(1, false), LevelFilter::INFO);
        assert_eq!(level_for(2, false), LevelFilter::DEBUG);
        assert_eq!(level_for(3, false), LevelFilter::TRACE);
        assert_eq!(level_for(255, false), LevelFilter::TRACE);
    }

    #[test]
    fn log_dir_ends_under_silvervine_logs() {
        if let Some(dir) = log_dir() {
            assert!(dir.ends_with(std::path::Path::new("silvervine").join("logs")));
        }
    }

    /// Init is idempotent — a second call must not panic.
    /// We can't actually verify the subscriber is installed (it's a
    /// process-wide singleton; tests that install one would flake under
    /// parallel cargo-test). Instead we verify the function returns
    /// without error when called twice.
    #[test]
    fn init_is_idempotent() {
        // The first call may fail if another test in this process already
        // installed a subscriber — that's OK, our second call should still
        // observe the same state.
        let _ = init(0, false, true);
        // Second call is a no-op.
        let res = init(2, false, true);
        assert!(res.is_ok());
    }
}
