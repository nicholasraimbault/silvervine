//! Neon — single-binary cross-platform DRM (Widevine) helper for Chromium-family browsers.
//!
//! `main.rs` is the thin dispatcher: parse [`clap`] args, install logging,
//! delegate to the matching `cli::<name>::run` impl. All real logic
//! lives in the library crate.

use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use neon::cli;
use neon::Error;

/// Neon — patches Chromium-family browsers to play Widevine-protected content.
#[derive(Debug, Parser)]
#[command(
    name = "neon",
    version,
    about,
    long_about = None,
    propagate_version = true
)]
struct Cli {
    /// Increase log verbosity (repeat for more detail: -v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Silence non-error output.
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Disable colored output (NO_COLOR environment variable also honored).
    #[arg(long, global = true)]
    no_color: bool,

    /// Emit structured JSON output where supported.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Interactive first-run setup wizard.
    Init,

    /// Non-interactive install (for scripts and CI).
    Setup {
        /// Skip the daemon registration step.
        #[arg(long)]
        no_daemon: bool,

        /// Skip the EME health check (already off by default).
        #[arg(long)]
        no_eme_test: bool,

        /// `--reporting=on|off` for the opt-in error reporter.
        #[arg(long, value_enum, default_value_t = ReportingFlag::Off)]
        reporting: ReportingFlag,
    },

    /// Patch one or more browsers with the Widevine CDM.
    Patch {
        /// Patch even if the browser appears to already be patched.
        #[arg(long)]
        force: bool,

        /// Show what would be done without making changes.
        #[arg(long)]
        dry_run: bool,

        /// Optional: specific browser name to patch (e.g. "Helium").
        browser: Option<String>,
    },

    /// Show patch state for all known browsers.
    Status {
        /// Continuously refresh status output.
        #[arg(long)]
        watch: bool,
    },

    /// Enumerate known + auto-discovered browsers.
    ListBrowsers {
        /// Include auto-discovered browsers and custom-config entries.
        #[arg(long)]
        all: bool,
    },

    /// Run diagnostics; optionally translate an EME error code.
    Doctor {
        /// Output an issue-template URL prefilled with diagnostics.
        #[arg(long)]
        share: bool,

        /// EME error code to translate (e.g. Netflix N8156-6013).
        error_code: Option<String>,
    },

    /// Run an EME health check against a known test page.
    Test {
        /// Override the browser to test against.
        #[arg(long)]
        browser: Option<String>,

        /// Override the test URL (defaults to the Shaka Player demo).
        #[arg(long)]
        url: Option<String>,
    },

    /// Update the Widevine CDM or self-update the Neon binary.
    Update {
        #[command(subcommand)]
        target: UpdateTarget,
    },

    /// Combination uninstall + setup; preserves user config.
    Repair,

    /// Verify a browser is patched, then launch it.
    Launch {
        /// Browser name (e.g. "Helium", "Thorium").
        browser: String,
    },

    /// Remove the Neon daemon and cache (browsers stay patched until they auto-update).
    Uninstall {
        /// Also remove the user config + state files.
        #[arg(long)]
        purge: bool,
    },

    /// Generate shell completion scripts.
    Completion {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Generate the man page in roff format.
    Manpage,
}

/// Reporting opt-in flag for `setup --reporting=...`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ReportingFlag {
    On,
    Off,
}

#[derive(Debug, Subcommand)]
enum UpdateTarget {
    /// Update the Widevine CDM (the bundled DRM module).
    Widevine {
        /// Roll back to the previous Widevine version.
        #[arg(long)]
        rollback: bool,

        /// Override the Mozilla manifest URL with a custom CRX3 source.
        #[arg(long)]
        cdm_source: Option<String>,
    },

    /// Self-update the Neon binary from GitHub Releases.
    #[command(name = "self")]
    SelfUpdate,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let _ = neon::log::init(cli.verbose, cli.quiet, cli.no_color);
    let output = cli::OutputOptions::from_flags(cli.json, cli.quiet, cli.no_color);

    let result: neon::Result<()> = match cli.command {
        // No subcommand → run the tray daemon (default).
        None => neon::daemon::run(),
        Some(cmd) => dispatch(cmd, output),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("neon: {e}");
            ExitCode::from(category_to_exit_code(&e))
        }
    }
}

/// Dispatch a parsed subcommand to its `cli::<name>::run` impl.
fn dispatch(cmd: Command, output: cli::OutputOptions) -> neon::Result<()> {
    match cmd {
        Command::Init => cli::init::run(&cli::init::Args { output }),
        Command::Setup {
            no_daemon,
            no_eme_test,
            reporting,
        } => cli::setup::run(&cli::setup::Args {
            no_daemon,
            no_eme_test,
            reporting_on: matches!(reporting, ReportingFlag::On),
            output,
        }),
        Command::Patch {
            force,
            dry_run,
            browser,
        } => cli::patch::run(&cli::patch::Args {
            force,
            dry_run,
            browser,
            output,
        }),
        Command::Status { watch } => cli::status::run(&cli::status::Args { watch, output }),
        Command::ListBrowsers { all } => {
            cli::list_browsers::run(&cli::list_browsers::Args { all, output })
        }
        Command::Doctor { share, error_code } => cli::doctor::run(&cli::doctor::Args {
            error_code,
            share,
            output,
        }),
        Command::Test { browser, url } => cli::test::run(&cli::test::Args {
            browser,
            url,
            output,
        }),
        Command::Update { target } => match target {
            UpdateTarget::Widevine {
                rollback,
                cdm_source,
            } => cli::update::run_widevine(&cli::update::WidevineArgs {
                rollback,
                cdm_source,
                output,
            }),
            UpdateTarget::SelfUpdate => cli::update::run_self(&cli::update::SelfArgs { output }),
        },
        Command::Repair => cli::repair::run(&cli::repair::Args { output }),
        Command::Launch { browser } => cli::launch::run(&cli::launch::Args { browser, output }),
        Command::Uninstall { purge } => {
            cli::uninstall::run(&cli::uninstall::Args { purge, output })
        }
        Command::Completion { shell } => cli::completion::run(shell, Cli::command),
        Command::Manpage => cli::manpage::run(Cli::command),
    }
}

/// Map an [`Error`]'s category to a stable exit code.
///
/// 0 → success (handled in `main`).
/// 1 → catch-all error.
/// 2 → invalid usage (clap handles this internally for parse errors).
/// 10+ → categorized neon failures.
fn category_to_exit_code(err: &Error) -> u8 {
    use neon::ErrorCategory;
    match err.category {
        ErrorCategory::PermissionDenied => 13,
        ErrorCategory::BrowserRunning => 11,
        ErrorCategory::NetworkError | ErrorCategory::ManifestFetchFailed => 14,
        ErrorCategory::HashMismatch => 15,
        ErrorCategory::DiskFull => 16,
        ErrorCategory::UnknownBundleStructure => 17,
        ErrorCategory::DaemonNotRunning => 18,
        ErrorCategory::StateCorrupted => 19,
        ErrorCategory::UnsupportedPlatform => 20,
        ErrorCategory::Other => 1,
    }
}
