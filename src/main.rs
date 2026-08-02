//! Silvervine — single-binary cross-platform DRM (Widevine) helper for Chromium-family browsers.
//!
//! `main.rs` is the thin dispatcher: parse [`clap`] args, install logging,
//! delegate to the matching `cli::<name>::run` impl. All real logic
//! lives in the library crate.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use silvervine::cli;
use silvervine::Error;

/// Silvervine — patches Chromium-family browsers to play Widevine-protected content.
#[derive(Debug, Parser)]
#[command(
    name = "silvervine",
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
    },

    /// Patch one or more browsers with the Widevine CDM.
    Patch {
        /// Patch even if the browser appears to already be patched.
        #[arg(long)]
        force: bool,

        /// Show what would be done without making changes.
        #[arg(long)]
        dry_run: bool,

        /// Replace an existing unmarked CDM that Silvervine cannot prove it owns.
        /// Requires an explicit browser positional so bulk replacement is impossible.
        #[arg(long, requires = "browser")]
        replace_external_cdm: bool,

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

        /// Collect passive browser/CDM/host media-stack evidence without launching a browser.
        #[arg(long = "media-stack", conflicts_with = "error_code")]
        media_stack: bool,

        /// Limit passive media-stack collection to one browser name.
        #[arg(long, requires = "media_stack")]
        browser: Option<String>,

        /// EME error code to translate (e.g. Netflix N8156-6013).
        error_code: Option<String>,
    },

    /// Run a browser-reported EME capability check.
    Test {
        /// Override the browser to test against.
        #[arg(long)]
        browser: Option<String>,

        /// Open a manual test page instead of running the automated capability probe.
        #[arg(long)]
        url: Option<String>,
    },

    /// Update or roll back the Widevine CDM.
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

    /// Remove the Silvervine daemon and cache (browsers stay patched until they auto-update).
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

    /// Internal filesystem-only operation used after privilege escalation.
    #[command(name = "__privileged-patch", hide = true)]
    PrivilegedPatch {
        #[arg(long)]
        install_path: PathBuf,
        #[arg(long)]
        framework_name: Option<String>,
        #[arg(long)]
        framework_version: Option<String>,
        #[arg(long)]
        backup_parent: PathBuf,
        #[arg(long)]
        cdm_dir: PathBuf,
        #[arg(long, value_parser = parse_managed_marker)]
        managed_marker: silvervine::widevine::ownership::ManagedMarker,
        #[arg(long)]
        browser_name: String,
        /// Closed ownership classification token from the locked parent.
        /// Direct hidden invocations omit this and reconstruct as Detected.
        #[arg(long, value_parser = parse_browser_kind_token)]
        browser_kind: Option<silvervine::browsers::BrowserKind>,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        replace_external_cdm: bool,
    },
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // The privileged child is dispatched immediately after clap parsing. It
    // must not discover browsers, read user configuration, migrate data, open
    // logs, fetch manifests, touch caches, or emit hooks.
    if let Some(Command::PrivilegedPatch {
        install_path,
        framework_name,
        framework_version,
        backup_parent,
        cdm_dir,
        managed_marker,
        browser_name,
        browser_kind,
        force,
        replace_external_cdm,
    }) = &cli.command
    {
        let result = cli::patch::run_privileged(&cli::patch::PrivilegedArgs {
            install_path: install_path.clone(),
            framework_name: framework_name.clone(),
            framework_version: framework_version.clone(),
            backup_parent: backup_parent.clone(),
            cdm_dir: cdm_dir.clone(),
            managed_marker: managed_marker.clone(),
            browser_name: browser_name.clone(),
            browser_kind: *browser_kind,
            force: *force,
            replace_external_cdm: *replace_external_cdm,
        });
        return result.map_or_else(
            |error| {
                eprintln!("silvervine: {error}");
                ExitCode::from(category_to_exit_code(&error))
            },
            |()| ExitCode::SUCCESS,
        );
    }

    // Passive media-stack diagnostics must not migrate XDG state or open logs.
    if let Some(Command::Doctor {
        share,
        media_stack: true,
        browser,
        error_code: None,
    }) = &cli.command
    {
        let output = cli::OutputOptions::from_flags(cli.json, cli.quiet, cli.no_color);
        let result = cli::doctor::run(&cli::doctor::Args {
            error_code: None,
            share: *share,
            media_stack: true,
            browser: browser.clone(),
            output,
        });
        return result.map_or_else(
            |error| {
                eprintln!("silvervine: {error}");
                ExitCode::from(category_to_exit_code(&error))
            },
            |()| ExitCode::SUCCESS,
        );
    }

    match prepare_startup_migration() {
        Ok(entries) => report_data_migration(&entries),
        Err(error) => {
            eprintln!("silvervine: {error}");
            return ExitCode::from(category_to_exit_code(&error));
        }
    }
    let _ = silvervine::log::init(cli.verbose, cli.quiet, cli.no_color);
    let output = cli::OutputOptions::from_flags(cli.json, cli.quiet, cli.no_color);

    let result: silvervine::Result<()> = match cli.command {
        // No subcommand → run the tray daemon (default).
        None => silvervine::daemon::run(),
        Some(cmd) => dispatch(cmd, output),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("silvervine: {e}");
            ExitCode::from(category_to_exit_code(&e))
        }
    }
}

fn parse_browser_kind_token(value: &str) -> Result<silvervine::browsers::BrowserKind, String> {
    silvervine::browsers::BrowserKind::from_str_token(value).ok_or_else(|| {
        format!("invalid browser kind '{value}'; expected known, detected, or custom")
    })
}
fn parse_managed_marker(
    value: &str,
) -> Result<silvervine::widevine::ownership::ManagedMarker, String> {
    serde_json::from_str(value).map_err(|error| format!("invalid managed marker: {error}"))
}

fn prepare_startup_migration() -> silvervine::Result<Vec<silvervine::migration::DataMigrationEntry>>
{
    silvervine::migration::migrate_v2_startup()
}

fn report_data_migration(entries: &[silvervine::migration::DataMigrationEntry]) {
    use silvervine::migration::DataMigrationStatus;
    for entry in entries {
        match &entry.status {
            DataMigrationStatus::Migrated => eprintln!(
                "Silvervine: migrated legacy Neon {} data from {} to {}",
                entry.kind,
                entry.from.display(),
                entry.to.display()
            ),
            DataMigrationStatus::Conflict => eprintln!(
                "Silvervine: kept both Neon and Silvervine {} data directories ({} and {})",
                entry.kind,
                entry.from.display(),
                entry.to.display()
            ),
            DataMigrationStatus::Error(error) => eprintln!(
                "Silvervine: could not migrate Neon {} data from {}: {error}",
                entry.kind,
                entry.from.display()
            ),
            DataMigrationStatus::MissingSource => {}
        }
    }
}

/// Dispatch a parsed subcommand to its `cli::<name>::run` impl.
fn dispatch(cmd: Command, output: cli::OutputOptions) -> silvervine::Result<()> {
    match cmd {
        Command::Init => cli::init::run(&cli::init::Args { output }),
        Command::Setup {
            no_daemon,
            no_eme_test,
        } => cli::setup::run(&cli::setup::Args {
            no_daemon,
            no_eme_test,
            output,
        }),
        Command::Patch {
            force,
            dry_run,
            replace_external_cdm,
            browser,
        } => cli::patch::run(&cli::patch::Args {
            force,
            dry_run,
            replace_external_cdm,
            browser,
            output,
        }),
        Command::Status { watch } => cli::status::run(&cli::status::Args { watch, output }),
        Command::ListBrowsers { all } => {
            cli::list_browsers::run(&cli::list_browsers::Args { all, output })
        }
        Command::Doctor {
            share,
            media_stack,
            browser,
            error_code,
        } => cli::doctor::run(&cli::doctor::Args {
            error_code,
            share,
            media_stack,
            browser,
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
        },
        Command::Repair => cli::repair::run(&cli::repair::Args { output }),
        Command::Launch { browser } => cli::launch::run(&cli::launch::Args { browser, output }),
        Command::Uninstall { purge } => {
            cli::uninstall::run(&cli::uninstall::Args { purge, output })
        }
        Command::Completion { shell } => cli::completion::run(shell, Cli::command),
        Command::Manpage => cli::manpage::run(Cli::command),
        Command::PrivilegedPatch { .. } => unreachable!("handled before startup side effects"),
    }
}

/// Map an [`Error`]'s category to a stable exit code.
///
/// 0 → success (handled in `main`).
/// 1 → catch-all error.
/// 2 → invalid usage (clap handles this internally for parse errors).
/// 10+ → categorized silvervine failures.
fn category_to_exit_code(err: &Error) -> u8 {
    use silvervine::ErrorCategory;
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
        ErrorCategory::ExternalCdm => 21,
        ErrorCategory::InvalidMarker => 22,
        ErrorCategory::BrowserProbeFailed => 23,
        ErrorCategory::Other => 1,
    }
}
