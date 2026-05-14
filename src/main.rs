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

    /// Internal: signal that this Neon process is the privileged child
    /// of an earlier escalation (`pkexec` / `sudo` / `osascript`). The
    /// patch flow uses this flag to (a) skip a second escalation attempt
    /// and (b) place its rollback snapshot in a same-filesystem sibling
    /// directory of the install path so atomic-swap rollback works
    /// (cross-filesystem `renameat2(RENAME_EXCHANGE)` returns `EXDEV`).
    /// Hidden from the help output — end users should never set this.
    #[arg(long, global = true, hide = true)]
    as_root: bool,

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

        /// Show V3 bridge hardware capability matrix + remediation
        /// (requires the `experimental-bridge` Cargo feature).
        #[cfg(feature = "experimental-bridge")]
        #[arg(long)]
        bridge: bool,
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

    /// Bridge a URL to a guest VM with hardware-backed Widevine
    /// (experimental; requires the `experimental-bridge` Cargo feature).
    ///
    /// V3-Phase F ships the full subcommand tree. With no subcommand,
    /// `neon stream` auto-dispatches: `init` if not provisioned,
    /// `status` otherwise.
    #[cfg(feature = "experimental-bridge")]
    Stream {
        #[command(subcommand)]
        sub: Option<StreamSubcommand>,
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

    /// Self-update the Neon binary from GitHub Releases.
    #[command(name = "self")]
    SelfUpdate,
}

/// `neon stream` subcommand group — V3-Phase C onward.
#[cfg(feature = "experimental-bridge")]
#[derive(Debug, Subcommand)]
enum StreamSubcommand {
    /// Provision the bridge VM (downloads ISO, defines libvirt domain,
    /// runs unattended install, takes a snapshot). Single command;
    /// ~30-45 minutes of unattended wait.
    Init {
        /// Accept the Microsoft 90-day evaluation license.
        #[arg(long)]
        accept_eval: bool,

        /// Bring your own Windows product key (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX).
        #[arg(long, conflicts_with_all = ["accept_eval", "license_file"])]
        license_key: Option<String>,

        /// Path to a CSV / KMS key file.
        #[arg(long, conflicts_with_all = ["accept_eval", "license_key"])]
        license_file: Option<std::path::PathBuf>,
    },

    /// Show bridge VM status: defined? running? snapshot age? license expiry?
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Resume the bridge VM and (optionally) open a URL in Edge inside
    /// the guest. Cold-start target: <10s on a warm snapshot pool.
    Start {
        /// Optional URL to open in the bridged browser. URL navigation
        /// is queued for V3-Phase F; for now Edge boots at default.
        url: Option<String>,
    },

    /// Snapshot + halt the bridge VM. Pauses the VM (suspend-to-RAM);
    /// next `neon stream start` resumes from the `last-good` snapshot.
    Stop,

    /// Detect + fix broken bridge state.
    Repair {
        /// Skip confirmation prompts and apply fixes in priority order.
        #[arg(long)]
        auto: bool,
        /// Force restore from a specific snapshot label.
        #[arg(long)]
        from_snapshot: Option<String>,
        /// Take a new `fresh` snapshot from the current VM state.
        #[arg(long)]
        refresh_snapshot: bool,
    },

    /// Remove the bridge VM, ISO, snapshots.
    Uninstall {
        /// Also remove `~/.config/neon/bridge.toml`.
        #[arg(long)]
        purge: bool,
    },

    /// Show / change the bridge license posture.
    License {
        #[command(subcommand)]
        action: Option<LicenseAction>,
    },
}

/// Subcommand under `neon stream license`.
#[cfg(feature = "experimental-bridge")]
#[derive(Debug, Subcommand)]
enum LicenseAction {
    /// Show the current license posture.
    Show,
    /// Set a new license posture.
    Set {
        /// Opt into the 90-day Microsoft trial.
        #[arg(long, conflicts_with_all = ["key", "key_file"])]
        eval: bool,
        /// Bring your own Windows product key.
        #[arg(long, conflicts_with_all = ["eval", "key_file"])]
        key: Option<String>,
        /// Path to a key file (CSV / KMS).
        #[arg(long, conflicts_with_all = ["eval", "key"])]
        key_file: Option<std::path::PathBuf>,
    },
    /// Show the PowerShell command the guest runs to re-arm the trial.
    Rearm,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let _ = neon::log::init(cli.verbose, cli.quiet, cli.no_color);
    let output = cli::OutputOptions::from_flags(cli.json, cli.quiet, cli.no_color);

    let result: neon::Result<()> = match cli.command {
        // No subcommand → run the tray daemon (default).
        None => neon::daemon::run(),
        Some(cmd) => dispatch(cmd, output, cli.as_root),
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
fn dispatch(cmd: Command, output: cli::OutputOptions, as_root: bool) -> neon::Result<()> {
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
            browser,
        } => cli::patch::run(&cli::patch::Args {
            force,
            dry_run,
            browser,
            as_root,
            output,
        }),
        Command::Status { watch } => cli::status::run(&cli::status::Args { watch, output }),
        Command::ListBrowsers { all } => {
            cli::list_browsers::run(&cli::list_browsers::Args { all, output })
        }
        Command::Doctor {
            share,
            error_code,
            #[cfg(feature = "experimental-bridge")]
            bridge,
        } => cli::doctor::run(&cli::doctor::Args {
            error_code,
            share,
            #[cfg(feature = "experimental-bridge")]
            bridge,
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
        #[cfg(feature = "experimental-bridge")]
        Command::Stream { sub } => dispatch_stream(sub, output),
    }
}

#[cfg(feature = "experimental-bridge")]
fn dispatch_stream(sub: Option<StreamSubcommand>, output: cli::OutputOptions) -> neon::Result<()> {
    use cli::stream;
    let s = match sub {
        None => stream::Subcommand::Default(output),
        Some(StreamSubcommand::Init {
            accept_eval,
            license_key,
            license_file,
        }) => stream::Subcommand::Init(stream::InitArgs {
            accept_eval,
            license_key,
            license_file,
            output,
        }),
        Some(StreamSubcommand::Status { json }) => {
            stream::Subcommand::Status(stream::StatusArgs { json, output })
        }
        Some(StreamSubcommand::Start { url }) => {
            stream::Subcommand::Start(stream::StartArgs { url, output })
        }
        Some(StreamSubcommand::Stop) => stream::Subcommand::Stop(stream::StopArgs { output }),
        Some(StreamSubcommand::Repair {
            auto,
            from_snapshot,
            refresh_snapshot,
        }) => stream::Subcommand::Repair(stream::RepairArgs {
            auto,
            from_snapshot,
            refresh_snapshot,
            output,
        }),
        Some(StreamSubcommand::Uninstall { purge }) => {
            stream::Subcommand::Uninstall(stream::UninstallArgs { purge, output })
        }
        Some(StreamSubcommand::License { action }) => {
            stream::Subcommand::License(stream::LicenseArgs {
                action: match action {
                    None | Some(LicenseAction::Show) => stream::license::Action::Show,
                    Some(LicenseAction::Set {
                        eval,
                        key,
                        key_file,
                    }) => stream::license::Action::Set {
                        eval,
                        key,
                        key_file,
                    },
                    Some(LicenseAction::Rearm) => stream::license::Action::Rearm,
                },
                output,
            })
        }
    };
    stream::run(s)
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
