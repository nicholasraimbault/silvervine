//! `silvervine` CLI subcommand implementations.
//!
//! Each subcommand lives in its own module under this directory and
//! exposes a `run(args)` entry point. The binary entry point in
//! `src/main.rs` parses the [`clap::Parser`] tree, dispatches to the
//! matching `cli::<name>::run(args)`, and translates the returned
//! [`crate::Result`] into a process exit code.
//!
//! ## Module layout
//!
//! | Module | Subcommand |
//! |---|---|
//! | [`init`] | `silvervine init` (interactive wizard) |
//! | [`setup`] | `silvervine setup` (non-interactive equivalent) |
//! | [`patch`] | `silvervine patch` |
//! | [`status`] | `silvervine status` |
//! | [`list_browsers`] | `silvervine list-browsers` |
//! | [`doctor`] | `silvervine doctor` |
//! | [`test`] | `silvervine test` (EME health check) |
//! | [`update`] | `silvervine update {widevine,self}` |
//! | [`repair`] | `silvervine repair` |
//! | [`launch`] | `silvervine launch <browser>` |
//! | [`uninstall`] | `silvervine uninstall` |
//! | [`completion`] | `silvervine completion <shell>` |
//! | [`manpage`] | `silvervine manpage` |
//!
//! ## Test-mode env-vars
//!
//! Tests honor a small set of `SILVERVINE_TEST_*` environment variables to
//! prevent the CLI from invoking long-running, graphical, or
//! privileged operations during `cargo test`:
//!
//! * `SILVERVINE_TEST_LAUNCH_NOOP=1` — `silvervine launch <browser>` records the
//!   browser it would spawn but does not actually call `Command::spawn`.
//! * `SILVERVINE_TEST_BROWSER_TEST_NOOP=1` — `silvervine test` builds the launch
//!   plan but does not actually drive a real browser.
//! * `SILVERVINE_TEST_ESCALATE_NOOP=1` — already honored at the platform
//!   layer; CLI subcommands inherit the gate.

pub mod completion;
pub mod doctor;
pub mod init;
pub mod launch;
pub mod list_browsers;
pub mod manpage;
pub mod patch;
pub mod repair;
pub mod setup;
pub mod status;
pub mod test;
pub mod uninstall;
pub mod update;

/// Common output style flags that apply to every subcommand.
///
/// Built once in `main.rs` from the global flags and passed down by
/// reference. Subcommands consult `json` to decide whether to emit
/// machine-readable output and `quiet`/`no_color` to suppress noise.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutputOptions {
    /// `--json` was passed: emit structured JSON instead of human-
    /// readable text.
    pub json: bool,
    /// `--quiet` was passed: suppress non-error output.
    pub quiet: bool,
    /// `--no-color` was passed (or `NO_COLOR` is set): no ANSI in output.
    pub no_color: bool,
}

impl OutputOptions {
    /// Construct from global CLI flags. Honors the `NO_COLOR` env var
    /// convention (any value disables color).
    #[must_use]
    pub fn from_flags(json: bool, quiet: bool, no_color: bool) -> Self {
        let no_color = no_color || std::env::var_os("NO_COLOR").is_some();
        Self {
            json,
            quiet,
            no_color,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_options_from_flags_honors_no_color_env() {
        // SAFETY: env mutations happen in serial test threads; we restore
        // at end-of-test.
        unsafe { std::env::set_var("NO_COLOR", "1") };
        let opts = OutputOptions::from_flags(false, false, false);
        assert!(opts.no_color);
        unsafe { std::env::remove_var("NO_COLOR") };
    }

    #[test]
    fn output_options_default_is_all_off() {
        let opts = OutputOptions::default();
        assert!(!opts.json);
        assert!(!opts.quiet);
        assert!(!opts.no_color);
    }
}
