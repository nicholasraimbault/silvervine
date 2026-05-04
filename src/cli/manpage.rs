//! `neon manpage` — emit a roff-formatted man page to stdout.
//!
//! Uses `clap_mangen` to render the binary's clap definition into
//! `groff_man(7)`-style roff. Users redirect into the appropriate
//! man directory:
//!
//! ```sh
//! neon manpage > /usr/local/share/man/man1/neon.1
//! ```
//!
//! Or, more commonly, the package builder pipes the output during
//! release packaging.

use std::io::Write;

use crate::error::{Error, Result};

/// Render `cmd`'s man page to `out`.
///
/// # Errors
///
/// * `Other` if `clap_mangen` fails to render or `out.write_all` fails.
pub fn render(cmd: clap::Command, out: &mut dyn Write) -> Result<()> {
    let man = clap_mangen::Man::new(cmd);
    man.render(out)
        .map_err(|e| Error::other(format!("failed to render manpage: {e}")))?;
    out.flush()
        .map_err(|e| Error::other(format!("failed to flush manpage output: {e}")))?;
    Ok(())
}

/// Convenience CLI entrypoint: render to stdout.
///
/// # Errors
///
/// See [`render`].
pub fn run(cmd_factory: impl FnOnce() -> clap::Command) -> Result<()> {
    let cmd = cmd_factory();
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    render(cmd, &mut handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[derive(Debug, clap::Parser)]
    #[command(name = "neon-test", version, about = "Test binary for manpage tests")]
    struct TestCli {
        #[command(subcommand)]
        cmd: TestCommand,
    }

    #[derive(Debug, clap::Subcommand)]
    enum TestCommand {
        Patch,
    }

    #[test]
    fn render_produces_non_empty_roff() {
        let cmd = TestCli::command();
        let mut buf = Vec::new();
        render(cmd, &mut buf).expect("render ok");
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.is_empty());
        // roff man pages begin with `.TH`.
        assert!(s.starts_with(".ie") || s.contains(".TH"), "got: {s:?}");
        assert!(s.to_uppercase().contains("NEON-TEST"));
    }

    #[test]
    fn render_writes_to_buffer() {
        let cmd = TestCli::command();
        let mut buf = Vec::new();
        render(cmd, &mut buf).expect("ok");
        // Should be at least a few hundred bytes for any non-trivial command.
        assert!(buf.len() > 100, "got {} bytes", buf.len());
    }
}
