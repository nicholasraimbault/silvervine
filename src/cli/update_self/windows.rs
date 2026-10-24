//! Free the installed filename while Windows still maps the old executable.
//!
//! The cargo-dist PowerShell installer copies over silvervine.exe. Windows
//! permits renaming a mapped executable but refuses that overwrite. Keep the
//! original in a private sibling directory until installation succeeds, and
//! restore it on a failed/no-op update. A bounded detached helper removes only
//! this transaction's old file after CLI/TUI/daemon processes release it.

use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::{Error, Result};

pub(super) struct ExecutableSwap {
    original: PathBuf,
    backup: PathBuf,
    directory: Option<tempfile::TempDir>,
}

impl ExecutableSwap {
    pub(super) fn prepare() -> Result<Self> {
        let original = std::env::current_exe()?.canonicalize()?;
        if !original
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("silvervine.exe"))
        {
            return Err(Error::other(
                "Run the installed silvervine.exe to update on Windows",
            ));
        }
        let parent = original
            .parent()
            .ok_or_else(|| Error::other("Executable has no parent"))?;
        let directory = tempfile::Builder::new()
            .prefix(".silvervine-update-")
            .tempdir_in(parent)?;
        let backup = directory.path().join("silvervine.exe");
        std::fs::rename(&original, &backup)
            .map_err(|error| Error::other(format!("Cannot prepare Windows update: {error}")))?;
        Ok(Self {
            original,
            backup,
            directory: Some(directory),
        })
    }

    pub(super) fn finish(mut self, installed: bool) -> Result<()> {
        if !installed || !self.original.is_file() {
            self.restore()?;
            if installed {
                return Err(Error::other("Updater reported success without installing silvervine.exe; restored the previous executable"));
            }
            return Ok(());
        }
        let directory = self
            .directory
            .take()
            .expect("active update transaction")
            .keep();
        if let Err(error) = schedule_cleanup(&self.backup, &directory) {
            tracing::warn!(path = %directory.display(), %error, "Update installed; old executable remains until removed after processes exit");
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
        if self.directory.is_none() {
            return Ok(());
        }
        if let Err(error) = std::fs::rename(&self.backup, &self.original) {
            let directory = self
                .directory
                .take()
                .expect("active update transaction")
                .keep();
            return Err(Error::other(format!(
                "Could not restore silvervine.exe: {error}. Previous executable preserved at {}",
                directory.join("silvervine.exe").display()
            )));
        }
        self.directory.take();
        Ok(())
    }
}

impl Drop for ExecutableSwap {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            tracing::error!(%error, "Windows update rollback failed");
        }
    }
}

fn schedule_cleanup(backup: &std::path::Path, directory: &std::path::Path) -> Result<()> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| Error::other("Cannot resolve Windows SystemRoot for update cleanup"))?;
    // Values travel through environment variables, never interpolated script.
    // Do not recurse, glob, or clean previous transactions/startup paths.
    Command::new(root.join("System32/WindowsPowerShell/v1.0/powershell.exe"))
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop'; for ($i=0; $i -lt 600; $i++) { try { if (Test-Path -LiteralPath $env:SILVERVINE_UPDATE_BACKUP) { Remove-Item -LiteralPath $env:SILVERVINE_UPDATE_BACKUP -Force }; [IO.Directory]::Delete($env:SILVERVINE_UPDATE_DIRECTORY); exit 0 } catch { Start-Sleep -Milliseconds 500 } }; exit 1"])
        .env("SILVERVINE_UPDATE_BACKUP", backup)
        .env("SILVERVINE_UPDATE_DIRECTORY", directory)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .creation_flags(0x0800_0000).spawn()?;
    Ok(())
}
