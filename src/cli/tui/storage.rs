//! Bounded log viewing and atomic, conflict-aware configuration writes.

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::config::Config;
use crate::{Error, Result};

const LOG_BYTES: u64 = 256 * 1024;

pub(super) fn save_config(path: &Path, expected: &[u8], config: &Config) -> Result<Vec<u8>> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(Error::other(
            "Configuration is a symlink; edit its target directly.",
        ));
    }
    let current = read_config(path)?;
    if current != expected {
        return Err(Error::other(
            "Configuration changed outside this window. Reload before saving.",
        ));
    }
    let serialized = config.to_toml_string()?;
    // Reuse the parser's validation for custom Windows profiles and unknown keys.
    Config::from_toml_str(&serialized)?;
    let serialized = serialized.into_bytes();
    let parent = path
        .parent()
        .ok_or_else(|| Error::other("Configuration has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    if let Ok(metadata) = fs::metadata(path) {
        staged.as_file().set_permissions(metadata.permissions())?;
    }
    staged.write_all(&serialized)?;
    staged.as_file().sync_all()?;
    if read_config(path)? != expected {
        return Err(Error::other(
            "Configuration changed while saving. Reload before saving.",
        ));
    }
    staged.persist(path).map_err(|e| Error::from(e.error))?;
    Ok(serialized)
}

pub(super) fn read_config(path: &Path) -> Result<Vec<u8>> {
    match fs::File::open(path) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err(Error::other("Configuration exceeds 1 MiB"));
            }
            Ok(bytes)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

pub(super) fn read_logs(directory: &Path) -> Result<String> {
    let mut paths = match fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("silvervine.log")
                    && entry.file_type().is_ok_and(|kind| kind.is_file())
            })
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok("No log files yet.".into()),
        Err(e) => return Err(e.into()),
    };
    paths.sort();
    let mut text = String::new();
    for path in paths.iter().rev().take(3).rev() {
        let mut file = fs::File::open(path)?;
        let size = file.metadata()?.len();
        file.seek(SeekFrom::Start(size.saturating_sub(LOG_BYTES)))?;
        let mut bytes = Vec::new();
        file.take(LOG_BYTES).read_to_end(&mut bytes)?;
        let _ = write!(
            text,
            "\n--- {} ---\n",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        text.push_str(&String::from_utf8_lossy(&bytes));
    }
    if text.is_empty() {
        text.push_str("No log files yet.");
    }
    Ok(text)
}

pub(super) fn export(path: &Path, report: &str) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(report.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn visible_line(line: &str, width: usize) -> String {
    line.chars()
        .filter(|c| !c.is_control())
        .take(width)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_save_preserves_fields_and_refuses_concurrent_edits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.toml");
        let mut config = Config::default();
        config.hooks.pre_patch = Some("/my/hooks/pre-patch".into());
        config.updates.channel = crate::config::UpdateChannel::Preview;
        let saved = save_config(&path, &[], &config).unwrap();
        assert_eq!(
            Config::from_toml_str(std::str::from_utf8(&saved).unwrap()).unwrap(),
            config
        );
        fs::write(&path, "[notifications]\non_failure = false\n").unwrap();
        assert!(save_config(&path, &saved, &Config::default()).is_err());
        assert!(fs::read_to_string(path)
            .unwrap()
            .contains("on_failure = false"));
    }

    #[test]
    fn export_never_overwrites_and_terminal_content_cannot_inject_controls() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("report.txt");
        export(&path, "report").unwrap();
        assert!(export(&path, "replacement").is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "report");
        assert!(!visible_line("browser\x1b[2J\rname", 100).contains('\x1b'));
    }
}
