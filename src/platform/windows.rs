//! Windows user-local storage and fail-closed publication.
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::error::{Error, Result};

pub(super) fn cache_dir() -> PathBuf {
    crate::platform::app_cache_dir().expect("Windows local application data directory unavailable")
}

pub(super) fn config_dir() -> PathBuf {
    crate::platform::config_home()
        .expect("Windows roaming application data directory unavailable")
        .join("silvervine")
}

pub(super) fn applications_dirs() -> Vec<PathBuf> {
    ["LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .collect()
}

pub(super) fn run_as_root(_command: &[&str]) -> Result<Output> {
    Err(Error::permission_denied("Windows installation uses your browser profile without elevation; protected application directories must be managed by their installer"))
}

pub(super) fn run_pinned_as_root(command: &[&str], _expected_sha512: &str) -> Result<Output> {
    run_as_root(command)
}

pub(super) fn atomic_rename(src: &Path, dst: &Path) -> Result<()> {
    // ponytail: Windows cannot atomically exchange directories; publish immutable versions instead.
    if dst.try_exists().map_err(Error::from)? {
        return Err(Error::other("Windows cannot atomically exchange existing directories; refusing non-atomic replacement"));
    }
    std::fs::rename(src, dst).map_err(Error::from)
}
