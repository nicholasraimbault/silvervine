//! Chromium Local State component-version publication.
use crate::error::{Error, Result};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
};

// ComponentInstaller::SelectComponentVersion prefers registered pv over a scan.
// https://chromium.googlesource.com/chromium/src/+/main/components/update_client/persisted_data.cc
pub(super) fn publish(root: &Path, version: &str) -> Result<()> {
    let profile = root
        .parent()
        .ok_or_else(|| Error::invalid_marker("component root has no profile"))?;
    let path = profile.join("Local State");
    let mut original = match fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
    {
        Ok(file) => Some(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(Error::from(error)),
    };
    let mut state = if let Some(file) = original.as_mut() {
        let metadata = file.metadata().map_err(Error::from)?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > 64 * 1024 * 1024
        {
            return Err(Error::invalid_marker(
                "Local State must be a bounded regular non-reparse file",
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(Error::from)?;
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(Error::from)?
    } else {
        serde_json::json!({})
    };
    let mut entry = &mut state;
    for key in [
        "updateclientdata",
        "apps",
        "oimompecagnajdejgnnjijobebaeigek",
    ] {
        let object = entry.as_object_mut().ok_or_else(|| {
            Error::invalid_marker("Local State component registration is not an object")
        })?;
        entry = object.entry(key).or_insert_with(|| serde_json::json!({}));
    }
    let object = entry.as_object_mut().ok_or_else(|| {
        Error::invalid_marker("Local State Widevine registration is not an object")
    })?;
    object.insert("pv".into(), serde_json::Value::String(version.into()));
    let mut staged = tempfile::NamedTempFile::new_in(profile).map_err(Error::from)?;
    serde_json::to_writer(staged.as_file_mut(), &state).map_err(Error::from)?;
    staged.flush().map_err(Error::from)?;
    staged.as_file().sync_all().map_err(Error::from)?;
    let current = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path);
    match (&original, current) {
        (Some(before), Ok(after))
            if super::super::target_identity(before)? == super::super::target_identity(&after)? => {
        }
        (None, Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => {
            return Err(Error::state_corrupted(
                "Local State changed during CDM publication",
            ))
        }
    }
    // Windows replacement may request write access to the destination. Release
    // our deny-write reader after the identity check and before replacement.
    drop(original);
    staged
        .persist(&path)
        .map_err(|error| Error::from(error.error))?;
    Ok(())
}
