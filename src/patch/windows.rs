//! Windows per-user CDM publication. Numeric version directories are immutable:
//! stage and verify before one rename; retain older versions for rollback.

use std::fs;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};

use super::{ManagedWrite, PlatformPatcher, TargetAuthorization};
use crate::error::{Error, Result};
use crate::widevine::ownership::{self, ManagedMarker};

#[path = "windows_registration.rs"]
mod registration;

/// Transactionally publishes verified CDMs into Windows browser profiles.
#[derive(Default)]
pub struct WindowsPatcher {
    profile: Option<PathBuf>,
}

impl WindowsPatcher {
    /// Construct the host patcher using configured or product-derived profiles.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn component_root(&self, application: &Path) -> Result<PathBuf> {
        if let Some(profile) = &self.profile {
            return Ok(profile.join("WidevineCdm"));
        }
        Ok(crate::browsers::windows::profile_dir(application)?.join("WidevineCdm"))
    }
}

impl PlatformPatcher for WindowsPatcher {
    fn write_cdm(&self, application: &Path, source: &Path) -> Result<()> {
        let marker = ownership::marker_for_payload(source)?;
        let target = self.cdm_target_for_candidate(application, &marker.cdm_version)?;
        let authorization = TargetAuthorization::capture(&target)?;
        self.write_authorized_managed_cdm(application, &target, source, &marker, &authorization)
            .map(|_| ())
    }

    fn write_managed_cdm(
        &self,
        application: &Path,
        target: &Path,
        source: &Path,
        marker: &ManagedMarker,
    ) -> Result<ManagedWrite> {
        let authorization = TargetAuthorization::capture(target)?;
        self.write_authorized_managed_cdm(application, target, source, marker, &authorization)
    }

    fn write_authorized_managed_cdm(
        &self,
        application: &Path,
        target: &Path,
        source: &Path,
        marker: &ManagedMarker,
        authorization: &TargetAuthorization,
    ) -> Result<ManagedWrite> {
        if self.cdm_target_for_candidate(application, &marker.cdm_version)? != target {
            return Err(Error::state_corrupted(
                "Windows CDM target changed after authorization",
            ));
        }
        let root = self.component_root(application)?;
        let _guards = pin_directories(&root, true)?;
        authorization.validate(target)?;
        if target.exists() {
            let installed = ownership::validate_installed_cdm(target)?;
            if installed.matches_candidate(marker)
                && latest_target(&root)?.as_deref() == Some(target)
            {
                registration::publish(&root, &marker.cdm_version)?;
                return Ok(ManagedWrite::MarkerCommitted);
            }
            return Err(Error::permission_denied("Windows CDM versions are immutable; close the browser and remove the conflicting version explicitly before retrying"));
        }
        if let Some(active) = latest_target(&root)? {
            if version_key(
                active
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default(),
            )? >= version_key(&marker.cdm_version)?
            {
                return Err(Error::invalid_marker(
                    "candidate would not be the active Windows CDM version",
                ));
            }
        }
        let staged = ownership::stage_verified_payload(source, &root, marker)?;
        ownership::write_marker(staged.path(), marker)?;
        ownership::validate_installed_cdm(staged.path())?;
        let staged_identity = TargetAuthorization::capture(staged.path())?;
        authorization.validate(target)?;
        // Windows rename never replaces an existing directory, including a raced-in target.
        fs::rename(staged.path(), target).map_err(Error::from)?;
        let result = ownership::validate_installed_cdm(target).and_then(|installed| {
            if !installed.matches_candidate(marker)
                || latest_target(&root)?.as_deref() != Some(target)
            {
                return Err(Error::invalid_marker(
                    "published Windows CDM did not match the selected candidate",
                ));
            }
            registration::publish(&root, &marker.cdm_version)
        });
        if let Err(error) = result {
            staged_identity.validate(target)?;
            // Do not delete live DLLs: move the new tree back to its private staging
            // name. Older versions have never been modified.
            fs::rename(target, staged.path()).map_err(|rollback| Error::from(rollback).with_context("could not roll back newly published Windows CDM; previous versions retained").with_source(error))?;
            return Err(Error::invalid_marker(
                "Windows CDM publication failed verification and was rolled back",
            ));
        }
        Ok(ManagedWrite::MarkerCommitted)
    }

    fn cdm_target(&self, application: &Path) -> Result<PathBuf> {
        let root = self.component_root(application)?;
        Ok(latest_target(&root)?.unwrap_or_else(|| root.join("0.0.0.0")))
    }
    fn cdm_target_for_candidate(&self, application: &Path, version: &str) -> Result<PathBuf> {
        version_key(version)?;
        Ok(self.component_root(application)?.join(version))
    }
    fn verify_post_patch(&self, application: &Path) -> Result<()> {
        ownership::validate_installed_cdm(&self.cdm_target(application)?).map(|_| ())
    }
    fn read_browser_version(&self, application: &Path) -> Option<String> {
        crate::browsers::windows::version_directory(application)
            .and_then(|path| path.file_name()?.to_str().map(str::to_owned))
            .or_else(|| {
                crate::browsers::windows::product_version(&crate::browsers::windows::executable(
                    application,
                )?)
            })
    }
    fn write_access_root(&self, application: &Path) -> Result<PathBuf> {
        let root = self.component_root(application)?;
        root.ancestors()
            .find(|path| path.is_dir())
            .map(Path::to_path_buf)
            .ok_or_else(|| Error::state_corrupted("Windows profile has no existing parent"))
    }
    fn supports_elevation(&self) -> bool {
        false
    }
    fn writes_transactionally(&self) -> bool {
        true
    }
}

fn version_key(version: &str) -> Result<[u32; 4]> {
    let mut result = [0; 4];
    let mut parts = version.split('.');
    for slot in &mut result {
        let part = parts
            .next()
            .filter(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(|| {
                Error::invalid_marker("CDM version must contain four numeric components")
            })?;
        *slot = part
            .parse()
            .map_err(|_| Error::invalid_marker("CDM version component is too large"))?;
    }
    if parts.next().is_some() {
        return Err(Error::invalid_marker(
            "CDM version must contain four numeric components",
        ));
    }
    Ok(result)
}

// Keep every ancestor open without FILE_SHARE_DELETE, preventing rename/junction
// substitution while publication is in progress. Never traverse a reparse point.
fn pin_directories(path: &Path, create: bool) -> Result<Vec<fs::File>> {
    let mut handles = Vec::new();
    let ancestors: Vec<_> = path.ancestors().collect();
    for ancestor in ancestors.into_iter().rev() {
        if create && !ancestor.exists() {
            fs::create_dir(ancestor).map_err(Error::from)?;
        }
        let handle = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(ancestor)
            .map_err(Error::from)?;
        let metadata = handle.metadata().map_err(Error::from)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::invalid_marker(
                "Windows CDM path contains a reparse point or non-directory",
            ));
        }
        handles.push(handle);
    }
    Ok(handles)
}

fn latest_target(root: &Path) -> Result<Option<PathBuf>> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::from(error)),
        Ok(_) => {}
    }
    let _guards = pin_directories(root, false)?;
    let mut best = None;
    for entry in fs::read_dir(root).map_err(Error::from)? {
        let entry = entry.map_err(Error::from)?;
        let name = entry.file_name();
        let Some(key) = name.to_str().and_then(|name| version_key(name).ok()) else {
            continue;
        };
        let metadata = fs::symlink_metadata(entry.path()).map_err(Error::from)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::invalid_marker(
                "Windows CDM version must be a non-reparse directory",
            ));
        }
        if best.as_ref().is_none_or(|(previous, _)| key > *previous) {
            best = Some((key, entry.path()));
        }
    }
    Ok(best.map(|(_, path)| path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_numeric_and_cannot_escape_component_root() {
        assert!(version_key("4.10.10.0").unwrap() > version_key("4.10.9.0").unwrap());
        for invalid in [
            "../1",
            "1.2.3",
            "1.2.3.4.5",
            "1.2.3.-1",
            "1.2.3.4:stream",
            "1.2.3.4294967296",
        ] {
            assert!(version_key(invalid).is_err());
        }
    }

    #[test]
    fn install_is_idempotent_and_conflicts_preserve_live_payload() {
        let temp = tempfile::tempdir().unwrap();
        let patcher = WindowsPatcher {
            profile: Some(temp.path().join("profile")),
        };
        let source = temp.path().join("source");
        let library = source.join("_platform_specific/win_x64/widevinecdm.dll");
        fs::create_dir_all(library.parent().unwrap()).unwrap();
        fs::write(&library, b"verified fixture").unwrap();
        fs::write(source.join("manifest.json"), br#"{"version":"4.10.2.0"}"#).unwrap();
        let application = temp.path().join("Application");
        patcher.write_cdm(&application, &source).unwrap();
        patcher.write_cdm(&application, &source).unwrap();
        let active = patcher.cdm_target(&application).unwrap();
        ownership::validate_installed_cdm(&active).unwrap();
        fs::write(&library, b"conflicting fixture").unwrap();
        assert!(patcher.write_cdm(&application, &source).is_err());
        assert_eq!(
            fs::read(active.join("_platform_specific/win_x64/widevinecdm.dll")).unwrap(),
            b"verified fixture"
        );
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(temp.path().join("profile/Local State")).unwrap())
                .unwrap();
        assert_eq!(
            state["updateclientdata"]["apps"]["oimompecagnajdejgnnjijobebaeigek"]["pv"],
            "4.10.2.0"
        );
        // A malformed Local State must not be replaced; publishing the next
        // version rolls back while the previous verified payload remains live.
        fs::write(temp.path().join("profile/Local State"), b"malformed").unwrap();
        fs::write(source.join("manifest.json"), br#"{"version":"4.10.3.0"}"#).unwrap();
        assert!(patcher.write_cdm(&application, &source).is_err());
        assert!(!patcher
            .cdm_target_for_candidate(&application, "4.10.3.0")
            .unwrap()
            .exists());
        ownership::validate_installed_cdm(&active).unwrap();
        assert_eq!(
            fs::read(temp.path().join("profile/Local State")).unwrap(),
            b"malformed"
        );
    }

    #[test]
    fn changed_source_fails_before_publication_and_retains_previous_version() {
        let temp = tempfile::tempdir().unwrap();
        let patcher = WindowsPatcher {
            profile: Some(temp.path().join("profile")),
        };
        let source = temp.path().join("source");
        let library = source.join("_platform_specific/win_x64/widevinecdm.dll");
        fs::create_dir_all(library.parent().unwrap()).unwrap();
        fs::write(&library, b"original fixture").unwrap();
        fs::write(source.join("manifest.json"), br#"{"version":"4.10.2.0"}"#).unwrap();
        let marker = ownership::marker_for_payload(&source).unwrap();
        fs::write(&library, b"changed fixture").unwrap();
        let application = temp.path().join("Application");
        let old = patcher
            .cdm_target_for_candidate(&application, "4.10.1.0")
            .unwrap();
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("retained"), b"old").unwrap();
        let target = patcher
            .cdm_target_for_candidate(&application, &marker.cdm_version)
            .unwrap();
        let authorization = TargetAuthorization::capture(&target).unwrap();
        assert!(patcher
            .write_authorized_managed_cdm(&application, &target, &source, &marker, &authorization)
            .is_err());
        assert!(!target.exists());
        assert_eq!(fs::read(old.join("retained")).unwrap(), b"old");
    }
}
