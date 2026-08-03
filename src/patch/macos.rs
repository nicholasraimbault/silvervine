//! macOS implementation of [`crate::patch::PlatformPatcher`] using Chromium's
//! per-user component directory.
//!
//! Silvervine never modifies or re-signs the browser application. Widevine is
//! installed at:
//!
//! ```text
//! ~/Library/Application Support/<browser>/WidevineCdm/<version>/
//! ```
//!
//! Chromium discovers that component layout at startup. Keeping the CDM in the
//! user profile preserves the vendor's application signature, hardened runtime,
//! entitlements, and update path.

use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::patch::{ManagedWrite, PlatformPatcher, TargetAuthorization};
use crate::widevine::ownership::{self, ManagedMarker};
use crate::widevine::{
    platform_directory, platform_library, Platform, CDM_BUNDLE_DIRECTORY,
    PLATFORM_SPECIFIC_DIRECTORY,
};

const ABSENT_COMPONENT_TARGET: &str = ".silvervine-absent";

/// macOS patcher for Chromium-family per-user component directories.
#[derive(Debug, Clone)]
pub struct MacosPatcher {
    application_support: Option<PathBuf>,
}

impl Default for MacosPatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl MacosPatcher {
    /// Build a patcher rooted in the current login user's Application Support.
    #[must_use]
    pub fn new() -> Self {
        Self {
            application_support: dirs::home_dir()
                .map(|home| home.join("Library").join("Application Support")),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_application_support(application_support: PathBuf) -> Self {
        Self {
            application_support: Some(application_support),
        }
    }

    fn application_support(&self) -> Result<&Path> {
        self.application_support.as_deref().ok_or_else(|| {
            Error::state_corrupted(
                "cannot resolve macOS Application Support directory (no login home)",
            )
        })
    }

    fn profile_root(&self, application: &Path) -> Result<PathBuf> {
        checked_application_bundle(application)?;
        let suffix = profile_suffix_for_application(application)?;
        Ok(self.application_support()?.join(suffix))
    }

    fn component_root(&self, application: &Path) -> Result<PathBuf> {
        Ok(self.profile_root(application)?.join(CDM_BUNDLE_DIRECTORY))
    }

    fn ensure_component_root_for_target(&self, target: &Path) -> Result<PathBuf> {
        let component = target.parent().ok_or_else(|| {
            Error::unknown_bundle_structure("macOS Widevine target has no component root")
        })?;
        if component.file_name() != Some(std::ffi::OsStr::new(CDM_BUNDLE_DIRECTORY)) {
            return Err(Error::unknown_bundle_structure(
                "macOS Widevine target is not inside a WidevineCdm component root",
            ));
        }
        let profile = component.parent().ok_or_else(|| {
            Error::unknown_bundle_structure("macOS Widevine component root has no browser profile")
        })?;
        let support = self.application_support()?;
        if profile.parent() != Some(support) {
            return Err(Error::state_corrupted(
                "macOS Widevine target escaped the authorized Application Support directory",
            ));
        }

        ensure_directory_with_parent(support, "Application Support")?;
        ensure_direct_directory(profile, "browser profile")?;
        ensure_direct_directory(component, "Widevine component root")?;
        Ok(component.to_path_buf())
    }

    fn candidate_target(&self, application: &Path, version: &str) -> Result<PathBuf> {
        validate_version(version)?;
        Ok(self.component_root(application)?.join(version))
    }
}

impl PlatformPatcher for MacosPatcher {
    fn write_cdm(&self, application: &Path, cdm_source: &Path) -> Result<()> {
        reject_root_profile_write()?;
        let version = crate::widevine::manifest::read_installed_cdm_version(
            &cdm_source.join("manifest.json"),
        )?;
        validate_version(&version)?;
        let destination = self.candidate_target(application, &version)?;
        let authorization = TargetAuthorization::capture(&destination)?;
        let component_root = self.ensure_component_root_for_target(&destination)?;
        replace_version_transactionally(
            &component_root,
            &destination,
            &version,
            cdm_source,
            None,
            &authorization,
            || self.candidate_target(application, &version),
        )
    }

    fn write_managed_cdm(
        &self,
        application: &Path,
        cdm_target: &Path,
        cdm_source: &Path,
        parent_marker: &ManagedMarker,
    ) -> Result<ManagedWrite> {
        let authorization = TargetAuthorization::capture(cdm_target)?;
        self.write_authorized_managed_cdm(
            application,
            cdm_target,
            cdm_source,
            parent_marker,
            &authorization,
        )
    }

    fn write_authorized_managed_cdm(
        &self,
        application: &Path,
        cdm_target: &Path,
        cdm_source: &Path,
        parent_marker: &ManagedMarker,
        authorization: &TargetAuthorization,
    ) -> Result<ManagedWrite> {
        reject_root_profile_write()?;
        validate_version(&parent_marker.cdm_version)?;
        let expected = self.candidate_target(application, &parent_marker.cdm_version)?;
        if expected != cdm_target {
            return Err(Error::state_corrupted(
                "macOS browser profile changed after target authorization",
            ));
        }
        let component_root = self.ensure_component_root_for_target(cdm_target)?;
        replace_version_transactionally(
            &component_root,
            cdm_target,
            &parent_marker.cdm_version,
            cdm_source,
            Some(parent_marker),
            authorization,
            || self.candidate_target(application, &parent_marker.cdm_version),
        )?;
        Ok(ManagedWrite::MarkerCommitted)
    }

    fn cdm_target(&self, application: &Path) -> Result<PathBuf> {
        let component_root = self.component_root(application)?;
        latest_version_directory(&component_root)
            .map(|target| target.unwrap_or_else(|| component_root.join(ABSENT_COMPONENT_TARGET)))
    }

    fn cdm_target_for_candidate(&self, application: &Path, version: &str) -> Result<PathBuf> {
        self.candidate_target(application, version)
    }

    fn verify_post_patch(&self, application: &Path) -> Result<()> {
        let target = self.cdm_target(application)?;
        verify_payload_at(&target)
    }

    fn read_browser_version(&self, application: &Path) -> Option<String> {
        read_browser_version_at(application)
    }

    fn write_access_root(&self, _application: &Path) -> Result<PathBuf> {
        let support = self.application_support()?;
        if support.is_dir() {
            return Ok(support.to_path_buf());
        }
        support.parent().map(Path::to_path_buf).ok_or_else(|| {
            Error::state_corrupted("macOS Application Support directory has no parent")
        })
    }

    fn supports_elevation(&self) -> bool {
        false
    }

    fn writes_transactionally(&self) -> bool {
        true
    }
}

/// Known macOS profile directory suffixes, in runtime preference order.
///
/// Diagnostics inspect every suffix. The patcher writes only the first suffix,
/// which is the browser's current canonical component root.
pub(crate) fn profile_support_suffixes(browser_name: &str) -> &'static [&'static str] {
    match browser_name {
        "helium" => &["net.imput.helium", "Helium"],
        "thorium" => &["Thorium"],
        "ungoogled-chromium" | "chromium" => &["Chromium", "ungoogled-chromium"],
        _ => &[],
    }
}

fn profile_suffix_for_application(application: &Path) -> Result<String> {
    let plist = read_info_plist(application)?;

    if let Some(value) = plist_dictionary_string(&plist, "CrProductDirName") {
        validate_profile_suffix(value)?;
        return Ok(value.to_owned());
    }

    let identifier =
        plist_dictionary_string(&plist, "CFBundleIdentifier").map(str::to_ascii_lowercase);
    if identifier.as_deref() == Some("net.imput.helium") {
        return Ok("net.imput.helium".into());
    }

    if let Some(value) = plist_dictionary_string(&plist, "CFBundleName") {
        validate_profile_suffix(value)?;
        return Ok(value.to_owned());
    }

    if let Some(identifier) = identifier {
        if identifier.contains("thorium") {
            return Ok("Thorium".into());
        }
        if identifier.contains("chromium") {
            return Ok("Chromium".into());
        }
    }

    let stem = application
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            Error::unknown_bundle_structure(format!(
                "browser application has no valid name: {}",
                application.display()
            ))
        })?;
    match stem.to_ascii_lowercase().as_str() {
        "helium" => return Ok("net.imput.helium".into()),
        "thorium" => return Ok("Thorium".into()),
        "chromium" | "ungoogled-chromium" => return Ok("Chromium".into()),
        _ => {}
    }

    validate_profile_suffix(stem)?;
    Ok(stem.to_owned())
}

fn validate_profile_suffix(suffix: &str) -> Result<()> {
    let mut components = Path::new(suffix).components();
    let valid = !suffix.is_empty()
        && matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if !valid {
        return Err(Error::unknown_bundle_structure(format!(
            "macOS browser profile name is not one safe path component: {suffix}"
        )));
    }
    Ok(())
}

fn reject_root_profile_write() -> Result<()> {
    if crate::platform::is_running_as_root() {
        return Err(Error::permission_denied(
            "macOS Widevine must be installed as the login user, not root",
        ));
    }
    Ok(())
}

fn checked_application_bundle(application: &Path) -> Result<()> {
    checked_directory(application, "browser application")?;
    let contents = application.join("Contents");
    checked_directory(&contents, "browser Contents directory")?;
    checked_regular_file(&contents.join("Info.plist"), "browser Info.plist")
}

fn checked_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ctx_err(
            error,
            format!("could not inspect {label} {}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(Error::unknown_bundle_structure(format!(
            "{label} is not a non-symlink directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn checked_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ctx_err(
            error,
            format!("could not inspect {label} {}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(Error::unknown_bundle_structure(format!(
            "{label} is not a non-symlink regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_directory_with_parent(path: &Path, label: &str) -> Result<()> {
    if path.exists() {
        return checked_directory(path, label);
    }
    let parent = path.parent().ok_or_else(|| {
        Error::unknown_bundle_structure(format!("{label} has no parent: {}", path.display()))
    })?;
    checked_directory(parent, "Application Support parent")?;
    fs::create_dir(path).map_err(|error| {
        ctx_err(
            error,
            format!("could not create {label} {}", path.display()),
        )
    })?;
    checked_directory(path, label)
}

fn ensure_direct_directory(path: &Path, label: &str) -> Result<()> {
    if path.exists() {
        return checked_directory(path, label);
    }
    let parent = path.parent().ok_or_else(|| {
        Error::unknown_bundle_structure(format!("{label} has no parent: {}", path.display()))
    })?;
    checked_directory(parent, "component parent")?;
    fs::create_dir(path).map_err(|error| {
        ctx_err(
            error,
            format!("could not create {label} {}", path.display()),
        )
    })?;
    checked_directory(path, label)
}

fn validate_version(version: &str) -> Result<()> {
    let mut components = Path::new(version).components();
    let single_component = matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none();
    if !single_component || numeric_version(version).is_none() {
        return Err(Error::unknown_bundle_structure(format!(
            "Widevine version is not a dotted numeric path component: {version}"
        )));
    }
    Ok(())
}

fn numeric_version(version: &str) -> Option<Vec<u64>> {
    if version.is_empty() {
        return None;
    }
    version
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .ok()
}

fn compare_numeric_versions(left: &[u64], right: &[u64]) -> Ordering {
    let width = left.len().max(right.len());
    (0..width)
        .map(|index| {
            left.get(index)
                .copied()
                .unwrap_or_default()
                .cmp(&right.get(index).copied().unwrap_or_default())
        })
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}

fn latest_version_directory(component_root: &Path) -> Result<Option<PathBuf>> {
    let metadata = match fs::symlink_metadata(component_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ctx_err(
                error,
                format!("could not inspect {}", component_root.display()),
            ));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(Error::unknown_bundle_structure(format!(
            "Widevine component root is not a non-symlink directory: {}",
            component_root.display()
        )));
    }

    let mut best: Option<(Vec<u64>, PathBuf)> = None;
    for entry in fs::read_dir(component_root).map_err(|error| {
        ctx_err(
            error,
            format!("could not read {}", component_root.display()),
        )
    })? {
        let entry = entry.map_err(|error| {
            ctx_err(
                error,
                format!("could not inspect entry in {}", component_root.display()),
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            ctx_err(
                error,
                format!("could not inspect {}", entry.path().display()),
            )
        })?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(version) = numeric_version(&name) else {
            continue;
        };
        if best.as_ref().is_none_or(|(current, _)| {
            compare_numeric_versions(&version, current) == Ordering::Greater
        }) {
            best = Some((version, entry.path()));
        }
    }
    Ok(best.map(|(_, path)| path))
}

fn validate_published_component<F>(
    component_root: &Path,
    destination: &Path,
    parent_marker: Option<&ManagedMarker>,
    resolve_destination: &F,
) -> Result<()>
where
    F: Fn() -> Result<PathBuf>,
{
    verify_payload_at(destination)?;
    if let Some(marker) = parent_marker {
        let installed = ownership::validate_installed_cdm(destination)?;
        if installed.marker() != marker {
            return Err(Error::invalid_marker(
                "macOS profile publication committed an unexpected ownership marker",
            ));
        }
    }
    if resolve_destination()? != destination {
        return Err(Error::state_corrupted(
            "macOS browser profile changed during CDM publication",
        ));
    }
    let active = latest_version_directory(component_root)?;
    if active.as_deref() != Some(destination) {
        let active = active.map_or_else(|| "<none>".to_owned(), |path| path.display().to_string());
        return Err(Error::state_corrupted(format!(
            "published macOS CDM did not become active; active target is {active}"
        )));
    }
    Ok(())
}

fn replace_version_transactionally<F>(
    component_root: &Path,
    destination: &Path,
    version: &str,
    cdm_source: &Path,
    parent_marker: Option<&ManagedMarker>,
    authorization: &TargetAuthorization,
    resolve_destination: F,
) -> Result<()>
where
    F: Fn() -> Result<PathBuf>,
{
    checked_directory(cdm_source, "cached Widevine payload")?;
    checked_directory(component_root, "Widevine component root")?;
    if component_root.join(version) != destination {
        return Err(Error::state_corrupted(
            "macOS publication target does not match the selected CDM version",
        ));
    }

    let staging = tempfile::Builder::new()
        .prefix(".silvervine-widevine-")
        .tempdir_in(component_root)
        .map_err(|error| {
            ctx_err(
                error,
                format!(
                    "could not create staging directory in {}",
                    component_root.display()
                ),
            )
        })?;
    let staged = staging.path().join(version);
    fs::create_dir(&staged).map_err(|error| {
        ctx_err(
            error,
            format!("could not create staged payload {}", staged.display()),
        )
    })?;
    copy_recursive(cdm_source, &staged)?;
    verify_payload_at(&staged)?;

    if let Some(marker) = parent_marker {
        let copied = ownership::marker_for_finalized_payload(&staged, marker)?;
        if &copied != marker {
            return Err(Error::invalid_marker(
                "macOS profile copy changed the parent-selected CDM payload",
            ));
        }
        ownership::write_marker(&staged, marker)?;
        let installed = ownership::validate_installed_cdm(&staged)?;
        if installed.marker() != marker {
            return Err(Error::invalid_marker(
                "macOS profile staging committed an unexpected ownership marker",
            ));
        }
    }

    if resolve_destination()? != destination {
        return Err(Error::state_corrupted(
            "macOS browser profile changed after target authorization",
        ));
    }
    authorization.validate(destination)?;
    let published_authorization = TargetAuthorization::capture(&staged)?;
    crate::platform::atomic_rename(&staged, destination)?;
    let exchanged = fs::symlink_metadata(&staged).is_ok();

    let live_validation = authorization.validate(&staged).and_then(|()| {
        validate_published_component(
            component_root,
            destination,
            parent_marker,
            &resolve_destination,
        )
    });
    if let Err(verify_error) = live_validation {
        let rollback = published_authorization
            .validate(destination)
            .and_then(|()| {
                if exchanged {
                    authorization.validate(&staged)?;
                    crate::platform::atomic_rename(&staged, destination)
                } else {
                    crate::platform::atomic_rename(destination, &staged)
                }
            })
            .and_then(|()| authorization.validate(destination))
            .and_then(|()| published_authorization.validate(&staged));
        if let Err(rollback_error) = rollback {
            let recovery = staging.keep();
            return Err(Error::new(
                verify_error.category,
                format!(
                    "{}; rollback also failed and transaction state was preserved at {}",
                    verify_error.message,
                    recovery.display()
                ),
            )
            .with_source(rollback_error));
        }
        if let Err(cleanup_error) = super::close_authorized_staging(
            staging,
            &staged,
            &published_authorization,
            component_root,
        ) {
            let category = verify_error.category;
            let message = format!("{}; {}", verify_error.message, cleanup_error.message);
            return Err(Error::new(category, message).with_source(cleanup_error));
        }
        return Err(verify_error);
    }

    super::close_authorized_staging(staging, &staged, authorization, component_root)?;
    Ok(())
}

fn copy_recursive(source: &Path, destination: &Path) -> Result<()> {
    for entry in fs::read_dir(source)
        .map_err(|error| ctx_err(error, format!("could not read {}", source.display())))?
    {
        let entry = entry.map_err(|error| {
            ctx_err(
                error,
                format!("could not inspect entry in {}", source.display()),
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().map_err(|error| {
            ctx_err(
                error,
                format!("could not inspect {}", source_path.display()),
            )
        })?;
        if file_type.is_dir() {
            fs::create_dir(&destination_path).map_err(|error| {
                ctx_err(
                    error,
                    format!("could not create {}", destination_path.display()),
                )
            })?;
            copy_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).map_err(|error| {
                ctx_err(
                    error,
                    format!(
                        "could not copy {} to {}",
                        source_path.display(),
                        destination_path.display()
                    ),
                )
            })?;
        } else {
            return Err(Error::unknown_bundle_structure(format!(
                "cached Widevine payload contains a non-regular entry: {}",
                source_path.display()
            )));
        }
    }
    Ok(())
}

fn verify_payload_at(version_root: &Path) -> Result<()> {
    checked_directory(version_root, "Widevine version directory")?;
    let manifest = version_root.join("manifest.json");
    checked_nonempty_regular_file(&manifest, "Widevine manifest")?;
    let library = version_root
        .join(PLATFORM_SPECIFIC_DIRECTORY)
        .join(platform_directory(mac_platform()))
        .join(platform_library(mac_platform()));
    checked_nonempty_regular_file(&library, "Widevine library")
}

fn checked_nonempty_regular_file(path: &Path, label: &str) -> Result<()> {
    checked_regular_file(path, label)?;
    let metadata = fs::metadata(path).map_err(|error| {
        ctx_err(
            error,
            format!("could not inspect {label} {}", path.display()),
        )
    })?;
    if metadata.len() == 0 {
        return Err(Error::unknown_bundle_structure(format!(
            "{label} is empty: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(test))]
const fn mac_platform() -> Platform {
    #[cfg(target_arch = "aarch64")]
    {
        Platform::DarwinAarch64
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        Platform::DarwinX86_64
    }
}

#[cfg(test)]
fn mac_platform() -> Platform {
    crate::widevine::current_platform_key().expect("test host platform")
}

fn read_info_plist(application: &Path) -> Result<plist::Dictionary> {
    let path = application.join("Contents").join("Info.plist");
    let value = plist::Value::from_file(&path).map_err(|error| {
        Error::unknown_bundle_structure(format!(
            "could not parse browser metadata {}: {error}",
            path.display()
        ))
    })?;
    match value {
        plist::Value::Dictionary(dictionary) => Ok(dictionary),
        _ => Err(Error::unknown_bundle_structure(format!(
            "browser metadata is not a property-list dictionary: {}",
            path.display()
        ))),
    }
}

fn plist_dictionary_string<'a>(dictionary: &'a plist::Dictionary, key: &str) -> Option<&'a str> {
    dictionary
        .get(key)?
        .as_string()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn read_info_plist_string(application: &Path, key: &str) -> Result<Option<String>> {
    let dictionary = read_info_plist(application)?;
    Ok(plist_dictionary_string(&dictionary, key).map(str::to_owned))
}

fn read_browser_version_at(application: &Path) -> Option<String> {
    read_info_plist_string(application, "CFBundleShortVersionString")
        .ok()
        .flatten()
}

fn ctx_err(error: std::io::Error, context: String) -> Error {
    Error::from(error).with_context(context)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::widevine::cache::CachedCdm;

    fn make_application(root: &Path, name: &str, identifier: &str) -> PathBuf {
        let application = root.join(format!("{name}.app"));
        let contents = application.join("Contents");
        fs::create_dir_all(&contents).expect("application contents");
        fs::write(
            contents.join("Info.plist"),
            format!(
                "<plist><dict><key>CFBundleIdentifier</key><string>{identifier}</string><key>CFBundleShortVersionString</key><string>150.0.7871.186</string></dict></plist>"
            ),
        )
        .expect("Info.plist");
        fs::write(contents.join("vendor-signature-sentinel"), b"unchanged")
            .expect("signature sentinel");
        application
    }

    fn make_cached_payload(root: &Path, version: &str) -> CachedCdm {
        let payload = root.join("payload");
        let platform = payload
            .join(PLATFORM_SPECIFIC_DIRECTORY)
            .join(platform_directory(mac_platform()));
        fs::create_dir_all(&platform).expect("platform directory");
        fs::write(
            payload.join("manifest.json"),
            format!(r#"{{"name":"WidevineCdm","version":"{version}"}}"#),
        )
        .expect("manifest");
        fs::write(
            platform.join(platform_library(mac_platform())),
            b"signed-dylib",
        )
        .expect("library");
        let marker = ownership::marker_for_payload(&payload).expect("payload marker");
        CachedCdm::from_verified_payload(
            version.to_owned(),
            payload,
            marker.library_sha512,
            marker.manifest_sha512,
        )
    }

    fn write_test_payload(target: &Path, version: &str, library: &[u8]) {
        let platform = target
            .join(PLATFORM_SPECIFIC_DIRECTORY)
            .join(platform_directory(mac_platform()));
        fs::create_dir_all(&platform).expect("platform directory");
        fs::write(
            target.join("manifest.json"),
            format!(r#"{{"name":"WidevineCdm","version":"{version}"}}"#),
        )
        .expect("manifest");
        fs::write(platform.join(platform_library(mac_platform())), library).expect("library");
    }

    fn install_managed_component(target: &Path, cached: &CachedCdm) {
        fs::create_dir_all(target).expect("component target");
        copy_recursive(cached.cdm_dir(), target).expect("copy cached component");
        let marker = ownership::marker_for_cached(cached).expect("managed marker");
        ownership::write_marker(target, &marker).expect("write managed marker");
    }

    #[test]
    fn helium_candidate_target_is_versioned_profile_component() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let support = tmp.path().join("Library/Application Support");
        fs::create_dir_all(&support).expect("application support");
        let patcher = MacosPatcher::for_application_support(support.clone());

        let target = patcher
            .cdm_target_for_candidate(&application, "4.10.3050.0")
            .expect("profile target");

        assert_eq!(
            target,
            support
                .join("net.imput.helium")
                .join("WidevineCdm")
                .join("4.10.3050.0")
        );
    }

    #[test]
    fn managed_write_installs_profile_component_without_touching_application() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let support = tmp.path().join("Library/Application Support");
        fs::create_dir_all(&support).expect("application support");
        let patcher = MacosPatcher::for_application_support(support.clone());
        let cached = make_cached_payload(tmp.path(), "4.10.3050.0");
        let marker = ownership::marker_for_cached(&cached).expect("candidate marker");
        let installed = support.join("net.imput.helium/WidevineCdm/4.10.3050.0");

        let outcome = patcher
            .write_managed_cdm(&application, &installed, cached.cdm_dir(), &marker)
            .expect("profile write");

        assert_eq!(outcome, ManagedWrite::MarkerCommitted);
        assert_eq!(
            ownership::validate_installed_cdm(&installed)
                .expect("installed marker")
                .marker(),
            &marker
        );
        assert_eq!(
            fs::read(application.join("Contents/vendor-signature-sentinel"))
                .expect("application sentinel"),
            b"unchanged"
        );
        assert!(!application.join("Contents/Frameworks/WidevineCdm").exists());
    }

    #[test]
    fn managed_write_preserves_target_created_after_authorization() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let support = tmp.path().join("Library/Application Support");
        fs::create_dir_all(&support).expect("application support");
        let patcher = MacosPatcher::for_application_support(support.clone());
        let cached = make_cached_payload(tmp.path(), "4.10.3050.0");
        let marker = ownership::marker_for_cached(&cached).expect("candidate marker");
        let installed = support.join("net.imput.helium/WidevineCdm/4.10.3050.0");
        let authorization =
            crate::patch::TargetAuthorization::capture(&installed).expect("missing target");
        fs::create_dir_all(&installed).expect("concurrent external target");
        fs::write(installed.join("external-sentinel"), b"preserve").expect("external sentinel");

        let error = patcher
            .write_authorized_managed_cdm(
                &application,
                &installed,
                cached.cdm_dir(),
                &marker,
                &authorization,
            )
            .expect_err("a target created after authorization must be preserved");

        assert_eq!(error.category, crate::ErrorCategory::StateCorrupted);
        assert_eq!(
            fs::read(installed.join("external-sentinel")).expect("preserved external target"),
            b"preserve"
        );
        assert!(!installed.join(ownership::MANAGED_MARKER_FILENAME).exists());
    }
    #[test]
    fn patch_preserves_higher_active_external_component() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let support = tmp.path().join("Library/Application Support");
        let component_root = support.join("net.imput.helium/WidevineCdm");
        fs::create_dir_all(&component_root).expect("component root");
        let active = component_root.join("4.10.4000.0");
        write_test_payload(&active, "4.10.4000.0", b"external-dylib");
        let candidate = make_cached_payload(&tmp.path().join("candidate"), "4.10.3050.0");
        let candidate_target = component_root.join(candidate.version());
        let patcher = MacosPatcher::for_application_support(support);
        let browser = crate::browsers::Browser {
            name: "Helium".into(),
            install_path: application,
            kind: crate::browsers::BrowserKind::Known,
        };

        let error = crate::patch::patch_browser(
            &browser,
            &candidate,
            &patcher,
            &crate::patch::PatchOptions {
                force_while_running: true,
                lock_path: Some(tmp.path().join("patch.lock")),
                ..Default::default()
            },
        )
        .expect_err("active external component must be preserved");

        assert_eq!(error.category, crate::ErrorCategory::ExternalCdm);
        assert!(!candidate_target.exists());
        assert!(active.exists());
    }

    #[test]
    fn patch_rolls_back_candidate_that_cannot_become_active() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let support = tmp.path().join("Library/Application Support");
        let component_root = support.join("net.imput.helium/WidevineCdm");
        let active_cache = make_cached_payload(&tmp.path().join("active"), "4.10.4000.0");
        let active = component_root.join(active_cache.version());
        install_managed_component(&active, &active_cache);
        let candidate = make_cached_payload(&tmp.path().join("candidate"), "4.10.3050.0");
        let candidate_target = component_root.join(candidate.version());
        let patcher = MacosPatcher::for_application_support(support);
        let browser = crate::browsers::Browser {
            name: "Helium".into(),
            install_path: application,
            kind: crate::browsers::BrowserKind::Known,
        };

        let error = crate::patch::patch_browser(
            &browser,
            &candidate,
            &patcher,
            &crate::patch::PatchOptions {
                force_while_running: true,
                lock_path: Some(tmp.path().join("patch.lock")),
                ..Default::default()
            },
        )
        .expect_err("an inactive candidate must not report success");

        assert!(error.message.contains("active"));
        assert!(!candidate_target.exists());
        assert!(ownership::validate_installed_cdm(&active).is_ok());
    }

    #[test]
    fn managed_write_rejects_profile_change_after_target_authorization() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let support = tmp.path().join("Library/Application Support");
        fs::create_dir_all(&support).expect("application support");
        let patcher = MacosPatcher::for_application_support(support.clone());
        let cached = make_cached_payload(&tmp.path().join("candidate"), "4.10.3050.0");
        let marker = ownership::marker_for_cached(&cached).expect("candidate marker");
        let authorized = patcher
            .cdm_target_for_candidate(&application, cached.version())
            .expect("authorized target");
        fs::write(
            application.join("Contents/Info.plist"),
            "<plist><dict><key>CFBundleIdentifier</key><string>org.chromium.Thorium</string></dict></plist>",
        )
        .expect("changed Info.plist");

        let error = patcher
            .write_managed_cdm(&application, &authorized, cached.cdm_dir(), &marker)
            .expect_err("profile remapping must invalidate the authorized target");

        assert!(error.message.contains("profile"));
        assert!(!authorized.exists());
        assert!(!support
            .join("Thorium/WidevineCdm")
            .join(cached.version())
            .exists());
    }

    #[test]
    fn current_target_uses_highest_numeric_component_version() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let support = tmp.path().join("Library/Application Support");
        let root = support.join("net.imput.helium/WidevineCdm");
        fs::create_dir_all(root.join("4.10.999.0")).expect("old version");
        fs::create_dir_all(root.join("4.10.3050.0")).expect("new version");
        let patcher = MacosPatcher::for_application_support(support);

        assert_eq!(
            patcher.cdm_target(&application).expect("target"),
            root.join("4.10.3050.0")
        );
    }

    #[test]
    fn empty_component_root_classifies_as_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let support = tmp.path().join("Library/Application Support");
        let root = support.join("net.imput.helium/WidevineCdm");
        fs::create_dir_all(&root).expect("empty component root");
        let patcher = MacosPatcher::for_application_support(support);
        let target = patcher.cdm_target(&application).expect("target");
        let browser = crate::browsers::Browser {
            name: "Helium".into(),
            install_path: application,
            kind: crate::browsers::BrowserKind::Known,
        };

        assert_eq!(target, root.join(ABSENT_COMPONENT_TARGET));
        assert_eq!(
            ownership::classify_without_candidate(&browser, &target)
                .expect("ownership")
                .kind,
            crate::widevine::ownership::OwnershipKind::Missing
        );
        assert_eq!(
            crate::daemon::select_patch_action(&browser, None, false, &target),
            crate::daemon::PatchSelection::Patch
        );
    }

    #[test]
    fn helium_profile_mapping_keeps_diagnostics_fallback_after_canonical_root() {
        assert_eq!(
            profile_support_suffixes("helium"),
            &["net.imput.helium", "Helium"]
        );
    }

    #[test]
    fn write_access_root_is_application_support_not_application_parent() {
        let tmp = TempDir::new().expect("tempdir");
        let support = tmp.path().join("Library/Application Support");
        fs::create_dir_all(&support).expect("application support");
        let patcher = MacosPatcher::for_application_support(support.clone());

        assert_eq!(
            patcher
                .write_access_root(Path::new("/Applications/Helium.app"))
                .expect("write root"),
            support
        );
        assert!(!patcher.supports_elevation());
    }

    #[test]
    fn read_browser_version_parses_info_plist() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let patcher = MacosPatcher::for_application_support(tmp.path().to_path_buf());

        assert_eq!(
            patcher.read_browser_version(&application).as_deref(),
            Some("150.0.7871.186")
        );
    }

    #[test]
    fn binary_info_plist_resolves_profile_and_browser_version() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert(
            "CFBundleIdentifier".into(),
            plist::Value::String("net.imput.helium".into()),
        );
        dictionary.insert(
            "CFBundleShortVersionString".into(),
            plist::Value::String("150.0.7871.186".into()),
        );
        plist::Value::Dictionary(dictionary)
            .to_file_binary(application.join("Contents/Info.plist"))
            .expect("binary Info.plist");
        let support = tmp.path().join("Library/Application Support");
        fs::create_dir_all(&support).expect("application support");
        let patcher = MacosPatcher::for_application_support(support.clone());

        assert_eq!(
            patcher
                .cdm_target_for_candidate(&application, "4.10.3050.0")
                .expect("binary plist target"),
            support.join("net.imput.helium/WidevineCdm/4.10.3050.0")
        );
        assert_eq!(
            patcher.read_browser_version(&application).as_deref(),
            Some("150.0.7871.186")
        );
    }

    #[test]
    fn explicit_product_directory_precedes_chromium_bundle_heuristic() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Customium", "org.chromium.Customium");
        fs::write(
            application.join("Contents/Info.plist"),
            "<plist><dict>\
             <key>CFBundleIdentifier</key><string>org.chromium.Customium</string>\
             <key>CrProductDirName</key><string>Customium Data</string>\
             </dict></plist>",
        )
        .expect("custom Info.plist");
        let support = tmp.path().join("Library/Application Support");
        fs::create_dir_all(&support).expect("application support");
        let patcher = MacosPatcher::for_application_support(support.clone());

        assert_eq!(
            patcher
                .cdm_target_for_candidate(&application, "4.10.3050.0")
                .expect("custom profile target"),
            support.join("Customium Data/WidevineCdm/4.10.3050.0")
        );
    }

    #[test]
    fn candidate_target_rejects_path_like_version() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Helium", "net.imput.helium");
        let patcher = MacosPatcher::for_application_support(tmp.path().to_path_buf());

        let error = patcher
            .cdm_target_for_candidate(&application, "../escape")
            .expect_err("path-like version must fail");
        assert_eq!(error.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn custom_browser_uses_declared_product_profile_directory() {
        let tmp = TempDir::new().expect("tempdir");
        let application = make_application(tmp.path(), "Customium", "org.example.customium");
        fs::write(
            application.join("Contents/Info.plist"),
            "<plist><dict><key>CFBundleIdentifier</key><string>org.example.customium</string><key>CrProductDirName</key><string>Customium Data</string></dict></plist>",
        )
        .expect("custom Info.plist");
        let support = tmp.path().join("Library/Application Support");
        fs::create_dir_all(&support).expect("application support");
        let patcher = MacosPatcher::for_application_support(support.clone());

        assert_eq!(
            patcher
                .cdm_target_for_candidate(&application, "4.10.3050.0")
                .expect("custom profile target"),
            support.join("Customium Data/WidevineCdm/4.10.3050.0")
        );
    }

    #[cfg(unix)]
    #[test]
    fn candidate_target_rejects_symlinked_application() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().expect("tempdir");
        let real = make_application(tmp.path(), "RealHelium", "net.imput.helium");
        let linked = tmp.path().join("Helium.app");
        symlink(real, &linked).expect("application symlink");
        let patcher = MacosPatcher::for_application_support(tmp.path().to_path_buf());

        assert!(patcher
            .cdm_target_for_candidate(&linked, "4.10.3050.0")
            .is_err());
    }
}
