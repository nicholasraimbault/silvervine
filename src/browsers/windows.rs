//! Windows installed and portable Chromium-family browser layouts.
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::{Browser, BrowserKind};

/// Explicit profile selected for this custom installation, never inferred from a fork name.
pub fn configured_user_data_dir(install: &Path) -> crate::error::Result<Option<PathBuf>> {
    let config = crate::config::load_config()?;
    let install = std::fs::canonicalize(install).map_err(crate::Error::from)?;
    Ok(config
        .browsers
        .iter()
        .find(|entry| {
            entry
                .install_path
                .as_deref()
                .and_then(resolve_install)
                .as_ref()
                == Some(&install)
        })
        .and_then(|entry| entry.user_data_dir.clone()))
}

/// Resolve the profile root used by patching, probes, and diagnostics.
#[cfg(windows)]
pub fn profile_dir(application: &Path) -> crate::error::Result<PathBuf> {
    if let Some(profile) = configured_user_data_dir(application)? {
        return Ok(profile);
    }
    let executable = executable(application).ok_or_else(|| {
        crate::Error::unknown_bundle_structure("Windows browser executable is missing")
    })?;
    let product = product_name(&executable).ok_or_else(|| {
        crate::Error::unknown_bundle_structure(
            "Browser product identity unavailable; configure user_data_dir explicitly",
        )
    })?;
    let directory = match product.as_str() {
        "Helium" => "Helium",
        "Thorium" => "Thorium",
        "Chromium" => "Chromium",
        _ => {
            return Err(crate::Error::unknown_bundle_structure(
                "Unknown browser profile; configure user_data_dir explicitly",
            ))
        }
    };
    dirs::data_local_dir()
        .map(|root| root.join(directory).join("User Data"))
        .ok_or_else(|| crate::Error::state_corrupted("Windows LocalAppData is unavailable"))
}

/// Product identity from the executable's version resource, not its filename.
#[cfg(windows)]
pub fn product_name(executable: &Path) -> Option<String> {
    version_resource(executable, "ProductName")
}

/// Passive browser version for flat portable and installed executables.
#[cfg(windows)]
pub fn product_version(executable: &Path) -> Option<String> {
    version_resource(executable, "ProductVersion").filter(|version| !version.is_empty())
}

#[cfg(windows)]
fn version_resource(executable: &Path, field: &str) -> Option<String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "version")]
    unsafe extern "system" {
        fn GetFileVersionInfoSizeW(filename: *const u16, handle: *mut u32) -> u32;
        fn GetFileVersionInfoW(
            filename: *const u16,
            handle: u32,
            length: u32,
            data: *mut c_void,
        ) -> i32;
        fn VerQueryValueW(
            block: *const c_void,
            subblock: *const u16,
            buffer: *mut *mut c_void,
            length: *mut u32,
        ) -> i32;
    }
    let filename: Vec<u16> = executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut ignored = 0;
    // SAFETY: all buffers remain live and Win32 receives their exact lengths.
    unsafe {
        let length = GetFileVersionInfoSizeW(filename.as_ptr(), &mut ignored);
        if length == 0 || length > 1024 * 1024 {
            return None;
        }
        let mut data = vec![0_u8; length as usize];
        if GetFileVersionInfoW(filename.as_ptr(), 0, length, data.as_mut_ptr().cast()) == 0 {
            return None;
        }
        let translations: Vec<u16> = "\\VarFileInfo\\Translation\0".encode_utf16().collect();
        let mut pointer = std::ptr::null_mut();
        let mut size = 0;
        if VerQueryValueW(
            data.as_ptr().cast(),
            translations.as_ptr(),
            &mut pointer,
            &mut size,
        ) == 0
            || size < 4
        {
            return None;
        }
        let language = std::ptr::read_unaligned(pointer.cast::<u16>());
        let codepage = std::ptr::read_unaligned(pointer.cast::<u16>().add(1));
        let key: Vec<u16> = format!("\\StringFileInfo\\{language:04x}{codepage:04x}\\{field}\0")
            .encode_utf16()
            .collect();
        if VerQueryValueW(data.as_ptr().cast(), key.as_ptr(), &mut pointer, &mut size) == 0
            || size == 0
            || size > 1024
        {
            return None;
        }
        let text = std::slice::from_raw_parts(pointer.cast::<u16>(), size as usize);
        Some(
            String::from_utf16_lossy(text)
                .trim_end_matches('\0')
                .to_owned(),
        )
    }
}

/// Known installation suffixes, relative to Program Files or LocalAppData.
pub const KNOWN_WINDOWS: &[(&str, &str)] = &[
    ("Helium", "Helium/Application"),
    ("Helium", "Helium"),
    ("Thorium", "Thorium/Application"),
    ("Thorium", "Thorium"),
    ("Chromium", "Chromium/Application"),
    ("ungoogled-chromium", "ungoogled-chromium"),
];

pub(crate) fn default_roots() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .collect()
}

fn regular(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file())
}

/// Resolve only browser-shaped executable names; never search PATH or launch them.
pub fn executable(install: &Path) -> Option<PathBuf> {
    ["helium.exe", "thorium.exe", "chromium.exe", "chrome.exe"]
        .into_iter()
        .map(|name| install.join(name))
        .find(|path| regular(path))
}

fn version_parts(name: &str) -> Option<Vec<u32>> {
    let parts: Vec<_> = name
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<_, _>>()
        .ok()?;
    (parts.len() == 4).then_some(parts)
}

/// Highest numeric installed browser version containing Chromium's main DLL.
pub fn version_directory(install: &Path) -> Option<PathBuf> {
    std::fs::read_dir(install)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| {
            let parts = version_parts(entry.file_name().to_str()?)?;
            regular(&entry.path().join("chrome.dll")).then(|| (parts, entry.path()))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, path)| path)
}

fn browser_layout(install: &Path) -> bool {
    executable(install).is_some()
        && (regular(&install.join("chrome.dll")) || version_directory(install).is_some())
}

/// Custom entries accept an executable, an Application directory, or its parent.
pub fn resolve_install(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let root = if path.is_file() { path.parent()? } else { path };
    [root.to_path_buf(), root.join("Application")]
        .into_iter()
        .find(|candidate| browser_layout(candidate))
        .and_then(|candidate| std::fs::canonicalize(candidate).ok())
}

pub(crate) fn known(roots: &[PathBuf]) -> Vec<Browser> {
    let mut seen = HashSet::new();
    roots
        .iter()
        .flat_map(|root| {
            KNOWN_WINDOWS.iter().filter_map(|(name, suffix)| {
                let install_path = resolve_install(&root.join(suffix))?;
                Some(Browser {
                    name: (*name).into(),
                    install_path,
                    kind: BrowserKind::Known,
                })
            })
        })
        .filter(|browser| seen.insert(browser.install_path.clone()))
        .collect()
}

pub(crate) fn discover(roots: &[PathBuf]) -> Vec<Browser> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut pending: Vec<_> = roots.iter().map(|root| (root.clone(), 0)).collect();
    while let Some((root, depth)) = pending.pop() {
        let Ok(canonical) = std::fs::canonicalize(&root) else {
            continue;
        };
        if !seen.insert(canonical.clone()) {
            continue;
        }
        if browser_layout(&root) {
            let label = if root.file_name().is_some_and(|name| name == "Application") {
                root.parent().unwrap_or(&root)
            } else {
                &root
            };
            out.push(Browser {
                name: label
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                install_path: canonical,
                kind: BrowserKind::Detected,
            });
            continue;
        }
        if depth >= 3 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    out.sort_by(|left, right| left.install_path.cmp(&right.install_path));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installed_portable_and_custom_layouts_require_chromium_payload() {
        let temp = tempfile::tempdir().unwrap();
        let app = temp.path().join("Helium/Application");
        std::fs::create_dir_all(app.join("130.0.0.1")).unwrap();
        std::fs::write(app.join("helium.exe"), b"browser").unwrap();
        assert!(resolve_install(&app).is_none());
        std::fs::write(app.join("130.0.0.1/chrome.dll"), b"dll").unwrap();
        let canonical = std::fs::canonicalize(&app).unwrap();
        assert_eq!(
            resolve_install(&app.join("helium.exe")),
            Some(canonical.clone())
        );
        assert_eq!(resolve_install(app.parent().unwrap()), Some(canonical));
        assert_eq!(known(&[temp.path().into()]).len(), 1);
        assert_eq!(discover(&[temp.path().into()]).len(), 1);
        let portable = temp.path().join("portable");
        std::fs::create_dir(&portable).unwrap();
        std::fs::write(portable.join("chrome.exe"), b"browser").unwrap();
        std::fs::write(portable.join("chrome.dll"), b"dll").unwrap();
        assert!(resolve_install(&portable).is_some());
        assert!(resolve_install(Path::new("relative/path")).is_none());
        assert!(version_parts("130.0.bad.1").is_none());
        let config = crate::config::Config {
            browsers: vec![crate::config::CustomBrowserConfig {
                name: "Portable fork".into(),
                install_path: Some(portable.join("chrome.exe")),
                user_data_dir: Some(temp.path().join("isolated-profile")),
                bundle_path: None,
                framework_name: None,
            }],
            ..crate::config::Config::default()
        };
        let found = super::super::detect_browsers_with(
            super::super::Os::Windows,
            &super::super::FilesystemRoots::default(),
            &config,
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, BrowserKind::Custom);
        assert_eq!(
            found[0].install_path,
            std::fs::canonicalize(portable).unwrap()
        );
    }
}
