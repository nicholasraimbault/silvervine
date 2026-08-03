//! Browser executable and passive version resolution.

#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::time::Duration;

use crate::browsers::Browser;
use crate::error::{Error, Result};
#[cfg(target_os = "linux")]
use crate::platform::process::{find_executable, run_output_with_timeout};

/// Resolve the executable for a detected Chromium-family browser.
///
/// # Errors
///
/// Returns `UnknownBundleStructure` when the install does not contain the
/// platform's expected executable layout.
pub fn executable_path(browser: &Browser) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let app = browser.install_path();
        let stem = app
            .file_stem()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                Error::unknown_bundle_structure(format!("no bundle name for {}", app.display()))
            })?;
        Ok(app.join("Contents").join("MacOS").join(stem))
    }
    #[cfg(target_os = "linux")]
    {
        let install = browser.install_path();
        for name in [
            browser.name().to_lowercase(),
            "chrome".into(),
            "chromium".into(),
            "chromium-browser".into(),
        ] {
            let candidate = install.join(name);
            if is_executable_file(&candidate) {
                return Ok(candidate);
            }
        }
        Err(Error::unknown_bundle_structure(format!(
            "could not locate browser executable in {}",
            install.display()
        )))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = browser;
        Err(Error::unsupported_platform(
            "browser launch is only implemented on Linux and macOS",
        ))
    }
}

/// Read the browser version without executing the browser or accessing the network.
#[must_use]
pub fn passive_version(browser: &Browser) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        for path in [
            browser.install_path().join("version"),
            browser.install_path().join("chrome").join("VERSION"),
            browser.install_path().join("VERSION"),
        ] {
            if let Some(version) = read_nonempty(&path) {
                return Some(version);
            }
        }
        package_manager_version(browser)
    }
    #[cfg(target_os = "macos")]
    {
        crate::patch::macos::read_info_plist_string(
            browser.install_path(),
            "CFBundleShortVersionString",
        )
        .ok()
        .flatten()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = browser;
        None
    }
}

#[cfg(target_os = "linux")]
fn read_nonempty(path: &Path) -> Option<String> {
    let value = std::fs::read_to_string(path).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(target_os = "linux")]
fn package_manager_version(browser: &Browser) -> Option<String> {
    let executable = executable_path(browser).ok()?;
    let executable = executable.to_str()?;

    if let Some(output) = run_version_command("pacman", &["-Qo", executable]) {
        if let Some(version) = parse_package_version(&output) {
            return Some(version);
        }
    }
    if let Some(output) = run_version_command("dpkg-query", &["-S", executable]) {
        if let Some(package) = parse_dpkg_owner(&output) {
            if let Some(version) =
                run_version_command("dpkg-query", &["-W", "-f=${Version}", &package])
                    .and_then(|value| parse_package_version(&value))
            {
                return Some(version);
            }
        }
    }
    run_version_command(
        "rpm",
        &["-qf", "--queryformat", "%{VERSION}-%{RELEASE}", executable],
    )
    .and_then(|value| parse_package_version(&value))
}

#[cfg(target_os = "linux")]
fn run_version_command(name: &str, arguments: &[&str]) -> Option<String> {
    let executable = find_executable(name)?;
    let output = run_output_with_timeout(&executable, arguments, Duration::from_secs(3)).ok()?;
    if output.timed_out || !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

#[cfg(target_os = "linux")]
fn parse_package_version(output: &str) -> Option<String> {
    let version = output.split_ascii_whitespace().last()?;
    let valid = !version.is_empty()
        && version.len() <= 128
        && version.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '.' | '+' | '~' | ':' | '_' | '-')
        });
    valid.then(|| version.to_owned())
}

#[cfg(target_os = "linux")]
fn parse_dpkg_owner(output: &str) -> Option<String> {
    let package = output.lines().next()?.rsplit_once(": ")?.0.trim();
    let valid = !package.is_empty()
        && package.len() <= 128
        && package.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '.' | ':' | '-')
        });
    valid.then(|| package.to_owned())
}

#[cfg(target_os = "linux")]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::{executable_path, passive_version};
    #[cfg(target_os = "linux")]
    use super::{parse_dpkg_owner, parse_package_version};
    use crate::browsers::{Browser, BrowserKind};

    fn browser(name: &str, install_path: PathBuf) -> Browser {
        Browser {
            name: name.to_owned(),
            install_path,
            kind: BrowserKind::Known,
        }
    }

    #[cfg(target_os = "linux")]
    fn executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, b"#!/bin/sh\nexit 0\n").expect("write executable");
        let mut permissions = fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_path_prefers_lowercase_browser_name() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("Helium");
        fs::create_dir(&install).expect("install");
        executable(&install.join("helium"));
        executable(&install.join("chrome"));

        assert_eq!(
            executable_path(&browser("Helium", install.clone())).expect("path"),
            install.join("helium")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_path_falls_back_to_chrome_then_chromium() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("browser");
        fs::create_dir(&install).expect("install");
        executable(&install.join("chromium"));
        executable(&install.join("chrome"));

        assert_eq!(
            executable_path(&browser("Fork", install.clone())).expect("path"),
            install.join("chrome")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executable_path_rejects_non_executable_candidate() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("browser");
        fs::create_dir(&install).expect("install");
        fs::write(install.join("chrome"), b"plain").expect("plain");

        assert!(executable_path(&browser("Fork", install)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn passive_version_reads_files_without_executing_browser() {
        let tmp = TempDir::new().expect("tempdir");
        let install = tmp.path().join("browser");
        fs::create_dir_all(install.join("chrome")).expect("install");
        fs::write(install.join("chrome/VERSION"), " 150.0.7871.186\n").expect("version");
        let sentinel = tmp.path().join("spawned");
        let binary = install.join("chromium");
        let script = format!("#!/bin/sh\ntouch '{}'\n", sentinel.display());
        fs::write(&binary, script).expect("browser script");
        executable(&binary);

        assert_eq!(
            passive_version(&browser("Chromium", install)).as_deref(),
            Some("150.0.7871.186")
        );
        assert!(!sentinel.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_manager_output_parsers_preserve_exact_installed_versions() {
        assert_eq!(
            parse_package_version("/opt/helium/helium is owned by helium-browser-bin 0.14.9.1-1\n")
                .as_deref(),
            Some("0.14.9.1-1")
        );
        assert_eq!(
            parse_dpkg_owner("chromium:amd64: /usr/lib/chromium/chromium\n").as_deref(),
            Some("chromium:amd64")
        );
        assert_eq!(
            parse_package_version("2:150.0.7871.186-1~deb12u1\n").as_deref(),
            Some("2:150.0.7871.186-1~deb12u1")
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn executable_and_version_resolve_from_app_bundle_without_spawning() {
        let tmp = TempDir::new().expect("tempdir");
        let app = tmp.path().join("Helium.app");
        fs::create_dir_all(app.join("Contents/MacOS")).expect("bundle");
        fs::write(
            app.join("Contents/Info.plist"),
            r"<plist><dict><key>CFBundleShortVersionString</key><string>150.0.1</string></dict></plist>",
        )
        .expect("plist");

        let browser = browser("Helium", app.clone());
        assert_eq!(
            executable_path(&browser).expect("path"),
            app.join("Contents/MacOS/Helium")
        );
        assert_eq!(passive_version(&browser).as_deref(), Some("150.0.1"));
    }
}
