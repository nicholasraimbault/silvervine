//! Linux implementation of [`crate::patch::PlatformPatcher`].
//!
//! Per the spec ("Linux → Atomic patch protocol"):
//!
//! > `cp -R`-equivalent into `<browser>/WidevineCdm/`; chmod 755.
//!
//! No codesign, no `xattr -cr` — those are macOS concerns. The Linux
//! patch is conceptually:
//!
//! 1. `mkdir -p <install_path>/WidevineCdm`
//! 2. recursive copy from `<cdm_source>` into `<install_path>/WidevineCdm`
//! 3. chmod each file to 0644 / each directory to 0755
//!
//! ## Verification
//!
//! Post-patch we look for `<install_path>/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so`.
//! If present and non-empty → success; otherwise → `UnknownBundleStructure`.
//!
//! ## Browser version detection
//!
//! Chromium on Linux usually emits a `chrome` (or `<browser>`) binary in
//! the install root. We try, in order:
//!
//! 1. `<install_path>/version` — some forks keep a literal version file.
//! 2. `<install_path>/chrome/VERSION` — Chromium official layout.
//! 3. `<install_path>/<single binary>` — `--version` (best-effort, with
//!    a 1s timeout to avoid hanging on a misbehaving binary).
//!
//! Returns `None` on any failure — version detection is best-effort.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::patch::PlatformPatcher;

/// Linux platform patcher.
///
/// Implements [`PlatformPatcher`] for the Linux Chromium-family bundle
/// layout. Construct with [`LinuxPatcher::new`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxPatcher;

impl LinuxPatcher {
    /// Build a new Linux patcher. The struct is stateless — every method
    /// derives its arguments from the `target` and `cdm_source` paths.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl PlatformPatcher for LinuxPatcher {
    fn write_cdm(&self, target: &Path, cdm_source: &Path) -> Result<()> {
        write_cdm_into(target, cdm_source)
    }

    fn verify_post_patch(&self, target: &Path) -> Result<()> {
        verify_cdm_at(target)
    }

    fn read_browser_version(&self, target: &Path) -> Option<String> {
        read_browser_version_at(target)
    }
}

/// Where the Linux patch puts the CDM, relative to the browser's install path.
///
/// Exposed publicly so the daemon's "is patched" check (Phase 3) can
/// look at the same location.
pub const CDM_SUBDIR: &str = "WidevineCdm";

/// File mode for regular files inside `WidevineCdm/`.
const FILE_MODE: u32 = 0o644;

/// File mode for directories inside `WidevineCdm/`.
const DIR_MODE: u32 = 0o755;

/// File mode for the CDM .so itself (matches what Chromium expects).
const CDM_SO_MODE: u32 = 0o755;

fn write_cdm_into(target: &Path, cdm_source: &Path) -> Result<()> {
    if !cdm_source.exists() {
        return Err(Error::unknown_bundle_structure(format!(
            "CDM source directory does not exist: {}",
            cdm_source.display()
        )));
    }
    if !target.exists() {
        return Err(Error::unknown_bundle_structure(format!(
            "browser install path does not exist: {}",
            target.display()
        )));
    }
    let dest = target.join(CDM_SUBDIR);
    // Idempotent: if `WidevineCdm/` already exists from a prior patch,
    // remove it so the new copy starts fresh. We hold the patch lockfile
    // (the orchestrator acquired it) so no other Neon invocation can be
    // racing here.
    if dest.exists() {
        fs::remove_dir_all(&dest)
            .map_err(|e| context_err(e, format!("could not clear {}", dest.display())))?;
    }
    fs::create_dir_all(&dest)
        .map_err(|e| context_err(e, format!("could not create {}", dest.display())))?;
    set_permissions(&dest, DIR_MODE)?;
    copy_recursive(cdm_source, &dest)?;
    Ok(())
}

/// Recursive copy of `src/*` into `dst`, applying mode bits as we go.
///
/// We don't use `std::fs::copy` directly on the directory because that
/// only copies a single file. The implementation is a small explicit
/// walker so we can:
///
/// 1. Apply the appropriate `FILE_MODE` / `DIR_MODE` per entry.
/// 2. Set the CDM `.so` bit explicitly to `0755` (matches existing bash
///    `fix-drm.sh` behavior).
/// 3. Surface clear path-context error messages.
fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in fs::read_dir(src)
        .map_err(|e| context_err(e, format!("could not read {}", src.display())))?
    {
        let entry =
            entry.map_err(|e| context_err(e, format!("error iterating {}", src.display())))?;
        let path = entry.path();
        let name = entry.file_name();
        let dst_path = dst.join(&name);
        let file_type = entry
            .file_type()
            .map_err(|e| context_err(e, format!("file_type({})", path.display())))?;
        if file_type.is_dir() {
            fs::create_dir_all(&dst_path)
                .map_err(|e| context_err(e, format!("mkdir {}", dst_path.display())))?;
            set_permissions(&dst_path, DIR_MODE)?;
            copy_recursive(&path, &dst_path)?;
        } else if file_type.is_file() {
            fs::copy(&path, &dst_path).map_err(|e| {
                context_err(
                    e,
                    format!("copy {} -> {}", path.display(), dst_path.display()),
                )
            })?;
            // The CDM library itself needs to be executable so the
            // browser can mmap it; everything else is plain data.
            let mode = if name == "libwidevinecdm.so" {
                CDM_SO_MODE
            } else {
                FILE_MODE
            };
            set_permissions(&dst_path, mode)?;
        } else {
            // Symlinks, sockets, FIFOs aren't part of a CDM bundle — skip
            // silently. (`extract` produces only files + directories.)
        }
    }
    Ok(())
}

fn verify_cdm_at(target: &Path) -> Result<()> {
    let so = target
        .join(CDM_SUBDIR)
        .join("_platform_specific")
        .join("linux_x64")
        .join("libwidevinecdm.so");
    if !so.exists() {
        return Err(Error::unknown_bundle_structure(format!(
            "post-patch verify: missing {}",
            so.display()
        )));
    }
    let meta = fs::metadata(&so)
        .map_err(|e| context_err(e, format!("post-patch verify: stat {}", so.display())))?;
    if meta.len() == 0 {
        return Err(Error::unknown_bundle_structure(format!(
            "post-patch verify: {} is empty",
            so.display()
        )));
    }
    Ok(())
}

fn read_browser_version_at(target: &Path) -> Option<String> {
    // 1. <install_path>/version (some forks)
    if let Some(v) = read_trimmed_string(&target.join("version")) {
        return Some(v);
    }
    // 2. <install_path>/chrome/VERSION (Chromium official)
    if let Some(map) = read_chromium_version_file(&target.join("chrome").join("VERSION")) {
        if let Some(v) = chromium_version_from_map(&map) {
            return Some(v);
        }
    }
    // 3. Fall through: try `<binary> --version` for any of a small
    //    set of known binary names. Best-effort; bounded timeout.
    for binary in [
        "chrome",
        "chromium",
        "chromium-browser",
        "thorium",
        "helium",
    ] {
        let bin = target.join(binary);
        if bin.is_file() && is_executable(&bin) {
            if let Some(v) = run_with_timeout(&bin, &["--version"], Duration::from_secs(1)) {
                return Some(v);
            }
        }
    }
    None
}

fn read_trimmed_string(p: &Path) -> Option<String> {
    let s = fs::read_to_string(p).ok()?;
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse a Chromium-style `chrome/VERSION` file:
///
/// ```text
/// MAJOR=128
/// MINOR=0
/// BUILD=6613
/// PATCH=119
/// ```
fn read_chromium_version_file(p: &Path) -> Option<std::collections::HashMap<String, String>> {
    let s = fs::read_to_string(p).ok()?;
    let mut map = std::collections::HashMap::new();
    for line in s.lines() {
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// Build `MAJOR.MINOR.BUILD.PATCH` from a parsed `chrome/VERSION` map.
fn chromium_version_from_map(map: &std::collections::HashMap<String, String>) -> Option<String> {
    let major = map.get("MAJOR")?;
    let minor = map.get("MINOR")?;
    let build = map.get("BUILD")?;
    let patch = map.get("PATCH")?;
    Some(format!("{major}.{minor}.{build}.{patch}"))
}

fn is_executable(p: &Path) -> bool {
    fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

/// Best-effort spawn of `binary --version` with a `timeout`-style wait.
///
/// Returns the trimmed first line of stdout on success. We can't use
/// `Command::output()` directly with a timeout (stdlib doesn't ship that
/// as of MSRV 1.85), so we use a simple thread-based wait pattern.
fn run_with_timeout(binary: &Path, args: &[&str], timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;

    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = String::new();
        let mut handle = stdout;
        let _ = handle.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });

    let result = rx.recv_timeout(timeout).ok()?;
    let _ = child.kill();
    let first_line = result.lines().next()?.trim();
    if first_line.is_empty() {
        None
    } else {
        Some(first_line.to_string())
    }
}

fn set_permissions(p: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
        .map_err(|e| context_err(e, format!("chmod {} -> {mode:o}", p.display())))
}

fn context_err(io_err: std::io::Error, ctx: String) -> Error {
    let mut err = Error::from(io_err);
    if err.message.is_empty() {
        err.message = ctx;
    } else {
        err.message = format!("{ctx}: {}", err.message);
    }
    err
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Build a fake CDM source layout matching what `extract::extract_crx3`
    /// produces.
    fn make_cdm_source(root: &Path) -> std::path::PathBuf {
        let dir = root.join("source");
        let plat = dir.join("_platform_specific").join("linux_x64");
        fs::create_dir_all(&plat).unwrap();
        fs::write(plat.join("libwidevinecdm.so"), b"fake-so-bytes").unwrap();
        fs::write(dir.join("manifest.json"), br#"{"version":"4.10.0.0"}"#).unwrap();
        // A nested directory to verify recursive copy.
        fs::create_dir_all(dir.join("LICENSES")).unwrap();
        fs::write(dir.join("LICENSES/widevine"), b"GOOG").unwrap();
        dir
    }

    /// Build a fake browser install path.
    fn make_install(root: &Path) -> std::path::PathBuf {
        let install = root.join("install");
        fs::create_dir_all(&install).unwrap();
        // Some pre-existing files we don't want clobbered.
        fs::write(install.join("chrome-sandbox"), b"#!/bin/sh\n").unwrap();
        install
    }

    #[test]
    fn write_cdm_creates_expected_directory_layout() {
        let tmp = TempDir::new().unwrap();
        let cdm = make_cdm_source(tmp.path());
        let install = make_install(tmp.path());

        let p = LinuxPatcher::new();
        p.write_cdm(&install, &cdm).expect("write ok");

        // CDM .so exists in the expected location.
        let so = install
            .join("WidevineCdm")
            .join("_platform_specific")
            .join("linux_x64")
            .join("libwidevinecdm.so");
        assert!(so.exists());
        // CDM .so is executable.
        let meta = fs::metadata(&so).unwrap();
        assert!(
            meta.permissions().mode() & 0o111 != 0,
            "libwidevinecdm.so should be executable"
        );
        // Manifest copied.
        assert!(install.join("WidevineCdm/manifest.json").exists());
        // Pre-existing browser file untouched.
        assert!(install.join("chrome-sandbox").exists());
    }

    #[test]
    fn write_cdm_clobbers_existing_widevine_cdm_directory() {
        let tmp = TempDir::new().unwrap();
        let cdm = make_cdm_source(tmp.path());
        let install = make_install(tmp.path());
        // Pre-populate WidevineCdm with a stale file.
        let stale = install.join("WidevineCdm/stale.txt");
        fs::create_dir_all(stale.parent().unwrap()).unwrap();
        fs::write(&stale, b"old").unwrap();

        let p = LinuxPatcher::new();
        p.write_cdm(&install, &cdm).expect("write ok");

        // Stale file is gone; new CDM is in place.
        assert!(!stale.exists());
        assert!(install.join("WidevineCdm/manifest.json").exists());
    }

    #[test]
    fn write_cdm_errors_when_target_missing() {
        let tmp = TempDir::new().unwrap();
        let cdm = make_cdm_source(tmp.path());
        let p = LinuxPatcher::new();
        let r = p.write_cdm(&tmp.path().join("nonexistent"), &cdm);
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn write_cdm_errors_when_source_missing() {
        let tmp = TempDir::new().unwrap();
        let install = make_install(tmp.path());
        let p = LinuxPatcher::new();
        let r = p.write_cdm(&install, &tmp.path().join("nonexistent"));
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn verify_post_patch_passes_after_write() {
        let tmp = TempDir::new().unwrap();
        let cdm = make_cdm_source(tmp.path());
        let install = make_install(tmp.path());
        let p = LinuxPatcher::new();
        p.write_cdm(&install, &cdm).expect("write");
        p.verify_post_patch(&install).expect("verify");
    }

    #[test]
    fn verify_post_patch_fails_when_so_missing() {
        let tmp = TempDir::new().unwrap();
        let install = make_install(tmp.path());
        let p = LinuxPatcher::new();
        let r = p.verify_post_patch(&install);
        assert!(r.is_err());
        assert_eq!(
            r.unwrap_err().category,
            crate::ErrorCategory::UnknownBundleStructure
        );
    }

    #[test]
    fn verify_post_patch_fails_when_so_empty() {
        let tmp = TempDir::new().unwrap();
        let install = make_install(tmp.path());
        let so_dir = install
            .join("WidevineCdm")
            .join("_platform_specific")
            .join("linux_x64");
        fs::create_dir_all(&so_dir).unwrap();
        fs::write(so_dir.join("libwidevinecdm.so"), b"").unwrap();
        let p = LinuxPatcher::new();
        let r = p.verify_post_patch(&install);
        assert!(r.is_err());
    }

    #[test]
    fn read_browser_version_reads_chromium_version_file() {
        let tmp = TempDir::new().unwrap();
        let install = make_install(tmp.path());
        fs::create_dir_all(install.join("chrome")).unwrap();
        fs::write(
            install.join("chrome/VERSION"),
            b"MAJOR=128\nMINOR=0\nBUILD=6613\nPATCH=119\n",
        )
        .unwrap();
        let p = LinuxPatcher::new();
        let v = p.read_browser_version(&install);
        assert_eq!(v.as_deref(), Some("128.0.6613.119"));
    }

    #[test]
    fn read_browser_version_reads_literal_version_file() {
        let tmp = TempDir::new().unwrap();
        let install = make_install(tmp.path());
        fs::write(install.join("version"), "  3.21.0  \n").unwrap();
        let p = LinuxPatcher::new();
        let v = p.read_browser_version(&install);
        assert_eq!(v.as_deref(), Some("3.21.0"));
    }

    #[test]
    fn read_browser_version_returns_none_when_unavailable() {
        let tmp = TempDir::new().unwrap();
        let install = make_install(tmp.path());
        let p = LinuxPatcher::new();
        let v = p.read_browser_version(&install);
        assert_eq!(v, None);
    }

    #[test]
    fn chromium_version_from_map_handles_partial_input() {
        let mut map = std::collections::HashMap::new();
        map.insert("MAJOR".into(), "128".into());
        map.insert("MINOR".into(), "0".into());
        // Missing BUILD/PATCH → None.
        assert_eq!(chromium_version_from_map(&map), None);
        map.insert("BUILD".into(), "6613".into());
        map.insert("PATCH".into(), "119".into());
        assert_eq!(
            chromium_version_from_map(&map).as_deref(),
            Some("128.0.6613.119")
        );
    }

    #[test]
    fn read_trimmed_string_returns_none_for_empty_or_missing() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(read_trimmed_string(&tmp.path().join("nope")), None);
        let empty = tmp.path().join("empty");
        fs::write(&empty, "  \n  ").unwrap();
        assert_eq!(read_trimmed_string(&empty), None);
    }

    #[test]
    fn copy_recursive_preserves_subdirectories() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(src.join("a/b/c")).unwrap();
        fs::write(src.join("a/b/c/file.txt"), b"hello").unwrap();
        fs::create_dir_all(&dst).unwrap();
        copy_recursive(&src, &dst).expect("copy ok");
        assert_eq!(fs::read(dst.join("a/b/c/file.txt")).unwrap(), b"hello");
    }

    #[test]
    fn run_with_timeout_returns_first_line_of_stdout() {
        // /bin/echo is on every Linux runner.
        let echo = std::path::Path::new("/bin/echo");
        if echo.exists() {
            let v = run_with_timeout(echo, &["hello world"], Duration::from_secs(2));
            assert_eq!(v.as_deref(), Some("hello world"));
        }
    }
}
