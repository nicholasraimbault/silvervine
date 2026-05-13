//! macOS implementation of [`crate::patch::PlatformPatcher`].
//!
//! Per the spec ("macOS → Atomic patch protocol"):
//!
//! > Bundle write into `<app>/Contents/Frameworks/<fw>/Versions/<n>/Libraries/WidevineCdm/`;
//! > `xattr -cr`; ad-hoc codesign.
//!
//! ## Bundle layout
//!
//! macOS Chromium-family bundles look like:
//!
//! ```text
//! /Applications/Helium.app/
//! └── Contents/
//!     ├── Info.plist
//!     ├── MacOS/
//!     │   └── Helium
//!     └── Frameworks/
//!         └── Helium Framework.framework/
//!             └── Versions/
//!                 └── 128.0.6613.119/
//!                     └── Libraries/
//!                         └── WidevineCdm/  ← we write here
//! ```
//!
//! The `<n>` (version) directory under `Versions/` is the active version
//! for the bundle. macOS Chromium uses `Versions/Current` as a symlink
//! pointing at the live version, but writing into the symlink target
//! (the actual versioned directory) is what survives bundle updates.
//!
//! ## xattr clearing
//!
//! Writes from a non-Apple-signed source (i.e. our `cp -R`) get the
//! `com.apple.quarantine` extended attribute. Browsers refuse to load
//! quarantined libraries, so we clear xattrs recursively after the
//! copy:
//!
//! ```sh
//! xattr -cr <bundle>
//! ```
//!
//! Verified during design that `xattr -r` exists on macOS — the previous
//! Bash implementation regressed to `xattr -c` (non-recursive) at one
//! point and broke patches; we explicitly use `-cr` here.
//!
//! ## Codesign
//!
//! Modifying any file inside an `.app` invalidates the bundle's signature.
//! Browsers refuse to launch with a broken signature on Gatekeeper-
//! enforced macOS, so we re-sign ad-hoc:
//!
//! ```sh
//! codesign --force --deep -s - <bundle>
//! ```
//!
//! The `-s -` (sign with the ad-hoc identity) is what produces an
//! unsigned-but-self-consistent bundle. `--deep` is **deprecated** by
//! Apple as of macOS 13 but still works for ad-hoc; the spec defers
//! migrating to inside-out signing to V2.
//!
//! ## Test mode
//!
//! The actual `xattr` and `codesign` invocations are gated on
//! `NEON_TEST_PATCH_NOOP=1`. CI runners don't have `codesign` available
//! anyway (and on Linux runners the binaries don't exist), so tests use
//! the no-op path and assert the bundle layout is correct.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};
use crate::patch::PlatformPatcher;

/// macOS platform patcher.
///
/// Implements [`PlatformPatcher`] for the macOS `.app`-bundle layout.
/// Construct with [`MacosPatcher::new`].
#[derive(Debug, Clone, Copy, Default)]
pub struct MacosPatcher;

impl MacosPatcher {
    /// Build a new macOS patcher. Stateless — argments come from the
    /// `target` (`.app` bundle path) and the implicit framework name
    /// inferred from the bundle.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl PlatformPatcher for MacosPatcher {
    fn write_cdm(&self, target: &Path, cdm_source: &Path) -> Result<()> {
        let layout = resolve_bundle_layout(target)?;
        write_cdm_into(&layout, cdm_source)?;
        // Order matters: clear xattrs FIRST (codesign cares about them),
        // then re-sign.
        run_xattr_clear(target)?;
        run_codesign_adhoc(target)?;
        Ok(())
    }

    fn verify_post_patch(&self, target: &Path) -> Result<()> {
        let layout = resolve_bundle_layout(target)?;
        verify_cdm_at(&layout)
    }

    fn read_browser_version(&self, target: &Path) -> Option<String> {
        read_browser_version_at(target)
    }
}

/// Resolved on-disk layout for a Chromium-family `.app` bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLayout {
    /// `.app` bundle root (e.g. `/Applications/Helium.app`).
    pub bundle: PathBuf,
    /// Framework directory (e.g. `Contents/Frameworks/Helium Framework.framework`).
    pub framework: PathBuf,
    /// Active version directory (e.g. `Frameworks/.../Versions/128.0.6613.119`).
    pub version_dir: PathBuf,
    /// Where the CDM goes (`<version_dir>/Libraries/WidevineCdm/`).
    pub cdm_target: PathBuf,
    /// Detected version string (the directory name under `Versions/`).
    pub version: String,
}

/// Walk into `target` (a `.app` bundle), find the framework directory,
/// and resolve the active version directory.
///
/// Algorithm:
///
/// 1. Look in `<target>/Contents/Frameworks/`.
/// 2. Take the first `*.framework` entry that has a `Versions/` directory.
/// 3. Inside `Versions/`, prefer `Current` if it exists and is a symlink;
///    otherwise pick the only non-symlink `<version>` entry.
///
/// # Errors
///
/// Returns [`crate::ErrorCategory::UnknownBundleStructure`] if any step
/// fails — the caller (the orchestrator) categorizes the error and
/// surfaces it through the patch flow.
pub fn resolve_bundle_layout(target: &Path) -> Result<BundleLayout> {
    let frameworks = target.join("Contents").join("Frameworks");
    if !frameworks.is_dir() {
        return Err(Error::unknown_bundle_structure(format!(
            "no Contents/Frameworks under {}",
            target.display()
        )));
    }
    let framework = first_framework_dir(&frameworks)?;
    let versions = framework.join("Versions");
    if !versions.is_dir() {
        return Err(Error::unknown_bundle_structure(format!(
            "no Versions/ under {}",
            framework.display()
        )));
    }
    let version_dir = active_version_dir(&versions)?;
    let version = version_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let cdm_target = version_dir.join("Libraries").join("WidevineCdm");
    Ok(BundleLayout {
        bundle: target.to_path_buf(),
        framework,
        version_dir,
        cdm_target,
        version,
    })
}

/// Find the first `*.framework` directory inside `frameworks` that has
/// a `Versions/` subdirectory.
fn first_framework_dir(frameworks: &Path) -> Result<PathBuf> {
    for entry in fs::read_dir(frameworks)
        .map_err(|e| ctx_err(e, format!("read_dir({})", frameworks.display())))?
    {
        let entry = entry.map_err(|e| ctx_err(e, format!("iter {}", frameworks.display())))?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if path.is_dir() && name_str.ends_with(".framework") && path.join("Versions").is_dir() {
            return Ok(path);
        }
    }
    Err(Error::unknown_bundle_structure(format!(
        "no Chromium-family framework directory under {}",
        frameworks.display()
    )))
}

/// Resolve the active version dir under `versions/`. Prefers `Current`
/// (followed if it's a symlink); otherwise picks the only versioned entry.
fn active_version_dir(versions: &Path) -> Result<PathBuf> {
    // Path 1: `Versions/Current` is a symlink.
    let current = versions.join("Current");
    if current.exists() {
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                let target = fs::read_link(&current)
                    .map_err(|e| ctx_err(e, format!("readlink {}", current.display())))?;
                let resolved = if target.is_absolute() {
                    target
                } else {
                    versions.join(target)
                };
                if resolved.is_dir() {
                    return Ok(resolved);
                }
            } else if meta.is_dir() {
                // Direct directory named "Current" — uncommon but tolerated.
                return Ok(current);
            }
        }
    }
    // Path 2: pick the lone non-symlink subdirectory.
    let mut candidates: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(versions)
        .map_err(|e| ctx_err(e, format!("read_dir({})", versions.display())))?
    {
        let entry = entry.map_err(|e| ctx_err(e, format!("iter {}", versions.display())))?;
        let path = entry.path();
        let name = entry.file_name();
        if name == "Current" {
            continue;
        }
        if path.is_dir() && !is_symlink(&path) {
            candidates.push(path);
        }
    }
    if candidates.len() == 1 {
        return Ok(candidates.into_iter().next().expect("len==1"));
    }
    if candidates.is_empty() {
        return Err(Error::unknown_bundle_structure(format!(
            "no version directory under {}",
            versions.display()
        )));
    }
    Err(Error::unknown_bundle_structure(format!(
        "multiple version directories under {} and no Current symlink",
        versions.display()
    )))
}

fn is_symlink(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

fn write_cdm_into(layout: &BundleLayout, cdm_source: &Path) -> Result<()> {
    if !cdm_source.exists() {
        return Err(Error::unknown_bundle_structure(format!(
            "CDM source directory does not exist: {}",
            cdm_source.display()
        )));
    }
    if layout.cdm_target.exists() {
        fs::remove_dir_all(&layout.cdm_target).map_err(|e| {
            ctx_err(
                e,
                format!("could not clear {}", layout.cdm_target.display()),
            )
        })?;
    }
    fs::create_dir_all(&layout.cdm_target).map_err(|e| {
        ctx_err(
            e,
            format!("could not create {}", layout.cdm_target.display()),
        )
    })?;
    copy_recursive(cdm_source, &layout.cdm_target)?;
    Ok(())
}

fn copy_recursive(src: &Path, dst: &Path) -> Result<()> {
    for entry in
        fs::read_dir(src).map_err(|e| ctx_err(e, format!("read_dir({})", src.display())))?
    {
        let entry = entry.map_err(|e| ctx_err(e, format!("iter {}", src.display())))?;
        let path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|e| ctx_err(e, format!("file_type({})", path.display())))?;
        if file_type.is_dir() {
            fs::create_dir_all(&dst_path)
                .map_err(|e| ctx_err(e, format!("mkdir {}", dst_path.display())))?;
            copy_recursive(&path, &dst_path)?;
        } else if file_type.is_file() {
            fs::copy(&path, &dst_path).map_err(|e| {
                ctx_err(
                    e,
                    format!("copy {} -> {}", path.display(), dst_path.display()),
                )
            })?;
        }
    }
    Ok(())
}

fn verify_cdm_at(layout: &BundleLayout) -> Result<()> {
    let dylib = layout
        .cdm_target
        .join("_platform_specific")
        .join("mac_x64")
        .join("libwidevinecdm.dylib");
    let dylib_arm = layout
        .cdm_target
        .join("_platform_specific")
        .join("mac_arm64")
        .join("libwidevinecdm.dylib");
    let chosen = if dylib.exists() { &dylib } else { &dylib_arm };
    if !chosen.exists() {
        return Err(Error::unknown_bundle_structure(format!(
            "post-patch verify: missing libwidevinecdm.dylib under {}",
            layout.cdm_target.display()
        )));
    }
    let meta = fs::metadata(chosen)
        .map_err(|e| ctx_err(e, format!("post-patch verify: stat {}", chosen.display())))?;
    if meta.len() == 0 {
        return Err(Error::unknown_bundle_structure(format!(
            "post-patch verify: {} is empty",
            chosen.display()
        )));
    }
    Ok(())
}

/// Clear extended attributes recursively on the bundle.
///
/// Honors `NEON_TEST_PATCH_NOOP=1` for tests that don't have `xattr`
/// available.
fn run_xattr_clear(bundle: &Path) -> Result<()> {
    if std::env::var_os("NEON_TEST_PATCH_NOOP").is_some() {
        return Ok(());
    }
    let bundle_str = bundle
        .to_str()
        .ok_or_else(|| Error::other(format!("bundle path not UTF-8: {}", bundle.display())))?;
    let output = Command::new("xattr")
        .args(["-cr", bundle_str])
        .output()
        .map_err(|e| ctx_err(e, "spawn xattr".into()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format!(
            "xattr -cr {} failed (exit {:?}): {}",
            bundle_str,
            output.status.code(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Ad-hoc codesign the bundle.
///
/// Honors `NEON_TEST_PATCH_NOOP=1`.
fn run_codesign_adhoc(bundle: &Path) -> Result<()> {
    if std::env::var_os("NEON_TEST_PATCH_NOOP").is_some() {
        return Ok(());
    }
    let bundle_str = bundle
        .to_str()
        .ok_or_else(|| Error::other(format!("bundle path not UTF-8: {}", bundle.display())))?;
    let output = Command::new("codesign")
        .args(["--force", "--deep", "-s", "-", bundle_str])
        .output()
        .map_err(|e| ctx_err(e, "spawn codesign".into()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format!(
            "codesign --force --deep -s - {} failed (exit {:?}): {}",
            bundle_str,
            output.status.code(),
            stderr.trim()
        )));
    }
    Ok(())
}

fn read_browser_version_at(target: &Path) -> Option<String> {
    // Read CFBundleShortVersionString from Contents/Info.plist.
    let plist = target.join("Contents/Info.plist");
    let text = fs::read_to_string(&plist).ok()?;
    parse_cfbundle_short_version_string(&text)
}

/// Parse `CFBundleShortVersionString` out of an Info.plist XML. The plist
/// crate would be a heavier dependency than necessary for one key; we
/// just look for the canonical XML fragment.
fn parse_cfbundle_short_version_string(plist: &str) -> Option<String> {
    let key = "<key>CFBundleShortVersionString</key>";
    let key_idx = plist.find(key)?;
    let after_key = &plist[key_idx + key.len()..];
    // Find the next `<string>...</string>`.
    let open = after_key.find("<string>")?;
    let after_open = &after_key[open + "<string>".len()..];
    let close = after_open.find("</string>")?;
    let value = after_open[..close].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn ctx_err(io_err: std::io::Error, ctx: String) -> Error {
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
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    /// Build a synthesized `.app` bundle layout under `root` and return
    /// the bundle path.
    fn make_app_bundle(root: &Path, app_name: &str, framework: &str, version: &str) -> PathBuf {
        let app = root.join(format!("{app_name}.app"));
        let frameworks = app.join("Contents").join("Frameworks");
        let fw_dir = frameworks.join(format!("{framework}.framework"));
        let versions = fw_dir.join("Versions");
        let v = versions.join(version);
        let libs = v.join("Libraries");
        fs::create_dir_all(&libs).unwrap();
        // Optional: a Versions/Current symlink that points at <version>
        #[cfg(unix)]
        {
            // We'd normally make Current → <version>; some tests exercise
            // the no-symlink path instead, so the helper writes it
            // unconditionally and tests can `remove_file` it.
            let _ = symlink(version, versions.join("Current"));
        }
        // Info.plist with a CFBundleShortVersionString.
        fs::write(
            app.join("Contents/Info.plist"),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleShortVersionString</key>
<string>{version}</string>
</dict></plist>
"#
            ),
        )
        .unwrap();
        app
    }

    /// Build a fake CDM source matching `extract::extract_crx3` output.
    fn make_cdm_source(root: &Path) -> PathBuf {
        let dir = root.join("source");
        let mac = dir.join("_platform_specific").join("mac_x64");
        fs::create_dir_all(&mac).unwrap();
        fs::write(mac.join("libwidevinecdm.dylib"), b"fake-mac-dylib").unwrap();
        fs::write(dir.join("manifest.json"), br#"{"version":"4.10.0.0"}"#).unwrap();
        dir
    }

    #[test]
    fn resolve_bundle_layout_finds_framework_and_version() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "Helium", "Helium Framework", "128.0.6613.119");
        let layout = resolve_bundle_layout(&app).expect("layout ok");
        assert_eq!(layout.bundle, app);
        assert_eq!(layout.version, "128.0.6613.119");
        assert!(layout.framework.ends_with("Helium Framework.framework"));
        assert!(layout.cdm_target.ends_with("Libraries/WidevineCdm"));
    }

    #[test]
    fn resolve_bundle_layout_handles_missing_current_symlink() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "Helium", "Helium Framework", "128.0.6613.119");
        let versions = app.join("Contents/Frameworks/Helium Framework.framework/Versions");
        let _ = fs::remove_file(versions.join("Current"));
        let layout = resolve_bundle_layout(&app).expect("ok without Current");
        assert_eq!(layout.version, "128.0.6613.119");
    }

    #[test]
    fn resolve_bundle_layout_errors_when_frameworks_missing() {
        let tmp = TempDir::new().unwrap();
        let app = tmp.path().join("Empty.app");
        fs::create_dir_all(app.join("Contents")).unwrap();
        let r = resolve_bundle_layout(&app);
        assert!(r.is_err());
        assert_eq!(
            r.unwrap_err().category,
            crate::ErrorCategory::UnknownBundleStructure
        );
    }

    #[test]
    fn resolve_bundle_layout_errors_when_versions_missing() {
        let tmp = TempDir::new().unwrap();
        let app = tmp.path().join("X.app");
        fs::create_dir_all(app.join("Contents/Frameworks/X.framework")).unwrap();
        let r = resolve_bundle_layout(&app);
        assert!(r.is_err());
    }

    #[test]
    fn write_cdm_writes_into_versions_libraries() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "Thorium", "Thorium Framework", "128.0.6613.119");
        let cdm = make_cdm_source(tmp.path());
        // SAFETY: env var mutation in serial test thread.
        unsafe { std::env::set_var("NEON_TEST_PATCH_NOOP", "1") };
        let p = MacosPatcher::new();
        p.write_cdm(&app, &cdm).expect("write ok");
        unsafe { std::env::remove_var("NEON_TEST_PATCH_NOOP") };

        let dylib = app
            .join("Contents/Frameworks/Thorium Framework.framework/Versions/128.0.6613.119")
            .join("Libraries/WidevineCdm/_platform_specific/mac_x64/libwidevinecdm.dylib");
        assert!(dylib.exists());
        assert_eq!(fs::read(&dylib).unwrap(), b"fake-mac-dylib");
    }

    #[test]
    fn write_cdm_clobbers_existing_widevine_cdm_directory() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "Helium", "Helium Framework", "1.0.0.0");
        let cdm = make_cdm_source(tmp.path());
        // Pre-populate WidevineCdm with a stale file.
        let layout = resolve_bundle_layout(&app).unwrap();
        fs::create_dir_all(&layout.cdm_target).unwrap();
        fs::write(layout.cdm_target.join("stale.txt"), b"old").unwrap();

        unsafe { std::env::set_var("NEON_TEST_PATCH_NOOP", "1") };
        let p = MacosPatcher::new();
        p.write_cdm(&app, &cdm).expect("write ok");
        unsafe { std::env::remove_var("NEON_TEST_PATCH_NOOP") };

        assert!(!layout.cdm_target.join("stale.txt").exists());
        assert!(layout.cdm_target.join("manifest.json").exists());
    }

    #[test]
    fn verify_post_patch_passes_after_write() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "Helium", "Helium Framework", "1.0.0.0");
        let cdm = make_cdm_source(tmp.path());
        unsafe { std::env::set_var("NEON_TEST_PATCH_NOOP", "1") };
        let p = MacosPatcher::new();
        p.write_cdm(&app, &cdm).unwrap();
        p.verify_post_patch(&app).expect("verify ok");
        unsafe { std::env::remove_var("NEON_TEST_PATCH_NOOP") };
    }

    #[test]
    fn verify_post_patch_fails_when_dylib_missing() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "Helium", "Helium Framework", "1.0.0.0");
        let p = MacosPatcher::new();
        let r = p.verify_post_patch(&app);
        assert!(r.is_err());
        assert_eq!(
            r.unwrap_err().category,
            crate::ErrorCategory::UnknownBundleStructure
        );
    }

    #[test]
    fn read_browser_version_parses_cfbundle_short_version_string() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "Helium", "Helium Framework", "128.0.6613.119");
        let p = MacosPatcher::new();
        let v = p.read_browser_version(&app);
        assert_eq!(v.as_deref(), Some("128.0.6613.119"));
    }

    #[test]
    fn read_browser_version_returns_none_when_plist_missing() {
        let tmp = TempDir::new().unwrap();
        let p = MacosPatcher::new();
        let v = p.read_browser_version(&tmp.path().join("nope.app"));
        assert!(v.is_none());
    }

    #[test]
    fn parse_cfbundle_short_version_string_handles_multiline_xml() {
        let plist = r"
            <key>CFBundleName</key>
            <string>Helium</string>
            <key>CFBundleShortVersionString</key>
            <string>128.0.6613.119</string>
            <key>CFBundleVersion</key>
            <string>128.0.6613.119</string>
        ";
        assert_eq!(
            parse_cfbundle_short_version_string(plist).as_deref(),
            Some("128.0.6613.119")
        );
    }

    #[test]
    fn parse_cfbundle_short_version_string_returns_none_when_absent() {
        let plist = "<plist><dict></dict></plist>";
        assert_eq!(parse_cfbundle_short_version_string(plist), None);
    }

    #[test]
    fn write_cdm_errors_when_source_missing() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "Helium", "Helium Framework", "1.0.0.0");
        unsafe { std::env::set_var("NEON_TEST_PATCH_NOOP", "1") };
        let p = MacosPatcher::new();
        let r = p.write_cdm(&app, &tmp.path().join("nope"));
        unsafe { std::env::remove_var("NEON_TEST_PATCH_NOOP") };
        assert!(r.is_err());
        assert_eq!(
            r.unwrap_err().category,
            crate::ErrorCategory::UnknownBundleStructure
        );
    }

    /// `resolve_bundle_layout` errors if multiple non-symlink version
    /// directories exist and there's no `Current` symlink to disambiguate.
    #[test]
    fn resolve_bundle_layout_errors_on_ambiguous_versions() {
        let tmp = TempDir::new().unwrap();
        let app = make_app_bundle(tmp.path(), "X", "X Framework", "1.0.0.0");
        // Add a second versioned directory and remove the Current symlink.
        let versions = app.join("Contents/Frameworks/X Framework.framework/Versions");
        fs::create_dir_all(versions.join("2.0.0.0")).unwrap();
        let _ = fs::remove_file(versions.join("Current"));
        let r = resolve_bundle_layout(&app);
        assert!(r.is_err());
    }

    #[test]
    fn run_xattr_clear_short_circuits_in_test_mode() {
        unsafe { std::env::set_var("NEON_TEST_PATCH_NOOP", "1") };
        let r = run_xattr_clear(std::path::Path::new("/Applications/whatever"));
        assert!(r.is_ok());
        unsafe { std::env::remove_var("NEON_TEST_PATCH_NOOP") };
    }

    #[test]
    fn run_codesign_adhoc_short_circuits_in_test_mode() {
        unsafe { std::env::set_var("NEON_TEST_PATCH_NOOP", "1") };
        let r = run_codesign_adhoc(std::path::Path::new("/Applications/whatever"));
        assert!(r.is_ok());
        unsafe { std::env::remove_var("NEON_TEST_PATCH_NOOP") };
    }
}
