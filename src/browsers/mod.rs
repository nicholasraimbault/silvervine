//! Browser detection: known list + auto-discovery + custom config entries.
//!
//! ## Detection sources
//!
//! 1. **Known list** ([`known`]) — hardcoded constants for browsers the
//!    spec calls out (Helium, Thorium, ungoogled-chromium, Chromium).
//! 2. **Filesystem auto-discovery** ([`discovery::discover_filesystem`]):
//!    * macOS: scan `/Applications/*.app` for Chromium-framework bundles.
//!    * Linux: scan `/opt/*`, `/usr/lib/*`, `/usr/lib64/*`,
//!      `/usr/local/lib/*` for `chrome-sandbox` / `chromium-sandbox`.
//! 3. **Custom config entries** ([`crate::config::CustomBrowserConfig`])
//!    — read from the platform config file.
//!
//! All sources are unioned with same-`install_path` deduplication
//! (keeping the first occurrence wins).

use std::path::{Path, PathBuf};

use crate::config::{Config, CustomBrowserConfig};
use crate::error::Result;

pub mod discovery;
pub mod known;

pub use discovery::{discover_filesystem, discover_processes, is_running, FilesystemRoots};
pub use known::{KnownBrowser, KNOWN_LINUX, KNOWN_MACOS};

/// Platform-of-interest for browser detection.
///
/// Mirrors the OS half of `widevine::manifest::Platform`. We keep them
/// separate types because the manifest's keys carry arch info too
/// (`Linux_x86_64-gcc3` vs `Darwin_aarch64-gcc3`), whereas browser
/// install layouts only vary by OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    /// Linux (any glibc-compatible distro).
    Linux,
    /// macOS.
    Macos,
}

impl Os {
    /// OS the binary is being run on. Returns `None` when running on a
    /// non-V1 target — callers in V1 code paths typically `expect("supported OS")`.
    #[must_use]
    pub fn current() -> Option<Self> {
        if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Self::Macos)
        } else {
            None
        }
    }
}

/// What kind of source surfaced this browser. Useful for `silvervine list-browsers`
/// to display "(known)" / "(detected)" / "(custom)" tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    /// One of the hardcoded entries in [`known`] that resolved to a path
    /// existing on disk.
    Known,
    /// Found by filesystem walking (e.g. `/opt/some-fork-of-chromium`).
    Detected,
    /// Listed in `~/.config/silvervine/config.toml`'s `[[browsers]]` array.
    Custom,
}

/// A detected browser.
///
/// `install_path` is the canonical "patch into here" location:
///
/// * macOS: the `.app` bundle — `/Applications/Helium.app`.
/// * Linux: the install root that contains `chrome-sandbox` (or another
///   Chromium-family marker) — e.g. `/opt/helium-browser-bin`.
///
/// `framework_name` is only meaningful on macOS (the patch flow walks
/// `<bundle>/Contents/Frameworks/<framework_name>/Versions/<n>/Libraries/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Browser {
    /// Display name (e.g. `"Helium"`, `"Thorium"`).
    pub name: String,
    /// Where it's installed. Always absolute, always exists at detection time.
    pub install_path: PathBuf,
    /// Source classification.
    pub kind: BrowserKind,
    /// macOS framework directory name; ignored on Linux.
    pub framework_name: Option<String>,
}

impl Browser {
    /// The browser's display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Installation path on disk.
    #[must_use]
    pub fn install_path(&self) -> &Path {
        &self.install_path
    }

    /// Whether this browser has been patched with the Widevine CDM.
    ///
    /// Check whether the Widevine CDM is currently installed in this browser.
    ///
    /// Looks for the CDM manifest at the expected per-platform path under
    /// `install_path`:
    /// - Linux: `<install_path>/WidevineCdm/manifest.json`
    /// - macOS: walks `<install_path>/Contents/Frameworks/<framework>.framework/Versions/<n>/Libraries/WidevineCdm/manifest.json`
    ///
    /// Returns `false` if the manifest is missing, unreadable, or the
    /// browser's framework structure has changed.
    #[must_use]
    pub fn is_patched(&self) -> bool {
        self.cdm_manifest_path().is_some()
    }

    /// Read the version of the currently-installed Widevine CDM, if
    /// any. Returns `None` if the browser isn't patched, the manifest
    /// is unreadable, or the manifest doesn't carry a `version` field.
    ///
    /// Used by `setup` for idempotency: re-running setup against an
    /// already-patched browser at the cached CDM version is a no-op
    /// instead of a re-patch (which would error with `BrowserRunning`
    /// if the user happens to have the browser open).
    #[must_use]
    pub fn installed_cdm_version(&self) -> Option<String> {
        let manifest_path = self.cdm_manifest_path()?;
        let body = std::fs::read_to_string(&manifest_path).ok()?;
        let manifest: serde_json::Value = serde_json::from_str(&body).ok()?;
        manifest.get("version")?.as_str().map(String::from)
    }

    /// Resolve the path to the installed CDM's `manifest.json`, if
    /// any. Mirrors [`Browser::is_patched`]'s search but returns the
    /// path so [`Browser::installed_cdm_version`] can read it. macOS
    /// picks the first version directory containing a manifest
    /// (matches `is_patched`'s short-circuit order).
    fn cdm_manifest_path(&self) -> Option<std::path::PathBuf> {
        if let Some(framework_name) = &self.framework_name {
            let versions_dir = self
                .install_path
                .join("Contents")
                .join("Frameworks")
                .join(format!("{framework_name}.framework"))
                .join("Versions");
            if let Ok(entries) = std::fs::read_dir(&versions_dir) {
                for entry in entries.flatten() {
                    let manifest = entry
                        .path()
                        .join("Libraries")
                        .join("WidevineCdm")
                        .join("manifest.json");
                    if manifest.exists() {
                        return Some(manifest);
                    }
                }
            }
            return None;
        }
        let manifest = self.install_path.join("WidevineCdm").join("manifest.json");
        manifest.exists().then_some(manifest)
    }
}

/// Detect browsers on the host using all available sources.
///
/// This is the primary public API used by commands that enumerate or patch
/// browsers.
///
/// # Behavior
///
/// * Loads the user config from `~/.config/silvervine/config.toml` (silent
///   default if missing).
/// * Resolves the host OS — non-V1 hosts get an empty list (no error).
/// * Walks the known list, the auto-discovery sources, and the custom
///   config; deduplicates by `install_path`.
///
/// # Errors
///
/// Returns the error from [`crate::config::load_config`] if the config
/// file is malformed.
pub fn detect_browsers() -> Result<Vec<Browser>> {
    let config = crate::config::load_config()?;
    let Some(os) = Os::current() else {
        return Ok(Vec::new());
    };
    Ok(detect_browsers_with(
        os,
        &FilesystemRoots::default_for(os),
        &config,
    ))
}

/// Test-and-injection-friendly detection.
///
/// Lets callers (and tests) supply their own filesystem roots and config
/// rather than reading from the user's actual `$HOME`.
///
/// The order of returned browsers is:
/// 1. Known browsers that exist on disk
/// 2. Auto-discovered browsers not already in the known list
/// 3. Custom-config browsers not already covered
///
/// Deduplication is by canonicalized `install_path`.
#[must_use]
pub fn detect_browsers_with(os: Os, roots: &FilesystemRoots, config: &Config) -> Vec<Browser> {
    let mut out: Vec<Browser> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

    let push =
        |b: Browser, out: &mut Vec<Browser>, seen: &mut std::collections::HashSet<PathBuf>| {
            let key = b.install_path.clone();
            if seen.insert(key) {
                out.push(b);
            }
        };

    // 1. Known browsers
    for b in known::known_for_os(os, roots) {
        push(b, &mut out, &mut seen);
    }
    // 2. Filesystem discovery
    for b in discovery::discover_filesystem(os, roots) {
        push(b, &mut out, &mut seen);
    }
    // 3. Custom config entries
    for entry in &config.browsers {
        if let Some(b) = browser_from_custom(os, entry) {
            push(b, &mut out, &mut seen);
        }
    }
    out
}

/// Convert a `[[browsers]]` config entry into a [`Browser`] if it has the
/// fields appropriate for the host OS.
fn browser_from_custom(os: Os, entry: &CustomBrowserConfig) -> Option<Browser> {
    match os {
        Os::Macos => {
            // macOS entries set `bundle_path`. The patcher discovers the
            // framework when `framework_name` is absent.
            entry.bundle_path.as_ref().map(|p| Browser {
                name: entry.name.clone(),
                install_path: p.clone(),
                kind: BrowserKind::Custom,
                framework_name: entry.framework_name.clone(),
            })
        }
        Os::Linux => entry.install_path.as_ref().map(|p| Browser {
            name: entry.name.clone(),
            install_path: p.clone(),
            kind: BrowserKind::Custom,
            framework_name: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_linux_browser_dir(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(&dir).expect("mkdir");
        // Linux Chromium-family markers: both the sandbox helper AND a
        // top-level `chrome` binary (the latter distinguishes real
        // browsers from Electron apps that ship chrome-sandbox but rename
        // their main binary).
        fs::write(dir.join("chrome-sandbox"), b"#!/bin/sh\n").expect("touch sandbox");
        fs::write(dir.join("chrome"), b"\x7fELF").expect("touch chrome binary");
        dir
    }

    fn make_macos_app(root: &Path, app_name: &str, framework: &str) -> PathBuf {
        let app = root.join(format!("{app_name}.app"));
        let frameworks = app.join("Contents").join("Frameworks");
        let fw_dir = frameworks.join(format!("{framework}.framework"));
        let versions = fw_dir.join("Versions").join("128.0.6613.119");
        fs::create_dir_all(&versions).expect("mkdir versions");
        // Detection only needs the Chromium framework shape; patching later
        // resolves the active version under `Versions/<n>/Libraries/`.
        app
    }

    #[test]
    fn detect_browsers_with_synthesized_linux_filesystem() {
        let tmp = TempDir::new().expect("tempdir");
        // Known list: a `helium-browser-bin` under `<sandbox>/opt/`,
        // matching the absolute spec path `/opt/helium-browser-bin`.
        let opt_under_sandbox = tmp.path().join("opt");
        fs::create_dir_all(&opt_under_sandbox).expect("mkdir opt");
        let known_helium = make_linux_browser_dir(&opt_under_sandbox, "helium-browser-bin");
        // Unknown fork lives in a separately-walked tree.
        let walk_dir = tmp.path().join("walk");
        fs::create_dir_all(&walk_dir).expect("mkdir walk");
        let unknown_fork = make_linux_browser_dir(&walk_dir, "my-fork-of-chromium");

        let config = Config::default();
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![walk_dir.clone()],
            sandbox_root: Some(tmp.path().to_path_buf()),
        };

        let browsers = detect_browsers_with(Os::Linux, &roots, &config);
        // Must contain a Helium entry sourced from the known list.
        let helium = browsers
            .iter()
            .find(|b| b.name == "Helium")
            .expect("helium found");
        assert_eq!(helium.install_path, known_helium);
        assert_eq!(helium.kind, BrowserKind::Known);
        // Must contain the auto-discovered fork.
        let fork = browsers
            .iter()
            .find(|b| b.install_path == unknown_fork)
            .expect("unknown fork detected");
        assert_eq!(fork.kind, BrowserKind::Detected);
    }

    #[test]
    fn detect_browsers_with_synthesized_macos_filesystem() {
        let tmp = TempDir::new().expect("tempdir");
        let apps = tmp.path().join("Applications");
        fs::create_dir_all(&apps).expect("mkdir apps");
        let helium = make_macos_app(&apps, "Helium", "Helium Framework");
        let unknown = make_macos_app(&apps, "WeirdChromium", "WeirdChromium Framework");

        let config = Config::default();
        let roots = FilesystemRoots {
            macos_applications: vec![apps.clone()],
            linux_search: vec![],
            sandbox_root: None,
        };

        let browsers = detect_browsers_with(Os::Macos, &roots, &config);
        let helium_entry = browsers
            .iter()
            .find(|b| b.name == "Helium")
            .expect("helium");
        assert_eq!(helium_entry.install_path, helium);
        let unknown_entry = browsers
            .iter()
            .find(|b| b.install_path == unknown)
            .expect("weird");
        assert_eq!(unknown_entry.kind, BrowserKind::Detected);
    }

    #[test]
    fn custom_browser_entries_are_added() {
        let tmp = TempDir::new().expect("tempdir");
        let custom = tmp.path().join("home/me/dev/my-build");
        fs::create_dir_all(&custom).expect("mkdir");
        let config = Config {
            browsers: vec![CustomBrowserConfig {
                name: "DevBuild".into(),
                bundle_path: None,
                framework_name: None,
                install_path: Some(custom.clone()),
            }],
            ..Default::default()
        };
        // Important: empty `linux_search` AND a sandbox_root that doesn't
        // contain the spec's `/opt/...` paths, so no known browsers
        // surface and the test counts only the custom entry.
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![],
            sandbox_root: Some(tmp.path().to_path_buf()),
        };
        let browsers = detect_browsers_with(Os::Linux, &roots, &config);
        assert_eq!(browsers.len(), 1);
        assert_eq!(browsers[0].name, "DevBuild");
        assert_eq!(browsers[0].install_path, custom);
        assert_eq!(browsers[0].kind, BrowserKind::Custom);
    }

    #[test]
    fn custom_browsers_are_filtered_by_os_specific_fields() {
        // A macOS-shaped entry (bundle_path set) shouldn't show up on Linux.
        let tmp = TempDir::new().expect("tempdir");
        let cfg = Config {
            browsers: vec![CustomBrowserConfig {
                name: "MacOnly".into(),
                bundle_path: Some(PathBuf::from("/Applications/MacOnly.app")),
                framework_name: Some("MacOnly Framework".into()),
                install_path: None,
            }],
            ..Default::default()
        };
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![],
            sandbox_root: Some(tmp.path().to_path_buf()),
        };
        let on_linux = detect_browsers_with(Os::Linux, &roots, &cfg);
        assert!(
            on_linux.is_empty(),
            "macOS-only custom entry shouldn't surface on Linux"
        );
    }

    #[test]
    fn dedup_by_install_path() {
        // A known browser that's also listed in custom config should
        // appear once, not twice.
        let tmp = TempDir::new().expect("tempdir");
        let opt_in_sandbox = tmp.path().join("opt");
        fs::create_dir_all(&opt_in_sandbox).expect("mkdir opt");
        let helium = make_linux_browser_dir(&opt_in_sandbox, "helium-browser-bin");
        let cfg = Config {
            browsers: vec![CustomBrowserConfig {
                name: "Helium-redundant".into(),
                bundle_path: None,
                framework_name: None,
                install_path: Some(helium.clone()),
            }],
            ..Default::default()
        };
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![],
            sandbox_root: Some(tmp.path().to_path_buf()),
        };
        let browsers = detect_browsers_with(Os::Linux, &roots, &cfg);
        let count = browsers.iter().filter(|b| b.install_path == helium).count();
        assert_eq!(count, 1, "should dedupe by install_path");
    }

    #[test]
    fn is_patched_returns_false_when_cdm_manifest_missing() {
        // Linux: pointing at a path with no WidevineCdm/manifest.json.
        let tmp = TempDir::new().expect("tempdir");
        let b = Browser {
            name: "x".into(),
            install_path: tmp.path().to_path_buf(),
            kind: BrowserKind::Detected,
            framework_name: None,
        };
        assert!(!b.is_patched());
        // Also exercise the convenience accessors.
        assert_eq!(b.name(), "x");
        assert_eq!(b.install_path(), tmp.path());
    }

    #[test]
    fn is_patched_returns_true_when_linux_cdm_manifest_exists() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm = tmp.path().join("WidevineCdm");
        fs::create_dir_all(&cdm).expect("mkdir cdm");
        fs::write(cdm.join("manifest.json"), b"{\"version\":\"4.10.0.0\"}")
            .expect("touch manifest");
        let b = Browser {
            name: "x".into(),
            install_path: tmp.path().to_path_buf(),
            kind: BrowserKind::Detected,
            framework_name: None,
        };
        assert!(b.is_patched());
    }

    #[test]
    fn installed_cdm_version_reads_manifest_field() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm = tmp.path().join("WidevineCdm");
        fs::create_dir_all(&cdm).expect("mkdir cdm");
        fs::write(
            cdm.join("manifest.json"),
            br#"{"version":"4.10.2934.0","name":"Widevine CDM"}"#,
        )
        .expect("write manifest");
        let b = Browser {
            name: "x".into(),
            install_path: tmp.path().to_path_buf(),
            kind: BrowserKind::Detected,
            framework_name: None,
        };
        assert_eq!(b.installed_cdm_version().as_deref(), Some("4.10.2934.0"));
    }

    #[test]
    fn installed_cdm_version_returns_none_when_unpatched() {
        let tmp = TempDir::new().expect("tempdir");
        let b = Browser {
            name: "x".into(),
            install_path: tmp.path().to_path_buf(),
            kind: BrowserKind::Detected,
            framework_name: None,
        };
        assert_eq!(b.installed_cdm_version(), None);
    }

    #[test]
    fn installed_cdm_version_returns_none_when_manifest_lacks_version() {
        let tmp = TempDir::new().expect("tempdir");
        let cdm = tmp.path().join("WidevineCdm");
        fs::create_dir_all(&cdm).expect("mkdir cdm");
        fs::write(cdm.join("manifest.json"), b"{}").expect("write manifest");
        let b = Browser {
            name: "x".into(),
            install_path: tmp.path().to_path_buf(),
            kind: BrowserKind::Detected,
            framework_name: None,
        };
        assert_eq!(b.installed_cdm_version(), None);
    }

    #[test]
    fn is_patched_macos_walks_versions_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("Helium.app");
        let framework_versions = bundle
            .join("Contents")
            .join("Frameworks")
            .join("Helium Framework.framework")
            .join("Versions")
            .join("147.0.7727.137");
        let cdm = framework_versions.join("Libraries").join("WidevineCdm");
        fs::create_dir_all(&cdm).expect("mkdir cdm");
        fs::write(cdm.join("manifest.json"), b"{}").expect("touch manifest");
        let b = Browser {
            name: "Helium".into(),
            install_path: bundle,
            kind: BrowserKind::Known,
            framework_name: Some("Helium Framework".into()),
        };
        assert!(b.is_patched());
    }

    #[test]
    fn os_current_resolves_when_running_on_supported_os() {
        // We can't assert which one; just that it isn't a panic and
        // is one of the two supported variants on V1 targets.
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(matches!(Os::current(), Some(Os::Linux | Os::Macos)));
        }
    }

    /// `detect_browsers` (production entry point) reads from `$HOME`. It
    /// must NOT panic for any host configuration; the worst case is an
    /// empty list.
    #[test]
    fn detect_browsers_does_not_panic() {
        let result = detect_browsers();
        // Either Ok with some list, or Err if the user's config is
        // malformed. We don't assert the contents — the host machine's
        // browsers (or lack thereof) determine that.
        match result {
            Ok(_) | Err(_) => {}
        }
    }

    /// `browser_from_custom` returns `None` when the OS-specific field
    /// is missing.
    #[test]
    fn browser_from_custom_returns_none_for_unspecified_os() {
        // macOS entry with no bundle_path on macOS: nothing usable.
        let mac_empty = CustomBrowserConfig {
            name: "Empty".into(),
            bundle_path: None,
            framework_name: None,
            install_path: None,
        };
        assert!(browser_from_custom(Os::Macos, &mac_empty).is_none());
        assert!(browser_from_custom(Os::Linux, &mac_empty).is_none());
        // Linux entry on macOS doesn't have a bundle_path.
        let linux_only = CustomBrowserConfig {
            name: "L".into(),
            bundle_path: None,
            framework_name: None,
            install_path: Some(PathBuf::from("/opt/x")),
        };
        assert!(browser_from_custom(Os::Macos, &linux_only).is_none());
        // ... but on Linux it works.
        let on_linux = browser_from_custom(Os::Linux, &linux_only).expect("linux");
        assert_eq!(on_linux.kind, BrowserKind::Custom);
        assert_eq!(on_linux.name, "L");
    }

    #[test]
    fn browser_from_custom_macos_carries_framework_name() {
        let mac = CustomBrowserConfig {
            name: "M".into(),
            bundle_path: Some(PathBuf::from("/Applications/M.app")),
            framework_name: Some("M Framework".into()),
            install_path: None,
        };
        let b = browser_from_custom(Os::Macos, &mac).expect("macos");
        assert_eq!(b.framework_name.as_deref(), Some("M Framework"));
    }
}
