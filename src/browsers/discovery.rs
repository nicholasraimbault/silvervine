//! Browser auto-discovery.
//!
//! ## Filesystem discovery
//!
//! Per the spec's "Auto-discovery" section:
//!
//! * **macOS:** scan `/Applications/*.app`. For each, check
//!   `Contents/Frameworks/*.framework/Versions/<n>.<n>...`. If matches
//!   Chromium framework structure, add to detected list.
//! * **Linux:** scan `/opt/*`, `/usr/lib/*`, `/usr/lib64/*`,
//!   `/usr/local/lib/*`. For each directory, check for presence of
//!   `chrome-sandbox` or `chromium-sandbox`. If present, add to detected list.
//!
//! ## Process inspection
//!
//! [`is_running`] uses `sysinfo` to check whether a detected browser is active.
//! Process enumeration alone does not provide enough installation metadata to
//! construct additional [`Browser`] values.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::{Browser, BrowserKind, Os};

/// Filesystem roots to scan during auto-discovery.
///
/// The defaults from [`FilesystemRoots::default_for`] match the spec; tests
/// pass synthesized `tempfile::TempDir` paths instead.
///
/// Two distinct concerns live in this struct:
///
/// * `sandbox_root` — a chroot-style prefix used by the **known list**
///   resolver. When set, an absolute path like `/opt/helium-browser-bin`
///   resolves to `<sandbox_root>/opt/helium-browser-bin`. Production code
///   leaves this `None`; tests set it to a `tempfile::TempDir` so the dev
///   machine's real `/opt/...` cannot mask synthesized fixtures.
/// * `linux_search` / `macos_applications` — directories the **discovery
///   walker** scans for unknown Chromium forks. Both production and tests
///   populate these.
#[derive(Debug, Clone, Default)]
pub struct FilesystemRoots {
    /// macOS: directories whose `*.app` children we'll inspect.
    /// Real default: `/Applications`.
    pub macos_applications: Vec<PathBuf>,
    /// Linux: directories we'll walk one level deep, looking for
    /// `chrome-sandbox` / `chromium-sandbox` markers.
    /// Real default: `/opt`, `/usr/lib`, `/usr/lib64`, `/usr/local/lib`.
    pub linux_search: Vec<PathBuf>,
    /// Optional chroot-style prefix for known-list path resolution.
    /// `None` in production; `Some(<TempDir>)` in tests.
    pub sandbox_root: Option<PathBuf>,
}

impl FilesystemRoots {
    /// Default roots for the host OS, matching the spec.
    #[must_use]
    pub fn default_for(os: Os) -> Self {
        match os {
            Os::Macos => Self {
                macos_applications: vec![PathBuf::from("/Applications")],
                linux_search: vec![],
                sandbox_root: None,
            },
            Os::Linux => Self {
                macos_applications: vec![],
                linux_search: vec![
                    PathBuf::from("/opt"),
                    PathBuf::from("/usr/lib"),
                    PathBuf::from("/usr/lib64"),
                    PathBuf::from("/usr/local/lib"),
                ],
                sandbox_root: None,
            },
        }
    }
}

/// Scan the filesystem for Chromium-family browsers.
///
/// Best-effort: any `read_dir` failure is silently skipped (we don't
/// have permission to scan every directory in `/usr/lib` on every
/// distro, and that's fine — the user can always add a custom entry).
#[must_use]
pub fn discover_filesystem(os: Os, roots: &FilesystemRoots) -> Vec<Browser> {
    match os {
        Os::Linux => discover_linux(roots),
        Os::Macos => discover_macos(roots),
    }
}

/// Linux discovery: walk each of `roots.linux_search` one level deep,
/// looking for directories that contain `chrome-sandbox` or
/// `chromium-sandbox`.
fn discover_linux(roots: &FilesystemRoots) -> Vec<Browser> {
    let mut out = Vec::new();
    let mut scanned = HashSet::new();
    for root in &roots.linux_search {
        if !scanned.insert(deduplication_key(root)) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if !(kind.is_dir() || kind.is_symlink() && path.is_dir()) {
                continue;
            }
            if has_chromium_sandbox(&path) {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map_or_else(|| path.display().to_string(), str::to_string);
                out.push(Browser {
                    name,
                    install_path: path,
                    kind: BrowserKind::Detected,
                    framework_name: None,
                });
            }
        }
    }
    out
}

/// Resolve aliases for root deduplication without changing discovered paths.
fn deduplication_key(root: &Path) -> PathBuf {
    std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf())
}

/// Returns true if `dir` looks like a standalone Chromium-family browser
/// (as opposed to an Electron-based application like Signal Desktop or
/// Tutanota).
///
/// A browser directory must contain BOTH:
/// 1. A Chromium sandbox helper (`chrome-sandbox` or `chromium-sandbox`)
/// 2. A top-level executable named `chrome` or `chromium`
///
/// Electron apps satisfy (1) — they bundle `chrome-sandbox` for their
/// own sandboxing — but rename their main binary to the app name
/// (`electron`, `signal-desktop`, `tutanota-desktop`, etc.). The (2)
/// check filters them out.
fn has_chromium_sandbox(dir: &Path) -> bool {
    let has_sandbox = dir.join("chrome-sandbox").exists() || dir.join("chromium-sandbox").exists();
    if !has_sandbox {
        return false;
    }
    // Must also have a browser-shaped main executable.
    dir.join("chrome").exists()
        || dir.join("chromium").exists()
        || dir.join("chromium-browser").exists()
}

/// macOS discovery: walk each of `roots.macos_applications` one level
/// deep, looking at `*.app` bundles whose
/// `Contents/Frameworks/<X>.framework/Versions/` contains at least one
/// numeric-style versioned directory (Chromium framework convention).
fn discover_macos(roots: &FilesystemRoots) -> Vec<Browser> {
    let mut out = Vec::new();
    for root in &roots.macos_applications {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Bundle = `<name>.app` directory.
            if path.extension().and_then(|s| s.to_str()) != Some("app") {
                continue;
            }
            if !path.is_dir() {
                continue;
            }
            let frameworks = path.join("Contents").join("Frameworks");
            let Some(framework) = first_chromium_framework(&frameworks) else {
                continue;
            };
            let app_name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map_or_else(|| path.display().to_string(), str::to_string);
            let framework_name = framework
                .file_stem()
                .and_then(|s| s.to_str())
                .map(str::to_string);
            out.push(Browser {
                name: app_name,
                install_path: path,
                kind: BrowserKind::Detected,
                framework_name,
            });
        }
    }
    out
}

/// Find the first `*.framework` child of `frameworks_dir` whose
/// `Versions/` directory contains a numeric-prefixed version directory.
/// Returns the path to the `.framework` directory.
fn first_chromium_framework(frameworks_dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(frameworks_dir).ok()?;
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("framework") {
            continue;
        }
        if has_versioned_subdir(&p.join("Versions")) {
            return Some(p);
        }
    }
    None
}

/// Returns true if `versions_dir` contains a child directory whose name
/// starts with a digit (e.g. `128.0.6613.119`). Chromium framework
/// version names follow the `<major>.<minor>.<build>.<patch>` shape.
fn has_versioned_subdir(versions_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(versions_dir) else {
        return false;
    };
    for e in entries.flatten() {
        if !e.path().is_dir() {
            continue;
        }
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// Process-only browser discovery.
///
/// Returns no entries because an executable path does not provide enough
/// browser metadata to construct a reliable [`Browser`]. Use [`is_running`]
/// to inspect the running state of browsers found by filesystem discovery.
#[must_use]
pub fn discover_processes() -> Vec<Browser> {
    Vec::new()
}

/// Returns `true` if at least one running process's executable path
/// lives under `browser.install_path()`.
///
/// We use [`sysinfo`] to enumerate processes; for each we compare the
/// process's executable path against the browser's install path. The
/// comparison uses [`std::path::Path::starts_with`] so a process at
/// `/opt/helium-browser-bin/helium` matches a browser whose
/// `install_path` is `/opt/helium-browser-bin`.
///
/// Best-effort: process paths can be unreadable (permission denied for
/// processes owned by other users). Those are skipped silently.
///
/// # Performance
///
/// Refreshing the process table is non-trivial (a few ms). The patch
/// flow calls this once per patch — that's fine. Daemon code that
/// needs frequent polling should cache and refresh on file-watch events
/// instead.
#[must_use]
pub fn is_running(browser: &Browser) -> bool {
    is_running_under(browser.install_path())
}

/// Test- and injection-friendly variant of [`is_running`]: caller passes
/// the directory under which to consider any executable as "the browser."
#[must_use]
pub(crate) fn is_running_under(install: &Path) -> bool {
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    for proc in system.processes().values() {
        let Some(exe) = proc.exe() else { continue };
        if exe.starts_with(install) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn linux_discovery_finds_dir_with_chrome_sandbox() {
        let tmp = TempDir::new().expect("tempdir");
        let opt = tmp.path().join("opt");
        let helium = opt.join("helium-browser-bin");
        fs::create_dir_all(&helium).expect("mkdir helium");
        fs::write(helium.join("chrome-sandbox"), b"#!/bin/sh\n").expect("touch sandbox");
        // Real browsers also have a top-level `chrome` binary; this is what
        // distinguishes them from Electron apps.
        fs::write(helium.join("chrome"), b"\x7fELF").expect("touch chrome");
        // A peer dir without a sandbox marker — should not be detected.
        let other = opt.join("not-a-browser");
        fs::create_dir_all(&other).expect("mkdir other");
        // An Electron app (chrome-sandbox present but no `chrome` binary) —
        // must NOT be detected.
        let electron_app = opt.join("signal-desktop");
        fs::create_dir_all(&electron_app).expect("mkdir electron app");
        fs::write(electron_app.join("chrome-sandbox"), b"").expect("touch");
        fs::write(electron_app.join("signal-desktop"), b"\x7fELF").expect("touch app");

        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![opt.clone()],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Linux, &roots);
        assert_eq!(found.len(), 1, "should find only the real browser");
        assert_eq!(found[0].name, "helium-browser-bin");
        assert_eq!(found[0].install_path, helium);
        assert_eq!(found[0].kind, BrowserKind::Detected);
        assert!(found[0].framework_name.is_none());
    }

    #[test]
    fn linux_discovery_deduplicates_alias_roots_and_preserves_first_path() {
        let tmp = TempDir::new().expect("tempdir");
        let actual = tmp.path().join("lib");
        let alias = tmp.path().join("lib64");
        let browser = actual.join("chromium");
        fs::create_dir_all(&browser).expect("mkdir browser");
        fs::write(browser.join("chrome-sandbox"), b"").expect("touch sandbox");
        fs::write(browser.join("chrome"), b"\x7fELF").expect("touch chrome");
        std::os::unix::fs::symlink(&actual, &alias).expect("symlink alias");

        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![alias.clone(), actual],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Linux, &roots);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].install_path, alias.join("chromium"));
    }

    #[test]
    fn linux_discovery_follows_browser_directory_symlinks() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path().join("opt");
        let actual = tmp.path().join("store").join("chromium");
        fs::create_dir_all(&root).expect("mkdir root");
        fs::create_dir_all(&actual).expect("mkdir browser");
        fs::write(actual.join("chrome-sandbox"), b"").expect("touch sandbox");
        fs::write(actual.join("chrome"), b"\x7fELF").expect("touch chrome");
        std::os::unix::fs::symlink(&actual, root.join("chromium")).expect("symlink browser");

        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![root.clone()],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Linux, &roots);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].install_path, root.join("chromium"));
    }

    #[test]
    fn deduplication_key_falls_back_to_original_missing_path() {
        let tmp = TempDir::new().expect("tempdir");
        let missing = tmp.path().join("missing");
        assert_eq!(deduplication_key(&missing), missing);
    }

    #[test]
    fn linux_discovery_also_recognizes_chromium_sandbox_name() {
        let tmp = TempDir::new().expect("tempdir");
        let opt = tmp.path().join("opt");
        let chromium = opt.join("chromium");
        fs::create_dir_all(&chromium).expect("mkdir");
        fs::write(chromium.join("chromium-sandbox"), b"").expect("touch");
        // Need the `chromium` binary alongside `chromium-sandbox`.
        fs::write(chromium.join("chromium"), b"\x7fELF").expect("touch chromium");
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![opt.clone()],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Linux, &roots);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "chromium");
    }

    #[test]
    fn linux_discovery_filters_out_electron_apps() {
        // Regression test for the V2-acceptance bug: chrome-sandbox alone
        // is insufficient; Signal Desktop, Tutanota, electron41, CEF all
        // ship chrome-sandbox but should NOT be patched as browsers.
        let tmp = TempDir::new().expect("tempdir");
        let opt = tmp.path().join("opt");
        for app in ["signal-desktop", "tutanota-desktop", "electron41", "cef"] {
            let dir = opt.join(app);
            fs::create_dir_all(&dir).expect("mkdir electron app");
            fs::write(dir.join("chrome-sandbox"), b"").expect("touch sandbox");
            // Each app's main binary is named after itself, NOT `chrome`.
            fs::write(dir.join(app), b"\x7fELF").expect("touch app");
        }
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![opt.clone()],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Linux, &roots);
        assert!(
            found.is_empty(),
            "Electron apps must not be auto-discovered as browsers"
        );
    }

    #[test]
    fn linux_discovery_skips_files_silently() {
        let tmp = TempDir::new().expect("tempdir");
        let opt = tmp.path().join("opt");
        fs::create_dir_all(&opt).expect("mkdir opt");
        // Create a regular file as a sibling of where browsers would live.
        fs::write(opt.join("README"), b"hello").expect("touch readme");
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![opt],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Linux, &roots);
        assert!(found.is_empty());
    }

    #[test]
    fn linux_discovery_handles_missing_root_gracefully() {
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![PathBuf::from("/this/does/not/exist")],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Linux, &roots);
        assert!(found.is_empty());
    }

    #[test]
    fn macos_discovery_finds_app_with_chromium_framework() {
        let tmp = TempDir::new().expect("tempdir");
        let apps = tmp.path().join("Applications");
        let app = apps.join("WeirdChromium.app");
        let versions = app
            .join("Contents")
            .join("Frameworks")
            .join("WeirdChromium Framework.framework")
            .join("Versions")
            .join("128.0.6613.119");
        fs::create_dir_all(&versions).expect("mkdir versions");

        let roots = FilesystemRoots {
            macos_applications: vec![apps.clone()],
            linux_search: vec![],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Macos, &roots);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "WeirdChromium");
        assert_eq!(
            found[0].framework_name.as_deref(),
            Some("WeirdChromium Framework")
        );
        assert_eq!(found[0].install_path, app);
        assert_eq!(found[0].kind, BrowserKind::Detected);
    }

    #[test]
    fn macos_discovery_skips_apps_without_chromium_framework() {
        let tmp = TempDir::new().expect("tempdir");
        let apps = tmp.path().join("Applications");
        let safari = apps.join("Safari.app").join("Contents").join("Frameworks");
        fs::create_dir_all(&safari).expect("mkdir Safari");
        // Safari has frameworks but none with a numeric Versions/<n> dir.
        fs::create_dir_all(safari.join("Safari.framework").join("Versions").join("A"))
            .expect("safari version A");

        let roots = FilesystemRoots {
            macos_applications: vec![apps],
            linux_search: vec![],
            sandbox_root: None,
        };
        let found = discover_filesystem(Os::Macos, &roots);
        assert!(found.is_empty(), "Safari isn't a Chromium-family app");
    }

    #[test]
    fn process_only_discovery_returns_empty_without_install_metadata() {
        let processes = discover_processes();
        assert!(processes.is_empty());
    }

    #[test]
    fn default_roots_for_macos_includes_applications() {
        let r = FilesystemRoots::default_for(Os::Macos);
        assert!(r
            .macos_applications
            .contains(&PathBuf::from("/Applications")));
        assert!(r.linux_search.is_empty());
    }

    #[test]
    fn default_roots_for_linux_includes_opt_and_lib() {
        let r = FilesystemRoots::default_for(Os::Linux);
        assert!(r.linux_search.contains(&PathBuf::from("/opt")));
        assert!(r.linux_search.contains(&PathBuf::from("/usr/lib")));
        assert!(r.linux_search.contains(&PathBuf::from("/usr/lib64")));
        assert!(r.linux_search.contains(&PathBuf::from("/usr/local/lib")));
        assert!(r.macos_applications.is_empty());
    }
}
