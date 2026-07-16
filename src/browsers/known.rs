//! Hardcoded list of browsers Silvervine is known to support.
//!
//! The constants here are static — the `paths` slice gives every path
//! we've ever seen a given browser install to. If a browser-of-interest
//! ships at a new path, the user can either add it to `[[browsers]]` in
//! their config, OR (preferred) we add a new path and roll out a Silvervine
//! release.
//!
//! Per the spec's "Browser support → Known browsers" section.

use std::path::PathBuf;

use super::{Browser, BrowserKind, FilesystemRoots, Os};

/// One known browser, broken out by platform.
///
/// `linux_paths` is searched in order; the first existing match wins.
/// `macos_apps` is the bundle name (without `.app` suffix) — matched
/// against `<applications-root>/<name>.app`.
#[derive(Debug, Clone, Copy)]
pub struct KnownBrowser {
    /// Display name (also used as the macOS bundle name).
    pub name: &'static str,
    /// macOS framework directory name. Always present so the patch flow
    /// (Phase 2) knows which framework folder to write into.
    pub macos_framework: &'static str,
    /// Linux install paths to probe, in priority order.
    pub linux_paths: &'static [&'static str],
}

/// Known browsers per the spec's `KNOWN_MACOS` + `KNOWN_LINUX` constants.
///
/// We unify the Linux + macOS lists into a single table here because the
/// browsers themselves are the same conceptually — only the install path
/// shape differs.
pub const KNOWN: &[KnownBrowser] = &[
    KnownBrowser {
        name: "Helium",
        macos_framework: "Helium Framework",
        // `/opt/helium` is the official .deb path used on Debian/Ubuntu/Pop!_OS
        // (apt repo pkg.helium.computer); `/opt/helium-browser-bin` is the AUR
        // path on Arch.
        linux_paths: &["/opt/helium", "/opt/helium-browser-bin"],
    },
    KnownBrowser {
        name: "Thorium",
        macos_framework: "Thorium Framework",
        linux_paths: &["/opt/chromium.org/thorium", "/opt/thorium-browser"],
    },
    KnownBrowser {
        name: "ungoogled-chromium",
        macos_framework: "Chromium Framework",
        linux_paths: &["/usr/lib/chromium", "/usr/lib64/chromium"],
    },
    KnownBrowser {
        name: "Chromium",
        macos_framework: "Chromium Framework",
        linux_paths: &["/usr/lib/chromium-browser"],
    },
];

/// Subset of [`KNOWN`] applicable to macOS. Provided for spec parity
/// — internally, the detection code just walks [`KNOWN`].
pub const KNOWN_MACOS: &[KnownBrowser] = KNOWN;

/// Subset of [`KNOWN`] applicable to Linux. Same structure as [`KNOWN_MACOS`].
pub const KNOWN_LINUX: &[KnownBrowser] = KNOWN;

/// Resolve the known browsers that exist on disk for the given OS,
/// using `roots` for the filesystem search prefixes.
///
/// Returns a `Vec` in the same order as [`KNOWN`].
#[must_use]
pub fn known_for_os(os: Os, roots: &FilesystemRoots) -> Vec<Browser> {
    let mut out = Vec::new();
    for kb in KNOWN {
        match os {
            Os::Linux => {
                if let Some(p) = first_existing_linux_path(kb, roots) {
                    out.push(Browser {
                        name: kb.name.to_string(),
                        install_path: p,
                        kind: BrowserKind::Known,
                        framework_name: None,
                    });
                }
            }
            Os::Macos => {
                if let Some(p) = first_existing_macos_app(kb, roots) {
                    out.push(Browser {
                        name: kb.name.to_string(),
                        install_path: p,
                        kind: BrowserKind::Known,
                        framework_name: Some(kb.macos_framework.to_string()),
                    });
                }
            }
        }
    }
    out
}

fn first_existing_linux_path(kb: &KnownBrowser, roots: &FilesystemRoots) -> Option<PathBuf> {
    // Resolution strategy:
    //
    // * If [`FilesystemRoots::sandbox_root`] is set, treat it as a
    //   chroot-style prefix: the absolute path `/opt/foo` resolves to
    //   `<sandbox>/opt/foo`. Tests use this so the dev machine's real
    //   `/opt/...` cannot mask the synthesized fixture tree.
    // * Otherwise, the literal absolute paths from the spec
    //   (`/opt/...`, `/usr/lib/...`) are checked directly. This is the
    //   production branch.
    //
    // The `linux_search` list is independent: it drives the "discover
    // unknown forks of Chromium" walk in `discovery.rs` — not the known
    // list resolution. Keeping the two concerns separate avoids the
    // leaf-rebase trap (where `/opt/chromium` could spuriously match
    // an unrelated `chromium` dir under any walk root).
    if let Some(sandbox) = &roots.sandbox_root {
        for raw in kb.linux_paths {
            let suffix = raw.trim_start_matches('/');
            let candidate = sandbox.join(suffix);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        return None;
    }
    for raw in kb.linux_paths {
        let absolute = PathBuf::from(raw);
        if absolute.exists() {
            return Some(absolute);
        }
    }
    None
}

fn first_existing_macos_app(kb: &KnownBrowser, roots: &FilesystemRoots) -> Option<PathBuf> {
    let app_name = format!("{}.app", kb.name);
    // Search every configured `macos_applications` root. Production
    // default is `/Applications`; tests inject a tempdir.
    for app_root in &roots.macos_applications {
        let candidate = app_root.join(&app_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn known_constants_have_expected_browsers() {
        let names: Vec<&str> = KNOWN.iter().map(|k| k.name).collect();
        assert!(names.contains(&"Helium"));
        assert!(names.contains(&"Thorium"));
        assert!(names.contains(&"ungoogled-chromium"));
        assert!(names.contains(&"Chromium"));
    }

    #[test]
    fn known_linux_resolves_under_sandbox_root() {
        let tmp = TempDir::new().expect("tempdir");
        // `/opt/helium-browser-bin` resolves under the sandbox to
        // `<tmp>/opt/helium-browser-bin`.
        fs::create_dir_all(tmp.path().join("opt").join("helium-browser-bin"))
            .expect("mkdir helium");
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![],
            sandbox_root: Some(tmp.path().to_path_buf()),
        };
        let found = known_for_os(Os::Linux, &roots);
        let names: Vec<&str> = found.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"Helium"));
        // Other known browsers don't have dirs in the sandbox, so they
        // don't surface.
        assert!(!names.contains(&"Thorium"));
    }

    #[test]
    fn known_linux_resolves_helium_at_opt_helium() {
        // The official Helium .deb (apt repo pkg.helium.computer, used on
        // Debian / Ubuntu / Pop!_OS) installs to `/opt/helium`, not the
        // Arch AUR path `/opt/helium-browser-bin`. Both must resolve.
        let tmp = TempDir::new().expect("tempdir");
        fs::create_dir_all(tmp.path().join("opt").join("helium")).expect("mkdir helium");
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![],
            sandbox_root: Some(tmp.path().to_path_buf()),
        };
        let found = known_for_os(Os::Linux, &roots);
        let helium = found
            .iter()
            .find(|b| b.name == "Helium")
            .expect("Helium found via /opt/helium");
        assert!(helium.install_path.ends_with("opt/helium"));
    }

    #[test]
    fn known_macos_resolves_under_test_root() {
        let tmp = TempDir::new().expect("tempdir");
        let apps = tmp.path().join("Applications");
        fs::create_dir_all(apps.join("Thorium.app")).expect("mkdir thorium app");
        let roots = FilesystemRoots {
            macos_applications: vec![apps.clone()],
            linux_search: vec![],
            sandbox_root: None,
        };
        let found = known_for_os(Os::Macos, &roots);
        let names: Vec<&str> = found.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"Thorium"));
        let entry = found.iter().find(|b| b.name == "Thorium").expect("thorium");
        assert_eq!(
            entry.framework_name.as_deref(),
            Some("Thorium Framework"),
            "macOS known browsers carry their framework name"
        );
    }

    #[test]
    fn no_match_returns_empty() {
        let tmp = TempDir::new().expect("tempdir");
        let roots = FilesystemRoots {
            macos_applications: vec![tmp.path().to_path_buf()],
            linux_search: vec![tmp.path().to_path_buf()],
            sandbox_root: Some(tmp.path().to_path_buf()),
        };
        assert!(known_for_os(Os::Linux, &roots).is_empty());
        assert!(known_for_os(Os::Macos, &roots).is_empty());
    }

    /// Production branch: `sandbox_root: None` should consult the literal
    /// absolute paths from `KNOWN`. We exercise the loop with default
    /// roots; either the machine has a known browser installed (in which
    /// case the function returns `Some(path)`) or it doesn't (returns
    /// `None`). Both are valid outcomes; the point is the code path
    /// runs without panic.
    #[test]
    fn production_branch_runs_with_no_sandbox_root() {
        let roots = FilesystemRoots {
            macos_applications: vec![],
            linux_search: vec![],
            sandbox_root: None,
        };
        // Doesn't matter what's on disk; the code must handle empty
        // `linux_paths` matches without panicking.
        let _ = known_for_os(Os::Linux, &roots);
        let _ = known_for_os(Os::Macos, &roots);
    }
}
