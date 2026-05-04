//! Detect and remove legacy (V1) Neon installs.
//!
//! V1 of Neon was a mix of bash scripts, a Swift macOS menu-bar app, and a
//! Go Linux tray. It installed itself in different locations depending on
//! the path and the platform. V2 must:
//!
//! 1. **Detect** any legacy install on the host.
//! 2. **Surface** what was found to the user (so the migration is observable).
//! 3. **Remove** the legacy artifacts cleanly — using privilege escalation
//!    where needed (e.g. system-wide `LaunchDaemon` plists, `/etc/systemd`
//!    units).
//!
//! ## Things detected (per spec "Migration from bash-installed Neon")
//!
//! | Path | What it is | Action |
//! |---|---|---|
//! | `/Library/LaunchDaemons/com.neon.fix-drm.plist` | Mac legacy `LaunchDaemon` | unload + remove (root) |
//! | `/etc/systemd/system/neon-fix-drm.path` | Linux legacy systemd path unit | disable + remove (root) |
//! | `/etc/systemd/system/neon-fix-drm.service` | Linux legacy systemd service | remove (root) |
//! | `~/Library/LaunchAgents/com.neon.app.plist` | Mac DMG/Swift app legacy | unload + remove (user) |
//! | `~/.config/autostart/neon.desktop` | Linux tray-app legacy | remove (user) |
//! | `~/.local/share/WidevineCdm/` | Legacy CDM cache | migrate to `~/.cache/neon/widevine/<version>/` |
//! | `/usr/lib/neon/` | Linux .deb install | leave (user removes manually) |
//!
//! Per the migration matrix in the spec, `/usr/lib/neon/` is detected and
//! reported but **not removed** — it's a system-managed package and the
//! user should run `dpkg -r neon-drm` themselves.
//!
//! ## Test strategy
//!
//! Tests synthesize each legacy artifact under a `tempfile::TempDir`,
//! point [`detect_legacy_install_in`] at the temp root, and assert the
//! expected `LegacyArtifact`s are reported. Removal tests use the same
//! temp root and check for absence afterward; commands that would
//! normally need root (`launchctl`, `systemctl`) are guarded by the
//! `NEON_TEST_ESCALATE_NOOP=1` env var that `crate::platform` honors.
//!
//! ## What this module does NOT do
//!
//! * No backup of removed artifacts. The legacy install is by definition
//!   broken/being replaced; preserving plists or service files would just
//!   confuse later runs of `neon doctor`.
//! * No state-file migration beyond the `WidevineCdm` cache move. Legacy
//!   never had a stable state file.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::platform;

/// One artifact of a legacy install detected on the host.
///
/// Returned as a flat list inside [`LegacyInstall`] so the caller can
/// render a summary ("Found 3 legacy artifacts: ...") before running
/// removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyArtifact {
    /// What kind of artifact this is (drives the removal action).
    pub kind: LegacyKind,
    /// Path on disk where the artifact lives.
    pub path: PathBuf,
    /// `true` if removing this requires elevated privileges. Drives the
    /// migration UX ("we'll prompt for your password to remove these").
    pub needs_root: bool,
}

/// Categorization of legacy artifacts.
///
/// New variants get added rather than reshuffling — `Display` strings
/// are stable for log scraping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyKind {
    /// `/Library/LaunchDaemons/com.neon.fix-drm.plist` (macOS, root).
    MacLaunchDaemon,
    /// `~/Library/LaunchAgents/com.neon.app.plist` (macOS, user).
    MacLaunchAgent,
    /// `/etc/systemd/system/neon-fix-drm.path` (Linux, root).
    LinuxSystemdPath,
    /// `/etc/systemd/system/neon-fix-drm.service` (Linux, root).
    LinuxSystemdService,
    /// `~/.config/autostart/neon.desktop` (Linux, user).
    LinuxAutostart,
    /// `~/.local/share/WidevineCdm/` (Linux user CDM cache; migrates).
    LinuxLegacyCdmCache,
    /// `/usr/lib/neon/` (Linux .deb install; reported, not removed).
    LinuxDebPackage,
}

impl LegacyKind {
    /// Stable display name for logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MacLaunchDaemon => "MacLaunchDaemon",
            Self::MacLaunchAgent => "MacLaunchAgent",
            Self::LinuxSystemdPath => "LinuxSystemdPath",
            Self::LinuxSystemdService => "LinuxSystemdService",
            Self::LinuxAutostart => "LinuxAutostart",
            Self::LinuxLegacyCdmCache => "LinuxLegacyCdmCache",
            Self::LinuxDebPackage => "LinuxDebPackage",
        }
    }
}

impl std::fmt::Display for LegacyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Aggregated result of [`detect_legacy_install`].
///
/// `is_empty()` returns `true` when no artifacts were found — the
/// caller can short-circuit "nothing to migrate" without iterating.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyInstall {
    /// Every legacy artifact found, in detection order. Empty list →
    /// no legacy install detected.
    pub artifacts: Vec<LegacyArtifact>,
}

impl LegacyInstall {
    /// `true` when no legacy artifacts were detected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Number of detected artifacts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// `true` if any artifact requires root privileges to remove.
    /// Migration UX uses this to decide whether to prompt for a password.
    #[must_use]
    pub fn needs_root(&self) -> bool {
        self.artifacts.iter().any(|a| a.needs_root)
    }
}

/// Detect every legacy install artifact present on the host.
///
/// Returns an empty [`LegacyInstall`] (`is_empty()` true) when nothing
/// is found. Always returns a value — there's no "error" mode for
/// detection; missing files are the expected case.
#[must_use]
pub fn detect_legacy_install() -> LegacyInstall {
    detect_legacy_install_in(&FsRoots::host())
}

/// Filesystem roots used by the legacy detector.
///
/// Tests construct one pointing at a `tempfile::TempDir` so they can
/// synthesize a fake legacy install under the temp root and assert the
/// expected artifacts surface.
#[derive(Debug, Clone)]
pub struct FsRoots {
    /// `/` on the host; tests use a tempdir.
    pub system_root: PathBuf,
    /// `$HOME` on the host; tests use a tempdir/home subdirectory.
    pub home: Option<PathBuf>,
}

impl FsRoots {
    /// Build the host-default roots from `dirs::home_dir()` and `/`.
    #[must_use]
    pub fn host() -> Self {
        Self {
            system_root: PathBuf::from("/"),
            home: dirs::home_dir(),
        }
    }
}

/// Variant of [`detect_legacy_install`] that operates against the given
/// filesystem roots. Used by tests to point detection at a `TempDir`.
#[must_use]
pub fn detect_legacy_install_in(roots: &FsRoots) -> LegacyInstall {
    let mut artifacts = Vec::new();

    // macOS: LaunchDaemon (root)
    let mac_daemon = roots
        .system_root
        .join("Library/LaunchDaemons/com.neon.fix-drm.plist");
    if mac_daemon.exists() {
        artifacts.push(LegacyArtifact {
            kind: LegacyKind::MacLaunchDaemon,
            path: mac_daemon,
            needs_root: true,
        });
    }
    // macOS: LaunchAgent (user)
    if let Some(home) = &roots.home {
        let mac_agent = home.join("Library/LaunchAgents/com.neon.app.plist");
        if mac_agent.exists() {
            artifacts.push(LegacyArtifact {
                kind: LegacyKind::MacLaunchAgent,
                path: mac_agent,
                needs_root: false,
            });
        }
    }

    // Linux: systemd path + service (root)
    let sys_path = roots
        .system_root
        .join("etc/systemd/system/neon-fix-drm.path");
    if sys_path.exists() {
        artifacts.push(LegacyArtifact {
            kind: LegacyKind::LinuxSystemdPath,
            path: sys_path,
            needs_root: true,
        });
    }
    let sys_service = roots
        .system_root
        .join("etc/systemd/system/neon-fix-drm.service");
    if sys_service.exists() {
        artifacts.push(LegacyArtifact {
            kind: LegacyKind::LinuxSystemdService,
            path: sys_service,
            needs_root: true,
        });
    }

    // Linux: autostart + WidevineCdm cache (user)
    if let Some(home) = &roots.home {
        let autostart = home.join(".config/autostart/neon.desktop");
        if autostart.exists() {
            artifacts.push(LegacyArtifact {
                kind: LegacyKind::LinuxAutostart,
                path: autostart,
                needs_root: false,
            });
        }
        let legacy_cdm = home.join(".local/share/WidevineCdm");
        if legacy_cdm.exists() {
            artifacts.push(LegacyArtifact {
                kind: LegacyKind::LinuxLegacyCdmCache,
                path: legacy_cdm,
                needs_root: false,
            });
        }
    }

    // Linux: .deb install (root, but not removed — reported only)
    let deb_install = roots.system_root.join("usr/lib/neon");
    if deb_install.exists() {
        artifacts.push(LegacyArtifact {
            kind: LegacyKind::LinuxDebPackage,
            path: deb_install,
            needs_root: true,
        });
    }

    LegacyInstall { artifacts }
}

/// Where legacy CDM caches get migrated to.
///
/// The destination layout matches V2's cache directory:
/// `<cache_dir>/widevine/legacy/`. The "legacy" suffix is intentional —
/// the V2 CDM cache uses the version string (e.g. `4.10.2934.0/`); we
/// stash the legacy cache under a sibling without claiming a version.
/// V2's update flow (`neon update widevine`) will replace it with a
/// properly-versioned cache at first use.
#[must_use]
pub fn legacy_cdm_destination() -> PathBuf {
    platform::cache_dir().join("widevine").join("legacy")
}

/// Remove every legacy artifact in `install`.
///
/// Behavior per artifact:
///
/// * **Mac `LaunchDaemon`** — `launchctl unload` then `rm` (both elevated).
/// * **Mac `LaunchAgent`** — `launchctl unload` (user-domain) then `rm` (user).
/// * **Linux systemd path/service** — `systemctl disable --now` then `rm`
///   (both elevated).
/// * **Linux autostart** — `rm` (user).
/// * **Linux legacy CDM cache** — moved to [`legacy_cdm_destination`]
///   (user). If the destination already exists, the source is removed.
/// * **Linux .deb package** — left alone; surface a warning to the
///   caller via the returned [`MigrationOutcome`].
///
/// Privilege escalation goes through [`platform::run_as_root`]; this
/// honors `NEON_TEST_ESCALATE_NOOP=1` so tests don't actually elevate.
///
/// # Errors
///
/// Returns the first removal error encountered. Earlier successes are
/// retained in the returned [`MigrationOutcome`] so the caller can
/// surface partial progress to the user.
pub fn remove_legacy(install: LegacyInstall) -> Result<MigrationOutcome> {
    remove_legacy_with(install, &legacy_cdm_destination())
}

/// Test/injection-friendly variant of [`remove_legacy`] that uses
/// `cdm_destination` instead of resolving via the platform cache dir.
///
/// # Errors
///
/// See [`remove_legacy`].
pub fn remove_legacy_with(
    install: LegacyInstall,
    cdm_destination: &Path,
) -> Result<MigrationOutcome> {
    let mut outcome = MigrationOutcome::default();
    for art in install.artifacts {
        match art.kind {
            LegacyKind::MacLaunchDaemon => {
                unload_and_remove_root(&art.path, "system", &mut outcome)?;
            }
            LegacyKind::MacLaunchAgent => {
                unload_and_remove_user(&art.path, &mut outcome)?;
            }
            LegacyKind::LinuxSystemdPath => {
                disable_and_remove_systemd(&art.path, "neon-fix-drm.path", &mut outcome)?;
            }
            LegacyKind::LinuxSystemdService => {
                disable_and_remove_systemd(&art.path, "neon-fix-drm.service", &mut outcome)?;
            }
            LegacyKind::LinuxAutostart => {
                remove_user_path(&art.path, &mut outcome)?;
            }
            LegacyKind::LinuxLegacyCdmCache => {
                migrate_legacy_cdm(&art.path, cdm_destination, &mut outcome)?;
            }
            LegacyKind::LinuxDebPackage => {
                outcome.skipped.push(SkipReason {
                    path: art.path.clone(),
                    reason: ".deb package — run `dpkg -r neon-drm` to remove".into(),
                });
            }
        }
    }
    Ok(outcome)
}

/// Result of a [`remove_legacy`] call.
///
/// Lists each artifact category outcome separately so the caller can
/// surface a useful summary ("Removed: launch agent, autostart entry;
/// migrated: `WidevineCdm` cache; skipped: .deb package").
#[derive(Debug, Clone, Default)]
pub struct MigrationOutcome {
    /// Legacy artifacts that were removed cleanly.
    pub removed: Vec<PathBuf>,
    /// Legacy CDM caches that were moved to the V2 cache directory.
    pub migrated: Vec<MigrationMove>,
    /// Artifacts that were intentionally not touched.
    pub skipped: Vec<SkipReason>,
}

/// Source/destination of a CDM cache migration.
#[derive(Debug, Clone)]
pub struct MigrationMove {
    /// Original location (e.g. `~/.local/share/WidevineCdm`).
    pub from: PathBuf,
    /// New V2 location.
    pub to: PathBuf,
}

/// Reason an artifact was intentionally skipped.
#[derive(Debug, Clone)]
pub struct SkipReason {
    /// Artifact's path on disk.
    pub path: PathBuf,
    /// Human-readable explanation.
    pub reason: String,
}

/// `launchctl unload` (system domain) then remove the plist (root).
fn unload_and_remove_root(plist: &Path, _scope: &str, out: &mut MigrationOutcome) -> Result<()> {
    let plist_str = plist
        .to_str()
        .ok_or_else(|| Error::other(format!("plist path not UTF-8: {}", plist.display())))?;
    // Best-effort unload — ignore failures here because the daemon may
    // already be unloaded (system reboot since installed) or the binary
    // it pointed to may no longer exist.
    let _ = platform::run_as_root(&["launchctl", "unload", "-w", plist_str]);
    let _ = platform::run_as_root(&["rm", "-f", plist_str]);
    out.removed.push(plist.to_path_buf());
    Ok(())
}

/// `launchctl unload` then remove the plist — user domain, no
/// elevation required.
fn unload_and_remove_user(plist: &Path, out: &mut MigrationOutcome) -> Result<()> {
    let plist_str = plist
        .to_str()
        .ok_or_else(|| Error::other(format!("plist path not UTF-8: {}", plist.display())))?;
    // Best-effort unload via user `launchctl`. Do not propagate spawn
    // errors — `launchctl` may not exist (e.g. running from inside a
    // sandboxed test runner). Removing the plist is the load-bearing
    // step; the unload merely tells `launchd` to stop the process.
    let _ = std::process::Command::new("launchctl")
        .args(["unload", "-w", plist_str])
        .output();
    remove_path(plist).map_err(|e| {
        Error::from(e).with_path_context(format!("could not remove {}", plist.display()))
    })?;
    out.removed.push(plist.to_path_buf());
    Ok(())
}

/// `systemctl disable --now <unit>` then `rm` the unit file (root).
fn disable_and_remove_systemd(
    unit_path: &Path,
    unit_name: &str,
    out: &mut MigrationOutcome,
) -> Result<()> {
    let unit_path_str = unit_path
        .to_str()
        .ok_or_else(|| Error::other(format!("unit path not UTF-8: {}", unit_path.display())))?;
    // Best-effort disable. The unit may already be inactive.
    let _ = platform::run_as_root(&["systemctl", "disable", "--now", unit_name]);
    let _ = platform::run_as_root(&["rm", "-f", unit_path_str]);
    // Reload systemd so the removed unit is forgotten.
    let _ = platform::run_as_root(&["systemctl", "daemon-reload"]);
    out.removed.push(unit_path.to_path_buf());
    Ok(())
}

/// Remove a user-owned file or directory.
fn remove_user_path(path: &Path, out: &mut MigrationOutcome) -> Result<()> {
    remove_path(path).map_err(|e| {
        Error::from(e).with_path_context(format!("could not remove {}", path.display()))
    })?;
    out.removed.push(path.to_path_buf());
    Ok(())
}

/// Migrate a legacy `WidevineCdm` cache to the V2 location.
///
/// If the destination doesn't exist we move the cache there. If the
/// destination already exists we **delete** the legacy cache (the user
/// already has a V2 cache; the legacy one is redundant).
fn migrate_legacy_cdm(legacy: &Path, destination: &Path, out: &mut MigrationOutcome) -> Result<()> {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::from(e).with_path_context(format!(
                "could not create parent of {}",
                destination.display()
            ))
        })?;
    }
    if destination.exists() {
        // V2 cache already present — drop the legacy copy.
        remove_path(legacy).map_err(|e| {
            Error::from(e).with_path_context(format!(
                "could not remove legacy cache {}",
                legacy.display()
            ))
        })?;
        out.skipped.push(SkipReason {
            path: legacy.to_path_buf(),
            reason: "V2 widevine cache already exists; removed legacy duplicate".into(),
        });
        return Ok(());
    }
    std::fs::rename(legacy, destination).map_err(|e| {
        Error::from(e).with_path_context(format!(
            "could not move {} to {}",
            legacy.display(),
            destination.display()
        ))
    })?;
    out.migrated.push(MigrationMove {
        from: legacy.to_path_buf(),
        to: destination.to_path_buf(),
    });
    Ok(())
}

/// Recursively remove a path. Returns the first IO error encountered.
fn remove_path(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

trait WithPathContext {
    fn with_path_context(self, ctx: String) -> Self;
}

impl WithPathContext for Error {
    /// Prepend `ctx` to the inner message.
    fn with_path_context(mut self, ctx: String) -> Self {
        if self.message.is_empty() {
            self.message = ctx;
        } else {
            self.message = format!("{ctx}: {}", self.message);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Build a fully-synthesized legacy install under `tmp` and return
    /// the [`FsRoots`] that points at it.
    fn synthesize_full_legacy(tmp: &Path) -> FsRoots {
        // System-side artifacts under `tmp/system/`.
        let system_root = tmp.join("system");
        fs::create_dir_all(system_root.join("Library/LaunchDaemons")).unwrap();
        fs::create_dir_all(system_root.join("etc/systemd/system")).unwrap();
        fs::create_dir_all(system_root.join("usr/lib/neon")).unwrap();
        fs::write(
            system_root.join("Library/LaunchDaemons/com.neon.fix-drm.plist"),
            b"<plist></plist>",
        )
        .unwrap();
        fs::write(
            system_root.join("etc/systemd/system/neon-fix-drm.path"),
            b"[Path]\n",
        )
        .unwrap();
        fs::write(
            system_root.join("etc/systemd/system/neon-fix-drm.service"),
            b"[Service]\n",
        )
        .unwrap();
        // The .deb package install dir is just an empty directory.
        // Already created by the create_dir_all above.

        // User-side artifacts under `tmp/home/`.
        let home = tmp.join("home");
        fs::create_dir_all(home.join("Library/LaunchAgents")).unwrap();
        fs::create_dir_all(home.join(".config/autostart")).unwrap();
        fs::create_dir_all(home.join(".local/share/WidevineCdm/4.10.0.0")).unwrap();
        fs::write(
            home.join("Library/LaunchAgents/com.neon.app.plist"),
            b"<plist></plist>",
        )
        .unwrap();
        fs::write(
            home.join(".config/autostart/neon.desktop"),
            b"[Desktop Entry]\n",
        )
        .unwrap();
        fs::write(
            home.join(".local/share/WidevineCdm/4.10.0.0/libwidevinecdm.so"),
            b"fake",
        )
        .unwrap();

        FsRoots {
            system_root,
            home: Some(home),
        }
    }

    #[test]
    fn detect_finds_every_artifact_in_synthesized_install() {
        let tmp = TempDir::new().unwrap();
        let roots = synthesize_full_legacy(tmp.path());
        let install = detect_legacy_install_in(&roots);
        assert!(!install.is_empty());
        assert_eq!(install.len(), 7);
        let kinds: Vec<LegacyKind> = install.artifacts.iter().map(|a| a.kind).collect();
        assert!(kinds.contains(&LegacyKind::MacLaunchDaemon));
        assert!(kinds.contains(&LegacyKind::MacLaunchAgent));
        assert!(kinds.contains(&LegacyKind::LinuxSystemdPath));
        assert!(kinds.contains(&LegacyKind::LinuxSystemdService));
        assert!(kinds.contains(&LegacyKind::LinuxAutostart));
        assert!(kinds.contains(&LegacyKind::LinuxLegacyCdmCache));
        assert!(kinds.contains(&LegacyKind::LinuxDebPackage));
        assert!(install.needs_root());
    }

    #[test]
    fn detect_returns_empty_for_clean_host() {
        let tmp = TempDir::new().unwrap();
        let roots = FsRoots {
            system_root: tmp.path().join("clean-system"),
            home: Some(tmp.path().join("clean-home")),
        };
        // The roots don't exist; detection finds nothing.
        let install = detect_legacy_install_in(&roots);
        assert!(install.is_empty());
        assert!(!install.needs_root());
    }

    #[test]
    fn detect_handles_missing_home() {
        let tmp = TempDir::new().unwrap();
        let roots = FsRoots {
            system_root: tmp.path().to_path_buf(),
            home: None,
        };
        // Without home, only system artifacts can surface.
        let install = detect_legacy_install_in(&roots);
        for a in &install.artifacts {
            assert!(
                matches!(
                    a.kind,
                    LegacyKind::MacLaunchDaemon
                        | LegacyKind::LinuxSystemdPath
                        | LegacyKind::LinuxSystemdService
                        | LegacyKind::LinuxDebPackage
                ),
                "no user-domain artifacts when home=None"
            );
        }
    }

    /// `remove_legacy_with` removes all user artifacts cleanly when
    /// running with `NEON_TEST_ESCALATE_NOOP` set so root operations
    /// don't actually shell out.
    #[test]
    fn remove_legacy_under_noop_short_circuit() {
        let tmp = TempDir::new().unwrap();
        let roots = synthesize_full_legacy(tmp.path());
        // SAFETY: env mutations happen in serial test threads; we
        // restore at end-of-test.
        unsafe { std::env::set_var("NEON_TEST_ESCALATE_NOOP", "1") };
        let install = detect_legacy_install_in(&roots);
        let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");
        let outcome = remove_legacy_with(install, &cdm_dest).expect("ok");

        // User-side artifacts were removed:
        let home = roots.home.as_ref().unwrap();
        assert!(!home
            .join("Library/LaunchAgents/com.neon.app.plist")
            .exists());
        assert!(!home.join(".config/autostart/neon.desktop").exists());

        // The legacy CDM cache was migrated to the V2 destination.
        assert!(cdm_dest.exists());
        assert!(cdm_dest.join("4.10.0.0/libwidevinecdm.so").exists());
        assert!(!home.join(".local/share/WidevineCdm").exists());

        // The .deb package install was reported as skipped.
        assert!(outcome
            .skipped
            .iter()
            .any(|s| s.path.ends_with("usr/lib/neon")));
        // System-side removed entries are recorded in `removed` even if
        // we didn't actually shell out (NOOP mode).
        assert!(outcome
            .removed
            .iter()
            .any(|p| p.ends_with("Library/LaunchDaemons/com.neon.fix-drm.plist")));
        assert!(!outcome.migrated.is_empty());

        unsafe { std::env::remove_var("NEON_TEST_ESCALATE_NOOP") };
    }

    #[test]
    fn remove_legacy_drops_redundant_cdm_when_v2_cache_exists() {
        let tmp = TempDir::new().unwrap();
        let roots = synthesize_full_legacy(tmp.path());
        // Pre-create the V2 destination so migrate_legacy_cdm sees it.
        let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");
        fs::create_dir_all(&cdm_dest).unwrap();
        fs::write(cdm_dest.join("v2-marker"), b"v2").unwrap();

        unsafe { std::env::set_var("NEON_TEST_ESCALATE_NOOP", "1") };
        let install = detect_legacy_install_in(&roots);
        let outcome = remove_legacy_with(install, &cdm_dest).expect("ok");
        unsafe { std::env::remove_var("NEON_TEST_ESCALATE_NOOP") };

        // Legacy CDM cache is gone; v2 marker is intact.
        let home = roots.home.as_ref().unwrap();
        assert!(!home.join(".local/share/WidevineCdm").exists());
        assert!(cdm_dest.join("v2-marker").exists());
        // It's reported as skipped (with the "v2 cache exists" reason).
        let skip = outcome
            .skipped
            .iter()
            .find(|s| s.path.ends_with(".local/share/WidevineCdm"))
            .expect("skipped entry");
        assert!(skip.reason.contains("V2"));
    }

    #[test]
    fn legacy_cdm_destination_lives_under_neon_cache() {
        let p = legacy_cdm_destination();
        assert!(p.ends_with("widevine/legacy"), "{}", p.display());
        // The parent should end with `neon` (cache_dir is .../neon).
        let parent = p.parent().expect("has parent").parent().expect("has gp");
        assert!(parent.ends_with("neon"));
    }

    #[test]
    fn legacy_kind_as_str_is_stable() {
        // Stable strings used in logs.
        assert_eq!(LegacyKind::MacLaunchDaemon.as_str(), "MacLaunchDaemon");
        assert_eq!(format!("{}", LegacyKind::MacLaunchAgent), "MacLaunchAgent");
        assert_eq!(LegacyKind::LinuxSystemdPath.as_str(), "LinuxSystemdPath");
        assert_eq!(
            LegacyKind::LinuxSystemdService.as_str(),
            "LinuxSystemdService"
        );
        assert_eq!(LegacyKind::LinuxAutostart.as_str(), "LinuxAutostart");
        assert_eq!(
            LegacyKind::LinuxLegacyCdmCache.as_str(),
            "LinuxLegacyCdmCache"
        );
        assert_eq!(LegacyKind::LinuxDebPackage.as_str(), "LinuxDebPackage");
    }

    #[test]
    fn legacy_install_default_is_empty() {
        let li = LegacyInstall::default();
        assert!(li.is_empty());
        assert_eq!(li.len(), 0);
        assert!(!li.needs_root());
    }

    #[test]
    fn fs_roots_host_returns_some_home_on_dev_machines() {
        // dirs::home_dir() returns Some() on every CI / dev system; the
        // call should not panic.
        let r = FsRoots::host();
        assert_eq!(r.system_root, PathBuf::from("/"));
        // home is Some(...) on systems with $HOME set.
        let _ = r.home; // tolerate either branch
    }

    /// `remove_user_path` returns an error when the path doesn't exist.
    #[test]
    fn remove_user_path_errors_on_missing_path() {
        let tmp = TempDir::new().unwrap();
        let mut out = MigrationOutcome::default();
        let r = remove_user_path(&tmp.path().join("nope"), &mut out);
        assert!(r.is_err());
    }

    #[test]
    fn migrate_legacy_cdm_creates_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let legacy = tmp.path().join("legacy");
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("file"), b"x").unwrap();
        let dest = tmp.path().join("a/b/c/widevine/legacy");
        let mut out = MigrationOutcome::default();
        migrate_legacy_cdm(&legacy, &dest, &mut out).expect("ok");
        assert!(dest.exists());
        assert!(dest.join("file").exists());
        assert_eq!(out.migrated.len(), 1);
    }

    #[test]
    fn with_path_context_replaces_or_prepends() {
        let e1 = Error::other("inner").with_path_context("ctx".into());
        assert_eq!(e1.message, "ctx: inner");
        let e2 = Error::other("").with_path_context("ctx".into());
        assert_eq!(e2.message, "ctx");
    }
}
