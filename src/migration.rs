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
//! | `/etc/systemd/system/neon-fix-drm.{path,service}` | Linux raw `install.sh` units | disable + remove (root) |
//! | `/usr/lib/systemd/system/neon-fix-drm.{path,service}` | Linux AUR / RPM-installed units | leave; surface pkg-manager hint |
//! | `/lib/systemd/system/neon-fix-drm.{path,service}` | Linux Debian / pre-merged-usr units | leave; surface pkg-manager hint |
//! | `~/Library/LaunchAgents/com.neon.app.plist` | Mac DMG/Swift app legacy | unload + remove (user) |
//! | `~/.config/autostart/neon.desktop` | Linux tray-app legacy | remove (user) |
//! | `~/.local/share/WidevineCdm/` | Legacy CDM cache | migrate to `~/.cache/neon/widevine/<version>/` |
//! | `/usr/lib/neon/` | Linux packaged install (AUR / .deb / .rpm) | leave; surface pkg-manager hint |
//!
//! Artifacts under `/usr/lib/` and `/lib/` are owned by the system package
//! manager — we **never** `rm` files behind its back (that desyncs its file
//! database). Instead the migration emits an advisory pointing at the right
//! uninstall command, sniffed from `/etc/os-release` (`pacman -R neon-drm`
//! on Arch, `dpkg -r neon-drm` on Debian, etc.).
//!
//! Merged-usr layouts (Arch, Fedora 27+, where `/lib -> /usr/lib`) are
//! deduplicated by canonical path so each on-disk unit is reported once.
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
    /// `true` when the artifact is owned by the system package manager
    /// (e.g. an AUR-installed unit under `/usr/lib/systemd/system/`).
    /// Such artifacts are NOT removed directly — `rm`-ing files behind
    /// the package manager's back desyncs its file database. Instead,
    /// removal surfaces an advisory pointing the user at the correct
    /// uninstall command.
    pub package_managed: bool,
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
    /// `/usr/lib/neon/` — Linux packaged install (AUR / .deb / .rpm).
    /// Reported with a pkg-manager-aware uninstall hint; never `rm`'d
    /// directly. Variant name kept for back-compat with stable log
    /// strings.
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
    /// Host package manager (sniffed from `/etc/os-release`). Drives
    /// the uninstall hint we surface for package-managed artifacts.
    pub package_manager: PackageManager,
}

/// Linux package manager family, detected from `/etc/os-release`.
///
/// Used to format the uninstall hint for package-managed legacy
/// artifacts (e.g. AUR's `pacman -R neon-drm` vs Debian's `dpkg -r
/// neon-drm`). `Unknown` is the safe fallback — emits a generic hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PackageManager {
    /// Arch family — `pacman` (AUR users typically wrap with `paru` / `yay`).
    Pacman,
    /// Debian family — `dpkg` / `apt`.
    Dpkg,
    /// RHEL / Fedora / SUSE family — `rpm` / `dnf`.
    Rpm,
    /// Couldn't sniff. Emits a generic uninstall hint.
    #[default]
    Unknown,
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
            package_managed: false,
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
                package_managed: false,
            });
        }
    }

    // Linux: systemd units. Probe every directory systemd loads from:
    //   /etc/systemd/system/   ← raw `install.sh` writes here.
    //   /usr/lib/systemd/system/ ← Arch (AUR) and Fedora/RPM packages.
    //   /lib/systemd/system/   ← Debian / pre-merged-usr Ubuntu.
    // Units under /usr/lib and /lib are package-managed; we defer
    // removal to the system package manager rather than rm-ing files
    // behind its back.
    //
    // Dedup via canonicalized paths so merged-usr distros (Arch,
    // Fedora 27+) where `/lib -> /usr/lib` don't report each unit
    // twice. `/etc/` is probed first so its (non-package-managed)
    // result wins for any file shared across locations.
    let mut seen_units: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for (dir, package_managed) in [
        ("etc/systemd/system", false),
        ("usr/lib/systemd/system", true),
        ("lib/systemd/system", true),
    ] {
        for (unit_name, kind) in [
            ("neon-fix-drm.path", LegacyKind::LinuxSystemdPath),
            ("neon-fix-drm.service", LegacyKind::LinuxSystemdService),
        ] {
            let p = roots.system_root.join(dir).join(unit_name);
            if !p.exists() {
                continue;
            }
            let canonical = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
            if !seen_units.insert(canonical) {
                continue; // Already detected via another path (merged-usr symlink).
            }
            artifacts.push(LegacyArtifact {
                kind,
                path: p,
                needs_root: true,
                package_managed,
            });
        }
    }

    // Linux: autostart + WidevineCdm cache (user)
    if let Some(home) = &roots.home {
        let autostart = home.join(".config/autostart/neon.desktop");
        if autostart.exists() {
            artifacts.push(LegacyArtifact {
                kind: LegacyKind::LinuxAutostart,
                path: autostart,
                needs_root: false,
                package_managed: false,
            });
        }
        let legacy_cdm = home.join(".local/share/WidevineCdm");
        if legacy_cdm.exists() {
            artifacts.push(LegacyArtifact {
                kind: LegacyKind::LinuxLegacyCdmCache,
                path: legacy_cdm,
                needs_root: false,
                package_managed: false,
            });
        }
    }

    // Linux: packaged install dir (root, never removed directly).
    let deb_install = roots.system_root.join("usr/lib/neon");
    if deb_install.exists() {
        artifacts.push(LegacyArtifact {
            kind: LegacyKind::LinuxDebPackage,
            path: deb_install,
            needs_root: true,
            package_managed: true,
        });
    }

    LegacyInstall {
        artifacts,
        package_manager: detect_package_manager_in(roots),
    }
}

/// Sniff the host's package manager from `/etc/os-release`.
///
/// Reads `ID` and `ID_LIKE`, lower-cases everything, then matches
/// against well-known distro families. Unknown distros fall through
/// to [`PackageManager::Unknown`], which renders a generic hint.
#[must_use]
pub fn detect_package_manager_in(roots: &FsRoots) -> PackageManager {
    let os_release = roots.system_root.join("etc/os-release");
    let Ok(contents) = std::fs::read_to_string(&os_release) else {
        return PackageManager::Unknown;
    };
    let mut tokens: Vec<String> = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        for prefix in ["ID=", "ID_LIKE="] {
            if let Some(rest) = line.strip_prefix(prefix) {
                let rest = rest.trim().trim_matches('"');
                for tok in rest.split_whitespace() {
                    tokens.push(tok.to_ascii_lowercase());
                }
            }
        }
    }
    let has = |needles: &[&str]| tokens.iter().any(|t| needles.contains(&t.as_str()));
    if has(&[
        "arch",
        "archlinux",
        "manjaro",
        "endeavouros",
        "cachyos",
        "garuda",
        "artix",
    ]) {
        PackageManager::Pacman
    } else if has(&["debian", "ubuntu", "linuxmint", "mint", "pop", "elementary"]) {
        PackageManager::Dpkg
    } else if has(&[
        "fedora",
        "rhel",
        "centos",
        "rocky",
        "almalinux",
        "opensuse",
        "suse",
        "sles",
    ]) {
        PackageManager::Rpm
    } else {
        PackageManager::Unknown
    }
}

/// Render a one-shot migration summary to `out`.
///
/// Always emits `Migration: removed=X migrated=Y skipped=Z`. When the
/// outcome has any skipped artifacts, also emits one indented line per
/// unique skip reason so the user sees the actionable uninstall hint
/// without scrolling through one repetition per affected path.
///
/// # Errors
///
/// Propagates IO errors from the underlying writer.
pub fn write_migration_summary(
    out: &mut dyn std::io::Write,
    outcome: &MigrationOutcome,
) -> std::io::Result<()> {
    writeln!(
        out,
        "Migration: removed={} migrated={} skipped={}",
        outcome.removed.len(),
        outcome.migrated.len(),
        outcome.skipped.len()
    )?;
    let mut seen_reasons: Vec<&str> = Vec::new();
    for skip in &outcome.skipped {
        if !seen_reasons.contains(&skip.reason.as_str()) {
            seen_reasons.push(skip.reason.as_str());
            writeln!(out, "  → {}", skip.reason)?;
        }
    }
    Ok(())
}

/// Format the uninstall hint surfaced for a package-managed legacy
/// artifact (e.g. AUR-installed systemd units, `/usr/lib/neon/`).
///
/// `pkg` is the source package name on the host (currently always
/// `"neon-drm"`, but kept as a parameter so test cases can exercise
/// the formatter directly).
#[must_use]
pub fn legacy_package_uninstall_hint(pm: PackageManager, pkg: &str) -> String {
    match pm {
        PackageManager::Pacman => format!(
            "packaged install — run `pacman -R {pkg}` (or `paru -R {pkg}` / `yay -R {pkg}` for AUR) to remove cleanly"
        ),
        PackageManager::Dpkg => {
            format!(".deb package — run `dpkg -r {pkg}` (or `apt remove {pkg}`) to remove")
        }
        PackageManager::Rpm => {
            format!("packaged install — run `rpm -e {pkg}` (or `dnf remove {pkg}`) to remove")
        }
        PackageManager::Unknown => format!(
            "packaged install — use your system package manager to remove `{pkg}`"
        ),
    }
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
    remove_legacy_with_elevator(install, cdm_destination, &platform::run_as_root_script)
}

/// Same as [`remove_legacy_with`] but with the elevator function
/// injected so tests can simulate user-cancelled sudo / pkexec dialogs.
/// Pass 1's batched-script failure routes the corresponding paths to
/// [`MigrationOutcome::skipped`] with the error reason — they are
/// **not** falsely reported in [`MigrationOutcome::removed`].
///
/// # Errors
///
/// See [`remove_legacy`]. The elevator's error is not propagated as a
/// hard error because Pass 2 (user-level ops) still has useful work to
/// do; instead the elevated artifacts are reported as skipped.
pub fn remove_legacy_with_elevator<E>(
    install: LegacyInstall,
    cdm_destination: &Path,
    elevator: &E,
) -> Result<MigrationOutcome>
where
    E: Fn(&str) -> Result<std::process::Output>,
{
    let mut outcome = MigrationOutcome::default();
    let pkg_hint = legacy_package_uninstall_hint(install.package_manager, "neon-drm");

    // Pass 1: batch every elevation-required operation into a single
    // shell script, then run that script under one elevation prompt.
    // Turns N sudo/pkexec prompts into exactly one regardless of how
    // many legacy artifacts are present.
    //
    // Failure of any individual sub-command inside the script is
    // tolerated (`|| true`) — best-effort cleanup that mirrors the
    // previous per-call behavior. Surfaced errors come from the
    // elevation itself, not the cleanup ops.
    //
    // Package-managed artifacts are *not* removed in this pass — we
    // skip them with a pkg-manager-aware advisory so the user can
    // uninstall cleanly via their distro's tooling.
    //
    // We collect the paths Pass 1 *would* remove into a pending vec
    // and only promote them to `outcome.removed` after the elevator
    // returns success. If the elevator fails (e.g. user dismisses the
    // sudo prompt), the paths are routed to `outcome.skipped` with the
    // error reason so the caller can surface accurate state instead of
    // falsely claiming the artifacts were removed.
    let mut root_script: Vec<String> = Vec::new();
    let mut pending_removed: Vec<PathBuf> = Vec::new();
    let mut needs_systemd_reload = false;
    for art in &install.artifacts {
        if art.package_managed {
            outcome.skipped.push(SkipReason {
                path: art.path.clone(),
                reason: pkg_hint.clone(),
            });
            continue;
        }
        match art.kind {
            LegacyKind::MacLaunchDaemon => {
                let p = sh_quote(&art.path)?;
                root_script.push(format!(
                    "launchctl unload -w {p} 2>/dev/null || true; rm -f {p}"
                ));
                pending_removed.push(art.path.clone());
            }
            LegacyKind::LinuxSystemdPath => {
                let p = sh_quote(&art.path)?;
                root_script.push(format!(
                    "systemctl disable --now neon-fix-drm.path 2>/dev/null || true; rm -f {p}"
                ));
                pending_removed.push(art.path.clone());
                needs_systemd_reload = true;
            }
            LegacyKind::LinuxSystemdService => {
                let p = sh_quote(&art.path)?;
                root_script.push(format!(
                    "systemctl disable --now neon-fix-drm.service 2>/dev/null || true; rm -f {p}"
                ));
                pending_removed.push(art.path.clone());
                needs_systemd_reload = true;
            }
            // Non-elevated kinds handled in Pass 2.
            _ => {}
        }
    }
    if needs_systemd_reload {
        root_script.push("systemctl daemon-reload 2>/dev/null || true".into());
    }
    if !root_script.is_empty() {
        let script = root_script.join("\n");
        match elevator(&script) {
            Ok(_) => outcome.removed.extend(pending_removed),
            Err(e) => {
                let reason = format!("elevated cleanup failed: {e}");
                for path in pending_removed {
                    outcome.skipped.push(SkipReason {
                        path,
                        reason: reason.clone(),
                    });
                }
            }
        }
    }

    // Pass 2: user-level operations (no elevation).
    for art in install.artifacts {
        if art.package_managed {
            continue; // Already handled in Pass 1 (skip + advisory).
        }
        match art.kind {
            LegacyKind::MacLaunchDaemon
            | LegacyKind::LinuxSystemdPath
            | LegacyKind::LinuxSystemdService => {
                // Already handled in Pass 1.
            }
            LegacyKind::MacLaunchAgent => {
                unload_and_remove_user(&art.path, &mut outcome)?;
            }
            LegacyKind::LinuxAutostart => {
                remove_user_path(&art.path, &mut outcome)?;
            }
            LegacyKind::LinuxLegacyCdmCache => {
                migrate_legacy_cdm(&art.path, cdm_destination, &mut outcome)?;
            }
            LegacyKind::LinuxDebPackage => {
                // /usr/lib/neon/ is always package-managed; the
                // `package_managed` short-circuit above handles it.
                // Falling through here would indicate a logic bug.
                debug_assert!(false, "LinuxDebPackage should be package_managed");
            }
        }
    }
    Ok(outcome)
}

/// POSIX-shell-quote a path for safe inclusion in a shell command.
///
/// Wraps in single quotes and escapes any embedded single quotes via
/// the standard `'\''` sequence. Returns an error if the path is not
/// valid UTF-8.
fn sh_quote(path: &Path) -> Result<String> {
    let s = path
        .to_str()
        .ok_or_else(|| Error::other(format!("path not UTF-8: {}", path.display())))?;
    let escaped = s.replace('\'', "'\\''");
    Ok(format!("'{escaped}'"))
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

    /// When the elevator fails (e.g. user cancels the sudo prompt),
    /// elevated artifacts must land in `outcome.skipped` with a reason
    /// — NOT in `outcome.removed` (which would falsely tell the user
    /// the artifact had been cleaned up when it's still on disk).
    #[test]
    fn elevator_failure_routes_paths_to_skipped_not_removed() {
        let tmp = TempDir::new().unwrap();
        let roots = synthesize_full_legacy(tmp.path());
        let install = detect_legacy_install_in(&roots);
        let cdm_dest = tmp.path().join("v2-cache").join("widevine").join("legacy");
        // Elevator always fails — simulates the user dismissing the
        // sudo / pkexec / osascript prompt.
        let elevator = |_script: &str| -> Result<std::process::Output> {
            Err(crate::error::Error::permission_denied(
                "user cancelled the prompt",
            ))
        };
        let outcome =
            remove_legacy_with_elevator(install, &cdm_dest, &elevator).expect("returns Ok");

        // The elevated-only artifacts must NOT appear in `removed`.
        assert!(
            !outcome
                .removed
                .iter()
                .any(|p| p.ends_with("Library/LaunchDaemons/com.neon.fix-drm.plist")),
            "LaunchDaemon must not be reported as removed when elevator failed; \
             removed={:?}",
            outcome.removed
        );
        // They must appear in `skipped` with a reason that explains why.
        let skipped_daemon = outcome.skipped.iter().find(|s| {
            s.path
                .ends_with("Library/LaunchDaemons/com.neon.fix-drm.plist")
        });
        assert!(
            skipped_daemon.is_some(),
            "LaunchDaemon must be in skipped; got skipped={:?}",
            outcome.skipped
        );
        assert!(
            skipped_daemon
                .unwrap()
                .reason
                .contains("elevated cleanup failed"),
            "skipped reason should mention the elevation failure; got {}",
            skipped_daemon.unwrap().reason
        );
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

    /// `detect_legacy_install()` (public host-tied entry) must not panic
    /// regardless of host state. On a dev machine with no legacy install,
    /// it returns an empty list; on a machine with legacy artifacts, it
    /// returns whatever's there. Either way: no panic.
    #[test]
    fn detect_legacy_install_does_not_panic() {
        let _ = detect_legacy_install();
    }

    /// `remove_legacy(empty)` succeeds with no work. Useful sanity check
    /// for callers that always run migration regardless of detection.
    #[test]
    fn remove_legacy_empty_install_is_noop() {
        let outcome = remove_legacy(LegacyInstall::default()).expect("ok");
        assert!(outcome.removed.is_empty());
        assert!(outcome.migrated.is_empty());
        assert!(outcome.skipped.is_empty());
    }

    /// `migrate_legacy_cdm` returns an error when `rename` fails (here,
    /// because the source doesn't exist).
    #[test]
    fn migrate_legacy_cdm_errors_when_source_missing() {
        let tmp = TempDir::new().unwrap();
        let legacy = tmp.path().join("not-here");
        let dest = tmp.path().join("dest/widevine");
        let mut out = MigrationOutcome::default();
        let r = migrate_legacy_cdm(&legacy, &dest, &mut out);
        assert!(r.is_err());
    }

    /// `unload_and_remove_user` removes a plist successfully even when
    /// `launchctl` isn't available (common on Linux CI runners).
    #[test]
    fn unload_and_remove_user_removes_plist() {
        let tmp = TempDir::new().unwrap();
        let plist = tmp.path().join("com.example.plist");
        fs::write(&plist, b"<plist></plist>").unwrap();
        let mut out = MigrationOutcome::default();
        unload_and_remove_user(&plist, &mut out).expect("ok");
        assert!(!plist.exists());
        assert_eq!(out.removed.len(), 1);
    }

    // --- Packaged-install detection (AUR / RPM systemd units in /usr/lib) ---

    #[test]
    fn detect_finds_systemd_units_in_usr_lib_systemd() {
        let tmp = TempDir::new().unwrap();
        let system_root = tmp.path().to_path_buf();
        fs::create_dir_all(system_root.join("usr/lib/systemd/system")).unwrap();
        fs::write(
            system_root.join("usr/lib/systemd/system/neon-fix-drm.path"),
            b"[Path]\n",
        )
        .unwrap();
        fs::write(
            system_root.join("usr/lib/systemd/system/neon-fix-drm.service"),
            b"[Service]\n",
        )
        .unwrap();
        let roots = FsRoots {
            system_root,
            home: None,
        };
        let install = detect_legacy_install_in(&roots);
        let kinds: Vec<LegacyKind> = install.artifacts.iter().map(|a| a.kind).collect();
        assert!(kinds.contains(&LegacyKind::LinuxSystemdPath), "{kinds:?}");
        assert!(
            kinds.contains(&LegacyKind::LinuxSystemdService),
            "{kinds:?}"
        );
        // Units under /usr/lib are package-managed — removal must defer
        // to the package manager rather than `rm`.
        for art in &install.artifacts {
            if matches!(
                art.kind,
                LegacyKind::LinuxSystemdPath | LegacyKind::LinuxSystemdService
            ) {
                assert!(
                    art.package_managed,
                    "{:?} at {} should be flagged package_managed",
                    art.kind,
                    art.path.display()
                );
            }
        }
    }

    #[test]
    fn detect_finds_systemd_units_in_lib_systemd() {
        let tmp = TempDir::new().unwrap();
        let system_root = tmp.path().to_path_buf();
        fs::create_dir_all(system_root.join("lib/systemd/system")).unwrap();
        fs::write(
            system_root.join("lib/systemd/system/neon-fix-drm.path"),
            b"[Path]\n",
        )
        .unwrap();
        let roots = FsRoots {
            system_root,
            home: None,
        };
        let install = detect_legacy_install_in(&roots);
        let kinds: Vec<LegacyKind> = install.artifacts.iter().map(|a| a.kind).collect();
        assert!(kinds.contains(&LegacyKind::LinuxSystemdPath), "{kinds:?}");
    }

    #[test]
    fn migration_summary_renders_counts_only_when_clean() {
        let outcome = MigrationOutcome::default();
        let mut buf = Vec::new();
        write_migration_summary(&mut buf, &outcome).expect("write ok");
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("removed=0 migrated=0 skipped=0"), "got: {s}");
        assert!(
            !s.contains("→"),
            "no skip-hint arrow without skips, got: {s}"
        );
    }

    #[test]
    fn migration_summary_dedupes_repeated_skip_reasons() {
        // Realistic AUR case: three paths skipped, all under the same
        // pacman uninstall hint. The summary should show the hint once,
        // not three times.
        let reason = "packaged install — run `pacman -R neon-drm` to remove";
        let outcome = MigrationOutcome {
            removed: vec![],
            migrated: vec![],
            skipped: vec![
                SkipReason {
                    path: PathBuf::from("/usr/lib/systemd/system/neon-fix-drm.path"),
                    reason: reason.into(),
                },
                SkipReason {
                    path: PathBuf::from("/usr/lib/systemd/system/neon-fix-drm.service"),
                    reason: reason.into(),
                },
                SkipReason {
                    path: PathBuf::from("/usr/lib/neon"),
                    reason: reason.into(),
                },
            ],
        };
        let mut buf = Vec::new();
        write_migration_summary(&mut buf, &outcome).expect("write ok");
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("skipped=3"), "got: {s}");
        assert_eq!(
            s.matches("pacman -R neon-drm").count(),
            1,
            "skip hint should be deduplicated, got: {s}"
        );
    }

    #[test]
    fn migration_summary_lists_distinct_skip_reasons() {
        let outcome = MigrationOutcome {
            removed: vec![],
            migrated: vec![],
            skipped: vec![
                SkipReason {
                    path: PathBuf::from("/a"),
                    reason: "reason A".into(),
                },
                SkipReason {
                    path: PathBuf::from("/b"),
                    reason: "reason B".into(),
                },
            ],
        };
        let mut buf = Vec::new();
        write_migration_summary(&mut buf, &outcome).expect("write ok");
        let s = std::str::from_utf8(&buf).unwrap();
        assert!(s.contains("reason A"), "got: {s}");
        assert!(s.contains("reason B"), "got: {s}");
    }

    #[cfg(unix)]
    #[test]
    fn detect_dedupes_units_under_merged_usr_symlink() {
        // Reproduce the Arch / Fedora "merged usr" layout where `/lib`
        // is a symlink to `/usr/lib`. Both
        //   <root>/usr/lib/systemd/system/neon-fix-drm.path
        //   <root>/lib/systemd/system/neon-fix-drm.path
        // resolve to the same file. The detector must report it once.
        let tmp = TempDir::new().unwrap();
        let system_root = tmp.path().to_path_buf();
        fs::create_dir_all(system_root.join("usr/lib/systemd/system")).unwrap();
        fs::write(
            system_root.join("usr/lib/systemd/system/neon-fix-drm.path"),
            b"[Path]\n",
        )
        .unwrap();
        fs::write(
            system_root.join("usr/lib/systemd/system/neon-fix-drm.service"),
            b"[Service]\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(system_root.join("usr/lib"), system_root.join("lib")).unwrap();

        let roots = FsRoots {
            system_root,
            home: None,
        };
        let install = detect_legacy_install_in(&roots);
        let path_count = install
            .artifacts
            .iter()
            .filter(|a| a.kind == LegacyKind::LinuxSystemdPath)
            .count();
        let service_count = install
            .artifacts
            .iter()
            .filter(|a| a.kind == LegacyKind::LinuxSystemdService)
            .count();
        assert_eq!(path_count, 1, "merged-usr should yield one path unit");
        assert_eq!(service_count, 1, "merged-usr should yield one service unit");
    }

    #[test]
    fn etc_systemd_units_are_not_package_managed() {
        let tmp = TempDir::new().unwrap();
        let roots = synthesize_full_legacy(tmp.path());
        let install = detect_legacy_install_in(&roots);
        for art in &install.artifacts {
            if matches!(
                art.kind,
                LegacyKind::LinuxSystemdPath | LegacyKind::LinuxSystemdService
            ) {
                assert!(
                    !art.package_managed,
                    "/etc/-housed unit at {} must not be package_managed",
                    art.path.display()
                );
            }
        }
    }

    // --- /etc/os-release -> PackageManager detection ---

    fn write_os_release(system_root: &Path, body: &[u8]) {
        fs::create_dir_all(system_root.join("etc")).unwrap();
        fs::write(system_root.join("etc/os-release"), body).unwrap();
    }

    #[test]
    fn detect_package_manager_pacman_from_id() {
        let tmp = TempDir::new().unwrap();
        write_os_release(tmp.path(), b"ID=arch\n");
        let roots = FsRoots {
            system_root: tmp.path().to_path_buf(),
            home: None,
        };
        assert_eq!(detect_package_manager_in(&roots), PackageManager::Pacman);
    }

    #[test]
    fn detect_package_manager_pacman_via_id_like() {
        let tmp = TempDir::new().unwrap();
        write_os_release(tmp.path(), b"ID=cachyos\nID_LIKE=arch\n");
        let roots = FsRoots {
            system_root: tmp.path().to_path_buf(),
            home: None,
        };
        assert_eq!(detect_package_manager_in(&roots), PackageManager::Pacman);
    }

    #[test]
    fn detect_package_manager_dpkg_from_id_like() {
        let tmp = TempDir::new().unwrap();
        write_os_release(tmp.path(), b"ID=ubuntu\nID_LIKE=debian\n");
        let roots = FsRoots {
            system_root: tmp.path().to_path_buf(),
            home: None,
        };
        assert_eq!(detect_package_manager_in(&roots), PackageManager::Dpkg);
    }

    #[test]
    fn detect_package_manager_rpm_from_id() {
        let tmp = TempDir::new().unwrap();
        write_os_release(tmp.path(), b"ID=fedora\n");
        let roots = FsRoots {
            system_root: tmp.path().to_path_buf(),
            home: None,
        };
        assert_eq!(detect_package_manager_in(&roots), PackageManager::Rpm);
    }

    #[test]
    fn detect_package_manager_unknown_without_os_release() {
        let tmp = TempDir::new().unwrap();
        let roots = FsRoots {
            system_root: tmp.path().to_path_buf(),
            home: None,
        };
        assert_eq!(detect_package_manager_in(&roots), PackageManager::Unknown);
    }

    #[test]
    fn detect_package_manager_handles_quoted_values() {
        let tmp = TempDir::new().unwrap();
        write_os_release(tmp.path(), b"ID=\"arch\"\nID_LIKE=\"\"\n");
        let roots = FsRoots {
            system_root: tmp.path().to_path_buf(),
            home: None,
        };
        assert_eq!(detect_package_manager_in(&roots), PackageManager::Pacman);
    }

    // --- Uninstall-hint formatting per package manager ---

    #[test]
    fn uninstall_hint_pacman_mentions_pacman() {
        let h = legacy_package_uninstall_hint(PackageManager::Pacman, "neon-drm");
        assert!(h.contains("pacman -R neon-drm"), "got: {h}");
    }

    #[test]
    fn uninstall_hint_dpkg_mentions_dpkg() {
        let h = legacy_package_uninstall_hint(PackageManager::Dpkg, "neon-drm");
        assert!(h.contains("dpkg -r neon-drm"), "got: {h}");
    }

    #[test]
    fn uninstall_hint_rpm_mentions_rpm_or_dnf() {
        let h = legacy_package_uninstall_hint(PackageManager::Rpm, "neon-drm");
        assert!(
            h.contains("rpm -e neon-drm") || h.contains("dnf remove neon-drm"),
            "got: {h}"
        );
    }

    #[test]
    fn uninstall_hint_unknown_is_generic() {
        let h = legacy_package_uninstall_hint(PackageManager::Unknown, "neon-drm");
        assert!(
            h.to_lowercase().contains("package manager"),
            "expected a generic 'package manager' hint, got: {h}"
        );
    }

    // --- Integration: packaged systemd units must be skipped, not removed ---

    #[test]
    fn remove_legacy_skips_package_managed_units_with_pacman_hint() {
        let tmp = TempDir::new().unwrap();
        let system_root = tmp.path().join("system");
        fs::create_dir_all(system_root.join("usr/lib/systemd/system")).unwrap();
        fs::create_dir_all(system_root.join("usr/lib/neon")).unwrap();
        fs::write(
            system_root.join("usr/lib/systemd/system/neon-fix-drm.path"),
            b"[Path]\n",
        )
        .unwrap();
        fs::write(
            system_root.join("usr/lib/systemd/system/neon-fix-drm.service"),
            b"[Service]\n",
        )
        .unwrap();
        write_os_release(&system_root, b"ID=arch\n");
        let roots = FsRoots {
            system_root,
            home: None,
        };

        unsafe { std::env::set_var("NEON_TEST_ESCALATE_NOOP", "1") };
        let install = detect_legacy_install_in(&roots);
        assert_eq!(install.package_manager, PackageManager::Pacman);
        let cdm_dest = tmp.path().join("v2-cache/widevine/legacy");
        let outcome = remove_legacy_with(install, &cdm_dest).expect("ok");
        unsafe { std::env::remove_var("NEON_TEST_ESCALATE_NOOP") };

        // Units under /usr/lib are reported as skipped with a pacman hint.
        let unit_skips: Vec<&SkipReason> = outcome
            .skipped
            .iter()
            .filter(|s| {
                s.path.ends_with("neon-fix-drm.path") || s.path.ends_with("neon-fix-drm.service")
            })
            .collect();
        assert_eq!(unit_skips.len(), 2, "skipped={:?}", outcome.skipped);
        for u in &unit_skips {
            assert!(u.reason.contains("pacman -R neon-drm"), "got: {}", u.reason);
        }
        // /usr/lib/neon/ also gets the pacman-flavored hint.
        let pkg_skip = outcome
            .skipped
            .iter()
            .find(|s| s.path.ends_with("usr/lib/neon"))
            .expect("usr/lib/neon entry");
        assert!(
            pkg_skip.reason.contains("pacman -R neon-drm"),
            "got: {}",
            pkg_skip.reason
        );
        // Packaged units must NOT be in `removed` (we deferred to pacman).
        for p in &outcome.removed {
            assert!(
                !p.starts_with(roots.system_root.join("usr/lib")),
                "packaged unit {} should not be in removed",
                p.display()
            );
        }
    }
}
