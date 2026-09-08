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
//! | `~/.local/share/WidevineCdm/` | Legacy CDM cache | migrate to `~/.cache/silvervine/widevine/<version>/` |
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
//! `SILVERVINE_TEST_ESCALATE_NOOP=1` env var that `crate::platform` honors.
//!
//! ## What this module does NOT do
//!
//! * No backup of removed artifacts. The legacy install is by definition
//!   broken/being replaced; preserving plists or service files would just
//!   confuse later runs of `silvervine doctor`.
//! * No state-file migration beyond the `WidevineCdm` cache move. Legacy
//!   never had a stable state file.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::platform;

/// Filesystem locations used to migrate data from the Neon V2 layout.
///
/// Tests inject temporary paths; production uses [`DataMigrationPaths::host`].
#[derive(Debug, Clone)]
pub struct DataMigrationPaths {
    /// Legacy and current config directories.
    pub config: (PathBuf, PathBuf),
    /// Legacy and current cache directories. The cache contains CLI/daemon logs.
    pub cache: (PathBuf, PathBuf),
    /// Optional separate tray-log directories (used on macOS).
    pub logs: Option<(PathBuf, PathBuf)>,
}

impl DataMigrationPaths {
    /// Resolve the host's Neon and Silvervine V2 data directories.
    #[must_use]
    pub fn host() -> Self {
        let current_config = platform::config_dir();
        let current_cache = platform::cache_dir();
        let legacy_config = sibling_named(&current_config, "neon");
        let legacy_cache = sibling_named(&current_cache, "neon");
        #[cfg(target_os = "macos")]
        let logs = dirs::home_dir().map(|home| {
            let base = home.join("Library").join("Logs");
            (base.join("neon"), base.join("silvervine"))
        });
        #[cfg(not(target_os = "macos"))]
        let logs = None;
        Self {
            config: (legacy_config, current_config),
            cache: (legacy_cache, current_cache),
            logs,
        }
    }
}

fn sibling_named(path: &Path, name: &str) -> PathBuf {
    path.parent()
        .map_or_else(|| PathBuf::from(name), |parent| parent.join(name))
}

/// Result of attempting one Neon V2 data-directory migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataMigrationEntry {
    /// Kind of data represented by this directory.
    pub kind: &'static str,
    /// Legacy Neon source.
    pub from: PathBuf,
    /// Silvervine destination.
    pub to: PathBuf,
    /// Observable result; conflicts and errors never overwrite either path.
    pub status: DataMigrationStatus,
}

/// Status for one V2 data-directory migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataMigrationStatus {
    /// The source was atomically renamed to the destination.
    Migrated,
    /// No source existed; repeated runs are harmless.
    MissingSource,
    /// Both paths existed, so both were preserved.
    Conflict,
    /// Migration could not proceed; the source was left in place.
    Error(String),
}

/// Migrate host Neon V2 data directories to Silvervine locations.
#[must_use]
pub fn migrate_v2_data() -> Vec<DataMigrationEntry> {
    if std::env::var_os("SILVERVINE_TEST_DATA_MIGRATION_NOOP").is_some() {
        return Vec::new();
    }
    migrate_v2_data_with(&DataMigrationPaths::host())
}

/// Serialize and transactionally coordinate Neon V2 daemon/data transition.
/// The lock lives beside (not inside) the renameable config directories, so
/// its inode remains stable for the entire first-launch transaction.
///
/// # Errors
///
/// Returns an error when preflight, daemon transition, a directory move,
/// rollback, or replacement registration fails.
pub fn migrate_v2_startup() -> Result<Vec<DataMigrationEntry>> {
    if std::env::var_os("SILVERVINE_TEST_DATA_MIGRATION_NOOP").is_some() {
        return Ok(Vec::new());
    }
    let paths = DataMigrationPaths::host();
    let lock = migration_lock_path(&paths);
    crate::lockfile::with_lock(&lock, || {
        startup_transaction(&paths, &mut HostLegacyLifecycle)
    })
}

fn migration_lock_path(paths: &DataMigrationPaths) -> PathBuf {
    paths
        .config
        .0
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".silvervine-v2-migration.lock")
}

trait LegacyLifecycle {
    fn is_registered(&mut self) -> Result<bool>;
    fn silvervine_is_registered(&mut self) -> Result<bool>;
    /// Stop Neon and return whether it was running before the stop.
    fn stop(&mut self) -> Result<bool>;
    /// Restore Neon only when it was running before the transaction.
    fn restore(&mut self, was_running: bool) -> Result<()>;
    fn register_silvervine(&mut self) -> Result<()>;
    fn unregister_silvervine(&mut self) -> Result<()>;
    fn remove_registration(&mut self) -> Result<()>;
}

struct HostLegacyLifecycle;

impl LegacyLifecycle for HostLegacyLifecycle {
    fn is_registered(&mut self) -> Result<bool> {
        crate::daemon::lifecycle::legacy_is_registered()
    }
    fn silvervine_is_registered(&mut self) -> Result<bool> {
        crate::daemon::lifecycle::registration_exists()
    }
    fn stop(&mut self) -> Result<bool> {
        crate::daemon::lifecycle::stop_legacy()
    }
    fn restore(&mut self, was_running: bool) -> Result<()> {
        crate::daemon::lifecycle::restore_legacy(was_running)
    }
    fn register_silvervine(&mut self) -> Result<()> {
        crate::daemon::lifecycle::register()
    }
    fn unregister_silvervine(&mut self) -> Result<()> {
        crate::daemon::lifecycle::unregister_for_rollback()
    }
    fn remove_registration(&mut self) -> Result<()> {
        crate::daemon::lifecycle::remove_legacy_registration()
    }
}

fn startup_transaction(
    paths: &DataMigrationPaths,
    lifecycle: &mut dyn LegacyLifecycle,
) -> Result<Vec<DataMigrationEntry>> {
    startup_transaction_with(paths, lifecycle, &mut no_replace_rename)
}

fn startup_transaction_with(
    paths: &DataMigrationPaths,
    lifecycle: &mut dyn LegacyLifecycle,
    promote: &mut dyn FnMut(&Path, &Path) -> std::io::Result<()>,
) -> Result<Vec<DataMigrationEntry>> {
    let pairs = migration_pairs(paths);
    preflight_pairs(&pairs)?;
    let had_registration = lifecycle.is_registered()?;
    if had_registration && lifecycle.silvervine_is_registered()? {
        return Err(Error::other(
            "both Neon and Silvervine daemon registrations exist; refusing an ambiguous migration",
        ));
    }
    let was_running = if had_registration {
        lifecycle.stop()?
    } else {
        false
    };

    let mut moved = Vec::new();
    let data_transaction = (|| {
        refuse_connectable_legacy_socket(paths)?;
        let mut entries = Vec::new();
        for (kind, from, to) in &pairs {
            let entry = migrate_data_directory(kind, from, to, promote);
            match &entry.status {
                DataMigrationStatus::Migrated => moved.push((from.clone(), to.clone())),
                DataMigrationStatus::Error(message) => {
                    return Err(Error::other(format!(
                        "could not migrate Neon {kind} data from {}: {message}",
                        from.display()
                    )));
                }
                _ => {}
            }
            entries.push(entry);
        }
        Ok(entries)
    })();

    let entries = match data_transaction {
        Ok(entries) => entries,
        Err(error) => {
            return Err(rollback_data_and_restore_legacy(
                error,
                &moved,
                lifecycle,
                had_registration,
                was_running,
            ));
        }
    };

    if had_registration {
        if let Err(error) = lifecycle.register_silvervine() {
            // Even registration's internal rollback can itself fail. An
            // idempotent unregister is the final safety barrier before
            // moving data back underneath Neon.
            if let Err(unregister) = lifecycle.unregister_silvervine() {
                return Err(with_rollback_failure(
                    error,
                    "unregister Silvervine after registration failure",
                    &unregister,
                ));
            }
            return Err(rollback_data_and_restore_legacy(
                error,
                &moved,
                lifecycle,
                true,
                was_running,
            ));
        }
        if let Err(error) = lifecycle.remove_registration() {
            // The new daemon must be stopped and unregistered before its data
            // paths can safely move back underneath Neon.
            if let Err(unregister) = lifecycle.unregister_silvervine() {
                return Err(with_rollback_failure(
                    error,
                    "unregister Silvervine",
                    &unregister,
                ));
            }
            return Err(rollback_data_and_restore_legacy(
                error,
                &moved,
                lifecycle,
                true,
                was_running,
            ));
        }
    }
    Ok(entries)
}

fn rollback_data_and_restore_legacy(
    error: Error,
    moved: &[(PathBuf, PathBuf)],
    lifecycle: &mut dyn LegacyLifecycle,
    had_registration: bool,
    was_running: bool,
) -> Error {
    if let Err(rollback) = rollback_moves(moved) {
        return with_rollback_failure(error, "restore Neon data", &rollback);
    }
    if had_registration {
        if let Err(restore) = lifecycle.restore(was_running) {
            return with_rollback_failure(error, "restore Neon daemon state", &restore);
        }
    }
    error
}

fn with_rollback_failure(primary: Error, action: &str, rollback: &Error) -> Error {
    let category = primary.category;
    Error::new(
        category,
        format!("{primary}; rollback failed while attempting to {action}: {rollback}"),
    )
    .with_source(primary)
}

fn migration_pairs(paths: &DataMigrationPaths) -> Vec<(&'static str, PathBuf, PathBuf)> {
    let mut pairs = vec![
        ("config", paths.config.0.clone(), paths.config.1.clone()),
        ("cache/log", paths.cache.0.clone(), paths.cache.1.clone()),
    ];
    if let Some((from, to)) = &paths.logs {
        pairs.push(("log", from.clone(), to.clone()));
    }
    pairs
}

fn preflight_pairs(pairs: &[(&'static str, PathBuf, PathBuf)]) -> Result<()> {
    for (kind, from, to) in pairs {
        if from.exists() && !from.is_dir() {
            return Err(Error::other(format!(
                "could not migrate Neon {kind} data from {}: source is not a directory",
                from.display()
            )));
        }
        if to.exists() && !to.is_dir() {
            return Err(Error::other(format!(
                "could not migrate Neon {kind} data to {}: destination is not a directory",
                to.display()
            )));
        }
        if from.is_dir() && !to.exists() {
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent).map_err(Error::from)?;
            }
        }
    }
    Ok(())
}

fn refuse_connectable_legacy_socket(paths: &DataMigrationPaths) -> Result<()> {
    let socket = paths.cache.0.join("daemon.sock");
    #[cfg(unix)]
    if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
        return Err(Error::other(format!(
            "legacy Neon daemon is still reachable at {}; refusing to migrate its cache",
            socket.display()
        )));
    }
    Ok(())
}

fn rollback_moves(moved: &[(PathBuf, PathBuf)]) -> Result<()> {
    for (from, to) in moved.iter().rev() {
        no_replace_rename(to, from).map_err(|error| {
            Error::other(format!(
                "could not roll back data migration {} -> {}: {error}",
                to.display(),
                from.display()
            ))
        })?;
    }
    Ok(())
}

/// Injection-friendly V2 data migration used by startup and tests.
///
/// Promotion uses the host's atomic no-replace rename primitive, so a
/// destination created after inspection is preserved and reported as a
/// [`DataMigrationStatus::Conflict`].
#[must_use]
pub fn migrate_v2_data_with(paths: &DataMigrationPaths) -> Vec<DataMigrationEntry> {
    migrate_v2_data_with_promoter(paths, no_replace_rename)
}

fn migrate_v2_data_with_promoter<F>(
    paths: &DataMigrationPaths,
    mut promote: F,
) -> Vec<DataMigrationEntry>
where
    F: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    let mut pairs = vec![
        ("config", &paths.config.0, &paths.config.1),
        ("cache/log", &paths.cache.0, &paths.cache.1),
    ];
    if let Some((from, to)) = &paths.logs {
        pairs.push(("log", from, to));
    }
    pairs
        .into_iter()
        .map(|(kind, from, to)| migrate_data_directory(kind, from, to, &mut promote))
        .collect()
}

fn migrate_data_directory<F>(
    kind: &'static str,
    from: &Path,
    to: &Path,
    promote: &mut F,
) -> DataMigrationEntry
where
    F: FnMut(&Path, &Path) -> std::io::Result<()> + ?Sized,
{
    let status = if !from.exists() {
        DataMigrationStatus::MissingSource
    } else if to.exists() {
        DataMigrationStatus::Conflict
    } else if !from.is_dir() {
        DataMigrationStatus::Error("source is not a directory".into())
    } else {
        let result = to
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| promote(from, to));
        match result {
            Ok(()) => DataMigrationStatus::Migrated,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                DataMigrationStatus::Conflict
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && !from.exists()
                    && to.is_dir() =>
            {
                DataMigrationStatus::Migrated
            }
            Err(error) => DataMigrationStatus::Error(error.to_string()),
        }
    };
    DataMigrationEntry {
        kind,
        from: from.to_path_buf(),
        to: to.to_path_buf(),
        status,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn no_replace_rename(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in source path"))?;
    let to = CString::new(to.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in destination path")
    })?;

    #[cfg(target_os = "linux")]
    // SAFETY: both C strings remain alive for the call; AT_FDCWD makes both
    // paths relative to the current working directory when not absolute.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: both C strings remain alive for the call. RENAME_EXCL is the
    // Darwin no-replace flag (0x4), not RENAME_SWAP.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn no_replace_rename(_from: &Path, _to: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace rename is only supported on Linux and macOS",
    ))
}

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
/// V2's update flow (`silvervine update widevine`) will replace it with a
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
/// honors `SILVERVINE_TEST_ESCALATE_NOOP=1` so tests don't actually elevate.
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

fn record_elevated_cleanup_postconditions(paths: Vec<PathBuf>, outcome: &mut MigrationOutcome) {
    for path in paths {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                outcome.removed.push(path);
            }
            Ok(_) => outcome.skipped.push(SkipReason {
                path,
                reason: "elevated cleanup left artifact in place".into(),
            }),
            Err(error) => outcome.skipped.push(SkipReason {
                path,
                reason: format!("could not verify elevated cleanup postcondition: {error}"),
            }),
        }
    }
}

fn remove_elevated_legacy<E>(
    install: &LegacyInstall,
    pkg_hint: &str,
    outcome: &mut MigrationOutcome,
    elevator: &E,
) -> Result<()>
where
    E: Fn(&str) -> Result<std::process::Output>,
{
    // Pass 1 batches every elevation-required operation into one script and
    // only records removal after a successful exit and absent-path check.
    let mut root_script: Vec<String> = Vec::new();
    let mut pending_removed: Vec<PathBuf> = Vec::new();
    let mut needs_systemd_reload = false;
    for art in &install.artifacts {
        if art.package_managed {
            outcome.skipped.push(SkipReason {
                path: art.path.clone(),
                reason: pkg_hint.to_owned(),
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
            Ok(output) if output.status.success() => {
                record_elevated_cleanup_postconditions(pending_removed, outcome);
            }
            Ok(output) => {
                let status = platform::format_exit_status(output.status);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let reason = if stderr.trim().is_empty() {
                    format!("elevated cleanup failed: {status}")
                } else {
                    format!("elevated cleanup failed: {status}: {}", stderr.trim())
                };
                for path in pending_removed {
                    outcome.skipped.push(SkipReason {
                        path,
                        reason: reason.clone(),
                    });
                }
            }
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
    Ok(())
}

/// Same as [`remove_legacy_with`] but with the elevator function
/// injected so tests can simulate user-cancelled sudo / pkexec dialogs,
/// nonzero elevator exits, and successful elevation that still leaves
/// artifacts on disk.
///
/// Pass 1 only promotes a path to [`MigrationOutcome::removed`] when the
/// elevator returns a successful exit **and** the path is gone afterward.
/// Cancelled prompts, spawn failures, nonzero elevator status, and
/// postcondition mismatches all route the corresponding paths to
/// [`MigrationOutcome::skipped`] with an actionable reason — they are
/// **not** falsely reported in [`MigrationOutcome::removed`].
///
/// # Errors
///
/// See [`remove_legacy`]. Elevator failures are not propagated as a hard
/// error because Pass 2 (user-level ops) still has useful work to do;
/// instead the elevated artifacts are reported as skipped.
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
    remove_elevated_legacy(&install, &pkg_hint, &mut outcome, elevator)?;

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
        Error::from(e).with_context(format!("could not remove {}", plist.display()))
    })?;
    out.removed.push(plist.to_path_buf());
    Ok(())
}

/// Remove a user-owned file or directory.
fn remove_user_path(path: &Path, out: &mut MigrationOutcome) -> Result<()> {
    remove_path(path)
        .map_err(|e| Error::from(e).with_context(format!("could not remove {}", path.display())))?;
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
            Error::from(e).with_context(format!(
                "could not create parent of {}",
                destination.display()
            ))
        })?;
    }
    if destination.exists() {
        // V2 cache already present — drop the legacy copy.
        remove_path(legacy).map_err(|e| {
            Error::from(e).with_context(format!(
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
        Error::from(e).with_context(format!(
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

#[cfg(test)]
mod tests;
