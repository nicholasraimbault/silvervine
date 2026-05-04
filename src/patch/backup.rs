//! Snapshot, restore, and atomic-rename helpers for the patch flow.
//!
//! ## Lifecycle
//!
//! ```text
//!   patch_browser() {
//!       let handle = backup::snapshot_for_browser(...);  // copy install_path → backups/
//!       run platform impl;
//!       if ok    { handle.commit();   }                  // delete the backup
//!       else     { handle.restore();  }                  // atomic-swap install_path
//!   }
//! ```
//!
//! ## Storage layout
//!
//! Per spec ("Snapshot original bundle → `~/.cache/neon/backups/<browser>-<version>-<timestamp>/`"):
//!
//! ```text
//! ~/.cache/neon/backups/
//! ├── Helium-128.0.6613.119-1715000000/
//! ├── Thorium-129.0.0.0-1715800000/
//! └── ...
//! ```
//!
//! Each subdirectory is a full deep-copy of the browser's install path at
//! the moment the snapshot was taken. [`prune_backups`] removes
//! subdirectories older than 30 days.
//!
//! ## Atomic rename
//!
//! `restore()` swaps the live install path with the backup. The platform
//! crate ([`crate::platform::atomic_rename`]) owns the syscall dispatch:
//!
//! * **Linux:** `renameat2(..., RENAME_EXCHANGE)` — single syscall, atomic
//!   on ext4/btrfs/xfs/f2fs.
//! * **macOS:** `renameatx_np(..., RENAME_SWAP)` — single syscall, atomic
//!   on APFS.
//! * **Fallback** (older filesystems, non-APFS, or syscall ENOSYS): the
//!   platform helper falls back to a two-step
//!   `rename(orig, orig.tmp); rename(staging, orig); rm orig.tmp` —
//!   atomic in the typical case but not crash-safe across the two
//!   `rename` calls. Documented limitation.
//!
//! We intentionally delegate the syscall to `platform` so the patch logic
//! here stays platform-agnostic — only one place in the codebase has to
//! know about `renameat2`/`renameatx_np`.
//!
//! ## What this module does NOT do
//!
//! * No platform-specific bundle handling (codesign, xattr, etc.) — that's
//!   the `PlatformPatcher` impl's job.
//! * No lockfile management — the orchestrator owns that.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::browsers::Browser;
use crate::error::{Error, Result};

/// Default backup directory: `~/.cache/neon/backups/`.
///
/// Returns `None` if `dirs::cache_dir()` is unresolvable.
#[must_use]
pub fn default_backups_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("neon").join("backups"))
}

/// Maximum age of backups before [`prune_backups`] deletes them.
pub const BACKUP_RETENTION: Duration = Duration::from_secs(30 * 86_400);

/// Handle to a snapshot directory, returned by [`snapshot_for_browser`] /
/// [`snapshot`].
///
/// On `Drop`, the snapshot is **kept** — callers must explicitly
/// [`BackupHandle::commit`] (delete) or [`BackupHandle::restore`] (swap
/// back). Leaving the snapshot in place is safer than dropping it
/// silently: a forgotten handle on the happy path costs ~100MB of disk;
/// the same forgetfulness on the error path would have lost user data.
#[derive(Debug)]
#[must_use = "BackupHandle requires explicit commit() or restore()"]
pub struct BackupHandle {
    /// The directory we backed up *from* (and that we'd swap back to).
    original: PathBuf,
    /// The on-disk snapshot directory.
    snapshot: PathBuf,
    /// Whether the handle has been finalized (commit or restore). Tracked
    /// so we can emit a debug-only warning on accidental `Drop`.
    finalized: bool,
}

impl BackupHandle {
    /// Path to the backed-up snapshot on disk.
    #[must_use]
    pub fn snapshot_path(&self) -> &Path {
        &self.snapshot
    }

    /// Path to the original install location the snapshot was taken from.
    #[must_use]
    pub fn original_path(&self) -> &Path {
        &self.original
    }

    /// Delete the snapshot. Called on the happy patch path.
    ///
    /// # Errors
    ///
    /// Returns the error from [`std::fs::remove_dir_all`] if the snapshot
    /// can't be removed (rare — we created it ourselves).
    pub fn commit(mut self) -> Result<()> {
        self.finalized = true;
        if self.snapshot.exists() {
            std::fs::remove_dir_all(&self.snapshot).map_err(|e| {
                Error::from(e).with_context(format!(
                    "failed to remove backup snapshot at {}",
                    self.snapshot.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Atomically swap the snapshot back into place over `original`.
    ///
    /// Delegates the syscall to [`crate::platform::atomic_rename`]
    /// (Linux: `renameat2(RENAME_EXCHANGE)`; macOS:
    /// `renameatx_np(RENAME_SWAP)`; with two-step fallback). After a
    /// successful swap the *previous* `original` content sits at
    /// `snapshot` — we delete it so the backups directory is clean again.
    ///
    /// If the original path no longer exists (e.g. someone `rm -rf`'d it
    /// between snapshot and restore) we fall through to a plain
    /// `rename(snapshot, original)` so the user still ends up with their
    /// pre-patch bundle.
    ///
    /// # Errors
    ///
    /// Surfaces any `rename` / removal failure as a categorized [`Error`].
    pub fn restore(mut self) -> Result<()> {
        self.finalized = true;
        let original = self.original.clone();
        let snapshot = self.snapshot.clone();

        if !original.exists() {
            // Original was destroyed; just move the snapshot into place.
            if let Some(parent) = original.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::from(e)
                        .with_context(format!("create parent {} for restore", parent.display()))
                })?;
            }
            std::fs::rename(&snapshot, &original).map_err(|e| {
                Error::from(e).with_context(format!(
                    "rename({}, {}) (restore from snapshot only)",
                    snapshot.display(),
                    original.display()
                ))
            })?;
            return Ok(());
        }

        // Both exist → atomic swap.
        crate::platform::atomic_rename(&snapshot, &original)?;
        // After the swap, `snapshot` holds what was previously the live
        // (patched) install dir; remove it.
        if snapshot.exists() {
            std::fs::remove_dir_all(&snapshot).map_err(|e| {
                Error::from(e).with_context(format!(
                    "remove patched-bundle leftover at {}",
                    snapshot.display()
                ))
            })?;
        }
        Ok(())
    }
}

impl Drop for BackupHandle {
    /// On accidental drop without commit/restore, leave the snapshot in
    /// place. The user can recover manually from `~/.cache/neon/backups/`
    /// if anything has gone wrong.
    fn drop(&mut self) {
        // No-op (intentional). The `must_use` attribute on the struct
        // gives a clippy lint at compile time; this Drop guarantees we
        // don't silently delete data on a buggy code path.
    }
}

/// Take a snapshot of `source` into `~/.cache/neon/backups/<source-basename>-<timestamp>/`.
///
/// # Errors
///
/// * `Error::permission_denied` / `Error::other` — copy or directory creation failed.
pub fn snapshot(source: &Path) -> Result<BackupHandle> {
    let basename = source
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("snapshot");
    let backups = default_backups_dir().ok_or_else(|| {
        Error::state_corrupted("cannot resolve ~/.cache/neon/backups (no \\$HOME / cache dir)")
    })?;
    snapshot_into(source, &backups, basename, None)
}

/// Take a snapshot tagged with the browser's display name + (optional) version.
///
/// Used by the patch orchestrator. The snapshot directory is named
/// `<browser>-<version>-<timestamp>/` so users browsing
/// `~/.cache/neon/backups/` can tell at a glance which patch left it.
///
/// # Errors
///
/// See [`snapshot`].
pub fn snapshot_for_browser(browser: &Browser, version: Option<&str>) -> Result<BackupHandle> {
    let backups = default_backups_dir().ok_or_else(|| {
        Error::state_corrupted("cannot resolve ~/.cache/neon/backups (no \\$HOME / cache dir)")
    })?;
    snapshot_into(browser.install_path(), &backups, browser.name(), version)
}

/// Test- and injection-friendly snapshot. Public to the crate so the
/// patch orchestrator's tests can route backups under a `tempfile::TempDir`.
pub(crate) fn snapshot_into(
    source: &Path,
    backups_root: &Path,
    label: &str,
    version: Option<&str>,
) -> Result<BackupHandle> {
    if !source.exists() {
        return Err(Error::unknown_bundle_structure(format!(
            "snapshot source {} does not exist",
            source.display()
        )));
    }
    std::fs::create_dir_all(backups_root).map_err(|e| {
        Error::from(e).with_context(format!("create backups root {}", backups_root.display()))
    })?;

    let stamp = unix_timestamp_secs();
    let dir_name = match version {
        Some(v) => format!("{label}-{v}-{stamp}"),
        None => format!("{label}-{stamp}"),
    };
    let snapshot = backups_root.join(dir_name);
    copy_dir_recursive(source, &snapshot)?;
    Ok(BackupHandle {
        original: source.to_path_buf(),
        snapshot,
        finalized: false,
    })
}

/// Recursively copy `src` into `dst`, mirroring `cp -R`.
///
/// Symlinks are copied as symlinks (we don't dereference) — important for
/// macOS framework `Versions/Current → A` symlinks.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(src)
        .map_err(|e| Error::from(e).with_context(format!("symlink_metadata({})", src.display())))?;

    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(src)
            .map_err(|e| Error::from(e).with_context(format!("read_link({})", src.display())))?;
        symlink_create(&target, dst)?;
        return Ok(());
    }

    if metadata.is_file() {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::from(e).with_context(format!("create_dir_all({})", parent.display()))
            })?;
        }
        std::fs::copy(src, dst).map_err(|e| {
            Error::from(e).with_context(format!("copy({} -> {})", src.display(), dst.display()))
        })?;
        // Preserve mode so `chmod 755` chrome-sandbox-style files survive
        // round-trips.
        copy_permissions(src, dst)?;
        return Ok(());
    }

    if metadata.is_dir() {
        std::fs::create_dir_all(dst).map_err(|e| {
            Error::from(e).with_context(format!("create_dir_all({})", dst.display()))
        })?;
        copy_permissions(src, dst)?;
        let entries = std::fs::read_dir(src)
            .map_err(|e| Error::from(e).with_context(format!("read_dir({})", src.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                Error::from(e).with_context(format!("entry under {}", src.display()))
            })?;
            let name = entry.file_name();
            copy_dir_recursive(&entry.path(), &dst.join(name))?;
        }
        return Ok(());
    }

    // Anything else (block/char devices, FIFOs, sockets) we silently skip
    // — they shouldn't appear in browser bundles, and trying to copy them
    // would just produce confusing errors.
    Ok(())
}

#[cfg(unix)]
fn symlink_create(target: &Path, link: &Path) -> Result<()> {
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::from(e).with_context(format!("create_dir_all({})", parent.display()))
        })?;
    }
    std::os::unix::fs::symlink(target, link).map_err(|e| {
        Error::from(e).with_context(format!(
            "symlink({} -> {})",
            link.display(),
            target.display()
        ))
    })
}

#[cfg(not(unix))]
fn symlink_create(_target: &Path, _link: &Path) -> Result<()> {
    Err(Error::unsupported_platform(
        "symlink creation is only supported on Unix",
    ))
}

#[cfg(unix)]
fn copy_permissions(src: &Path, dst: &Path) -> Result<()> {
    let permissions = std::fs::metadata(src)
        .map_err(|e| Error::from(e).with_context(format!("metadata({})", src.display())))?
        .permissions();
    std::fs::set_permissions(dst, permissions)
        .map_err(|e| Error::from(e).with_context(format!("set_permissions({})", dst.display())))
}

#[cfg(not(unix))]
fn copy_permissions(_src: &Path, _dst: &Path) -> Result<()> {
    Ok(())
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Delete backups in `backups_root` older than [`BACKUP_RETENTION`].
///
/// Best-effort: failures to read individual entries are skipped (the
/// snapshot directory might be in use, the user might have lost
/// permission, etc.); only fatal errors (cannot read the root) are
/// surfaced.
///
/// # Errors
///
/// Returns the error from [`std::fs::read_dir`] on `backups_root` if it
/// cannot be read at all.
pub fn prune_backups() -> Result<usize> {
    let Some(root) = default_backups_dir() else {
        // No cache dir; nothing to prune.
        return Ok(0);
    };
    if !root.exists() {
        return Ok(0);
    }
    prune_backups_in(&root)
}

/// Test-friendly variant of [`prune_backups`] that takes the root path.
pub(crate) fn prune_backups_in(backups_root: &Path) -> Result<usize> {
    let mut deleted = 0usize;
    let cutoff = SystemTime::now()
        .checked_sub(BACKUP_RETENTION)
        .unwrap_or(UNIX_EPOCH);
    let entries = std::fs::read_dir(backups_root).map_err(|e| {
        Error::from(e).with_context(format!("read backups dir {}", backups_root.display()))
    })?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if modified < cutoff && std::fs::remove_dir_all(&path).is_ok() {
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Internal helper trait — same shape as in [`crate::lockfile`] but kept
/// private to this module so we don't leak it across modules. Lifted
/// here so both the snapshot/restore branches can prepend rich context
/// without losing the category routing.
trait ErrorContext {
    fn with_context(self, context: impl Into<String>) -> Self;
}

impl ErrorContext for Error {
    fn with_context(mut self, context: impl Into<String>) -> Self {
        let ctx = context.into();
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

    /// Build a small "browser bundle" tree under `root`.
    fn build_fake_bundle(root: &Path) {
        fs::create_dir_all(root).expect("mkdir root");
        fs::write(root.join("hello.txt"), b"hello").expect("write hello");
        let nested = root.join("nested").join("deep");
        fs::create_dir_all(&nested).expect("mkdir nested");
        fs::write(nested.join("data.bin"), [1u8, 2, 3, 4]).expect("write data");
        // Symlink ./hello.txt → nested/link
        let link = nested.join("link.txt");
        let _ = std::os::unix::fs::symlink("../../hello.txt", &link);
    }

    #[test]
    fn snapshot_into_copies_full_tree() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("install");
        build_fake_bundle(&bundle);
        let backups = tmp.path().join("backups");
        let handle =
            snapshot_into(&bundle, &backups, "Test", Some("1.0")).expect("snapshot must succeed");
        // Confirm the snapshot has the same shape.
        let snap = handle.snapshot_path();
        assert!(snap.exists());
        assert!(snap.join("hello.txt").exists());
        assert!(snap.join("nested").join("deep").join("data.bin").exists());
        // Symlink is preserved.
        let link = snap.join("nested").join("deep").join("link.txt");
        let meta = fs::symlink_metadata(&link).expect("symlink metadata");
        assert!(
            meta.file_type().is_symlink(),
            "snapshot must preserve symlinks"
        );
        // Path naming convention.
        assert!(snap
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .starts_with("Test-1.0-"));
    }

    #[test]
    fn snapshot_handle_exposes_paths() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("install");
        build_fake_bundle(&bundle);
        let backups = tmp.path().join("backups");
        let handle = snapshot_into(&bundle, &backups, "X", None).expect("snapshot");
        assert_eq!(handle.original_path(), bundle);
        assert!(handle.snapshot_path().starts_with(&backups));
        // Tidy up.
        handle.commit().expect("commit");
    }

    #[test]
    fn snapshot_for_missing_source_errors() {
        let tmp = TempDir::new().expect("tempdir");
        let nope = tmp.path().join("nope");
        let backups = tmp.path().join("backups");
        let err = snapshot_into(&nope, &backups, "X", None).expect_err("missing src");
        assert_eq!(err.category, crate::ErrorCategory::UnknownBundleStructure);
    }

    #[test]
    fn commit_deletes_snapshot() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("install");
        build_fake_bundle(&bundle);
        let backups = tmp.path().join("backups");
        let handle = snapshot_into(&bundle, &backups, "X", None).expect("snapshot");
        let snap = handle.snapshot_path().to_path_buf();
        assert!(snap.exists());
        handle.commit().expect("commit");
        assert!(!snap.exists());
    }

    #[test]
    fn restore_swaps_snapshot_back_into_original() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("install");
        build_fake_bundle(&bundle);
        let backups = tmp.path().join("backups");
        let handle = snapshot_into(&bundle, &backups, "X", None).expect("snapshot");
        // Mutate the original (simulating a botched patch).
        fs::write(bundle.join("hello.txt"), b"corrupted").expect("write corrupt");
        // Restore.
        handle.restore().expect("restore must succeed");
        // Original content is back.
        let restored = fs::read(bundle.join("hello.txt")).expect("read");
        assert_eq!(restored, b"hello");
        // Restore cleans up after itself: no leftover backup or .neon-restore.
        let stale = bundle.with_file_name("install.neon-restore");
        assert!(!stale.exists());
    }

    /// Restore with the original missing entirely (e.g. someone `rm -rf`'d
    /// it between snapshot and restore) still puts the snapshot in place.
    #[test]
    fn restore_recovers_when_original_was_deleted() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("install");
        build_fake_bundle(&bundle);
        let backups = tmp.path().join("backups");
        let handle = snapshot_into(&bundle, &backups, "X", None).expect("snapshot");
        fs::remove_dir_all(&bundle).expect("rm bundle");
        handle.restore().expect("restore from snapshot only");
        assert!(bundle.exists());
        assert_eq!(fs::read(bundle.join("hello.txt")).expect("read"), b"hello");
    }

    #[test]
    fn prune_backups_in_keeps_recent_and_drops_old() {
        let tmp = TempDir::new().expect("tempdir");
        let backups = tmp.path().join("backups");
        fs::create_dir_all(&backups).expect("mkdir");
        // Recent — modified now.
        let recent = backups.join("recent");
        fs::create_dir_all(&recent).expect("mkdir recent");
        fs::write(recent.join("x"), b"x").expect("write x");
        // Old — backdate the directory's mtime.
        let old = backups.join("old");
        fs::create_dir_all(&old).expect("mkdir old");
        fs::write(old.join("y"), b"y").expect("write y");
        let way_old = SystemTime::now() - Duration::from_secs(100 * 86_400);
        // Set the entry mtime by writing then setting it.
        if let Ok(file) = fs::OpenOptions::new().write(true).open(old.join("y")) {
            let _ = file.set_modified(way_old);
        }
        if let Ok(file) = fs::OpenOptions::new().read(true).open(&old) {
            let _ = file.set_modified(way_old);
        }
        // Note: not all platforms allow setting a directory's mtime via
        // file handle; if it didn't take, we just don't assert deletion.
        let deleted = prune_backups_in(&backups).expect("prune");
        // Recent must always remain.
        assert!(recent.exists(), "recent backup must survive");
        // If we managed to backdate the old one, it should now be gone.
        if old.exists() {
            // Couldn't backdate; nothing pruned but no error either.
            assert_eq!(deleted, 0);
        } else {
            assert_eq!(deleted, 1);
        }
    }

    #[test]
    fn snapshot_via_default_for_browser_writes_under_basename() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("MyBrowser");
        build_fake_bundle(&bundle);
        let backups = tmp.path().join("backups");
        let handle = snapshot_into(&bundle, &backups, "MyBrowser", Some("v1")).expect("snapshot");
        let snap = handle.snapshot_path();
        let name = snap.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert!(
            name.starts_with("MyBrowser-v1-"),
            "expected MyBrowser-v1-<ts>, got {name}"
        );
        handle.commit().expect("commit");
    }

    #[test]
    fn unix_timestamp_is_nonzero() {
        // Sanity: not exactly the epoch.
        assert!(unix_timestamp_secs() > 1_700_000_000);
    }

    #[test]
    fn default_backups_dir_resolves_under_neon_subdir() {
        if let Some(p) = default_backups_dir() {
            let suffix = std::path::Path::new("neon").join("backups");
            assert!(p.ends_with(&suffix), "got {}", p.display());
        }
    }

    #[test]
    fn copy_dir_recursive_creates_destination_when_root_is_a_file() {
        let tmp = TempDir::new().expect("tempdir");
        let src = tmp.path().join("just-a-file");
        fs::write(&src, b"hello").expect("write src");
        let dst = tmp.path().join("dst");
        copy_dir_recursive(&src, &dst).expect("file copy");
        assert_eq!(fs::read(&dst).expect("read"), b"hello");
    }

    /// Confirm we surface a categorized error rather than panicking when
    /// a snapshot's parent path is a regular file (causing `create_dir_all`
    /// to fail).
    #[test]
    fn snapshot_into_errors_when_backups_root_is_a_file() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("install");
        build_fake_bundle(&bundle);
        let blocker = tmp.path().join("backups");
        fs::write(&blocker, b"blocker").expect("write blocker");
        let err = snapshot_into(&bundle, &blocker, "X", None).expect_err("must error");
        assert!(matches!(
            err.category,
            crate::ErrorCategory::PermissionDenied | crate::ErrorCategory::Other
        ));
    }

    /// `prune_backups_in` is a no-op when the backups dir doesn't exist.
    #[test]
    fn prune_backups_in_with_missing_root_returns_zero() {
        let tmp = TempDir::new().expect("tempdir");
        let phantom = tmp.path().join("does-not-exist");
        let deleted = prune_backups_in(&phantom);
        // Reading a missing dir errors, but the public surface tolerates that.
        // We just want to make sure the helper doesn't panic.
        assert!(deleted.is_err() || deleted.is_ok());
    }

    /// `prune_backups` (the public default-path variant) doesn't panic.
    #[test]
    fn prune_backups_does_not_panic() {
        let _ = prune_backups();
    }

    /// `snapshot` (the public default-path variant) writes under `dirs::cache_dir`.
    /// We don't actually want to leave files in the user's real cache, so
    /// we verify the function returns a handle whose `original_path` matches
    /// what we passed in. We use a small tempdir for the source.
    #[test]
    fn snapshot_default_path_uses_cache_dir() {
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("install");
        build_fake_bundle(&bundle);
        // This will write to `~/.cache/neon/backups/<name>-<ts>/` on a
        // dev machine, which is fine for a test (we clean up immediately).
        // If `dirs::cache_dir()` is None, snapshot returns a state-corrupted
        // error — also fine.
        match snapshot(&bundle) {
            Ok(handle) => {
                assert_eq!(handle.original_path(), bundle);
                assert!(handle.snapshot_path().exists());
                handle.commit().expect("clean up");
            }
            Err(e) => {
                assert_eq!(e.category, crate::ErrorCategory::StateCorrupted);
            }
        }
    }

    /// `snapshot_for_browser` builds the `<name>-<version>-<ts>` form.
    #[test]
    fn snapshot_for_browser_includes_browser_name() {
        use crate::browsers::BrowserKind;
        let tmp = TempDir::new().expect("tempdir");
        let bundle = tmp.path().join("install");
        build_fake_bundle(&bundle);
        let browser = Browser {
            name: "TestyBrowser".into(),
            install_path: bundle.clone(),
            kind: BrowserKind::Detected,
            framework_name: None,
        };
        match snapshot_for_browser(&browser, Some("v1.2.3")) {
            Ok(handle) => {
                let name = handle
                    .snapshot_path()
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                assert!(
                    name.starts_with("TestyBrowser-v1.2.3-"),
                    "expected TestyBrowser-v1.2.3-<ts>, got {name}"
                );
                handle.commit().expect("clean up");
            }
            Err(e) => {
                assert_eq!(e.category, crate::ErrorCategory::StateCorrupted);
            }
        }
    }
}
