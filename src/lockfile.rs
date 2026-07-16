//! `flock`-based exclusive lockfile for concurrent-patch protection.
//!
//! Per the spec's data flow:
//!
//! > 1. Acquire lockfile  `~/.cache/silvervine/patch.lock`  (flock exclusive)
//!
//! and:
//!
//! > `flock` exclusive lock on `~/.cache/silvervine/patch.lock`. Second invocation
//! > blocks (CLI) or skips with notification (daemon, to avoid blocking UI thread).
//!
//! This module exposes one helper, [`with_lock`], that:
//!
//! * Creates the parent directory (and the lockfile itself) if missing.
//! * Acquires an exclusive `flock` (blocking, by default).
//! * Runs the caller's closure.
//! * Releases the lock on closure return — even if the closure panics, since
//!   `fs2`'s file-drop will release the kernel lock.
//!
//! The Phase 1 deliverable is **just the helper**. Phase 2 patch flows wire
//! it into `patch::patch_browser` and the Widevine update flow.
//!
//! # Example
//!
//! ```no_run
//! use silvervine::lockfile::with_lock;
//! use std::path::Path;
//!
//! let result = with_lock(Path::new("/tmp/example.lock"), || {
//!     // Do exclusive work here.
//!     Ok::<_, silvervine::Error>(42)
//! })?;
//! assert_eq!(result, 42);
//! # Ok::<_, silvervine::Error>(())
//! ```

use std::fs::{File, OpenOptions};
use std::path::Path;

use fs2::FileExt;

use crate::error::{Error, Result};

/// Acquire an exclusive `flock` on `path`, run `f`, and release the lock.
///
/// * Creates `path`'s parent directory (recursively) if missing.
/// * Creates `path` itself (mode 0644) if missing — the file content is not
///   used; the lock is on the inode.
/// * **Blocks** until the lock is acquired. Use [`try_with_lock`] if the
///   caller cannot block (e.g. the daemon's UI thread).
/// * Releases the lock on closure exit, including panic — `fs2`'s `Drop`
///   impl on the file handle calls `flock(LOCK_UN)`.
///
/// # Errors
///
/// Returns an [`Error`] (with the appropriate category) if:
/// * The parent directory cannot be created (`PermissionDenied` / `Other`).
/// * The lockfile cannot be opened (`PermissionDenied` / `Other`).
/// * `flock` itself fails (rare; surfaces as `Other`).
/// * The caller's closure returns an error — it's bubbled up unchanged.
pub fn with_lock<T, F>(path: &Path, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let file = open_lockfile(path)?;
    file.lock_exclusive().map_err(|e| {
        Error::other(format!("flock(LOCK_EX) on {} failed", path.display())).with_source(e)
    })?;
    // The file handle's `Drop` will release the lock; even if `f` panics,
    // unwinding will release it before propagating up.
    let result = f();
    // Best-effort explicit unlock — Drop also handles this, but we drop
    // explicitly here to make ordering obvious in tests.
    let _ = FileExt::unlock(&file);
    result
}

/// Try to acquire an exclusive `flock` on `path` without blocking, run `f`
/// if the lock was acquired, and release the lock.
///
/// Returns `Ok(None)` if the lock could not be acquired (held by another
/// process). Returns `Ok(Some(value))` if `f` ran and produced `value`.
/// Returns `Err(_)` for any I/O error or for a propagated error from `f`.
///
/// # Errors
///
/// See [`with_lock`].
pub fn try_with_lock<T, F>(path: &Path, f: F) -> Result<Option<T>>
where
    F: FnOnce() -> Result<T>,
{
    let file = open_lockfile(path)?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            let result = f()?;
            let _ = FileExt::unlock(&file);
            Ok(Some(result))
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(
            Error::other(format!("try_lock_exclusive on {} failed", path.display())).with_source(e),
        ),
    }
}

/// Open (or create) the lockfile, ensuring its parent directory exists.
///
/// Mode is left at the platform default (0644 on Unix); only the inode is
/// load-bearing.
fn open_lockfile(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::from(e).attach(format!(
                    "create lockfile parent directory {}",
                    parent.display()
                ))
            })?;
        }
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|e| Error::from(e).attach(format!("open lockfile {}", path.display())))
}

// Tiny extension trait so we can prepend context to an `Error`'s message
// without losing the category routing. Kept private to this module — when
// other modules need this pattern we'll lift it into `error.rs`.
trait ErrorAttach {
    fn attach(self, context: impl Into<String>) -> Self;
}

impl ErrorAttach for Error {
    fn attach(mut self, context: impl Into<String>) -> Self {
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use tempfile::TempDir;

    /// Sanity check: a single-threaded acquisition runs the closure and
    /// returns the value.
    #[test]
    fn single_acquisition_runs_closure() {
        let tmp = TempDir::new().expect("tempdir");
        let lock_path = tmp.path().join("single.lock");
        let result = with_lock(&lock_path, || Ok::<_, Error>(7));
        assert_eq!(result.expect("with_lock returned an error"), 7);
        // The lockfile should exist on disk afterwards (we created it).
        assert!(lock_path.exists());
    }

    /// Errors from the closure propagate through.
    #[test]
    fn closure_error_propagates() {
        let tmp = TempDir::new().expect("tempdir");
        let lock_path = tmp.path().join("err.lock");
        let result = with_lock(&lock_path, || -> Result<()> {
            Err(Error::permission_denied("nope"))
        });
        let err = result.expect_err("expected the closure error to propagate");
        assert_eq!(err.category, crate::ErrorCategory::PermissionDenied);
    }

    /// Concurrent acquisition: spawn N threads, each grabs the lock,
    /// increments a counter, and the lock guarantees no two are inside the
    /// critical section at the same time.
    #[test]
    fn concurrent_acquisition_is_mutually_exclusive() {
        let tmp = TempDir::new().expect("tempdir");
        let lock_path = tmp.path().join("concurrent.lock");
        let path = Arc::new(lock_path);
        // Tracks the in-flight count inside the critical section. If the
        // lock is exclusive, this should never go above 1.
        let inflight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let total_runs = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let path = Arc::clone(&path);
            let inflight = Arc::clone(&inflight);
            let max_observed = Arc::clone(&max_observed);
            let total_runs = Arc::clone(&total_runs);
            handles.push(thread::spawn(move || {
                with_lock(&path, || {
                    let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                    // Track the high-water mark.
                    let mut observed = max_observed.load(Ordering::SeqCst);
                    while cur > observed {
                        match max_observed.compare_exchange(
                            observed,
                            cur,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        ) {
                            Ok(_) => break,
                            Err(actual) => observed = actual,
                        }
                    }
                    // Hold the lock briefly to make a race observable.
                    thread::sleep(Duration::from_millis(10));
                    inflight.fetch_sub(1, Ordering::SeqCst);
                    total_runs.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .expect("with_lock");
            }));
        }
        for h in handles {
            h.join().expect("thread join");
        }
        assert_eq!(total_runs.load(Ordering::SeqCst), 8);
        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            1,
            "more than one thread was inside the lock at once"
        );
    }

    /// `try_with_lock` returns `None` when another process holds the lock.
    /// We model "another process" with a second `File` that takes the
    /// exclusive lock for the duration of the test.
    #[test]
    fn try_with_lock_returns_none_when_held() {
        let tmp = TempDir::new().expect("tempdir");
        let lock_path = tmp.path().join("try.lock");

        // Pre-acquire the lock on a separate handle that we keep alive.
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open holder file");
        holder.lock_exclusive().expect("hold the lock");

        let outcome = try_with_lock(&lock_path, || Ok::<_, Error>(42))
            .expect("try_with_lock should not error");
        assert!(outcome.is_none(), "expected None when lock is held");

        // Release; now the same call should succeed.
        FileExt::unlock(&holder).expect("release holder lock");
        let outcome2 =
            try_with_lock(&lock_path, || Ok::<_, Error>(99)).expect("second try_with_lock");
        assert_eq!(outcome2, Some(99));
    }

    /// Releasing the lock allows a subsequent acquisition to succeed
    /// immediately (i.e. we don't leave a kernel-level lock dangling).
    #[test]
    fn lock_is_released_after_closure() {
        let tmp = TempDir::new().expect("tempdir");
        let lock_path = tmp.path().join("release.lock");
        with_lock(&lock_path, || Ok::<_, Error>(())).expect("first lock");
        // Second acquisition should also succeed without blocking forever.
        let outcome =
            try_with_lock(&lock_path, || Ok::<_, Error>(1)).expect("try_with_lock after release");
        assert_eq!(outcome, Some(1));
    }

    /// Closure errors propagate from `try_with_lock` when the lock IS
    /// acquired.
    #[test]
    fn try_with_lock_propagates_closure_error() {
        let tmp = TempDir::new().expect("tempdir");
        let lock_path = tmp.path().join("try-err.lock");
        let outcome: Result<Option<i32>> =
            try_with_lock(&lock_path, || Err(Error::network("simulated")));
        let err = outcome.expect_err("closure error must surface");
        assert_eq!(err.category, crate::ErrorCategory::NetworkError);
    }

    /// `attach` prepends context to a non-empty message; an empty-message
    /// error gets the context as its new message.
    #[test]
    fn attach_prepends_context_to_message() {
        let err = Error::permission_denied("oops").attach("foo");
        assert_eq!(err.message, "foo: oops");
        let mut empty = Error::other("");
        empty.message.clear();
        let attached = empty.attach("bare");
        assert_eq!(attached.message, "bare");
    }

    /// `open_lockfile` happily creates parent directories that don't yet
    /// exist (covers the `create_dir_all` branch).
    #[test]
    fn open_lockfile_creates_parent_directories() {
        let tmp = TempDir::new().expect("tempdir");
        let nested = tmp.path().join("a").join("b").join("c").join("nested.lock");
        // `nested.parent()` is `<tmp>/a/b/c` which doesn't exist yet.
        open_lockfile(&nested).expect("must create parents and open");
        assert!(nested.exists());
    }

    /// Failing to open the lockfile (here: parent path is a regular
    /// file, not a directory) surfaces as an [`Error`] rather than a
    /// panic.
    #[test]
    fn open_lockfile_returns_error_when_parent_is_a_file() {
        let tmp = TempDir::new().expect("tempdir");
        let blocker = tmp.path().join("not-a-dir");
        std::fs::write(&blocker, b"hello").expect("write blocker file");
        // We try to use `<blocker>/inside.lock` where `<blocker>` is a
        // regular file — `create_dir_all` will fail.
        let lock = blocker.join("inside.lock");
        let err = open_lockfile(&lock).expect_err("must error");
        // Either PermissionDenied or Other depending on the kernel; both
        // valid. The point is: no panic, no Ok.
        assert!(matches!(
            err.category,
            crate::ErrorCategory::PermissionDenied | crate::ErrorCategory::Other
        ));
    }
}
