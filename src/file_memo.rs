//! Best-effort on-disk memo of file identity keyed by canonical path, length,
//! and mtime.
//!
//! Used so `doctor --media-stack` does not re-hash a large browser or CDM
//! binary, or re-run `pacman -Qo`, when the live file has not changed. Cache
//! I/O failures are ignored. The live file is opened with `O_NOFOLLOW`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::platform;
use crate::widevine::download::sha512_reader;
use crate::widevine::sha512_hex;

const MAX_MEMO_BYTES: u64 = 8 * 1024;
#[cfg(any(test, target_os = "linux"))]
const MAX_TEXT_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestMemo {
    canonical_path: String,
    len: u64,
    modified: u64,
    sha512: String,
}

#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextMemo {
    canonical_path: String,
    len: u64,
    modified: u64,
    value: String,
}

/// Identity observed from a regular file opened with `O_NOFOLLOW`.
pub(crate) struct FileIdentity {
    pub canonical: PathBuf,
    pub len: u64,
    pub modified: u64,
}

/// SHA-512 of `path`, reused when canonical path, length, and mtime match.
pub(crate) fn sha512_memoized(path: &Path) -> Result<String> {
    let (identity, file) = open_identity(path)?;
    digest_for(&identity, file)
}

/// SHA-512 plus the identity fields used as the memo key.
pub(crate) fn sha512_memoized_with_identity(path: &Path) -> Result<(FileIdentity, String)> {
    let (identity, file) = open_identity(path)?;
    let digest = digest_for(&identity, file)?;
    Ok((identity, digest))
}

/// Return a previously stored short string for `path`, or `compute` and store it.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn text_memoized(
    path: &Path,
    compute: impl FnOnce() -> Option<String>,
) -> Option<String> {
    let (identity, _file) = open_identity(path).ok()?;
    let key = identity.canonical.to_string_lossy();
    if let Some(value) = load_text(&key, identity.len, identity.modified) {
        return Some(value);
    }
    let value = compute()?;
    if !is_short_text(&value) {
        return Some(value);
    }
    store_text(&TextMemo {
        canonical_path: key.into_owned(),
        len: identity.len,
        modified: identity.modified,
        value: value.clone(),
    });
    Some(value)
}

fn digest_for(identity: &FileIdentity, mut file: File) -> Result<String> {
    let key = identity.canonical.to_string_lossy();
    if let Some(digest) = load_digest(&key, identity.len, identity.modified) {
        return Ok(digest);
    }
    let digest = sha512_reader(&mut file)?;
    if is_lowercase_sha512(&digest) {
        store_digest(&DigestMemo {
            canonical_path: key.into_owned(),
            len: identity.len,
            modified: identity.modified,
            sha512: digest.clone(),
        });
    }
    Ok(digest)
}

fn open_identity(path: &Path) -> Result<(FileIdentity, File)> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        Error::unknown_bundle_structure(format!(
            "could not canonicalize {}: {error}",
            path.display()
        ))
        .with_source(error)
    })?;
    let file = open_nofollow(&canonical)?;
    let metadata = file.metadata().map_err(Error::from)?;
    if !metadata.is_file() {
        return Err(Error::unknown_bundle_structure(format!(
            "{} must be a regular file",
            canonical.display()
        )));
    }
    let modified = metadata
        .modified()
        .map_err(Error::from)?
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::other("file mtime predates the Unix epoch").with_source(error))?
        .as_secs();
    Ok((
        FileIdentity {
            canonical,
            len: metadata.len(),
            modified,
        },
        file,
    ))
}

fn open_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(Error::from)
}

fn digest_root() -> PathBuf {
    platform::cache_dir()
        .join("diagnostics")
        .join("file-digests")
}

#[cfg(any(test, target_os = "linux"))]
fn text_root() -> PathBuf {
    platform::cache_dir().join("diagnostics").join("file-text")
}

fn memo_path(root: &Path, prefix: &str, canonical: &str) -> PathBuf {
    let digest = sha512_hex(canonical.as_bytes());
    root.join(format!("{prefix}-{}.json", &digest[..24]))
}

fn is_lowercase_sha512(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(any(test, target_os = "linux"))]
fn is_short_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES
}

fn load_digest(canonical: &str, len: u64, modified: u64) -> Option<String> {
    let cached: DigestMemo = load_json(&memo_path(&digest_root(), "sha", canonical))?;
    if cached.canonical_path != canonical
        || cached.len != len
        || cached.modified != modified
        || !is_lowercase_sha512(&cached.sha512)
    {
        return None;
    }
    Some(cached.sha512)
}

fn store_digest(cached: &DigestMemo) {
    store_json(
        &digest_root(),
        &memo_path(&digest_root(), "sha", &cached.canonical_path),
        cached,
    );
}

#[cfg(any(test, target_os = "linux"))]
fn load_text(canonical: &str, len: u64, modified: u64) -> Option<String> {
    let cached: TextMemo = load_json(&memo_path(&text_root(), "txt", canonical))?;
    if cached.canonical_path != canonical
        || cached.len != len
        || cached.modified != modified
        || !is_short_text(&cached.value)
    {
        return None;
    }
    Some(cached.value)
}

#[cfg(any(test, target_os = "linux"))]
fn store_text(cached: &TextMemo) {
    store_json(
        &text_root(),
        &memo_path(&text_root(), "txt", &cached.canonical_path),
        cached,
    );
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_MEMO_BYTES {
        return None;
    }
    let mut file = open_nofollow(path).ok()?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_MEMO_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_MEMO_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn memo_writes_allowed() -> bool {
    // The privileged patch child must not create cache or log state.
    !std::env::args_os().any(|argument| argument == "__privileged-patch")
}

fn store_json<T: Serialize>(root: &Path, path: &Path, value: &T) {
    if !memo_writes_allowed() {
        return;
    }
    if ensure_root(root).is_err() {
        return;
    }
    if reject_unsafe(path).is_err() {
        return;
    }
    let Ok(bytes) = serde_json::to_vec(value) else {
        return;
    };
    let _ = atomic_write(path, &bytes);
}

fn ensure_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::state_corrupted(format!(
                "{} must be a regular cache directory",
                root.display()
            )));
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::from(error)),
    }
    fs::create_dir_all(root).map_err(Error::from)?;
    let metadata = fs::symlink_metadata(root).map_err(Error::from)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Error::state_corrupted(
            "file memo root changed while it was created",
        ));
    }
    Ok(())
}

fn reject_unsafe(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            Error::state_corrupted(format!("{} must be a regular cache file", path.display())),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::from(error)),
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::state_corrupted("file memo path has no parent"))?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".silvervine-memo.tmp-{}-{counter}",
        std::process::id()
    ));
    let cleanup = TempFile(temp.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(Error::from)?;
    file.write_all(bytes).map_err(Error::from)?;
    file.write_all(b"\n").map_err(Error::from)?;
    file.sync_all().map_err(Error::from)?;
    drop(file);
    fs::rename(&temp, path).map_err(Error::from)?;
    let _ = File::open(parent).and_then(|directory| directory.sync_all());
    std::mem::forget(cleanup);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    use tempfile::TempDir;

    use super::{sha512_memoized, text_memoized};
    use crate::test_support::{isolated_xdg_cache, set_mtime};
    use crate::widevine::sha512_hex;

    #[test]
    fn sha512_memo_reuses_digest_when_path_len_and_mtime_match() {
        let _env = crate::test_support::env_lock();
        let _cache = isolated_xdg_cache();
        let tmp = TempDir::new().expect("tmp");
        let path = tmp.path().join("lib.so");
        fs::write(&path, b"AAAAAAAAAAAA").expect("write");
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        set_mtime(&path, mtime);

        let first = sha512_memoized(&path).expect("hash");
        assert_eq!(first, sha512_hex(b"AAAAAAAAAAAA"));

        fs::write(&path, b"BBBBBBBBBBBB").expect("rewrite");
        set_mtime(&path, mtime);
        let second = sha512_memoized(&path).expect("cached");
        assert_eq!(second, sha512_hex(b"AAAAAAAAAAAA"));
        assert_ne!(second, sha512_hex(b"BBBBBBBBBBBB"));
    }

    #[test]
    fn sha512_memo_rehashes_when_mtime_changes() {
        let _env = crate::test_support::env_lock();
        let _cache = isolated_xdg_cache();
        let tmp = TempDir::new().expect("tmp");
        let path = tmp.path().join("lib.so");
        fs::write(&path, b"AAAAAAAAAAAA").expect("write");
        set_mtime(
            &path,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        );
        let _ = sha512_memoized(&path).expect("hash");

        fs::write(&path, b"BBBBBBBBBBBB").expect("rewrite");
        set_mtime(
            &path,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_001),
        );
        assert_eq!(
            sha512_memoized(&path).expect("rehash"),
            sha512_hex(b"BBBBBBBBBBBB")
        );
    }

    #[test]
    fn text_memo_does_not_recompute_when_identity_matches() {
        let _env = crate::test_support::env_lock();
        let _cache = isolated_xdg_cache();
        let tmp = TempDir::new().expect("tmp");
        let path = tmp.path().join("chrome");
        fs::write(&path, b"AAAAAAAAAAAA").expect("write");
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        set_mtime(&path, mtime);

        let calls = AtomicUsize::new(0);
        let first = text_memoized(&path, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Some("1.2.3-1".into())
        });
        let second = text_memoized(&path, || {
            calls.fetch_add(1, Ordering::SeqCst);
            Some("9.9.9-9".into())
        });

        assert_eq!(first.as_deref(), Some("1.2.3-1"));
        assert_eq!(second.as_deref(), Some("1.2.3-1"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
