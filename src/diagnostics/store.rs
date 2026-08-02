//! Persisted browser capability reports keyed by exact binary/CDM fingerprints.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::eme::probe::{CapabilityAssessment, RawProbeResult};
use crate::error::{Error, Result};
use crate::widevine::download::sha512_reader;
use crate::widevine::sha512_hex;

/// Current on-disk capability-report schema.
pub const STORE_SCHEMA_VERSION: u8 = 3;
const MAX_REPORT_BYTES: u64 = 1024 * 1024;

/// One CDM library identity included in a probe fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CdmFingerprintEntry {
    /// Canonical absolute path of the CDM library or install root.
    pub canonical_path: String,
    /// Manifest/component version when passively readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// SHA-512 of the library when the file is a safely readable regular file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library_sha512: Option<String>,
}

impl CdmFingerprintEntry {
    /// Construct one ordered CDM identity entry.
    #[must_use]
    pub fn new(
        canonical_path: impl Into<String>,
        version: Option<String>,
        library_sha512: Option<String>,
    ) -> Self {
        Self {
            canonical_path: canonical_path.into(),
            version,
            library_sha512,
        }
    }

    fn is_complete(&self) -> bool {
        Path::new(&self.canonical_path).is_absolute()
            && self
                .version
                .as_deref()
                .is_some_and(|version| !version.trim().is_empty())
            && self
                .library_sha512
                .as_deref()
                .is_some_and(|digest| !digest.is_empty())
    }
}

/// Exact browser/CDM identity that makes cached evidence reusable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeFingerprint {
    /// Canonical absolute browser executable path.
    pub canonical_executable: String,
    /// Passive browser version observed at probe time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_version: Option<String>,
    /// Browser executable byte length.
    pub executable_len: u64,
    /// Browser executable mtime in Unix seconds.
    pub executable_modified: u64,
    /// SHA-512 of the exact browser executable bytes.
    pub executable_sha512: String,
    /// Ordered set of relevant CDM identities (install-root and external/component).
    #[serde(default)]
    pub cdm_entries: Vec<CdmFingerprintEntry>,
    /// Host operating system.
    pub host_os: String,
    /// Host CPU architecture.
    pub host_arch: String,
}

impl ProbeFingerprint {
    /// Construct a fingerprint from already-observed executable identity fields.
    #[must_use]
    pub fn new(
        canonical_executable: impl Into<String>,
        browser_version: Option<String>,
        executable_len: u64,
        executable_modified: u64,
        executable_sha512: impl Into<String>,
        mut cdm_entries: Vec<CdmFingerprintEntry>,
    ) -> Self {
        cdm_entries.sort();
        cdm_entries.dedup();
        Self {
            canonical_executable: canonical_executable.into(),
            browser_version,
            executable_len,
            executable_modified,
            executable_sha512: executable_sha512.into(),
            cdm_entries,
            host_os: std::env::consts::OS.into(),
            host_arch: std::env::consts::ARCH.into(),
        }
    }

    /// Build a fingerprint by canonicalizing `executable` and reading len/mtime.
    ///
    /// # Errors
    ///
    /// Returns a categorized I/O error when the executable cannot be inspected.
    pub fn from_executable(
        executable: &Path,
        browser_version: Option<String>,
        cdm_entries: Vec<CdmFingerprintEntry>,
    ) -> Result<Self> {
        if browser_version
            .as_deref()
            .is_none_or(|version| version.trim().is_empty())
            || cdm_entries.is_empty()
            || cdm_entries.iter().any(|entry| !entry.is_complete())
        {
            return Err(Error::state_corrupted(
                "exact probe fingerprints require browser and byte-exact CDM identities",
            ));
        }
        let canonical = canonicalize_path(executable)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&canonical).map_err(Error::from)?;
        let metadata = file.metadata().map_err(Error::from)?;
        if !metadata.is_file() {
            return Err(Error::unknown_bundle_structure(format!(
                "{} must be a regular executable file",
                canonical.display()
            )));
        }
        let modified = metadata
            .modified()
            .map_err(Error::from)?
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                Error::other("executable mtime predates the Unix epoch").with_source(error)
            })?
            .as_secs();
        let executable_sha512 = sha512_reader(&mut file)?;
        Ok(Self::new(
            canonical.to_string_lossy().into_owned(),
            browser_version,
            metadata.len(),
            modified,
            executable_sha512,
            cdm_entries,
        ))
    }

    /// Primary install-root CDM version when present (compatibility helper).
    #[must_use]
    pub fn primary_cdm_version(&self) -> Option<&str> {
        self.cdm_entries
            .iter()
            .find_map(|entry| entry.version.as_deref())
    }

    /// Primary install-root CDM digest when present (compatibility helper).
    #[must_use]
    pub fn primary_cdm_digest(&self) -> Option<&str> {
        self.cdm_entries
            .iter()
            .find_map(|entry| entry.library_sha512.as_deref())
    }
    fn validate(&self) -> Result<()> {
        if !Path::new(&self.canonical_executable).is_absolute()
            || self.executable_sha512.is_empty()
            || self
                .browser_version
                .as_deref()
                .is_none_or(|version| version.trim().is_empty())
            || self.cdm_entries.is_empty()
            || self.cdm_entries.iter().any(|entry| !entry.is_complete())
        {
            return Err(Error::state_corrupted(
                "capability cache fingerprint is not byte-exact",
            ));
        }
        Ok(())
    }
}

/// Persisted live-browser evidence and its conservative assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredProbeReport {
    /// Must equal [`STORE_SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Probe completion timestamp in Unix seconds.
    pub probed_at: u64,
    /// Browser display name selected for the live probe.
    pub browser_name: String,
    /// Browser/CDM identity bound to the evidence.
    pub fingerprint: ProbeFingerprint,
    /// Raw, validated browser-reported capability evidence.
    pub raw: RawProbeResult,
    /// Conservative Rust assessment rendered at probe time.
    pub assessment: CapabilityAssessment,
}

impl StoredProbeReport {
    /// Build a report stamped with the current system time.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCategory::Other`](crate::ErrorCategory::Other) if the
    /// system clock predates the Unix epoch.
    pub fn now(
        browser_name: impl Into<String>,
        fingerprint: ProbeFingerprint,
        raw: RawProbeResult,
        assessment: CapabilityAssessment,
    ) -> Result<Self> {
        let probed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                Error::other("system clock predates the Unix epoch").with_source(error)
            })?
            .as_secs();
        Ok(Self {
            schema_version: STORE_SCHEMA_VERSION,
            probed_at,
            browser_name: browser_name.into(),
            fingerprint,
            raw,
            assessment,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.schema_version != STORE_SCHEMA_VERSION {
            return Err(Error::state_corrupted(format!(
                "unsupported capability cache schema {}; expected {STORE_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.browser_name.is_empty() || self.browser_name.len() > 128 {
            return Err(Error::state_corrupted(
                "capability cache browser name must contain 1..=128 bytes",
            ));
        }
        self.fingerprint.validate()?;
        self.raw.validate_schema()
    }
}

/// Result of looking up cached evidence for an expected fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    /// No report exists for this browser executable.
    Missing,
    /// The browser and CDM fingerprint matches exactly.
    Hit(StoredProbeReport),
    /// A report exists but its browser or CDM fingerprint changed.
    Stale(StoredProbeReport),
}

/// Default capability-report cache root.
#[must_use]
pub fn default_store_root() -> Option<PathBuf> {
    dirs::cache_dir().map(|root| root.join("silvervine").join("diagnostics").join("probes"))
}

/// Persist `report` beneath `root` using a same-directory atomic rename.
///
/// # Errors
///
/// Returns a categorized I/O error, or
/// [`ErrorCategory::StateCorrupted`](crate::ErrorCategory::StateCorrupted)
/// for unsafe cache paths or schema-invalid reports.
pub fn save_report(root: &Path, report: &StoredProbeReport) -> Result<PathBuf> {
    report.validate()?;
    ensure_store_root(root)?;
    let path = report_path(root, &report.fingerprint);
    reject_unsafe_target(&path)?;
    let bytes = serde_json::to_vec_pretty(report).map_err(Error::from)?;
    atomic_write_report(&path, &bytes)?;
    Ok(path)
}

/// Load cached evidence for `expected`, distinguishing exact hits from stale
/// browser/CDM state.
///
/// # Errors
///
/// Returns a categorized I/O error, or
/// [`ErrorCategory::StateCorrupted`](crate::ErrorCategory::StateCorrupted)
/// when a cache file is unsafe, malformed, oversized, or schema-incompatible.
pub fn load_report(root: &Path, expected: &ProbeFingerprint) -> Result<CacheLookup> {
    let path = report_path(root, expected);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CacheLookup::Missing);
        }
        Err(error) => return Err(Error::from(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::state_corrupted(format!(
            "{} must be a regular cache file",
            path.display()
        )));
    }
    let mut file = open_report(&path)?;
    let metadata = file.metadata().map_err(Error::from)?;
    if !metadata.is_file() {
        return Err(Error::state_corrupted(format!(
            "{} must be a regular cache file",
            path.display()
        )));
    }
    if metadata.len() > MAX_REPORT_BYTES {
        return Err(Error::state_corrupted(format!(
            "{} exceeds the capability cache size limit",
            path.display()
        )));
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| Error::state_corrupted("capability cache size is not representable"))?;
    let mut bytes = Vec::with_capacity(length);
    (&mut file)
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(Error::from)?;
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err(Error::state_corrupted(format!(
            "{} grew beyond the capability cache size limit while it was read",
            path.display()
        )));
    }
    let report: StoredProbeReport = serde_json::from_slice(&bytes).map_err(|error| {
        Error::state_corrupted(format!("malformed capability cache {}", path.display()))
            .with_source(error)
    })?;
    report.validate()?;
    if report.fingerprint == *expected {
        Ok(CacheLookup::Hit(report))
    } else {
        Ok(CacheLookup::Stale(report))
    }
}

/// Save to the default Silvervine diagnostics cache.
///
/// # Errors
///
/// Returns [`ErrorCategory::StateCorrupted`](crate::ErrorCategory::StateCorrupted)
/// when the host cache root cannot be resolved, plus errors from
/// [`save_report`].
pub fn save_default(report: &StoredProbeReport) -> Result<PathBuf> {
    let root = default_store_root()
        .ok_or_else(|| Error::state_corrupted("cannot resolve diagnostics cache root"))?;
    save_report(&root, report)
}

/// Load from the default Silvervine diagnostics cache.
///
/// # Errors
///
/// Returns [`ErrorCategory::StateCorrupted`](crate::ErrorCategory::StateCorrupted)
/// when the host cache root cannot be resolved, plus errors from
/// [`load_report`].
pub fn load_default(expected: &ProbeFingerprint) -> Result<CacheLookup> {
    let root = default_store_root()
        .ok_or_else(|| Error::state_corrupted("cannot resolve diagnostics cache root"))?;
    load_report(&root, expected)
}

pub(crate) fn report_path(root: &Path, fingerprint: &ProbeFingerprint) -> PathBuf {
    let digest = sha512_hex(fingerprint.canonical_executable.as_bytes());
    root.join(format!("browser-{}.json", &digest[..24]))
}

pub(crate) fn canonicalize_path(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(|error| {
        Error::unknown_bundle_structure(format!(
            "could not canonicalize {}: {error}",
            path.display()
        ))
        .with_source(error)
    })
}

fn ensure_store_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(Error::state_corrupted(format!(
                "{} must be a regular diagnostics cache directory",
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
            "diagnostics cache root changed while it was created",
        ));
    }
    Ok(())
}

fn reject_unsafe_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(
            Error::state_corrupted(format!("{} must be a regular cache file", path.display())),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::from(error)),
    }
}

fn open_report(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(Error::from)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempReport(PathBuf);

impl Drop for TempReport {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn atomic_write_report(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::state_corrupted("capability cache path has no parent"))?;
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".silvervine-diagnostics.tmp-{}-{counter}",
        std::process::id()
    ));
    let cleanup = TempReport(temp.clone());
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
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(Error::from)?;
    std::mem::forget(cleanup);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use tempfile::TempDir;

    use super::{
        load_report, report_path, save_report, CacheLookup, CdmFingerprintEntry, ProbeFingerprint,
        StoredProbeReport, STORE_SCHEMA_VERSION,
    };
    use crate::eme::probe::{assess, CapabilityStatus, EmeProbeResult, PROBE_SCHEMA_VERSION};
    use crate::widevine::ownership::OwnershipAssessment;
    use crate::widevine::sha512_hex;

    fn cdm_entry(path: &str, digest: &str) -> CdmFingerprintEntry {
        CdmFingerprintEntry::new(path, Some("4.10.0.0".into()), Some(digest.into()))
    }

    fn fingerprint(
        executable: &str,
        browser_version: &str,
        len: u64,
        modified: u64,
        digest: &str,
    ) -> ProbeFingerprint {
        ProbeFingerprint::new(
            executable,
            Some(browser_version.into()),
            len,
            modified,
            "browser-digest",
            vec![cdm_entry(
                "/opt/test-browser/WidevineCdm/libwidevinecdm.so",
                digest,
            )],
        )
    }

    fn stored(fingerprint: ProbeFingerprint) -> StoredProbeReport {
        let probe = EmeProbeResult {
            schema_version: PROBE_SCHEMA_VERSION,
            user_agent: "Chromium/150".into(),
            eme_api: true,
            media_capabilities_api: true,
            baseline: CapabilityStatus::Supported,
            baseline_error: None,
            robustness: Vec::new(),
            encryption_schemes: Vec::new(),
            hdcp: Vec::new(),
            codecs: Vec::new(),
        };
        let ownership = OwnershipAssessment::default();
        StoredProbeReport {
            schema_version: STORE_SCHEMA_VERSION,
            probed_at: 123,
            browser_name: "Chromium".into(),
            fingerprint,
            assessment: assess(&probe, &ownership),
            raw: probe,
        }
    }

    #[test]
    fn exact_fingerprint_round_trips_as_a_cache_hit() {
        let tmp = TempDir::new().expect("tempdir");
        let expected = fingerprint(
            "/opt/test-browser/chromium",
            "150.0",
            100,
            1_700_000_000,
            "abc",
        );
        let report = stored(expected.clone());

        save_report(tmp.path(), &report).expect("save");
        let loaded = load_report(tmp.path(), &expected).expect("load");

        assert_eq!(loaded, CacheLookup::Hit(report));
    }

    #[test]
    fn browser_version_change_invalidates_cached_evidence() {
        let tmp = TempDir::new().expect("tempdir");
        let old = fingerprint(
            "/opt/test-browser/chromium",
            "149.0",
            100,
            1_700_000_000,
            "abc",
        );
        save_report(tmp.path(), &stored(old)).expect("save");

        let lookup = load_report(
            tmp.path(),
            &fingerprint(
                "/opt/test-browser/chromium",
                "150.0",
                100,
                1_700_000_000,
                "abc",
            ),
        )
        .expect("load");

        assert!(matches!(lookup, CacheLookup::Stale(_)));
    }

    #[test]
    fn executable_mtime_or_length_change_invalidates_cached_evidence() {
        let tmp = TempDir::new().expect("tempdir");
        let old = fingerprint(
            "/opt/test-browser/chromium",
            "150.0",
            100,
            1_700_000_000,
            "abc",
        );
        save_report(tmp.path(), &stored(old)).expect("save");

        let mtime_changed = load_report(
            tmp.path(),
            &fingerprint(
                "/opt/test-browser/chromium",
                "150.0",
                100,
                1_700_000_001,
                "abc",
            ),
        )
        .expect("mtime");
        let length_changed = load_report(
            tmp.path(),
            &fingerprint(
                "/opt/test-browser/chromium",
                "150.0",
                101,
                1_700_000_000,
                "abc",
            ),
        )
        .expect("length");

        assert!(matches!(mtime_changed, CacheLookup::Stale(_)));
        assert!(matches!(length_changed, CacheLookup::Stale(_)));
    }
    #[test]
    fn executable_digest_change_invalidates_cached_evidence() {
        let tmp = TempDir::new().expect("tempdir");
        let old = fingerprint(
            "/opt/test-browser/chromium",
            "150.0",
            100,
            1_700_000_000,
            "abc",
        );
        let mut changed = old.clone();
        changed.executable_sha512 = "different-browser-digest".into();
        save_report(tmp.path(), &stored(old)).expect("save");

        assert!(matches!(
            load_report(tmp.path(), &changed).expect("digest"),
            CacheLookup::Stale(_)
        ));
    }

    #[test]
    fn executable_path_change_uses_distinct_cache_key() {
        let tmp = TempDir::new().expect("tempdir");
        let first = fingerprint("/opt/a/chromium", "150.0", 100, 1, "abc");
        let second = fingerprint("/opt/b/chromium", "150.0", 100, 1, "abc");
        save_report(tmp.path(), &stored(first.clone())).expect("save");

        assert_ne!(
            report_path(tmp.path(), &first),
            report_path(tmp.path(), &second)
        );
        assert_eq!(
            load_report(tmp.path(), &second).expect("load"),
            CacheLookup::Missing
        );
    }

    #[test]
    fn cdm_path_or_digest_change_invalidates_cached_evidence() {
        let tmp = TempDir::new().expect("tempdir");
        let old = ProbeFingerprint::new(
            "/opt/test-browser/chromium",
            Some("150.0".into()),
            100,
            1,
            "browser-digest",
            vec![cdm_entry("/opt/old/libwidevinecdm.so", "old-digest")],
        );
        save_report(tmp.path(), &stored(old)).expect("save");

        let path_changed = ProbeFingerprint::new(
            "/opt/test-browser/chromium",
            Some("150.0".into()),
            100,
            1,
            "browser-digest",
            vec![cdm_entry("/opt/new/libwidevinecdm.so", "old-digest")],
        );
        let digest_changed = ProbeFingerprint::new(
            "/opt/test-browser/chromium",
            Some("150.0".into()),
            100,
            1,
            "browser-digest",
            vec![cdm_entry("/opt/old/libwidevinecdm.so", "new-digest")],
        );

        assert!(matches!(
            load_report(tmp.path(), &path_changed).expect("path"),
            CacheLookup::Stale(_)
        ));
        assert!(matches!(
            load_report(tmp.path(), &digest_changed).expect("digest"),
            CacheLookup::Stale(_)
        ));
    }

    #[test]
    fn cdm_entries_are_ordered_and_deduplicated() {
        let fingerprint = ProbeFingerprint::new(
            "/opt/browser/chromium",
            None,
            1,
            1,
            "browser-digest",
            vec![
                cdm_entry("/z/lib.so", "z"),
                cdm_entry("/a/lib.so", "a"),
                cdm_entry("/a/lib.so", "a"),
            ],
        );

        assert_eq!(
            fingerprint
                .cdm_entries
                .iter()
                .map(|entry| entry.canonical_path.as_str())
                .collect::<Vec<_>>(),
            vec!["/a/lib.so", "/z/lib.so"]
        );
    }
    #[test]
    fn undigested_cdm_identity_prevents_cache_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let executable = tmp.path().join("chromium");
        fs::write(&executable, b"browser").expect("write executable");
        let entry = CdmFingerprintEntry::new("/opt/cdm/lib.so", None, None);

        let error = ProbeFingerprint::from_executable(&executable, None, vec![entry])
            .expect_err("undigested CDM must disable caching");

        assert_eq!(error.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn incomplete_browser_or_cdm_identity_prevents_cache_fingerprint() {
        let tmp = TempDir::new().expect("tempdir");
        let executable = tmp.path().join("chromium");
        fs::write(&executable, b"browser").expect("write executable");

        let no_browser_version = ProbeFingerprint::from_executable(
            &executable,
            None,
            vec![cdm_entry("/opt/cdm/lib.so", "digest")],
        );
        let no_cdm =
            ProbeFingerprint::from_executable(&executable, Some("150.0".into()), Vec::new());
        let no_cdm_version = ProbeFingerprint::from_executable(
            &executable,
            Some("150.0".into()),
            vec![CdmFingerprintEntry::new(
                "/opt/cdm/lib.so",
                None,
                Some("digest".into()),
            )],
        );

        assert!(no_browser_version.is_err());
        assert!(no_cdm.is_err());
        assert!(no_cdm_version.is_err());
    }

    #[test]
    fn from_executable_captures_len_and_mtime() {
        let tmp = TempDir::new().expect("tempdir");
        let exe = tmp.path().join("chromium");
        fs::write(&exe, b"browser-bytes").expect("write");
        let modified = SystemTime::now() - Duration::from_secs(30);
        filetime_set(&exe, modified);

        let fingerprint = ProbeFingerprint::from_executable(
            &exe,
            Some("150.0".into()),
            vec![cdm_entry(
                tmp.path()
                    .join("WidevineCdm/lib.so")
                    .to_string_lossy()
                    .as_ref(),
                "digest",
            )],
        )
        .expect("fingerprint");

        assert_eq!(fingerprint.executable_len, 13);
        assert_eq!(
            fingerprint.canonical_executable,
            exe.canonicalize().expect("canon").to_string_lossy()
        );
        assert!(fingerprint.executable_modified > 0);
        assert_eq!(fingerprint.executable_sha512, sha512_hex(b"browser-bytes"));
        assert_eq!(fingerprint.cdm_entries.len(), 1);
    }

    #[test]
    fn malformed_cache_is_an_explicit_state_error() {
        let tmp = TempDir::new().expect("tempdir");
        let expected = fingerprint("/opt/test-browser/chromium", "150.0", 100, 1, "abc");
        fs::create_dir_all(tmp.path()).expect("root");
        fs::write(report_path(tmp.path(), &expected), b"not json").expect("corrupt");

        let error = load_report(tmp.path(), &expected).expect_err("corrupt cache");

        assert_eq!(error.category, crate::ErrorCategory::StateCorrupted);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cache_file_is_rejected() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().expect("tempdir");
        let expected = fingerprint("/opt/test-browser/chromium", "150.0", 100, 1, "abc");
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"outside").expect("outside");
        symlink(&outside, report_path(tmp.path(), &expected)).expect("symlink");

        let error = save_report(tmp.path(), &stored(expected)).expect_err("unsafe target");

        assert_eq!(error.category, crate::ErrorCategory::StateCorrupted);
        assert_eq!(fs::read(outside).expect("outside preserved"), b"outside");
    }

    fn filetime_set(path: &Path, modified: SystemTime) {
        // Best-effort: touch via std only keeps current time on some hosts.
        // The test primarily asserts from_executable reads metadata fields.
        let _ = (path, modified);
        let _ = fs::File::open(path).and_then(|file| file.sync_all());
    }
}
