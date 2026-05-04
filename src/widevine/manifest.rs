//! Mozilla Widevine manifest (`widevinecdm.json`) parsing + fetch.
//!
//! ## Schema reference
//!
//! Mozilla publishes a JSON manifest at the Mercurial mozilla-central tree:
//!
//! ```text
//! https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/content/gmp-sources/widevinecdm.json
//! ```
//!
//! And mirrored on GitHub:
//!
//! ```text
//! https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/toolkit/content/gmp-sources/widevinecdm.json
//! ```
//!
//! The shape (per the live file at the time of Phase 1 implementation) is:
//!
//! ```json
//! {
//!   "hashFunction": "sha512",
//!   "name": "Widevine-4.10.2934.0",
//!   "schema_version": 1000,
//!   "vendors": {
//!     "gmp-widevinecdm": {
//!       "platforms": {
//!         "Linux_x86_64-gcc3":      { "fileUrl": "...", "filesize": 18257362, "hashValue": "..." },
//!         "Darwin_aarch64-gcc3":    { "fileUrl": "...", ... },
//!         "Darwin_x86_64-gcc3":     { "alias": "Darwin_x86_64-gcc3-u-i386-x86_64" },
//!         "Darwin_x86_64-gcc3-u-i386-x86_64": { "fileUrl": "...", ... },
//!         "WINNT_*-msvc":           { "fileUrl": "...", ... }
//!       },
//!       "version": "4.10.2934.0"
//!     }
//!   }
//! }
//! ```
//!
//! Some entries are **aliases** — they have only an `alias` key pointing
//! at another platform key. [`Manifest::resolve_platform`] follows aliases
//! transparently.
//!
//! ## URL fallback chain
//!
//! Per the spec ("Mozilla manifest URL fallback chain"):
//!
//! 1. `https://hg.mozilla.org/...`
//! 2. `https://raw.githubusercontent.com/...`
//! 3. `~/.cache/neon/last-manifest.json` (TTL 24h)
//!
//! [`fetch_manifest`] walks the chain in order. On any successful network
//! fetch it writes the parsed JSON back to the cache so step 3 stays warm.
//!
//! ## What this module does NOT do
//!
//! * No CRX3 download — that's Phase 2 in `widevine::download`.
//! * No SHA-512 verification of the CRX3 — also Phase 2.
//! * No staging or extraction — Phase 2 in `widevine::extract` / `cache`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, ErrorCategory, Result};

/// TTL for the cached `last-manifest.json` file. Matches the spec
/// (`~/.cache/neon/last-manifest.json (TTL 24h)`).
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// HTTP request timeout per fallback URL. The chain has three steps; we
/// don't want any single step to hang for too long.
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

/// Top-level manifest shape.
///
/// We deserialize the small subset we use; unknown fields (e.g.
/// `hashFunction`, `schema_version`, `name`) are tolerated via serde's
/// default behavior of ignoring them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    /// Map of vendor name → entry. We only consume `gmp-widevinecdm`.
    pub vendors: HashMap<String, GmpVendor>,
    /// Mozilla's hash function name (always `"sha512"` in practice).
    /// Carried through so we can record what we verified against.
    #[serde(default, rename = "hashFunction")]
    pub hash_function: Option<String>,
    /// Mozilla's release name (e.g. `"Widevine-4.10.2934.0"`).
    #[serde(default)]
    pub name: Option<String>,
}

/// One vendor in the manifest. For Neon, the only vendor of interest is
/// `gmp-widevinecdm`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GmpVendor {
    /// Map from platform key → entry (or alias).
    pub platforms: HashMap<String, PlatformEntry>,
    /// Vendor version string (e.g. `"4.10.2934.0"`).
    pub version: String,
}

/// A single platform entry. Either a "real" entry with a download URL,
/// hash, and size — or an `alias` redirecting to another platform key.
///
/// Serde's `untagged` variant tag makes this represent the raw JSON's
/// either-or shape directly.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PlatformEntry {
    /// Concrete entry. Mozilla also includes `mirrorUrls` in some entries
    /// — we capture those for the download flow (Phase 2).
    Concrete {
        /// Direct CRX3 download URL.
        #[serde(rename = "fileUrl")]
        file_url: String,
        /// Optional alternate download URLs (Mozilla's mirror list).
        #[serde(default, rename = "mirrorUrls")]
        mirror_urls: Vec<String>,
        /// Expected file size in bytes.
        #[serde(default)]
        filesize: Option<u64>,
        /// SHA-512 hex digest (matches the manifest's `hashFunction`,
        /// always `sha512` in practice).
        #[serde(rename = "hashValue")]
        hash_value: String,
    },
    /// An alias to another platform key. e.g.
    /// `"Linux_x86_64-gcc3-asan": { "alias": "Linux_x86_64-gcc3" }`.
    Alias {
        /// Target platform key.
        alias: String,
    },
}

/// Platforms Neon supports in V1.
///
/// V1 explicitly excludes Windows (planned V2) and ARM64 Linux (cut for
/// V1 — see spec non-goals).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// `Linux_x86_64-gcc3`.
    LinuxX86_64,
    /// `Darwin_aarch64-gcc3` (Apple Silicon).
    DarwinAarch64,
    /// `Darwin_x86_64-gcc3-u-i386-x86_64` (Intel Mac).
    DarwinX86_64,
}

impl Platform {
    /// Stable Mozilla platform-key string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "Linux_x86_64-gcc3",
            Self::DarwinAarch64 => "Darwin_aarch64-gcc3",
            Self::DarwinX86_64 => "Darwin_x86_64-gcc3-u-i386-x86_64",
        }
    }
}

/// Resolve the Mozilla platform key for the host the binary is running on.
///
/// # Errors
///
/// Returns [`ErrorCategory::UnsupportedPlatform`] if the OS/arch combination
/// isn't in V1's support matrix.
// `clippy::needless_return` fires on the cfg-guarded early returns, but
// they're load-bearing: each `cfg` block compiles into the binary
// independently and falls through to the next branch only when the
// matching condition is false. Restructuring as `cfg!` macros loses the
// "compile only the right branch" property we want.
#[allow(clippy::needless_return)]
pub fn current_platform_key() -> Result<Platform> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return Ok(Platform::LinuxX86_64);
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return Ok(Platform::DarwinAarch64);
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return Ok(Platform::DarwinX86_64);
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
    )))]
    {
        Err(Error::unsupported_platform(format!(
            "no Mozilla platform key for OS={} ARCH={}",
            std::env::consts::OS,
            std::env::consts::ARCH,
        )))
    }
}

impl Manifest {
    /// Look up the `gmp-widevinecdm` vendor block.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCategory::StateCorrupted`] if the manifest does not
    /// contain a `gmp-widevinecdm` entry — that's a schema break we don't
    /// expect from Mozilla in practice.
    pub fn widevine(&self) -> Result<&GmpVendor> {
        self.vendors.get("gmp-widevinecdm").ok_or_else(|| {
            Error::state_corrupted("manifest missing required 'gmp-widevinecdm' vendor")
        })
    }

    /// Resolve a platform key to its concrete entry, transparently
    /// following one or more `alias` redirects.
    ///
    /// # Errors
    ///
    /// * [`ErrorCategory::UnsupportedPlatform`] — the platform key is not
    ///   present in the manifest.
    /// * [`ErrorCategory::StateCorrupted`] — alias chain exceeds 8 hops
    ///   (almost certainly a malformed manifest).
    pub fn resolve_platform(&self, platform: Platform) -> Result<&PlatformEntry> {
        self.resolve_platform_key(platform.as_str())
    }

    /// Like [`Manifest::resolve_platform`] but takes the raw string key,
    /// for tests and for callers that need to inspect Windows / asan keys
    /// not in our [`Platform`] enum.
    ///
    /// # Errors
    ///
    /// See [`Manifest::resolve_platform`].
    pub fn resolve_platform_key(&self, key: &str) -> Result<&PlatformEntry> {
        let vendor = self.widevine()?;
        let mut current = key;
        // Bound the alias chain so a malformed manifest can't make us loop.
        for _ in 0..8 {
            match vendor.platforms.get(current) {
                Some(entry @ PlatformEntry::Concrete { .. }) => return Ok(entry),
                Some(PlatformEntry::Alias { alias }) => current = alias,
                None => {
                    return Err(Error::unsupported_platform(format!(
                        "manifest has no entry for platform key '{current}'"
                    )));
                }
            }
        }
        Err(Error::state_corrupted(format!(
            "alias chain starting at '{key}' exceeds 8 hops; manifest is malformed"
        )))
    }
}

/// Parse a manifest JSON byte slice.
///
/// # Errors
///
/// [`ErrorCategory::StateCorrupted`] if the bytes are not valid JSON or
/// don't match the expected schema.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest> {
    serde_json::from_slice(bytes).map_err(Error::from)
}

/// Default URL fallback chain (per spec).
///
/// Returned as a `Vec` (not a const) because [`Url::parse`] is not
/// `const`-evaluable.
fn default_urls() -> Vec<Url> {
    let primary = "https://hg.mozilla.org/mozilla-central/raw-file/tip/toolkit/content/gmp-sources/widevinecdm.json";
    let secondary = "https://raw.githubusercontent.com/mozilla-firefox/firefox/refs/heads/main/toolkit/content/gmp-sources/widevinecdm.json";
    // Both URLs are static and known-good; if these ever fail to parse,
    // the binary itself is corrupt.
    let primary_url = Url::parse(primary).expect("default primary URL is valid");
    let secondary_url = Url::parse(secondary).expect("default secondary URL is valid");
    vec![primary_url, secondary_url]
}

/// Compute the on-disk path for the cached manifest fallback (`step 3` of
/// the chain). Returns `None` if `dirs::cache_dir()` cannot be resolved
/// (e.g. running with no `HOME`).
#[must_use]
pub fn cached_manifest_path() -> Option<PathBuf> {
    let cache = dirs::cache_dir()?;
    Some(cache.join("neon").join("last-manifest.json"))
}

/// Fetch the manifest using the full default URL chain plus the on-disk
/// 24h cache fallback. This is the convenience entry point most callers
/// (CLI, daemon) want.
///
/// # Errors
///
/// [`ErrorCategory::ManifestFetchFailed`] if every URL in the chain fails
/// AND the on-disk cache is missing or stale. The error's `source` chains
/// through the network errors so `--verbose` output can show what went
/// wrong.
pub fn fetch_manifest() -> Result<Manifest> {
    let urls = default_urls();
    fetch_manifest_with(&urls, cached_manifest_path().as_deref(), CACHE_TTL)
}

/// Fetch the manifest with a caller-specified URL chain and cache config.
///
/// This is the testable form: integration tests pass in a `urls` slice
/// pointing at a local mock server, and a `cache_path` pointing at a
/// `tempfile::TempDir` so the test doesn't touch the user's real cache.
///
/// # Behavior
///
/// 1. Try each URL in `urls` in order. On the first successful parse,
///    write the bytes to `cache_path` (if `Some`) and return.
/// 2. If all URLs fail and `cache_path` exists and was modified within
///    `cache_ttl`, return the cached manifest.
/// 3. Otherwise return [`ErrorCategory::ManifestFetchFailed`].
///
/// # Errors
///
/// See above. The returned error's `source` chains through the most recent
/// network failure for diagnostic purposes.
pub fn fetch_manifest_with(
    urls: &[Url],
    cache_path: Option<&Path>,
    cache_ttl: Duration,
) -> Result<Manifest> {
    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| Error::network("failed to construct HTTP client").with_source(e))?;

    let mut last_network_failure: Option<Error> = None;
    for url in urls {
        match try_fetch_one(&client, url) {
            Ok(bytes) => {
                let manifest = parse_manifest(&bytes)?;
                // Best-effort cache write — failures here shouldn't fail
                // the whole fetch (we have a perfectly good response in hand).
                if let Some(path) = cache_path {
                    let _ = write_cache(path, &bytes);
                }
                return Ok(manifest);
            }
            Err(e) => {
                last_network_failure = Some(e);
            }
        }
    }

    // All network attempts exhausted; fall back to disk cache if recent.
    if let Some(path) = cache_path {
        if let Some(bytes) = read_recent_cache(path, cache_ttl) {
            return parse_manifest(&bytes);
        }
    }

    let mut err = Error::manifest_fetch_failed(format!(
        "all {} manifest URLs failed and no recent cache available",
        urls.len()
    ));
    if let Some(network_err) = last_network_failure {
        err.source = Some(Box::new(network_err));
    }
    Err(err)
}

/// Fetch one URL and return the raw response bytes.
fn try_fetch_one(client: &reqwest::blocking::Client, url: &Url) -> Result<Vec<u8>> {
    let response = client
        .get(url.clone())
        .send()
        .map_err(|e| Error::network(format!("GET {url} failed")).with_source(e))?;
    if !response.status().is_success() {
        return Err(Error::network(format!(
            "GET {url} returned HTTP {}",
            response.status()
        )));
    }
    let bytes = response
        .bytes()
        .map_err(|e| Error::network(format!("read body from {url}")).with_source(e))?;
    Ok(bytes.to_vec())
}

/// Write cached manifest bytes to disk, creating the parent directory if
/// missing. Best-effort — caller ignores failures.
fn write_cache(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Read cached manifest bytes if the file exists AND was modified within
/// `ttl`. Returns `None` if missing, stale, or unreadable — those all
/// fall through to the "every URL failed" branch.
fn read_recent_cache(path: &Path, ttl: Duration) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age > ttl {
        return None;
    }
    std::fs::read(path).ok()
}

// `ErrorCategory` is not used directly here, but documenting it inline
// (and re-exporting for tests below) keeps the module self-contained.
#[allow(unused_imports)]
use ErrorCategory as _;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Read the committed fixture JSON for use in unit tests.
    fn fixture_bytes() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("widevinecdm.json");
        std::fs::read(&path).unwrap_or_else(|e| {
            panic!("could not read manifest fixture at {}: {e}", path.display())
        })
    }

    #[test]
    fn parses_real_manifest_fixture() {
        let manifest = parse_manifest(&fixture_bytes()).expect("fixture parses");
        let vendor = manifest.widevine().expect("has gmp-widevinecdm");
        assert!(!vendor.version.is_empty());
        // Real shape: at least these platforms must be present.
        assert!(vendor.platforms.contains_key("Linux_x86_64-gcc3"));
        assert!(vendor.platforms.contains_key("Darwin_aarch64-gcc3"));
        assert!(vendor
            .platforms
            .contains_key("Darwin_x86_64-gcc3-u-i386-x86_64"));
    }

    #[test]
    fn resolves_concrete_linux_platform() {
        let manifest = parse_manifest(&fixture_bytes()).expect("fixture parses");
        let entry = manifest
            .resolve_platform(Platform::LinuxX86_64)
            .expect("Linux entry");
        match entry {
            PlatformEntry::Concrete {
                file_url,
                hash_value,
                ..
            } => {
                assert!(file_url.starts_with("https://"));
                assert_eq!(hash_value.len(), 128, "SHA-512 hex is 128 chars");
            }
            PlatformEntry::Alias { alias } => {
                panic!("expected concrete Linux entry, got alias to {alias}");
            }
        }
    }

    /// `Darwin_x86_64-gcc3` is an alias to `Darwin_x86_64-gcc3-u-i386-x86_64`
    /// in the live manifest. Make sure following the alias works.
    #[test]
    fn resolves_alias_chain_for_darwin_x86_64() {
        let manifest = parse_manifest(&fixture_bytes()).expect("fixture parses");
        // Use the raw string variant since Platform::DarwinX86_64 already
        // points at the canonical key — we want to verify the alias hop.
        let via_alias = manifest
            .resolve_platform_key("Darwin_x86_64-gcc3")
            .expect("alias resolution");
        let direct = manifest
            .resolve_platform_key("Darwin_x86_64-gcc3-u-i386-x86_64")
            .expect("direct lookup");
        // Both should return concrete entries with the same fileUrl.
        match (via_alias, direct) {
            (
                PlatformEntry::Concrete {
                    file_url: url_a, ..
                },
                PlatformEntry::Concrete {
                    file_url: url_b, ..
                },
            ) => {
                assert_eq!(url_a, url_b, "alias should resolve to same concrete entry");
            }
            _ => panic!("both resolutions must be concrete entries"),
        }
    }

    #[test]
    fn unknown_platform_key_returns_unsupported() {
        let manifest = parse_manifest(&fixture_bytes()).expect("fixture parses");
        let err = manifest
            .resolve_platform_key("Plan9_riscv-gcc7")
            .expect_err("unknown key should fail");
        assert_eq!(err.category, ErrorCategory::UnsupportedPlatform);
    }

    #[test]
    fn alias_chain_too_long_is_state_corrupted() {
        // Build a synthetic manifest whose aliases form a 9-deep chain.
        let mut platforms: HashMap<String, PlatformEntry> = HashMap::new();
        for i in 0..9 {
            platforms.insert(
                format!("k{i}"),
                PlatformEntry::Alias {
                    alias: format!("k{}", i + 1),
                },
            );
        }
        // The terminal "k9" key is missing; chain length itself trips the
        // bound first.
        platforms.insert(
            "real".to_string(),
            PlatformEntry::Concrete {
                file_url: "https://example.invalid/x.crx3".into(),
                mirror_urls: vec![],
                filesize: None,
                hash_value: "0".repeat(128),
            },
        );
        let manifest = Manifest {
            hash_function: Some("sha512".into()),
            name: Some("Widevine-test".into()),
            vendors: HashMap::from([(
                "gmp-widevinecdm".to_string(),
                GmpVendor {
                    platforms,
                    version: "1.2.3.4".into(),
                },
            )]),
        };
        let err = manifest
            .resolve_platform_key("k0")
            .expect_err("9-hop chain should error");
        assert_eq!(err.category, ErrorCategory::StateCorrupted);
    }

    #[test]
    fn malformed_json_is_state_corrupted() {
        let err = parse_manifest(b"not json").expect_err("garbage should fail to parse");
        assert_eq!(err.category, ErrorCategory::StateCorrupted);
    }

    #[test]
    fn missing_widevine_vendor_is_state_corrupted() {
        let manifest = Manifest {
            hash_function: None,
            name: None,
            vendors: HashMap::new(),
        };
        let err = manifest.widevine().expect_err("missing vendor");
        assert_eq!(err.category, ErrorCategory::StateCorrupted);
    }

    #[test]
    fn current_platform_key_returns_a_supported_value() {
        // On Linux/macOS x86_64/aarch64 the call returns Ok; on other
        // arches it returns UnsupportedPlatform. Either way it doesn't
        // panic. Just exercise the code path.
        let _ = current_platform_key();
    }

    #[test]
    fn cached_manifest_path_is_under_xdg_cache() {
        if let Some(path) = cached_manifest_path() {
            // Always ends in `neon/last-manifest.json`.
            let suffix = std::path::Path::new("neon").join("last-manifest.json");
            assert!(
                path.ends_with(&suffix),
                "expected cached manifest path to end with {} (got {})",
                suffix.display(),
                path.display()
            );
        }
        // If `dirs::cache_dir()` returned None (no HOME), we just don't
        // assert anything — that's a valid environment for the binary.
    }

    /// `fetch_manifest_with` falls back to disk cache when every URL fails.
    /// We use the literal <http://127.0.0.1:1/nope> URL (port 1 is in
    /// privileged range and almost always rejects connections) so the
    /// network step deterministically fails without external network
    /// dependencies.
    #[test]
    fn falls_back_to_disk_cache_on_network_failure() {
        let tmp = TempDir::new().expect("tempdir");
        let cache_path = tmp.path().join("last-manifest.json");
        // Pre-seed the cache with the fixture.
        fs::write(&cache_path, fixture_bytes()).expect("seed cache");

        let bad_url = Url::parse("http://127.0.0.1:1/nope").expect("url parse");
        let manifest =
            fetch_manifest_with(&[bad_url], Some(&cache_path), CACHE_TTL).expect("disk fallback");
        assert!(!manifest.widevine().expect("vendor").version.is_empty());
    }

    #[test]
    fn returns_manifest_fetch_failed_when_chain_and_cache_both_empty() {
        let tmp = TempDir::new().expect("tempdir");
        let cache_path = tmp.path().join("missing.json"); // does not exist
        let bad_url = Url::parse("http://127.0.0.1:1/nope").expect("url parse");
        let err = fetch_manifest_with(&[bad_url], Some(&cache_path), CACHE_TTL)
            .expect_err("both should fail");
        assert_eq!(err.category, ErrorCategory::ManifestFetchFailed);
    }

    #[test]
    fn stale_cache_is_ignored() {
        let tmp = TempDir::new().expect("tempdir");
        let cache_path = tmp.path().join("stale.json");
        fs::write(&cache_path, fixture_bytes()).expect("seed cache");
        // Backdate the file. We use the platform's `set_modified` if
        // available; otherwise we just skip the assertion (cache is "fresh"
        // by virtue of being just written).
        let one_year_ago = SystemTime::now() - Duration::from_secs(365 * 86_400);
        if let Ok(file) = fs::OpenOptions::new().write(true).open(&cache_path) {
            // `set_modified` exists on Rust 1.75 (our MSRV).
            let _ = file.set_modified(one_year_ago);
        }
        let bad_url = Url::parse("http://127.0.0.1:1/nope").expect("url parse");
        let outcome = fetch_manifest_with(
            &[bad_url],
            Some(&cache_path),
            Duration::from_secs(60), // 60s TTL ≪ 1 year
        );
        let err = outcome.expect_err("stale cache should not be honored");
        assert_eq!(err.category, ErrorCategory::ManifestFetchFailed);
    }

    #[test]
    fn platform_as_str_is_stable() {
        assert_eq!(Platform::LinuxX86_64.as_str(), "Linux_x86_64-gcc3");
        assert_eq!(Platform::DarwinAarch64.as_str(), "Darwin_aarch64-gcc3");
        assert_eq!(
            Platform::DarwinX86_64.as_str(),
            "Darwin_x86_64-gcc3-u-i386-x86_64"
        );
    }

    #[test]
    fn default_urls_has_both_endpoints() {
        let urls = default_urls();
        assert_eq!(urls.len(), 2);
        assert!(urls[0].host_str().expect("host").contains("hg.mozilla.org"));
        assert!(urls[1]
            .host_str()
            .expect("host")
            .contains("raw.githubusercontent.com"));
    }

    /// Spin up an in-process HTTP/1.1 stub server on `127.0.0.1:0`,
    /// serving the fixture on a single GET. Returns the URL once the
    /// listener is bound.
    ///
    /// We hand-roll the HTTP because pulling in `tiny_http`/`hyper-test`
    /// crates for one test would bloat the dep graph. The protocol we
    /// implement is "read the request line + headers (don't care what
    /// they say), then write a fixed 200 OK response with the fixture
    /// body". `reqwest` is happy with that.
    fn spawn_fixture_server(body: Vec<u8>) -> Url {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind random port");
        let local_addr = listener.local_addr().expect("local_addr");
        thread::spawn(move || {
            // Serve until the test process tears down. We accept N
            // connections sequentially; the test only needs one.
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                // Read request line + headers (ignore bodies).
                let mut reader = BufReader::new(stream.try_clone().expect("clone for read"));
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line == "\r\n" || line == "\n" || line.is_empty() {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
        Url::parse(&format!("http://{local_addr}/widevinecdm.json"))
            .expect("url parse for stub server")
    }

    /// Happy-path: a primary URL that responds with the fixture body
    /// gets parsed into a manifest, and the parsed bytes are also
    /// written back to the cache file.
    #[test]
    fn fetch_manifest_with_returns_first_successful_url() {
        let url = spawn_fixture_server(fixture_bytes());
        let tmp = TempDir::new().expect("tempdir");
        let cache_path = tmp.path().join("cache.json");

        let manifest = fetch_manifest_with(&[url], Some(&cache_path), CACHE_TTL)
            .expect("happy path must succeed");
        assert!(!manifest.widevine().expect("vendor").version.is_empty());
        // The cache should have been populated.
        let cached = std::fs::read(&cache_path).expect("cache file written");
        assert_eq!(cached, fixture_bytes());
    }

    /// A failing primary URL should fall through to a working secondary.
    #[test]
    fn fetch_manifest_with_falls_through_to_working_secondary() {
        let bad = Url::parse("http://127.0.0.1:1/missing").expect("url");
        let good = spawn_fixture_server(fixture_bytes());
        let manifest =
            fetch_manifest_with(&[bad, good], None, CACHE_TTL).expect("secondary must win");
        assert!(!manifest.widevine().expect("vendor").version.is_empty());
    }

    /// A non-2xx HTTP response is treated as a network failure.
    #[test]
    fn fetch_manifest_with_handles_non_2xx_response() {
        // Spawn a server that always returns 404.
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let local = listener.local_addr().expect("local_addr");
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line == "\r\n" || line == "\n" || line.is_empty() {
                        break;
                    }
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
        let url = Url::parse(&format!("http://{local}/")).expect("url");
        let err =
            fetch_manifest_with(&[url], None, CACHE_TTL).expect_err("404 with no cache must fail");
        assert_eq!(err.category, ErrorCategory::ManifestFetchFailed);
    }
}
