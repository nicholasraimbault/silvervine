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
//! The manifest shape is:
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
//! ## Authenticated URL fallback chain
//!
//! [`fetch_manifest`] tries the fixed Mozilla HTTPS origins in order:
//!
//! 1. `https://hg.mozilla.org/...`
//! 2. `https://raw.githubusercontent.com/...`
//!
//! Each origin attempt covers download **and** parse/schema validation.
//! Transport failures, non-success HTTP status, and malformed/schema-invalid
//! bodies all continue to the next fixed origin. A successful response may be
//! written as a diagnostic snapshot, but mutable on-disk snapshots are never
//! read back to authorize executable CDM content.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, ErrorCategory, Result};

/// Legacy manifest snapshot freshness value retained for API compatibility.
///
/// Mutable snapshots are write-only and never used as executable-content
/// authenticity roots.
pub const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// HTTP request timeout per origin.
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

/// Minimal schema for a CDM bundle's installed `manifest.json`.
///
/// Chromium extension manifests contain many fields, but Silvervine only
/// needs the version. Serde ignores all other fields without allocating a
/// dynamic JSON tree.
#[derive(Debug, Deserialize)]
struct InstalledCdmManifest {
    version: String,
}

/// Stream an installed CDM manifest and return its version.
pub(crate) fn read_installed_cdm_version(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).map_err(|error| {
        Error::from(error).with_context(format!(
            "could not open installed Widevine manifest {}",
            path.display()
        ))
    })?;
    let manifest: InstalledCdmManifest = serde_json::from_reader(std::io::BufReader::new(file))
        .map_err(|error| {
            Error::from(error).with_context(format!(
                "could not parse installed Widevine manifest {}",
                path.display()
            ))
        })?;
    Ok(manifest.version)
}

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

/// One vendor in the manifest. For Silvervine, the only vendor of interest is
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
    /// Concrete entry. Mozilla also includes `mirrorUrls` in some entries,
    /// which are retained for download fallback.
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

/// Platforms Silvervine supports in V1.
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

/// Compute the path for the best-effort manifest diagnostic snapshot.
///
/// Returns `None` if `dirs::cache_dir()` cannot be resolved.
#[must_use]
pub fn cached_manifest_path() -> Option<PathBuf> {
    let cache = dirs::cache_dir()?;
    Some(cache.join("silvervine").join("last-manifest.json"))
}

/// Fetch a fresh manifest from the fixed Mozilla HTTPS origins.
///
/// Successful bytes are retained as a best-effort diagnostic snapshot. The
/// snapshot is never read back: if both origins fail (transport **or**
/// parse/schema), this function fails closed rather than allowing mutable
/// cache data to authorize native code.
///
/// # Errors
///
/// [`ErrorCategory::ManifestFetchFailed`] if every HTTPS origin fails. The
/// error's `source` retains the last per-origin failure (network or parse)
/// for verbose diagnostics — never surfaces a bare
/// [`ErrorCategory::StateCorrupted`] from a single origin.
pub fn fetch_manifest() -> Result<Manifest> {
    let urls = default_urls();
    fetch_manifest_with(&urls, cached_manifest_path().as_deref(), CACHE_TTL)
}

/// Fetch a manifest from a caller-specified URL chain.
///
/// A successful response is written to `cache_path` when provided. The
/// `cache_ttl` argument is retained for API compatibility, but snapshots are
/// deliberately write-only and never become executable-content trust roots.
///
/// # Behavior
///
/// 1. Try each URL in order (download + parse/schema validation as one attempt).
/// 2. On the first fully valid response, optionally snapshot its exact bytes
///    and return the parsed manifest.
/// 3. Transport, HTTP status, and parse/schema failures all continue to the
///    next URL.
/// 4. If every URL fails, return [`ErrorCategory::ManifestFetchFailed`] with
///    the last per-origin failure as `source`.
///
/// # Errors
///
/// See above. The returned error's category is always
/// [`ErrorCategory::ManifestFetchFailed`] when the chain is exhausted; parse
/// corruption from one origin is not leaked as the top-level category.
pub fn fetch_manifest_with(
    urls: &[Url],
    cache_path: Option<&Path>,
    _cache_ttl: Duration,
) -> Result<Manifest> {
    let client = reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| Error::network("failed to construct HTTP client").with_source(e))?;

    let mut last_failure: Option<Error> = None;
    for url in urls {
        match try_fetch_one(&client, url) {
            Ok((manifest, bytes)) => {
                // Best-effort cache write — failures here shouldn't fail
                // the whole fetch (we have a perfectly good response in hand).
                // Only the exact bytes of the first fully parsed valid
                // response are retained; snapshots are never read back.
                if let Some(path) = cache_path {
                    let _ = write_cache(path, &bytes);
                }
                return Ok(manifest);
            }
            Err(e) => {
                last_failure = Some(e);
            }
        }
    }

    let mut err = Error::manifest_fetch_failed(format!(
        "all {} authenticated manifest URLs failed",
        urls.len()
    ));
    if let Some(origin_err) = last_failure {
        err.source = Some(Box::new(origin_err));
    }
    Err(err)
}

/// Fetch one URL, parse/schema-validate the body, and return both the
/// manifest and the exact response bytes on success.
///
/// Failures cover transport errors, non-success HTTP status, body read
/// errors, and JSON/schema validation. Callers treat every failure the same
/// for fallback purposes.
fn try_fetch_one(client: &reqwest::blocking::Client, url: &Url) -> Result<(Manifest, Vec<u8>)> {
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
        .map_err(|e| Error::network(format!("read body from {url}")).with_source(e))?
        .to_vec();
    let manifest = parse_manifest(&bytes).map_err(|e| {
        Error::state_corrupted(format!("manifest from {url} failed schema validation"))
            .with_source(e)
    })?;
    Ok((manifest, bytes))
}

/// Atomically cache manifest bytes, creating the parent directory if needed.
/// Best-effort — callers intentionally ignore failures.
fn write_cache(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::platform::atomic_write(path, bytes)
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
            // Always ends in `silvervine/last-manifest.json`.
            let suffix = std::path::Path::new("silvervine").join("last-manifest.json");
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

    /// Mutable manifest snapshots are diagnostic cache only and must never
    /// authorize executable bytes after the HTTPS origins fail.
    #[test]
    fn fresh_cache_is_not_used_when_network_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let cache_path = tmp.path().join("last-manifest.json");
        fs::write(&cache_path, fixture_bytes()).expect("seed forged cache");
        let bad_url = Url::parse("http://127.0.0.1:1/nope").expect("url parse");

        let error = fetch_manifest_with(&[bad_url], Some(&cache_path), CACHE_TTL)
            .expect_err("mutable cache must not become an authenticity root");

        assert_eq!(error.category, ErrorCategory::ManifestFetchFailed);
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

    /// A 200 response whose body fails JSON/schema validation must continue
    /// to the next fixed origin exactly like a transport failure. The valid
    /// secondary wins, and only its exact bytes are snapshotted.
    #[test]
    fn fetch_manifest_with_falls_through_on_malformed_primary() {
        let malformed = spawn_fixture_server(b"{\"vendors\": \"not-an-object\"}".to_vec());
        let good = spawn_fixture_server(fixture_bytes());
        let tmp = TempDir::new().expect("tempdir");
        let cache_path = tmp.path().join("cache.json");

        let manifest = fetch_manifest_with(&[malformed, good], Some(&cache_path), CACHE_TTL)
            .expect("valid secondary must win after schema-invalid primary");
        assert!(!manifest.widevine().expect("vendor").version.is_empty());

        let cached = std::fs::read(&cache_path).expect("cache file written");
        assert_eq!(
            cached,
            fixture_bytes(),
            "snapshot must be exact bytes of the first fully parsed valid response"
        );
    }

    /// Exhausting the chain on parse/schema failures (not only transport)
    /// must surface ManifestFetchFailed, never a leaked StateCorrupted.
    #[test]
    fn exhausted_parse_failures_are_manifest_fetch_failed() {
        let bad = spawn_fixture_server(b"not-json-at-all".to_vec());
        let err = fetch_manifest_with(&[bad], None, CACHE_TTL)
            .expect_err("schema-invalid sole origin must fail the chain");
        assert_eq!(err.category, ErrorCategory::ManifestFetchFailed);
        let source = err
            .source
            .as_ref()
            .and_then(|s| s.downcast_ref::<Error>())
            .expect("last origin failure retained as Error source");
        assert_eq!(source.category, ErrorCategory::StateCorrupted);
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
