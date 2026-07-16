//! Categorized error type for Silvervine.
//!
//! Every public API in the crate returns [`Result<T>`] where the inner
//! [`Error`] carries an [`ErrorCategory`]. The category is the routing key for:
//!
//! * `silvervine doctor` — surfacing actionable advice per category.
//! * Notifications — categorized error → notification body.
//!
//! Design principles:
//!
//! * **Categories are stable.** New variants get added rather than reshuffled.
//!   Downstream consumers (e.g. log-scrapers, JSON output) depend on the
//!   string form being stable.
//! * **`Other` is a last resort.** If a code path repeatedly hits `Other`,
//!   it's a signal we need to add a new category.
//! * **No `unwrap`/`expect` in production code paths** — surface a proper
//!   `Error` instead, even for "this should never happen" cases.

use std::fmt;

use serde::Serialize;

/// High-level category of a Silvervine error.
///
/// Categories drive UX (notification copy, doctor advice) and analytics
/// (opt-in reporter payload). The string form of each variant is committed
/// API; renaming a variant is a breaking change for the Worker schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ErrorCategory {
    /// Filesystem write was rejected; we likely need privilege escalation.
    PermissionDenied,
    /// Browser process is currently running; patching now would leave it
    /// with a stale framework reference. Retry once it has quit.
    BrowserRunning,
    /// Generic network-layer failure (DNS, TCP, TLS, HTTP transport, etc.).
    NetworkError,
    /// Every Mozilla manifest URL in the fallback chain failed.
    ManifestFetchFailed,
    /// SHA-512 (or other integrity) check failed; the artifact does not
    /// match the manifest's expected hash.
    HashMismatch,
    /// `ENOSPC` or equivalent.
    DiskFull,
    /// We expected a Chromium-family bundle layout and didn't find one.
    UnknownBundleStructure,
    /// `silvervine doctor` and similar commands reached out to the daemon and
    /// found no liveness file (or a stale one).
    DaemonNotRunning,
    /// State file (`~/.config/silvervine/state.json` etc.) is unparseable; user
    /// action (or `silvervine repair`) required.
    StateCorrupted,
    /// Running on a platform we don't (yet) support — e.g. ARM64 Linux in V1.
    UnsupportedPlatform,
    /// Anything not yet categorized. **Avoid in new code** — add a variant.
    Other,
}

impl ErrorCategory {
    /// Stable string form of the variant.
    ///
    /// This is what the opt-in reporter payload sends to the Cloudflare
    /// Worker, and what `silvervine doctor --json` emits. **Do not rename without
    /// coordinating with the Worker schema.**
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PermissionDenied => "PermissionDenied",
            Self::BrowserRunning => "BrowserRunning",
            Self::NetworkError => "NetworkError",
            Self::ManifestFetchFailed => "ManifestFetchFailed",
            Self::HashMismatch => "HashMismatch",
            Self::DiskFull => "DiskFull",
            Self::UnknownBundleStructure => "UnknownBundleStructure",
            Self::DaemonNotRunning => "DaemonNotRunning",
            Self::StateCorrupted => "StateCorrupted",
            Self::UnsupportedPlatform => "UnsupportedPlatform",
            Self::Other => "Other",
        }
    }
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Categorized error type used everywhere in Silvervine.
///
/// Construct via [`Error::new`] or one of the variant-specific helpers
/// (e.g. [`Error::network`], [`Error::permission_denied`]). The `source`
/// field carries an optional underlying error chain for `?`-propagated
/// causes.
#[derive(Debug, thiserror::Error)]
pub struct Error {
    /// Routing category — drives UX and analytics.
    pub category: ErrorCategory,
    /// Human-readable, sanitized message. Avoid leaking absolute filesystem
    /// paths or hostnames the user didn't already know about.
    pub message: String,
    /// Optional underlying cause for debug/logging purposes.
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// Construct an error with an explicit category and message.
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
            source: None,
        }
    }

    /// Attach an underlying source error (chained via `?`).
    #[must_use]
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// Construct a [`ErrorCategory::PermissionDenied`] error.
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::PermissionDenied, message)
    }

    /// Construct a [`ErrorCategory::BrowserRunning`] error.
    pub fn browser_running(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::BrowserRunning, message)
    }

    /// Construct a [`ErrorCategory::NetworkError`] error.
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::NetworkError, message)
    }

    /// Construct a [`ErrorCategory::ManifestFetchFailed`] error.
    pub fn manifest_fetch_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::ManifestFetchFailed, message)
    }

    /// Construct a [`ErrorCategory::HashMismatch`] error.
    pub fn hash_mismatch(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::HashMismatch, message)
    }

    /// Construct a [`ErrorCategory::DiskFull`] error.
    pub fn disk_full(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::DiskFull, message)
    }

    /// Construct a [`ErrorCategory::UnknownBundleStructure`] error.
    pub fn unknown_bundle_structure(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::UnknownBundleStructure, message)
    }

    /// Construct a [`ErrorCategory::DaemonNotRunning`] error.
    pub fn daemon_not_running(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::DaemonNotRunning, message)
    }

    /// Construct a [`ErrorCategory::StateCorrupted`] error.
    pub fn state_corrupted(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::StateCorrupted, message)
    }

    /// Construct a [`ErrorCategory::UnsupportedPlatform`] error.
    pub fn unsupported_platform(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::UnsupportedPlatform, message)
    }

    /// Construct a [`ErrorCategory::Other`] error. Prefer a more specific
    /// variant when one exists — `Other` is the catch-all for unclassified
    /// causes and shows up in dashboards as the "we should categorize this"
    /// pile.
    pub fn other(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Other, message)
    }
}

impl fmt::Display for Error {
    /// Renders as `"<Category>: <message>"` so the category is the first
    /// thing a user (or log scraper) sees.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.category, self.message)
    }
}

/// Map filesystem errors into a category. `PermissionDenied` and disk-full
/// (`StorageFull` / `ENOSPC`) get their own categories; everything else
/// falls into `Other` with the io error as the source.
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        let kind = err.kind();
        let category = match kind {
            std::io::ErrorKind::PermissionDenied => ErrorCategory::PermissionDenied,
            // `StorageFull` is stable in Rust 1.83; on older toolchains
            // ENOSPC reports as `Other`. The MSRV in our `Cargo.toml`
            // is 1.75, so we don't depend on the new variant here.
            _ => ErrorCategory::Other,
        };
        let message = err.to_string();
        Self {
            category,
            message,
            source: Some(Box::new(err)),
        }
    }
}

/// Map JSON parse errors into a `StateCorrupted` category — the most
/// common consumer of `serde_json` is the manifest cache and the state
/// file, both of which are "corrupted" if they fail to parse.
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        let message = err.to_string();
        Self {
            category: ErrorCategory::StateCorrupted,
            message,
            source: Some(Box::new(err)),
        }
    }
}

/// Map TOML deserialization errors into `StateCorrupted` (config file
/// is unparseable).
impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        let message = err.to_string();
        Self {
            category: ErrorCategory::StateCorrupted,
            message,
            source: Some(Box::new(err)),
        }
    }
}

/// Map reqwest HTTP errors into the `NetworkError` category.
impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        let message = err.to_string();
        Self {
            category: ErrorCategory::NetworkError,
            message,
            source: Some(Box::new(err)),
        }
    }
}

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every category produces a non-empty, deterministic string.
    #[test]
    fn every_category_has_stable_name() {
        let all = [
            (ErrorCategory::PermissionDenied, "PermissionDenied"),
            (ErrorCategory::BrowserRunning, "BrowserRunning"),
            (ErrorCategory::NetworkError, "NetworkError"),
            (ErrorCategory::ManifestFetchFailed, "ManifestFetchFailed"),
            (ErrorCategory::HashMismatch, "HashMismatch"),
            (ErrorCategory::DiskFull, "DiskFull"),
            (
                ErrorCategory::UnknownBundleStructure,
                "UnknownBundleStructure",
            ),
            (ErrorCategory::DaemonNotRunning, "DaemonNotRunning"),
            (ErrorCategory::StateCorrupted, "StateCorrupted"),
            (ErrorCategory::UnsupportedPlatform, "UnsupportedPlatform"),
            (ErrorCategory::Other, "Other"),
        ];
        for (cat, expected) in all {
            assert_eq!(cat.as_str(), expected, "category string for {cat:?}");
            assert_eq!(format!("{cat}"), expected);
        }
    }

    #[test]
    fn display_format_includes_category_prefix() {
        let err = Error::permission_denied("can't write to /opt/foo");
        assert_eq!(
            format!("{err}"),
            "PermissionDenied: can't write to /opt/foo"
        );
    }

    #[test]
    fn variant_helpers_set_correct_category() {
        assert_eq!(Error::network("dns").category, ErrorCategory::NetworkError);
        assert_eq!(
            Error::manifest_fetch_failed("all").category,
            ErrorCategory::ManifestFetchFailed
        );
        assert_eq!(
            Error::hash_mismatch("sha").category,
            ErrorCategory::HashMismatch
        );
        assert_eq!(Error::disk_full("space").category, ErrorCategory::DiskFull);
        assert_eq!(
            Error::unknown_bundle_structure("nope").category,
            ErrorCategory::UnknownBundleStructure
        );
        assert_eq!(
            Error::daemon_not_running("stale").category,
            ErrorCategory::DaemonNotRunning
        );
        assert_eq!(
            Error::state_corrupted("bad json").category,
            ErrorCategory::StateCorrupted
        );
        assert_eq!(
            Error::unsupported_platform("BSD").category,
            ErrorCategory::UnsupportedPlatform
        );
        assert_eq!(
            Error::browser_running("Helium").category,
            ErrorCategory::BrowserRunning
        );
        assert_eq!(Error::other("oops").category, ErrorCategory::Other);
    }

    #[test]
    fn with_source_attaches_chain() {
        let io = std::io::Error::other("boom");
        let err = Error::other("wrapped").with_source(io);
        assert!(err.source.is_some());
        let chain = std::error::Error::source(&err);
        assert!(chain.is_some());
    }

    #[test]
    fn io_permission_denied_routes_to_category() {
        let io = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let err: Error = io.into();
        assert_eq!(err.category, ErrorCategory::PermissionDenied);
    }

    #[test]
    fn io_other_routes_to_other_category() {
        let io = std::io::Error::other("weird");
        let err: Error = io.into();
        assert_eq!(err.category, ErrorCategory::Other);
    }

    #[test]
    fn json_parse_routes_to_state_corrupted() {
        let json_err: serde_json::Error =
            serde_json::from_str::<serde_json::Value>("{not json").unwrap_err();
        let err: Error = json_err.into();
        assert_eq!(err.category, ErrorCategory::StateCorrupted);
    }

    #[test]
    fn toml_parse_routes_to_state_corrupted() {
        let toml_err = toml::from_str::<toml::Value>("[[invalid").unwrap_err();
        let err: Error = toml_err.into();
        assert_eq!(err.category, ErrorCategory::StateCorrupted);
    }

    #[test]
    fn category_serializes_as_external_tag() {
        let json = serde_json::to_string(&ErrorCategory::HashMismatch).expect("serialize category");
        assert_eq!(json, "\"HashMismatch\"");
    }

    /// `Error::new` is the explicit-category constructor used in cases
    /// where a variant helper isn't a perfect fit.
    #[test]
    fn error_new_with_explicit_category() {
        let err = Error::new(ErrorCategory::DiskFull, "disk is full");
        assert_eq!(err.category, ErrorCategory::DiskFull);
        assert_eq!(err.message, "disk is full");
        assert!(err.source.is_none());
    }

    /// `reqwest::Error` gets routed to `NetworkError`. We synthesize one
    /// by trying to send a request to an invalid URL via the blocking
    /// client.
    #[test]
    fn reqwest_error_routes_to_network() {
        // Build a client and try to GET a URL whose host won't resolve.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(50))
            .build()
            .expect("build client");
        let result = client.get("http://invalid.host.test.local:1/").send();
        let reqwest_err = result.expect_err("send must error");
        let err: Error = reqwest_err.into();
        assert_eq!(err.category, ErrorCategory::NetworkError);
    }
}
