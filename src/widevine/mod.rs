//! Widevine acquisition.
//!
//! The [`manifest`], [`download`], [`extract`], and [`cache`] modules acquire
//! and verify the CDM consumed by the patch flow.
//!
//! Public surface re-exports the most-used types so consumers can
//! `use silvervine::widevine::{Manifest, fetch_manifest};` without reaching into
//! the submodule.

pub mod cache;
mod crx3;
pub mod download;
pub mod extract;
pub mod manifest;
pub mod ownership;

/// HTTPS origins trusted to serve Silvervine's default manifest chain.
pub(crate) const OFFICIAL_MANIFEST_HOSTS: &[&str] = &[
    "hg.mozilla.org",
    "hg-edge.mozilla.org",
    "raw.githubusercontent.com",
];

/// HTTPS origins present in Mozilla's Widevine manifest for CDM archives.
const OFFICIAL_CDM_HOSTS: &[&str] = &["www.google.com", "edgedl.me.gvt1.com"];

/// Whether an official manifest URL is safe to dispatch.
pub(crate) fn is_official_manifest_url(url: &url::Url) -> bool {
    is_exact_https_origin(url, OFFICIAL_MANIFEST_HOSTS)
}

/// Whether an explicit, caller-selected manifest URL may be dispatched.
///
/// HTTPS is required and explicit local/private address literals are rejected.
/// Redirects are constrained to the exact selected origin.
pub(crate) fn is_allowed_custom_manifest_url(url: &url::Url) -> bool {
    match url.scheme() {
        "https" => has_no_credentials(url) && has_nonlocal_host_literal(url),
        #[cfg(test)]
        "http" => is_loopback_remote_host(url),
        _ => false,
    }
}

/// Whether a manifest-controlled CDM URL is safe to dispatch.
pub(crate) fn is_allowed_cdm_url(url: &url::Url) -> bool {
    if is_exact_https_origin(url, OFFICIAL_CDM_HOSTS) {
        return true;
    }
    #[cfg(test)]
    if url.scheme() == "http" && is_loopback_remote_host(url) {
        return true;
    }
    false
}

/// Redirect policy for one caller-selected manifest source.
///
/// Official Mozilla/GitHub sources may redirect only among the fixed official
/// origins. Explicit custom sources may redirect only within their exact
/// scheme/host/port origin. Unit tests additionally permit loopback-to-loopback
/// HTTP redirects for hermetic stub servers.
pub(crate) fn manifest_redirect_policy(source: &url::Url) -> reqwest::redirect::Policy {
    let source = source.clone();
    let official = is_official_manifest_url(&source);
    reqwest::redirect::Policy::custom(move |attempt| {
        let target = attempt.url();
        let allowed = if official {
            is_official_manifest_url(target)
        } else {
            is_allowed_custom_manifest_url(target) && has_same_origin(&source, target)
        };
        #[cfg(test)]
        let allowed = allowed
            || (source.scheme() == "http"
                && target.scheme() == "http"
                && is_loopback_remote_host(&source)
                && is_loopback_remote_host(target));

        if attempt.previous().len() >= 10 {
            attempt.error("too many redirects")
        } else if allowed {
            attempt.follow()
        } else {
            attempt.error("redirect target violates Silvervine's manifest-origin policy")
        }
    })
}

fn is_exact_https_origin(url: &url::Url, hosts: &[&str]) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && has_no_credentials(url)
        && url.domain().is_some_and(|host| {
            hosts
                .iter()
                .any(|allowed| host.eq_ignore_ascii_case(allowed))
        })
}

fn has_no_credentials(url: &url::Url) -> bool {
    url.username().is_empty() && url.password().is_none()
}

fn has_same_origin(left: &url::Url, right: &url::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn has_nonlocal_host_literal(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => {
            let host = host.trim_end_matches('.');
            !host.eq_ignore_ascii_case("localhost")
                && !host
                    .rsplit_once('.')
                    .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("localhost"))
        }
        Some(url::Host::Ipv4(address)) => !ipv4_is_non_public(address),
        Some(url::Host::Ipv6(address)) => !ipv6_is_non_public(address),
        None => false,
    }
}

#[cfg(test)]
fn is_loopback_remote_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(host)) => {
            host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
        }
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn ipv4_is_non_public(address: std::net::Ipv4Addr) -> bool {
    let [first, second, _, _] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_multicast()
        || first == 0
        || first >= 240
        || (first == 100 && (64..=127).contains(&second))
        || (first == 192 && second == 0)
        || (first == 198 && matches!(second, 18 | 19))
}

fn ipv6_is_non_public(address: std::net::Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return ipv4_is_non_public(mapped);
    }
    let segments = address.segments();
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || segments[0] & 0xffc0 == 0xfec0
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

/// CDM directory installed into a Chromium-family browser.
pub(crate) const CDM_BUNDLE_DIRECTORY: &str = "WidevineCdm";
/// Manifest filename at the root of an extracted or installed CDM.
pub(crate) const CDM_MANIFEST_FILENAME: &str = "manifest.json";
/// Parent directory for architecture-specific CDM libraries.
pub(crate) const PLATFORM_SPECIFIC_DIRECTORY: &str = "_platform_specific";

/// Architecture directory used by Chromium's extracted CDM layout.
pub(crate) const fn platform_directory(platform: Platform) -> &'static str {
    match platform {
        Platform::LinuxX86_64 => "linux_x64",
        Platform::DarwinAarch64 => "mac_arm64",
        Platform::DarwinX86_64 => "mac_x64",
    }
}

/// Shared-library filename used by Chromium for a platform.
pub(crate) const fn platform_library(platform: Platform) -> &'static str {
    match platform {
        Platform::LinuxX86_64 => "libwidevinecdm.so",
        Platform::DarwinAarch64 | Platform::DarwinX86_64 => "libwidevinecdm.dylib",
    }
}

pub use cache::{
    current as current_cdm, default_cache_root, ensure_cdm_for, prune as prune_cache,
    rollback as rollback_cdm, verify_current_integrity, verify_integrity, CachedCdm, CdmCache,
};
pub use download::{default_download_dir, download_to, download_to_cache, sha512_hex, verify_file};
pub use extract::{extract_crx3, extract_crx3_bytes, parse_crx3_header, verify_widevine_layout};
pub use manifest::{
    cached_manifest_path, current_platform_key, fetch_manifest, fetch_manifest_with,
    parse_manifest, GmpVendor, Manifest, Platform, PlatformEntry,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> url::Url {
        url::Url::parse(raw).expect("URL")
    }

    #[test]
    fn official_manifest_origins_are_exact() {
        for raw in [
            "https://hg.mozilla.org/manifest.json",
            "https://hg-edge.mozilla.org/manifest.json",
            "https://raw.githubusercontent.com/manifest.json",
        ] {
            assert!(is_official_manifest_url(&url(raw)), "{raw}");
        }
        for raw in [
            "https://hg.mozilla.org.evil.example/manifest.json",
            "https://hg.mozilla.org.:443/manifest.json",
            "https://hg.mozilla.org:444/manifest.json",
            "https://user@hg.mozilla.org/manifest.json",
        ] {
            assert!(!is_official_manifest_url(&url(raw)), "{raw}");
        }
    }

    #[test]
    fn cdm_origins_are_exact() {
        assert!(is_allowed_cdm_url(&url(
            "https://www.google.com/dl/release2/component.crx3"
        )));
        assert!(is_allowed_cdm_url(&url(
            "https://edgedl.me.gvt1.com/edgedl/release2/component.crx3"
        )));
        for raw in [
            "https://www.google.com.evil.example/component.crx3",
            "https://www.google.com.:443/component.crx3",
            "https://www.google.com:444/component.crx3",
            "https://internal.service.corp/component.crx3",
            "https://localhost./component.crx3",
            "https://sub.localhost./component.crx3",
        ] {
            assert!(!is_allowed_cdm_url(&url(raw)), "{raw}");
        }
    }

    #[test]
    fn custom_manifest_sources_reject_localhost_fqdns() {
        assert!(is_allowed_custom_manifest_url(&url(
            "https://updates.example.com/manifest.json"
        )));
        for raw in [
            "https://localhost./manifest.json",
            "https://sub.localhost./manifest.json",
            "https://127.0.0.1/manifest.json",
            "https://[::1]/manifest.json",
            "https://192.168.1.2/manifest.json",
        ] {
            assert!(!is_allowed_custom_manifest_url(&url(raw)), "{raw}");
        }
    }

    #[test]
    fn custom_manifest_redirects_require_same_origin() {
        let source = url("https://updates.example.com/manifest.json");
        assert!(has_same_origin(
            &source,
            &url("https://updates.example.com/next.json")
        ));
        assert!(!has_same_origin(
            &source,
            &url("https://cdn.example.com/next.json")
        ));
        assert!(!has_same_origin(
            &source,
            &url("https://updates.example.com:444/next.json")
        ));
    }
}
