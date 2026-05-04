//! Error-code → diagnosis map.
//!
//! Sources used to seed this list:
//!
//! * Netflix help-center articles — N8156-6024, N8156-6013, M7361-1253,
//!   M7111-1331-2206 (Linux/widevine-related codes called out in their
//!   "Code: ..." help pages).
//! * Disney+ help-center — Error 14, Error 83, Error 39 (DRM-related).
//! * Spotify "Error code 4" / general DRM playback-failure reports.
//!
//! Each entry maps a stable code → service + likely cause + suggested
//! `neon` command. Codes are normalized to upper-case at lookup time,
//! so the table itself stores upper-case keys.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Diagnosis of an EME error code: the service that emitted it, the
/// likely root cause, and the `neon` subcommand the user should run
/// to fix it (when applicable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmeDiagnosis {
    /// The error code as the user entered it (normalized to upper case).
    pub code: String,
    /// Streaming service that emits this code (e.g. `"Netflix"`).
    pub service: &'static str,
    /// Plain-language explanation of what the code means and why it
    /// happens.
    pub likely_cause: &'static str,
    /// Suggested `neon` command to run to fix the underlying issue.
    /// `None` for codes that aren't fixable from neon (e.g. a region
    /// licensing block, or an account-level entitlement issue).
    pub suggested_command: Option<&'static str>,
}

/// Lookup an EME error code in the static map.
///
/// Lookup is case-insensitive: `n8156-6024` and `N8156-6024` resolve
/// to the same diagnosis. Unrecognized codes return `None` — the
/// caller (typically `neon doctor`) should fall back to a generic
/// "code not recognized" message.
#[must_use]
pub fn translate_error_code(code: &str) -> Option<EmeDiagnosis> {
    let normalized = code.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return None;
    }
    let map = code_map();
    map.get(normalized.as_str()).map(|raw| EmeDiagnosis {
        code: normalized,
        service: raw.service,
        likely_cause: raw.likely_cause,
        suggested_command: raw.suggested_command,
    })
}

/// Return the keys of the static map. Useful for tests + for `neon
/// doctor --list-codes` (a possible future flag).
#[must_use]
#[cfg(test)]
pub fn known_codes() -> Vec<&'static str> {
    code_map().keys().copied().collect()
}

struct RawDiagnosis {
    service: &'static str,
    likely_cause: &'static str,
    suggested_command: Option<&'static str>,
}

/// Lazy static initialization of the code → diagnosis map.
fn code_map() -> &'static HashMap<&'static str, RawDiagnosis> {
    static CELL: OnceLock<HashMap<&'static str, RawDiagnosis>> = OnceLock::new();
    CELL.get_or_init(build_map)
}

#[allow(clippy::too_many_lines)] // Static seed data; line count tracks code coverage, not complexity.
fn build_map() -> HashMap<&'static str, RawDiagnosis> {
    let entries: &[(&str, RawDiagnosis)] = &[
        // ---- Netflix ----
        (
            "N8156-6024",
            RawDiagnosis {
                service: "Netflix",
                likely_cause: "The Widevine CDM is missing or out of date for your browser. \
                    Linux + Chromium-family browsers commonly hit this when the bundled CDM \
                    was never installed or has been wiped by an update.",
                suggested_command: Some("neon update widevine && neon patch"),
            },
        ),
        (
            "N8156-6013",
            RawDiagnosis {
                service: "Netflix",
                likely_cause: "Widevine is installed but Netflix's license server rejected the \
                    request. Most often the system clock is wrong, or the CDM is at an \
                    incompatible version. Verify your time, then reinstall the CDM.",
                suggested_command: Some("neon doctor && neon update widevine"),
            },
        ),
        (
            "N8156-6205",
            RawDiagnosis {
                service: "Netflix",
                likely_cause: "Browser is in an unsupported state — typically caused by an \
                    outdated CDM or a non-Widevine build of Chromium. Re-patching with the \
                    latest CDM resolves most cases.",
                suggested_command: Some("neon update widevine && neon patch"),
            },
        ),
        (
            "M7361-1253",
            RawDiagnosis {
                service: "Netflix",
                likely_cause: "Network connectivity issue between the browser and Netflix's \
                    license server. Not a Widevine issue per se, but if the browser was just \
                    patched, a stale CDM cache may also be involved.",
                suggested_command: Some("neon doctor"),
            },
        ),
        (
            "M7111-1331-2206",
            RawDiagnosis {
                service: "Netflix",
                likely_cause: "VPN or geo-restriction issue. This isn't fixable from neon — \
                    Netflix has detected a proxy and blocked playback. Disable the VPN.",
                suggested_command: None,
            },
        ),
        (
            "M7121-1331",
            RawDiagnosis {
                service: "Netflix",
                likely_cause: "Browser is missing the Widevine CDM, or the CDM is at a version \
                    Netflix no longer accepts. Update + re-patch resolves both.",
                suggested_command: Some("neon update widevine && neon patch"),
            },
        ),
        (
            "F7355-1204",
            RawDiagnosis {
                service: "Netflix",
                likely_cause: "Browser cache or cookies are corrupt. Clear browser cookies for \
                    netflix.com and reload. If the issue persists after a clean cookie state, \
                    re-run neon's patch flow.",
                suggested_command: Some("neon doctor"),
            },
        ),
        // ---- Disney+ ----
        (
            "ERROR 14",
            RawDiagnosis {
                service: "Disney+",
                likely_cause: "Login session has expired or is invalid. Sign out and back in. \
                    Not a Widevine issue.",
                suggested_command: None,
            },
        ),
        (
            "ERROR 83",
            RawDiagnosis {
                service: "Disney+",
                likely_cause: "Device compatibility issue — most often a missing or outdated \
                    Widevine CDM, or HDCP-protected output running over a non-HDCP cable. \
                    Update the CDM and re-patch the browser.",
                suggested_command: Some("neon update widevine && neon patch"),
            },
        ),
        (
            "ERROR 39",
            RawDiagnosis {
                service: "Disney+",
                likely_cause: "DRM-related playback issue. The Widevine CDM may be missing or \
                    at an incompatible version. Reinstall the CDM with neon.",
                suggested_command: Some("neon update widevine && neon patch"),
            },
        ),
        // ---- Spotify ----
        (
            "ERROR CODE 4",
            RawDiagnosis {
                service: "Spotify",
                likely_cause: "Connection to Spotify's servers failed. Not a Widevine issue, \
                    but Spotify's web player does use Widevine for some content — if a \
                    network issue is ruled out, re-patching may help.",
                suggested_command: None,
            },
        ),
        (
            "PLAYBACK ERROR",
            RawDiagnosis {
                service: "Spotify",
                likely_cause: "Generic playback failure. For DRM-protected tracks (some \
                    podcasts, regional catalogs), a missing or outdated Widevine CDM is the \
                    most common cause on Linux + Chromium-family browsers.",
                suggested_command: Some("neon doctor"),
            },
        ),
        // ---- HBO Max / Max ----
        (
            "100-104",
            RawDiagnosis {
                service: "Max (HBO Max)",
                likely_cause: "Playback engine error. Most often a missing or outdated Widevine \
                    CDM, especially on Linux. Re-patching the browser usually resolves it.",
                suggested_command: Some("neon update widevine && neon patch"),
            },
        ),
        (
            "VID-1102",
            RawDiagnosis {
                service: "Max (HBO Max)",
                likely_cause: "DRM license could not be acquired. Update the CDM and re-patch.",
                suggested_command: Some("neon update widevine && neon patch"),
            },
        ),
        // ---- Generic Widevine errors users will paste in ----
        (
            "WIDEVINE NOT FOUND",
            RawDiagnosis {
                service: "Generic",
                likely_cause: "The browser couldn't locate the Widevine CDM at startup. This is \
                    the canonical neon-fixable error — run patch to install the CDM.",
                suggested_command: Some("neon patch"),
            },
        ),
    ];
    let mut map = HashMap::with_capacity(entries.len());
    for (k, v) in entries {
        let raw = RawDiagnosis {
            service: v.service,
            likely_cause: v.likely_cause,
            suggested_command: v.suggested_command,
        };
        map.insert(*k, raw);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_code_round_trips() {
        for code in known_codes() {
            let d = translate_error_code(code).expect("round trip");
            assert_eq!(d.code, code.to_ascii_uppercase());
            assert!(!d.likely_cause.is_empty());
        }
    }

    #[test]
    fn whitespace_is_trimmed() {
        let a = translate_error_code("  N8156-6024  ").expect("trimmed");
        assert_eq!(a.code, "N8156-6024");
    }

    #[test]
    fn empty_returns_none() {
        assert!(translate_error_code("").is_none());
        assert!(translate_error_code("   ").is_none());
    }

    #[test]
    fn unknown_returns_none() {
        assert!(translate_error_code("totally-unknown-code").is_none());
    }

    #[test]
    fn netflix_n_codes_have_widevine_advice() {
        // The N-codes most commonly seen on Linux are about the CDM —
        // verify they all suggest a neon command.
        for code in ["N8156-6024", "N8156-6013", "M7121-1331"] {
            let d = translate_error_code(code).expect(code);
            assert_eq!(d.service, "Netflix");
            assert!(
                d.suggested_command.is_some(),
                "{code} should have a suggested command"
            );
        }
    }

    #[test]
    fn vpn_code_has_no_command() {
        // Netflix's M7111-1331-2206 is a VPN block — neon can't fix it.
        let d = translate_error_code("M7111-1331-2206").expect("vpn");
        assert!(d.suggested_command.is_none());
    }

    #[test]
    fn disney_error_83_translates() {
        let d = translate_error_code("Error 83").expect("disney");
        assert_eq!(d.service, "Disney+");
        assert!(d.suggested_command.is_some());
    }

    #[test]
    fn case_normalization() {
        let lower = translate_error_code("n8156-6024");
        let upper = translate_error_code("N8156-6024");
        assert_eq!(lower, upper);
    }

    #[test]
    fn map_has_at_least_one_entry_per_service() {
        // Every service we list must have at least one code in the map.
        let services: Vec<&str> = known_codes()
            .iter()
            .map(|c| translate_error_code(c).unwrap().service)
            .collect();
        for required in ["Netflix", "Disney+", "Spotify", "Max (HBO Max)", "Generic"] {
            assert!(
                services.contains(&required),
                "{required} must have at least one code in the map"
            );
        }
    }

    #[test]
    fn diagnosis_is_clone_eq() {
        let a = translate_error_code("N8156-6024").unwrap();
        let b = a.clone();
        assert_eq!(a, b);
    }
}
