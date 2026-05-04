//! EME (Encrypted Media Extensions) error-code translation.
//!
//! Streaming services (Netflix, Disney+, Spotify, etc.) surface opaque
//! error codes when CDM playback fails. Most users see the code and have
//! no idea what to do. This module ships a hand-curated map from common
//! codes to actionable advice the user can act on locally — including
//! the suggested `neon` subcommand to run.
//!
//! ## Public API
//!
//! ```ignore
//! pub fn translate_error_code(code: &str) -> Option<EmeDiagnosis>;
//! ```
//!
//! The CLI's `neon doctor <code>` subcommand surfaces the diagnosis to
//! the user. Unknown codes return `None` — callers should fall back to
//! a generic message ("error code unrecognized; try `neon doctor` to
//! check Widevine state").
//!
//! ## What this module does NOT do
//!
//! * No network calls. The map is fully offline; we don't try to look
//!   up codes against a service-provider documentation page.
//! * No exhaustive coverage. We ship the codes that point at fixable
//!   *Widevine / DRM* problems. Codes that mean "your subscription
//!   lapsed" or "this title isn't licensed for your region" are out
//!   of scope — neon can't help with those.

mod codes;

pub use codes::{translate_error_code, EmeDiagnosis};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_code_returns_none() {
        assert!(translate_error_code("ZZZZ-9999").is_none());
        assert!(translate_error_code("").is_none());
    }

    #[test]
    fn netflix_n8156_codes_translate() {
        let d = translate_error_code("N8156-6024").expect("known");
        assert_eq!(d.service, "Netflix");
        assert!(d.suggested_command.is_some());
    }

    #[test]
    fn case_insensitive_lookup() {
        // Mixed case (n8156-6024) should match (NF8156-6024 too).
        let lower = translate_error_code("n8156-6024");
        let upper = translate_error_code("N8156-6024");
        assert_eq!(lower.is_some(), upper.is_some());
    }
}
