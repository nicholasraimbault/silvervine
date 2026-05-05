//! Bridge license posture management — V3-Phase C.
//!
//! Tracks whether the user accepted Microsoft's evaluation license,
//! brought their own key, or pointed at a `.csv`-bundled key file. The
//! choice is persisted in `~/.config/neon/bridge.toml` so subsequent
//! `neon stream init` invocations don't re-prompt.
//!
//! ## Format
//!
//! ```toml
//! [license]
//! mode = "trial"          # or "key" or "key_file"
//! accepted_at = 1714838400  # Unix timestamp; trial starts here
//! key = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"  # only for mode = "key"
//! key_file = "/home/user/.config/neon/keys.csv"  # only for "key_file"
//! ```
//!
//! ## Trial expiry
//!
//! Microsoft's Win11 `IoT` Enterprise LTSC trial is 90 days, with
//! `slmgr.vbs /rearm` extending up to 3 additional 90-day cycles. The
//! trial-mode arm tracks `accepted_at` so we can compute days-remaining
//! + decide when to surface a "rearm now" notification.
//!
//! The actual rearm runs in the guest as a scheduled task; see
//! [`rearm_command_for_guest`].

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Length of the trial period in seconds (90 days).
const TRIAL_PERIOD_SECS: i64 = 90 * 24 * 60 * 60;

/// PowerShell command guests run via scheduled task to extend the trial
/// license. Microsoft's `slmgr.vbs /rearm` accepts up to 3 additional
/// 90-day cycles before a real key is required.
const REARM_COMMAND: &str =
    "powershell -NoProfile -Command \"& {{ cscript //B C:\\\\Windows\\\\System32\\\\slmgr.vbs /rearm; Restart-Computer -Force }}\"";

/// One-line PowerShell helper guests can paste into the run dialog when
/// the scheduled task fails.
#[must_use]
pub fn rearm_command_for_guest() -> &'static str {
    REARM_COMMAND
}

/// License posture chosen by the user.
///
/// Persisted in `~/.config/neon/bridge.toml` and consumed by:
///
/// * `bridge::install::provision` — drives the unattended XML's
///   `<ProductKey>` block.
/// * `cli::stream::status` — surfaces trial expiry to the user.
/// * `bridge::unattended::render_autounattend` — picks the right
///   first-logon scheduled-task posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicensePosture {
    /// User accepted Microsoft's 90-day evaluation license. We track
    /// `accepted_at` (Unix seconds) so we can compute days-remaining +
    /// auto-rearm via guest-side scheduled task.
    Eval {
        /// Unix timestamp when the user accepted (or last rearmed).
        accepted_at: i64,
    },
    /// User supplied a Windows product key on the command line. The key
    /// is written to the unattended XML verbatim.
    Key(String),
    /// User pointed at a key file (CSV / KMS). We embed the file path in
    /// the unattended pipeline; the file content is read at install time
    /// to avoid persisting raw keys in `bridge.toml`.
    KeyFile(PathBuf),
}

impl LicensePosture {
    /// Construct a trial-mode posture using the current system time as
    /// `accepted_at`.
    #[must_use]
    pub fn eval_now() -> Self {
        Self::Eval {
            accepted_at: now_unix_secs(),
        }
    }

    /// Days until the trial license expires. Returns `None` for
    /// non-trial postures.
    ///
    /// A negative result means the trial has already expired.
    #[must_use]
    pub fn days_until_expiry(&self) -> Option<i64> {
        match self {
            Self::Eval { accepted_at } => {
                let expires_at = accepted_at.saturating_add(TRIAL_PERIOD_SECS);
                let now = now_unix_secs();
                let secs_remaining = expires_at.saturating_sub(now);
                Some(secs_remaining.div_euclid(24 * 60 * 60))
            }
            Self::Key(_) | Self::KeyFile(_) => None,
        }
    }

    /// `true` if the trial license has fewer than `n` days remaining.
    /// Returns `false` for non-trial postures.
    #[must_use]
    pub fn eval_expiring_soon(&self, days: i64) -> bool {
        self.days_until_expiry().is_some_and(|d| d < days)
    }
}

/// Persisted form of a license posture, suitable for serializing to
/// TOML. Uses an enum-tag pattern to round-trip cleanly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LicensePostureToml {
    /// Discriminator: `"trial"`, `"key"`, or `"key_file"`.
    mode: String,
    /// Unix seconds; only relevant for `mode = "trial"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_at: Option<i64>,
    /// Product key; only relevant for `mode = "key"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    /// Key file path; only relevant for `mode = "key_file"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    key_file: Option<PathBuf>,
}

impl LicensePostureToml {
    fn from_posture(p: &LicensePosture) -> Self {
        match p {
            LicensePosture::Eval { accepted_at } => Self {
                mode: "trial".into(),
                accepted_at: Some(*accepted_at),
                key: None,
                key_file: None,
            },
            LicensePosture::Key(k) => Self {
                mode: "key".into(),
                accepted_at: None,
                key: Some(k.clone()),
                key_file: None,
            },
            LicensePosture::KeyFile(p) => Self {
                mode: "key_file".into(),
                accepted_at: None,
                key: None,
                key_file: Some(p.clone()),
            },
        }
    }

    fn into_posture(self) -> Result<LicensePosture> {
        match self.mode.as_str() {
            "trial" => Ok(LicensePosture::Eval {
                accepted_at: self.accepted_at.unwrap_or(0),
            }),
            "key" => self
                .key
                .ok_or_else(|| {
                    Error::state_corrupted("bridge.toml: mode=\"key\" requires a `key` value")
                })
                .and_then(|k| {
                    if validate_product_key(&k) {
                        Ok(LicensePosture::Key(k))
                    } else {
                        Err(Error::state_corrupted(format!(
                            "bridge.toml: product key {k:?} fails the X-X-X-X-X format check"
                        )))
                    }
                }),
            "key_file" => self.key_file.map(LicensePosture::KeyFile).ok_or_else(|| {
                Error::state_corrupted(
                    "bridge.toml: mode=\"key_file\" requires a `key_file` path",
                )
            }),
            other => Err(Error::state_corrupted(format!(
                "bridge.toml: unknown license mode {other:?} (expected \"trial\", \"key\", or \"key_file\")"
            ))),
        }
    }
}

/// Top-level shape of `~/.config/neon/bridge.toml`.
///
/// Future bridge sub-features (ISO override URL, install path, etc.)
/// add new fields here. Today only `[license]` is required.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct BridgeConfig {
    /// `[license]` block — license posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<LicensePostureToml>,
}

/// Default config path: `$XDG_CONFIG_HOME/neon/bridge.toml`.
#[must_use]
pub fn default_bridge_config_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("neon").join("bridge.toml"))
}

/// Read the current license posture from disk. Returns `None` if no
/// `bridge.toml` exists or it has no `[license]` block.
///
/// # Errors
///
/// * [`crate::ErrorCategory::StateCorrupted`] — `bridge.toml` is
///   malformed or has an invalid mode value.
pub fn current_posture() -> Result<Option<LicensePosture>> {
    let Some(path) = default_bridge_config_path() else {
        return Ok(None);
    };
    current_posture_from(&path)
}

/// Like [`current_posture`] but reads from an explicit path. Tests
/// point this at a tempdir-resident bridge.toml.
///
/// # Errors
///
/// See [`current_posture`].
pub fn current_posture_from(path: &Path) -> Result<Option<LicensePosture>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::from(e)),
    };
    let cfg: BridgeConfig = toml::from_str(&raw).map_err(Error::from)?;
    match cfg.license {
        Some(t) => Ok(Some(t.into_posture()?)),
        None => Ok(None),
    }
}

/// Persist the user's license posture to `bridge.toml`.
///
/// Reads any existing config (preserving non-license sections) before
/// writing back. The file is created with mode 0600 on Unix because it
/// can contain a raw product key.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] — disk I/O / serialization.
/// * [`crate::ErrorCategory::StateCorrupted`] — existing file
///   malformed.
pub fn save_posture(posture: &LicensePosture) -> Result<()> {
    let path = default_bridge_config_path()
        .ok_or_else(|| Error::state_corrupted("cannot resolve ~/.config/neon/bridge.toml"))?;
    save_posture_to(posture, &path)
}

/// Like [`save_posture`] but writes to an explicit path.
///
/// # Errors
///
/// See [`save_posture`].
pub fn save_posture_to(posture: &LicensePosture, path: &Path) -> Result<()> {
    let mut cfg: BridgeConfig = match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).map_err(Error::from)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BridgeConfig::default(),
        Err(e) => return Err(Error::from(e)),
    };
    cfg.license = Some(LicensePostureToml::from_posture(posture));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::from)?;
    }
    let body = toml::to_string_pretty(&cfg)
        .map_err(|e| Error::other("could not serialize bridge.toml").with_source(e))?;
    std::fs::write(path, body).map_err(Error::from)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Best-effort validation that `key` matches the canonical Windows
/// product-key shape `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
#[must_use]
pub fn validate_product_key(key: &str) -> bool {
    let parts: Vec<&str> = key.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    parts
        .iter()
        .all(|p| p.len() == 5 && p.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn eval_now_starts_within_recent_window() {
        let p = LicensePosture::eval_now();
        let LicensePosture::Eval { accepted_at } = p else {
            panic!("expected trial-mode posture");
        };
        let now = now_unix_secs();
        assert!((now - accepted_at).abs() < 10);
    }

    #[test]
    fn days_until_expiry_for_fresh_eval_is_about_90() {
        let p = LicensePosture::eval_now();
        let d = p.days_until_expiry().expect("trial has expiry");
        // Expect 89 or 90 depending on rounding window.
        assert!((89..=90).contains(&d), "got {d} days");
    }

    #[test]
    fn days_until_expiry_negative_for_old_eval() {
        let p = LicensePosture::Eval {
            accepted_at: now_unix_secs() - (200 * 24 * 60 * 60),
        };
        let d = p.days_until_expiry().expect("expiry returns Some");
        assert!(d < 0, "expired trial should report negative days, got {d}");
    }

    #[test]
    fn days_until_expiry_none_for_key_postures() {
        let key = LicensePosture::Key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".into());
        assert!(key.days_until_expiry().is_none());
        let kf = LicensePosture::KeyFile(PathBuf::from("/tmp/keys.csv"));
        assert!(kf.days_until_expiry().is_none());
    }

    #[test]
    fn eval_expiring_soon_threshold() {
        let p_fresh = LicensePosture::eval_now();
        // Fresh trial has ~90 days; "<7" should be false.
        assert!(!p_fresh.eval_expiring_soon(7));
        let p_old = LicensePosture::Eval {
            accepted_at: now_unix_secs() - (88 * 24 * 60 * 60),
        };
        // Roughly 1-2 days remaining; "<7" should be true.
        assert!(p_old.eval_expiring_soon(7));
    }

    #[test]
    fn round_trip_eval_through_toml() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        let p = LicensePosture::Eval {
            accepted_at: 1_700_000_000,
        };
        save_posture_to(&p, &path).expect("save trial");
        let back = current_posture_from(&path)
            .expect("load")
            .expect("posture present");
        assert_eq!(back, p);
    }

    #[test]
    fn round_trip_key_through_toml() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        let p = LicensePosture::Key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".into());
        save_posture_to(&p, &path).expect("save key");
        let back = current_posture_from(&path)
            .expect("load")
            .expect("posture present");
        assert_eq!(back, p);
    }

    #[test]
    fn round_trip_key_file_through_toml() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        let kf = tmp.path().join("keys.csv");
        let p = LicensePosture::KeyFile(kf);
        save_posture_to(&p, &path).expect("save key_file");
        let back = current_posture_from(&path)
            .expect("load")
            .expect("posture present");
        assert_eq!(back, p);
    }

    #[test]
    fn missing_file_returns_none() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("does-not-exist.toml");
        assert_eq!(current_posture_from(&path).expect("ok"), None);
    }

    #[test]
    fn malformed_toml_routes_to_state_corrupted() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(&path, "[license\nmode = \"trial\"").expect("write malformed");
        let err = current_posture_from(&path).expect_err("malformed");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn unknown_mode_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(&path, "[license]\nmode = \"unknown_mode_foo\"\n").expect("write");
        let err = current_posture_from(&path).expect_err("unknown mode");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn key_mode_without_key_field_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(&path, "[license]\nmode = \"key\"\n").expect("write");
        let err = current_posture_from(&path).expect_err("missing key");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn invalid_key_format_rejected() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(&path, "[license]\nmode = \"key\"\nkey = \"short-key\"\n").expect("write");
        let err = current_posture_from(&path).expect_err("malformed key");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn validate_product_key_accepts_xxxxx_format() {
        assert!(validate_product_key("VK7JG-NPHTM-C97JM-9MPGT-3V66T"));
        assert!(validate_product_key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"));
        assert!(validate_product_key("12345-67890-ABCDE-FGHIJ-KLMNO"));
    }

    #[test]
    fn validate_product_key_rejects_obviously_bad_inputs() {
        assert!(!validate_product_key(""));
        assert!(!validate_product_key("abc"));
        assert!(!validate_product_key("AAAAA-BBBBB-CCCCC-DDDDD"));
        assert!(!validate_product_key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE-FFFFF"));
        assert!(!validate_product_key("AAAA-BBBBB-CCCCC-DDDDD-EEEEE"));
        assert!(!validate_product_key("AAAAA BBBBB CCCCC DDDDD EEEEE"));
        assert!(!validate_product_key("AAAAA-BBBBB-CCCCC-DDDDD-EEE!E"));
    }

    #[test]
    fn save_overwrites_existing_block() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        save_posture_to(&LicensePosture::Eval { accepted_at: 1 }, &path).expect("first");
        save_posture_to(
            &LicensePosture::Key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".into()),
            &path,
        )
        .expect("second");
        let back = current_posture_from(&path).expect("load").expect("some");
        assert!(matches!(back, LicensePosture::Key(_)));
    }

    #[test]
    fn rearm_command_for_guest_is_powershell_invocation() {
        let cmd = rearm_command_for_guest();
        assert!(cmd.contains("powershell"));
        assert!(cmd.contains("slmgr"));
        assert!(cmd.contains("/rearm"));
    }

    #[test]
    fn default_bridge_config_path_ends_with_neon_bridge_toml() {
        if let Some(path) = default_bridge_config_path() {
            let suffix = std::path::Path::new("neon").join("bridge.toml");
            assert!(path.ends_with(&suffix), "got {}", path.display());
        }
    }

    #[test]
    fn empty_bridge_toml_has_no_posture() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        std::fs::write(&path, "").expect("write empty");
        assert_eq!(current_posture_from(&path).expect("ok"), None);
    }

    #[test]
    fn eval_accepted_at_zero_treated_as_long_ago() {
        let p = LicensePosture::Eval { accepted_at: 0 };
        let d = p.days_until_expiry().expect("some");
        assert!(d < 0);
    }

    #[cfg(unix)]
    #[test]
    fn save_posture_writes_with_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("bridge.toml");
        save_posture_to(
            &LicensePosture::Key("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".into()),
            &path,
        )
        .expect("save");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "license file with raw key must be mode 0600 (got {mode:o})"
        );
    }
}
