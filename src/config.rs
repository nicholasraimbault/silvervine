//! Global Silvervine config schema (`~/.config/silvervine/config.toml`).
//!
//! Per the spec's "Custom browser config" section, the schema is:
//!
//! ```toml
//! [notifications]
//! on_success = true
//! on_failure = true
//!
//! [[browsers]]
//! name = "MyCustomBrowser"
//! # macOS:
//! bundle_path = "/Users/me/Applications/MyCustomBrowser.app"
//! framework_name = "MyCustomBrowser Framework"
//! # Linux alternative:
//! # install_path = "/home/me/dev/my-build"
//!
//! [hooks]
//! post_patch = "~/.config/silvervine/hooks/post-patch"
//! post_update = "~/.config/silvervine/hooks/post-update"
//! ```
//!
//! ## Loading rules
//!
//! 1. If the file is absent → return [`Config::default`] (no error).
//! 2. If the file is present and valid TOML matching the schema → parsed config.
//! 3. If the file is present but malformed → [`crate::ErrorCategory::StateCorrupted`].
//!
//! ## Path expansion
//!
//! `[hooks]` values get a `~` -> `$HOME` expansion; otherwise paths are
//! taken verbatim. We don't expand `[[browsers]]` paths because the
//! browsers module owns canonicalization (a custom browser's path may
//! validly point at something that does not yet exist).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Default location of the config file: `$XDG_CONFIG_HOME/silvervine/config.toml`.
///
/// Returns `None` if neither `$XDG_CONFIG_HOME` nor `$HOME` are set —
/// callers should treat this as "no config file" (i.e. use defaults).
#[must_use]
pub fn default_config_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("silvervine").join("config.toml"))
}

/// Top-level config schema.
///
/// All sections are optional in TOML; serde fills in `Default::default`
/// for any missing one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `[notifications]` block — when to surface tray/desktop notifications.
    pub notifications: NotificationsConfig,
    /// Zero or more `[[browsers]]` entries adding to the auto-discovered list.
    #[serde(rename = "browsers", default)]
    pub browsers: Vec<CustomBrowserConfig>,
    /// `[hooks]` block — paths to scripts run on patch / update events.
    pub hooks: HooksConfig,
}

/// `[notifications]` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationsConfig {
    /// Show a notification on a successful patch / update. Default: `true`.
    pub on_success: bool,
    /// Show a notification on a failed patch / update. Default: `true`.
    pub on_failure: bool,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            on_success: true,
            on_failure: true,
        }
    }
}

/// One `[[browsers]]` entry in the config.
///
/// The schema is intentionally union-style: macOS users set
/// `bundle_path` + `framework_name`; Linux users set `install_path`.
/// The browsers module (`browsers::config`) consumes this to extend
/// the auto-discovered list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomBrowserConfig {
    /// Display name for the browser (e.g. `"MyCustomBrowser"`).
    pub name: String,
    /// macOS: absolute path to the `.app` bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_path: Option<PathBuf>,
    /// macOS: name of the framework directory inside the bundle
    /// (e.g. `"MyCustomBrowser Framework"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_name: Option<String>,
    /// Linux: absolute path to the install directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_path: Option<PathBuf>,
}

/// `[hooks]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HooksConfig {
    /// Path to a post-patch script. `~` is expanded to `$HOME`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_patch: Option<String>,
    /// Path to a post-update script. `~` is expanded to `$HOME`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_update: Option<String>,
}

/// Top-level sections from older config schemas that should be silently
/// dropped on load. Keeps existing user configs from hard-failing the
/// daemon after an upgrade. Add to this list when a section is removed
/// from the schema; never repurpose a name.
const DEPRECATED_TOP_LEVEL_SECTIONS: &[&str] = &["reporting"];

impl Config {
    /// Parse a TOML string into a [`Config`].
    ///
    /// Top-level sections listed in [`DEPRECATED_TOP_LEVEL_SECTIONS`] are
    /// stripped before strict deserialization, so a config carried over
    /// from an older Silvervine release doesn't crash the daemon. Unknown
    /// *non-deprecated* keys still fail loudly to catch typos.
    ///
    /// # Errors
    ///
    /// [`crate::ErrorCategory::StateCorrupted`] if the input is not valid
    /// TOML or contains unknown fields outside the deprecated allow-list.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let mut value: toml::Value = toml::from_str(s).map_err(Error::from)?;
        if let Some(table) = value.as_table_mut() {
            for &section in DEPRECATED_TOP_LEVEL_SECTIONS {
                if table.remove(section).is_some() {
                    tracing::warn!(
                        target: "silvervine::config",
                        section,
                        "ignoring deprecated top-level config section"
                    );
                }
            }
        }
        value.try_into().map_err(Error::from)
    }

    /// Serialize back to a TOML string. Useful for round-trip tests and
    /// for an eventual "silvervine config edit" command.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ErrorCategory::Other`] if serialization fails (very
    /// rare with `Serialize`-derived types).
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| Error::other("could not serialize config to TOML").with_source(e))
    }

    /// Resolve the post-patch hook script path (with `~` expansion).
    ///
    /// Returns `None` if no `[hooks].post_patch` entry is set.
    #[must_use]
    pub fn post_patch_hook(&self) -> Option<PathBuf> {
        self.hooks.post_patch.as_deref().map(resolve_hook_path)
    }

    /// Resolve the post-update hook script path (with `~` expansion).
    #[must_use]
    pub fn post_update_hook(&self) -> Option<PathBuf> {
        self.hooks.post_update.as_deref().map(resolve_hook_path)
    }
}

/// Load the config from the default path (`~/.config/silvervine/config.toml`).
///
/// If the file is absent, returns [`Config::default`]. If the file is
/// malformed, returns [`crate::ErrorCategory::StateCorrupted`].
///
/// # Errors
///
/// See above.
pub fn load_config() -> Result<Config> {
    let Some(path) = default_config_path() else {
        return Ok(Config::default());
    };
    load_config_from(&path)
}

/// Load config from an explicit path. Used by tests and by callers that
/// want to point at a non-default location.
///
/// # Errors
///
/// See [`load_config`].
pub fn load_config_from(path: &std::path::Path) -> Result<Config> {
    match std::fs::read_to_string(path) {
        Ok(s) => Config::from_toml_str(&s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(Error::from(e)),
    }
}

/// Expand a leading `~/` to `$HOME/` (or `$HOME` if the input is just `~`).
/// Anything else is returned verbatim. Returns the input unchanged if no
/// `$HOME` is set.
fn expand_tilde(s: &str) -> PathBuf {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if s == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(s)
}

fn resolve_hook_path(value: &str) -> PathBuf {
    let path = expand_tilde(value);
    let current_root = crate::platform::config_dir();
    let legacy_root = current_root
        .parent()
        .map_or_else(|| PathBuf::from("neon"), |parent| parent.join("neon"));
    remap_legacy_hook_path(&path, &legacy_root, &current_root)
}

/// Remap an absent explicit hook under the Neon config root to its migrated
/// Silvervine location. Existing legacy paths remain authoritative.
fn remap_legacy_hook_path(
    path: &std::path::Path,
    legacy_root: &std::path::Path,
    current_root: &std::path::Path,
) -> PathBuf {
    if path.exists() || !path.starts_with(legacy_root) {
        return path.to_path_buf();
    }
    path.strip_prefix(legacy_root).map_or_else(
        |_| path.to_path_buf(),
        |relative| current_root.join(relative),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sensible_defaults() {
        let cfg = Config::default();
        assert!(cfg.notifications.on_success);
        assert!(cfg.notifications.on_failure);
        assert!(cfg.browsers.is_empty());
        assert!(cfg.hooks.post_patch.is_none());
    }

    #[test]
    fn parses_full_example_from_spec() {
        let toml = r#"
[notifications]
on_success = true
on_failure = true

[[browsers]]
name = "MyCustomBrowser"
bundle_path = "/Users/me/Applications/MyCustomBrowser.app"
framework_name = "MyCustomBrowser Framework"

[[browsers]]
name = "LinuxBrowser"
install_path = "/home/me/dev/my-build"

[hooks]
post_patch = "~/.config/silvervine/hooks/post-patch"
post_update = "~/.config/silvervine/hooks/post-update"
"#;
        let cfg = Config::from_toml_str(toml).expect("spec example must parse");
        assert!(cfg.notifications.on_success);
        assert!(cfg.notifications.on_failure);
        assert_eq!(cfg.browsers.len(), 2);
        assert_eq!(cfg.browsers[0].name, "MyCustomBrowser");
        assert_eq!(
            cfg.browsers[0].framework_name.as_deref(),
            Some("MyCustomBrowser Framework")
        );
        assert!(cfg.browsers[0].bundle_path.is_some());
        assert!(cfg.browsers[1].install_path.is_some());
        assert_eq!(
            cfg.hooks.post_patch.as_deref(),
            Some("~/.config/silvervine/hooks/post-patch")
        );
    }

    #[test]
    fn empty_toml_yields_defaults() {
        let cfg = Config::from_toml_str("").expect("empty toml is valid");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let toml = r"
unknown_field = 42

[notifications]
on_success = true
on_failure = true
";
        let err = Config::from_toml_str(toml).expect_err("unknown field should fail");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    /// Legacy `[reporting]` block (from v1 / v2-rc.0 configs) must be
    /// tolerated and silently dropped — not hard-fail the daemon on first
    /// launch after upgrading.
    #[test]
    fn legacy_reporting_section_is_silently_dropped() {
        let toml = r"
browsers = []

[notifications]
on_success = true
on_failure = true

[reporting]
opt_in_error_reporting = false

[hooks]
";
        let cfg = Config::from_toml_str(toml).expect("legacy [reporting] block must parse");
        assert!(cfg.notifications.on_success);
        assert!(cfg.notifications.on_failure);
        assert!(cfg.browsers.is_empty());
        assert!(cfg.hooks.post_patch.is_none());
    }

    /// Round-trip through legacy config: re-serializing the parsed Config
    /// must not emit the `[reporting]` block (the section is gone for good).
    #[test]
    fn legacy_reporting_section_does_not_round_trip() {
        let toml = r"
[reporting]
opt_in_error_reporting = false
";
        let cfg = Config::from_toml_str(toml).expect("parses");
        let out = cfg.to_toml_string().expect("serializes");
        assert!(
            !out.contains("[reporting]"),
            "legacy section must not be re-serialized; got:\n{out}"
        );
    }

    #[test]
    fn unknown_field_in_subsection_is_rejected() {
        let toml = r"
[notifications]
on_success = true
on_failure = true
typo_field = false
";
        let err = Config::from_toml_str(toml).expect_err("unknown nested field should fail");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn malformed_toml_routes_to_state_corrupted() {
        let toml = "[unterminated table";
        let err = Config::from_toml_str(toml).expect_err("bad TOML must error");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn round_trip_preserves_values() {
        let cfg = Config {
            notifications: NotificationsConfig {
                on_success: false,
                on_failure: true,
            },
            browsers: vec![CustomBrowserConfig {
                name: "X".into(),
                bundle_path: None,
                framework_name: None,
                install_path: Some(PathBuf::from("/opt/x")),
            }],
            hooks: HooksConfig {
                post_patch: Some("/tmp/post-patch".into()),
                post_update: None,
            },
        };
        let s = cfg.to_toml_string().expect("round trip serializes");
        let back = Config::from_toml_str(&s).expect("round trip parses");
        assert_eq!(cfg, back);
    }

    #[test]
    fn missing_file_returns_default() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let nonexistent = tmp.path().join("not-here.toml");
        let cfg = load_config_from(&nonexistent).expect("missing file is fine");
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn malformed_file_returns_error() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("bad.toml");
        std::fs::write(&path, "[bad").expect("write malformed file");
        let err = load_config_from(&path).expect_err("malformed file must error");
        assert_eq!(err.category, crate::ErrorCategory::StateCorrupted);
    }

    #[test]
    fn valid_file_is_loaded_from_disk() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let path = tmp.path().join("ok.toml");
        std::fs::write(
            &path,
            r"
[notifications]
on_success = false
on_failure = true
",
        )
        .expect("write file");
        let cfg = load_config_from(&path).expect("parses ok");
        assert!(!cfg.notifications.on_success);
        assert!(cfg.notifications.on_failure);
    }

    #[test]
    fn tilde_expansion_uses_home_dir() {
        if let Some(home) = dirs::home_dir() {
            let expanded = expand_tilde("~/foo/bar");
            assert_eq!(expanded, home.join("foo").join("bar"));
        }
        // When no home_dir is available we fall through; the test
        // still asserts something useful (no panic).
        let no_tilde = expand_tilde("/etc/passwd");
        assert_eq!(no_tilde, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn post_patch_hook_resolves_through_expand_tilde() {
        let cfg = Config {
            hooks: HooksConfig {
                post_patch: Some("/absolute/post-patch".into()),
                post_update: None,
            },
            ..Default::default()
        };
        assert_eq!(
            cfg.post_patch_hook(),
            Some(PathBuf::from("/absolute/post-patch"))
        );
        assert_eq!(cfg.post_update_hook(), None);
    }

    #[test]
    fn default_config_path_ends_with_silvervine_config() {
        if let Some(path) = default_config_path() {
            let suffix = std::path::Path::new("silvervine").join("config.toml");
            assert!(path.ends_with(&suffix), "got {}", path.display());
        }
    }

    /// Production `load_config` entrypoint must not panic. It reads from
    /// `~/.config/silvervine/config.toml`, which on a fresh machine is absent
    /// (so it returns the default). On the dev machine it may either be
    /// absent or contain user-edited content; either way the function
    /// must succeed (or return a categorized error).
    #[test]
    fn load_config_does_not_panic() {
        let _ = load_config();
    }

    #[test]
    fn absent_explicit_neon_hook_path_maps_to_silvervine_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let legacy = tmp.path().join("neon");
        let current = tmp.path().join("silvervine");
        let old_hook = legacy.join("hooks/post-patch");
        assert_eq!(
            remap_legacy_hook_path(&old_hook, &legacy, &current),
            current.join("hooks/post-patch")
        );
    }

    #[test]
    fn existing_explicit_neon_hook_path_is_preserved() {
        let tmp = tempfile::TempDir::new().unwrap();
        let legacy = tmp.path().join("neon");
        let current = tmp.path().join("silvervine");
        let old_hook = legacy.join("hooks/post-patch");
        std::fs::create_dir_all(old_hook.parent().unwrap()).unwrap();
        std::fs::write(&old_hook, b"#!/bin/sh").unwrap();
        assert_eq!(
            remap_legacy_hook_path(&old_hook, &legacy, &current),
            old_hook
        );
    }

    #[test]
    fn post_update_hook_returns_none_when_unset() {
        let cfg = Config::default();
        assert!(cfg.post_update_hook().is_none());
    }

    #[test]
    fn post_update_hook_returns_path_when_set() {
        let cfg = Config {
            hooks: HooksConfig {
                post_patch: None,
                post_update: Some("/tmp/post-update".into()),
            },
            ..Default::default()
        };
        assert_eq!(
            cfg.post_update_hook(),
            Some(PathBuf::from("/tmp/post-update"))
        );
    }

    #[test]
    fn bare_tilde_expands_to_home() {
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_tilde("~"), home);
        }
    }
}
