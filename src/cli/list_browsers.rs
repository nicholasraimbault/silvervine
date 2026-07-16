//! `silvervine list-browsers` — enumerate detected + custom-config browsers.
//!
//! Default mode prints a friendly table of "currently installed" browsers.
//! `--all` includes auto-discovered + custom-config entries that aren't
//! resolvable on disk. `--json` emits structured output for scripts.

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::browsers::{self, Browser, BrowserKind};
use crate::cli::OutputOptions;
use crate::error::Result;

/// Args for `silvervine list-browsers`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Args {
    /// `--all`: include known browsers from the static list that aren't
    /// installed on disk (i.e. potential install targets).
    pub all: bool,
    /// Output flags inherited from the global CLI parser.
    pub output: OutputOptions,
}

/// JSON representation of one entry in the list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEntry {
    /// Display name of the browser.
    pub name: String,
    /// Absolute path on disk (if installed).
    pub install_path: Option<String>,
    /// `"known"` / `"detected"` / `"custom"`.
    pub source: String,
    /// `true` if the path resolves to an existing directory.
    pub installed: bool,
}

impl ListEntry {
    fn from_browser(b: &Browser) -> Self {
        let installed = b.install_path().exists();
        Self {
            name: b.name().to_string(),
            install_path: Some(b.install_path().display().to_string()),
            source: source_label(b.kind).to_string(),
            installed,
        }
    }
}

fn source_label(kind: BrowserKind) -> &'static str {
    match kind {
        BrowserKind::Known => "known",
        BrowserKind::Detected => "detected",
        BrowserKind::Custom => "custom",
    }
}

/// Build the list of entries to display, given a snapshot of detected
/// browsers and the `all` flag.
///
/// In `--all` mode we add known-browser stubs even when they aren't
/// installed on disk, so the user can see "Helium is supported but not
/// installed".
#[must_use]
pub fn build_entries(detected: &[Browser], os: Option<browsers::Os>, all: bool) -> Vec<ListEntry> {
    let mut entries: Vec<ListEntry> = detected.iter().map(ListEntry::from_browser).collect();
    if all {
        if let Some(os) = os {
            // Add known browsers not in `detected` (i.e. ones whose paths
            // don't currently exist on disk).
            let known = match os {
                browsers::Os::Linux => browsers::KNOWN_LINUX,
                browsers::Os::Macos => browsers::KNOWN_MACOS,
            };
            for k in known {
                if !entries.iter().any(|e| e.name == k.name) {
                    entries.push(ListEntry {
                        name: k.name.to_string(),
                        install_path: None,
                        source: "known".into(),
                        installed: false,
                    });
                }
            }
        }
    }
    entries
}

/// Render entries as a friendly text table to `out`.
fn render_text(entries: &[ListEntry], out: &mut dyn Write) -> std::io::Result<()> {
    if entries.is_empty() {
        writeln!(out, "No browsers detected.")?;
        return Ok(());
    }
    let name_w = entries
        .iter()
        .map(|e| e.name.len())
        .max()
        .unwrap_or(0)
        .max(8);
    let source_w = 9;
    writeln!(
        out,
        "{:name_w$}  {:source_w$}  {:9}  PATH",
        "BROWSER",
        "SOURCE",
        "INSTALLED",
        name_w = name_w,
        source_w = source_w,
    )?;
    for e in entries {
        let installed = if e.installed { "yes" } else { "no" };
        let path = e.install_path.as_deref().unwrap_or("(not installed)");
        writeln!(
            out,
            "{:name_w$}  {:source_w$}  {:9}  {}",
            e.name,
            e.source,
            installed,
            path,
            name_w = name_w,
            source_w = source_w,
        )?;
    }
    Ok(())
}

/// Render entries as a JSON array.
fn render_json(entries: &[ListEntry], out: &mut dyn Write) -> Result<()> {
    let s = serde_json::to_string_pretty(entries)?;
    writeln!(out, "{s}").map_err(crate::error::Error::from)?;
    Ok(())
}

/// CLI entry point.
///
/// # Errors
///
/// * Any error from [`browsers::detect_browsers`] (malformed config).
pub fn run(args: &Args) -> Result<()> {
    let detected = browsers::detect_browsers().unwrap_or_default();
    let os = browsers::Os::current();
    let entries = build_entries(&detected, os, args.all);

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    if args.output.json {
        render_json(&entries, &mut handle)?;
    } else {
        render_text(&entries, &mut handle).map_err(crate::error::Error::from)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn fake_browser(name: &str, path: PathBuf, kind: BrowserKind) -> Browser {
        Browser {
            name: name.into(),
            install_path: path,
            kind,
            framework_name: None,
        }
    }

    #[test]
    fn build_entries_no_all_flag_only_includes_detected() {
        let tmp = TempDir::new().unwrap();
        let helium = tmp.path().join("helium");
        std::fs::create_dir_all(&helium).unwrap();
        let detected = vec![fake_browser("Helium", helium, BrowserKind::Known)];
        let entries = build_entries(&detected, Some(browsers::Os::Linux), false);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Helium");
        assert!(entries[0].installed);
        assert_eq!(entries[0].source, "known");
    }

    #[test]
    fn build_entries_with_all_flag_adds_uninstalled_known() {
        // No browsers detected; --all should surface the static known list.
        let entries = build_entries(&[], Some(browsers::Os::Linux), true);
        assert!(!entries.is_empty(), "all flag should add known entries");
        for e in &entries {
            assert_eq!(e.source, "known");
            assert!(!e.installed);
            assert!(e.install_path.is_none());
        }
    }

    #[test]
    fn build_entries_no_os_returns_just_detected() {
        let tmp = TempDir::new().unwrap();
        let helium = tmp.path().join("h");
        std::fs::create_dir_all(&helium).unwrap();
        let detected = vec![fake_browser("Helium", helium, BrowserKind::Known)];
        let entries = build_entries(&detected, None, true);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn render_text_empty_says_nothing_detected() {
        let mut buf = Vec::new();
        render_text(&[], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("No browsers"));
    }

    #[test]
    fn render_text_includes_columns() {
        let entries = vec![ListEntry {
            name: "Helium".into(),
            install_path: Some("/opt/helium".into()),
            source: "known".into(),
            installed: true,
        }];
        let mut buf = Vec::new();
        render_text(&entries, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("BROWSER"));
        assert!(s.contains("Helium"));
        assert!(s.contains("/opt/helium"));
        assert!(s.contains("yes"));
    }

    #[test]
    fn render_json_emits_valid_array() {
        let entries = vec![ListEntry {
            name: "Helium".into(),
            install_path: None,
            source: "known".into(),
            installed: false,
        }];
        let mut buf = Vec::new();
        render_json(&entries, &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed[0]["name"], "Helium");
        assert_eq!(parsed[0]["installed"], false);
    }

    #[test]
    fn list_entry_round_trips_through_json() {
        let original = ListEntry {
            name: "Test".into(),
            install_path: Some("/x".into()),
            source: "known".into(),
            installed: true,
        };
        let json = serde_json::to_string(&original).unwrap();
        let back: ListEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, original.name);
    }

    #[test]
    fn source_label_covers_every_kind() {
        assert_eq!(source_label(BrowserKind::Known), "known");
        assert_eq!(source_label(BrowserKind::Detected), "detected");
        assert_eq!(source_label(BrowserKind::Custom), "custom");
    }
}
