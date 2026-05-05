//! kvmfr kernel module detection — V3-Phase D.
//!
//! The kvmfr module is the kernel side of [Looking Glass](https://looking-glass.io)'s
//! shared-memory transport. It exposes a `/dev/kvmfr0` character device
//! that QEMU maps as an `IVSHMEM` region; the Windows guest writes
//! framebuffer data there and the Linux host reads it (with no copy).
//!
//! kvmfr is **not** in the mainline Linux kernel — Looking Glass ships
//! it as an out-of-tree module that's typically installed via DKMS:
//! `looking-glass-module-dkms` (Arch AUR) / `looking-glass-kvmfr-dkms`
//! (Debian backports). Once installed + loaded, `/dev/kvmfr0` appears
//! and Looking Glass works without root.
//!
//! ## Detection contract
//!
//! [`detect_kvmfr`] walks three signals in order:
//!
//! 1. `/proc/modules` — is the module currently loaded into the running
//!    kernel?
//! 2. `/sys/class/misc/kvmfr` — does the loaded module's misc class
//!    entry exist? (Confirms the module is loaded; a stale entry in
//!    `/proc/modules` without this is a kernel bug.)
//! 3. `/dev/kvmfr0` — is the user-facing device file present?
//!
//! All three must agree for [`KvmfrStatus::Loaded`]. Any partial state
//! degrades gracefully:
//!
//! * `Loaded` — all three signals present.
//! * `Available` — module file exists under `/lib/modules/<ver>/extra`
//!   or `/lib/modules/<ver>/updates/dkms` but isn't currently loaded.
//!   User runs the documented `modprobe` command (sudo).
//! * `Missing` — no signs of kvmfr anywhere; user must install
//!   `looking-glass-module-dkms` (or equivalent) first.
//!
//! ## Test mode
//!
//! [`NOOP_ENV`] (`NEON_TEST_KVMFR_NOOP=1`) makes [`detect_kvmfr`]
//! return [`KvmfrStatus::Loaded`] with a fixture device path. Tests that
//! want to exercise a specific status code use [`detect_kvmfr_with`]
//! against a [`KvmfrRoots`] pointing at a synthesized tempdir tree.

use std::path::{Path, PathBuf};

/// Env var that short-circuits real kvmfr probing in tests. When set,
/// [`detect_kvmfr`] returns a fixture [`KvmfrStatus::Loaded`].
pub const NOOP_ENV: &str = "NEON_TEST_KVMFR_NOOP";

/// Documented `sudo modprobe` command users run to load kvmfr with the
/// recommended 64 MB static shared-memory region (Looking Glass needs
/// at least 32 MB; 64 MB gives headroom for 4K @ 60Hz HDR).
const MODPROBE_COMMAND: &str = "sudo modprobe kvmfr static_size_mb=64";

/// Single-line return: the documented modprobe command. **Does NOT
/// execute** — the wizard surfaces this in remediation and the user runs
/// it themselves (sudo guardrail).
#[must_use]
pub fn load_module_command() -> &'static str {
    MODPROBE_COMMAND
}

/// udev rule body installers paste into `/etc/udev/rules.d/99-kvmfr.rules`
/// to give `/dev/kvmfr0` mode `0660` and group `libvirt` (or `kvm`) so
/// non-root users in those groups can read+write.
const UDEV_RULE: &str = r#"# /etc/udev/rules.d/99-kvmfr.rules — neon-bridge kvmfr permissions.
SUBSYSTEM=="kvmfr", OWNER="root", GROUP="kvm", MODE="0660"
"#;

/// udev rule text the wizard tells the user to install.
#[must_use]
pub fn udev_rule_text() -> &'static str {
    UDEV_RULE
}

/// Detection outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvmfrStatus {
    /// Module loaded; `/dev/kvmfr0` exists and is usable.
    Loaded {
        /// Path to the device file (typically `/dev/kvmfr0`).
        device_path: PathBuf,
    },
    /// Module is installed (`.ko` file under `/lib/modules/<ver>/extra/`
    /// or DKMS) but not currently loaded into the running kernel.
    Available {
        /// Path to the `.ko` file we detected.
        module_path: PathBuf,
    },
    /// No kvmfr installed or loaded. User runs `looking-glass-module-dkms`
    /// (or equivalent) installation first.
    Missing,
}

impl KvmfrStatus {
    /// `true` when the module is currently loaded and the device file
    /// is present.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        matches!(self, Self::Loaded { .. })
    }
}

/// Filesystem roots used by [`detect_kvmfr_with`]. Tests construct one
/// pointing at a `tempfile::TempDir` so the synthesized `/proc/modules`,
/// `/sys/class/misc`, and `/dev` trees are isolated from the host.
#[derive(Debug, Clone)]
pub struct KvmfrRoots {
    /// `/proc/modules` file path (real host: `/proc/modules`).
    pub proc_modules: PathBuf,
    /// `/sys/class/misc` directory path.
    pub sys_class_misc: PathBuf,
    /// `/dev` directory path (we look for `kvmfr0` inside).
    pub dev: PathBuf,
    /// `/lib/modules` root (we look for `<ver>/extra/kvmfr.ko*`).
    pub lib_modules: PathBuf,
}

impl KvmfrRoots {
    /// Build host-default roots from the real filesystem.
    #[must_use]
    pub fn host() -> Self {
        Self {
            proc_modules: PathBuf::from("/proc/modules"),
            sys_class_misc: PathBuf::from("/sys/class/misc"),
            dev: PathBuf::from("/dev"),
            lib_modules: PathBuf::from("/lib/modules"),
        }
    }
}

/// Detect kvmfr status using the real host filesystem.
///
/// Honors [`NOOP_ENV`]: when set, returns
/// `KvmfrStatus::Loaded { device_path: "/dev/kvmfr0" }` (the fixture
/// path) without touching the filesystem.
#[must_use]
pub fn detect_kvmfr() -> KvmfrStatus {
    if std::env::var_os(NOOP_ENV).is_some() {
        return KvmfrStatus::Loaded {
            device_path: PathBuf::from("/dev/kvmfr0"),
        };
    }
    detect_kvmfr_with(&KvmfrRoots::host())
}

/// Detect kvmfr status against the given roots.
///
/// Tests synthesize a tempdir tree and pass roots pointing at it.
#[must_use]
pub fn detect_kvmfr_with(roots: &KvmfrRoots) -> KvmfrStatus {
    let module_loaded = is_module_loaded(&roots.proc_modules);
    let misc_present = roots.sys_class_misc.join("kvmfr").exists();
    let device_path = roots.dev.join("kvmfr0");
    let device_present = device_path.exists();

    if module_loaded && misc_present && device_present {
        return KvmfrStatus::Loaded { device_path };
    }
    // If any signal exists but the trio isn't complete, treat as
    // partially-loaded → still surface "Available" so the wizard
    // suggests modprobe + udev rule.
    if module_loaded || misc_present || device_present {
        return KvmfrStatus::Available {
            module_path: device_path,
        };
    }
    if let Some(p) = find_module_ko(&roots.lib_modules) {
        return KvmfrStatus::Available { module_path: p };
    }
    KvmfrStatus::Missing
}

/// Parse `/proc/modules` looking for a line starting with `kvmfr `.
///
/// `/proc/modules` format: each line is `<name> <size> <usecount>
/// <dependencies> <state> <addr>`. We only care about the first column.
fn is_module_loaded(proc_modules: &Path) -> bool {
    let Ok(s) = std::fs::read_to_string(proc_modules) else {
        return false;
    };
    s.lines()
        .any(|line| line.split_whitespace().next() == Some("kvmfr"))
}

/// Walk `<lib_modules>/<any-ver>/{extra,updates/dkms,kernel}` looking for
/// `kvmfr.ko*` (raw, gzipped, zstd). Returns the first match.
fn find_module_ko(lib_modules: &Path) -> Option<PathBuf> {
    let kernel_dirs = std::fs::read_dir(lib_modules).ok()?;
    for entry in kernel_dirs.flatten() {
        let kernel_dir = entry.path();
        if !kernel_dir.is_dir() {
            continue;
        }
        for sub in &["extra", "updates/dkms", "kernel/extra"] {
            let candidate = kernel_dir.join(sub);
            if let Some(p) = scan_for_kvmfr_ko(&candidate) {
                return Some(p);
            }
        }
    }
    None
}

/// Recursively scan a directory for any file whose name begins with
/// `kvmfr.ko`. Returns the first match.
fn scan_for_kvmfr_ko(dir: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("kvmfr.ko") {
                return Some(path);
            }
        }
        if path.is_dir() {
            if let Some(p) = scan_for_kvmfr_ko(&path) {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Synthesize a `KvmfrRoots` pointing at a tempdir tree.
    fn synth_roots(tmp: &Path) -> KvmfrRoots {
        std::fs::create_dir_all(tmp.join("proc")).expect("mkdir proc");
        std::fs::create_dir_all(tmp.join("sys/class/misc")).expect("mkdir misc");
        std::fs::create_dir_all(tmp.join("dev")).expect("mkdir dev");
        std::fs::create_dir_all(tmp.join("lib/modules")).expect("mkdir libmodules");
        KvmfrRoots {
            proc_modules: tmp.join("proc/modules"),
            sys_class_misc: tmp.join("sys/class/misc"),
            dev: tmp.join("dev"),
            lib_modules: tmp.join("lib/modules"),
        }
    }

    #[test]
    fn missing_when_nothing_present() {
        let tmp = TempDir::new().expect("tempdir");
        let roots = synth_roots(tmp.path());
        assert_eq!(detect_kvmfr_with(&roots), KvmfrStatus::Missing);
    }

    #[test]
    fn loaded_when_all_three_signals_present() {
        let tmp = TempDir::new().expect("tempdir");
        let roots = synth_roots(tmp.path());
        std::fs::write(
            &roots.proc_modules,
            "kvmfr 16384 0 - Live 0xffffffffc0e60000\n",
        )
        .expect("write proc/modules");
        std::fs::create_dir_all(roots.sys_class_misc.join("kvmfr")).expect("misc/kvmfr");
        std::fs::write(roots.dev.join("kvmfr0"), b"").expect("write dev/kvmfr0");
        match detect_kvmfr_with(&roots) {
            KvmfrStatus::Loaded { device_path } => {
                assert_eq!(device_path, roots.dev.join("kvmfr0"));
            }
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    #[test]
    fn available_when_partially_loaded() {
        let tmp = TempDir::new().expect("tempdir");
        let roots = synth_roots(tmp.path());
        std::fs::write(
            &roots.proc_modules,
            "kvmfr 16384 0 - Live 0xffffffffc0e60000\n",
        )
        .expect("write proc/modules");
        // sys/class/misc/kvmfr is missing → Available, not Loaded.
        let status = detect_kvmfr_with(&roots);
        assert!(matches!(status, KvmfrStatus::Available { .. }));
    }

    #[test]
    fn available_when_only_module_file_present() {
        let tmp = TempDir::new().expect("tempdir");
        let roots = synth_roots(tmp.path());
        let kernel_dir = roots.lib_modules.join("6.6.0-arch1-1/extra");
        std::fs::create_dir_all(&kernel_dir).expect("mkdir extra");
        std::fs::write(kernel_dir.join("kvmfr.ko"), b"fake").expect("write ko");
        match detect_kvmfr_with(&roots) {
            KvmfrStatus::Available { module_path } => {
                assert!(module_path.ends_with("kvmfr.ko"));
            }
            other => panic!("expected Available, got {other:?}"),
        }
    }

    #[test]
    fn available_when_module_under_dkms_updates() {
        let tmp = TempDir::new().expect("tempdir");
        let roots = synth_roots(tmp.path());
        let dkms_dir = roots.lib_modules.join("6.6.0/updates/dkms");
        std::fs::create_dir_all(&dkms_dir).expect("mkdir dkms");
        std::fs::write(dkms_dir.join("kvmfr.ko.zst"), b"fake-zst").expect("write zst");
        let status = detect_kvmfr_with(&roots);
        assert!(matches!(status, KvmfrStatus::Available { .. }));
    }

    #[test]
    fn proc_modules_lookup_handles_other_modules() {
        let tmp = TempDir::new().expect("tempdir");
        let roots = synth_roots(tmp.path());
        std::fs::write(
            &roots.proc_modules,
            "btrfs 1740800 0 - Live 0xffffffffc1234567\nzstd_compress 245760 1 btrfs, Live 0x0\n",
        )
        .expect("write proc/modules");
        // No kvmfr line → nothing detected from proc.
        assert_eq!(detect_kvmfr_with(&roots), KvmfrStatus::Missing);
    }

    #[test]
    fn proc_modules_match_must_be_exact_name() {
        let tmp = TempDir::new().expect("tempdir");
        let roots = synth_roots(tmp.path());
        // A module named `kvmfr_companion` should not trigger a match.
        std::fs::write(
            &roots.proc_modules,
            "kvmfr_companion 16384 0 - Live 0xffffffffc0e60000\n",
        )
        .expect("write proc/modules");
        assert_eq!(detect_kvmfr_with(&roots), KvmfrStatus::Missing);
    }

    #[test]
    fn detect_kvmfr_under_noop_env_returns_loaded_fixture() {
        let _g = crate::test_support::env_lock();
        // SAFETY: env behind env_lock.
        unsafe { std::env::set_var(NOOP_ENV, "1") };
        let status = detect_kvmfr();
        match status {
            KvmfrStatus::Loaded { device_path } => {
                assert_eq!(device_path, PathBuf::from("/dev/kvmfr0"));
            }
            other => panic!("expected Loaded under NOOP, got {other:?}"),
        }
        unsafe { std::env::remove_var(NOOP_ENV) };
    }

    #[test]
    fn load_module_command_documents_static_size_64mb() {
        let cmd = load_module_command();
        assert!(cmd.contains("modprobe"));
        assert!(cmd.contains("kvmfr"));
        assert!(cmd.contains("static_size_mb=64"));
        assert!(cmd.contains("sudo"));
    }

    #[test]
    fn udev_rule_text_grants_kvm_group_read_write() {
        let rule = udev_rule_text();
        assert!(rule.contains("SUBSYSTEM"));
        assert!(rule.contains("kvmfr"));
        assert!(rule.contains("0660"));
        assert!(rule.contains("kvm") || rule.contains("libvirt"));
    }

    #[test]
    fn kvmfr_status_is_loaded_predicate() {
        assert!(KvmfrStatus::Loaded {
            device_path: PathBuf::from("/dev/kvmfr0"),
        }
        .is_loaded());
        assert!(!KvmfrStatus::Available {
            module_path: PathBuf::from("/lib/modules/x/extra/kvmfr.ko"),
        }
        .is_loaded());
        assert!(!KvmfrStatus::Missing.is_loaded());
    }

    #[test]
    fn host_roots_use_real_filesystem_paths() {
        let r = KvmfrRoots::host();
        assert_eq!(r.proc_modules, PathBuf::from("/proc/modules"));
        assert_eq!(r.sys_class_misc, PathBuf::from("/sys/class/misc"));
        assert_eq!(r.dev, PathBuf::from("/dev"));
        assert_eq!(r.lib_modules, PathBuf::from("/lib/modules"));
    }

    #[test]
    fn find_module_ko_returns_none_when_lib_modules_empty() {
        let tmp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("lib/modules")).unwrap();
        assert!(find_module_ko(&tmp.path().join("lib/modules")).is_none());
    }
}
