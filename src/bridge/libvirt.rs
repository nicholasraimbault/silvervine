//! libvirt orchestration for the V3 bridge VM — V3-Phase C.
//!
//! Wraps the libvirt-rs (`virt`) crate's `Connect` / `Domain` /
//! `DomainSnapshot` APIs into a small, mock-friendly façade. The
//! [`Hypervisor`] type is the only entry point; tests run under
//! [`HV_NOOP_ENV`] (`NEON_TEST_VIRT_NOOP=1`) which returns a mock
//! hypervisor that records calls without touching libvirt at all.
//!
//! ## Cross-platform note
//!
//! libvirt is a Linux library; the `virt` crate is gated to the Linux
//! target. On macOS the entire real-libvirt path is `cfg`-out and
//! [`Hypervisor::connect`] returns an `UnsupportedPlatform` error.
//! Tests under NOOP mode work on every target.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};

/// Env var that gates real libvirt connections in tests. When set, the
/// `Hypervisor` API returns a mock that records calls instead of
/// touching libvirt at all.
pub const HV_NOOP_ENV: &str = "NEON_TEST_VIRT_NOOP";

/// `true` if [`HV_NOOP_ENV`] is set.
#[must_use]
pub fn noop_enabled() -> bool {
    std::env::var_os(HV_NOOP_ENV).is_some()
}

/// One recorded call against the mock hypervisor. Tests inspect this
/// to assert the orchestration sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HvCall {
    /// `Hypervisor::connect()` was invoked.
    Connect,
    /// `Hypervisor::define_domain(name, _xml)` — name pulled from XML.
    DefineDomain(String),
    /// `Domain::start()` for the named domain.
    StartDomain(String),
    /// `Domain::stop()` for the named domain.
    StopDomain(String),
    /// `Domain::snapshot(name)` — captures the snapshot label.
    SnapshotDomain {
        /// Domain name.
        domain: String,
        /// Snapshot label.
        snapshot: String,
    },
    /// `Domain::restore_from_snapshot(name)`.
    RestoreSnapshot {
        /// Domain name.
        domain: String,
        /// Snapshot label.
        snapshot: String,
    },
    /// `Domain::is_running()` queried.
    QueryIsRunning(String),
    /// `Domain::undefine()` for the named domain.
    UndefineDomain(String),
}

/// Shared mock-recorder log. Cloning the [`Hypervisor`] under NOOP
/// mode shares the same `MockRecorder` across all clones — this lets
/// tests inspect calls made by the production code path.
#[derive(Debug, Clone, Default)]
pub struct MockRecorder {
    inner: Arc<Mutex<Vec<HvCall>>>,
    /// Domains currently "running" in the mock state machine. Pushed to
    /// when `start_domain` is called, removed on `stop_domain`.
    running: Arc<Mutex<Vec<String>>>,
    /// Snapshot labels per domain, in order of creation.
    snapshots: Arc<Mutex<std::collections::HashMap<String, Vec<String>>>>,
}

impl MockRecorder {
    /// Build a fresh recorder. Tests call this to construct a
    /// mock-mode `Hypervisor`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of all calls made so far (cloned). Tests assert against
    /// this.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (a previous lock holder
    /// panicked). Tests don't run multi-threaded against the recorder so
    /// this is essentially unreachable.
    #[must_use]
    pub fn calls(&self) -> Vec<HvCall> {
        self.inner.lock().expect("mock log").clone()
    }

    /// Push a call into the log.
    ///
    /// # Panics
    ///
    /// See [`Self::calls`].
    pub fn push(&self, call: HvCall) {
        self.inner.lock().expect("mock log").push(call);
    }

    /// `true` when the named domain is "running" in the mock state.
    ///
    /// # Panics
    ///
    /// See [`Self::calls`].
    #[must_use]
    pub fn is_running(&self, domain: &str) -> bool {
        self.running
            .lock()
            .expect("running")
            .iter()
            .any(|d| d == domain)
    }

    /// Mark a domain as running in the mock.
    ///
    /// # Panics
    ///
    /// See [`Self::calls`].
    pub fn mark_running(&self, domain: &str) {
        let mut g = self.running.lock().expect("running");
        if !g.iter().any(|d| d == domain) {
            g.push(domain.to_string());
        }
    }

    /// Mark a domain as stopped in the mock.
    ///
    /// # Panics
    ///
    /// See [`Self::calls`].
    pub fn mark_stopped(&self, domain: &str) {
        let mut g = self.running.lock().expect("running");
        g.retain(|d| d != domain);
    }

    /// Add a snapshot to the mock state.
    ///
    /// # Panics
    ///
    /// See [`Self::calls`].
    pub fn record_snapshot(&self, domain: &str, snap: &str) {
        let mut g = self.snapshots.lock().expect("snaps");
        g.entry(domain.to_string())
            .or_default()
            .push(snap.to_string());
    }

    /// All recorded snapshots for a domain.
    ///
    /// # Panics
    ///
    /// See [`Self::calls`].
    #[must_use]
    pub fn snapshots(&self, domain: &str) -> Vec<String> {
        self.snapshots
            .lock()
            .expect("snaps")
            .get(domain)
            .cloned()
            .unwrap_or_default()
    }
}

/// Mode the [`Hypervisor`] is in.
#[derive(Debug)]
enum HvMode {
    /// Mock — records calls, no libvirt I/O.
    Mock(MockRecorder),
    /// Real — wraps a `virt::Connect` (Linux only).
    #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
    Real(virt::connect::Connect),
}

/// Hypervisor connection wrapper.
///
/// Construct via [`Hypervisor::connect`] (production) or
/// [`Hypervisor::mock`] (tests).
pub struct Hypervisor {
    mode: HvMode,
}

impl Hypervisor {
    /// Connect to the host hypervisor.
    ///
    /// * If `NEON_TEST_VIRT_NOOP=1` is set, returns a mock-mode
    ///   hypervisor (zero I/O, records calls).
    /// * On Linux without NOOP, opens `qemu:///system` (Nick's
    ///   primary path).
    /// * On macOS, returns
    ///   [`crate::ErrorCategory::UnsupportedPlatform`] — the bridge
    ///   is Linux-only.
    ///
    /// # Errors
    ///
    /// See above.
    pub fn connect() -> Result<Self> {
        if noop_enabled() {
            let recorder = MockRecorder::new();
            recorder.push(HvCall::Connect);
            return Ok(Self {
                mode: HvMode::Mock(recorder),
            });
        }
        #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
        {
            let conn = virt::connect::Connect::open(Some("qemu:///system")).map_err(|e| {
                Error::other(format!(
                    "libvirt qemu:///system connection failed: {e}. Is libvirtd running?"
                ))
            })?;
            return Ok(Self {
                mode: HvMode::Real(conn),
            });
        }
        #[cfg(not(all(target_os = "linux", feature = "experimental-bridge-libvirt")))]
        {
            #[cfg(target_os = "linux")]
            {
                Err(Error::other(
                    "libvirt linkage is not compiled into this binary. Rebuild with \
                     `--features experimental-bridge,experimental-bridge-libvirt` \
                     and ensure `libvirt0` (or your distro's equivalent) is installed.",
                ))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(Error::unsupported_platform(
                    "libvirt is Linux-only. The neon bridge runs on Linux hosts only.",
                ))
            }
        }
    }

    /// Construct a mock hypervisor for tests, regardless of the env
    /// var. Useful when a test doesn't want to mutate global env state.
    #[must_use]
    pub fn mock() -> Self {
        let recorder = MockRecorder::new();
        recorder.push(HvCall::Connect);
        Self {
            mode: HvMode::Mock(recorder),
        }
    }

    /// Return the mock recorder if this hypervisor is in mock mode.
    /// Returns `None` for real-libvirt mode.
    #[must_use]
    pub fn recorder(&self) -> Option<MockRecorder> {
        match &self.mode {
            HvMode::Mock(r) => Some(r.clone()),
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            HvMode::Real(_) => None,
        }
    }

    /// Define a domain (persistent VM) from XML.
    ///
    /// Returns a [`Domain`] handle that can be started, stopped,
    /// snapshotted, etc.
    ///
    /// # Errors
    ///
    /// * [`crate::ErrorCategory::Other`] — libvirt rejected the XML.
    pub fn define_domain(&self, xml: &str) -> Result<Domain> {
        let name = parse_name_from_xml(xml).unwrap_or_else(|| "<unknown>".to_string());
        match &self.mode {
            HvMode::Mock(r) => {
                r.push(HvCall::DefineDomain(name.clone()));
                Ok(Domain {
                    name,
                    handle: DomainHandle::Mock(r.clone()),
                })
            }
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            HvMode::Real(conn) => {
                let dom = virt::domain::Domain::define_xml(conn, xml)
                    .map_err(|e| Error::other(format!("libvirt define_xml({name}) failed: {e}")))?;
                Ok(Domain {
                    name,
                    handle: DomainHandle::Real(dom),
                })
            }
        }
    }

    /// Look up a previously-defined domain by name.
    ///
    /// # Errors
    ///
    /// * [`crate::ErrorCategory::Other`] — domain not found or libvirt
    ///   error.
    pub fn lookup_domain(&self, name: &str) -> Result<Domain> {
        match &self.mode {
            HvMode::Mock(r) => Ok(Domain {
                name: name.to_string(),
                handle: DomainHandle::Mock(r.clone()),
            }),
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            HvMode::Real(conn) => {
                let dom = virt::domain::Domain::lookup_by_name(conn, name).map_err(|e| {
                    Error::other(format!("libvirt lookup_by_name({name}) failed: {e}"))
                })?;
                Ok(Domain {
                    name: name.to_string(),
                    handle: DomainHandle::Real(dom),
                })
            }
        }
    }
}

/// Best-effort: extract `<name>X</name>` from an XML string. Used to
/// label mock recorder events.
fn parse_name_from_xml(xml: &str) -> Option<String> {
    let start = xml.find("<name>")?;
    let after = &xml[start + "<name>".len()..];
    let end = after.find("</name>")?;
    Some(after[..end].trim().to_string())
}

/// Domain handle returned from [`Hypervisor::define_domain`].
pub struct Domain {
    name: String,
    handle: DomainHandle,
}

enum DomainHandle {
    Mock(MockRecorder),
    #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
    Real(virt::domain::Domain),
}

impl Domain {
    /// Domain name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Start the VM.
    ///
    /// # Errors
    ///
    /// [`crate::ErrorCategory::Other`] — libvirt error.
    pub fn start(&self) -> Result<()> {
        match &self.handle {
            DomainHandle::Mock(r) => {
                r.push(HvCall::StartDomain(self.name.clone()));
                r.mark_running(&self.name);
                Ok(())
            }
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            DomainHandle::Real(dom) => dom
                .create()
                .map(|_id| ())
                .map_err(|e| Error::other(format!("libvirt create({}) failed: {e}", self.name))),
        }
    }

    /// Stop the VM (graceful shutdown).
    ///
    /// # Errors
    ///
    /// [`crate::ErrorCategory::Other`] — libvirt error.
    pub fn stop(&self) -> Result<()> {
        match &self.handle {
            DomainHandle::Mock(r) => {
                r.push(HvCall::StopDomain(self.name.clone()));
                r.mark_stopped(&self.name);
                Ok(())
            }
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            DomainHandle::Real(dom) => dom
                .shutdown()
                .map(|_| ())
                .map_err(|e| Error::other(format!("libvirt shutdown({}) failed: {e}", self.name))),
        }
    }

    /// Take a named snapshot.
    ///
    /// # Errors
    ///
    /// [`crate::ErrorCategory::Other`] — libvirt error.
    pub fn snapshot(&self, label: &str) -> Result<()> {
        match &self.handle {
            DomainHandle::Mock(r) => {
                r.push(HvCall::SnapshotDomain {
                    domain: self.name.clone(),
                    snapshot: label.to_string(),
                });
                r.record_snapshot(&self.name, label);
                Ok(())
            }
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            DomainHandle::Real(dom) => {
                let xml = format!(
                    "<domainsnapshot><name>{}</name></domainsnapshot>",
                    xml_escape(label)
                );
                virt::domain_snapshot::DomainSnapshot::create_xml(dom, &xml, 0)
                    .map(|_| ())
                    .map_err(|e| {
                        Error::other(format!(
                            "libvirt snapshot({}, {label}) failed: {e}",
                            self.name
                        ))
                    })
            }
        }
    }

    /// Restore from a named snapshot.
    ///
    /// # Errors
    ///
    /// [`crate::ErrorCategory::Other`] — libvirt error / snapshot not
    /// found.
    pub fn restore_from_snapshot(&self, label: &str) -> Result<()> {
        match &self.handle {
            DomainHandle::Mock(r) => {
                r.push(HvCall::RestoreSnapshot {
                    domain: self.name.clone(),
                    snapshot: label.to_string(),
                });
                Ok(())
            }
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            DomainHandle::Real(dom) => {
                let snap = virt::domain_snapshot::DomainSnapshot::lookup_by_name(dom, label, 0)
                    .map_err(|e| {
                        Error::other(format!(
                            "libvirt lookup snapshot({label}) for {} failed: {e}",
                            self.name
                        ))
                    })?;
                snap.revert(0).map_err(|e| {
                    Error::other(format!(
                        "libvirt revert snapshot({label}) for {} failed: {e}",
                        self.name
                    ))
                })
            }
        }
    }

    /// `true` if the VM is currently running.
    ///
    /// # Errors
    ///
    /// [`crate::ErrorCategory::Other`] — libvirt error.
    pub fn is_running(&self) -> Result<bool> {
        match &self.handle {
            DomainHandle::Mock(r) => {
                r.push(HvCall::QueryIsRunning(self.name.clone()));
                Ok(r.is_running(&self.name))
            }
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            DomainHandle::Real(dom) => dom
                .is_active()
                .map_err(|e| Error::other(format!("libvirt is_active({}) failed: {e}", self.name))),
        }
    }

    /// Undefine the domain (remove from libvirt's persistent state).
    ///
    /// # Errors
    ///
    /// [`crate::ErrorCategory::Other`] — libvirt error.
    pub fn undefine(&self) -> Result<()> {
        match &self.handle {
            DomainHandle::Mock(r) => {
                r.push(HvCall::UndefineDomain(self.name.clone()));
                Ok(())
            }
            #[cfg(all(target_os = "linux", feature = "experimental-bridge-libvirt"))]
            DomainHandle::Real(dom) => dom
                .undefine()
                .map_err(|e| Error::other(format!("libvirt undefine({}) failed: {e}", self.name))),
        }
    }

    /// Path to the serial console pty, when libvirt has assigned one.
    /// Tests under NOOP mode return `None`.
    #[must_use]
    pub fn serial_console_path(&self) -> Option<PathBuf> {
        // libvirt's console pty is dynamic; we'd need to query
        // <devices><serial> in the live XML and parse the assigned
        // path. For V3-Phase C we surface None and rely on the
        // VM's first-logon sentinel + Sunshine handshake instead.
        None
    }
}

/// Minimal XML escape for snapshot names. Only used when real
/// libvirt linkage is enabled; the mock path stores names verbatim.
#[cfg_attr(
    not(all(target_os = "linux", feature = "experimental-bridge-libvirt")),
    allow(dead_code)
)]
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_from_xml_finds_the_name() {
        let xml = "<domain><name>neon-bridge</name></domain>";
        assert_eq!(parse_name_from_xml(xml), Some("neon-bridge".to_string()));
    }

    #[test]
    fn parse_name_from_xml_handles_whitespace() {
        let xml = "<domain><name>  spaced  </name></domain>";
        assert_eq!(parse_name_from_xml(xml), Some("spaced".to_string()));
    }

    #[test]
    fn parse_name_from_xml_returns_none_when_absent() {
        assert_eq!(parse_name_from_xml("<domain/>"), None);
    }

    #[test]
    fn mock_records_full_provision_sequence() {
        let hv = Hypervisor::mock();
        let dom = hv
            .define_domain("<domain><name>neon-bridge</name></domain>")
            .expect("define");
        dom.start().expect("start");
        assert!(dom.is_running().expect("query"));
        dom.snapshot("fresh").expect("snap");
        dom.stop().expect("stop");
        assert!(!dom.is_running().expect("query2"));
        let r = hv.recorder().expect("mock");
        let calls = r.calls();
        assert!(matches!(calls[0], HvCall::Connect));
        assert!(matches!(calls[1], HvCall::DefineDomain(ref n) if n == "neon-bridge"));
        assert!(matches!(calls[2], HvCall::StartDomain(ref n) if n == "neon-bridge"));
        assert!(matches!(calls[3], HvCall::QueryIsRunning(ref n) if n == "neon-bridge"));
        assert!(matches!(
            calls[4],
            HvCall::SnapshotDomain { ref domain, ref snapshot }
                if domain == "neon-bridge" && snapshot == "fresh"
        ));
    }

    #[test]
    fn mock_records_snapshot_label_per_domain() {
        let hv = Hypervisor::mock();
        let dom = hv
            .define_domain("<domain><name>neon-bridge</name></domain>")
            .expect("define");
        dom.snapshot("fresh").expect("snap");
        dom.snapshot("post-edge").expect("snap2");
        let r = hv.recorder().expect("mock");
        let snaps = r.snapshots("neon-bridge");
        assert_eq!(snaps, vec!["fresh".to_string(), "post-edge".to_string()]);
    }

    #[test]
    fn mock_restore_from_snapshot_records_call() {
        let hv = Hypervisor::mock();
        let dom = hv
            .define_domain("<domain><name>n</name></domain>")
            .expect("define");
        dom.restore_from_snapshot("fresh").expect("restore");
        let r = hv.recorder().expect("mock");
        let calls = r.calls();
        assert!(calls.iter().any(|c| matches!(c, HvCall::RestoreSnapshot { domain, snapshot } if domain == "n" && snapshot == "fresh")));
    }

    #[test]
    fn mock_undefine_records_call() {
        let hv = Hypervisor::mock();
        let dom = hv
            .define_domain("<domain><name>n</name></domain>")
            .expect("define");
        dom.undefine().expect("undefine");
        let r = hv.recorder().expect("mock");
        let calls = r.calls();
        assert!(calls
            .iter()
            .any(|c| matches!(c, HvCall::UndefineDomain(n) if n == "n")));
    }

    #[test]
    fn mock_is_running_reflects_lifecycle() {
        let hv = Hypervisor::mock();
        let dom = hv
            .define_domain("<domain><name>n</name></domain>")
            .expect("define");
        assert!(!dom.is_running().expect("query before start"));
        dom.start().expect("start");
        assert!(dom.is_running().expect("query running"));
        dom.stop().expect("stop");
        assert!(!dom.is_running().expect("query after stop"));
    }

    #[test]
    fn mock_lookup_domain_returns_handle() {
        let hv = Hypervisor::mock();
        let dom = hv.lookup_domain("preexisting").expect("lookup");
        assert_eq!(dom.name(), "preexisting");
    }

    #[test]
    fn noop_enabled_reflects_env_var() {
        let _g = crate::test_support::env_lock();
        let saved = std::env::var_os(HV_NOOP_ENV);
        // SAFETY: env behind env_lock.
        unsafe { std::env::remove_var(HV_NOOP_ENV) };
        assert!(!noop_enabled());
        unsafe { std::env::set_var(HV_NOOP_ENV, "1") };
        assert!(noop_enabled());
        unsafe { std::env::remove_var(HV_NOOP_ENV) };
        if let Some(v) = saved {
            unsafe { std::env::set_var(HV_NOOP_ENV, v) };
        }
    }

    #[test]
    fn connect_under_noop_returns_mock() {
        let _g = crate::test_support::env_lock();
        let saved = std::env::var_os(HV_NOOP_ENV);
        // SAFETY: env behind env_lock.
        unsafe { std::env::set_var(HV_NOOP_ENV, "1") };
        let hv = Hypervisor::connect().expect("connect under noop");
        assert!(hv.recorder().is_some());
        unsafe { std::env::remove_var(HV_NOOP_ENV) };
        if let Some(v) = saved {
            unsafe { std::env::set_var(HV_NOOP_ENV, v) };
        }
    }

    #[test]
    fn xml_escape_handles_specials() {
        assert_eq!(xml_escape("<>&\"'"), "&lt;&gt;&amp;&quot;&apos;");
    }

    #[test]
    fn serial_console_path_is_none_under_mock() {
        let hv = Hypervisor::mock();
        let dom = hv
            .define_domain("<domain><name>n</name></domain>")
            .expect("define");
        assert!(dom.serial_console_path().is_none());
    }
}
