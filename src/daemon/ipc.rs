//! Unix socket IPC server for CLI ↔ daemon communication.
//!
//! ## Wire format
//!
//! Length-prefixed JSON. Each message is `{u32-be-length}{json-body}`. 32-bit
//! big-endian length prefix means each message is bounded by ~4 GiB; in
//! practice messages are tiny (a few hundred bytes at most), but the cap
//! prevents a runaway client from exhausting memory.
//!
//! ## Socket location and permissions
//!
//! Socket lives at `<cache_dir>/neon/daemon.sock`. After binding we
//! `chmod 0600` so only the owning user can connect — the daemon never
//! talks to other users, and anyone with write access to the socket can
//! invoke privileged-elevation flows on the daemon's behalf.
//!
//! On startup we remove any pre-existing socket file at the same path
//! (left over from a previous daemon run that crashed without cleanup).
//! If a *live* daemon owns the socket we'd want to refuse to start, but
//! `bind()` will succeed against a stale path — the only mitigation for a
//! genuinely-live double-start is the `lifecycle::is_registered()` /
//! systemd-user `Restart=on-failure` semantics, both of which prevent
//! parallel daemons in practice.
//!
//! ## Public API
//!
//! ```ignore
//! pub struct IpcServer { /* ... */ }
//! pub enum IpcRequest { Status, Patch { browser, force }, TriggerCheck, GetState }
//! pub enum IpcResponse { Ok(IpcResult), Err { category, message } }
//! pub enum IpcResult { /* per-method results */ }
//! pub fn start(handler) -> Result<IpcServer>;
//! pub fn default_socket_path() -> Option<PathBuf>;
//! ```
//!
//! The handler takes an [`IpcRequest`] and returns an [`IpcResponse`]; the
//! server runs its accept loop on a background thread, calling the
//! handler from that thread for each connection.
//!
//! ## Test mode
//!
//! `start_at(socket_path, handler)` lets tests bind to a `tempfile::TempDir`
//! path — production callers use [`start`] which resolves to the
//! conventional location.
//!
//! [`IpcServer::shutdown`] joins the accept thread and removes the socket
//! file. `Drop` calls `shutdown` if the user didn't.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorCategory, Result};

/// Maximum size of a single IPC message body (bytes). Bigger requests are
/// rejected — the on-wire schema doesn't carry anything larger than a few
/// hundred bytes in V1.
pub const MAX_MESSAGE_SIZE: usize = 1 << 20; // 1 MiB

/// Default socket path: `<cache_dir>/neon/daemon.sock`.
///
/// Returns `None` when `dirs::cache_dir()` is unresolvable (e.g. no
/// `$HOME` / `$XDG_CACHE_HOME`); callers in that case should treat IPC as
/// unavailable.
#[must_use]
pub fn default_socket_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("neon").join("daemon.sock"))
}

/// Request methods sent by CLI clients.
///
/// `serde` tags the variant via an internal `"method"` key so the wire
/// format reads naturally:
///
/// ```json
/// {"method":"status"}
/// {"method":"patch","browser":"Helium","force":false}
/// {"method":"trigger_check"}
/// {"method":"get_state"}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Report current daemon state (browsers, last patch, heartbeat freshness).
    Status,
    /// Patch a specific browser (or all if `browser` is `None`).
    Patch {
        /// Browser to patch by display name; `None` patches all detected browsers.
        #[serde(default)]
        browser: Option<String>,
        /// If true, patch even when our internal state thinks the browser
        /// is already at the latest CDM. Maps to `--force` on the CLI side.
        #[serde(default)]
        force: bool,
    },
    /// Force the file watcher / scheduled checks to re-run their detection
    /// cycle (skipping debounce). Use to recover after manual changes.
    TriggerCheck,
    /// Return the daemon's serialized state file (browsers, patch history).
    GetState,
}

/// Response variants. `Ok(...)` carries a method-specific result; `Err`
/// carries a categorized failure that the CLI can route back to the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ok")]
pub enum IpcResponse {
    /// Successful completion. `result` is method-specific.
    #[serde(rename = "true")]
    Ok {
        /// Method-specific success payload.
        result: IpcResult,
    },
    /// Failure, with a routing category and human-readable message.
    #[serde(rename = "false")]
    Err {
        /// Error category as a stable string (matches [`ErrorCategory::as_str`]).
        category: String,
        /// Human-readable message for the user / logs.
        message: String,
    },
}

impl IpcResponse {
    /// Construct a successful response from an [`IpcResult`].
    #[must_use]
    pub fn ok(result: IpcResult) -> Self {
        Self::Ok { result }
    }

    /// Construct a failure response from a categorized [`Error`].
    #[must_use]
    pub fn err(error: &Error) -> Self {
        Self::Err {
            category: error.category.as_str().to_string(),
            message: error.message.clone(),
        }
    }

    /// `true` if this response is the `Ok(...)` variant.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok { .. })
    }
}

/// Method-specific success payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcResult {
    /// Output of [`IpcRequest::Status`].
    Status {
        /// Number of browsers detected.
        browser_count: usize,
        /// Timestamp (seconds since epoch) of the last successful patch run,
        /// or `None` if no record.
        last_patch_at: Option<u64>,
        /// Daemon heartbeat (seconds since epoch).
        heartbeat_at: Option<u64>,
    },
    /// Output of [`IpcRequest::Patch`].
    Patch {
        /// Per-browser results: `(name, succeeded)`.
        results: Vec<(String, bool)>,
    },
    /// Output of [`IpcRequest::TriggerCheck`].
    TriggerCheck {
        /// Number of browsers re-checked.
        rechecked: usize,
    },
    /// Output of [`IpcRequest::GetState`].
    GetState {
        /// JSON-encoded state snapshot. Opaque to the IPC layer; the CLI
        /// parses it with the state-file schema (Phase 4).
        state_json: String,
    },
    /// Generic acknowledgment used for fire-and-forget methods. Currently
    /// unused but exposed as a future-friendly catch-all so we don't have
    /// to extend `IpcResult` for trivial new methods.
    Ack,
}

/// Handle to a running IPC server. Drop calls [`shutdown`].
pub struct IpcServer {
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
}

impl IpcServer {
    /// Path the server is bound to.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Stop the accept loop and remove the socket file.
    ///
    /// Calling `shutdown` more than once is a no-op. `Drop` runs this
    /// automatically.
    pub fn shutdown(&mut self) {
        if !self.stop.swap(true, Ordering::SeqCst) {
            // Wake the accept thread by trying to connect — that pumps the
            // listener so it observes the stop flag on its next iteration.
            // Best-effort; if the connect fails we'll still rely on the
            // `accept` timeout below.
            let _ = UnixStream::connect(&self.socket_path);
        }
        if let Some(handle) = self.accept_thread.take() {
            // Joining an already-finished thread is fine. If the accept
            // thread panicked we propagate by ignoring (best-effort cleanup;
            // the daemon's main loop should also be shutting down).
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Start an IPC server on the default socket path with the supplied
/// handler.
///
/// `handler` is called for each incoming connection. The closure runs on
/// the accept loop's thread, so handlers that do non-trivial work should
/// return quickly or dispatch to a worker pool internally.
///
/// Returns an [`IpcServer`] handle the caller must keep alive for the
/// duration of the server's run.
///
/// # Errors
///
/// * [`crate::ErrorCategory::Other`] if the cache directory can't be
///   resolved or the socket can't be bound.
pub fn start<F>(handler: F) -> Result<IpcServer>
where
    F: Fn(IpcRequest) -> IpcResponse + Send + Sync + 'static,
{
    let path = default_socket_path()
        .ok_or_else(|| Error::other("cannot resolve default IPC socket path"))?;
    start_at(&path, handler)
}

/// Test- and injection-friendly variant of [`start`]: caller passes the
/// socket path explicitly.
///
/// # Errors
///
/// See [`start`].
pub fn start_at<F>(socket_path: &Path, handler: F) -> Result<IpcServer>
where
    F: Fn(IpcRequest) -> IpcResponse + Send + Sync + 'static,
{
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::other(format!("cannot create IPC socket parent: {e}")).with_source(e)
        })?;
    }
    // Best-effort: clear a stale socket file from a previous run.
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path).map_err(|e| {
        Error::other(format!(
            "cannot bind IPC socket at {}: {e}",
            socket_path.display()
        ))
        .with_source(e)
    })?;
    set_socket_permissions(socket_path).map_err(|e| {
        Error::other(format!(
            "cannot chmod IPC socket at {}: {e}",
            socket_path.display()
        ))
        .with_source(e)
    })?;

    // Non-blocking accept so the loop can observe the stop flag without
    // requiring a dedicated wakeup connection. We use a 200ms poll
    // interval — fast enough to shutdown promptly, slow enough to cost
    // ~0.0% CPU at idle.
    listener.set_nonblocking(true).map_err(|e| {
        Error::other(format!("cannot set IPC listener non-blocking: {e}")).with_source(e)
    })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let handler = Arc::new(handler);

    let accept_thread = std::thread::Builder::new()
        .name("neon-ipc".to_string())
        .spawn(move || run_accept_loop(&listener, &stop_for_thread, handler))
        .map_err(|e| Error::other(format!("cannot spawn IPC accept thread: {e}")))?;

    Ok(IpcServer {
        socket_path: socket_path.to_path_buf(),
        stop,
        accept_thread: Some(accept_thread),
    })
}

/// Set the socket's filesystem mode to 0600 (owner read+write only).
fn set_socket_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

/// Accept loop: poll the listener, handle each connection by dispatching
/// to the handler.
#[allow(clippy::needless_pass_by_value)] // `handler` is consumed across loop iterations via Arc::clone
fn run_accept_loop<F>(listener: &UnixListener, stop: &Arc<AtomicBool>, handler: Arc<F>)
where
    F: Fn(IpcRequest) -> IpcResponse + Send + Sync + 'static,
{
    loop {
        if stop.load(Ordering::SeqCst) {
            tracing::debug!(target: "neon::ipc", "accept loop received stop signal");
            return;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                let h = Arc::clone(&handler);
                if let Err(e) = handle_one(stream, h.as_ref()) {
                    tracing::warn!(
                        target: "neon::ipc",
                        error = %e,
                        "IPC connection error"
                    );
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                tracing::warn!(target: "neon::ipc", error = %e, "accept failed");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// Read one request from `stream`, call the handler, write back the response.
fn handle_one<F>(mut stream: UnixStream, handler: &F) -> Result<()>
where
    F: Fn(IpcRequest) -> IpcResponse + Send + Sync + 'static,
{
    // BSD/macOS accepted sockets inherit O_NONBLOCK from the listener, while
    // Linux accepted sockets generally do not. The protocol handler uses
    // blocking `read_exact`/`write_all`, so establish the same semantics on
    // every supported platform before applying bounded I/O timeouts.
    stream
        .set_nonblocking(false)
        .map_err(|e| Error::other(format!("set accepted stream blocking: {e}")).with_source(e))?;

    // Each connection processes a single request → response round trip.
    // (Ergonomic for the CLI; the daemon doesn't need long-lived sessions.)
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Error::other(format!("set read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Error::other(format!("set write timeout: {e}")))?;

    let request = read_request(&mut stream)?;
    let response = handler(request);
    write_response(&mut stream, &response)?;
    Ok(())
}

/// Read a length-prefixed JSON request from `stream`. The 4-byte big-endian
/// length is followed by the JSON body of that length.
fn read_request(stream: &mut UnixStream) -> Result<IpcRequest> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| Error::other(format!("read request length: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(Error::other(format!(
            "IPC request too large: {len} bytes > {MAX_MESSAGE_SIZE}"
        )));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| Error::other(format!("read request body: {e}")))?;
    let req: IpcRequest = serde_json::from_slice(&body).map_err(|e| {
        Error::new(
            ErrorCategory::StateCorrupted,
            format!("invalid IPC request JSON: {e}"),
        )
    })?;
    Ok(req)
}

/// Write a length-prefixed JSON response to `stream`.
fn write_response(stream: &mut UnixStream, response: &IpcResponse) -> Result<()> {
    let body = serde_json::to_vec(response)
        .map_err(|e| Error::other(format!("serialize IPC response: {e}")).with_source(e))?;
    let len: u32 = body.len().try_into().map_err(|_| {
        Error::other(format!(
            "IPC response too large to encode length: {} bytes",
            body.len()
        ))
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| Error::other(format!("write response length: {e}")))?;
    stream
        .write_all(&body)
        .map_err(|e| Error::other(format!("write response body: {e}")))?;
    stream
        .flush()
        .map_err(|e| Error::other(format!("flush response: {e}")))?;
    Ok(())
}

/// Connect to a running IPC server, send `request`, read back the response.
///
/// This is the symmetric client to [`start_at`] and is exposed primarily
/// for tests + smoke checks. The CLI team's IPC client (Phase 4) will
/// build on this helper.
///
/// # Errors
///
/// * [`crate::ErrorCategory::DaemonNotRunning`] if the connect fails (no
///   daemon listening on the socket).
/// * [`crate::ErrorCategory::Other`] for any other I/O failure.
pub fn send_request(socket_path: &Path, request: &IpcRequest) -> Result<IpcResponse> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        Error::daemon_not_running(format!(
            "cannot connect to IPC socket {}: {e}",
            socket_path.display()
        ))
        .with_source(e)
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Error::other(format!("set read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| Error::other(format!("set write timeout: {e}")))?;

    let body = serde_json::to_vec(request)
        .map_err(|e| Error::other(format!("serialize IPC request: {e}")).with_source(e))?;
    let len: u32 = body.len().try_into().map_err(|_| {
        Error::other(format!(
            "IPC request too large to encode length: {} bytes",
            body.len()
        ))
    })?;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| Error::other(format!("write request length: {e}")))?;
    stream
        .write_all(&body)
        .map_err(|e| Error::other(format!("write request body: {e}")))?;
    stream
        .flush()
        .map_err(|e| Error::other(format!("flush request: {e}")))?;

    // Read length + body.
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| Error::other(format!("read response length: {e}")))?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_MESSAGE_SIZE {
        return Err(Error::other(format!(
            "IPC response too large: {resp_len} bytes > {MAX_MESSAGE_SIZE}"
        )));
    }
    let mut resp_body = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_body)
        .map_err(|e| Error::other(format!("read response body: {e}")))?;
    let response: IpcResponse = serde_json::from_slice(&resp_body).map_err(|e| {
        Error::new(
            ErrorCategory::StateCorrupted,
            format!("invalid IPC response JSON: {e}"),
        )
    })?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;
    use tempfile::TempDir;

    /// Build a unique socket path inside `tmp` to avoid collisions when
    /// tests run in parallel.
    fn socket_in(tmp: &TempDir, name: &str) -> PathBuf {
        tmp.path().join(format!("{name}.sock"))
    }

    /// Wait up to 1s for `path` to exist as a Unix socket.
    fn wait_for_socket(path: &Path) {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(1) {
            if path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Round-trip a `Status` request → `Status` response.
    #[test]
    fn round_trip_status_request() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "status");
        let server = start_at(&path, |req| match req {
            IpcRequest::Status => IpcResponse::ok(IpcResult::Status {
                browser_count: 3,
                last_patch_at: Some(1_700_000_000),
                heartbeat_at: Some(1_700_000_060),
            }),
            _ => IpcResponse::err(&Error::other("unexpected method")),
        })
        .expect("start ok");
        wait_for_socket(&path);

        let resp = send_request(&path, &IpcRequest::Status).expect("send ok");
        match resp {
            IpcResponse::Ok {
                result:
                    IpcResult::Status {
                        browser_count,
                        last_patch_at,
                        heartbeat_at,
                    },
            } => {
                assert_eq!(browser_count, 3);
                assert_eq!(last_patch_at, Some(1_700_000_000));
                assert_eq!(heartbeat_at, Some(1_700_000_060));
            }
            other => panic!("unexpected response: {other:?}"),
        }
        drop(server);
    }

    /// Round-trip a `Patch` request, including parameters.
    #[test]
    fn round_trip_patch_request_with_params() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "patch");
        let saw_browser: Arc<std::sync::Mutex<Option<String>>> =
            Arc::new(std::sync::Mutex::default());
        let saw_force = Arc::new(AtomicBool::new(false));

        let saw_b = Arc::clone(&saw_browser);
        let saw_f = Arc::clone(&saw_force);
        let server = start_at(&path, move |req| {
            if let IpcRequest::Patch { browser, force } = req {
                *saw_b.lock().unwrap() = browser;
                saw_f.store(force, Ordering::SeqCst);
                IpcResponse::ok(IpcResult::Patch {
                    results: vec![("Helium".into(), true)],
                })
            } else {
                IpcResponse::err(&Error::other("unexpected method"))
            }
        })
        .expect("start ok");
        wait_for_socket(&path);

        let resp = send_request(
            &path,
            &IpcRequest::Patch {
                browser: Some("Helium".into()),
                force: true,
            },
        )
        .expect("send ok");
        assert!(resp.is_ok());
        assert_eq!(saw_browser.lock().unwrap().as_deref(), Some("Helium"));
        assert!(saw_force.load(Ordering::SeqCst));
        drop(server);
    }

    /// Round-trip a `TriggerCheck` request.
    #[test]
    fn round_trip_trigger_check() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "trigger");
        let server = start_at(&path, |req| match req {
            IpcRequest::TriggerCheck => IpcResponse::ok(IpcResult::TriggerCheck { rechecked: 5 }),
            _ => IpcResponse::err(&Error::other("unexpected")),
        })
        .expect("start");
        wait_for_socket(&path);

        let resp = send_request(&path, &IpcRequest::TriggerCheck).unwrap();
        match resp {
            IpcResponse::Ok {
                result: IpcResult::TriggerCheck { rechecked },
            } => assert_eq!(rechecked, 5),
            other => panic!("{other:?}"),
        }
        drop(server);
    }

    /// `GetState` round-trips an opaque JSON blob.
    #[test]
    fn round_trip_get_state() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "state");
        let server = start_at(&path, |req| match req {
            IpcRequest::GetState => IpcResponse::ok(IpcResult::GetState {
                state_json: r#"{"version":1,"browsers":{}}"#.into(),
            }),
            _ => IpcResponse::err(&Error::other("unexpected")),
        })
        .expect("start");
        wait_for_socket(&path);

        let resp = send_request(&path, &IpcRequest::GetState).unwrap();
        match resp {
            IpcResponse::Ok {
                result: IpcResult::GetState { state_json },
            } => assert!(state_json.contains("version")),
            other => panic!("{other:?}"),
        }
        drop(server);
    }

    /// A nonblocking accepted connection may sit idle briefly before sending
    /// its request. This models the macOS/BSD behavior where accepted sockets
    /// inherit the listener's nonblocking flag.
    #[test]
    fn accepted_stream_waits_for_delayed_request() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        server.set_nonblocking(true).expect("set nonblocking");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");

        let server_thread =
            std::thread::spawn(move || handle_one(server, &|_| IpcResponse::ok(IpcResult::Ack)));
        // Ensure `handle_one` attempts its read before the request arrives. It
        // must restore blocking mode rather than fail immediately with
        // WouldBlock.
        std::thread::sleep(Duration::from_millis(50));

        let body = serde_json::to_vec(&IpcRequest::Status).expect("serialize request");
        let len = u32::try_from(body.len()).expect("request length fits");
        client.write_all(&len.to_be_bytes()).expect("write length");
        client.write_all(&body).expect("write body");

        let mut len_buf = [0u8; 4];
        client
            .read_exact(&mut len_buf)
            .expect("read response length");
        let response_len = u32::from_be_bytes(len_buf) as usize;
        let mut response_body = vec![0u8; response_len];
        client
            .read_exact(&mut response_body)
            .expect("read response body");
        let response: IpcResponse =
            serde_json::from_slice(&response_body).expect("decode response");
        assert!(matches!(
            response,
            IpcResponse::Ok {
                result: IpcResult::Ack
            }
        ));
        server_thread
            .join()
            .expect("server thread")
            .expect("handle request");
    }

    /// Handler that returns an error → wire-format `Err` response.
    #[test]
    fn handler_error_routes_to_err_response() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "err");
        let server = start_at(&path, |_| {
            IpcResponse::err(&Error::permission_denied("denied"))
        })
        .expect("start");
        wait_for_socket(&path);

        let resp = send_request(&path, &IpcRequest::Status).unwrap();
        match resp {
            IpcResponse::Err { category, message } => {
                assert_eq!(category, "PermissionDenied");
                assert!(message.contains("denied"));
            }
            IpcResponse::Ok { result } => panic!("expected Err, got Ok({result:?})"),
        }
        drop(server);
    }

    /// Connecting to a non-existent socket returns `DaemonNotRunning`.
    #[test]
    fn send_request_to_missing_socket_errors_daemon_not_running() {
        let tmp = TempDir::new().unwrap();
        let bogus = tmp.path().join("never-bound.sock");
        let err = send_request(&bogus, &IpcRequest::Status).expect_err("must error");
        assert_eq!(err.category, ErrorCategory::DaemonNotRunning);
    }

    /// Server creates the parent directory if absent.
    #[test]
    fn start_creates_parent_dir() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a/b/c/daemon.sock");
        let server = start_at(&nested, |_| {
            IpcResponse::ok(IpcResult::TriggerCheck { rechecked: 0 })
        })
        .expect("start");
        wait_for_socket(&nested);
        assert!(nested.exists());
        drop(server);
    }

    /// Socket file is removed on shutdown.
    #[test]
    fn shutdown_removes_socket_file() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "cleanup");
        let mut server = start_at(&path, |_| {
            IpcResponse::ok(IpcResult::TriggerCheck { rechecked: 0 })
        })
        .expect("start");
        wait_for_socket(&path);
        assert!(path.exists());
        server.shutdown();
        // After shutdown the file should be gone.
        assert!(
            !path.exists(),
            "socket file should be removed after shutdown"
        );
    }

    /// Calling `shutdown` twice is a no-op.
    #[test]
    fn shutdown_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "double");
        let mut server = start_at(&path, |_| {
            IpcResponse::ok(IpcResult::TriggerCheck { rechecked: 0 })
        })
        .expect("start");
        server.shutdown();
        server.shutdown();
    }

    /// Drop runs shutdown automatically.
    #[test]
    fn drop_calls_shutdown() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "drop");
        {
            let _server = start_at(&path, |_| {
                IpcResponse::ok(IpcResult::TriggerCheck { rechecked: 0 })
            })
            .expect("start");
            wait_for_socket(&path);
            assert!(path.exists());
        }
        // After Drop the socket file should be removed.
        assert!(!path.exists());
    }

    /// `default_socket_path` ends in `daemon.sock` under `neon/`.
    #[test]
    fn default_socket_path_ends_with_neon_daemon_sock() {
        if let Some(p) = default_socket_path() {
            let suffix = std::path::Path::new("neon").join("daemon.sock");
            assert!(p.ends_with(&suffix), "{}", p.display());
        }
    }

    /// Socket has 0600 permissions after binding.
    #[test]
    #[cfg(unix)]
    fn socket_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "perms");
        let server = start_at(&path, |_| {
            IpcResponse::ok(IpcResult::TriggerCheck { rechecked: 0 })
        })
        .expect("start");
        wait_for_socket(&path);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
        drop(server);
    }

    /// Stale socket file at the target path is removed on start.
    #[test]
    fn start_removes_stale_socket_file() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "stale");
        // Create a junk regular file at the path that bind() would
        // otherwise refuse to overwrite.
        std::fs::write(&path, b"garbage").unwrap();
        let server = start_at(&path, |_| {
            IpcResponse::ok(IpcResult::TriggerCheck { rechecked: 0 })
        })
        .expect("start despite stale file");
        wait_for_socket(&path);
        // The path now refers to a Unix socket, not a regular file.
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let ftype = metadata.file_type();
        // On Linux this is detectable via `is_socket()`; on macOS it's
        // also a "special" file. Either way it's not a regular file.
        assert!(
            !ftype.is_file(),
            "expected socket-type file at {}",
            path.display()
        );
        drop(server);
    }

    /// `IpcResponse::is_ok` reflects the Ok variant.
    #[test]
    fn ipc_response_is_ok_predicate() {
        let ok = IpcResponse::ok(IpcResult::Ack);
        assert!(ok.is_ok());
        let err = IpcResponse::err(&Error::other("nope"));
        assert!(!err.is_ok());
    }

    /// `IpcResponse::err` carries the error's category as a stable string.
    #[test]
    fn ipc_response_err_carries_category_string() {
        let resp = IpcResponse::err(&Error::network("boom"));
        match resp {
            IpcResponse::Err { category, message } => {
                assert_eq!(category, "NetworkError");
                assert_eq!(message, "boom");
            }
            IpcResponse::Ok { result } => panic!("expected Err, got Ok({result:?})"),
        }
    }

    /// Multiple sequential round-trips succeed (the server handles each
    /// connection one at a time, but successive connections work).
    #[test]
    fn multiple_sequential_requests_succeed() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "multi");
        let count = Arc::new(AtomicUsize::new(0));
        let count_for = Arc::clone(&count);
        let server = start_at(&path, move |_req| {
            let n = count_for.fetch_add(1, Ordering::SeqCst);
            IpcResponse::ok(IpcResult::TriggerCheck { rechecked: n })
        })
        .expect("start");
        wait_for_socket(&path);

        for _ in 0..5 {
            let _ = send_request(&path, &IpcRequest::TriggerCheck).expect("send ok");
        }
        assert_eq!(count.load(Ordering::SeqCst), 5);
        drop(server);
    }

    /// Wire format of `Status` request is the documented JSON.
    #[test]
    fn status_request_serializes_to_documented_form() {
        let req = IpcRequest::Status;
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, r#"{"method":"status"}"#);
    }

    /// Wire format of `Patch` request is the documented JSON.
    #[test]
    fn patch_request_serializes_to_documented_form() {
        let req = IpcRequest::Patch {
            browser: Some("Helium".into()),
            force: true,
        };
        let s = serde_json::to_string(&req).unwrap();
        // The fields ordering is arbitrary in serde-json, but it must
        // round-trip and contain the right keys.
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["method"], "patch");
        assert_eq!(v["browser"], "Helium");
        assert_eq!(v["force"], true);
    }

    /// `MAX_MESSAGE_SIZE` is enforced — the server rejects oversized
    /// length prefixes without reading the body.
    #[test]
    fn oversize_request_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = socket_in(&tmp, "oversize");
        let server = start_at(&path, |_| {
            IpcResponse::ok(IpcResult::TriggerCheck { rechecked: 0 })
        })
        .expect("start");
        wait_for_socket(&path);

        // Send a bogus length prefix that exceeds the cap.
        let mut stream = UnixStream::connect(&path).expect("connect");
        let oversize: u32 = u32::try_from(MAX_MESSAGE_SIZE + 1)
            .expect("oversize fits in u32 (MAX_MESSAGE_SIZE = 1 MiB)");
        stream.write_all(&oversize.to_be_bytes()).expect("write");
        // The server should close the connection without writing a
        // response. We try a read with a short timeout — eof is the
        // expected outcome.
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();
        let mut buf = [0u8; 4];
        let res = stream.read_exact(&mut buf);
        assert!(res.is_err(), "server must close on oversize request");
        drop(server);
    }
}
