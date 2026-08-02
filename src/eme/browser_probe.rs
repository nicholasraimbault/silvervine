//! Secure loopback transport and browser launcher for live EME evidence.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::browsers::{runtime::executable_path, Browser};
use crate::eme::probe::{assess, CapabilityAssessment, RawProbeResult};
use crate::error::{Error, Result};
use crate::widevine::ownership::OwnershipAssessment;

const MAX_REQUEST_LINE_BYTES: usize = 2 * 1024;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_REQUESTS: usize = 64;
const PROBE_SCRIPT: &str = include_str!("probe.js");

/// Single-use loopback HTTP server for browser-reported EME evidence.
pub struct ProbeServer {
    listener: TcpListener,
    address: SocketAddr,
    token: String,
    nonce: String,
    timeout: Duration,
    ownership: OwnershipAssessment,
    accepted_post: bool,
}

/// Raw browser facts plus the identical Rust assessment returned to page and CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// Validated browser-posted document.
    pub raw: RawProbeResult,
    /// Conservative assessment computed in-process.
    pub assessment: CapabilityAssessment,
}

impl ProbeServer {
    /// Bind an ephemeral IPv4 loopback port with separate route and CSP nonce bytes.
    ///
    /// # Errors
    ///
    /// Returns a categorized I/O or entropy-source error.
    pub fn bind(timeout: Duration, ownership: OwnershipAssessment) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(Error::from)?;
        listener.set_nonblocking(true).map_err(Error::from)?;
        let address = listener.local_addr().map_err(Error::from)?;
        let token = hex_bytes(&read_urandom(32)?)?;
        let nonce = hex_bytes(&read_urandom(16)?)?;
        Ok(Self {
            listener,
            address,
            token,
            nonce,
            timeout,
            ownership,
            accepted_post: false,
        })
    }

    /// Browser URL for the single-use probe page.
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/{}/", self.address, self.token)
    }

    /// Bound IPv4 loopback address.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Random token embedded in the probe URL.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// CSP nonce embedded in the page and policy.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Serve the embedded page and wait for one valid same-origin result.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCategory::BrowserProbeFailed`] on timeout, request-flood
    /// exhaustion, malformed probe JSON, or schema validation failure.
    pub fn wait_for_result(mut self) -> Result<ProbeOutcome> {
        let started = Instant::now();
        let mut requests = 0_usize;
        loop {
            let elapsed = started.elapsed();
            if elapsed >= self.timeout {
                return Err(Error::browser_probe_failed(
                    "browser capability probe timed out without a result",
                ));
            }
            match self.listener.accept() {
                Ok((mut stream, peer)) => {
                    requests += 1;
                    if requests > MAX_REQUESTS {
                        return Err(Error::browser_probe_failed(
                            "browser capability probe rejected too many requests",
                        ));
                    }
                    stream.set_nonblocking(false).map_err(Error::from)?;
                    let remaining = self.timeout.saturating_sub(started.elapsed());
                    stream
                        .set_read_timeout(Some(remaining.min(Duration::from_secs(2))))
                        .map_err(Error::from)?;
                    stream
                        .set_write_timeout(Some(remaining.min(Duration::from_secs(2))))
                        .map_err(Error::from)?;
                    if !peer.ip().is_loopback() {
                        respond(&mut stream, 403, "text/plain", b"forbidden", None)?;
                        continue;
                    }
                    if let Some(outcome) = self.handle(&mut stream)? {
                        return Ok(outcome);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(
                        Duration::from_millis(5)
                            .min(self.timeout.saturating_sub(started.elapsed())),
                    );
                }
                Err(error) => return Err(Error::from(error)),
            }
        }
    }

    /// Compatibility wrapper around [`Self::wait_for_result`].
    ///
    /// # Errors
    ///
    /// Propagates probe transport and validation errors.
    pub fn wait(self) -> Result<ProbeOutcome> {
        self.wait_for_result()
    }

    fn handle(&mut self, stream: &mut TcpStream) -> Result<Option<ProbeOutcome>> {
        let request = match read_request(stream) {
            Ok(request) => request,
            Err(error) => {
                respond_request_error(stream, &error)?;
                return Ok(None);
            }
        };
        let expected_host = self.address.to_string();
        if request.headers.get("host").map(String::as_str) != Some(&expected_host) {
            respond(stream, 403, "text/plain", b"forbidden", None)?;
            return Ok(None);
        }

        let root_path = format!("/{}/", self.token);
        let root_path_trim = format!("/{}", self.token);
        let result_path = format!("/{}/result", self.token);
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", path) if path == root_path || path == root_path_trim => {
                let page = render_page(&self.nonce);
                respond(
                    stream,
                    200,
                    "text/html; charset=utf-8",
                    page.as_bytes(),
                    Some(self.csp()),
                )?;
                Ok(None)
            }
            ("POST", path) if path == result_path => self.handle_result_post(stream, &request),
            ("GET" | "POST", _) => {
                respond(stream, 404, "text/plain", b"not found", None)?;
                Ok(None)
            }
            (_, path) if path == root_path || path == root_path_trim || path == result_path => {
                respond(stream, 405, "text/plain", b"method not allowed", None)?;
                Ok(None)
            }
            _ => {
                respond(stream, 404, "text/plain", b"not found", None)?;
                Ok(None)
            }
        }
    }

    fn handle_result_post(
        &mut self,
        stream: &mut TcpStream,
        request: &HttpRequest,
    ) -> Result<Option<ProbeOutcome>> {
        if self.accepted_post {
            respond(stream, 409, "text/plain", b"result already accepted", None)?;
            return Ok(None);
        }
        let expected_origin = format!("http://{}", self.address);
        if request.headers.get("origin").map(String::as_str) != Some(expected_origin.as_str()) {
            respond(stream, 403, "text/plain", b"forbidden", None)?;
            return Ok(None);
        }
        let content_type = request
            .headers
            .get("content-type")
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/json") {
            respond(
                stream,
                415,
                "text/plain",
                b"application/json required",
                None,
            )?;
            return Ok(None);
        }
        let raw: RawProbeResult = serde_json::from_slice(&request.body).map_err(|error| {
            Error::browser_probe_failed("browser returned malformed EME probe JSON")
                .with_source(error)
        })?;
        raw.validate_live_matrix().map_err(|error| {
            Error::browser_probe_failed(error.message.clone()).with_source(error)
        })?;
        let assessment = assess(&raw, &self.ownership);
        let body = serde_json::to_vec(&assessment).map_err(|error| {
            Error::browser_probe_failed("could not encode capability assessment").with_source(error)
        })?;
        respond_strict(stream, 200, "application/json; charset=utf-8", &body, None)?;
        self.accepted_post = true;
        Ok(Some(ProbeOutcome { raw, assessment }))
    }

    fn csp(&self) -> String {
        format!(
            "default-src 'none'; script-src 'nonce-{}'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            self.nonce
        )
    }
}

/// Launch the selected browser with its normal profile and collect one live
/// EME result plus assessment. No remote-debugging interface is enabled.
///
/// # Errors
///
/// Returns browser path/spawn errors or errors from [`ProbeServer::wait_for_result`].
pub fn run_browser_probe(
    browser: &Browser,
    timeout: Duration,
    ownership: &OwnershipAssessment,
) -> Result<ProbeOutcome> {
    let executable = executable_path(browser)?;
    run_browser_probe_with_executable(browser, &executable, timeout, ownership)
}

/// Launch using an already-resolved executable path.
///
/// # Errors
///
/// Returns spawn or probe transport errors.
pub fn run_browser_probe_with_executable(
    browser: &Browser,
    executable: &Path,
    timeout: Duration,
    ownership: &OwnershipAssessment,
) -> Result<ProbeOutcome> {
    let server = ProbeServer::bind(timeout, ownership.clone())?;
    let url = server.url();
    let mut command = Command::new(executable);
    command
        .arg(&url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().map_err(|error| {
        Error::browser_probe_failed(format!(
            "could not launch {} for the capability probe",
            browser.name()
        ))
        .with_source(error)
    })?;
    thread::spawn(move || {
        let _ = child.wait();
    });
    server.wait_for_result()
}

fn render_page(nonce: &str) -> String {
    format!(
        concat!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
            "<title>Silvervine capability check</title>",
            "<style>",
            ":root{{color-scheme:light dark;--ink:#14201b;--paper:#f4f1e8;--panel:#e7efe8;",
            "--line:#2f4a3c;--accent:#0b6e4f;--fail:#8b1e1e;--mute:#4d5c55;",
            "font-family:\"IBM Plex Sans\",\"Segoe UI\",sans-serif}}",
            "@media (prefers-color-scheme:dark){{:root{{--ink:#e7efe8;--paper:#101612;--panel:#18211c;",
            "--line:#7aa892;--accent:#5dcea2;--fail:#ff8e8e;--mute:#9bb0a5}}}}",
            "body{{margin:0;min-height:100vh;background:linear-gradient(180deg,var(--panel),var(--paper));color:var(--ink)}}",
            "main{{max-width:46rem;margin:0 auto;padding:2.5rem 1.25rem 3rem}}",
            ".eyebrow{{letter-spacing:.16em;text-transform:uppercase;font-size:.72rem;color:var(--mute)}}",
            "h1{{font-family:\"IBM Plex Serif\",Georgia,serif;font-size:clamp(1.8rem,4vw,2.4rem);line-height:1.15}}",
            "#status{{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:.35rem .8rem}}",
            "#status[data-phase=completed]{{color:var(--accent)}}#status[data-phase=error]{{color:var(--fail)}}",
            "section{{margin-top:1.4rem;padding:1rem 1.1rem;border:1px solid color-mix(in srgb,var(--line) 55%,transparent);",
            "border-radius:.9rem;background:color-mix(in srgb,var(--panel) 88%,transparent)}}",
            "h2{{margin:0 0 .55rem;font-size:.78rem;letter-spacing:.12em;text-transform:uppercase;color:var(--mute)}}",
            "ul{{margin:0;padding-left:1.15rem;line-height:1.45}}footer{{margin-top:1.5rem;color:var(--mute);font-size:.9rem}}",
            "</style></head><body><main>",
            "<p class=\"eyebrow\">Silvervine local probe</p>",
            "<h1>Browser media capability check</h1>",
            "<p id=\"status\" data-phase=\"running\" role=\"status\" aria-live=\"polite\">Checking browser media capabilities…</p>",
            "<section aria-labelledby=\"summary-heading\"><h2 id=\"summary-heading\">Summary</h2>",
            "<p id=\"summary\">Waiting for browser evidence…</p></section>",
            "<section aria-labelledby=\"findings-heading\"><h2 id=\"findings-heading\">Findings</h2>",
            "<ul id=\"findings\"><li>Collecting local EME and MediaCapabilities facts.</li></ul></section>",
            "<section aria-labelledby=\"actions-heading\"><h2 id=\"actions-heading\">Actions</h2>",
            "<ul id=\"actions\"><li>Remain on this page until the check finishes.</li></ul></section>",
            "<section aria-labelledby=\"limits-heading\"><h2 id=\"limits-heading\">Service limits</h2>",
            "<ul id=\"limits\"><li>Streaming-service policy and entitlement are not tested.</li></ul></section>",
            "<footer>Evidence stays on this device. No long-lived session or required distinctive identifier is requested.</footer>",
            "</main><script nonce=\"{nonce}\">{script}</script></body></html>"
        ),
        nonce = nonce,
        script = PROBE_SCRIPT
    )
}

fn read_urandom(len: usize) -> Result<Vec<u8>> {
    let mut file = File::open("/dev/urandom").map_err(|error| {
        Error::browser_probe_failed("could not read /dev/urandom for probe entropy")
            .with_source(error)
    })?;
    let mut bytes = vec![0_u8; len];
    file.read_exact(&mut bytes).map_err(|error| {
        Error::browser_probe_failed("could not read /dev/urandom for probe entropy")
            .with_source(error)
    })?;
    Ok(bytes)
}

fn hex_bytes(bytes: &[u8]) -> Result<String> {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    if out.is_empty() {
        return Err(Error::browser_probe_failed(
            "probe entropy source returned no bytes",
        ));
    }
    Ok(out)
}

struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

enum RequestError {
    Malformed,
    TooLarge,
    LengthRequired,
    /// `Transfer-Encoding` is forbidden; Content-Length only.
    TransferEncoding,
}
fn respond_request_error(stream: &mut TcpStream, error: &RequestError) -> Result<()> {
    let (status, body): (u16, &[u8]) = match error {
        RequestError::TooLarge => (413, b"payload too large"),
        RequestError::LengthRequired => (411, b"length required"),
        RequestError::TransferEncoding => (400, b"transfer-encoding not allowed"),
        RequestError::Malformed => (400, b"bad request"),
    };
    respond(stream, status, "text/plain", body, None)
}

fn discard_declared_body(stream: &mut TcpStream, buffered: usize, content_length: usize) {
    let mut remaining = content_length.saturating_sub(buffered.min(content_length));
    let mut buffer = [0_u8; 4096];
    while remaining > 0 {
        let limit = buffer.len().min(remaining);
        match stream.read(&mut buffer[..limit]) {
            Ok(0) | Err(_) => return,
            Ok(count) => remaining -= count,
        }
    }
}

fn read_request(stream: &mut TcpStream) -> std::result::Result<HttpRequest, RequestError> {
    let mut received = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) = received.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        if received.len() >= MAX_HEADER_BYTES {
            return Err(RequestError::TooLarge);
        }
        let mut buffer = [0_u8; 4096];
        let limit = buffer.len().min(MAX_HEADER_BYTES - received.len());
        let count = stream
            .read(&mut buffer[..limit])
            .map_err(|_| RequestError::Malformed)?;
        if count == 0 {
            return Err(RequestError::Malformed);
        }
        received.extend_from_slice(&buffer[..count]);
    };

    let header =
        std::str::from_utf8(&received[..header_end]).map_err(|_| RequestError::Malformed)?;
    let mut lines = header[..header.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(RequestError::Malformed)?;
    if request_line.len() > MAX_REQUEST_LINE_BYTES {
        return Err(RequestError::TooLarge);
    }
    let mut request_parts = request_line.split_ascii_whitespace();
    let method = request_parts.next().ok_or(RequestError::Malformed)?;
    let path = request_parts.next().ok_or(RequestError::Malformed)?;
    let version = request_parts.next().ok_or(RequestError::Malformed)?;
    if request_parts.next().is_some()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !path.starts_with('/')
    {
        return Err(RequestError::Malformed);
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(RequestError::Malformed)?;
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || headers.insert(name, value.trim().to_owned()).is_some() {
            return Err(RequestError::Malformed);
        }
    }
    // Content-Length only. Drain a bounded, declared body before rejecting
    // Transfer-Encoding so closing the connection does not discard the 400
    // response with a TCP reset.
    if headers.contains_key("transfer-encoding") {
        if let Some(content_length) = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|length| *length <= MAX_BODY_BYTES)
        {
            discard_declared_body(
                stream,
                received.len().saturating_sub(header_end),
                content_length,
            );
        }
        return Err(RequestError::TransferEncoding);
    }
    let content_length = match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| RequestError::Malformed)?,
        None if method == "POST" => return Err(RequestError::LengthRequired),
        None => 0,
    };
    if content_length > MAX_BODY_BYTES {
        return Err(RequestError::TooLarge);
    }
    let available = received.len().saturating_sub(header_end);
    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(&received[header_end..header_end + available.min(content_length)]);
    while body.len() < content_length {
        let remaining = content_length - body.len();
        let mut buffer = [0_u8; 4096];
        let limit = buffer.len().min(remaining);
        let count = stream
            .read(&mut buffer[..limit])
            .map_err(|_| RequestError::Malformed)?;
        if count == 0 {
            return Err(RequestError::Malformed);
        }
        body.extend_from_slice(&buffer[..count]);
    }
    Ok(HttpRequest {
        method: method.into(),
        path: path.into(),
        headers,
        body,
    })
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    csp: Option<String>,
) -> Result<()> {
    match write_response(stream, status, content_type, body, csp) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::NotConnected
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(Error::from(error)),
    }
}

fn respond_strict(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    csp: Option<String>,
) -> Result<()> {
    write_response(stream, status, content_type, body, csp).map_err(|error| {
        Error::browser_probe_failed("browser disconnected before receiving the assessment")
            .with_source(error)
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    csp: Option<String>,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Error",
    };
    let mut headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n",
        body.len()
    );
    if let Some(policy) = csp {
        write!(&mut headers, "Content-Security-Policy: {policy}\r\n")
            .expect("writing to String cannot fail");
    }
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpStream};
    use std::thread;
    use std::time::Duration;

    use super::{ProbeServer, PROBE_SCRIPT};
    use crate::eme::probe::{
        CanPlayStatus, CapabilityStatus, CodecCapability, EncryptionSchemeResult, HdcpResult,
        MediaCapabilitiesFacts, MediaKind, RawProbeResult, RobustnessResult, PROBE_SCHEMA_VERSION,
    };
    use crate::widevine::ownership::{OwnershipAssessment, OwnershipKind};

    fn ownership() -> OwnershipAssessment {
        OwnershipAssessment {
            kind: OwnershipKind::Managed,
            summary: "The installed CDM has valid Silvervine provenance.".into(),
            action: None,
            details: BTreeMap::default(),
        }
    }

    fn send(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).expect("connect");
        stream.write_all(request.as_bytes()).expect("request");
        stream.shutdown(Shutdown::Write).expect("shutdown");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("response");
        response
    }

    fn result_json() -> String {
        let mut robustness = Vec::new();
        for media_kind in [MediaKind::Audio, MediaKind::Video] {
            for level in [
                "SW_SECURE_CRYPTO",
                "SW_SECURE_DECODE",
                "HW_SECURE_CRYPTO",
                "HW_SECURE_DECODE",
                "HW_SECURE_ALL",
            ] {
                robustness.push(RobustnessResult {
                    media_kind,
                    robustness: level.into(),
                    accepted: level.starts_with("SW_"),
                    error: None,
                });
            }
        }
        let mut codecs = Vec::new();
        for codec in [
            ("avc1.640028", "video/mp4; codecs=\"avc1.640028\""),
            ("hvc1.1.6.L120.B0", "video/mp4; codecs=\"hvc1.1.6.L120.B0\""),
            ("vp09.00.51.08", "video/webm; codecs=\"vp09.00.51.08\""),
            ("av01.0.08M.08", "video/mp4; codecs=\"av01.0.08M.08\""),
        ] {
            for (width, height, framerate) in [
                (1280_u32, 720_u32, 30_u32),
                (1920, 1080, 30),
                (3840, 2160, 30),
            ] {
                codecs.push(CodecCapability {
                    codec: codec.0.into(),
                    content_type: codec.1.into(),
                    width,
                    height,
                    framerate,
                    mse_supported: true,
                    direct_playback: CanPlayStatus::Probably,
                    media_capabilities: Some(MediaCapabilitiesFacts {
                        supported: true,
                        smooth: Some(true),
                        power_efficient: Some(false),
                        key_system_access: Some(true),
                    }),
                    error: None,
                });
            }
        }
        serde_json::to_string(&RawProbeResult {
            schema_version: PROBE_SCHEMA_VERSION,
            user_agent: "Chromium/150".into(),
            eme_api: true,
            media_capabilities_api: true,
            baseline: CapabilityStatus::Supported,
            baseline_error: None,
            robustness,
            encryption_schemes: vec![
                EncryptionSchemeResult {
                    scheme: "cenc".into(),
                    accepted: true,
                    error: None,
                },
                EncryptionSchemeResult {
                    scheme: "cbcs".into(),
                    accepted: true,
                    error: None,
                },
            ],
            hdcp: vec![
                HdcpResult {
                    min_version: "1.4".into(),
                    status: Some("usable".into()),
                    error: None,
                },
                HdcpResult {
                    min_version: "2.2".into(),
                    status: Some("usable".into()),
                    error: None,
                },
            ],
            codecs,
        })
        .expect("json")
    }

    #[test]
    fn server_uses_ipv4_loopback_and_unique_random_tokens() {
        let first = ProbeServer::bind(Duration::from_secs(1), ownership()).expect("first");
        let second = ProbeServer::bind(Duration::from_secs(1), ownership()).expect("second");
        assert!(first.address().ip().is_loopback());
        assert_ne!(first.token(), second.token());
        assert_ne!(first.nonce(), second.nonce());
    }

    #[test]
    fn serves_nonce_page_then_returns_rust_assessment_json() {
        let server = ProbeServer::bind(Duration::from_secs(2), ownership()).expect("server");
        let address = server.address();
        let token = server.token().to_owned();
        let nonce = server.nonce().to_owned();
        let origin = format!("http://{address}");
        let waiter = thread::spawn(move || server.wait_for_result());

        let page = send(
            address,
            &format!("GET /{token}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"),
        );
        assert!(page.starts_with("HTTP/1.1 200"));
        assert!(page.contains(&format!("script-src 'nonce-{nonce}'")));
        assert!(!page.contains("script-src 'self'"));
        assert!(page.contains(&format!("<script nonce=\"{nonce}\">")));
        assert!(!page.to_ascii_lowercase().contains("persistent-license"));

        let body = result_json();
        let response = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(response.starts_with("HTTP/1.1 200"));
        let outcome = waiter.join().expect("waiter").expect("probe result");
        let response_body = response.split("\r\n\r\n").nth(1).expect("body");
        let returned: crate::eme::probe::CapabilityAssessment =
            serde_json::from_str(response_body).expect("assessment json");
        assert_eq!(returned, outcome.assessment);
    }

    #[test]
    fn rejects_wrong_method_and_missing_content_length() {
        let server = ProbeServer::bind(Duration::from_secs(2), ownership()).expect("server");
        let address = server.address();
        let token = server.token().to_owned();
        let origin = format!("http://{address}");
        let waiter = thread::spawn(move || server.wait_for_result());

        let wrong_method = send(
            address,
            &format!("PUT /{token}/ HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"),
        );
        assert!(wrong_method.starts_with("HTTP/1.1 405"));

        let missing_length = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{{}}"
            ),
        );
        assert!(missing_length.starts_with("HTTP/1.1 411"));

        let body = result_json();
        let accepted = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(accepted.starts_with("HTTP/1.1 200"));
        waiter.join().expect("waiter").expect("result");
    }

    #[test]
    fn second_accepted_post_is_rejected() {
        let mut server = ProbeServer::bind(Duration::from_secs(2), ownership()).expect("server");
        let address = server.address();
        let token = server.token().to_owned();
        let origin = format!("http://{address}");
        let body = result_json();

        let first = {
            let mut stream = TcpStream::connect(address).expect("connect");
            let request = format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let accept = thread::spawn(move || {
                let (mut inbound, _) = server.listener.accept().expect("accept");
                inbound.set_nonblocking(false).expect("blocking");
                let outcome = server.handle(&mut inbound).expect("handle");
                (server, outcome)
            });
            stream.write_all(request.as_bytes()).expect("write");
            stream.shutdown(Shutdown::Write).expect("shutdown");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read");
            let (updated, outcome) = accept.join().expect("accept join");
            server = updated;
            assert!(outcome.is_some());
            response
        };
        assert!(first.starts_with("HTTP/1.1 200"));

        let second = {
            let mut stream = TcpStream::connect(address).expect("connect2");
            let request = format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let accept = thread::spawn(move || {
                let (mut inbound, _) = server.listener.accept().expect("accept2");
                inbound.set_nonblocking(false).expect("blocking2");
                server.handle(&mut inbound).expect("handle2")
            });
            stream.write_all(request.as_bytes()).expect("write2");
            stream.shutdown(Shutdown::Write).expect("shutdown2");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read2");
            assert!(accept.join().expect("accept2 join").is_none());
            response
        };
        assert!(second.starts_with("HTTP/1.1 409"));
    }

    #[test]
    fn rejects_foreign_origin_without_consuming_the_token() {
        let server = ProbeServer::bind(Duration::from_secs(2), ownership()).expect("server");
        let address = server.address();
        let token = server.token().to_owned();
        let origin = format!("http://{address}");
        let waiter = thread::spawn(move || server.wait_for_result());
        let body = result_json();

        let rejected = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: https://attacker.example\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(rejected.starts_with("HTTP/1.1 403"));

        let accepted = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(accepted.starts_with("HTTP/1.1 200"));
        waiter.join().expect("waiter").expect("probe result");
    }

    #[test]
    fn rejects_oversized_posts_without_allocating_the_body() {
        let server = ProbeServer::bind(Duration::from_secs(2), ownership()).expect("server");
        let address = server.address();
        let token = server.token().to_owned();
        let origin = format!("http://{address}");
        let waiter = thread::spawn(move || server.wait_for_result());

        let rejected = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: 9999999\r\nConnection: close\r\n\r\n"
            ),
        );
        assert!(rejected.starts_with("HTTP/1.1 413"));

        let body = result_json();
        let accepted = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(accepted.starts_with("HTTP/1.1 200"));
        waiter.join().expect("waiter").expect("probe result");
    }

    #[test]
    fn no_result_is_a_bounded_probe_timeout() {
        let server = ProbeServer::bind(Duration::from_millis(30), ownership()).expect("server");
        let error = server.wait_for_result().expect_err("timeout");
        assert_eq!(error.category, crate::ErrorCategory::BrowserProbeFailed);
        assert!(error.message.contains("timed out"));
    }

    #[test]
    fn probe_script_never_requests_forbidden_capabilities() {
        let script = PROBE_SCRIPT;
        assert!(!script.contains("persistent-license"));
        assert!(!script.contains("distinctiveIdentifier: \"optional\""));
        assert!(!script.contains("distinctiveIdentifier: \"required\""));
        assert!(!script.contains("persistentState: \"optional\""));
        assert!(!script.contains("persistentState: \"required\""));
        assert_eq!(
            script
                .matches("distinctiveIdentifier: \"not-allowed\"")
                .count(),
            2
        );
        assert_eq!(
            script.matches("persistentState: \"not-allowed\"").count(),
            2
        );
        assert!(script.contains("sessionTypes: [\"temporary\"]"));
        assert!(script.contains("avc1.640028"));
        assert!(script.contains("hvc1.1.6.L120.B0"));
        assert!(script.contains("vp09.00.51.08"));
        assert!(script.contains("av01.0.08M.08"));
        assert!(script.contains("3840"));
        assert!(script.contains("cenc"));
        assert!(script.contains("cbcs"));
        assert!(script.contains("\"1.4\""));
        assert!(script.contains("\"2.2\""));
        assert!(!script.contains("\"2.3\""));
    }

    #[test]
    fn rejects_transfer_encoding_even_with_content_length() {
        let server = ProbeServer::bind(Duration::from_secs(2), ownership()).expect("server");
        let address = server.address();
        let token = server.token().to_owned();
        let origin = format!("http://{address}");
        let waiter = thread::spawn(move || server.wait_for_result());
        let body = result_json();

        let rejected = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(
            rejected.starts_with("HTTP/1.1 400"),
            "expected 400 for Transfer-Encoding, got {rejected}"
        );

        let accepted = send(
            address,
            &format!(
                "POST /{token}/result HTTP/1.1\r\nHost: {address}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        );
        assert!(accepted.starts_with("HTTP/1.1 200"));
        waiter.join().expect("waiter").expect("probe result");
    }

    #[test]
    fn probe_script_matrix_matches_approved_shape() {
        use crate::eme::probe::{
            EXPECTED_CODEC_ROWS, EXPECTED_HDCP_ROWS, EXPECTED_ROBUSTNESS_ROWS, EXPECTED_SCHEME_ROWS,
        };
        let script = PROBE_SCRIPT;
        // 5 robustness levels × 2 media kinds
        assert_eq!(EXPECTED_ROBUSTNESS_ROWS, 10);
        assert_eq!(EXPECTED_SCHEME_ROWS, 2);
        assert_eq!(EXPECTED_HDCP_ROWS, 2);
        assert_eq!(EXPECTED_CODEC_ROWS, 12);
        for token in [
            "SW_SECURE_CRYPTO",
            "SW_SECURE_DECODE",
            "HW_SECURE_CRYPTO",
            "HW_SECURE_DECODE",
            "HW_SECURE_ALL",
            "cenc",
            "cbcs",
            "avc1.640028",
            "hvc1.1.6.L120.B0",
            "vp09.00.51.08",
            "av01.0.08M.08",
            "1280",
            "1920",
            "3840",
            "\"1.4\"",
            "\"2.2\"",
        ] {
            assert!(script.contains(token), "probe.js missing {token}");
        }
        assert!(!script.contains("\"2.3\""));
        assert!(!script.contains("persistent-license"));
    }
}
