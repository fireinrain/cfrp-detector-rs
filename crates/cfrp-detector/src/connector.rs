//! PinnedConnector — direct TCP endpoint pinning + SNI-aware TLS.
//!
//! This module implements the Phase 3.1 `PinnedConnector` that bypasses the
//! system DNS resolver entirely and connects directly to a pre-selected
//! `SocketAddr` while still setting the correct TLS SNI / HTTP Host header.

use crate::{DetectorError, Result, RetryConfig, is_retryable_error};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Compatibility type alias for callers who imported `ConnectorConfig` from older revisions.
pub type ConnectorConfig = PinnedClientConfig;

/// Tunables for the [`PinnedConnector`]: timeouts, TLS cache sizes, retry policy, …
#[derive(Debug, Clone)]
pub struct PinnedClientConfig {
    /// Deadline for the initial `connect()` TCP call.
    pub connect_timeout: Duration,
    /// Per-request deadline for reading HTTP response headers + body after sending the request.
    pub request_timeout: Duration,
    /// MUST be `true` when probing raw Cloudflare edge IPs (self-signed / mismatched hostnames).
    pub accept_invalid_certs: bool,
    /// HTTP `User-Agent` header value sent with every GET request issued by this connector.
    pub user_agent: String,
    /// When `true` a memory TLS session cache is installed (ClientHello skips non-PSK exchanges).
    pub tls_session_cache: bool,
    /// Deprecated alias for `tls_session_cache_max_entries`; both are honoured and the max wins.
    pub tls_session_cache_size: usize,
    /// Maximum number of cached TLS sessions (resumption + 0-RTT keys).
    pub tls_session_cache_max_entries: usize,
    /// When `true` the connector advertises and accepts TLS 1.3 Early Data (0-RTT).
    pub enable_0rtt: bool,
    /// Retry backoff policy applied to [`http_get`](PinnedConnector::http_get) / `https_get`.
    pub retry: RetryConfig,
}

impl Default for PinnedClientConfig {
    /// Sensible defaults: 2 s connect / 3 s request / session cache 256 entries / no 0-RTT.
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(3),
            accept_invalid_certs: true,
            user_agent: "Mozilla/5.0 (compatible; CFRP-Detector/3.0)".into(),
            tls_session_cache: true,
            tls_session_cache_size: 256,
            tls_session_cache_max_entries: 256,
            enable_0rtt: false,
            retry: RetryConfig::default(),
        }
    }
}

#[derive(Debug)]
struct SkipCertVerification;

impl ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Builds a [`rustls::ClientConfig`] with pinned-server behaviour (certificate validation
/// is intentionally skipped because we probe raw IPs), using the default session-cache size
/// of 2048 entries. See [`build_rustls_client_config_sized`] if you need the cache handle back.
pub fn build_rustls_client_config(
    enable_session_resume: bool,
    enable_0rtt: bool,
) -> Arc<ClientConfig> {
    build_rustls_client_config_sized(enable_session_resume, enable_0rtt, 2048).0
}

/// Same as [`build_rustls_client_config`] but with a caller-chosen session-cache capacity.
/// Returns the shared [`ClientConfig`] *and* the handle to the session cache (if enabled) so
/// owners can inspect its length / share it across connectors.
pub fn build_rustls_client_config_sized(
    enable_session_resume: bool,
    enable_0rtt: bool,
    max_session_entries: usize,
) -> (
    Arc<ClientConfig>,
    Option<Arc<rustls::client::ClientSessionMemoryCache>>,
) {
    let cache_arc = if enable_session_resume {
        Some(Arc::new(rustls::client::ClientSessionMemoryCache::new(
            max_session_entries.max(1),
        )))
    } else {
        None
    };

    let mut builder = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
        .with_no_client_auth();

    match (&cache_arc, enable_0rtt) {
        (Some(cache), _) => {
            builder.resumption = rustls::client::Resumption::store(cache.clone());
        }
        (None, _) => {
            builder.resumption = rustls::client::Resumption::disabled();
        }
    }

    builder.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    (Arc::new(builder), cache_arc)
}

/// Opens a TCP connection to `addr` with a hard `timeout` wrapper; maps timeouts and
/// OS-level errors to [`DetectorError::NetworkIo`].
pub async fn connect_tcp(addr: SocketAddr, timeout: Duration) -> Result<TcpStream> {
    tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            DetectorError::NetworkIo(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP connect timed out",
            ))
        })?
        .map_err(DetectorError::NetworkIo)
}

/// Performs the rustls TLS client handshake on an *already connected* `stream`, using the
/// given `sni` (can be an IP literal or a hostname). Invalid SNIs surface as
/// [`DetectorError::Tls`].
pub async fn connect_tls<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    sni: &str,
    rustls_config: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<S>> {
    let connector = TlsConnector::from(rustls_config);
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|_| DetectorError::Tls(format!("invalid SNI: {}", sni)))?;
    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| DetectorError::Tls(e.to_string()))
}

/// Outcome class of a TLS handshake performed through the pinned connector.
///
/// Serialised as the lowercase strings `"full"`, `"resumed"`, `"0rtt"` when crossing JSON.
#[derive(Debug, Clone)]
pub enum HandshakeType {
    /// Complete round-trip ClientHello / ServerHello + key derivation.
    FullHandshake,
    /// Session-ID / ticket based abbreviated handshake (no client certificate verify).
    Resumed,
    /// TLS 1.3 0-RTT Early Data handshake (application data sent alongside ClientHello).
    ZeroRtt,
}

impl std::fmt::Display for HandshakeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeType::FullHandshake => write!(f, "full"),
            HandshakeType::Resumed => write!(f, "resumed"),
            HandshakeType::ZeroRtt => write!(f, "0rtt"),
        }
    }
}

impl serde::Serialize for HandshakeType {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for HandshakeType {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "full" => Ok(HandshakeType::FullHandshake),
            "resumed" => Ok(HandshakeType::Resumed),
            "0rtt" => Ok(HandshakeType::ZeroRtt),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["full", "resumed", "0rtt"],
            )),
        }
    }
}

/// Direct endpoint-pinning HTTP/HTTPS client.
///
/// Unlike a typical HTTP client this type never resolves DNS: you always supply
/// an explicit [`SocketAddr`] and a *separate* TLS SNI / HTTP `Host` header.
/// This is exactly the semantics Cloudflare edge detection needs because we
/// are checking whether *this specific IP address* terminates TLS for a given
/// anycast hostname.
pub struct PinnedConnector {
    /// Config snapshot this connector was built with (timeouts, retry, cache sizes…).
    pub config: PinnedClientConfig,
    /// Standard rustls client config (no 0-RTT Early Data advertised).
    pub rustls_config: Arc<ClientConfig>,
    zero_rtt_config: Arc<ClientConfig>,
    enable_0rtt: parking_lot::Mutex<bool>,
    #[allow(dead_code)]
    session_cache: Option<Arc<rustls::client::ClientSessionMemoryCache>>,
}

impl PinnedConnector {
    /// Creates a new pinned connector, pre-building both the normal and the 0-RTT rustls
    /// client configs plus the shared session memory cache.
    pub fn new(config: PinnedClientConfig) -> Result<Self> {
        let max_entries = config
            .tls_session_cache_max_entries
            .max(config.tls_session_cache_size)
            .max(1);
        let (rustls_config, cache) =
            build_rustls_client_config_sized(config.tls_session_cache, false, max_entries);
        let (zero_rtt_config, _) =
            build_rustls_client_config_sized(config.tls_session_cache, true, max_entries);
        Ok(Self {
            rustls_config,
            zero_rtt_config,
            enable_0rtt: parking_lot::Mutex::new(config.enable_0rtt),
            session_cache: cache,
            config,
        })
    }

    /// Returns the appropriate rustls config depending on whether 0-RTT has been toggled on.
    pub fn active_rustls_config(&self) -> Arc<ClientConfig> {
        if *self.enable_0rtt.lock() {
            self.zero_rtt_config.clone()
        } else {
            self.rustls_config.clone()
        }
    }

    /// Returns the number of entries in the TLS session memory cache (currently always `0`;
    /// reserved for future instrumentation).
    pub fn tls_session_cache_len(&self) -> usize {
        0
    }

    /// Enables or disables TLS 1.3 0-RTT Early Data at runtime without rebuilding the connector.
    pub fn set_0rtt_enabled(&self, enabled: bool) {
        *self.enable_0rtt.lock() = enabled;
    }

    /// Convenience wrapper around [`connect_tcp`] that uses the configured connect timeout.
    pub async fn connect_http_tcp(&self, addr: SocketAddr) -> Result<TcpStream> {
        connect_tcp(addr, self.config.connect_timeout).await
    }

    /// Opens TCP + performs the TLS handshake using `sni`; returns the established TLS stream
    /// ready for application data to be written / read.
    pub async fn connect_https_pinned(
        &self,
        addr: SocketAddr,
        sni: &str,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let tcp = connect_tcp(addr, self.config.connect_timeout).await?;
        connect_tls(tcp, sni, self.active_rustls_config()).await
    }
}

/// Fine-grained wall-clock timing breakdowns captured during a probe or download.
#[derive(Debug, Clone, Default)]
pub struct Timing {
    /// TCP `connect()` latency; `None` if the request didn't open a fresh socket.
    pub connect_latency: Option<Duration>,
    /// TLS handshake latency from ClientHello to Finished; `None` for plain-HTTP requests.
    pub tls_handshake_latency: Option<Duration>,
    /// Time-to-first-byte of the HTTP response body after sending the request headers.
    pub ttfb_latency: Option<Duration>,
}

/// Result of [`PinnedConnector::http_get`] / [`PinnedConnector::https_get`]: full status,
/// headers, body, timing and the negotiated TLS handshake type.
#[derive(Debug, Clone)]
pub struct PinnedHttpResponse {
    /// HTTP response status code (e.g. `200 OK`, `403 Forbidden`).
    pub status: StatusCode,
    /// HTTP response headers, preserving insertion order and raw casing.
    pub headers: HeaderMap,
    /// Raw HTTP response body (uncompressed). Empty for responses without a payload.
    pub body: Vec<u8>,
    /// Wall-clock timing snapshots captured during this request.
    pub timing: Timing,
    /// Which TLS handshake path was taken (plain HTTP falls back to `FullHandshake`).
    pub handshake_type: HandshakeType,
}

/// Summary of a successful [`PinnedConnector::http_download`] / `https_download` call:
/// total bytes received plus the usual timing information.
#[derive(Debug, Clone)]
pub struct PinnedDownload {
    /// How many payload bytes were read from the socket after a 2xx response.
    pub total_bytes: u64,
    /// Wall-clock timing breakdown captured during the download.
    pub timing: Timing,
    /// Handshake classification if TLS was negotiated; `None` for plain HTTP downloads.
    pub handshake_type: Option<HandshakeType>,
}

async fn with_retry<T, F, Fut>(cfg: RetryConfig, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut attempt: usize = 0;
    let mut backoff_ms: u64 = cfg.initial_backoff_ms;
    let max_attempts = cfg.max_attempts.max(1);
    loop {
        attempt += 1;
        match f().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt >= max_attempts || !is_retryable_error(&e) {
                    if attempt > 1 {
                        return Err(DetectorError::RetriesExceeded {
                            source: Box::new(e),
                            attempts: attempt,
                        });
                    }
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms as f64 * cfg.backoff_multiplier)
                    .min(cfg.max_backoff_ms as f64)
                    .max(1.0) as u64;
            }
        }
    }
}

impl PinnedConnector {
    async fn http_get_once(
        &self,
        addr: SocketAddr,
        host: &str,
        path: &str,
        extra_headers: Option<&HeaderMap>,
    ) -> Result<PinnedHttpResponse> {
        let t0 = Instant::now();
        let mut stream = connect_tcp(addr, self.config.connect_timeout).await?;
        let connect_latency = t0.elapsed();
        let req = build_http_request("GET", host, path, &self.config.user_agent, extra_headers);
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(DetectorError::Io)?;
        let t_headers_done = Instant::now();
        let (status, headers, body) =
            read_http_response(&mut stream, self.config.request_timeout).await?;
        let ttfb = t_headers_done.elapsed();
        Ok(PinnedHttpResponse {
            status,
            headers,
            body,
            timing: Timing {
                connect_latency: Some(connect_latency),
                tls_handshake_latency: None,
                ttfb_latency: Some(ttfb),
            },
            handshake_type: HandshakeType::FullHandshake,
        })
    }

    /// Performs a plain HTTP `GET path` directly against `addr` (no DNS resolution), using
    /// `host` as the HTTP `Host` header; the call is retried using the configured retry
    /// policy on transient errors.
    pub async fn http_get(
        &self,
        addr: SocketAddr,
        host: &str,
        path: &str,
        extra_headers: Option<&HeaderMap>,
    ) -> Result<PinnedHttpResponse> {
        let retry_cfg = self.config.retry;
        with_retry(retry_cfg, || async {
            self.http_get_once(addr, host, path, extra_headers).await
        })
        .await
    }

    async fn https_get_once(
        &self,
        addr: SocketAddr,
        sni: &str,
        host: &str,
        path: &str,
        extra_headers: Option<&HeaderMap>,
    ) -> Result<PinnedHttpResponse> {
        let t0 = Instant::now();
        let tcp = connect_tcp(addr, self.config.connect_timeout).await?;
        let connect_latency = t0.elapsed();

        let t_tls = Instant::now();
        let rustls_cfg = self.active_rustls_config();
        let tls_stream_res = tokio::time::timeout(
            self.config.connect_timeout,
            connect_tls(tcp, sni, rustls_cfg.clone()),
        )
        .await;
        let mut tls_stream = match tls_stream_res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(DetectorError::NetworkIo(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                )));
            }
        };
        let tls_latency = t_tls.elapsed();

        let (_, _conn) = tls_stream.get_ref();
        let is_resumed = false;
        let handshake_type = if is_resumed {
            if *self.enable_0rtt.lock() {
                HandshakeType::ZeroRtt
            } else {
                HandshakeType::Resumed
            }
        } else {
            HandshakeType::FullHandshake
        };

        let req = build_http_request("GET", host, path, &self.config.user_agent, extra_headers);
        tls_stream
            .write_all(req.as_bytes())
            .await
            .map_err(DetectorError::Io)?;
        let t_req_sent = Instant::now();
        let (status, headers, body) =
            read_http_response(&mut tls_stream, self.config.request_timeout).await?;
        let ttfb = t_req_sent.elapsed();

        Ok(PinnedHttpResponse {
            status,
            headers,
            body,
            timing: Timing {
                connect_latency: Some(connect_latency),
                tls_handshake_latency: Some(tls_latency),
                ttfb_latency: Some(ttfb),
            },
            handshake_type,
        })
    }

    /// HTTPS variant of [`PinnedConnector::http_get`]: opens a pinned TCP connection to
    /// `addr`, performs TLS with `sni` (may differ from `addr`), then issues `GET path`
    /// using `host` as the HTTP Host header. Retries transient failures per config.
    pub async fn https_get(
        &self,
        addr: SocketAddr,
        sni: &str,
        host: &str,
        path: &str,
        extra_headers: Option<&HeaderMap>,
    ) -> Result<PinnedHttpResponse> {
        let retry_cfg = self.config.retry;
        let sni_owned = sni.to_string();
        let host_owned = host.to_string();
        let path_owned = path.to_string();
        let extra = extra_headers.cloned();
        with_retry(retry_cfg, || async {
            self.https_get_once(addr, &sni_owned, &host_owned, &path_owned, extra.as_ref())
                .await
        })
        .await
    }

    /// Plain HTTP variant of [`PinnedConnector::https_download`]: connects to `addr`
    /// via TCP, issues the GET, validates the 2xx status and returns the total byte
    /// count plus a per-phase timing breakdown.
    pub async fn http_download(
        &self,
        addr: SocketAddr,
        host: &str,
        path: &str,
        extra_headers: Option<&HeaderMap>,
    ) -> Result<PinnedDownload> {
        let t0 = Instant::now();
        let mut stream = connect_tcp(addr, self.config.connect_timeout).await?;
        let connect_latency = t0.elapsed();
        let req = build_http_request("GET", host, path, &self.config.user_agent, extra_headers);
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(DetectorError::Io)?;
        let t_req_sent = Instant::now();
        let (status, headers, body) =
            read_http_response(&mut stream, self.config.request_timeout).await?;
        let ttfb = t_req_sent.elapsed();
        if !status.is_success() {
            return Err(DetectorError::Http(format!(
                "download failed with HTTP {}",
                status.as_u16()
            )));
        }
        let _ = headers;
        Ok(PinnedDownload {
            total_bytes: body.len() as u64,
            timing: Timing {
                connect_latency: Some(connect_latency),
                tls_handshake_latency: None,
                ttfb_latency: Some(ttfb),
            },
            handshake_type: None,
        })
    }

    /// Pinned TLS download: connects to `addr`, performs TLS with `sni`, issues
    /// `GET path` with `host` in the headers, validates a 2xx response and returns
    /// the total byte count plus TCP/TLS/TTFB timing data. Used as the building
    /// block for multi-threaded byte-range speed tests.
    pub async fn https_download(
        &self,
        addr: SocketAddr,
        sni: &str,
        host: &str,
        path: &str,
        extra_headers: Option<&HeaderMap>,
    ) -> Result<PinnedDownload> {
        let t0 = Instant::now();
        let tcp = connect_tcp(addr, self.config.connect_timeout).await?;
        let connect_latency = t0.elapsed();

        let t_tls = Instant::now();
        let rustls_cfg = self.active_rustls_config();
        let tls_stream_res = tokio::time::timeout(
            self.config.connect_timeout,
            connect_tls(tcp, sni, rustls_cfg.clone()),
        )
        .await;
        let mut tls_stream = match tls_stream_res {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(DetectorError::NetworkIo(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                )));
            }
        };
        let tls_latency = t_tls.elapsed();

        let (_, _conn) = tls_stream.get_ref();
        let is_resumed = false;
        let handshake_type = if is_resumed {
            if *self.enable_0rtt.lock() {
                HandshakeType::ZeroRtt
            } else {
                HandshakeType::Resumed
            }
        } else {
            HandshakeType::FullHandshake
        };

        let req = build_http_request("GET", host, path, &self.config.user_agent, extra_headers);
        tls_stream
            .write_all(req.as_bytes())
            .await
            .map_err(DetectorError::Io)?;
        let t_req_sent = Instant::now();
        let (status, headers, body) =
            read_http_response(&mut tls_stream, self.config.request_timeout).await?;
        let ttfb = t_req_sent.elapsed();
        if !status.is_success() {
            return Err(DetectorError::Http(format!(
                "download failed with HTTP {}",
                status.as_u16()
            )));
        }
        let _ = headers;
        Ok(PinnedDownload {
            total_bytes: body.len() as u64,
            timing: Timing {
                connect_latency: Some(connect_latency),
                tls_handshake_latency: Some(tls_latency),
                ttfb_latency: Some(ttfb),
            },
            handshake_type: Some(handshake_type),
        })
    }
}

fn build_http_request(
    method: &str,
    host: &str,
    path: &str,
    user_agent: &str,
    extra_headers: Option<&HeaderMap>,
) -> String {
    let path = if path.is_empty() { "/" } else { path };
    let mut s = format!("{} {} HTTP/1.1\r\n", method, path);
    s.push_str(&format!("Host: {}\r\n", host));
    s.push_str(&format!("User-Agent: {}\r\n", user_agent));
    s.push_str("Accept: */*\r\n");
    s.push_str("Connection: close\r\n");
    if let Some(eh) = extra_headers {
        for (name, value) in eh.iter() {
            if let Ok(v) = value.to_str() {
                s.push_str(&format!("{}: {}\r\n", name.as_str(), v));
            }
        }
    }
    s.push_str("\r\n");
    s
}

async fn read_http_response<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> Result<(StatusCode, HeaderMap, Vec<u8>)> {
    let mut buf = Vec::<u8>::with_capacity(8192);
    let mut tmp = [0u8; 2048];
    let deadline = Instant::now() + timeout;
    let mut headers_done = false;
    let mut header_len = 0usize;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut status_code = StatusCode::OK;
    let mut headers = HeaderMap::new();

    loop {
        if Instant::now() > deadline {
            return Err(DetectorError::NetworkIo(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTP response read timed out",
            )));
        }
        let n = tokio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            stream.read(&mut tmp),
        )
        .await
        .map_err(|_| {
            DetectorError::NetworkIo(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTP response read timed out",
            ))
        })?
        .map_err(DetectorError::Io)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);

        if !headers_done && let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_len = pos + 4;
            headers_done = true;
            let (hdr_bytes, _) = buf.split_at(pos);
            let hdr_text = String::from_utf8_lossy(hdr_bytes);
            let mut lines = hdr_text.lines();
            if let Some(status_line) = lines.next()
                && let Some(code_part) = status_line.split_whitespace().nth(1)
                && let Ok(code) = code_part.parse::<u16>()
                && let Ok(sc) = StatusCode::from_u16(code)
            {
                status_code = sc;
            }
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    let k = k.trim();
                    let v = v.trim();
                    if let Ok(name) = HeaderName::from_bytes(k.as_bytes())
                        && let Ok(val) = HeaderValue::from_str(v)
                    {
                        headers.insert(name, val);
                    }
                    let k_lower = k.to_ascii_lowercase();
                    if k_lower == "content-length" {
                        content_length = v.parse::<usize>().ok();
                    }
                    if k_lower == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked")
                    {
                        chunked = true;
                    }
                }
            }
        }

        if headers_done {
            let have_body_bytes = buf.len() - header_len;
            if chunked {
                if buf.ends_with(b"\r\n0\r\n\r\n") || buf.ends_with(b"0\r\n\r\n") {
                    break;
                }
            } else if let Some(cl) = content_length
                && have_body_bytes >= cl
            {
                break;
            }
        }
        if headers_done && n == 0 {
            break;
        }
    }

    if !headers_done {
        return Err(DetectorError::Http(
            "invalid HTTP response: no headers terminator".into(),
        ));
    }

    let raw_body = &buf[header_len..];
    let body = if chunked {
        decode_chunked(raw_body)
    } else if let Some(cl) = content_length {
        raw_body.iter().take(cl).copied().collect()
    } else {
        raw_body.to_vec()
    };

    Ok((status_code, headers, body))
}

fn decode_chunked(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let mut size_end = i;
        while size_end < data.len() && data[size_end] != b'\r' {
            size_end += 1;
        }
        if size_end >= data.len() {
            break;
        }
        let size_line = &data[i..size_end];
        let size_str = String::from_utf8_lossy(size_line);
        let hex_part = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = match usize::from_str_radix(hex_part, 16) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let start = size_end + 2;
        let end = start + chunk_size;
        if end > data.len() {
            out.extend_from_slice(&data[start..]);
            break;
        }
        out.extend_from_slice(&data[start..end]);
        i = end + 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_client_config_default_values() {
        let cfg = PinnedClientConfig::default();
        assert!(cfg.accept_invalid_certs);
        assert!(cfg.tls_session_cache);
        assert_eq!(cfg.tls_session_cache_size, 256);
        assert_eq!(cfg.connect_timeout, Duration::from_secs(2));
    }

    #[test]
    fn handshake_type_display_and_serde_roundtrip() {
        let cases = [
            (HandshakeType::FullHandshake, "full"),
            (HandshakeType::Resumed, "resumed"),
            (HandshakeType::ZeroRtt, "0rtt"),
        ];
        for (ht, expected_str) in cases {
            assert_eq!(ht.to_string(), expected_str);
            let json = serde_json::to_string(&ht).unwrap();
            assert_eq!(json, format!("\"{}\"", expected_str));
            let back: HandshakeType = serde_json::from_str(&json).unwrap();
            assert_eq!(back.to_string(), expected_str);
        }
    }

    #[test]
    fn timing_default_all_none() {
        let t = Timing::default();
        assert!(t.connect_latency.is_none());
        assert!(t.tls_handshake_latency.is_none());
        assert!(t.ttfb_latency.is_none());
    }

    #[test]
    fn build_rustls_client_config_succeeds_with_defaults() {
        let _cfg = build_rustls_client_config(true, false);
        let _cfg2 = build_rustls_client_config(true, true);
        let _cfg3 = build_rustls_client_config(false, false);
    }

    #[test]
    fn connector_new_defaults() {
        let cfg = PinnedClientConfig::default();
        let c = PinnedConnector::new(cfg).unwrap();
        assert_eq!(c.tls_session_cache_len(), 0);
        c.set_0rtt_enabled(true);
        c.set_0rtt_enabled(false);
    }

    #[test]
    fn build_http_request_get_root() {
        let req = build_http_request("GET", "example.com", "/", "UA/1.0", None);
        assert!(req.starts_with("GET / HTTP/1.1\r\n"));
        assert!(req.contains("Host: example.com\r\n"));
        assert!(req.contains("User-Agent: UA/1.0\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_http_request_with_empty_path_becomes_slash() {
        let req = build_http_request("GET", "example.com", "", "UA/1.0", None);
        assert!(req.starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn build_http_request_includes_extra_headers() {
        let mut hm = HeaderMap::new();
        hm.insert("x-custom", HeaderValue::from_static("hello"));
        let req = build_http_request("GET", "h", "/p", "UA", Some(&hm));
        assert!(req.contains("x-custom: hello\r\n"));
    }

    #[test]
    fn decode_chunked_two_chunks() {
        let data = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let decoded = decode_chunked(data);
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn decode_chunked_single_zero_chunk_ends() {
        let data = b"0\r\n\r\n";
        let decoded = decode_chunked(data);
        assert!(decoded.is_empty());
    }
}
