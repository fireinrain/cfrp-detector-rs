use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::pin::Pin;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, body::Incoming, Method};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use cfrp_detector::cidr::CidrSource;
use cfrp_detector::location::{CfLocation, LocationSource};
use cfrp_detector::model::Target;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct MockCfServerConfig {
    pub https: bool,
    pub colo_code: String,
    pub host: String,
    pub latency: Option<Duration>,
    pub reset_probability: f64,
    pub override_status: Option<StatusCode>,
    pub sni_check: bool,
    pub extra_headers: HashMap<String, String>,
    pub speedtest_payload_bytes: usize,
}

pub struct MockCfServer {
    pub addr: SocketAddr,
    pub config: MockCfServerConfig,
    pub req_count: Arc<Mutex<usize>>,
    pub cert_der: Option<Vec<u8>>,
    cancel: tokio_util::sync::CancellationToken,
}

pub fn gen_cert_chain(host: &str) -> (Vec<u8>, Vec<u8>) {
    let sans = vec![
        host.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    let mut cert_params = rcgen::CertificateParams::new(sans).expect("rcgen params");
    cert_params.distinguished_name = rcgen::DistinguishedName::new();
    cert_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);
    let key_pair = rcgen::KeyPair::generate().expect("generate keypair");
    let cert = cert_params.self_signed(&key_pair).expect("self-sign cert");
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();
    (cert_der, key_der)
}

fn build_trace_body(config: &MockCfServerConfig) -> String {
    format!(
        "fl=42000\nh={}\nip=127.0.0.1\nts=1700000000.000\nvisit_scheme=https\nuag=Mozilla/5.0\ncolo={}\nhttp=http/1.1\nloc=US\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n",
        config.host, config.colo_code
    )
}

fn build_response<B>(
    status: StatusCode,
    body: B,
    extra_headers: &HashMap<String, String>,
    is_cf: bool,
) -> Response<Full<Bytes>>
where
    B: Into<Bytes>,
{
    let mut builder = Response::builder().status(status);
    if is_cf {
        builder = builder
            .header("Server", "cloudflare")
            .header("CF-RAY", "8d0e1a2b3c4d5e6f-LAX");
    }
    for (k, v) in extra_headers {
        builder = builder.header(k, v);
    }
    builder
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(Full::new(body.into()))
        .unwrap()
}

fn make_handler(
    config: MockCfServerConfig,
    req_count: Arc<Mutex<usize>>,
) -> impl Fn(Request<Incoming>) -> Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, Infallible>> + Send>> + Clone + Send + 'static
{
    move |req: Request<Incoming>| {
        let config = config.clone();
        let req_count = req_count.clone();
        Box::pin(async move {
            *req_count.lock() += 1;
            if config.reset_probability > 0.0 {
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut h = DefaultHasher::new();
                std::time::SystemTime::now().hash(&mut h);
                let val = h.finish() as f64 / u64::MAX as f64;
                if val < config.reset_probability {
                    let resp = Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Full::new(Bytes::from("reset mock")))
                        .unwrap();
                    return Ok::<_, Infallible>(resp);
                }
            }
            if let Some(delay) = config.latency {
                tokio::time::sleep(delay).await;
            }
            let status = config.override_status.unwrap_or(StatusCode::OK);
            let path = req.uri().path().to_string();
            let method = req.method().clone();
            let result: Response<Full<Bytes>> = match (method.as_ref(), path.as_str()) {
                (_, "/cdn-cgi/trace") => {
                    let body = build_trace_body(&config);
                    build_response(status, body, &config.extra_headers, true)
                }
                (m, p) if p.contains("/speedtest") || (m == Method::GET.as_str() && config.speedtest_payload_bytes > 0 && p != "/") => {
                    let payload = vec![0xAAu8; config.speedtest_payload_bytes];
                    build_response(status, payload, &config.extra_headers, true)
                }
                _ => {
                    let body = format!("ok mock host={}", config.host);
                    build_response(status, body, &config.extra_headers, true)
                }
            };
            Ok(result)
        })
    }
}

impl MockCfServer {
    pub async fn start(config: MockCfServerConfig) -> Arc<Self> {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        let req_count = Arc::new(Mutex::new(0usize));
        let handler = make_handler(config.clone(), req_count.clone());
        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_server = cancel.clone();
        let cert_der = if config.https {
            let (cert, key) = gen_cert_chain(&config.host);
            let cert_arc = CertificateDer::from(cert.clone());
            let key_arc = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));
            let mut sc = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_arc], key_arc)
                .unwrap();
            sc.alpn_protocols = vec![b"http/1.1".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(sc));
            let acceptor = Arc::new(acceptor);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel_server.cancelled() => return,
                        accept = listener.accept() => {
                            let (stream, _) = match accept {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            let handler = handler.clone();
                            let acceptor = acceptor.clone();
                            let cancel = cancel_server.clone();
                            tokio::spawn(async move {
                                let tls = match acceptor.accept(stream).await {
                                    Ok(t) => t,
                                    Err(_) => return,
                                };
                                let io = TokioIo::new(tls);
                                let svc = service_fn(handler);
                                tokio::select! {
                                    _ = cancel.cancelled() => {}
                                    r = http1::Builder::new().serve_connection(io, svc) => {
                                        let _ = r;
                                    }
                                }
                            });
                        }
                    }
                }
            });
            let (c, _) = gen_cert_chain(&config.host);
            Some(c)
        } else {
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel_server.cancelled() => return,
                        accept = listener.accept() => {
                            let (stream, _) = match accept {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            let handler = handler.clone();
                            let cancel = cancel_server.clone();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let svc = service_fn(handler);
                                tokio::select! {
                                    _ = cancel.cancelled() => {}
                                    r = http1::Builder::new().serve_connection(io, svc) => {
                                        let _ = r;
                                    }
                                }
                            });
                        }
                    }
                }
            });
            None
        };
        Arc::new(Self {
            addr: bound_addr,
            config,
            req_count,
            cert_der,
            cancel,
        })
    }

    pub fn target(&self) -> Target {
        Target::new(self.addr.ip(), self.addr.port())
    }

    pub fn http_base_url(&self) -> String {
        if self.config.https {
            format!("https://{}", self.addr)
        } else {
            format!("http://{}", self.addr)
        }
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }

    pub fn request_count(&self) -> usize {
        *self.req_count.lock()
    }
}

impl Drop for MockCfServer {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticRanges {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
}

impl StaticRanges {
    pub fn from<I, S>(ranges: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for s in ranges.into_iter() {
            let s: String = s.into();
            if s.contains(':') {
                v6.push(s);
            } else {
                v4.push(s);
            }
        }
        Self { v4, v6 }
    }

    pub fn with_loopback() -> Self {
        Self::from(["127.0.0.1/32", "::1/128"])
    }
}

impl CidrSource for StaticRanges {
    fn contains(&self, ip: IpAddr) -> bool {
        use cfrp_detector::cidr::CloudflareRanges;
        let all: Vec<String> = self.v4.iter().chain(self.v6.iter()).cloned().collect();
        CloudflareRanges::from(all).contains(ip)
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticLocations {
    pub map: HashMap<String, CfLocation>,
}

impl StaticLocations {
    pub fn from<I>(items: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, CfLocation)>,
    {
        let mut map = HashMap::new();
        for (code, loc) in items.into_iter() {
            map.insert(code.to_ascii_uppercase(), loc);
        }
        Self { map }
    }

    pub fn sample() -> Self {
        Self::from([
            (
                "LAX",
                CfLocation {
                    iata: "LAX".into(),
                    lat: 33.9425,
                    lon: -118.4081,
                    city: "Los Angeles".into(),
                    region: "CA".into(),
                    cca2: "US".into(),
                },
            ),
            (
                "NRT",
                CfLocation {
                    iata: "NRT".into(),
                    lat: 35.7647,
                    lon: 140.3864,
                    city: "Tokyo".into(),
                    region: "TYO".into(),
                    cca2: "JP".into(),
                },
            ),
        ])
    }
}

impl LocationSource for StaticLocations {
    fn lookup(&self, colo: &str) -> Option<CfLocation> {
        self.map.get(&colo.to_ascii_uppercase()).cloned()
    }
}

pub fn make_detector_with_mocks(
    ranges: StaticRanges,
    locations: StaticLocations,
    cfg: cfrp_detector::DetectorConfig,
) -> cfrp_detector::Detector {
    use cfrp_detector::cidr::CloudflareRanges;
    use std::sync::Arc;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let v: Vec<String> = ranges.v4.iter().chain(ranges.v6.iter()).cloned().collect();
    let cr = CloudflareRanges::from(v);
    let loc: Arc<dyn LocationSource> = Arc::new(locations);
    cfrp_detector::Detector::with_data_sources(cfg, client, cr, loc)
}