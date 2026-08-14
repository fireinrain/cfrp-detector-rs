use crate::{
    connector::{HandshakeType, PinnedConnector, PinnedHttpResponse},
    Result,
    model::{Protocol, Target},
};
use http::{HeaderMap, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub user_agent: String,
    pub default_sni: String,
    pub tls_session_cache: bool,
    pub tls_session_cache_size: usize,
    pub allow_0rtt_speedtest: bool,
    pub accept_invalid_certs: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(3),
            user_agent: "Mozilla/5.0 (compatible; CFRP-Detector/3.0)".into(),
            default_sni: "www.cloudflare.com".into(),
            tls_session_cache: true,
            tls_session_cache_size: 256,
            allow_0rtt_speedtest: false,
            accept_invalid_certs: true,
        }
    }
}

impl ProbeConfig {
    pub fn build_client(
        &self,
        resolve: Option<(&str, SocketAddr)>,
    ) -> std::result::Result<reqwest::Client, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(self.accept_invalid_certs)
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .redirect(reqwest::redirect::Policy::none());
        if self.accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some((host, addr)) = resolve {
            builder = builder.resolve(host, addr);
        }
        builder.build()
    }

    pub fn to_pinned(&self) -> crate::connector::PinnedClientConfig {
        crate::connector::PinnedClientConfig {
            connect_timeout: self.connect_timeout,
            request_timeout: self.request_timeout,
            accept_invalid_certs: self.accept_invalid_certs,
            user_agent: self.user_agent.clone(),
            tls_session_cache: self.tls_session_cache,
            tls_session_cache_size: self.tls_session_cache_size,
            tls_session_cache_max_entries: self.tls_session_cache_size,
            enable_0rtt: self.allow_0rtt_speedtest,
            retry: Default::default(),
        }
    }

    pub fn build_pinned_connector(&self) -> Result<Arc<PinnedConnector>> {
        let pc = PinnedConnector::new(self.to_pinned())?;
        Ok(Arc::new(pc))
    }
}

#[derive(Debug, Clone)]
pub struct TlsProbe {
    pub working_sni: String,
    pub cloudflare_trait: bool,
    #[allow(dead_code)]
    pub reason: Option<String>,
    pub handshake_type: HandshakeType,
    pub connect_latency: Option<Duration>,
    pub tls_handshake_latency: Option<Duration>,
    pub ttfb_latency: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct HttpProbe {
    pub status: Option<StatusCode>,
    pub cloudflare_trait: bool,
    pub reasons: Vec<String>,
}

pub struct ProbeEngine {
    cfg: ProbeConfig,
    connector: Arc<PinnedConnector>,
}

impl ProbeEngine {
    pub fn new(cfg: ProbeConfig) -> Self {
        let connector = cfg.build_pinned_connector().unwrap_or_else(|_| {
            Arc::new(PinnedConnector::new(cfg.to_pinned()).expect("fallback pinned connector build"))
        });
        Self { cfg, connector }
    }

    pub fn connector(&self) -> &Arc<PinnedConnector> {
        &self.connector
    }

    pub async fn tls_probe(
        &self,
        target: &Target,
        domain: Option<&str>,
    ) -> Result<Option<TlsProbe>> {
        let candidates = unique_snis(domain, &self.cfg.default_sni);
        let addr = SocketAddr::new(target.ip, target.port);
        for sni in candidates {
            let host = if sni.is_empty() {
                self.cfg.default_sni.as_str()
            } else {
                sni.as_str()
            };
            let resp = self.connector.https_get(
                addr,
                host,
                host,
                "/cdn-cgi/trace",
                None,
            ).await;
            match resp {
                Ok(r) if r.status.is_success() || r.status.is_redirection() => {
                    let mut trait_found = false;
                    let server = r
                        .headers
                        .get("server")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default();
                    if server.to_ascii_lowercase().contains("cloudflare") {
                        trait_found = true;
                    }
                    return Ok(Some(TlsProbe {
                        working_sni: sni,
                        cloudflare_trait: trait_found,
                        reason: Some("HTTPS endpoint responded".into()),
                        handshake_type: r.handshake_type,
                        connect_latency: r.timing.connect_latency,
                        tls_handshake_latency: r.timing.tls_handshake_latency,
                        ttfb_latency: r.timing.ttfb_latency,
                    }));
                }
                _ => continue,
            }
        }
        Ok(None)
    }

    pub async fn http_probe(
        &self,
        target: &Target,
        protocol: Protocol,
        host: &str,
    ) -> Result<HttpProbe> {
        let addr = SocketAddr::new(target.ip, target.port);
        let resp: PinnedHttpResponse = match protocol {
            Protocol::Https => {
                self.connector.https_get(addr, host, host, "/", None).await?
            }
            Protocol::Http => {
                self.connector.http_get(addr, host, "/", None).await?
            }
        };
        Ok(analyze_headers(resp.status, &resp.headers))
    }
}

fn unique_snis(domain: Option<&str>, default: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(3);
    if let Some(d) = domain.filter(|d| !d.is_empty()) {
        out.push(d.to_string());
    }
    if !out.iter().any(|x| x == default) {
        out.push(default.to_string());
    }
    out.push(String::new());
    out
}

fn analyze_headers(status: StatusCode, headers: &HeaderMap) -> HttpProbe {
    let mut reasons = Vec::new();
    let mut trait_found = false;
    if let Some(server) = headers.get("server").and_then(|x| x.to_str().ok()) {
        if server.to_ascii_lowercase().contains("cloudflare") {
            reasons.push("HTTP Server header contains 'cloudflare'".into());
            trait_found = true;
        }
    }
    if headers.contains_key("cf-ray") {
        reasons.push("HTTP response has CF-RAY header".into());
        trait_found = true;
    }
    HttpProbe {
        status: Some(status),
        cloudflare_trait: trait_found,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::time::Duration;

    #[test]
    fn probe_config_default_values() {
        let cfg = ProbeConfig::default();
        assert_eq!(cfg.connect_timeout, Duration::from_secs(2));
        assert_eq!(cfg.request_timeout, Duration::from_secs(3));
        assert!(cfg.user_agent.contains("CFRP-Detector"));
        assert!(!cfg.default_sni.is_empty());
    }

    #[test]
    fn probe_config_clone() {
        let cfg = ProbeConfig::default();
        let cfg2 = cfg.clone();
        assert_eq!(cfg.connect_timeout, cfg2.connect_timeout);
        assert_eq!(cfg.user_agent, cfg2.user_agent);
    }

    #[test]
    fn analyze_headers_no_cloudflare_traits() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx"));
        let probe = analyze_headers(StatusCode::OK, &headers);
        assert!(!probe.cloudflare_trait);
        assert!(probe.reasons.is_empty());
        assert_eq!(probe.status, Some(StatusCode::OK));
    }

    #[test]
    fn analyze_headers_server_cloudflare() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "server",
            HeaderValue::from_static("cloudflare"),
        );
        let probe = analyze_headers(StatusCode::OK, &headers);
        assert!(probe.cloudflare_trait);
        assert!(probe
            .reasons
            .iter()
            .any(|r| r.contains("Server header contains 'cloudflare'")));
    }

    #[test]
    fn analyze_headers_server_cloudflare_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("CloudFlare"));
        let probe = analyze_headers(StatusCode::OK, &headers);
        assert!(probe.cloudflare_trait);
    }

    #[test]
    fn analyze_headers_cf_ray_header() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-ray", HeaderValue::from_static("abc123-LAX"));
        let probe = analyze_headers(StatusCode::FORBIDDEN, &headers);
        assert!(probe.cloudflare_trait);
        assert!(probe
            .reasons
            .iter()
            .any(|r| r.contains("CF-RAY header")));
        assert_eq!(probe.status, Some(StatusCode::FORBIDDEN));
    }

    #[test]
    fn analyze_headers_both_traits_collects_both_reasons() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("cloudflare"));
        headers.insert("cf-ray", HeaderValue::from_static("xyz-LHR"));
        let probe = analyze_headers(StatusCode::MOVED_PERMANENTLY, &headers);
        assert!(probe.cloudflare_trait);
        assert_eq!(probe.reasons.len(), 2);
    }

    #[test]
    fn unique_snis_with_custom_domain() {
        let snis = unique_snis(Some("example.com"), "www.cloudflare.com");
        assert_eq!(snis.len(), 3);
        assert_eq!(snis[0], "example.com");
        assert_eq!(snis[1], "www.cloudflare.com");
        assert_eq!(snis[2], "");
    }

    #[test]
    fn unique_snis_no_domain() {
        let snis = unique_snis(None, "www.cloudflare.com");
        assert_eq!(snis.len(), 2);
        assert_eq!(snis[0], "www.cloudflare.com");
        assert_eq!(snis[1], "");
    }

    #[test]
    fn unique_snis_empty_domain_treated_as_none() {
        let snis = unique_snis(Some(""), "www.cloudflare.com");
        assert_eq!(snis.len(), 2);
        assert_eq!(snis[0], "www.cloudflare.com");
        assert_eq!(snis[1], "");
    }

    #[test]
    fn unique_snis_dedupes_when_custom_matches_default() {
        let snis = unique_snis(Some("www.cloudflare.com"), "www.cloudflare.com");
        assert_eq!(snis.len(), 2);
        assert_eq!(snis[0], "www.cloudflare.com");
        assert_eq!(snis[1], "");
    }

    #[test]
    fn probe_engine_new_constructs() {
        let cfg = ProbeConfig::default();
        let engine = ProbeEngine::new(cfg.clone());
        assert_eq!(engine.cfg.connect_timeout, cfg.connect_timeout);
    }

    #[test]
    fn tls_probe_struct_fields() {
        let probe = TlsProbe {
            working_sni: "test.com".into(),
            cloudflare_trait: true,
            reason: Some("ok".into()),
            handshake_type: HandshakeType::FullHandshake,
            connect_latency: None,
            tls_handshake_latency: None,
            ttfb_latency: None,
        };
        assert_eq!(probe.working_sni, "test.com");
        assert!(probe.cloudflare_trait);
        assert!(probe.reason.is_some());
    }

    #[test]
    fn http_probe_struct_fields() {
        let probe = HttpProbe {
            status: Some(StatusCode::OK),
            cloudflare_trait: false,
            reasons: vec!["none".into()],
        };
        assert_eq!(probe.status, Some(StatusCode::OK));
        assert!(!probe.cloudflare_trait);
        assert_eq!(probe.reasons.len(), 1);
    }
}