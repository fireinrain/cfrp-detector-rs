use crate::{
    DetectorError, Result,
    model::{Protocol, Target},
};
use reqwest::{StatusCode, header::HeaderMap};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub user_agent: String,
    pub default_sni: String,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(3),
            user_agent: "Mozilla/5.0 (compatible; CFRP-Detector/3.0)".into(),
            default_sni: "www.cloudflare.com".into(),
        }
    }
}

impl ProbeConfig {
    pub fn build_client(
        &self,
        resolve: Option<(&str, SocketAddr)>,
    ) -> std::result::Result<reqwest::Client, reqwest::Error> {
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .redirect(reqwest::redirect::Policy::none());
        if let Some((host, addr)) = resolve {
            builder = builder.resolve(host, addr);
        }
        builder.build()
    }
}

#[derive(Debug, Clone)]
pub struct TlsProbe {
    pub working_sni: String,
    pub cloudflare_trait: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpProbe {
    pub status: Option<StatusCode>,
    pub cloudflare_trait: bool,
    pub reasons: Vec<String>,
}

pub struct ProbeEngine {
    cfg: ProbeConfig,
}

impl ProbeEngine {
    pub fn new(cfg: ProbeConfig) -> Self {
        Self { cfg }
    }

    pub async fn tls_probe(
        &self,
        target: &Target,
        domain: Option<&str>,
    ) -> std::result::Result<Option<TlsProbe>, reqwest::Error> {
        let candidates = unique_snis(domain, &self.cfg.default_sni);
        for sni in candidates {
            let host = if sni.is_empty() {
                self.cfg.default_sni.as_str()
            } else {
                sni.as_str()
            };
            let client = self.cfg.build_client(Some((
                host,
                SocketAddr::new(target.ip, target.port),
            )))?;
            let url = format!("https://{}:{}/cdn-cgi/trace", host, target.port);
            let response = timeout(
                self.cfg.request_timeout,
                client
                    .get(&url)
                    .header("Host", host)
                    .header("User-Agent", &self.cfg.user_agent)
                    .send(),
            )
            .await;
            match response {
                Ok(Ok(resp)) if resp.status().is_success() || resp.status().is_redirection() => {
                    let mut trait_found = false;
                    let server = resp
                        .headers()
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
        let client = self.cfg.build_client(Some((
            host,
            SocketAddr::new(target.ip, target.port),
        )))?;
        let url = format!("{}://{}:{}/", protocol.scheme(), host, target.port);
        let req = client
            .get(url)
            .header("Host", host)
            .header("User-Agent", &self.cfg.user_agent);
        let resp = timeout(self.cfg.request_timeout, req.send())
            .await
            .map_err(|_| DetectorError::Http("probe request timed out".into()))??;
        let headers = resp.headers();
        Ok(analyze_headers(resp.status(), headers))
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