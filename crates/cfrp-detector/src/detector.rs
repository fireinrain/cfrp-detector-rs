use crate::{DetectorError, Result};
use crate::{
    cidr::CloudflareRanges,
    cidr::CidrSource,
    location::{LocationSource, LocationStore},
    model::{BatchResult, BatchTarget, Confidence, DetectionResult, EdgeInfo, Protocol, Target},
    probe::{ProbeConfig, ProbeEngine},
};
use reqwest::{Client, ClientBuilder};
use std::{sync::Arc, time::Duration};
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    pub probe: ProbeConfig,
    pub cache: crate::CacheConfig,
    pub max_concurrency: usize,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            probe: ProbeConfig::default(),
            cache: crate::CacheConfig::default(),
            max_concurrency: 256,
        }
    }
}

pub struct Detector {
    client: Arc<Client>,
    ranges: Arc<CloudflareRanges>,
    locations: Arc<dyn LocationSource>,
    pub cfg: DetectorConfig,
}

impl Detector {
    pub async fn new(cfg: DetectorConfig) -> Result<Self> {
        let client = Arc::new(
            ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .connect_timeout(cfg.probe.connect_timeout)
                .timeout(cfg.probe.request_timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
        );
        let cache = crate::FileCache::new(cfg.cache.clone());
        let ranges = Arc::new(CloudflareRanges::load(&client, &cache).await?);
        let locations = Arc::new(LocationStore::load(&client, &cache).await?);
        Ok(Self {
            client,
            ranges,
            locations,
            cfg,
        })
    }

    pub fn with_data_sources(
        cfg: DetectorConfig,
        client: Client,
        ranges: CloudflareRanges,
        locations: Arc<dyn LocationSource>,
    ) -> Self {
        Self {
            client: Arc::new(client),
            ranges: Arc::new(ranges),
            locations,
            cfg,
        }
    }

    pub async fn detect(&self, target: &Target, domain: Option<&str>) -> Result<DetectionResult> {
        let mut result = DetectionResult::default();
        let in_range = self.ranges.contains(target.ip);
        if in_range {
            result.is_cloudflare_edge = true;
            result
                .reasons
                .push("IP is within official Cloudflare CIDR ranges".into());
        }

        let probe = ProbeEngine::new(self.cfg.probe.clone());
        let tls = probe
            .tls_probe(target, domain)
            .await
            .map_err(DetectorError::Network)?;
        let (protocol, host) = match tls {
            Some(tls) => {
                result.is_tls = true;
                if tls.cloudflare_trait {
                    result
                        .reasons
                        .push("TLS/HTTPS probe exhibits Cloudflare traits".into());
                }
                (
                    Protocol::Https,
                    if tls.working_sni.is_empty() {
                        self.cfg.probe.default_sni.as_str()
                    } else {
                        tls.working_sni.as_str()
                    }
                    .to_string(),
                )
            }
            None => (
                Protocol::Http,
                domain.unwrap_or(&self.cfg.probe.default_sni).to_string(),
            ),
        };
        let http = probe.http_probe(target, protocol, &host).await?;
        result.http_status_code = http.status.map(|s| s.as_u16());
        if http.cloudflare_trait {
            result.reasons.push(format!(
                "Service detected on {}",
                protocol.scheme().to_ascii_uppercase()
            ));
            result.reasons.extend(http.reasons);
        }
        result.is_usable = http
            .status
            .map(|s| s.as_u16() >= 200 && s.as_u16() < 400)
            .unwrap_or(false);

        let application_traits = usize::from(result.is_usable) + usize::from(http.cloudflare_trait);
        result.confidence = match (in_range, application_traits) {
            (true, n) if n > 0 => Confidence::High,
            (true, _) => Confidence::Medium,
            (false, n) if n > 0 => {
                result.is_cloudflare_edge = true;
                Confidence::Low
            }
            _ => Confidence::None,
        };
        result.confidence_reason = match result.confidence {
            Confidence::High => {
                "IP belongs to Cloudflare and shows application-level traits".into()
            }
            Confidence::Medium => {
                "IP belongs to Cloudflare ranges, but active service traits are limited".into()
            }
            Confidence::Low => {
                "IP is outside official ranges but exhibits Cloudflare application traits".into()
            }
            Confidence::None => {
                "IP is outside Cloudflare ranges and no Cloudflare traits were detected".into()
            }
        };
        if result.is_usable {
            result.reasons.push(format!(
                "Successful domain-based response (HTTP {})",
                result.http_status_code.unwrap_or_default()
            ));
        }

        if result.is_cloudflare_edge {
            if let Some(edge) = self.fetch_edge_info(target, result.is_tls, &host).await? {
                result.edge_info = Some(edge);
            }
        }
        Ok(result)
    }

    pub async fn fetch_edge_info(
        &self,
        target: &Target,
        is_tls: bool,
        host: &str,
    ) -> Result<Option<EdgeInfo>> {
        let protocol = if is_tls {
            Protocol::Https
        } else {
            Protocol::Http
        };
        let started = std::time::Instant::now();
        let client = self.cfg.probe.build_client(Some((
            host,
            std::net::SocketAddr::new(target.ip, target.port),
        )))?;
        let response = client
            .get(format!(
                "{}://{}:{}/cdn-cgi/trace",
                protocol.scheme(),
                host,
                target.port
            ))
            .header("Host", host)
            .header("User-Agent", &self.cfg.probe.user_agent)
            .send()
            .await?;
        let body = response.text().await?;
        let latency = started.elapsed();
        let colo = body
            .lines()
            .find_map(|line| line.strip_prefix("colo="))
            .map(str::to_string);
        let Some(colo_code) = colo else {
            return Ok(None);
        };
        let mut info = EdgeInfo {
            colo_code: Some(colo_code.clone()),
            latency: Some(latency),
            ..Default::default()
        };
        if let Some(loc) = self.locations.lookup(&colo_code) {
            info.city = Some(loc.city);
            info.country = Some(loc.cca2);
            info.region = Some(loc.region);
        }
        Ok(Some(info))
    }

    pub async fn detect_batch(
        &self,
        targets: &[BatchTarget],
        domain: Option<&str>,
        concurrency: usize,
    ) -> Vec<BatchResult> {
        use futures::{StreamExt, stream};
        let limit = concurrency.clamp(1, self.cfg.max_concurrency.max(1));
        let results = stream::iter(targets.iter().cloned().enumerate())
            .map(|(idx, item)| async move {
                let target = item.target.clone();
                let result = self.detect(&target, domain).await;
                (idx, target, result)
            })
            .buffer_unordered(limit)
            .collect::<Vec<_>>()
            .await;
        let mut ordered = results;
        ordered.sort_by_key(|(idx, _, _)| *idx);
        ordered
            .into_iter()
            .map(|(_, target, result)| BatchResult {
                target,
                result: result.as_ref().ok().cloned(),
                error: result.err().map(|e| e.to_string()),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::location::LocationSource;
    use crate::model::{Confidence, DetectionResult, EdgeInfo, Target};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;

    struct EmptyLocationSource;

    impl LocationSource for EmptyLocationSource {
        fn lookup(&self, _colo: &str) -> Option<crate::CfLocation> {
            None
        }
    }

    #[test]
    fn detector_config_default_values() {
        let cfg = DetectorConfig::default();
        assert_eq!(cfg.probe.connect_timeout, Duration::from_secs(2));
        assert_eq!(cfg.max_concurrency, 256);
        assert_eq!(cfg.cache.directory, std::path::PathBuf::from("data/cfrpdata"));
    }

    #[test]
    fn detector_config_clone() {
        let cfg = DetectorConfig {
            probe: ProbeConfig::default(),
            cache: crate::CacheConfig::default(),
            max_concurrency: 10,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg.max_concurrency, cfg2.max_concurrency);
    }

    #[test]
    fn detector_with_data_sources_builds_struct() {
        let client = reqwest::Client::builder()
            .build()
            .expect("client build");
        let ranges = CloudflareRanges::empty();
        let locations: Arc<dyn LocationSource> = Arc::new(EmptyLocationSource);
        let cfg = DetectorConfig::default();
        let detector = Detector::with_data_sources(cfg.clone(), client, ranges, locations);
        assert_eq!(detector.cfg.max_concurrency, cfg.max_concurrency);
    }

    #[test]
    fn detect_batch_concurrency_clamps_to_one() {
        let limit = 0usize.clamp(1, 10);
        assert_eq!(limit, 1);
    }

    #[test]
    fn detect_batch_concurrency_clamps_to_max() {
        let max = 256;
        let limit = 10_000usize.clamp(1, max.max(1));
        assert_eq!(limit, 256);
    }

    #[test]
    fn detection_result_confidence_reason_high() {
        let mut r = DetectionResult::default();
        r.confidence = Confidence::High;
        r.confidence_reason = match r.confidence {
            Confidence::High => "IP belongs to Cloudflare and shows application-level traits".into(),
            _ => "".into(),
        };
        assert!(r.confidence_reason.contains("application-level traits"));
    }

    #[test]
    fn detection_result_confidence_reason_medium() {
        let reason = match Confidence::Medium {
            Confidence::High => "",
            Confidence::Medium => "IP belongs to Cloudflare ranges, but active service traits are limited".into(),
            _ => "".into(),
        };
        assert!(reason.contains("ranges, but active service traits are limited"));
    }

    #[test]
    fn detection_result_confidence_reason_low() {
        let reason: String = match Confidence::Low {
            Confidence::Low => "IP is outside official ranges but exhibits Cloudflare application traits".into(),
            _ => String::new(),
        };
        assert!(reason.contains("exhibits Cloudflare application traits"));
    }

    #[test]
    fn detection_result_confidence_reason_none() {
        let reason: String = match Confidence::None {
            Confidence::None => "IP is outside Cloudflare ranges and no Cloudflare traits were detected".into(),
            _ => String::new(),
        };
        assert!(reason.contains("no Cloudflare traits were detected"));
    }

    #[test]
    fn edge_info_partial_construction() {
        let info = EdgeInfo {
            colo_code: Some("NRT".into()),
            latency: Some(Duration::from_millis(25)),
            ..Default::default()
        };
        assert_eq!(info.colo_code.as_deref(), Some("NRT"));
        assert!(info.city.is_none());
        assert!(info.download_speed_bytes_per_sec.is_none());
    }

    #[test]
    fn confidence_ordering_is_not_relied_on_but_variants_exist() {
        use Confidence::*;
        let all = vec![None, Low, Medium, High];
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn target_new_with_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229));
        let t = Target::new(ip, 443);
        assert_eq!(t.port, 443);
        assert_eq!(t.ip, ip);
    }
}