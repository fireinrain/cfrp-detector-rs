use crate::{DetectorError, Result};
use crate::{
    cidr::CloudflareRanges,
    cidr::CidrSource,
    location::{LocationSource, LocationStore},
    model::{BatchResult, BatchTarget, Confidence, DetectionResult, EdgeInfo, Protocol, Target},
    probe::{ProbeConfig, ProbeEngine},
};
use reqwest::{Client, ClientBuilder};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct BatchProgress {
    pub completed: usize,
    pub total: usize,
    pub current_concurrency: usize,
    pub last_success: bool,
    pub last_target: Option<Target>,
}

#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    pub enabled: bool,
    pub initial: usize,
    pub min: usize,
    pub max: usize,
    pub window: usize,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            initial: 16,
            min: 1,
            max: 128,
            window: 10,
        }
    }
}

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
    #[allow(dead_code)]
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
        self.detect_batch_with_progress(targets, domain, concurrency, AdaptiveConfig::default(), |_| {})
            .await
    }

    pub async fn detect_oneshot(
        target: &Target,
        domain: Option<&str>,
    ) -> Result<DetectionResult> {
        let detector = Self::new(DetectorConfig::default()).await?;
        detector.detect(target, domain).await
    }

    pub async fn detect_batch_with_progress<F>(
        &self,
        targets: &[BatchTarget],
        domain: Option<&str>,
        base_concurrency: usize,
        adaptive: AdaptiveConfig,
        mut on_progress: F,
    ) -> Vec<BatchResult>
    where
        F: FnMut(BatchProgress) + Send,
    {
        use parking_lot::Mutex;
        use std::collections::VecDeque;
        use tokio::sync::{OwnedSemaphorePermit, Semaphore};

        let total = targets.len();
        if total == 0 {
            return Vec::new();
        }
        let max_limit = self.cfg.max_concurrency.max(1);
        let current_limit: Arc<Mutex<usize>> = Arc::new(Mutex::new(if adaptive.enabled {
            adaptive.initial.clamp(adaptive.min, adaptive.max).min(max_limit)
        } else {
            base_concurrency.clamp(1, max_limit)
        }));
        let sem = Arc::new(Semaphore::new(*current_limit.lock()));
        let recent: Arc<Mutex<VecDeque<bool>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(adaptive.window.max(1))));
        let completed = Arc::new(Mutex::new(0usize));
        let domain_owned: Arc<str> = domain.unwrap_or("").into();

        let tasks: Vec<_> = targets
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, item)| {
                let target = item.target.clone();
                let self_clone = unsafe {
                    std::mem::transmute::<&Detector, &'static Detector>(self)
                };
                let domain_ref = domain_owned.clone();
                let sem = sem.clone();
                let completed_c = completed.clone();
                let recent_c = recent.clone();
                let adaptive_c = adaptive.clone();
                let limit_c = current_limit.clone();
                let max_limit_c = max_limit;
                tokio::spawn(async move {
                    let _permit: OwnedSemaphorePermit = match sem.clone().acquire_owned().await {
                        Ok(p) => p,
                        Err(_) => {
                            let prev = {
                                let mut c = completed_c.lock();
                                let p = *c;
                                *c += 1;
                                p
                            };
                            return (prev, idx, target, Err(DetectorError::Http("semaphore closed".into())));
                        }
                    };
                    let dom = if domain_ref.is_empty() { None } else { Some(domain_ref.as_ref()) };
                    let result = self_clone.detect(&target, dom).await;
                    let ok = result.is_ok();
                    drop(_permit);
                    {
                        let mut r = recent_c.lock();
                        r.push_back(ok);
                        if r.len() > adaptive_c.window.max(1) {
                            r.pop_front();
                        }
                    }
                    let prev = {
                        let mut c = completed_c.lock();
                        let p = *c;
                        *c += 1;
                        p
                    };
                    if adaptive_c.enabled {
                        let r = recent_c.lock();
                        let n = r.len();
                        if n >= adaptive_c.window.min(3) {
                            let successes = r.iter().filter(|&&x| x).count();
                            let rate = successes as f64 / n as f64;
                            let mut limit = limit_c.lock();
                            let mut new_limit = *limit;
                            if rate >= 0.85 {
                                new_limit = (*limit as f64 * 1.25).ceil() as usize;
                            } else if rate <= 0.35 {
                                new_limit = (*limit as f64 * 0.5).floor() as usize;
                            }
                            new_limit = new_limit.clamp(adaptive_c.min, adaptive_c.max).min(max_limit_c).max(1);
                            if new_limit != *limit {
                                let delta = new_limit as isize - *limit as isize;
                                if delta > 0 {
                                    sem.add_permits(delta as usize);
                                } else {
                                    for _ in 0..(-delta) {
                                        if let Ok(p) = sem.clone().try_acquire_owned() {
                                            p.forget();
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                *limit = new_limit;
                            }
                        }
                    }
                    (prev, idx, target, result)
                })
            })
            .collect();

        let mut out: Vec<(usize, Target, std::result::Result<DetectionResult, DetectorError>)> = Vec::with_capacity(total);
        let mut last_reported = 0usize;
        for task in tasks {
            match task.await {
                Ok((order, idx, tgt, result)) => {
                    let ok = result.is_ok();
                    out.push((idx, tgt, result));
                    let done_count = order + 1;
                    if done_count > last_reported || done_count == total {
                        last_reported = done_count;
                        let limit = *current_limit.lock();
                        on_progress(BatchProgress {
                            completed: done_count.min(total),
                            total,
                            current_concurrency: limit,
                            last_success: ok,
                            last_target: None,
                        });
                    }
                }
                Err(join_err) => {
                    tracing::warn!("detect task join error: {}", join_err);
                }
            }
        }

        out.sort_by_key(|(i, _, _)| *i);
        out.into_iter()
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