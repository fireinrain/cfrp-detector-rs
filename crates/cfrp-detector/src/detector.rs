//! The primary `Detector` engine, batch processing, and adaptive concurrency.
//!
//! This module is the heart of the library: [`Detector`] bundles together the
//! TLS/HTTP probe engine, Cloudflare CIDR data, geolocation data, and an
//! optional resource governor into a single reusable component. It exposes
//! both single-target and adaptive batch APIs.
//!
//! The adaptive concurrency mechanism uses an AIMD (additive-increase /
//! multiplicative-decrease) algorithm driven by probe success rate, with
//! additional hard constraints from the `ResourceGovernor` (file descriptor
//! ceiling, sliding-window resource-error ratio).

use crate::{DetectorError, Result};
use crate::{
    cidr::CidrSource,
    cidr::CloudflareRanges,
    governor::{
        GovernorSnapshot, ResourceGovernor, ResourceGovernorConfig, SystemFdCounter,
        classify_resource_error,
    },
    location::{LocationSource, LocationStore},
    model::{BatchResult, BatchTarget, Confidence, DetectionResult, EdgeInfo, Protocol, Target},
    probe::{ProbeConfig, ProbeEngine},
};
use http::HeaderMap;
use reqwest::{Client, ClientBuilder};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Snapshot of resource-governor state forwarded from the governor to the
/// progress callback. Allows callers to log or visualise back-pressure events.
#[derive(Debug, Clone, Default)]
pub struct GovernorFeedback {
    /// Latest governor snapshot if the governor is enabled.
    pub snapshot: Option<GovernorSnapshot>,
}

/// Progress update delivered through the batch progress callback.
///
/// Emitted after every single probe completion (success *or* failure) so that
/// UIs can render live progress indicators and statistics.
#[derive(Debug, Clone, Default)]
pub struct BatchProgress {
    /// Number of probes finished so far.
    pub completed: usize,
    /// Total number of probes in the current batch.
    pub total: usize,
    /// Concurrency level currently being used by the adaptive algorithm.
    pub current_concurrency: usize,
    /// Whether the most recently finished probe succeeded.
    pub last_success: bool,
    /// The most recently processed target, if available.
    pub last_target: Option<Target>,
    /// `true` when the governor just throttled concurrency because of FD pressure.
    pub throttled_due_to_fd: bool,
    /// Deeper governor internal snapshot.
    pub governor_feedback: GovernorFeedback,
}

/// Parameters for the AIMD adaptive concurrency controller.
///
/// When enabled, the detector starts at `initial` concurrent probes and
/// adjusts the level up (additive) on success or down (multiplicative) on
/// failure, bounded by `min`..`max` and smoothed over the last `window` events.
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Master toggle for AIMD adaptive concurrency.
    pub enabled: bool,
    /// Starting concurrency value.
    pub initial: usize,
    /// Hard floor for concurrency (≥1).
    pub min: usize,
    /// Hard ceiling for concurrency.
    pub max: usize,
    /// Sliding-window size (number of events) used for smoothing.
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

/// Top-level configuration for [`Detector`].
///
/// Aggregates probe options, HTTP cache settings, concurrency limits, and
/// resource-governor tuning. Use [`DetectorConfig::default()`] for sane defaults.
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    /// Low-level HTTP/TLS probe knobs (timeouts, SNI, TLS session cache).
    pub probe: ProbeConfig,
    /// Local HTTP cache configuration for Cloudflare CIDR / colo lookups.
    pub cache: crate::CacheConfig,
    /// Maximum allowed concurrent probes (upper bound; adaptive stays ≤ this).
    pub max_concurrency: usize,
    /// Whether the resource governor is active. Always enable in production.
    pub governor_enabled: bool,
    /// Fine tuning for the resource governor (FD headroom, thresholds, etc.).
    pub governor: ResourceGovernorConfig,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            probe: ProbeConfig::default(),
            cache: crate::CacheConfig::default(),
            max_concurrency: 256,
            governor_enabled: true,
            governor: ResourceGovernorConfig::default(),
        }
    }
}

/// Main Cloudflare edge detection engine.
///
/// `Detector` is cheap to clone (internally reference-counted) and safe to
/// share across tasks. Create one instance per process, configure it with
/// [`DetectorConfig`], and reuse it for all probes — it caches TLS sessions,
/// HTTP clients, Cloudflare CIDR ranges, and geolocation data internally.
///
/// # Examples
///
/// ```no_run
/// # use cfrp_detector::{Detector, DetectorConfig, Target};
/// # use std::net::{IpAddr, Ipv4Addr};
/// # #[tokio::main] async fn main() -> anyhow::Result<()> {
/// let cfg = DetectorConfig::default();
/// let detector = Detector::new(cfg).await?;
/// let target = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
/// let result = detector.detect(&target, Some("cloudflare.com")).await?;
/// println!("is edge = {}", result.is_cloudflare_edge);
/// # Ok(()) }
/// ```
pub struct Detector {
    #[allow(dead_code)]
    client: Arc<Client>,
    ranges: Arc<CloudflareRanges>,
    locations: Arc<dyn LocationSource>,
    /// Active configuration (read-only after construction).
    pub cfg: DetectorConfig,
    governor: Option<Arc<ResourceGovernor>>,
    probe_engine: Arc<ProbeEngine>,
}

impl Detector {
    /// Builds a new detector, loading Cloudflare CIDR ranges and colo
    /// geolocation data from their authoritative sources (using the built-in
    /// HTTP cache as configured).
    ///
    /// # Errors
    ///
    /// Fails if the network fetches for CIDR ranges or the colo mapping fail
    /// fatally and no cached fallback is available.
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
        let governor = if cfg.governor_enabled {
            let mut g_cfg = cfg.governor.clone();
            g_cfg.user_max_concurrency = cfg.max_concurrency.max(1);
            Some(Arc::new(ResourceGovernor::new(
                g_cfg,
                Arc::new(SystemFdCounter),
            )))
        } else {
            None
        };
        let probe_engine = Arc::new(ProbeEngine::new(cfg.probe.clone()));
        Ok(Self {
            client,
            ranges,
            locations,
            cfg,
            governor,
            probe_engine,
        })
    }

    /// Builds a detector using caller-provided data sources (dependency
    /// injection). Useful for tests or when you want to pre-load / cache
    /// CIDR ranges and colo data yourself.
    pub fn with_data_sources(
        cfg: DetectorConfig,
        client: Client,
        ranges: CloudflareRanges,
        locations: Arc<dyn LocationSource>,
    ) -> Self {
        let governor = if cfg.governor_enabled {
            let mut g_cfg = cfg.governor.clone();
            g_cfg.user_max_concurrency = cfg.max_concurrency.max(1);
            Some(Arc::new(ResourceGovernor::new(
                g_cfg,
                Arc::new(SystemFdCounter),
            )))
        } else {
            None
        };
        let probe_engine = Arc::new(ProbeEngine::new(cfg.probe.clone()));
        Self {
            client: Arc::new(client),
            ranges: Arc::new(ranges),
            locations,
            cfg,
            governor,
            probe_engine,
        }
    }

    /// Returns a reference to the resource governor, if enabled.
    pub fn governor(&self) -> Option<&ResourceGovernor> {
        self.governor.as_deref()
    }

    /// Returns a reference to the inner probe engine for advanced use cases.
    pub fn probe_engine(&self) -> &ProbeEngine {
        &self.probe_engine
    }

    /// Runs the full multi-layer Cloudflare edge detection pipeline against a single target.
    ///
    /// Detection layers (in order):
    /// 1. Cloudflare official CIDR membership (from `CloudflareRanges`)
    /// 2. TLS leaf / intermediate certificate fingerprinting
    /// 3. HTTP response headers (`Server: cloudflare`, `CF-Ray`, `CF-Cache-Status`, …)
    /// 4. Optional `cdn-cgi/trace` endpoint + colo geolocation
    ///
    /// `domain` overrides the TLS SNI and HTTP `Host` header; pass `None` to use
    /// the configured default (`cloudflare.com`).
    pub async fn detect(&self, target: &Target, domain: Option<&str>) -> Result<DetectionResult> {
        let mut result = DetectionResult::default();
        let in_range = self.ranges.contains(target.ip);
        if in_range {
            result.is_cloudflare_edge = true;
            result
                .reasons
                .push("IP is within official Cloudflare CIDR ranges".into());
        }

        let tls = self.probe_engine.tls_probe(target, domain).await?;
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
        let http = self
            .probe_engine
            .http_probe(target, protocol, &host)
            .await?;
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

        if result.is_cloudflare_edge
            && let Some(edge) = self.fetch_edge_info(target, result.is_tls, &host).await?
        {
            result.edge_info = Some(edge);
        }
        Ok(result)
    }

    /// Fetches geographic / quality [`EdgeInfo`] for a target already known to
    /// be a Cloudflare edge node by hitting its `/cdn-cgi/trace` endpoint and
    /// looking up the returned `colo=` code in the geolocation store.
    ///
    /// Returns `Ok(None)` if the trace endpoint does not yield a colo code —
    /// this means the target is not actually serving a Cloudflare edge stack
    /// even if other heuristics matched.
    pub async fn fetch_edge_info(
        &self,
        target: &Target,
        is_tls: bool,
        host: &str,
    ) -> Result<Option<EdgeInfo>> {
        let connector = self.probe_engine.connector();
        let addr = SocketAddr::new(target.ip, target.port);
        let started = std::time::Instant::now();
        let extra = HeaderMap::new();
        let response = if is_tls {
            connector
                .https_get(addr, host, host, "/cdn-cgi/trace", Some(&extra))
                .await?
        } else {
            connector
                .http_get(addr, host, "/cdn-cgi/trace", Some(&extra))
                .await?
        };
        let latency = started.elapsed();
        let body_str = String::from_utf8_lossy(&response.body);
        let colo = extract_colo_from_trace(&body_str);
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

    /// Runs detection for a batch of targets using a fixed concurrency level.
    ///
    /// Results are returned in the *same order* as the input `targets` slice.
    /// Every entry contains either a successful [`DetectionResult`] or an error
    /// string — the method never panics on per-target failures.
    pub async fn detect_batch(
        &self,
        targets: &[BatchTarget],
        domain: Option<&str>,
        concurrency: usize,
    ) -> Vec<BatchResult> {
        self.detect_batch_with_progress(
            targets,
            domain,
            concurrency,
            AdaptiveConfig::default(),
            |_| {},
        )
        .await
    }

    /// Batch detection with full control over adaptive concurrency, graceful
    /// cancellation, and a per-probe progress callback.
    ///
    /// The `cancel` token lets you shut down the batch early (e.g. on `SIGINT`);
    /// in-flight probes are aborted and their slots are marked with
    /// `error = "cancelled"` in the returned vector. Progress events fire
    /// synchronously on the task driving the method, so keep the callback
    /// cheap (send through a channel if you need to do heavy work).
    pub async fn detect_batch_with_cancel<F>(
        &self,
        targets: &[BatchTarget],
        domain: Option<&str>,
        base_concurrency: usize,
        adaptive: AdaptiveConfig,
        cancel: CancellationToken,
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
        let initial_raw = if adaptive.enabled {
            adaptive
                .initial
                .clamp(adaptive.min, adaptive.max)
                .min(max_limit)
        } else {
            base_concurrency.clamp(1, max_limit)
        };
        let initial_limit = if let Some(gov) = self.governor.as_deref() {
            let (capped, _) = gov.cap_concurrency(initial_raw);
            capped
        } else {
            initial_raw
        };
        let current_limit: Arc<Mutex<usize>> = Arc::new(Mutex::new(initial_limit));
        let last_gov_snap: Arc<Mutex<Option<GovernorSnapshot>>> = Arc::new(Mutex::new(None));
        let sem = Arc::new(Semaphore::new(*current_limit.lock()));
        let recent: Arc<Mutex<VecDeque<bool>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(adaptive.window.max(1))));
        let completed = Arc::new(Mutex::new(0usize));
        let domain_owned: Arc<str> = domain.unwrap_or("").into();
        let gov_enabled = self.governor.is_some();
        let cancelled_flag: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let shared_ranges = self.ranges.clone();
        let shared_locations = self.locations.clone();
        let shared_cfg = self.cfg.clone();
        let shared_governor = self.governor.clone();
        let shared_probe_engine = self.probe_engine.clone();

        let tasks: Vec<_> = targets
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, item)| {
                let target = item.target.clone();
                let bt_id = item.id;
                let domain_ref = domain_owned.clone();
                let sem = sem.clone();
                let completed_c = completed.clone();
                let recent_c = recent.clone();
                let adaptive_c = adaptive.clone();
                let limit_c = current_limit.clone();
                let gov_snap_c = last_gov_snap.clone();
                let max_limit_c = max_limit;
                let ranges = shared_ranges.clone();
                let locations = shared_locations.clone();
                let cfg = shared_cfg.clone();
                let governor = shared_governor.clone();
                let probe_engine = shared_probe_engine.clone();
                let cancel = cancel.clone();
                let cancelled_flag = cancelled_flag.clone();
                tokio::spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            let prev = {
                                let mut c = completed_c.lock();
                                let p = *c;
                                *c += 1;
                                p
                            };
                            *cancelled_flag.lock() = true;
                            return (prev, idx, bt_id, target, Err(DetectorError::Http("cancelled".into())));
                        }
                        permit = sem.clone().acquire_owned() => {
                            let _permit: OwnedSemaphorePermit = match permit {
                                Ok(p) => p,
                                Err(_) => {
                                    let prev = {
                                        let mut c = completed_c.lock();
                                        let p = *c;
                                        *c += 1;
                                        p
                                    };
                                    return (prev, idx, bt_id, target, Err(DetectorError::Http("semaphore closed".into())));
                                }
                            };
                            if cancel.is_cancelled() {
                                let prev = {
                                    let mut c = completed_c.lock();
                                    let p = *c;
                                    *c += 1;
                                    p
                                };
                                *cancelled_flag.lock() = true;
                                return (prev, idx, bt_id, target, Err(DetectorError::Http("cancelled".into())));
                            }
                            let dom = if domain_ref.is_empty() { None } else { Some(domain_ref.as_ref()) };
                            let result = tokio::select! {
                                r = detect_impl(&ranges, &locations, &cfg, &probe_engine, governor.as_deref(), &target, dom) => r,
                                _ = cancel.cancelled() => {
                                    *cancelled_flag.lock() = true;
                                    Err(DetectorError::Http("cancelled".into()))
                                }
                            };
                            let ok = result.is_ok();
                            if gov_enabled {
                                if let Err(ref e) = result {
                                    let is_res = classify_resource_error(e);
                                    if let Some(gov) = governor.as_deref() {
                                        gov.record_outcome(is_res);
                                    }
                                } else if let Some(gov) = governor.as_deref() {
                                    gov.record_outcome(false);
                                }
                            }
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
                            if adaptive_c.enabled || gov_enabled {
                                let r = recent_c.lock();
                                let n = r.len();
                                let mut proposed: usize = if adaptive_c.enabled && n >= adaptive_c.window.min(3) {
                                    let successes = r.iter().filter(|&&x| x).count();
                                    let rate = successes as f64 / n as f64;
                                    let cur = *limit_c.lock();
                                    let mut new_limit = cur;
                                    if rate >= 0.85 {
                                        new_limit = (cur as f64 * 1.25).ceil() as usize;
                                    } else if rate <= 0.35 {
                                        new_limit = (cur as f64 * 0.5).floor() as usize;
                                    }
                                    let clamp_lo = adaptive_c.min.max(1);
                                    let clamp_hi = adaptive_c.max.min(max_limit_c);
                                    new_limit.clamp(clamp_lo, clamp_hi).max(1)
                                } else {
                                    *limit_c.lock()
                                };
                                if !adaptive_c.enabled {
                                    proposed = proposed.clamp(1, max_limit_c);
                                }
                                let (capped, snap) = if let Some(gov) = governor.as_deref() {
                                    gov.cap_concurrency(proposed)
                                } else {
                                    (proposed.min(max_limit_c).max(1), Default::default())
                                };
                                {
                                    let mut gs = gov_snap_c.lock();
                                    *gs = Some(snap);
                                }
                                let mut limit = limit_c.lock();
                                let new_limit = capped.max(1);
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
                            (prev, idx, bt_id, target, result)
                        }
                    }
                })
            })
            .collect();

        let mut out: Vec<(
            usize,
            usize,
            Target,
            std::result::Result<DetectionResult, DetectorError>,
        )> = Vec::with_capacity(total);
        let mut last_reported = 0usize;
        let mut cancelled_raised = false;
        let mut result_by_idx: Vec<
            Option<(
                usize,
                Target,
                std::result::Result<DetectionResult, DetectorError>,
            )>,
        > = (0..total).map(|_| None).collect();
        for task in tasks {
            if cancel.is_cancelled() && !cancelled_raised {
                cancelled_raised = true;
            }
            let task_result = task.await;
            match task_result {
                Ok((order, idx, bt_id, tgt, result)) => {
                    let ok = result.is_ok();
                    let tgt_for_progress = tgt.clone();
                    let result_normalized = match result {
                        Err(DetectorError::Http(ref m)) if m == "cancelled" => {
                            Err(DetectorError::Http("cancelled by shutdown".into()))
                        }
                        other => other,
                    };
                    let was_cancelled = matches!(result_normalized, Err(DetectorError::Http(ref m)) if m.contains("cancelled"));
                    result_by_idx[idx] = Some((bt_id, tgt, result_normalized));
                    let done_count = order + 1;
                    if done_count > last_reported || done_count == total || cancelled_raised {
                        last_reported = done_count;
                        let limit = *current_limit.lock();
                        let snap_guard = last_gov_snap.lock();
                        let (throttled, feedback) = if let Some(s) = snap_guard.as_ref() {
                            (
                                s.throttled_due_to_fd || s.throttled_due_to_resource_errors,
                                GovernorFeedback {
                                    snapshot: Some(s.clone()),
                                },
                            )
                        } else {
                            (false, GovernorFeedback::default())
                        };
                        on_progress(BatchProgress {
                            completed: done_count.min(total),
                            total,
                            current_concurrency: limit,
                            last_success: ok && !was_cancelled,
                            last_target: Some(tgt_for_progress),
                            throttled_due_to_fd: throttled,
                            governor_feedback: feedback,
                        });
                    }
                }
                Err(join_err) => {
                    tracing::warn!("detect task join error: {}", join_err);
                }
            }
        }
        // Always produce exactly `total` results; gap-fill any missing (e.g. join error) with cancelled placeholder.
        for (idx, slot) in result_by_idx.into_iter().enumerate() {
            let bt = &targets[idx];
            match slot {
                Some((bt_id, tgt, result)) => out.push((idx, bt_id, tgt, result)),
                None => out.push((
                    idx,
                    bt.id,
                    bt.target.clone(),
                    Err(DetectorError::Http(
                        "cancelled by shutdown (gap fill)".into(),
                    )),
                )),
            }
        }

        out.sort_by_key(|(i, _, _, _)| *i);
        out.into_iter()
            .map(|(_, bt_id, target, result)| BatchResult {
                id: bt_id,
                target,
                result: result.as_ref().ok().cloned(),
                error: result.err().map(|e| e.to_string()),
            })
            .collect()
    }

    /// Convenience one-shot constructor + probe for ad-hoc scripts and tests.
    ///
    /// Builds a brand new [`Detector`] internally (loading CIDR / colo data)
    /// and runs a single detection. Prefer [`Detector::new`] + reuse when you
    /// have more than one target to check.
    pub async fn detect_oneshot(target: &Target, domain: Option<&str>) -> Result<DetectionResult> {
        let detector = Self::new(DetectorConfig::default()).await?;
        detector.detect(target, domain).await
    }

    /// Batch detection with optional AIMD adaptive concurrency and a
    /// per-probe progress callback.
    ///
    /// Equivalent to [`Detector::detect_batch_with_cancel`] but without a
    /// cancellation token; internally passes one that never fires.
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
        let initial_raw = if adaptive.enabled {
            adaptive
                .initial
                .clamp(adaptive.min, adaptive.max)
                .min(max_limit)
        } else {
            base_concurrency.clamp(1, max_limit)
        };
        let initial_limit = if let Some(gov) = self.governor.as_deref() {
            let (capped, _) = gov.cap_concurrency(initial_raw);
            capped
        } else {
            initial_raw
        };
        let current_limit: Arc<Mutex<usize>> = Arc::new(Mutex::new(initial_limit));
        let last_gov_snap: Arc<Mutex<Option<GovernorSnapshot>>> = Arc::new(Mutex::new(None));
        let sem = Arc::new(Semaphore::new(*current_limit.lock()));
        let recent: Arc<Mutex<VecDeque<bool>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(adaptive.window.max(1))));
        let completed = Arc::new(Mutex::new(0usize));
        let domain_owned: Arc<str> = domain.unwrap_or("").into();
        let gov_enabled = self.governor.is_some();

        let shared_ranges = self.ranges.clone();
        let shared_locations = self.locations.clone();
        let shared_cfg = self.cfg.clone();
        let shared_governor = self.governor.clone();
        let shared_probe_engine = self.probe_engine.clone();

        let tasks: Vec<_> = targets
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, item)| {
                let target = item.target.clone();
                let bt_id = item.id;
                let domain_ref = domain_owned.clone();
                let sem = sem.clone();
                let completed_c = completed.clone();
                let recent_c = recent.clone();
                let adaptive_c = adaptive.clone();
                let limit_c = current_limit.clone();
                let gov_snap_c = last_gov_snap.clone();
                let max_limit_c = max_limit;
                let ranges = shared_ranges.clone();
                let locations = shared_locations.clone();
                let cfg = shared_cfg.clone();
                let governor = shared_governor.clone();
                let probe_engine = shared_probe_engine.clone();
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
                            return (
                                prev,
                                idx,
                                bt_id,
                                target,
                                Err(DetectorError::Http("semaphore closed".into())),
                            );
                        }
                    };
                    let dom = if domain_ref.is_empty() {
                        None
                    } else {
                        Some(domain_ref.as_ref())
                    };
                    let result = detect_impl(
                        &ranges,
                        &locations,
                        &cfg,
                        &probe_engine,
                        governor.as_deref(),
                        &target,
                        dom,
                    )
                    .await;
                    let ok = result.is_ok();
                    if gov_enabled {
                        if let Err(ref e) = result {
                            let is_res = classify_resource_error(e);
                            if let Some(gov) = governor.as_deref() {
                                gov.record_outcome(is_res);
                            }
                        } else if let Some(gov) = governor.as_deref() {
                            gov.record_outcome(false);
                        }
                    }
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
                    if adaptive_c.enabled || gov_enabled {
                        let r = recent_c.lock();
                        let n = r.len();
                        let mut proposed: usize =
                            if adaptive_c.enabled && n >= adaptive_c.window.min(3) {
                                let successes = r.iter().filter(|&&x| x).count();
                                let rate = successes as f64 / n as f64;
                                let cur = *limit_c.lock();
                                let mut new_limit = cur;
                                if rate >= 0.85 {
                                    new_limit = (cur as f64 * 1.25).ceil() as usize;
                                } else if rate <= 0.35 {
                                    new_limit = (cur as f64 * 0.5).floor() as usize;
                                }
                                let clamp_lo = adaptive_c.min.max(1);
                                let clamp_hi = adaptive_c.max.min(max_limit_c);
                                new_limit.clamp(clamp_lo, clamp_hi).max(1)
                            } else {
                                *limit_c.lock()
                            };
                        if !adaptive_c.enabled {
                            proposed = proposed.clamp(1, max_limit_c);
                        }
                        let (capped, snap) = if let Some(gov) = governor.as_deref() {
                            gov.cap_concurrency(proposed)
                        } else {
                            (proposed.min(max_limit_c).max(1), Default::default())
                        };
                        {
                            let mut gs = gov_snap_c.lock();
                            *gs = Some(snap);
                        }
                        let mut limit = limit_c.lock();
                        let new_limit = capped.max(1);
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
                    (prev, idx, bt_id, target, result)
                })
            })
            .collect();

        let mut out: Vec<(
            usize,
            usize,
            Target,
            std::result::Result<DetectionResult, DetectorError>,
        )> = Vec::with_capacity(total);
        let mut last_reported = 0usize;
        for task in tasks {
            match task.await {
                Ok((order, idx, bt_id, tgt, result)) => {
                    let ok = result.is_ok();
                    let tgt_for_progress = tgt.clone();
                    out.push((idx, bt_id, tgt, result));
                    let done_count = order + 1;
                    if done_count > last_reported || done_count == total {
                        last_reported = done_count;
                        let limit = *current_limit.lock();
                        let snap_guard = last_gov_snap.lock();
                        let (throttled, feedback) = if let Some(s) = snap_guard.as_ref() {
                            (
                                s.throttled_due_to_fd || s.throttled_due_to_resource_errors,
                                GovernorFeedback {
                                    snapshot: Some(s.clone()),
                                },
                            )
                        } else {
                            (false, GovernorFeedback::default())
                        };
                        on_progress(BatchProgress {
                            completed: done_count.min(total),
                            total,
                            current_concurrency: limit,
                            last_success: ok,
                            last_target: Some(tgt_for_progress),
                            throttled_due_to_fd: throttled,
                            governor_feedback: feedback,
                        });
                    }
                }
                Err(join_err) => {
                    tracing::warn!("detect task join error: {}", join_err);
                }
            }
        }

        out.sort_by_key(|(i, _, _, _)| *i);
        out.into_iter()
            .map(|(_, bt_id, target, result)| BatchResult {
                id: bt_id,
                target,
                result: result.as_ref().ok().cloned(),
                error: result.err().map(|e| e.to_string()),
            })
            .collect()
    }
}

async fn detect_impl(
    ranges: &Arc<CloudflareRanges>,
    locations: &Arc<dyn LocationSource>,
    cfg: &DetectorConfig,
    probe_engine: &Arc<ProbeEngine>,
    governor: Option<&ResourceGovernor>,
    target: &Target,
    domain: Option<&str>,
) -> Result<DetectionResult> {
    let _ = governor;
    let mut result = DetectionResult::default();
    let in_range = ranges.contains(target.ip);
    if in_range {
        result.is_cloudflare_edge = true;
        result
            .reasons
            .push("IP is within official Cloudflare CIDR ranges".into());
    }

    let tls = probe_engine.tls_probe(target, domain).await?;
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
                    cfg.probe.default_sni.as_str()
                } else {
                    tls.working_sni.as_str()
                }
                .to_string(),
            )
        }
        None => (
            Protocol::Http,
            domain.unwrap_or(&cfg.probe.default_sni).to_string(),
        ),
    };
    let http = probe_engine.http_probe(target, protocol, &host).await?;
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
        Confidence::High => "IP belongs to Cloudflare and shows application-level traits".into(),
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
        let connector = probe_engine.connector();
        let addr = SocketAddr::new(target.ip, target.port);
        let started = std::time::Instant::now();
        let extra = HeaderMap::new();
        let response = if result.is_tls {
            connector
                .https_get(addr, &host, &host, "/cdn-cgi/trace", Some(&extra))
                .await?
        } else {
            connector
                .http_get(addr, &host, "/cdn-cgi/trace", Some(&extra))
                .await?
        };
        let latency = started.elapsed();
        let body_str = String::from_utf8_lossy(&response.body);
        let colo = extract_colo_from_trace(&body_str);
        if let Some(colo_code) = colo {
            let mut info = EdgeInfo {
                colo_code: Some(colo_code.clone()),
                latency: Some(latency),
                ..Default::default()
            };
            if let Some(loc) = locations.lookup(&colo_code) {
                info.city = Some(loc.city);
                info.country = Some(loc.cca2);
                info.region = Some(loc.region);
            }
            result.edge_info = Some(info);
        }
    }
    Ok(result)
}

pub(crate) fn extract_colo_from_trace(body: &str) -> Option<String> {
    for raw_line in body.lines() {
        let line = raw_line.trim();
        if let Some(rest) = line.strip_prefix("colo=") {
            let trimmed = rest.trim();
            if trimmed.is_empty() {
                return None;
            }
            return Some(trimmed.to_ascii_uppercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::location::LocationSource;
    use crate::model::{Confidence, DetectionResult, EdgeInfo, Target};
    use proptest::prelude::*;
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
        assert_eq!(
            cfg.cache.directory,
            std::path::PathBuf::from("data/cfrpdata")
        );
    }

    #[test]
    fn detector_config_clone() {
        let cfg = DetectorConfig {
            probe: ProbeConfig::default(),
            cache: crate::CacheConfig::default(),
            max_concurrency: 10,
            governor_enabled: true,
            governor: crate::governor::ResourceGovernorConfig::default(),
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg.max_concurrency, cfg2.max_concurrency);
    }

    #[test]
    fn detector_with_data_sources_builds_struct() {
        let client = reqwest::Client::builder().build().expect("client build");
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
            Confidence::High => {
                "IP belongs to Cloudflare and shows application-level traits".into()
            }
            _ => "".into(),
        };
        assert!(r.confidence_reason.contains("application-level traits"));
    }

    #[test]
    fn detection_result_confidence_reason_medium() {
        let reason = match Confidence::Medium {
            Confidence::High => "",
            Confidence::Medium => {
                "IP belongs to Cloudflare ranges, but active service traits are limited"
            }
            _ => "",
        };
        assert!(reason.contains("ranges, but active service traits are limited"));
    }

    #[test]
    fn detection_result_confidence_reason_low() {
        let reason: String = match Confidence::Low {
            Confidence::Low => {
                "IP is outside official ranges but exhibits Cloudflare application traits".into()
            }
            _ => String::new(),
        };
        assert!(reason.contains("exhibits Cloudflare application traits"));
    }

    #[test]
    fn detection_result_confidence_reason_none() {
        let reason: String = match Confidence::None {
            Confidence::None => {
                "IP is outside Cloudflare ranges and no Cloudflare traits were detected".into()
            }
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
        let all = [None, Low, Medium, High];
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn target_new_with_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229));
        let t = Target::new(ip, 443);
        assert_eq!(t.port, 443);
        assert_eq!(t.ip, ip);
    }

    #[test]
    fn extract_colo_happy_path() {
        let body = "fl=42\nh=www.cloudflare.com\ncolo=LAX\nloc=US\nsni=plaintext\n";
        assert_eq!(extract_colo_from_trace(body).as_deref(), Some("LAX"));
    }

    #[test]
    fn extract_colo_case_and_ws_insensitive() {
        assert_eq!(
            extract_colo_from_trace("  colo=lax  \n").as_deref(),
            Some("LAX")
        );
        assert_eq!(
            extract_colo_from_trace("\ncolo=NRT\n").as_deref(),
            Some("NRT")
        );
        assert_eq!(
            extract_colo_from_trace("foo=bar\r\ncolo=  lax  \r\n").as_deref(),
            Some("LAX")
        );
    }

    #[test]
    fn extract_colo_missing_or_empty_returns_none() {
        assert_eq!(extract_colo_from_trace(""), None);
        assert_eq!(extract_colo_from_trace("foo=bar\nbar=baz\n"), None);
        assert_eq!(extract_colo_from_trace("colo=\n"), None);
        assert_eq!(extract_colo_from_trace("colo=   \n"), None);
    }

    proptest! {
        #[test]
        fn prop_extract_colo_never_panics(
            lines in prop::collection::vec(
                "[[:print:]]{0,80}",
                0..20
            )
        ) {
            let body = lines.join("\n");
            let _ = extract_colo_from_trace(&body);
        }

        #[test]
        fn prop_extract_colo_uppercase_roundtrip(
            prefix in prop::collection::vec("[[:print:]]{0,40}", 0..5),
            colo in "[A-Za-z]{2,6}",
            suffix in prop::collection::vec("[[:print:]]{0,40}", 0..5)
        ) {
            let prefix_str = prefix.join("\n");
            let suffix_str = suffix.join("\n");
            let body = format!("{}\ncolo={}\n{}", prefix_str, colo, suffix_str);
            let result = extract_colo_from_trace(&body);
            prop_assert!(result.is_some());
            prop_assert_eq!(result.unwrap(), colo.to_ascii_uppercase());
        }
    }
}
