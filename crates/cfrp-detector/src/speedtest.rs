use crate::{
    DetectorError, Result,
    connector::{ConnectorConfig, HandshakeType, PinnedConnector, Timing},
    model::Target,
};
use futures::stream::{self, StreamExt};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct SpeedTestConfig {
    pub timeout: Duration,
    pub threads_per_target: usize,
    pub concurrency: usize,
}

impl Default for SpeedTestConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            threads_per_target: 3,
            concurrency: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestResult {
    pub target: Target,
    pub bytes_per_second: u64,
    pub elapsed: Duration,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_latency: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_handshake_latency: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttfb_latency: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_type: Option<HandshakeType>,
}

impl SpeedTestResult {
    pub fn with_timing(mut self, timing: Timing) -> Self {
        self.connect_latency = timing.connect_latency;
        self.tls_handshake_latency = timing.tls_handshake_latency;
        self.ttfb_latency = timing.ttfb_latency;
        self
    }
}

pub struct SpeedTester {
    connector: Arc<PinnedConnector>,
    use_tls: bool,
    sni: String,
    host: String,
}

impl SpeedTester {
    pub fn new(
        connector_cfg: ConnectorConfig,
        use_tls: bool,
        sni: impl Into<String>,
        host: impl Into<String>,
    ) -> Result<Self> {
        let connector = PinnedConnector::new(connector_cfg)?;
        Ok(Self {
            connector: Arc::new(connector),
            use_tls,
            sni: sni.into(),
            host: host.into(),
        })
    }

    pub fn with_connector(
        connector: Arc<PinnedConnector>,
        use_tls: bool,
        sni: impl Into<String>,
        host: impl Into<String>,
    ) -> Self {
        Self {
            connector,
            use_tls,
            sni: sni.into(),
            host: host.into(),
        }
    }

    pub fn connector(&self) -> &Arc<PinnedConnector> {
        &self.connector
    }

    pub fn tls_session_cache_len(&self) -> usize {
        self.connector.tls_session_cache_len()
    }

    pub fn set_0rtt_enabled(&self, enabled: bool) {
        self.connector.set_0rtt_enabled(enabled);
    }

    async fn download_once(
        &self,
        addr: SocketAddr,
        path: &str,
        timeout: Duration,
        extra_headers: Option<&HeaderMap>,
    ) -> Result<(u64, Timing, Option<HandshakeType>)> {
        if self.use_tls {
            let dl = tokio::time::timeout(
                timeout,
                self.connector
                    .https_download(addr, &self.sni, &self.host, path, extra_headers),
            )
            .await
            .map_err(|_| DetectorError::Http("speedtest timed out".into()))??;
            let t = dl.timing.clone();
            let h = dl.handshake_type;
            Ok((dl.total_bytes, t, h))
        } else {
            let dl = tokio::time::timeout(
                timeout,
                self.connector
                    .http_download(addr, &self.host, path, extra_headers),
            )
            .await
            .map_err(|_| DetectorError::Http("speedtest timed out".into()))??;
            Ok((dl.total_bytes, dl.timing, None))
        }
    }

    pub async fn test(
        &self,
        target: &Target,
        path: &str,
        cfg: &SpeedTestConfig,
    ) -> Result<SpeedTestResult> {
        let addr = SocketAddr::new(target.ip, target.port);
        let started = Instant::now();
        let first_byte = Arc::new(parking_lot::Mutex::<Option<Duration>>::new(None));
        let mut tasks = Vec::new();
        let timeout_limit = cfg.timeout;
        let _extra = HeaderMap::new();
        for i in 0..cfg.threads_per_target.max(1) {
            let conn = self.connector.clone();
            let use_tls = self.use_tls;
            let sni = self.sni.clone();
            let host = self.host.clone();
            let p = path.to_string();
            let fb = first_byte.clone();
            tasks.push(tokio::spawn(async move {
                let send_started = Instant::now();
                let (bytes, timing, hs) = if use_tls {
                    let dl = tokio::time::timeout(
                        timeout_limit,
                        conn.https_download(addr, &sni, &host, &p, None),
                    )
                    .await
                    .map_err(|_| DetectorError::Http("speedtest timed out".into()))??;
                    (dl.total_bytes, dl.timing, dl.handshake_type)
                } else {
                    let dl = tokio::time::timeout(
                        timeout_limit,
                        conn.http_download(addr, &host, &p, None),
                    )
                    .await
                    .map_err(|_| DetectorError::Http("speedtest timed out".into()))??;
                    (dl.total_bytes, dl.timing, None)
                };
                if i == 0 {
                    let mut g = fb.lock();
                    if g.is_none() {
                        *g = Some(send_started.elapsed());
                    }
                }
                Ok::<(u64, Timing, Option<HandshakeType>), DetectorError>((bytes, timing, hs))
            }));
        }
        let mut total = 0u64;
        let mut first_timing: Option<Timing> = None;
        let mut first_hs: Option<HandshakeType> = None;
        for (i, task) in tasks.into_iter().enumerate() {
            let (b, t, hs) = task
                .await
                .map_err(|e| DetectorError::Http(e.to_string()))??;
            total += b;
            if i == 0 {
                first_timing = Some(t);
                first_hs = hs;
            }
        }
        let elapsed = started.elapsed();
        let bps = if elapsed.is_zero() {
            0
        } else {
            total.saturating_mul(1_000_000_000) / elapsed.as_nanos() as u64
        };
        let ttfb = first_byte
            .lock()
            .clone()
            .and_then(|d| if d.is_zero() { None } else { Some(d) });
        let mut result = SpeedTestResult {
            target: target.clone(),
            bytes_per_second: bps,
            elapsed,
            connect_latency: None,
            tls_handshake_latency: None,
            ttfb_latency: ttfb,
            handshake_type: first_hs,
        };
        if let Some(t) = first_timing {
            result = result.with_timing(t);
        }
        Ok(result)
    }

    pub async fn test_with_warmup(
        &self,
        target: &Target,
        path: &str,
        cfg: &SpeedTestConfig,
    ) -> Result<SpeedTestResult> {
        let addr = SocketAddr::new(target.ip, target.port);
        let extra = HeaderMap::new();
        let _warmup = self
            .download_once(addr, path, cfg.timeout, Some(&extra))
            .await?;
        self.test(target, path, cfg).await
    }

    pub async fn test_with_timing(
        &self,
        target: &Target,
        path: &str,
        cfg: &SpeedTestConfig,
        timing: Timing,
        handshake_type: Option<HandshakeType>,
    ) -> Result<SpeedTestResult> {
        let mut base = self.test(target, path, cfg).await?;
        base = base.with_timing(timing);
        base.handshake_type = handshake_type;
        Ok(base)
    }

    pub async fn test_batch(
        &self,
        targets: &[Target],
        path: &str,
        cfg: &SpeedTestConfig,
    ) -> Vec<SpeedTestResult> {
        let cfg_arc = Arc::new(cfg.clone());
        let path_arc: Arc<str> = path.into();
        stream::iter(targets.iter().cloned())
            .map(|target| {
                let cfg_c = cfg_arc.clone();
                let p = path_arc.clone();
                let use_tls = self.use_tls;
                let sni = self.sni.clone();
                let host = self.host.clone();
                let conn = self.connector.clone();
                async move {
                    let addr = SocketAddr::new(target.ip, target.port);
                    let started = Instant::now();
                    let first_byte = Arc::new(parking_lot::Mutex::<Option<Duration>>::new(None));
                    let mut tasks = Vec::new();
                    let timeout_limit = cfg_c.timeout;
                    for i in 0..cfg_c.threads_per_target.max(1) {
                        let c2 = conn.clone();
                        let s2 = sni.clone();
                        let h2 = host.clone();
                        let p2: Arc<str> = p.clone();
                        let fb2 = first_byte.clone();
                        tasks.push(tokio::spawn(async move {
                            let send_started = Instant::now();
                            let (bytes, timing, hs) = if use_tls {
                                let dl = tokio::time::timeout(
                                    timeout_limit,
                                    c2.https_download(addr, &s2, &h2, &p2, None),
                                )
                                .await
                                .map_err(|_| DetectorError::Http("speedtest timed out".into()))??;
                                (dl.total_bytes, dl.timing, dl.handshake_type)
                            } else {
                                let dl = tokio::time::timeout(
                                    timeout_limit,
                                    c2.http_download(addr, &h2, &p2, None),
                                )
                                .await
                                .map_err(|_| DetectorError::Http("speedtest timed out".into()))??;
                                (dl.total_bytes, dl.timing, None)
                            };
                            if i == 0 {
                                let mut g = fb2.lock();
                                if g.is_none() {
                                    *g = Some(send_started.elapsed());
                                }
                            }
                            Ok::<(u64, Timing, Option<HandshakeType>), DetectorError>((
                                bytes, timing, hs,
                            ))
                        }));
                    }
                    let mut total = 0u64;
                    let mut first_timing: Option<Timing> = None;
                    let mut first_hs: Option<HandshakeType> = None;
                    for (i, task) in tasks.into_iter().enumerate() {
                        let (b, t, hs) = match task.await {
                            Ok(r) => match r {
                                Ok(x) => x,
                                Err(_) => return None,
                            },
                            Err(_) => return None,
                        };
                        total += b;
                        if i == 0 {
                            first_timing = Some(t);
                            first_hs = hs;
                        }
                    }
                    let elapsed = started.elapsed();
                    let bps = if elapsed.is_zero() {
                        0
                    } else {
                        total.saturating_mul(1_000_000_000) / elapsed.as_nanos() as u64
                    };
                    let ttfb = first_byte
                        .lock()
                        .clone()
                        .and_then(|d| if d.is_zero() { None } else { Some(d) });
                    let mut result = SpeedTestResult {
                        target,
                        bytes_per_second: bps,
                        elapsed,
                        connect_latency: None,
                        tls_handshake_latency: None,
                        ttfb_latency: ttfb,
                        handshake_type: first_hs,
                    };
                    if let Some(t) = first_timing {
                        result = result.with_timing(t);
                    }
                    Some(result)
                }
            })
            .buffer_unordered(cfg.concurrency.max(1))
            .filter_map(async move |r| r)
            .collect()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::HandshakeType;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn speedtest_config_default_values() {
        let cfg = SpeedTestConfig::default();
        assert_eq!(cfg.timeout, Duration::from_secs(5));
        assert_eq!(cfg.threads_per_target, 3);
        assert_eq!(cfg.concurrency, 8);
    }

    #[test]
    fn speedtest_config_clone() {
        let cfg = SpeedTestConfig {
            timeout: Duration::from_secs(10),
            threads_per_target: 5,
            concurrency: 16,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg.timeout, cfg2.timeout);
        assert_eq!(cfg.threads_per_target, cfg2.threads_per_target);
        assert_eq!(cfg.concurrency, cfg2.concurrency);
    }

    #[test]
    fn speedtest_result_struct_fields_all_optional_latencies() {
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let res = SpeedTestResult {
            target: target.clone(),
            bytes_per_second: 5_000_000,
            elapsed: Duration::from_millis(1234),
            connect_latency: Some(Duration::from_millis(25)),
            tls_handshake_latency: Some(Duration::from_millis(40)),
            ttfb_latency: Some(Duration::from_millis(80)),
            handshake_type: Some(HandshakeType::Resumed),
        };
        assert_eq!(res.target, target);
        assert_eq!(res.bytes_per_second, 5_000_000);
        assert_eq!(res.elapsed.as_millis(), 1234);
        assert_eq!(res.connect_latency.map(|d| d.as_millis()), Some(25));
        assert_eq!(res.tls_handshake_latency.map(|d| d.as_millis()), Some(40));
        assert_eq!(res.ttfb_latency.map(|d| d.as_millis()), Some(80));
        assert!(matches!(res.handshake_type, Some(HandshakeType::Resumed)));
    }

    #[test]
    fn speedtest_result_with_timing_populates_latencies() {
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let base = SpeedTestResult {
            target,
            bytes_per_second: 0,
            elapsed: Duration::ZERO,
            connect_latency: None,
            tls_handshake_latency: None,
            ttfb_latency: None,
            handshake_type: None,
        };
        let timing = Timing {
            connect_latency: Some(Duration::from_millis(10)),
            tls_handshake_latency: Some(Duration::from_millis(20)),
            ttfb_latency: Some(Duration::from_millis(30)),
        };
        let r = base.with_timing(timing);
        assert_eq!(r.connect_latency.unwrap().as_millis(), 10);
        assert_eq!(r.tls_handshake_latency.unwrap().as_millis(), 20);
        assert_eq!(r.ttfb_latency.unwrap().as_millis(), 30);
    }

    #[test]
    fn speedtest_clamp_zero_elapsed_to_zero_bps() {
        let total = 1000u64;
        let elapsed = Duration::ZERO;
        let bps = if elapsed.is_zero() {
            0
        } else {
            total.saturating_mul(1_000_000_000) / elapsed.as_nanos() as u64
        };
        assert_eq!(bps, 0);
    }

    #[test]
    fn speedtest_bps_calculation_one_second() {
        let total = 10_000_000u64;
        let elapsed = Duration::from_secs(1);
        let bps = if elapsed.is_zero() {
            0
        } else {
            total.saturating_mul(1_000_000_000) / elapsed.as_nanos() as u64
        };
        assert_eq!(bps, 10_000_000);
    }

    #[test]
    fn speedtest_concurrency_min_is_one() {
        let cfg = SpeedTestConfig {
            timeout: Duration::from_secs(1),
            threads_per_target: 0,
            concurrency: 0,
        };
        assert_eq!(cfg.concurrency.max(1), 1);
        assert_eq!(cfg.threads_per_target.max(1), 1);
    }

    #[test]
    fn speedtest_optional_fields_skipped_in_serde_json() {
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let r = SpeedTestResult {
            target,
            bytes_per_second: 100,
            elapsed: Duration::from_millis(500),
            connect_latency: None,
            tls_handshake_latency: None,
            ttfb_latency: None,
            handshake_type: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("connect_latency"));
        assert!(!json.contains("tls_handshake"));
        assert!(!json.contains("ttfb"));
        assert!(!json.contains("handshake_type"));
    }
}
