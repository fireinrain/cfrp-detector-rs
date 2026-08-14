use crate::{DetectorError, Result, model::Target};
use futures::stream::{self, StreamExt};
use reqwest::Client;
use std::{
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

#[derive(Debug, Clone)]
pub struct SpeedTestResult {
    pub target: Target,
    pub bytes_per_second: u64,
    pub elapsed: Duration,
}

pub struct SpeedTester {
    client: Arc<Client>,
}
impl SpeedTester {
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    pub async fn test(
        &self,
        target: &Target,
        target_url: &str,
        cfg: &SpeedTestConfig,
    ) -> Result<SpeedTestResult> {
        let started = Instant::now();
        // MVP: DNS bypass and Host/SNI separation are handled by the caller's URL in this layer.
        // The next phase will introduce a custom resolver/connector that pins the TCP endpoint.
        let mut tasks = Vec::new();
        let timeout_limit = cfg.timeout;
        for _ in 0..cfg.threads_per_target.max(1) {
            let client = self.client.clone();
            let url = target_url.to_string();
            tasks.push(tokio::spawn(async move {
                let resp = tokio::time::timeout(timeout_limit, client.get(url).send())
                    .await
                    .map_err(|_| DetectorError::Http("speedtest timed out".into()))??;
                let bytes = tokio::time::timeout(timeout_limit, resp.bytes())
                    .await
                    .map_err(|_| DetectorError::Http("speedtest body timed out".into()))??;
                Ok::<u64, DetectorError>(bytes.len() as u64)
            }));
        }
        let mut total = 0u64;
        for task in tasks {
            total += task
                .await
                .map_err(|e| DetectorError::Http(e.to_string()))??;
        }
        let elapsed = started.elapsed();
        let bps = if elapsed.is_zero() {
            0
        } else {
            total.saturating_mul(1_000_000_000) / elapsed.as_nanos() as u64
        };
        Ok(SpeedTestResult {
            target: target.clone(),
            bytes_per_second: bps,
            elapsed,
        })
    }

    pub async fn test_batch(
        &self,
        targets: &[Target],
        target_url: &str,
        cfg: &SpeedTestConfig,
    ) -> Vec<SpeedTestResult> {
        stream::iter(targets.iter().cloned())
            .map(|target| async move { self.test(&target, target_url, cfg).await.ok() })
            .buffer_unordered(cfg.concurrency.max(1))
            .filter_map(async move |r| r)
            .collect()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn speedtest_result_struct_fields() {
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let res = SpeedTestResult {
            target: target.clone(),
            bytes_per_second: 5_000_000,
            elapsed: Duration::from_millis(1234),
        };
        assert_eq!(res.target, target);
        assert_eq!(res.bytes_per_second, 5_000_000);
        assert_eq!(res.elapsed.as_millis(), 1234);
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
}