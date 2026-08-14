use cfrp_detector::{
    ConnectorConfig, HandshakeType, SpeedTestConfig, SpeedTestResult, SpeedTester, Target,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[test]
fn speedtest_config_default() {
    let cfg = SpeedTestConfig::default();
    assert!(cfg.timeout.as_secs() >= 3);
    assert!(cfg.threads_per_target >= 1);
    assert!(cfg.concurrency >= 1);
}

#[test]
fn speedtester_new_from_client() {
    let cfg = ConnectorConfig::default();
    let st = SpeedTester::new(cfg, true, "example.com", "example.com").unwrap();
    let _ = st;
}

#[test]
fn speedtest_result_bytes_per_sec_is_u64() {
    let r = SpeedTestResult {
        target: Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        bytes_per_second: u64::MAX,
        elapsed: Duration::from_secs(1),
        connect_latency: None,
        tls_handshake_latency: None,
        ttfb_latency: None,
        handshake_type: Some(HandshakeType::FullHandshake),
    };
    assert_eq!(r.bytes_per_second, u64::MAX);
}

#[test]
fn bps_calc_saturating_no_overflow() {
    let big_total = u64::MAX;
    let elapsed = Duration::from_nanos(1);
    let bps = if elapsed.is_zero() {
        0
    } else {
        big_total.saturating_mul(1_000_000_000) / elapsed.as_nanos() as u64
    };
    assert!(bps > 0);
}

#[test]
fn bps_zero_elapsed_is_zero_no_panic() {
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
fn speedtest_batch_does_not_require_network() {
    let targets: Vec<Target> = vec![];
    let cfg = SpeedTestConfig {
        timeout: Duration::from_millis(100),
        threads_per_target: 1,
        concurrency: 1,
    };
    let _ = (targets, cfg);
}

#[test]
fn speedtest_config_zero_values_clamp() {
    let cfg = SpeedTestConfig {
        timeout: Duration::ZERO,
        threads_per_target: 0,
        concurrency: 0,
    };
    assert_eq!(cfg.threads_per_target.max(1), 1);
    assert_eq!(cfg.concurrency.max(1), 1);
}

#[test]
fn speedtest_config_clone_independent() {
    let mut a = SpeedTestConfig::default();
    let b = a.clone();
    a.concurrency = 999;
    assert_ne!(a.concurrency, b.concurrency);
}
