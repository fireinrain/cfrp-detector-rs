mod support;

use support::{MockCfServer, MockCfServerConfig, StaticLocations, StaticRanges, make_detector_with_mocks};
use cfrp_detector::{
    AdaptiveConfig, BatchTarget, CidrSource, Confidence, ConnectorConfig, DetectorConfig,
    LocationSource, SpeedTestConfig, SpeedTester,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn phase4_1_detect_in_cidr_high_confidence() {
    let config = MockCfServerConfig {
        https: true,
        colo_code: "LAX".into(),
        host: "www.cloudflare.com".into(),
        override_status: None,
        ..Default::default()
    };
    let server = MockCfServer::start(config).await;
    let ranges = StaticRanges::from([format!("{}/32", server.addr.ip())]);
    let locations = StaticLocations::sample();
    let cfg = DetectorConfig::default();
    let detector = make_detector_with_mocks(ranges, locations, cfg);
    let target = server.target();
    let result = detector
        .detect(&target, Some("www.cloudflare.com"))
        .await
        .unwrap();
    assert!(result.is_cloudflare_edge, "should be cloudflare edge");
    assert_eq!(result.confidence, Confidence::High, "expected HIGH confidence for in-range + CF headers");
    assert!(result.edge_info.is_some(), "edge info should be populated");
    assert_eq!(result.edge_info.as_ref().unwrap().colo_code.as_deref(), Some("LAX"));
    assert_eq!(result.edge_info.as_ref().unwrap().city.as_deref(), Some("Los Angeles"));
    server.stop();
}

#[tokio::test]
async fn phase4_1_detect_outside_cidr_but_cf_headers_low() {
    let config = MockCfServerConfig {
        https: true,
        colo_code: "NRT".into(),
        host: "www.cloudflare.com".into(),
        ..Default::default()
    };
    let server = MockCfServer::start(config).await;
    let ranges = StaticRanges::from(["10.0.0.0/8"]);
    let locations = StaticLocations::sample();
    let cfg = DetectorConfig::default();
    let detector = make_detector_with_mocks(ranges, locations, cfg);
    let target = server.target();
    let result = detector
        .detect(&target, Some("www.cloudflare.com"))
        .await
        .unwrap();
    assert_eq!(result.confidence, Confidence::Low, "outside CIDR but has CF headers => LOW");
    assert!(result.is_cloudflare_edge, "should still report edge");
    server.stop();
}

#[tokio::test]
async fn phase4_1_fetch_edge_info_parse_trace() {
    let config = MockCfServerConfig {
        https: false,
        colo_code: "LAX".into(),
        host: "trace.example.com".into(),
        ..Default::default()
    };
    let server = MockCfServer::start(config).await;
    let ranges = StaticRanges::with_loopback();
    let locations = StaticLocations::sample();
    let cfg = DetectorConfig::default();
    let detector = make_detector_with_mocks(ranges, locations, cfg);
    let target = server.target();
    let info = detector
        .fetch_edge_info(&target, false, "trace.example.com")
        .await
        .unwrap();
    assert!(info.is_some(), "trace parse should succeed");
    let info = info.unwrap();
    assert_eq!(info.colo_code.as_deref(), Some("LAX"));
    assert_eq!(info.city.as_deref(), Some("Los Angeles"));
    assert_eq!(info.country.as_deref(), Some("US"));
    assert_eq!(info.region.as_deref(), Some("CA"));
    assert!(info.latency.is_some());
    server.stop();
}

#[tokio::test]
async fn phase4_1_fetch_edge_info_missing_colo_returns_none() {
    let config = MockCfServerConfig {
        https: false,
        colo_code: "XYZ".into(),
        host: "example.com".into(),
        ..Default::default()
    };
    let server = MockCfServer::start(config).await;
    let ranges = StaticRanges::with_loopback();
    let locations = StaticLocations::sample();
    let cfg = DetectorConfig::default();
    let detector = make_detector_with_mocks(ranges, locations, cfg);
    let target = server.target();
    let info = detector
        .fetch_edge_info(&target, false, "example.com")
        .await
        .unwrap();
    assert!(info.is_some(), "even unknown colo should still extract colo code");
    let info = info.unwrap();
    assert_eq!(info.colo_code.as_deref(), Some("XYZ"));
    assert!(info.city.is_none(), "XYZ is not in location source");
    server.stop();
}

#[tokio::test]
async fn phase4_1_detect_batch_with_reset_keeps_order() {
    let config = MockCfServerConfig {
        https: true,
        colo_code: "LAX".into(),
        host: "www.cloudflare.com".into(),
        reset_probability: 0.3,
        ..Default::default()
    };
    let server = MockCfServer::start(config).await;
    let addr_str = format!("{}/32", server.addr.ip());
    let ranges = StaticRanges::from([addr_str.as_str()]);
    let locations = StaticLocations::sample();
    let mut cfg = DetectorConfig::default();
    cfg.max_concurrency = 8;
    let detector = make_detector_with_mocks(ranges, locations, cfg);
    let n = 30usize;
    let targets: Vec<BatchTarget> = (0..n)
        .map(|i| BatchTarget {
            target: server.target(),
            id: i,
        })
        .collect();
    let adaptive = AdaptiveConfig {
        enabled: true,
        initial: 4,
        min: 1,
        max: 8,
        window: 10,
    };
    let results = detector
        .detect_batch_with_progress(&targets, Some("www.cloudflare.com"), 4, adaptive, |_| {})
        .await;
    assert_eq!(results.len(), n);
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.id, i, "output order must match input order (id={})", i);
        assert_eq!(r.target, server.target(), "target preserved for id={}", i);
    }
    let ok_count = results.iter().filter(|r| r.result.is_some()).count();
    assert!(ok_count > 0, "at least some should succeed with 70% success prob");
    server.stop();
}

#[tokio::test]
async fn phase4_1_speedtest_payload_size_calculation() {
    let payload_size = 1024 * 64usize;
    let config = MockCfServerConfig {
        https: true,
        colo_code: "LAX".into(),
        host: "speed.example".into(),
        speedtest_payload_bytes: payload_size,
        ..Default::default()
    };
    let server = MockCfServer::start(config).await;
    let mut connector_cfg = ConnectorConfig::default();
    connector_cfg.accept_invalid_certs = true;
    let st = SpeedTester::new(connector_cfg, true, "speed.example", "speed.example")
        .expect("speedtester build");
    let speed_cfg = SpeedTestConfig {
        threads_per_target: 1,
        timeout: Duration::from_secs(10),
        concurrency: 1,
    };
    let target = server.target();
    let result = st
        .test(&target, "/cdn-cgi/speedtest", &speed_cfg)
        .await
        .expect("speedtest");
    assert!(
        result.bytes_per_second > 0,
        "bps should be > 0, got bps={}, elapsed={:?}",
        result.bytes_per_second,
        result.elapsed
    );
    assert!(
        !result.elapsed.is_zero(),
        "elapsed must be non-zero for non-zero bps, bps={}",
        result.bytes_per_second
    );
    let expected_min = payload_size as u64;
    let estimated_bytes = (result.bytes_per_second as f64)
        * result.elapsed.as_secs_f64();
    assert!(
        estimated_bytes >= expected_min as f64 * 0.1,
        "estimated bytes {} from bps*elapsed should be >= 10% of payload {}, bps={}",
        estimated_bytes as u64,
        expected_min,
        result.bytes_per_second
    );
    server.stop();
}

#[tokio::test]
async fn phase4_5_cache_retry_config_defaults_sane() {
    let cfg = cfrp_detector::CacheConfig::default();
    assert!(cfg.retry.max_attempts >= 1, "should have at least 1 attempt");
    assert!(cfg.retry.max_backoff_ms >= cfg.retry.initial_backoff_ms);
    assert!(cfg.retry.backoff_multiplier >= 1.0);
}

#[tokio::test]
async fn phase4_5_retry_error_is_retryable_for_connect_and_timeout() {
    use cfrp_detector::{DetectorError, is_retryable_error};
    let io_err = DetectorError::Io(std::io::Error::from_raw_os_error(104));
    assert!(is_retryable_error(&io_err));
    let refused = DetectorError::Io(std::io::Error::from_raw_os_error(61));
    assert!(is_retryable_error(&refused));
    let http_timeout = DetectorError::Http("speedtest timed out".into());
    assert!(is_retryable_error(&http_timeout));
    let non_retryable = DetectorError::InvalidPort(0);
    assert!(!is_retryable_error(&non_retryable));
}

#[tokio::test]
async fn phase4_6_cancellation_returns_partial_results_in_order() {
    let config = MockCfServerConfig {
        https: true,
        colo_code: "LAX".into(),
        host: "cancel.example".into(),
        latency: Some(Duration::from_millis(150)),
        ..Default::default()
    };
    let server = MockCfServer::start(config).await;
    let ranges = StaticRanges::from([format!("{}/32", server.addr.ip())]);
    let locations = StaticLocations::sample();
    let mut cfg = DetectorConfig::default();
    cfg.max_concurrency = 4;
    let detector = make_detector_with_mocks(ranges, locations, cfg);
    let n = 20usize;
    let targets: Vec<BatchTarget> = (0..n)
        .map(|i| BatchTarget {
            target: server.target(),
            id: i,
        })
        .collect();
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel_clone.cancel();
    });
    let adaptive = AdaptiveConfig {
        enabled: false,
        initial: 4,
        min: 1,
        max: 4,
        window: 10,
    };
    let results = detector
        .detect_batch_with_cancel(&targets, Some("cancel.example"), 4, adaptive, cancel, |_| {})
        .await;
    assert_eq!(results.len(), n, "even cancelled should have N results, partial error-filled");
    for (i, r) in results.iter().enumerate() {
        assert_eq!(r.id, i, "order preserved: id {} out of place", i);
    }
    server.stop();
}

#[tokio::test]
async fn phase4_static_ranges_contains_loopback() {
    let r = StaticRanges::with_loopback();
    assert!(r.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(r.contains(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)));
    assert!(!r.contains(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[tokio::test]
async fn phase4_static_locations_case_insensitive() {
    let loc = StaticLocations::sample();
    assert!(loc.lookup("lax").is_some());
    assert!(loc.lookup("LAX").is_some());
    assert!(loc.lookup("Lax").is_some());
    assert!(loc.lookup("XXX").is_none());
}

#[tokio::test]
async fn phase4_1_tls_probe_against_mock_https() {
    let config = MockCfServerConfig {
        https: true,
        colo_code: "LAX".into(),
        host: "www.cloudflare.com".into(),
        ..Default::default()
    };
    let server = MockCfServer::start(config).await;
    let probe_cfg = cfrp_detector::ProbeConfig::default();
    let engine = cfrp_detector::probe::ProbeEngine::new(probe_cfg);
    let target = server.target();
    let tls = engine
        .tls_probe(&target, Some("www.cloudflare.com"))
        .await
        .unwrap();
    assert!(tls.is_some(), "mock HTTPS server TLS probe should succeed");
    let tls = tls.unwrap();
    assert!(!tls.working_sni.is_empty());
    server.stop();
}