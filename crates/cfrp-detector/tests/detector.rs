use cfrp_detector::{
    BatchTarget, CloudflareRanges, Detector, DetectorConfig, LocationStore, Target,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn empty_detector() -> Detector {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let ranges = CloudflareRanges::empty();
    let locations = Arc::new(LocationStore::empty());
    Detector::with_data_sources(DetectorConfig::default(), client, ranges, locations)
}

#[test]
fn detector_config_defaults() {
    let cfg = DetectorConfig::default();
    assert!(cfg.max_concurrency > 0);
    assert!(cfg.probe.connect_timeout.as_millis() > 0);
    assert!(cfg.probe.request_timeout.as_millis() > 0);
    assert!(!cfg.probe.default_sni.is_empty());
}

#[test]
fn detector_cfg_clone_keeps_values() {
    let cfg = DetectorConfig {
        max_concurrency: 10,
        probe: cfrp_detector::ProbeConfig::default(),
        cache: cfrp_detector::CacheConfig::default(),
    };
    let cloned = cfg.clone();
    assert_eq!(cloned.max_concurrency, 10);
}

#[test]
fn with_data_sources_instantiates() {
    let d = empty_detector();
    assert_eq!(d.cfg.max_concurrency, DetectorConfig::default().max_concurrency);
}

#[test]
fn batch_target_construction_for_detect_batch() {
    let targets: Vec<BatchTarget> = ["1.1.1.1", "1.0.0.1", "8.8.8.8"]
        .iter()
        .map(|s| {
            let ip: Ipv4Addr = s.parse().unwrap();
            BatchTarget {
                target: Target::new(IpAddr::V4(ip), 443),
            }
        })
        .collect();
    assert_eq!(targets.len(), 3);
    assert_eq!(targets[1].target.port, 443);
}

#[test]
fn target_ip_and_port_can_be_accessed_publicly() {
    let t = Target::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
    assert!(matches!(t.ip, IpAddr::V4(_)));
    assert_eq!(t.port, 8080);
}

#[test]
fn concurrency_clamp_logic() {
    let max = 256;
    for (input, want) in [(0usize, 1usize), (1, 1), (50, 50), (256, 256), (1000, 256)] {
        let got = input.clamp(1, max.max(1));
        assert_eq!(got, want, "input={input}");
    }
}

#[test]
fn ordered_by_index_behavior() {
    let mut pairs: Vec<(usize, &'static str)> = vec![(2, "c"), (0, "a"), (1, "b")];
    pairs.sort_by_key(|(idx, _)| *idx);
    assert_eq!(pairs, vec![(0, "a"), (1, "b"), (2, "c")]);
}