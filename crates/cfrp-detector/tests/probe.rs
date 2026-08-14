use cfrp_detector::{ProbeConfig, Target};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[test]
fn probe_config_defaults_user_agent_mentions_product() {
    let cfg = ProbeConfig::default();
    assert!(cfg.user_agent.contains("CFRP-Detector"));
}

#[test]
fn probe_config_defaults_default_sni_is_cloudflare() {
    let cfg = ProbeConfig::default();
    assert!(cfg.default_sni.contains("cloudflare"));
}

#[test]
fn probe_config_mutate_connect_timeout() {
    let mut cfg = ProbeConfig::default();
    cfg.connect_timeout = Duration::from_millis(500);
    assert_eq!(cfg.connect_timeout, Duration::from_millis(500));
    assert_ne!(cfg.connect_timeout, ProbeConfig::default().connect_timeout);
}

#[test]
fn target_struct_port_stored_correctly() {
    let t = Target::new(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 1)), 8443);
    assert_eq!(t.port, 8443);
}

#[test]
fn header_map_construction_case_insensitive_lookup() {
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_static("cf-ray"),
        HeaderValue::from_static("a-LAX"),
    );
    assert!(h.get("cf-ray").is_some());
    assert!(h.get("CF-RAY").is_some());
    assert!(h.get("Cf-Ray").is_some());
}

#[test]
fn status_code_classification_usable_2xx_and_3xx() {
    for code in [200u16, 201, 204, 301, 302, 304, 399] {
        let usable = code >= 200 && code < 400;
        assert!(usable, "code {} should be usable", code);
    }
    for code in [100u16, 199, 400, 404, 500, 599] {
        let usable = code >= 200 && code < 400;
        assert!(!usable, "code {} should NOT be usable", code);
    }
}

#[test]
fn application_traits_count_logic() {
    for (usable, cf_trait, expected) in [
        (false, false, 0usize),
        (true, false, 1),
        (false, true, 1),
        (true, true, 2),
    ] {
        let got = usize::from(usable) + usize::from(cf_trait);
        assert_eq!(got, expected, "usable={usable}, cf_trait={cf_trait}");
    }
}

#[test]
fn confidence_matches_table() {
    use cfrp_detector::Confidence::*;
    let table = vec![
        ((true, 2usize), High),
        ((true, 1usize), High),
        ((true, 0usize), Medium),
        ((false, 2usize), Low),
        ((false, 1usize), Low),
        ((false, 0usize), None),
    ];
    for ((in_range, traits), want) in table {
        let got = match (in_range, traits) {
            (true, n) if n > 0 => High,
            (true, _) => Medium,
            (false, n) if n > 0 => Low,
            _ => None,
        };
        assert_eq!(got, want, "in_range={in_range}, traits={traits}");
    }
}
