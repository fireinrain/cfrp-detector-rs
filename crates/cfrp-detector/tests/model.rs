use cfrp_detector::{
    BatchResult, BatchTarget, Confidence, DetectionResult, EdgeInfo, Protocol, Target,
};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[test]
fn target_display_roundtrip_v4() {
    let ip = IpAddr::V4(Ipv4Addr::new(104, 18, 241, 5));
    let t = Target::new(ip, 443);
    assert_eq!(t.to_string(), "104.18.241.5:443");
}

#[test]
fn target_display_roundtrip_v6() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1));
    let t = Target::new(ip, 8443);
    assert_eq!(t.to_string(), "[2606:4700::1]:8443");
}

#[test]
fn detection_result_serde_contains_all_keys() {
    let result = DetectionResult {
        is_cloudflare_edge: true,
        is_usable: true,
        http_status_code: Some(200),
        is_tls: true,
        confidence: Confidence::High,
        confidence_reason: "test".into(),
        reasons: vec!["A".into(), "B".into()],
        edge_info: Some(EdgeInfo {
            colo_code: Some("LAX".into()),
            city: Some("Los Angeles".into()),
            country: Some("US".into()),
            region: Some("CA".into()),
            latency: Some(Duration::from_millis(30)),
            download_speed_bytes_per_sec: Some(5_000_000),
        }),
    };
    let v: Value = serde_json::to_value(&result).unwrap();
    assert_eq!(v["is_cloudflare_edge"], true);
    assert_eq!(v["is_usable"], true);
    assert_eq!(v["http_status_code"], 200);
    assert_eq!(v["is_tls"], true);
    assert_eq!(v["confidence"], "HIGH");
    assert_eq!(v["confidence_reason"], "test");
    assert_eq!(v["reasons"].as_array().unwrap().len(), 2);
    assert!(v["edge_info"].is_object());
    assert_eq!(v["edge_info"]["colo_code"], "LAX");
    assert_eq!(v["edge_info"]["city"], "Los Angeles");
    assert_eq!(v["edge_info"]["country"], "US");
    assert_eq!(v["edge_info"]["region"], "CA");
}

#[test]
fn batch_target_serde_roundtrip() {
    let t = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
    let bt = BatchTarget { target: t, id: 1 };
    let json = serde_json::to_string(&bt).unwrap();
    let bt2: BatchTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(bt.target, bt2.target);
    assert_eq!(bt.id, bt2.id);
}

#[test]
fn batch_result_error_only_serde() {
    let t = Target::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    let br = BatchResult {
        target: t,
        result: None,
        error: Some("timeout".into()),
        id: 42,
    };
    let json = serde_json::to_string(&br).unwrap();
    let v: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["error"], "timeout");
    assert!(v["result"].is_null());
    assert_eq!(v["id"], 42);
}

#[test]
fn confidence_serde_roundtrip_all_variants() {
    for c in [
        Confidence::None,
        Confidence::Low,
        Confidence::Medium,
        Confidence::High,
    ] {
        let s = serde_json::to_string(&c).unwrap();
        let c2: Confidence = serde_json::from_str(&s).unwrap();
        assert_eq!(c, c2);
    }
}

#[test]
fn protocol_scheme_and_serde_match() {
    assert_eq!(Protocol::Http.scheme(), "http");
    assert_eq!(
        serde_json::to_string(&Protocol::Http).unwrap(),
        json!("http").to_string()
    );
    assert_eq!(Protocol::Https.scheme(), "https");
    assert_eq!(
        serde_json::to_string(&Protocol::Https).unwrap(),
        json!("https").to_string()
    );
}

#[test]
fn target_can_be_sorted_via_ip_then_port() {
    let t1 = Target::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 80);
    let t2 = Target::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 443);
    let t3 = Target::new(IpAddr::V4(Ipv4Addr::new(2, 0, 0, 1)), 443);
    let mut v = vec![t3.clone(), t1.clone(), t2.clone()];
    v.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.port.cmp(&b.port)));
    assert_eq!(v[0], t1);
    assert_eq!(v[1], t2);
    assert_eq!(v[2], t3);
}