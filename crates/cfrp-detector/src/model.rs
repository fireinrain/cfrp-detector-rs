use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, time::Duration};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub ip: IpAddr,
    pub port: u16,
}

impl Target {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V6(_) => write!(f, "[{}]:{}", self.ip, self.port),
            IpAddr::V4(_) => write!(f, "{}:{}", self.ip, self.port),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTarget {
    pub target: Target,
    #[serde(default)]
    pub id: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}

impl Protocol {
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EdgeInfo {
    pub colo_code: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub latency: Option<Duration>,
    pub download_speed_bytes_per_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub is_cloudflare_edge: bool,
    pub is_usable: bool,
    pub http_status_code: Option<u16>,
    pub is_tls: bool,
    pub confidence: Confidence,
    pub confidence_reason: String,
    pub reasons: Vec<String>,
    pub edge_info: Option<EdgeInfo>,
}

impl Default for DetectionResult {
    fn default() -> Self {
        Self {
            is_cloudflare_edge: false,
            is_usable: false,
            http_status_code: None,
            is_tls: false,
            confidence: Confidence::None,
            confidence_reason: String::new(),
            reasons: Vec::new(),
            edge_info: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    pub target: Target,
    pub result: Option<DetectionResult>,
    pub error: Option<String>,
    #[serde(default)]
    pub id: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    #[test]
    fn target_display_is_ipv6_safe() {
        let target = Target::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        assert_eq!(target.to_string(), "[::1]:443");
    }

    #[test]
    fn target_display_ipv4_plain() {
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        assert_eq!(target.to_string(), "192.168.1.1:8080");
    }

    #[test]
    fn target_equality_and_hash() {
        use std::collections::HashSet;
        let t1 = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let t2 = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let t3 = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 80);
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
        let mut set = HashSet::new();
        set.insert(t1.clone());
        assert!(set.contains(&t2));
        assert!(!set.contains(&t3));
    }

    #[test]
    fn target_new_constructor() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let t = Target::new(ip, 8443);
        assert_eq!(t.ip, ip);
        assert_eq!(t.port, 8443);
    }

    #[test]
    fn protocol_scheme_http() {
        assert_eq!(Protocol::Http.scheme(), "http");
    }

    #[test]
    fn protocol_scheme_https() {
        assert_eq!(Protocol::Https.scheme(), "https");
    }

    #[test]
    fn confidence_variants_exist() {
        let _ = Confidence::None;
        let _ = Confidence::Low;
        let _ = Confidence::Medium;
        let _ = Confidence::High;
    }

    #[test]
    fn confidence_equality() {
        assert_eq!(Confidence::High, Confidence::High);
        assert_ne!(Confidence::High, Confidence::Low);
    }

    #[test]
    fn detection_result_default_values() {
        let r = DetectionResult::default();
        assert!(!r.is_cloudflare_edge);
        assert!(!r.is_usable);
        assert!(r.http_status_code.is_none());
        assert!(!r.is_tls);
        assert_eq!(r.confidence, Confidence::None);
        assert!(r.confidence_reason.is_empty());
        assert!(r.reasons.is_empty());
        assert!(r.edge_info.is_none());
    }

    #[test]
    fn edge_info_default_values() {
        let e = EdgeInfo::default();
        assert!(e.colo_code.is_none());
        assert!(e.city.is_none());
        assert!(e.country.is_none());
        assert!(e.region.is_none());
        assert!(e.latency.is_none());
        assert!(e.download_speed_bytes_per_sec.is_none());
    }

    #[test]
    fn edge_info_with_fields() {
        let e = EdgeInfo {
            colo_code: Some("LAX".into()),
            city: Some("Los Angeles".into()),
            country: Some("US".into()),
            region: Some("CA".into()),
            latency: Some(Duration::from_millis(50)),
            download_speed_bytes_per_sec: Some(1_000_000),
        };
        assert_eq!(e.colo_code.as_deref(), Some("LAX"));
        assert_eq!(e.latency.unwrap().as_millis(), 50);
    }

    #[test]
    fn batch_target_construction() {
        let t = Target::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let bt = BatchTarget { target: t.clone(), id: 0 };
        assert_eq!(bt.target.ip, t.ip);
        assert_eq!(bt.target.port, t.port);
    }

    #[test]
    fn batch_result_fields() {
        let t = Target::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let br = BatchResult {
            target: t.clone(),
            result: Some(DetectionResult::default()),
            error: None,
            id: 0,
        };
        assert!(br.result.is_some());
        assert!(br.error.is_none());
        assert_eq!(br.target, t);
    }

    #[test]
    fn batch_result_with_error() {
        let t = Target::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let br = BatchResult {
            target: t,
            result: None,
            error: Some("connection refused".into()),
            id: 0,
        };
        assert!(br.result.is_none());
        assert_eq!(br.error.as_deref(), Some("connection refused"));
    }

    #[test]
    fn target_serde_roundtrip() {
        let t = Target::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
        let json = serde_json::to_string(&t).unwrap();
        let t2: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn confidence_serde_uppercase() {
        assert_eq!(serde_json::to_string(&Confidence::High).unwrap(), "\"HIGH\"");
        assert_eq!(serde_json::to_string(&Confidence::Low).unwrap(), "\"LOW\"");
        let c: Confidence = serde_json::from_str("\"MEDIUM\"").unwrap();
        assert_eq!(c, Confidence::Medium);
    }

    #[test]
    fn protocol_serde_lowercase() {
        assert_eq!(serde_json::to_string(&Protocol::Http).unwrap(), "\"http\"");
        assert_eq!(serde_json::to_string(&Protocol::Https).unwrap(), "\"https\"");
    }
}