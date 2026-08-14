use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

fn parse_target(raw: &str, default_port: u16) -> Option<(IpAddr, u16)> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(addr) = SocketAddr::from_str(s) {
        return Some((addr.ip(), addr.port()));
    }
    if let Ok(ip) = IpAddr::from_str(s) {
        return Some((ip, default_port));
    }
    if let Some((ip, port)) = s.rsplit_once(':') {
        return Some((
            IpAddr::from_str(ip.trim_matches(['[', ']'])).ok()?,
            port.parse().ok()?,
        ));
    }
    None
}

#[test]
fn parse_socket_addr_with_port() {
    let got = parse_target("127.0.0.1:8080", 443).unwrap();
    assert_eq!(got.0, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(got.1, 8080);
}

#[test]
fn parse_ip_only_uses_default_port() {
    let got = parse_target("8.8.8.8", 443).unwrap();
    assert_eq!(got.0, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert_eq!(got.1, 443);
}

#[test]
fn parse_ipv6_bracketed_with_port() {
    let got = parse_target("[::1]:8443", 443).unwrap();
    assert_eq!(got.0, IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(got.1, 8443);
}

#[test]
fn parse_ipv6_unbracketed_without_port() {
    let got = parse_target("2606:4700::1", 443).unwrap();
    assert_eq!(got.1, 443);
}

#[test]
fn parse_empty_string_returns_none() {
    assert!(parse_target("", 443).is_none());
    assert!(parse_target("   ", 443).is_none());
}

#[test]
fn parse_invalid_string_returns_none() {
    assert!(parse_target("definitely-not-valid", 443).is_none());
    assert!(parse_target("1.2.3.4.5.6", 443).is_none());
    assert!(parse_target("1.2.3.4:99999", 443).is_none());
}

#[test]
fn parse_ipv6_socket_addr_formal() {
    let got = parse_target("[2001:db8::1]:80", 443).unwrap();
    assert_eq!(got.1, 80);
}

#[test]
fn parse_trims_whitespace() {
    let got = parse_target("  1.1.1.1:443  ", 80).unwrap();
    assert_eq!(got.0, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
    assert_eq!(got.1, 443);
}

#[test]
fn parse_v6_with_colon_port_split() {
    let raw = "[fd00::1]:53";
    let (ip, port) = raw.rsplit_once(':').unwrap();
    let ip_clean = ip.trim_matches(['[', ']']);
    assert_eq!(ip_clean, "fd00::1");
    assert_eq!(port, "53");
}

#[test]
fn input_target_json_shape() {
    use serde::{Deserialize, Serialize};
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct InputTarget {
        ip: String,
        port: u16,
    }
    let it = InputTarget {
        ip: "104.18.241.5".into(),
        port: 443,
    };
    let json = serde_json::to_string(&it).unwrap();
    let back: InputTarget = serde_json::from_str(&json).unwrap();
    assert_eq!(back.ip, "104.18.241.5");
    assert_eq!(back.port, 443);
}

#[test]
fn json_input_array_of_strings() {
    let raw = r#"["1.1.1.1:443","1.0.0.1"]"#;
    let as_list: Vec<String> = serde_json::from_str(raw).unwrap();
    assert_eq!(as_list.len(), 2);
}

#[test]
fn json_input_array_of_objects() {
    let raw = r#"[{"ip":"8.8.8.8","port":53}]"#;
    #[derive(Debug, Clone, serde::Deserialize)]
    struct InputTarget {
        #[allow(dead_code)]
        ip: String,
        #[allow(dead_code)]
        port: u16,
    }
    let as_list: Vec<InputTarget> = serde_json::from_str(raw).unwrap();
    assert_eq!(as_list.len(), 1);
}