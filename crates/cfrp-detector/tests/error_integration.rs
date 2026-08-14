use cfrp_detector::{DetectorError, Result};
use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

#[test]
fn invalid_target_from_string_parsing_failure() {
    let _e = DetectorError::InvalidTarget("1..1::555".into());
}

#[test]
fn invalid_ip_from_parse_failure() {
    let res = IpAddr::from_str("not an ip");
    assert!(res.is_err());
    let e = DetectorError::InvalidIp("not an ip".into());
    assert!(format!("{}", e).contains("invalid IP address"));
}

#[test]
fn invalid_port_message_shows_value() {
    let e = DetectorError::InvalidPort(65535);
    assert!(e.to_string().contains("65535"));
}

#[test]
fn detector_error_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DetectorError>();
}

#[test]
fn detector_error_is_std_error() {
    let e: Box<dyn Error> = DetectorError::Http("boom".into()).into();
    assert!(e.to_string().contains("boom"));
}

#[test]
fn io_into_error_is_idiomatic() {
    let io = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
    let e: DetectorError = io.into();
    let msg = e.to_string();
    assert!(msg.starts_with("I/O error:"));
    assert!(msg.contains("denied"));
}

#[test]
fn json_into_error() {
    let res: std::result::Result<serde_json::Value, _> =
        serde_json::from_str("{ missing: value }");
    let json_err = res.unwrap_err();
    let e: DetectorError = json_err.into();
    assert!(format!("{e}").contains("JSON error"));
}

#[test]
fn result_alias_box_error_works() {
    fn fallible(ok: bool) -> Result<i32> {
        if ok {
            Ok(42)
        } else {
            Err(DetectorError::InvalidTarget("bad".into()))
        }
    }
    assert_eq!(fallible(true).unwrap(), 42);
    let err = fallible(false).unwrap_err();
    assert!(matches!(err, DetectorError::InvalidTarget(_)));
}

#[test]
fn socketaddr_from_str_valid_v4() {
    let sa = SocketAddr::from_str("127.0.0.1:443").unwrap();
    assert_eq!(sa.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(sa.port(), 443);
}

#[test]
fn socketaddr_from_str_invalid_propagates() {
    let sa = SocketAddr::from_str("not a socket addr");
    assert!(sa.is_err());
}