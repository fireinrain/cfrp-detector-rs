use cfrp_detector::{CidrSource, CloudflareRanges};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn from_vec_handles_empty_list() {
    let r = CloudflareRanges::from(vec![]);
    assert!(!r.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

#[test]
fn from_vec_handles_whitespace_in_cidr() {
    let r = CloudflareRanges::from(vec!["  10.0.0.0/8  ".to_string()]);
    assert!(r.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(!r.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
}

#[test]
fn multiple_v4_ranges_all_active() {
    let r = CloudflareRanges::from(vec![
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "192.168.0.0/16".to_string(),
    ]);
    assert!(r.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 254))));
    assert!(r.contains(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254))));
    assert!(r.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 254))));
    assert!(!r.contains(IpAddr::V4(Ipv4Addr::new(9, 255, 255, 255))));
}

#[test]
fn multiple_v6_ranges_all_active() {
    let r = CloudflareRanges::from(vec!["2001:db8::/32".to_string(), "fc00::/7".to_string()]);
    assert!(r.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    assert!(r.contains(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(!r.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))));
}

#[test]
fn cidr_31_prefix_v4_two_hosts() {
    let r = CloudflareRanges::from(vec!["192.168.1.4/31".to_string()]);
    assert!(r.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4))));
    assert!(r.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));
    assert!(!r.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))));
    assert!(!r.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6))));
}

#[test]
fn cidr_127_prefix_v6_two_hosts() {
    let r = CloudflareRanges::from(vec!["fd00::1/127".to_string()]);
    assert!(r.contains(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0))));
    assert!(r.contains(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
    assert!(!r.contains(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2))));
    assert!(!r.contains(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3))));
}

#[test]
fn clone_of_ranges_shares_state() {
    let r1 = CloudflareRanges::from(vec!["10.0.0.0/8".to_string()]);
    let r2 = r1.clone();
    assert!(r2.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    drop(r1);
    assert!(r2.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
}
