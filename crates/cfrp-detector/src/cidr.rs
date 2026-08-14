use crate::{FileCache, Result};
use parking_lot::RwLock;
use std::{net::IpAddr, sync::Arc, time::Duration};

const IPV4_URL: &str = "https://www.cloudflare.com/ips-v4";
const IPV6_URL: &str = "https://www.cloudflare.com/ips-v6";

pub trait CidrSource: Send + Sync {
    fn contains(&self, ip: IpAddr) -> bool;
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CloudflareCidrs {
    pub fetched_at: Option<u64>,
    pub source: String,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CloudflareRanges {
    v4: Arc<RwLock<Vec<netip::IpNetLike>>>,
    v6: Arc<RwLock<Vec<netip::IpNetLike>>>,
}

// Local compact CIDR representation; avoids another dependency just for membership.
mod netip {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    #[derive(Debug, Clone)]
    pub enum IpNetLike {
        V4(Ipv4Addr, u8),
        V6(Ipv6Addr, u8),
    }
    impl IpNetLike {
        pub fn parse(s: &str) -> Option<Self> {
            let (ip, bits) = s.trim().split_once('/')?;
            let bits: u8 = bits.parse().ok()?;
            match IpAddr::from_str(ip).ok()? {
                IpAddr::V4(v) if bits <= 32 => Some(Self::V4(v, bits)),
                IpAddr::V6(v) if bits <= 128 => Some(Self::V6(v, bits)),
                _ => None,
            }
        }
        pub fn contains(&self, ip: IpAddr) -> bool {
            match (self, ip) {
                (Self::V4(net, p), IpAddr::V4(ip)) => {
                    let mask = if *p == 0 {
                        0
                    } else {
                        u32::MAX << (32 - *p as u32)
                    };
                    u32::from(ip) & mask == u32::from(*net) & mask
                }
                (Self::V6(net, p), IpAddr::V6(ip)) => {
                    let a = u128::from_be_bytes(ip.octets());
                    let b = u128::from_be_bytes(net.octets());
                    let mask = if *p == 0 {
                        0
                    } else {
                        u128::MAX << (128 - *p as u32)
                    };
                    a & mask == b & mask
                }
                _ => false,
            }
        }
    }
}

impl CloudflareRanges {
    pub fn empty() -> Self {
        Self {
            v4: Arc::new(RwLock::new(Vec::new())),
            v6: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn from_cidrs(cidrs: CloudflareCidrs) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for s in cidrs.ipv4 {
            if let Some(p) = netip::IpNetLike::parse(&s) {
                v4.push(p);
            }
        }
        for s in cidrs.ipv6 {
            if let Some(p) = netip::IpNetLike::parse(&s) {
                v6.push(p);
            }
        }
        Self {
            v4: Arc::new(RwLock::new(v4)),
            v6: Arc::new(RwLock::new(v6)),
        }
    }

    pub async fn load(client: &reqwest::Client, cache: &FileCache) -> Result<Self> {
        let (v4, v6) = tokio::try_join!(
            Self::load_one(client, cache, "ips-v4", IPV4_URL),
            Self::load_one(client, cache, "ips-v6", IPV6_URL),
        )?;
        Ok(Self {
            v4: Arc::new(RwLock::new(v4)),
            v6: Arc::new(RwLock::new(v6)),
        })
    }

    async fn load_one(
        client: &reqwest::Client,
        cache: &FileCache,
        prefix: &str,
        url: &str,
    ) -> Result<Vec<netip::IpNetLike>> {
        let data = cache
            .load_or_fetch(
                prefix,
                ".txt",
                url,
                Duration::from_secs(7 * 24 * 3600),
                client,
            )
            .await?;
        Ok(String::from_utf8_lossy(&data)
            .lines()
            .filter_map(netip::IpNetLike::parse)
            .collect())
    }
}

impl CidrSource for CloudflareRanges {
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.v4.read().iter().any(|p| p.contains(ip)),
            IpAddr::V6(_) => self.v6.read().iter().any(|p| p.contains(ip)),
        }
    }
}

impl From<Vec<String>> for CloudflareRanges {
    fn from(value: Vec<String>) -> Self {
        let r = Self::empty();
        let mut v4 = r.v4.write();
        let mut v6 = r.v6.write();
        for s in value {
            if let Some(p) = netip::IpNetLike::parse(&s) {
                match p {
                    netip::IpNetLike::V4(_, _) => v4.push(p),
                    netip::IpNetLike::V6(_, _) => v6.push(p),
                }
            }
        }
        drop(v4);
        drop(v6);
        r
    }
}

impl Default for CloudflareRanges {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn cidr_membership_works_for_v4_and_v6() {
        let ranges =
            CloudflareRanges::from(vec!["1.1.0.0/16".to_string(), "2606:4700::/32".to_string()]);
        assert!(ranges.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!ranges.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 1, 1))));
        assert!(ranges.contains(IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1))));
        assert!(!ranges.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn cidr_ipnet_parse_valid_v4() {
        let n = netip::IpNetLike::parse("10.0.0.0/8").unwrap();
        assert!(n.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 1))));
        assert!(!n.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn cidr_ipnet_parse_valid_v6() {
        let n = netip::IpNetLike::parse("::1/128").unwrap();
        assert!(n.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!n.contains(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn cidr_ipnet_parse_single_host_v4() {
        let n = netip::IpNetLike::parse("192.168.1.1/32").unwrap();
        assert!(n.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!n.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
    }

    #[test]
    fn cidr_ipnet_parse_zero_prefix_v4() {
        let n = netip::IpNetLike::parse("0.0.0.0/0").unwrap();
        assert!(n.contains(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(n.contains(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn cidr_ipnet_parse_zero_prefix_v6() {
        let n = netip::IpNetLike::parse("::/0").unwrap();
        assert!(n.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(n.contains(IpAddr::V6(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8))));
    }

    #[test]
    fn cidr_ipnet_parse_rejects_invalid() {
        assert!(netip::IpNetLike::parse("not-a-cidr").is_none());
        assert!(netip::IpNetLike::parse("10.0.0.1").is_none());
        assert!(netip::IpNetLike::parse("10.0.0.0/33").is_none());
        assert!(netip::IpNetLike::parse("::1/129").is_none());
        assert!(netip::IpNetLike::parse("::1/-1").is_none());
    }

    #[test]
    fn cidr_cloudflare_ranges_empty() {
        let r = CloudflareRanges::empty();
        assert!(!r.contains(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!r.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn cidr_cloudflare_ranges_default_is_empty() {
        let r = CloudflareRanges::default();
        assert!(!r.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn cidr_from_vec_ignores_invalid() {
        let ranges = CloudflareRanges::from(vec![
            "valid garbage".to_string(),
            "172.16.0.0/12".to_string(),
            "not a cidr".to_string(),
        ]);
        assert!(ranges.contains(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!ranges.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn cidr_v4_v6_cross_mismatch_returns_false() {
        let ranges = CloudflareRanges::from(vec!["10.0.0.0/8".to_string()]);
        assert!(!ranges.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let v6only = CloudflareRanges::from(vec!["fd00::/8".to_string()]);
        assert!(!v6only.contains(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn cidr_boundary_network_address() {
        let r = CloudflareRanges::from(vec!["192.168.1.0/24".to_string()]);
        assert!(r.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))));
    }

    #[test]
    fn cidr_boundary_broadcast_address() {
        let r = CloudflareRanges::from(vec!["192.168.1.0/24".to_string()]);
        assert!(r.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))));
    }

    #[test]
    fn cidr_boundary_outside_prefix() {
        let r = CloudflareRanges::from(vec!["192.168.1.0/24".to_string()]);
        assert!(!r.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 0))));
    }

    proptest! {
        #[test]
        fn prop_v4_zero_prefix_contains_all_ips(ip in any::<Ipv4Addr>()) {
            let n = netip::IpNetLike::parse("0.0.0.0/0").unwrap();
            prop_assert!(n.contains(IpAddr::V4(ip)));
        }

        #[test]
        fn prop_v6_zero_prefix_contains_all_ips(ip in any::<Ipv6Addr>()) {
            let n = netip::IpNetLike::parse("::/0").unwrap();
            prop_assert!(n.contains(IpAddr::V6(ip)));
        }

        #[test]
        fn prop_v4_self_32_contains_self(ip in any::<Ipv4Addr>()) {
            let s = format!("{}/32", ip);
            let n = netip::IpNetLike::parse(&s).unwrap();
            prop_assert!(n.contains(IpAddr::V4(ip)));
        }

        #[test]
        fn prop_v6_self_128_contains_self(ip in any::<Ipv6Addr>()) {
            let s = format!("{}/128", ip);
            let n = netip::IpNetLike::parse(&s).unwrap();
            prop_assert!(n.contains(IpAddr::V6(ip)));
        }

        #[test]
        fn prop_cidr_parse_does_not_panic(s in "\\PC*") {
            let _ = netip::IpNetLike::parse(&s);
        }

        #[test]
        fn prop_v4_24_boundary(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255) {
            let cidr = format!("{}.{}.{}.0/24", a, b, c);
            let n = netip::IpNetLike::parse(&cidr).unwrap();
            prop_assert!(n.contains(IpAddr::V4(Ipv4Addr::new(a, b, c, 0))));
            prop_assert!(n.contains(IpAddr::V4(Ipv4Addr::new(a, b, c, 255))));
            let outside = if c < 255 {
                Ipv4Addr::new(a, b, c + 1, 0)
            } else {
                Ipv4Addr::new(a, b, 0, 0)
            };
            let outside_cidr = format!("{}.{}.{}.0/24", a, b, if c < 255 { c + 1 } else { 0 });
            let n2 = netip::IpNetLike::parse(&outside_cidr).unwrap();
            prop_assert!(n2.contains(IpAddr::V4(outside)));
        }
    }
}
