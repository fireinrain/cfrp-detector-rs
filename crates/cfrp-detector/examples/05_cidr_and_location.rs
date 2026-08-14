//! Example 05 — 纯离线功能: Cloudflare CIDR 归属 + Colo → 地理位置查询
//!
//! 运行: cargo run --example 05_cidr_and_location -p cfrp-detector
//! 联网: ❌ 不需要 (所有数据来自内置表 + 本地缓存文件, 首次自动加载)
//!
//! ✅ 这是 CI 安全 / 离线环境下最适合跑的 example (无外部 IO, 无网络失败可能)

use cfrp_detector::{CidrSource, CloudflareRanges, LocationSource, LocationStore};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn main() -> anyhow::Result<()> {
    // ========== A. CIDR 归属判断 ==========
    println!("═══════════════════════════════════════════════════");
    println!(" Part A · Cloudflare IP 范围归属判断 (空表 + 手动注入常见段)");
    println!("═══════════════════════════════════════════════════\n");

    // 因为离线 example 不创建 reqwest client + 不访问网络,
    // 这里构造一个 ranges 对象并手动装入一些常见 CF 段, 用于演示 contains() API.
    let manual_cidrs = cfrp_detector::CloudflareCidrs {
        fetched_at: None,
        source: "example-builtin".into(),
        ipv4: vec![
            "1.1.1.0/24".into(),      // CF DNS v4
            "1.0.0.0/24".into(),      // CF DNS v4 次级
            "104.16.0.0/12".into(),   // 经典 CF 公共段
            "172.64.0.0/13".into(),   // CF 另一大段
            "103.21.244.0/22".into(), // CF APAC
        ],
        ipv6: vec![
            "2606:4700::/32".into(), // CF DNS v6
            "2400:cb00::/32".into(), // CF v6 段
            "2803:f800::/32".into(), // CF v6 段
        ],
    };
    let ranges = CloudflareRanges::from_cidrs(manual_cidrs);
    println!("✅ 已加载示例 IPv4 CIDRs: 5 条 (手动内置)");
    println!("✅ 已加载示例 IPv6 CIDRs: 3 条 (手动内置)\n");

    let ip_cases: Vec<(IpAddr, bool, &str)> = vec![
        // (IP, 是否属于 CF, 说明)
        (
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            true,
            "Cloudflare 公共 DNS",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(104, 16, 0, 1)),
            true,
            "典型 CF 104.16/12 段",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(172, 67, 0, 1)),
            true,
            "典型 CF 172.64/13 段",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            false,
            "Google DNS (非 CF)",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            false,
            "APNIC 实验段",
        ),
        (
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0x1111, 1)),
            true,
            "CF DNS IPv6 2606:4700::/32",
        ),
        (
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0x8888, 0x8888)),
            false,
            "Google DNS IPv6",
        ),
    ];

    println!("{:<50} {:<8} NOTES", "IP", "CF?");
    println!("{}", "-".repeat(90));
    let mut hit = 0usize;
    for (ip, expected, note) in &ip_cases {
        let actual = ranges.contains(*ip);
        let ok = if actual == *expected {
            "✅"
        } else {
            "❌ MISMATCH"
        };
        println!(
            "{:<50} {:<8} [{}] {}",
            ip.to_string(),
            if actual { "YES" } else { "no" },
            ok,
            note
        );
        if actual == *expected {
            hit += 1;
        }
    }
    println!("\nCIDR 归属测试: {}/{} 通过\n", hit, ip_cases.len());

    // ========== B. 机场码 → 地理位置查询 ==========
    println!("═══════════════════════════════════════════════════");
    println!(" Part B · Colo 三字码 → 地理位置 (示例离线, 显示空 + 接口说明)");
    println!("═══════════════════════════════════════════════════\n");

    // 离线环境下 LocationStore::empty() 创建空表, 所有 lookup 返回 None.
    // 真实使用时调用 LocationStore::load(client, cache).await 从缓存/网络填充.
    let loc = LocationStore::empty();
    println!("ℹ️  离线示例: LocationStore 为空 (未加载反查表)");
    println!("   → 生产代码: let loc = LocationStore::load(&client, &cache).await?;\n");

    let colos = [
        "LAX", "SFO", "DFW", "IAD", "JFK", "YYZ", "LHR", "CDG", "FRA", "AMS", "MAD", "WAW", "IST",
        "DXB", "NRT", "HND", "KIX", "ICN", "SIN", "HKG", "BKK", "SYD", "GRU", "JNB", "SJC", "PEK",
        "SHA", "CAN",
    ];

    println!(
        "{:<8} {:<20} {:<16} {:<18} NOTES",
        "CODE", "CITY", "REGION", "COUNTRY"
    );
    println!("{}", "-".repeat(100));
    let mut found = 0usize;
    for code in colos {
        match loc.lookup(code) {
            Some(info) => {
                println!(
                    "{:<8} {:<20} {:<16} {:<18} ✓",
                    code,
                    info.city.as_str(),
                    info.region.as_str(),
                    info.cca2.as_str()
                );
                found += 1;
            }
            None => println!(
                "{:<8} {:<20} {:<16} {:<18} (离线空表 → 未命中)",
                code, "-", "-", "-"
            ),
        }
    }
    println!(
        "\n地理位置查询: {}/{} 命中 (预期 0, 离线示例)",
        found,
        colos.len()
    );

    // C. 演示: 拿 A 部分中判定为 CF 的 IP → 模拟 trace body colo 命中查位置
    println!("\n═══════════════════════════════════════════════════");
    println!(" Part C · 串联: IP∈CF CIDR + 假设 colo=LAX → 完整地理");
    println!("═══════════════════════════════════════════════════\n");
    let ip = IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229));
    println!("目标 IP: {}", ip);
    println!(
        "  CIDR 命中? → {}",
        if ranges.contains(ip) {
            "✅ 属于 Cloudflare"
        } else {
            "❌ 非 Cloudflare"
        }
    );
    println!("  说明: 真实场景中判定为边缘后, 会请求 /cdn-cgi/trace 拿到 colo=XXX");
    println!("        然后调用 LocationStore::lookup(\"XXX\") 反查城市/国家等信息");
    Ok(())
}
