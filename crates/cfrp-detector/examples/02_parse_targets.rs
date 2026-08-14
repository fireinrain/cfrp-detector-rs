//! Example 02 — parse_target 字符串格式解析
//!
//! 运行: cargo run --example 02_parse_targets -p cfrp-detector
//! 联网: ❌ 不需要 (纯字符串解析, 非常适合离线 smoke test)

use cfrp_detector::parse_target;

fn main() {
    let cases = [
        // (用户输入, 默认端口, 期望简述)
        ("1.1.1.1", 443, "IPv4 无端口 → 默认 443"),
        ("1.1.1.1:80", 443, "IPv4 有显式端口 80"),
        ("8.8.8.8:53", 443, "IPv4 DNS 端口"),
        ("104.16.132.229:443", 443, "IPv4 完整地址"),
        (
            "[2606:4700::1111]:443",
            443,
            "IPv6 方括号 + 端口 (标准写法)",
        ),
        ("2606:4700::1111", 8443, "IPv6 无端口 → 默认 8443"),
        ("192.168.1.1:65535", 443, "端口上限 65535"),
        ("1.1.1.1:0", 443, "端口 0"),
        ("[::1]", 443, "IPv6 方括号无端口 → 默认端口"),
    ];

    println!("{:<40} {:<6} {:<10} NOTES", "INPUT", "DEF", "RESULT");
    println!("{}", "-".repeat(100));

    let mut pass = 0usize;
    for (raw, def, note) in cases {
        match parse_target(raw, def) {
            Ok(t) => {
                println!(
                    "{:<40} {:<6} {:<10} {}:{}  ✓ {}",
                    format!("{:?}", raw),
                    def,
                    "OK",
                    t.ip,
                    t.port,
                    note
                );
                pass += 1;
            }
            Err(e) => {
                println!(
                    "{:<40} {:<6} {:<10} {:?}  ✗ {}",
                    format!("{:?}", raw),
                    def,
                    "ERR",
                    e,
                    note
                );
            }
        }
    }
    println!("\n✅ {}/{} cases parsed 无错误", pass, cases.len());

    // ---------- 错误场景演示 ----------
    println!("\n--- 以下 case 都会返回 Err ---");
    let bad_cases = [
        ("not-an-ip", "无效字符串"),
        ("1.1.1.1:99999", "端口越界 > 65535"),
        ("1.2.3.4.5", "错误 IPv4 格式"),
        ("", "空字符串"),
        ("   # comment line", "注释行"),
    ];
    for (b, note) in bad_cases {
        match parse_target(b, 443) {
            Ok(t) => println!(
                "  {:<25} → (意外成功) {}:{}  ({})",
                format!("{:?}", b),
                t.ip,
                t.port,
                note
            ),
            Err(e) => println!("  {:<25} → 预期错误: {}  ({})", format!("{:?}", b), e, note),
        }
    }
}
