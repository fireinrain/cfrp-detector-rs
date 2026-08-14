//! Example 01 — 最小可运行的 Cloudflare 边缘检测
//!
//! 运行: cargo run --example 01_basic_detect -p cfrp-detector
//! 联网: ✅ 需要 (真实访问 1.1.1.1 等公网目标)

use cfrp_detector::{BatchTarget, Detector, DetectorConfig, Target};
use std::net::{IpAddr, Ipv4Addr};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    let cfg = DetectorConfig::default();
    println!(
        "🧪 默认 DetectorConfig: 并发={}, 超时={:?}, governor={}",
        cfg.max_concurrency,
        cfg.probe.request_timeout,
        if cfg.governor_enabled { "开" } else { "关" }
    );
    println!();

    let concurrency = cfg.max_concurrency;
    let detector = Detector::new(cfg).await?;

    // 典型目标: CF DNS, CF 官网 A, Google DNS(反例)
    let targets: Vec<BatchTarget> = vec![
        Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        Target::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 443),
        Target::new(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)), 443),
        Target::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, t)| BatchTarget { target: t, id: i })
    .collect();

    println!("🔎 开始探测 {} 个目标...\n", targets.len());
    let results = detector.detect_batch(&targets, None, concurrency).await;

    println!(
        "{:<24} {:<8} {:<6} {:<6} {:<10} {}",
        "IP:PORT", "EDGE?", "TLS?", "OK?", "CONF", "COLO / LATENCY"
    );
    println!("{}", "-".repeat(85));

    for r in &results {
        let t = &r.target;
        let key = format!("{}:{}", t.ip, t.port);
        match (&r.result, &r.error) {
            (Some(res), _) => {
                let colo = res
                    .edge_info
                    .as_ref()
                    .and_then(|e| e.colo_code.clone())
                    .unwrap_or("-".into());
                let lat = res
                    .edge_info
                    .as_ref()
                    .and_then(|e| e.latency)
                    .map(|d| format!("{}ms", d.as_millis()))
                    .unwrap_or("-".into());
                let conf = format!("{:?}", res.confidence).to_uppercase();
                println!(
                    "{:<24} {:<8} {:<6} {:<6} {:<10} {} / {}",
                    key,
                    yn(res.is_cloudflare_edge),
                    yn(res.is_tls),
                    yn(res.is_usable),
                    conf,
                    colo,
                    lat
                );
                if !res.reasons.is_empty() {
                    println!("  ↳ 特征: {}", res.reasons.join("; "));
                }
            }
            (None, Some(e)) => println!("{:<24} ❌ 失败: {}", key, e),
            _ => println!("{:<24} ⚠️ 无结果", key),
        }
    }
    let n_edge = results
        .iter()
        .filter(|r| {
            r.result
                .as_ref()
                .map(|x| x.is_cloudflare_edge)
                .unwrap_or(false)
        })
        .count();
    println!(
        "\n📊 {}/{} 目标判定为 Cloudflare 边缘",
        n_edge,
        results.len()
    );
    Ok(())
}
fn yn(v: bool) -> &'static str {
    if v { "✅" } else { "·" }
}
