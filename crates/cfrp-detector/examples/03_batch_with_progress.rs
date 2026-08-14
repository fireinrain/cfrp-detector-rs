//! Example 03 — 批量探测 + indicatif 风格进度回调 + 统计汇总
//!
//! 运行: cargo run --example 03_batch_with_progress -p cfrp-detector -- 100
//!       (最后的 100 是目标数量, 默认 20)
//! 联网: ✅ 需要

use std::net::{IpAddr, Ipv4Addr};
use cfrp_detector::{AdaptiveConfig, BatchProgress, BatchTarget, Detector, DetectorConfig, Target};

fn build_demo_targets(n: usize) -> Vec<BatchTarget> {
    // 构造一批目标: 实际 CF 范围内常用的不同 IP
    // 注意: 这里用常见 CF 网段合成, 不是都真实可达
    let pool = [
        (104, 16, 132), (104, 18, 100), (172, 67, 73),
        (1, 1, 1), (1, 0, 0), (104, 21, 0),
    ];
    (0..n).enumerate().map(|(id, i)| {
        let p = pool[i % pool.len()];
        let d = (i / pool.len()) as u8;
        let ip = IpAddr::V4(Ipv4Addr::new(p.0, p.1, p.2, 1u8.wrapping_add(d)));
        BatchTarget { target: Target::new(ip, 443), id }
    }).collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).init();

    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let targets = build_demo_targets(n);
    println!("🚀 准备探测 {} 个目标 (并发默认, governor 开)\n", targets.len());

    let cfg = DetectorConfig::default();
    let concurrency = cfg.max_concurrency;
    let detector = Detector::new(cfg).await?;

    // 进度回调: 每隔一段时间打印一行状态
    let start = std::time::Instant::now();
    let cb = move |p: BatchProgress| {
        let total = p.total;
        let pct = if total > 0 { (p.completed as f64 / total as f64) * 100.0 } else { 0.0 };
        // 每完成 5 个 或 全部完成 时刷新
        if p.completed == total || p.completed % 5 == 0 {
            eprintln!(
                "  [{:>3.0}%] {:>width$}/{total}  活跃并发={:>3}  已用时={:>5.1}s",
                pct, p.completed, p.current_concurrency,
                start.elapsed().as_secs_f64(),
                width = total.to_string().len());
        }
    };

    let results = detector.detect_batch_with_progress(&targets, Option::<&str>::None, concurrency, AdaptiveConfig::default(), cb).await;

    // ============ 统计汇总 ============
    let total = results.len();
    let success = results.iter().filter(|r| r.result.is_some()).count();
    let errors  = results.iter().filter(|r| r.error.is_some()).count();
    let edges   = results.iter().filter(|r| r.result.as_ref().map(|x|x.is_cloudflare_edge).unwrap_or(false)).count();
    let usable  = results.iter().filter(|r| r.result.as_ref().map(|x|x.is_usable).unwrap_or(false)).count();

    // 平均/中位数延迟 (仅 CF 边缘节点)
    let mut lats: Vec<u128> = results.iter()
        .filter_map(|r| r.result.as_ref()?.edge_info.as_ref()?.latency)
        .map(|d| d.as_millis())
        .collect();
    lats.sort_unstable();
    let p50 = lats.get(lats.len()/2).copied().unwrap_or(0);
    let avg = if lats.is_empty() { 0 } else { lats.iter().sum::<u128>() / lats.len() as u128 };

    // 置信度分布
    use cfrp_detector::Confidence::{High, Medium, Low};
    let mut cnt = [0usize; 4];
    for r in &results {
        if let Some(res) = &r.result {
            match res.confidence {
                High                           => cnt[0] += 1,
                Medium                         => cnt[1] += 1,
                Low                            => cnt[2] += 1,
                cfrp_detector::Confidence::None => cnt[3] += 1,
            }
        }
    }

    // Colo Top-5
    use std::collections::HashMap;
    let mut colos: HashMap<String, usize> = HashMap::new();
    for r in &results {
        if let Some(c) = r.result.as_ref()
            .and_then(|x| x.edge_info.as_ref())
            .and_then(|x| x.colo_code.as_ref()) {
            *colos.entry(c.clone()).or_default() += 1;
        }
    }
    let mut colo_v: Vec<_> = colos.into_iter().collect();
    colo_v.sort_by(|a,b| b.1.cmp(&a.1));

    println!("\n═══════════════════════ 探测结果汇总 ═══════════════════════");
    println!("  总目标数        : {total}");
    println!("  ✅ 探测成功    : {success}  ({:.1}%)", success as f64/total as f64*100.0);
    println!("  ❌ 探测失败    : {errors}");
    println!("  🌩  判定为 CF 边: {edges}");
    println!("  🟢 判定为可使用 : {usable}");
    println!("  ┌ 置信度分布: HIGH={} / MEDIUM={} / LOW={} / NONE={}", cnt[0], cnt[1], cnt[2], cnt[3]);
    println!("  ├ 延迟 (仅边缘): 平均 {avg}ms  |  中位数 P50 = {p50}ms");
    println!("  └ Top-5 COLO   : {}",
        if colo_v.is_empty() { "无".into() }
        else { colo_v.iter().take(5).map(|(c,n)| format!("{c}x{n}")).collect::<Vec<_>>().join(", ") });
    println!("  总耗时          : {:.2}s", start.elapsed().as_secs_f64());
    println!("═══════════════════════════════════════════════════════════");

    Ok(())
}