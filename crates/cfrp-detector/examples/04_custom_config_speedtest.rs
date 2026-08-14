//! Example 04 — 自定义 DetectorConfig + 速度测试开启
//!
//! 运行: cargo run --example 04_custom_config_speedtest -p cfrp-detector
//! 联网: ✅ 需要 (且测速会下载若干 KB 数据, 消耗少量带宽)
//!
//! 演示重点:
//!   ✓ 调整并发 (max_concurrency)
//!   ✓ 自定义 SNI/域名 / User-Agent / 超时
//!   ✓ 启用 ResourceGovernor 并调 FD 安全预留
//!   ✓ 启用 TLS Session 缓存 + 0-RTT
//!   ✓ 注册 SpeedTester 并在检测后测速

use cfrp_detector::{
    AdaptiveConfig, BatchResult, BatchTarget, ConnectorConfig, Detector, DetectorConfig,
    ProbeConfig, SpeedTestConfig, SpeedTester, Target,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn build_cfg() -> DetectorConfig {
    let mut cfg = DetectorConfig::default();

    // 1. 探测层
    cfg.probe = ProbeConfig {
        connect_timeout: Duration::from_millis(1500),
        request_timeout: Duration::from_secs(4),
        user_agent: "cfrp-detector-example/0.4 +https://github.com/fireinrain/cfrp-detector".into(),
        default_sni: "speed.cloudflare.com".into(), // SNI / Host 头
        tls_session_cache: true,
        tls_session_cache_size: 1024,
        allow_0rtt_speedtest: true, // 允许 0-RTT
        accept_invalid_certs: false,
    };

    // 2. 并发层
    cfg.max_concurrency = 8;
    cfg.governor_enabled = true;
    cfg.governor.user_max_concurrency = 8;
    cfg.governor.fd_safety_headroom = 64;

    // 3. 自适应并发 (演示 AIMD 参数)
    //    注意: AdaptiveConfig 是在 detect_batch_with_progress 内部单独使用的,
    //    这里展示字段含义, 实际通过参数传入.
    let _demo = AdaptiveConfig {
        enabled: true,
        initial: 4,
        min: 1,
        max: 32,
        window: 8,
    };

    cfg
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_run())
}

async fn async_run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cfg = build_cfg();
    println!("🔧 自定义 DetectorConfig:");
    println!("   SNI/Host        = {}", cfg.probe.default_sni);
    println!("   RequestTimeout  = {:?}", cfg.probe.request_timeout);
    println!("   并发上限        = {}", cfg.max_concurrency);
    println!(
        "   TLS Session     = {} (size={})",
        cfg.probe.tls_session_cache, cfg.probe.tls_session_cache_size
    );
    println!("   0-RTT 测速      = {}", cfg.probe.allow_0rtt_speedtest);
    println!("   Governor        = {}", cfg.governor_enabled);
    println!();

    let concurrency = cfg.max_concurrency;
    let detector = Detector::new(cfg.clone()).await?;

    // 选取一批 CF 公共 IP 做测速
    let raw_targets = vec![
        Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        Target::new(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 443),
        Target::new(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)), 443),
    ];
    let targets: Vec<BatchTarget> = raw_targets
        .clone()
        .into_iter()
        .enumerate()
        .map(|(i, t)| BatchTarget { target: t, id: i })
        .collect();

    // ---------- 第一步: 边缘检测 ----------
    println!("📡 Phase 1/2 — Cloudflare 边缘探测:");
    let results: Vec<BatchResult> = detector.detect_batch(&targets, None, concurrency).await;

    // 收集 is_usable=true 的边缘节点作为测速候选
    let candidates: Vec<Target> = results
        .iter()
        .filter(|r| r.result.as_ref().map(|x| x.is_usable).unwrap_or(false))
        .map(|r| r.target.clone())
        .collect();
    println!(
        "   → {}/{} 候选节点进入测速\n",
        candidates.len(),
        raw_targets.len()
    );

    if candidates.is_empty() {
        println!("⚠️  没有可用节点, 跳过测速 (可能网络受限)");
        return Ok(());
    }

    // ---------- 第二步: 速度测试 ----------
    println!("⚡ Phase 2/2 — 下载测速 (下载路径 /cdn-cgi/trace, 多线程并发连接):");
    let st_cfg = SpeedTestConfig {
        timeout: Duration::from_secs(5),
        threads_per_target: 3, // 单目标并发连接
        concurrency: 2,        // 目标间并行
    };
    println!(
        "   配置: timeout={:?}, threads_per_target={}, concurrency={}\n",
        st_cfg.timeout, st_cfg.threads_per_target, st_cfg.concurrency
    );

    // 构造 SpeedTester: 从 ProbeConfig 映射到 ConnectorConfig
    let mut connector_cfg = ConnectorConfig::default();
    connector_cfg.connect_timeout = cfg.probe.connect_timeout;
    connector_cfg.request_timeout = cfg.probe.request_timeout;
    connector_cfg.accept_invalid_certs = cfg.probe.accept_invalid_certs;
    connector_cfg.user_agent = cfg.probe.user_agent.clone();
    connector_cfg.tls_session_cache = cfg.probe.tls_session_cache;
    connector_cfg.tls_session_cache_size = cfg.probe.tls_session_cache_size;
    connector_cfg.tls_session_cache_max_entries = cfg.probe.tls_session_cache_size;
    connector_cfg.enable_0rtt = cfg.probe.allow_0rtt_speedtest;
    let tester = SpeedTester::new(
        connector_cfg,
        true,
        cfg.probe.default_sni.clone(),
        cfg.probe.default_sni.clone(),
    )?;
    let speed_results = tester
        .test_batch(&candidates, "/cdn-cgi/trace", &st_cfg)
        .await;

    println!("{:<22} {:>10}  {:>10}", "TARGET", "BPS", "ELAPSED");
    println!("{}", "-".repeat(60));

    for (t, sr) in candidates.iter().zip(speed_results.iter()) {
        let key = format!("{}:{}", t.ip, t.port);
        println!(
            "{:<22} {:>8.1} MB/s  {:>7.1}s",
            key,
            sr.bytes_per_second as f64 / 1_000_000.0,
            sr.elapsed.as_secs_f64()
        );
        println!(
            "  ↳ TCP={:?}  TLS={:?}  TTFB={:?}",
            sr.connect_latency,
            sr.tls_handshake_latency.unwrap_or_default(),
            sr.ttfb_latency
        );
    }
    Ok(())
}
