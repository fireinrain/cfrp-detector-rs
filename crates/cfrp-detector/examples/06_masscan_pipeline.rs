//! Example 06 — MasscanScanner + MasscanPipeline 集成演示
//!
//! 运行 (需 root):  sudo -E cargo run --example 06_masscan_pipeline -p cfrp-detector
//! 联网: ✅ 需要 (需要 masscan 二进制 且 能发送原始 SYN 包)
//!
//! ⚠️  前置检查:
//!     1) $ which masscan              → 有结果 (或用 --masscan-bin 指定)
//!     2) masscan --version            → 能正常打印
//!     3) masscan 需要 CAP_NET_RAW     → 所以 example 建议 sudo
//!
//! 示例场景:
//!   • 单 ASN 扫描: 扫描 AS13335 (Cloudflare) 的 443 端口
//!   • 不实际探测 (演示参数构造流程 + 运行入口)

use std::net::Ipv4Addr;
use std::path::PathBuf;
use cfrp_detector::{
    MasscanConfig, MasscanScanner, MasscanPipeline, PipelineAsnTask,
    PipelineOptions,
};

fn main() -> anyhow::Result<()> {
    // ======= 0. 环境自检 (帮助用户 debug 常见问题) =======
    println!("🌐 Example 06 · masscan 流水线集成演示");
    println!("================================================\n");

    let is_root = match std::env::var("USER") {
        Ok(u) => u == "root",
        Err(_) => false,
    };
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        println!("⚠️  当前 EUID = {euid}, masscan 原始套接字模式通常需要 root.");
        println!("   → 如果你看到 'permission denied' 请用 sudo -E 重跑\n");
    } else {
        println!("✅ 当前以 root/EUID=0 运行, masscan 权限 OK\n");
    }
    let _ = is_root;

    // ======= 1. 构造 MasscanScanner =======
    let mut mcfg = MasscanConfig::new();
    // 如果系统中 masscan 不在 PATH, 可改这里:
    // mcfg.masscan_binary_path = Some(PathBuf::from("/usr/local/sbin/masscan"));
    mcfg.rate = 10_000;                 // 10k pps, 示例慢一点避免触发网络告警
    mcfg.wait_seconds = 5;              // 发包后等待 5s 接收回包
    mcfg.asn_cache_dir   = PathBuf::from("./_example_asn_cache");
    mcfg.iface_setting_file = PathBuf::from("./_example_iface.txt");
    // interface: None 让 Scanner 自动探测并写入 iface_setting_file

    let scanner = MasscanScanner::new(mcfg.clone());
    println!("🧭 MasscanScanner 构造完成:");
    println!("   rate            = {} pps", mcfg.rate);
    println!("   wait_seconds    = {}", mcfg.wait_seconds);
    println!("   asn_cache_dir   = {}", mcfg.asn_cache_dir.display());
    println!("   iface_setting   = {}", mcfg.iface_setting_file.display());

    // ======= 2. 可用性检查 =======
    match scanner.check_masscan_available() {
        Ok(path) => println!("✅ masscan 可执行: {}\n", path.display()),
        Err(e) => {
            println!("❌ masscan 不可用: {e}");
            println!("   请安装 masscan: macOS → brew install masscan ; Debian/Ubuntu → apt install masscan\n");
            // 仅示例, 不直接 panic 返回, 让用户看到下面的配置演示
            return Ok(());
        }
    }

    // ======= 3. 构造流水线 PipelineOptions =======
    let popts = PipelineOptions {
        domain: Some("cloudflare.com".to_string()),
        concurrency: 50,
        speedtest: false,                       // 示例关闭测速, 只开+存端口
        speedtest_threads: 3,
        speedtest_url_path: "/cdn-cgi/trace".into(),
        speedtest_concurrency: 8,
        adaptive_min: 10,
        adaptive_max: 200,
        probe_timeout_secs: 3,
        tls_session_cache: 256,
        output_dir: PathBuf::from("./_example_masscan_output"),
    };
    std::fs::create_dir_all(&popts.output_dir).ok();

    let pipeline = MasscanPipeline::new(popts.clone());
    println!("🏭 MasscanPipeline 构造完成:");
    println!("   domain          = {:?}", popts.domain);
    println!("   concurrency     = {}", popts.concurrency);
    println!("   speedtest       = {}", popts.speedtest);
    println!("   output_dir      = {}", popts.output_dir.display());

    // ======= 4. 实际运行: 两种模式 ==========
    //
    // 注意: 真正执行扫描比较耗时, 这里用 runtime + 交互式开关:
    //       通过环境变量 CFRP_EXAMPLE_RUN=1 时才真实运行, 否则只做 dry-run 打印

    let should_run = std::env::var("CFRP_EXAMPLE_RUN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false);

    if !should_run {
        println!();
        println!("──────────────────────────────────────────────────");
        println!(" 🔕 DRY-RUN 模式: 未设置 CFRP_EXAMPLE_RUN=1");
        println!("    将不执行真正的 masscan 发包, 仅打印任务参数.");
        println!("    如要真实扫描并检测, 请执行:");
        println!("      sudo -E CFRP_EXAMPLE_RUN=1 \\\n        cargo run --example 06_masscan_pipeline -p cfrp-detector");
        println!("──────────────────────────────────────────────────\n");

        // A. 构造一个单 IP 扫描任务 (Dry run: 打印预期命令参数)
        let demo_ip = std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        println!("📝 Task A · run_single_ip(ip={}, ports=\"443\", tls=true) [Dry-run]", demo_ip);
        println!("   → masscan 将会合成命令行, 扫描该 IP 443 端口");
        println!("   → 结果写入 {}/", popts.output_dir.display());
        println!("   → 然后对 open ports 执行 Cloudflare 检测\n");

        // B. 构造一个批量 ASN 任务列表 (Dry run)
        let batch = vec![
            PipelineAsnTask { asn: 13335, ports: "443".to_string(), tls: true },     // Cloudflare
            PipelineAsnTask { asn: 132203, ports: "443,8443".to_string(), tls: true }, // Tencent Cloud
        ];
        println!("📝 Task B · run_batch_asn 任务列表 [Dry-run]:");
        for t in &batch {
            println!("   • AS{}  ports={:<12}  tls={}", t.asn, t.ports, t.tls);
        }
        println!();

        // C. 演示: resolve_interface 逻辑 (可独立使用)
        match scanner.resolve_interface() {
            Ok(iface) => println!("🧭 自动检测/从缓存读取到网卡: {iface}"),
            Err(e) => println!("🧭 网卡读取失败 (多网卡或未探测): {e}"),
        }
        println!();

        // D. 演示: 清除 cache API
        println!("🧹 清除缓存命令 (不会真执行, 仅显示调用):");
        println!("   cfrp_detector::clear_cache(\n     asn_dir = {},\n     setting = {} )",
            mcfg.asn_cache_dir.display(), mcfg.iface_setting_file.display());
        return Ok(());
    }

    // ====== 真实执行 (CFRP_EXAMPLE_RUN=1) ======
    println!("\n🚀 开始真实执行 run_single_ip(1.1.1.1, ports=443, tls=true)...");
    println!("   预计用时: ~{}s (发包 wait + 检测)\n", mcfg.wait_seconds + 10);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4).enable_all().build()?;

    let demo_ip = std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let res = rt.block_on(async {
        pipeline.run_single_ip(&scanner, demo_ip, "443", true).await
    });

    match res {
        Ok(out) => {
            println!("\n✅ 流水线完成!");
            println!("   label           = {}", out.label);
            println!("   open_ports      = {}", out.open_ports_count);
            println!("   cf_edges        = {}", out.cloudflare_edges_count);
            println!("   masscan 用时    = {}s", out.masscan_duration_secs);
            println!("   检测用时        = {}s", out.detection_duration_secs);
            println!("   输出文件        = {}", out.output_path.display());
        }
        Err(e) => {
            println!("\n❌ 流水线失败: {e:?}");
            println!("   → 常见原因: 没有 root / masscan 缺依赖 / 路由器阻断 / 目标IP不可达");
        }
    }
    Ok(())
}