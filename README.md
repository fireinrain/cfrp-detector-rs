
# cfrp-detector-rs

> **Cloudflare 边缘节点检测器 + 网络质量探测套件**  
> 高性能 Rust 实现的 Cloudflare 边缘 IP 识别、地理定位与带宽/延迟质量评估工具  

[![CI Status](https://img.shields.io/github/actions/workflow/status/fireinrain/cfrp-detector/ci.yml?branch=main)](https://github.com/fireinrain/cfrp-detector/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust 1.97.1+](https://img.shields.io/badge/rustc-1.97.1+-orange.svg)](https://blog.rust-lang.org/)
[![Rust Edition 2024](https://img.shields.io/badge/edition-2024-DEA584.svg)](https://doc.rust-lang.org/edition-guide/editions/edition-2024.html)

---

## ✨ 核心特性

| 特性 | 说明 |
|------|------|
| 🎯 **Cloudflare 边缘识别** | 通过 TLS 证书指纹、`Server`/`CF-Ray` 响应头、`cdn-cgi/trace` 等多维特征综合判定，给出 `HIGH / MEDIUM / LOW / NONE` 四档置信度 + 判定理由链 |
| 🗺️ **地理定位** | 自动解析 `colo` 三字机场代码 → 填充国家 / 地区 / 城市信息 (LAX, NRT, SIN, HKG…) |
| 📈 **质量评估** | TCP/TLS 握手延迟、HTTP 状态码、**多线程下载测速** (可开启 TLS 0-RTT Early Data) |
| ⚡ **masscan 深度集成** | 单 ASN / 批量 ASN / 单 IP / 批量 IP 四种流水线；ASN → IP 段从 bgp.he 抓取并本地缓存 |
| 🎚️ **自适应并发** | AIMD 加增乘减算法实时根据错误率 / 超时率调节并发；结合 `ResourceGovernor` 主动防文件描述符耗尽 |
| 🧩 **三层配置系统** | **CLI 标志 > 环境变量 `CFRP_*` > TOML 配置文件 > 内置默认**， 任意组合正确覆盖 |
| 📦 **多格式 I/O** | 输入支持 JSON 对象数组 / JSON 字符串数组 / CSV / 带 `#` 注释 TXT；输出支持 JSON / CSV / TXT |
| 🛟 **优雅关闭** | `SIGINT` / `SIGTERM` 捕获 + 可配置宽限期 (grace seconds)，已完成探测结果全部写盘不丢失 |
| 🧱 **库 / CLI 双层架构** | `cfrp-detector` 纯库可嵌入任何 Rust 服务，`cfrp-detector-cli` 命令行开箱即用 |

---

## 📁 项目结构 (Cargo Workspace)

```
cfrp-detector-rs/
├── Cargo.toml                          # Workspace 根 (edition 2024, rustc ≥1.97.1)
├── README.md
├── COMMERCIAL-ROADMAP.md               # 商用交付路线图
├── .github/workflows/ci.yml            # CI: 安装 masscan + lint + test + clippy
└── crates/
    ├── cfrp-detector/                  # 🔵 核心库 (lib crate)
    │   └── src/
    │       ├── lib.rs                  # 对外公开 API 重导出
    │       ├── detector.rs             # Detector 主体: 自适应并发 + ResourceGovernor
    │       ├── masscan.rs              # MasscanScanner + ASN抓取 + 缓存管理
    │       ├── masscan_pipeline.rs     # 扫描→探测→CSV/JSON导出 一体化流水线
    │       ├── probe/                  # HTTP/TLS 探测 + SpeedTester
    │       ├── model.rs                # DetectionResult / EdgeInfo / Confidence / Target
    │       ├── governor/               # 资源调控: FD计数 / 错误滑窗 / 限流快照
    │       ├── location.rs             # Colo 机场码 → 地理位置映射
    │       ├── cidr.rs                 # Cloudflare IP/CIDR 归属判定数据源
    │       ├── cache.rs                # 带 TTL 日切本地文件缓存 (load_or_fetch)
    │       └── error.rs                # DetectorError + 可重试错误分类
    └── cfrp-detector-cli/              # 🟢 命令行工具 (bin name: cfrp-detector)
        └── src/main.rs                 # clap解析 / figment配置合并 / 信号 / 导出
```

---

## 🚀 快速开始

### 环境要求

| 依赖 | 最低版本 | 说明 |
|------|---------|------|
| Rust Toolchain | **1.97.1** | Edition 2024，通过 `rustup update stable` 升级 |
| masscan | 1.3.2+ | **仅 masscan 子命令需要**，普通探测模式不需要。安装方式：<br>• Debian/Ubuntu: `sudo apt-get install masscan`<br>• macOS: `brew install masscan`<br>• 自定义路径: `--masscan-bin /path/to/masscan` |
| 操作系统 | Linux / macOS | 支持 IPv4 / IPv6；网卡选择自动记忆到 `iface_setting.txt` |

### 编译 / 安装

```bash
# 1. 克隆仓库
git clone https://github.com/fireinrain/cfrp-detector && cd cfrp-detector

# 2. 开发构建 (调试信息, 编译快)
cargo build

# 3. 发布构建 (LTO 优化, 生产使用强烈推荐)
cargo build --release

# 4. (可选) 安装到 ~/.cargo/bin
cargo install --path crates/cfrp-detector-cli

# 5. 验证
./target/release/cfrp-detector --help
```

### 运行测试

```bash
# 全量测试
cargo test --all

# 只跑核心库单测
cargo test -p cfrp-detector

# criterion 基准
cargo bench -p cfrp-detector
```

---

## ⌨️ CLI 使用手册

### 命令总览

```
cfrp-detector <全局选项> [子命令]

可用子命令:
  detect       直接探测目标 IP:Port 是否为 Cloudflare 边缘节点 (无需 masscan)
  speedtest    对给定目标执行独立下载测速 (不做边缘识别)
  scan         masscan 扫描 → 探测 → 可选测速 的一体化流水线 (需 masscan)
    asn        扫描单个 ASN
    asns       批量扫描多个 ASN (从任务文件读取)
    ip         全端口扫描单个 IP
    ips        批量扫描多个 IP (从列表文件读取)
    clear-cache  清除 ASN 缓存 / 网卡配置 / 临时文件
  help         打印此帮助或子命令帮助
```

---

### 1️⃣ `detect` — 直接探测模式 (无需 masscan)

直接传入 `ip[:port]` 目标列表，立刻做 Cloudflare 边缘检测 + 质量评估：

```bash
# 🌱 基础: 探测 3 个目标，并发 50，显示进度
cfrp-detector detect --concurrency 50 --progress \
    104.16.132.229:443  172.67.73.54:443  1.1.1.1:80

# 📥 从 CSV/JSON/TXT 文件批量读目标 + 📤 输出 CSV 报告
cfrp-detector detect \
    --input  targets.csv \
    --output result.csv  \
    --format csv

# 🚀 开启速度测试 (仅对确认是 Cloudflare edge 的目标测速) + 自定义 SNI Host 域名
cfrp-detector detect \
    --speed  --speedtest-threads 8 \
    --domain speed.cloudflare.com \
    -i ips.txt  -o result.json
```

---

### 2️⃣ `speedtest` — 独立测速模式

对已知目标做纯下载测速（不做 CF 边缘判定，可直接用 `detect` 的输出文件作为输入）：

```bash
# 直接对指定目标测速 (SNI = speed.cloudflare.com, 显示进度)
cfrp-detector speedtest 1.1.1.1:443 104.16.132.229:443 -d speed.cloudflare.com -p

# 读取 detect 输出做批量测速，输出 CSV
cfrp-detector speedtest -i detect_results.json -o speeds.csv -f csv
```

---

### 3️⃣ `scan` — Masscan 扫描流水线 (需要 masscan + 高权限)

#### `scan asn` — 扫描单个 ASN

```bash
# 扫描 AS13335 (Cloudflare), 默认端口 443 + TLS，探测后对 CF 边缘节点测速
cfrp-detector scan asn 13335 --rate 50000 -s

# 扫描 AS45102 (阿里云), 多端口 + HTTP (关闭 TLS)
cfrp-detector scan asn 45102 --tls false --port 80,443,8443
```

#### `scan asns` — 批量 ASN 任务

**任务文件格式** (每行: `ASN:PORT:TLS`，如 `as.txt`)：
```
13335:443:true
45102:"443,8443":true
16509:80:false
```

```bash
cfrp-detector scan asns -f as.txt --concurrency 300 --rate 100000
```

#### `scan ip` — 扫描单 IP 全端口

```bash
# 默认: IP=172.67.73.54, ports=1-65535, TLS=true
cfrp-detector scan ip 1.1.1.1 --rate 200000 --output-dir /tmp/out

# 显式指定端口范围
cfrp-detector scan ip 104.16.132.229 --port 80,443,8000-9000 --tls false
```

#### `scan ips` — 批量 IP 列表

**`ips.txt`** 每行一个 IP：
```
104.16.132.229
172.67.73.54
```

```bash
cfrp-detector scan ips -f ips.txt --rate 500000 --port 443 --tls true
```

#### `scan clear-cache` — 清理缓存

```bash
cfrp-detector scan clear-cache \
  --asn-cache-dir        ./asn  \
  --iface-setting-file   ./setting.txt
```

---

### 🎛️ 选项速查表

#### 全局选项 (全局可用)
| 选项 (短 / 长) | 默认值 | 说明 |
|---------------|--------|------|
| `-C, --config FILE` | — | TOML 配置文件 |
| `--grace-seconds N` | `30` | Ctrl+C 后最大等待秒数 |

#### `detect` 子命令
| 分类 | 选项 (短 / 长) | 默认值 | 说明 |
|------|---------------|--------|------|
| **I/O** | `-i, --input FILE` | — | 批量目标输入 (.json/.csv/.txt) |
| ↳ | `-o, --output FILE` | stdout | 输出文件 |
| ↳ | `-f, --format json\|csv\|txt` | auto | 强制输出格式 |
| ↳ | `TARGET...` | — | 位置参数: `ip[:port]` / `[ipv6]:port` |
| **并发** | `-c, --concurrency N` | `10` | 最大并发探测数 |
| **自适应** | `-a, --adaptive` | `false` | 启用 AIMD 动态并发调节 |
| ↳ | `--a-min / --a-max / --a-initial` | 1 / 128 / 16 | 并发范围 + 初始值 |
| ↳ | `--a-window N` | 10 | 滑动窗口大小 |
| **进度** | `-p, --progress` | `false` | 显示 indicatif 进度条 |
| **测速** | `-s, --speed` | `false` | 探测后测速 **(仅 Cloudflare edge 目标)** |
| ↳ | `--speedtest-threads N` | `3` | 单目标测速连接数 |
| ↳ | `--speedtest-timeout N` | `5` | 测速超时 (秒) |
| ↳ | `--speedtest-concurrency N` | `8` | 多个目标并行测速 |
| ↳ | `--speedtest-url PATH` | `/cdn-cgi/trace` | 测速 URL 路径 |
| ↳ | `--enable-0rtt` | `false` | 启用 TLS 0-RTT Early Data |
| **探测** | `-d, --domain DOMAIN` | `cloudflare.com` | TLS SNI + Host 头域名 |
| ↳ | `--timeout N` | `3` | 单次探测超时 (秒) |
| ↳ | `--tls-session-cache N` | `256` | TLS Session 缓存容量 |
| ↳ | `--no-governor` | `false` | 关闭资源调控器 ❌不推荐 |
| ↳ | `--governor-report` | `false` | 探测结束后 stderr 打印资源调控快照 |
| **调试** | `-v, --verbose`... | 0 | `-v` INFO / `-vv` DEBUG / `-vvv` TRACE |
| **基准** | `--bench / --bench-quick` | — | 运行进程内 Go 兼容 JSON 基准报告 |

#### `speedtest` 子命令 (独立测速)
| 分类 | 选项 (短 / 长) | 默认值 | 说明 |
|------|---------------|--------|------|
| **I/O** | `-i, --input FILE` / `-o, --output FILE` / `-f, --format` | 同上 | 与 detect 一致 |
| **测速** | `-d, --domain DOMAIN` | `cloudflare.com` | 连接 SNI/Host |
| ↳ | `--url PATH` | `/cdn-cgi/trace` | 下载 payload 路径 |
| ↳ | `-t, --threads N` | `3` | 单目标并发下载线程 |
| ↳ | `--timeout N` | `5` | 单目标超时 |
| ↳ | `-C, --concurrency N` | `8` | 并行测速目标数 |
| ↳ | `--enable-0rtt` | `false` | 启用 0-RTT Early Data |
| ↳ | `--tls-session-cache N` | `256` | TLS Session 缓存 |
| ↳ | `-p, --progress` | `false` | 显示进度条 |

#### `scan asn/asns/ip/ips` 通用选项
由三类参数 flatten 组合：**scan 引擎** + **探测参数** + **测速参数**

| 分类 | 选项 | 默认值 | 说明 |
|------|------|--------|------|
| **masscan 引擎** | `--interface IFACE` | 自动探测 | 发包网卡 |
| ↳ | `--rate PPS` | `10000` | masscan 发包速率 |
| ↳ | `--masscan-bin FILE` | PATH 搜索 | 自定义 masscan 路径 |
| ↳ | `--asn-cache-dir DIR` | `asn` | ASN→IP 段缓存目录 |
| ↳ | `--iface-setting-file FILE` | `setting.txt` | 网卡记忆文件 |
| ↳ | `--output-dir DIR` | `.` | scan 流水线 CSV 输出目录 |
| **探测 (同 detect 子集)** | `-d, --domain` / `-c, --concurrency` / `-a, --adaptive` / `--a-*` / `-p, --progress` / `--timeout` / `--tls-session-cache` / `--no-governor` / `--governor-report` | — | 与 detect 语义相同 |
| **测速** | `-s, --speedtest` | `false` | 对确认的 CF edge 测速 |
| ↳ | `-t, --threads` | `3` | 单目标测速线程数 |
| ↳ | `--speedtest-url` | `/cdn-cgi/trace` | 测速 URL 路径 |
| ↳ | `--speedtest-timeout` | `5` | 测速超时 |
| ↳ | `--speedtest-concurrency` | `8` | 并行目标数 |

---

### 📥 输入文件格式

#### ① JSON (两种 schema 自动识别)
```jsonc
// 对象数组 (推荐, 带显式端口)
[{"ip":"104.16.132.229","port":443},{"ip":"1.1.1.1","port":80}]

// 字符串数组 (自动解析 ip:port)
["104.16.132.229:443", "1.1.1.1:80", "172.67.73.54"]
```

#### ② CSV (`ip` 列 + 可选 `port` 列)
```csv
ip,port
104.16.132.229,443
1.1.1.1,80
172.67.73.54              # port 留空 → 默认 443
```

#### ③ TXT (行格式, 空行/`#`注释自动跳过)
```
# 示例目标列表
104.16.132.229:443
1.1.1.1
[2606:4700::1111]:443    # IPv6 方括号写法
```

---

### 📤 输出字段字典

| 字段 (CSV / JSON) | 类型 | 含义 |
|-----------------|------|------|
| `target` | string | 原始目标串 `ip:port` |
| `ip` | string | IP 地址 (v4/v6) |
| `port` | number | 端口 |
| `is_cloudflare_edge` | bool | 是否判定为 Cloudflare 边缘节点 |
| `is_tls` | bool | 探测时使用的协议 (TLS=true / HTTP=false) |
| `is_usable` | bool | 综合可用性：边缘=true + 状态码正常 |
| `status_code` | number \| null | HTTP 响应状态码 |
| `colo` | string | 机场三字码 (LAX / NRT / HKG / SIN …) |
| `country` / `region` / `city` | string | 地理位置 (从 colo 反查) |
| `latency_ms` | number | 探测往返时间 (ms) |
| `download_speed_bytes_per_sec` | number \| null | 测速结果 (B/s, 0=未测速) |
| `confidence` | enum | `HIGH` / `MEDIUM` / `LOW` / `NONE` |
| `confidence_reason` | string | 最强判定依据简述 |
| `reasons` | string | 所有命中的特征 (`;` 分隔) |
| `error` | string \| null | 探测失败时错误信息 |

---

## ⚙️ 三层配置系统

优先级从高到低：  
**🥇 CLI 标志  →  🥈 环境变量 `CFRP_*`  →  🥉 TOML 配置文件  →  编译期默认值**

### TOML 示例 (`config.toml`)

```toml
# ========== I/O ==========
domain            = "cf.bench.example.com"
input             = "ips.csv"             # .json / .csv / .txt 皆可
output            = "results/cf.json"
format            = "json"                # json | csv | txt
targets           = ["104.16.132.229:443", "172.67.73.54"]

# ========== 并发 & 性能 ==========
concurrency       = 200
adaptive          = true                  # AIMD 动态并发
a_min             = 2
a_max             = 512
a_initial         = 32
a_window          = 8

# ========== 探测 & 测速 ==========
progress          = true
speedtest         = true                  # 与 detect -s / --speed 语义相同
speedtest_threads = 6
speedtest_timeout_secs      = 8
speedtest_concurrency       = 16
speedtest_url_path          = "/cdn-cgi/trace"
speedtest_0rtt    = true
probe_timeout_secs          = 5
tls_session_cache = 512
no_governor       = false

# ========== masscan (scan 子命令) ==========
rate              = 200000
interface         = "eth0"
asn_cache_dir     = "asn"
iface_setting_file = "setting.txt"
output_dir        = "."
grace_seconds     = 60
```

### 环境变量 (前缀自动 `CFRP_`，下划线分隔)

```bash
export CFRP_CONCURRENCY=300
export CFRP_SPEEDTEST=true              # 对应 detect --speed / scan -s
export CFRP_DOMAIN=my-cf.example.net
export CFRP_INPUT=/data/targets/ips.csv
export CFRP_OUTPUT=/data/out.csv
export CFRP_ASN_CACHE_DIR=/var/cache/cfrp/asn

# 提示: CFRP_TARGETS 会被主动忽略 (shell 数组传递不可靠)
#       多目标请使用 CLI 位置参数 或 --input 文件
```

---

## 🧠 Cloudflare 边缘识别算法概览

```
对每个 ip:port:
├─ TCP 连接失败   ❌ → 错误退出, is_edge=false
├─ TLS/HTTP 握手失败 → 记录错误, 置信度整体下调
├─ 🟢 [TLS 证书指纹层]
│   ├─ leaf/intermediate 证书 O=Cloudflare Inc → HIGH
│   ├─ Origin CA 特征 → HIGH
│   ├─ 典型 cipher suite 组合命中 → MEDIUM
│   └─ 0-RTT Early Data 被接受 (--speedtest-0rtt) → HIGH
├─ 🟢 [HTTP 响应头层]
│   ├─ CF-Ray: <hash>-<colo> → HIGH + 提取 colo
│   ├─ Server: cloudflare → HIGH
│   ├─ CF-Cache-Status 存在 → MEDIUM
│   └─ Set-Cookie: __cf_bm / cf_ob_info → HIGH
└─ 🟢 [cdn-cgi/trace 层]
    ├─ HTTP 200 + 合法 trace body → HIGH
    ├─ colo=XXX 存在 → 地理定位 EdgeInfo 完整填充
    └─ ip=/ts=/h= 字段完整性 → 可用性强信号

综合所有命中特征 → 取最高置信度 + 完整 reasons 列表
同时输出 is_usable (推荐是否可作为 CF 反代入口)
```

---

## 🏗️ 作为 `cfrp-detector` 库嵌入使用

`Cargo.toml`:
```toml
[dependencies]
cfrp-detector = { path = "../crates/cfrp-detector" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
anyhow = "1"
```

`src/main.rs`:
```rust
use std::net::{IpAddr, Ipv4Addr};
use cfrp_detector::{Detector, DetectorConfig, Target, BatchProgress};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化检测器（复用 TLS 缓存、HTTP client、资源调控器）
    let cfg = DetectorConfig::default();
    let detector = Detector::new(cfg).await?;

    // 构造目标
    let targets = vec![
        Target::new(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)), 443),
        Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
    ];

    // 可选进度回调
    let on_progress = |p: BatchProgress| {
        eprintln!("[{}/{}] cur_concurrency={}",
            p.completed, p.total, p.current_concurrency);
    };

    // 批量探测 (自适应并发 + 资源调控全部内部处理)
    let results = detector
        .run_batch(&targets, Some(Box::new(on_progress)))
        .await;

    for r in results {
        if let Some(result) = r.result {
            if result.is_cloudflare_edge {
                let colo = result.edge_info.as_ref()
                    .and_then(|e| e.colo_code.as_deref());
                println!("✅ {}:{}  CF边缘 | colo={:?} | 置信度={:?}",
                    r.target.ip(), r.target.port(), colo, result.confidence);
            }
        }
    }
    Ok(())
}
```

---

## 🧪 常见问题 FAQ

**Q: masscan 报错 `permission denied` / `you need to be root`?**  
A: masscan 发送原始 SYN 需要 `CAP_NET_RAW`。两种方案：
   ```bash
   # (a) 直接 sudo 运行 (推荐简单场景)
   sudo -E ./target/release/cfrp-detector scan asn 13335 --rate 200000

   # (b) 给二进制能力 (免 sudo, 生产部署)
   sudo setcap cap_net_raw,cap_net_admin=ep ./target/release/cfrp-detector
   ```

**Q: 出现 `Too many open files` (OS 错误 24 / EMFILE)?**  
A: 工具内置 `ResourceGovernor` 会在 `ulimit -n` 附近主动限流；仍然报错请调高 shell 限制：
   ```bash
   ulimit -n 65536   # 临时, 当前 shell 生效
   # 永久: /etc/security/limits.conf (Linux) 或 launchctl limit maxfiles (macOS)
   ```

**Q: 怎么提高速度？**  
   1. masscan 速率：`--rate 500000` ~ `--rate 1000000` (取决于网卡，千兆网卡建议 100k–500k)
   2. 探测器并发：`--concurrency 300` ~ `--concurrency 1000` (配合 ulimit)
   3. `--adaptive` 开启自适应并发，工具会自动寻找本机最优并发值，无需手动调参

**Q: ASN 缓存多久失效？**  
A: 从 `https://bgp.he.net/AS{asn}#_prefixes` 拉取，下载的 HTML 永久缓存到 `--asn-cache-dir`，直到 `clear-cache` 或手动删除。适合定期对同一批 ASN 做重复扫描。

---

## 🤝 贡献

Issues / PRs 欢迎！本地验证清单：

```bash
cargo fmt --all -- --check           # 格式检查
cargo check --all                    # 编译
cargo test  --all                    # 单元/集成测试
cargo clippy --all --all-targets -- -D warnings
```

CI (`.github/workflows/ci.yml`) 除了以上四步，还会通过 `apt-get install masscan` 安装 masscan 后再跑一遍测试，确保流水线端到端通过。

---

## 📝 License

**MIT** © fireinrain — 详见仓库根目录 `LICENSE` 文件