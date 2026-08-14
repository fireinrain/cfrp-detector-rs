
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
| 🧩 **四层配置系统** | **CLI 标志 > 环境变量 `CFRP_*` > TOML 配置文件 (自动发现) > 内置默认**， 任意组合正确覆盖；`init` 显式生成，`config show/get` 调试溯源 |
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

# 5. (推荐) 生成一份带注释的默认配置到当前目录 (可跳过，但新用户强烈建议)
./target/release/cfrp-detector init

# 6. 验证
./target/release/cfrp-detector --help

# 7. (可选) 快速查看生效的配置 + 来源标记
./target/release/cfrp-detector config show
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
  init         生成带注释的 TOML 配置文件 (默认: ./cfrp.toml)
  config       查看 / 诊断当前生效的配置 (带来源标记)
    show       打印全部配置及来源: [CLI]/[FILE path]/[ENV]/[DEF]
    get        查询单个配置键的有效值与来源
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

### 0️⃣ `init` — 生成配置文件 (显式优于隐式)

**第一次使用强烈建议先运行一次**，工具会生成一份**带详尽中文注释**的 TOML，比翻手册直观得多：

```bash
# 🌱 默认: 在当前目录生成 cfrp.toml (已存在则拒绝覆盖，防止丢配置)
cfrp-detector init

# 📌 生成到指定路径
cfrp-detector init -o /etc/cfrp/config.toml

# ⚠️ 强制覆盖已有文件 (危险: 会丢弃用户的手动修改)
cfrp-detector init --force

# 🎯 极简版 (只保留核心字段，适合老手)
cfrp-detector init --minimal
```

> 💡 **设计原则**: 只有显式调用 `init` 才会写文件；其他命令**永远不会自动创建**配置文件，但会**自动发现**已存在的配置文件。

---

### 0️⃣½ `config` — 诊断配置来源

排错神器，直接回答「为什么这个参数和我想的不一样？」：

```bash
# 打印全部生效配置，并标出每一项的来源
cfrp-detector config show
# [CLI]  concurrency          = 100
# [FILE ./cfrp.toml] adaptive = true
# [ENV]  probe_timeout_secs   = 5
# [DEF]  a_min                = 2

# 查询单个键 (支持下划线或连字符)
cfrp-detector config get speedtest_concurrency
# [FILE ~/.config/cfrp/config.toml] speedtest_concurrency = 16

cfrp-detector config get rate
# [DEF] rate = 100000
```

四种来源标记：
| 标签 | 含义 | 优先级 |
|------|------|--------|
| `[CLI]` | 命令行 flag 传入 | 🥇 最高 |
| `[ENV]` | `CFRP_*` 环境变量 | 🥈 |
| `[FILE <path>]` | TOML 配置文件 (含路径) | 🥉 |
| `[DEF]` | 编译期默认值 | 🏠 最低 |

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
| `-C, --config FILE` | (自动发现) | **显式指定** TOML 配置文件。不传则按下列路径**自动查找**：<br>① `./cfrp.toml` (项目级)<br>② `$XDG_CONFIG_HOME/cfrp/config.toml` (用户级，通常为 `~/.config/cfrp/config.toml`)<br>③ `/etc/cfrp/config.toml` (系统级) |
| `--no-config` | `false` | **完全跳过**所有 TOML 配置文件 (即使 -C 指定或自动发现路径存在也不用)；CI / 排错时非常有用 |
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
| ↳ | `--rate PPS` | `10000` (CLI) / `100000` (配置文件) | masscan 发包速率；**只要加载了 init 生成的默认配置就是 100000** |
| ↳ | `--masscan-bin FILE` | PATH 搜索 | 自定义 masscan 路径 |
| ↳ | `--asn-cache-dir DIR` | `asn` | ASN→IP 段缓存目录 |
| ↳ | `--iface-setting-file FILE` | `setting.txt` | 网卡记忆文件 |
| ↳ | `--output-dir DIR` | `.` (CLI) / `./scan_results` (配置文件) | scan 流水线 CSV 输出目录 |
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

## ⚙️ 四层配置系统

优先级从高到低：  
**🥇 CLI 标志  →  🥈 环境变量 `CFRP_*`  →  🥉 TOML 配置文件 (自动发现)  →  🏠 编译期默认值**

> 💡 配置文件**不会自动创建** — 必须通过 `cfrp-detector init` 显式生成。但只要文件存在于标准路径，工具就会**自动找到并加载**。

### 配置文件查找顺序（无 `-C` 时）

```
① 项目级:   ./cfrp.toml                         ← 优先使用，每个项目/目录单独配置
② 用户级:   ~/.config/cfrp/config.toml          ← XDG 兼容，CFRP_CONFIG_HOME 环境变量可覆盖
③ 系统级:   /etc/cfrp/config.toml               ← 全机器统一默认 (类 Unix)
```

若需完全跳过配置文件（CI 环境 / 排错），加 `--no-config` 全局标志。

### TOML 示例 (由 `init` 生成的默认版，节选)

**文件名建议**：项目根目录 `cfrp.toml`，或全局放 `~/.config/cfrp/config.toml`

```toml
# ============================================================
# cfrp-detector default configuration file
# 生成方式: cfrp-detector init
# 优先级 (高→低): CLI 标志 > CFRP_* env > 本文件 > 编译默认
# ============================================================

# ========== I/O ==========
# domain            = "cloudflare.com"        # TLS SNI + Host 头
# input             = "ips.txt"               # 批量目标文件
# output            = "result.json"           # 输出文件
# format            = "json"                  # json | csv | txt
# targets           = ["1.1.1.1:443", "104.16.132.229:443"]  # 固定目标列表

# ========== 并发 & 自适应 (AIMD) ==========
concurrency       = 50                      # 出厂默认 10 → init 建议值 50
adaptive          = true                    # 默认开 AIMD (省心)
a_min             = 2
a_max             = 256
a_initial         = 32
a_window          = 10

# ========== 探测参数 ==========
progress          = true                    # 默认显示进度条
probe_timeout_secs          = 5             # 3s 对跨国链路太紧，放宽到 5s
tls_session_cache = 512
# governor_report  = false
# no_governor      = false                   # 资源调控器不建议关

# ========== 测速参数 ==========
# speedtest        = false                   # 探测后是否自动测速 (较慢)
speedtest_threads = 4
speedtest_timeout_secs      = 10
speedtest_concurrency       = 16
speedtest_url_path          = "/cdn-cgi/trace"
# speedtest_0rtt   = false

# ========== masscan (scan 子命令) ==========
rate              = 100000                  # 100k pps (家用/办公网卡安全值)
# interface        = "eth0"                  # 留空自动探测
asn_cache_dir     = "asn"
iface_setting_file = "setting.txt"
output_dir        = "./scan_results"        # 统一放到独立子目录，别乱扔到 ./

# ========== 其他 ==========
grace_seconds     = 30
```

### 环境变量 (前缀自动 `CFRP_`，下划线分隔)

```bash
export CFRP_CONCURRENCY=300
export CFRP_ADAPTIVE=true
export CFRP_SPEEDTEST=true                  # 对应 detect -s / scan -s
export CFRP_DOMAIN=my-cf.example.net
export CFRP_INPUT=/data/targets/ips.csv
export CFRP_OUTPUT=/data/out.csv
export CFRP_ASN_CACHE_DIR=/var/cache/cfrp/asn
export CFRP_RATE=500000                     # masscan 速率 (scan)
export CFRP_INTERFACE=eth0

# 可用的完整变量清单 (对应 TOML 字段, 全大写下划线):
# DOMAIN / INPUT / OUTPUT / FORMAT / TARGETS
# CONCURRENCY / ADAPTIVE / A_MIN / A_MAX / A_INITIAL / A_WINDOW
# PROGRESS / PROBE_TIMEOUT_SECS / TLS_SESSION_CACHE / GOVERNOR_REPORT / NO_GOVERNOR
# SPEEDTEST / SPEEDTEST_URL_PATH / SPEEDTEST_THREADS / SPEEDTEST_TIMEOUT_SECS
# SPEEDTEST_CONCURRENCY / SPEEDTEST_0RTT
# INTERFACE / RATE / MASSCAN_BINARY / ASN_CACHE_DIR / IFACE_SETTING_FILE / OUTPUT_DIR
# BENCH / BENCH_QUICK / GRACE_SECONDS
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

**Q: 怎么确认当前到底生效的是哪份配置 / 某个值从哪来的？**  
A: 用 `config` 子命令，这是最直接的排错方式：
   ```bash
   # 打印全部配置及来源标记
   cfrp-detector config show

   # 只查某一项 (例: 为什么 rate 是 100000 不是 10000？)
   cfrp-detector config get rate
   # [FILE ./cfrp.toml] rate = 100000   ← 答案: 因为当前目录有 cfrp.toml

   # 临时忽略所有配置文件，确认"纯 CLI+默认"的行为
   cfrp-detector --no-config detect ...
   ```

**Q: 为什么默认 `--concurrency` 文档里写的是 10，但我实际跑看到的是 50？**  
A: 因为你当前目录 / 用户目录下已经有一份由 `init` 生成的 `cfrp.toml` 把它覆盖成 50 了。用 `cfrp-detector config get concurrency` 立刻就能看到来源。这正是「自动发现 + 配置溯源」设计的目的 — 不再有"幽灵默认值"。

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