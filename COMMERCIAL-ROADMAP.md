# Commercial implementation roadmap

## 全局总览

| Phase | 主题 | 状态 | 核心交付物 | 前置依赖 |
|---|---|---|---|---|
| 1 | Foundation (库/CLI 骨架 + 基础检测引擎) | ✅ 已交付 | workspace, CIDR loader, cache, ProbeEngine, 基础 API | — |
| 2 | Compatibility (Go CLI 1:1 兼容) | ✅ 已交付 | TXT/CSV/JSON 输出、进度条、自适应并发、speedtest、oneshot | Phase 1 |
| 3 | Performance (性能/资源优化) | 📋 规格就绪 / 待实现 | PinnedConnector、TLS 会话复用、bench harness、FD-aware governor | Phase 2；Bench harness 子集依赖 Phase 4.1 mock server |
| 4 | Production Hardening (生产级加固) | 📋 规格就绪 / 待实现 | 集成测试、fuzz、metrics、配置、重试、优雅关闭、CI、发布 | Phase 3 至少完成 3.1 |

---

## Phase 1 — Foundation (已交付)

> 对应本仓库初始交付的骨架层，完成库/CLI 分层、核心检测引擎、数据接入、基础模型与单元测试。

### 1.1 Workspace + library + CLI 分层
- **范围**：
  - `Cargo.toml` workspace resolver = 2，members 为 `crates/cfrp-detector` (lib) 与 `crates/cfrp-detector-cli` (bin)。
  - 所有共享依赖走 `workspace.dependencies`，单一版本真相源。
- **验收 / 代码锚点**：
  - `/Cargo.toml:1-6` workspace 定义；`/Cargo.toml:14-29` 统一依赖版本。
  - 库发布类型为 `lib`，CLI 通过 `path = "../cfrp-detector"` 引用库，无循环依赖。

### 1.2 类型化 IP/port/domain 模型
- **范围**：
  - `Target { ip: IpAddr, port: u16 }`，`Display` 支持 IPv6 `[addr]:port` 格式。
  - `BatchTarget` / `BatchResult` / `DetectionResult` / `EdgeInfo` / `Confidence` / `Protocol` 全部 typed，`Confidence` 使用 enum 而非自由字符串。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector/src/model.rs:4-97` 全部类型定义。
  - `model.rs:106-115` 单元测试确认 IPv6 方括号 display 与 IPv4 纯文本。
  - `model.rs:30-37` `Confidence` 为 enum 并支持 UPPERCASE serde。

### 1.3 官方 Cloudflare IPv4/IPv6 CIDR 加载
- **范围**：
  - 自实现轻量 `IpNetLike` (v4: u32 mask / v6: u128 mask)，零额外 CIDR 依赖。
  - 按 v4/v6 分组缓存，成员查询分族短路。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector/src/cidr.rs:19-61` `netip` 模块实现。
  - `cidr.rs:143-151` 集成测试：`1.1.0.0/16` + `2606:4700::/32` 的成员关系正反用例都通过。
  - `CIDRS_URL` 常量指向 cloudflare.com 官方 `ips-v4` / `ips-v6`。

### 1.4 本地 TTL 文件缓存
- **范围**：
  - 按 `{prefix}-{day-N}{ext}` 命名，UNIX day 编号避免 chrono 依赖。
  - 自动清理除最新文件外的同前缀历史副本。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector/src/cache.rs:33-60` `load_or_fetch` 主流程。
  - `cache.rs:109-118` `chrono_like_date` 零依赖日期生成；`cache.rs:150-155` 单测验证格式。

### 1.5 Cloudflare colo (colo→city/country) 元数据加载
- **范围**：
  - 从社区维护的 JSON 加载 colo 列表，大小写不敏感 lookup。
  - `LocationSource` trait 抽象，便于 mock / 自定义数据源。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector/src/location.rs:7` `LOCATIONS_URL`。
  - `location.rs:98-111` 单测：大小写混用的 `lax` / `Lax` / `LAX` 均命中。

### 1.6 有界异步批检测 + 确定性输出序
- **范围**：
  - `tokio::sync::Semaphore` + `AdaptiveConfig` 控制并发上界。
  - 通过 `(order, idx)` 元组收集后按 idx 重新排序，严格保持输入顺序。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector/src/detector.rs:260-407` `detect_batch_with_progress` 核心调度器。
  - `detector.rs:399` `out.sort_by_key(|(i, _, _)| *i)` 保持序步骤。

### 1.7 HTTPS SNI-safe per-target resolver pinning (MVP 版)
- **范围**：
  - `ProbeConfig::build_client(resolve: Some((host, addr)))`，用 reqwest 的 `.resolve()` 将特定 host 绑定到目标 IP，初步避免 DNS 污染。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector/src/probe.rs:30-43`。
  - 注意：Phase 3.1 将替换为真正 TCP-level IP pinning。

### 1.8 JSON 输出基础 + 单元测试集
- **范围**：
  - 所有核心模型 derive `Serialize/Deserialize`。
  - 覆盖 CIDR membership、IPv6 显示格式、ProbeConfig、header 分析、unique_snis、Target parse 等 60+ 单测。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector/src/model.rs:234-254` serde 往返测试。
  - `cargo test --all` 下的 `lib test` + 8 个 integration test crate (`cidr`/`cache`/`probe`/`detector`/`error`/`speedtest`/`location`/`model`)。

---

## Phase 2 — Compatibility (已交付)

> 目标：CLI 的 flags、输入解析、输出格式、进度/自适应/speedtest 与 Go 原版行为级一致。

### 2.1 精确 Go CLI 输入语法兼容
- **范围**：
  - 位置参数：`ip` / `ip:port` / `[ipv6]:port` 三种自由混合。
  - `-i/--input` 支持纯文本（# 注释）、JSON（`[{ip,port}]` 或 `[string]` 两种 schema）、CSV 三种。
  - 端口缺省 443。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector-cli/src/main.rs:511-566` `collect_targets`。
  - `main.rs:574-592` `parse_target` 覆盖 `SocketAddr::from_str`、`IpAddr::from_str`、`rsplit_once(':')` 三条路径。

### 2.2 TXT / CSV / JSON 导出 1:1 parity
- **范围**：
  - 统一中间表示 `ExportRecord` → 三种 emit 格式。
  - TXT key=value 风格、CSV 使用 `csv` crate、JSON 使用 `serde_json::to_writer_pretty`。
  - 自动从 `-o/--output` 扩展名推断格式（无扩展名默认 JSON）。
- **验收 / 代码锚点**：
  - `main.rs:157-242` `ExportRecord` + `txt_line()`。
  - `main.rs:421-464` `infer_format` + `emit_records`。
  - `main.rs:466-509` `CsvRow<'a>` + `From<&ExportRecord>`。

### 2.3 进度报告 (stderr progress bar)
- **范围**：
  - `indicatif::ProgressBar`，模板显示 spinner / elapsed / bar / pos/len / eta / 当前并发 c=。
  - 通过 `detect_batch_with_progress` 的回调更新，speedtest 阶段复用同一 bar 并 reset。
- **验收 / 代码锚点**：
  - `main.rs:289-301` PB 构造与模板。
  - `main.rs:319-324` 检测阶段回调；`main.rs:342-345` / `390-392` speedtest 阶段 reset + inc。

### 2.4 自适应并发
- **范围**：
  - `AdaptiveConfig { enabled, initial, min, max, window }`。
  - 滑窗成功率 ≥ 85% 并发 ×1.25，≤ 35% 并发 ×0.5，clamp 到 `[min, max] ∩ max_limit`。
  - 信号量 permits 动态增减（delta > 0 `add_permits`；delta < 0 `try_acquire_owned().forget()`）。
- **验收 / 代码锚点**：
  - `detector.rs:22-41` `AdaptiveConfig` 默认值。
  - `detector.rs:337-366` 自适应更新循环。

### 2.5 Speedtest API parity
- **范围**：
  - `SpeedTester::test` / `test_batch`，每目标 `threads_per_target` 并发下载同 URL，聚合字节数计算 bps。
  - CLI 暴露 `--speedtest`、`--speedtest-url`、`-t/--threads`、`--speedtest-timeout`、`--speedtest-concurrency`。
  - 只对 `is_cloudflare_edge && is_tls` 的结果启用测速。
- **验收 / 代码锚点**：
  - `crates/cfrp-detector/src/speedtest.rs:9-98` 配置、结果、测试器。
  - `main.rs:340-410` speedtest 分支（StreamExt::buffer_unordered）。

### 2.6 Fast one-shot detector
- **范围**：
  - `Detector::detect_oneshot(target, domain)` 内部走 `new(DetectorConfig::default())` + 单次 detect，跳过批处理。
  - CLI `--fast` 开关，严格要求 1 个目标。
- **验收 / 代码锚点**：
  - `detector.rs:252-258` `detect_oneshot`。
  - `main.rs:261-276` CLI `--fast` 分支（含 `targets.len() != 1` 的报错）。

---

## Phase 3 — Performance (规格就绪 / 待实现)

### 3.1 IP-pinned connector (direct socket connect + SNI-aware TLS)
- **背景**：当前 `speedtest.rs:50` 的 MVP 注释明确提到 "next phase will introduce a custom resolver/connector that pins the TCP endpoint"；CLI `main.rs:380-386` 也只是用 `reqwest::resolve()` 做 DNS 覆盖，不是真正绕过系统解析器的 TCP 直连。
- **目标**：实现真正的 TCP endpoint pinning，在 SocketAddr 层面直接连到目标 IP:port，同时在 TLS ClientHello 中设置正确的 SNI，HTTP 层设置 Host 头，消除所有对系统 DNS 的依赖。
- **范围**：
  - 在 `crate::probe` 或新增 `crate::connector` 模块中实现 `PinnedConnector`：
    - 直接 `tokio::net::TcpStream::connect(SocketAddr)` 而非走 DNS。
    - 使用 `tokio-rustls` / reqwest 的 `connect_with` 钩子构造 TLS 流，SNI 参数来源于 `host`，TCP 远端来源于 `Target`。
    - 对 HTTP/HTTPS 双协议都支持；保留现有 `danger_accept_invalid_certs` 行为以探测自签名的边缘节点。
  - 改造 `ProbeConfig::build_client` (probe.rs:30-43)：新增 `build_pinned_client(host, socket_addr)` 或在现有参数里用枚举标识连接策略。
  - 改造 `SpeedTester::test` (speedtest.rs:43-84)：接收 `(Target, host, path)` 三元组，用 PinnedConnector 而非 URL + resolve，这样测速结果反映真实 IP 握手 RTT 而不含 DNS 时延。
  - 改造 `Detector::fetch_edge_info` (detector.rs:193-240) / `tls_probe` (probe.rs:69-116) / `http_probe` (probe.rs:118-138)：使用统一的 PinnedConnector，保持 SNI 与 Host 头一致。
- **验收**：对同一个目标 IP，`nslookup` 返回错误 IP 的环境下探测依然成功；抓包确认 TCP SYN 直接打向 `Target.ip`，TLS ClientHello 中 SNI 为 `host`。

### 3.2 TLS session resumption (client-side session cache / 0-RTT where safe)
- **背景**：当前每个 probe 都会新建一个 reqwest `Client` (见 `ProbeConfig::build_client` 每次都 `builder.build()`)，TLS 握手开销占主导。批处理同一批 Cloudflare IP 时握手可复用。
- **目标**：在安全边界内（同一目标 IP+SNI）复用 TLS session，降低批量探测 20-50% 的握手耗时。
- **范围**：
  - 在 `ProbeEngine` / `Detector` 内部引入按 `(SocketAddr, sni)` 键化的 `Client` 或 `rustls::ClientConfig` 缓存，cache TTL 默认 30s 可配。
  - 启用 rustls `ClientConfig` 的 session storage：使用 `rustls::client::ClientSessionMemoryCache`（可按容量上限）。
  - 对测速/探测阶段分离策略：
    - 探测阶段（TLS/HTTP probe、trace fetch）：启用 session id/ticket 复用，跳过 0-RTT（保证结果确定性）。
    - 测速阶段：允许 0-RTT early data，但在结果中用 `SpeedTestResult` 新增字段区分 `handshake_type: FullHandshake | Resumed | ZeroRtt`，避免与 Go 基准对比时数据污染。
  - 暴露 `DetectorConfig` / `ProbeConfig` 开关：`tls_session_cache: bool`、`tls_session_cache_size: usize`、`allow_0rtt_speedtest: bool`。
- **验收**：同一目标连续两次 TLS probe，第二次 `server_hello` 中出现 resumed session 指示；批量 1000 目标相比 Phase 2 总耗时下降 ≥25%。

### 3.3 Benchmark harness against the Go baseline
- **背景**：`phase-1-notes.md:23-29` 明确了从 Go 迁移的映射关系和已知后续阶段，缺少与 Go 版本的定量对比。
- **范围**：
  - 在 workspace 中新增 `crates/cfrp-bench` 或用 `criterion` 把基准放在 `cfrp-detector/benches/`：
    - `parse_target`：对 Go 的 `ParseTarget` 同等输入做 per-case 对比。
    - `cidr_contains`：Cloudflare 全量 v4+v6 CIDR 下 10k 随机 IP 的吞吐/尾延迟，对比 Go 的 `IsCloudflareIP`。
    - `tls_probe_single` / `http_probe_single`：用 mock server（见 Phase 4.1）分别测单目标的端到端延迟 p50/p99。
    - `detect_batch_100 / detect_batch_10k`：在 mock 环境 + 真实网络两套场景下，测完成时间、内存占用（`getrusage` / `tikv-jemalloc` stats）、活动 File Descriptor 峰值。
  - 产出对比报告脚本 `scripts/bench-vs-go.sh`：
    - 自动构建 Go 原版（通过 git submodule 或可下载的 tag）与 Rust 版。
    - 同一输入文件（1k/10k/100k 目标），同一台机器，关闭自适应并发以固定并发 N 运行 3 次。
    - 输出 CSV：phase, impl, targets, concurrency, elapsed_secs, max_rss_kb, max_fds, p50_latency_ms, p99_latency_ms。
  - 将 `SpeedTestResult` 增加 `connect_latency`、`tls_handshake_latency`、`ttfb_latency` 分项，便于和 Go 的测速字段 1:1 对齐。
- **验收**：`cargo bench` 成功；在 10k 目标、并发 256 的场景下，Rust 版端到端总耗时 ≤ Go 版 1.1x（目标 0.8x），内存占用 ≤ Go 版 0.7x。

### 3.4 FD / resource-aware concurrency governor
- **背景**：`detector.rs:260-407` 实现的是基于成功率的 adaptive concurrency，但没有把 OS 资源（ulimit -n、当前进程已打开 FD 数、TCP/tokio 半连接队列压力）纳入反馈环。高并发下会出现 `Too many open files` 并导致后续所有任务被 semaphore 永久阻塞。
- **目标**：并发上限同时受三种约束：
  1. 用户/配置给定的 `max_concurrency`（已存在）。
  2. 进程可用 FD 头空间（`rlimit_nofile - current_open_fds - safety_headroom`）。
  3. 最近 N 秒内的连接错误率（EMFILE/ENFILE/ECONNRESET 等资源类错误占比）。
- **范围**：
  - 定义 `ResourceGovernor` 结构：
    - 跨平台读取当前进程打开 FD 数：
      - Linux: 读 `/proc/self/fd` 目录条目数（可用简单计数 + 采样衰减）。
      - macOS: `proc_pidinfo` / `libc::getdtablesize` 或扫描 `/dev/fd`。
      - 提供 `trait FdCounter` 以便测试 mock。
    - 读 `rlimit(RLIMIT_NOFILE)` 取软上限，若未设置则按 OS 默认（Linux 1024，macOS 256 等）。
    - 资源错误分类：`DetectorError::Network(reqwest_err)` 中若 source 为 `std::io::Error` 且 kind 为 `WouldBlock`/`AddrNotAvailable`/其他 OS EMFILE 映射，归为资源类。
  - 改造 `detect_batch_with_progress` 的自适应逻辑（detector.rs:337-367）：
    - 在每轮自适应调整时，额外 clamp 到 `fd_budget()`：`new_limit = new_limit.min(fd_budget())`。
    - 新增错误率回退：资源类错误在滑动窗口中占比 > 10% 时强制按 0.5 倍降速，并在 `BatchProgress` 中新增 `throttled_due_to_fd: bool` 供 CLI 可视化。
    - semaphore 初始化值不超过 `fd_budget()`，避免一开始就炸 FD。
  - 新增 CLI 输出/进度提示：当 governor 因为资源降速时，stderr 的 progress message 从 `"c=256"` 变为 `"c=32(fd)"` 以便排障。
  - 单元测试：用 mock `FdCounter` 模拟 "FD 逼近上限 → 并发下降 → FD 释放 → 并发回升" 的闭环。
- **验收**：人为把 `ulimit -n` 设到 128，对 10k 目标运行，不得出现 `Too many open files` 错误；观察并发曲线自动在 32-64 区间内收敛；`BatchProgress.current_concurrency` 与实际 FD 消耗负相关。

### 3.5 Phase 3 非功能要求（与 Phase 2 衔接）
- 所有优化通过 `DetectorConfig` 的布尔/数值开关可关闭，保证能与 Go 版在「无优化」基线对比。
- 新增的 TLS session 缓存、PinnedConnector、ResourceGovernor 各自独立可测，接口为 `pub(crate)` 或拆分到单独 module，避免破坏 Phase 2 的稳定 API。
- 保留原有确定性：`detect_batch` 输出顺序依然严格等于输入顺序，不因连接复用/资源调度乱序。
- Bench harness 的 mock server 接口与 Phase 4.1 的 mock-server integration suite 共用一套类型，避免重复投资。

---

## Phase 4 — Production Hardening (规格就绪 / 待实现)

### 4.1 Mock-server integration suite
- **背景**：当前所有 probe / detector 的集成测试（`tests/detector.rs` 等）均无 mock server，要么测纯逻辑，要么在真实 Cloudflare IP 上跑（网络不可控、CI 失败）。phase-1-notes.md:27 明确标记此项为 next phase。
- **目标**：本地启动可控 HTTP/HTTPS mock，模拟 Cloudflare 的 `Server: cloudflare`、`CF-RAY` 头、`/cdn-cgi/trace` 路由、自签名证书、TLS SNI 行为，覆盖 80% 以上关键代码路径的离线确定性测试。
- **范围**：
  - 新增 `crates/cfrp-test-macros` / 或直接在 `cfrp-detector/tests/support/` 放 `mock_server.rs`：
    - `MockCfServer` 支持：
      - 纯 HTTP 模式 (监听 127.0.0.1:0 随机端口)
      - HTTPS 模式：自签发证书（`rcgen` + `rustls`），可配置 SNI 检查/拒绝
      - 路由处理：`/cdn-cgi/trace` 返回 `colo=LAX\nh=www.cloudflare.com\n...`；`/` 返回带/不带 Cloudflare headers 的响应
      - 故障注入：`latency(Duration)`、`probability_reset_conn(f64)`、`status_override(StatusCode)`
    - 暴露 `CidrSource` + `LocationSource` 的 in-memory mock：`StaticRanges::from(["127.0.0.1/32"])` 与 `StaticLocations::from([("LAX", CfLocation{...})])`，避免真实网络加载 CIDR / locations JSON。
  - 集成测试用例矩阵：
    - ✅ `detect()` 命中 Cloudflare CIDR → 期望 `is_cloudflare_edge=true, confidence=HIGH`
    - ✅ `detect()` 不在 CIDR 但 HTTP 返回 `cf-ray` + `Server: cloudflare` → 期望 `confidence=LOW`
    - ✅ `tls_probe` 对 3 个 SNI 候选按优先级回退：自定义域名 → www.cloudflare.com → ""（空 SNI fallback）
    - ✅ `fetch_edge_info` 解析 trace 行 → colo 匹配后 city/country/region 填充正确
    - ✅ `detect_batch` 在 mock server 注入 30% 连接重置时，adaptive concurrency 正确降速且结果序正确
    - ✅ `speedtest` 给定固定响应大小 → 计算的 `bytes_per_second` 在 ±10% 误差内
- **验收**：CI 环境无外网 `cargo test --all` 全部通过；`cargo llvm-cov` 库 crate 行覆盖率 ≥ 75%。

### 4.2 Property / fuzz 测试 for target parsing + trace parsing
- **背景**：`parse_target` 处理 3 种输入格式 + IPv6 方括号；`/cdn-cgi/trace` body 解析依赖自由文本行，当前仅有 happy path 单测，缺少边界/畸形输入覆盖。
- **目标**：用 property test (proptest) 覆盖合法空间，用 fuzz (cargo-fuzz / afl) 覆盖畸形空间，杜绝 panic 和 OOM。
- **范围**：
  - **Property tests (proptest)**：
    - Target roundtrip：`any::<IpAddr>()` × `any::<u16>()` → `format!("{}", Target::new(ip, port))` → `parse_target(_, 443)` 必须还原；对 IPv6 额外要求方括号表现。
    - CIDR 单调性：任意 IP 与 `0.0.0.0/0` 必须成员；与 `/32`(v4)/`/128`(v6) 自身必成员；`a.b.c.d/X` 相邻前缀边界正确。
    - Trace body 解析：`colo=XXX` 出现在任意行位置、大小写混合、前后空白都能被 `Detector::fetch_edge_info` 正确提取；缺失 colo 行时返回 `None`。
    - CSV/JSON input 解析：序列化再反序列化 `Vec<Target>` 的 roundtrip。
  - **Fuzz tests (cargo-fuzz, `fuzz/` crate)**：
    - Fuzz target `parse_target_fuzz`：对任意 `&[u8]` / String 运行，保证不 panic。
    - Fuzz target `trace_parse_fuzz`：对任意 trace body 文本跑 fetch_edge_info 逻辑拆行，保证不 panic、不无限循环。
    - Fuzz target `cidr_parse_fuzz`：对任意字符串调用 `IpNetLike::parse`，不 panic。
  - CI 中 property tests 作为常规 `cargo test` 运行（proptest 默认 256 cases）；fuzz 在 release 管道中周期性跑 10min，不作为 PR gate。
- **验收**：proptest 256 cases 全绿；本地对每个 fuzz target 跑 1M cases 无 panic；引入 2 个已知历史 bug（如方括号解析漏洞）回归时 property test 能捕获。

### 4.4 配置文件 + 环境变量（多层配置合并）
- **背景**：当前所有配置只能通过 CLI flags 传递；商用部署通常希望一份 `cfrp-detector.toml` + 部分 secret 从环境变量覆盖（如代理、超时）。
- **目标**：优先级 CLI flags > 环境变量 > 配置文件 > 默认值；配置 schema 与 `DetectorConfig / ProbeConfig / SpeedTestConfig / AdaptiveConfig` 1:1 对应。
- **范围**：
  - 引入 `figment` 或自定义 3 层 merge：
    1. `--config <file>` (TOML / YAML / JSON 自动识别)
    2. 环境变量前缀 `CFRP_*`：`CFRP_PROBE_TIMEOUT=5`、`CFRP_ADAPTIVE__A_MAX=128`（双下划线分隔嵌套）
    3. CLI flags 最后覆盖
  - 新增 `CfrpAppConfig` 顶层结构（derive Deserialize）：
    ```rust
    struct CfrpAppConfig { probe: ProbeConfigOverrides, cache: CacheConfigOverrides, adaptive: AdaptiveConfig, speedtest: SpeedTestConfigOverrides, output: OutputConfig }
    ```
    带 `..Default::default()` 的 partial override 语义，避免要求用户填全字段。
  - 配置文件路径缺省搜索：`./cfrp-detector.toml` → `$XDG_CONFIG_HOME/cfrp-detector/config.toml` → macOS `~/Library/Application Support/...`；可被 `--no-config` 关闭以还原 Phase 2 CLI 纯 flags 行为。
  - 增加 `--print-config` 诊断开关：以 JSON 形式 dump 最终 merged 配置后立即退出，便于排障。
- **验收**：`CFRP_ADAPTIVE__ENABLED=true cfrp-detector -c 10 --print-config` 输出 JSON 中 `adaptive.enabled=true` 且 `concurrency=10`；显式 flag 正确覆盖 env。

### 4.5 元数据下载专用 retry/backoff（不对 probe 重试）
- **背景**：Cloudflare CIDR 列表 / locations JSON 下载偶发网络抖动会让整个 `Detector::new` 失败；但对 edge target 的 probe 绝不能自动重试，否则污染置信度/测速结果。
- **目标**：`FileCache::load_or_fetch` 的上游 HTTP 下载部分引入指数退避重试；`probe / speedtest` 路径保持"单次尝试"行为不变。
- **范围**：
  - 在 `cache.rs` 中新增 `fetch_with_retry(url, client, policy)`：
    - 默认策略：最大 3 次重试；初始 delay 500ms，factor 2，jitter 30%；仅对 5xx / 连接超时 / DNS 失败重试。
    - 对 4xx（除 429）直接放弃，避免死循环。
    - `RetryPolicy` 可在 `CacheConfig` 中覆盖：`max_retries / base_delay / retry_on_429`。
  - 在 `DetectorError` 中新增 `RetriesExceeded { source, attempts }` 变体，便于 CLI 输出"重试 N 次后仍失败"的诊断。
  - **硬约束**：`ProbeEngine::tls_probe / http_probe`、`SpeedTester::test`、`Detector::fetch_edge_info` **不**引入任何 retry；如需 benchmark 消除偶发抖动，由调用层多次跑再取均值。
- **验收**：用 Phase 4.1 mock server 注入前 2 次 503 第 3 次 200，`Detector::new` 成功；注入 4 次失败 → 返回 `RetriesExceeded{attempts:3}`。probe 层遇到相同错误序列仍在第 1 次失败就返回。

### 4.6 Graceful shutdown / cancellation
- **背景**：`detect_batch_with_progress` 中每个 task 都是 `tokio::spawn` 并 `acquire_owned()`，收到 Ctrl+C 时任务要么立即 drop（连接泄露）要么继续跑完锁死 bar；无法输出"已完成 N/总 M"的部分结果。
- **目标**：
  - 响应 SIGINT/SIGTERM（Ctrl+C）：停止接受新任务，等待 in-flight 任务最多 N 秒 grace period，超时后强制 abort 并输出 partial results。
  - 支持在 `detect_batch_with_progress` 中注入 cancellation token，便于库作为 library 嵌入到 server 时由外层 axum/tonic 优雅取消。
- **范围**：
  - 新增 `Detector::detect_batch_with_cancel(..., cancel: tokio_util::sync::CancellationToken)`：
    - 每个 spawn 的 task 在 `sem.acquire_owned().await` 之前先 `tokio::select! { _ = cancel.cancelled() => return }`。
    - in-flight task 完成后，收集器 loop 中也 select cancel token，触发后跳出提前进入排序/输出阶段。
  - CLI 层：`tokio::signal::ctrl_c()` 包装 cancel token；grace period 默认 `--shutdown-timeout 10s`。
  - 进度条在收到 SIGINT 时 `abandon_with_message("shutdown after N/M done")` 而非无限等待。
  - **资源清理保障**：`Detector` / `ProbeEngine` 内部的连接池、session cache 在 `Drop` 时无需阻塞（已由 tokio runtime 驱动），仅确保无 `must_use` 未 drop 的资源句柄告警。
- **验收**：对 10k 目标运行到 20% 时 Ctrl+C：≤ shutdown-timeout 内进程退出；exit code 非 0；输出文件中包含截至取消点的部分结果（与输入序前缀一致）。第二次 Ctrl+C 立即 abort exit code 130。

### 4.7 CI：fmt / check / clippy / test / bench + cross 编译
- **背景**：无 CI 配置文件。商用交付至少保证 Linux x86_64、Linux aarch64、macOS aarch64 三个 Tier 1 平台的构建与测试。
- **范围**：
  - GitHub Actions `.github/workflows/ci.yml`：
    - **Lint job (fast path)**：`cargo fmt --all --check` + `cargo clippy --all --all-targets -- -D warnings`（Rust 工具链 pin 到 workspace 的 rust-version = 1.97.1，用 `dtolnay/rust-toolchain` action）。
    - **Test job**：Linux x86_64 下 `cargo test --all`，开启 `--nocapture` 可重现日志；生成覆盖率报告（`cargo-llvm-cov` → codecov.io 上传）。
    - **Clippy extra job (release)**：`cargo clippy --all --release` 加上 `clippy::pedantic` allowlist，避免 debug 版的 pedantic 噪音。
    - **Cross compile job**：使用 `cross` (`cross-rs/cross`) 构建：
      - `x86_64-unknown-linux-gnu` (glibc 静态 / 动态双产物)
      - `aarch64-unknown-linux-gnu`
      - `aarch64-apple-darwin`（如果是 macOS runner）
      - `x86_64-pc-windows-msvc`（最低优先级，预留）
    - **Bench smoke job**：cargo bench 跑 1 次迭代（不收集数据，只保证能编译通过）。
  - 缓存策略：`Swatinem/rust-cache` 缓存 target / cargo registry，PR 运行 < 10 分钟目标。
  - 分支策略：main 保护，PR 必须通过 lint + test + cross-compile build；bench smoke 可允许失败但需评论提示。
- **验收**：空提交触发 CI，4 个 job 全绿；本地 `cargo fmt` / `cargo clippy -- -D warnings` / `cross build --target aarch64-unknown-linux-gnu` 全通。


### 4.9 Phase 4 跨子项一致性要求
- 所有 CLI 新增开关（`--no-config`、`--log-format`、`--shutdown-timeout` 等）必须 `--help` 中有中文/英文一致的说明，与 Phase 2 的 clap 风格一致。
- 所有错误场景引入的新 `DetectorError` 变体必须有 `#[error("...")]` thiserror 映射，且 CLI 层用 `anyhow::Context` 包装为人类可读的提示。
- Phase 3 bench harness 必须能在 Phase 4 mock server 上无外网跑通 baseline，保证 4.1 与 3.3 类型复用。
- Retry / Cancel 逻辑**不得**影响 `detect_batch` 的输出确定性：取消触发时 partial result 的顺序仍等于输入前缀顺序。