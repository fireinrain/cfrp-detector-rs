use anyhow::{Context, Result};
use cfrp_detector::{
    AdaptiveConfig, BatchProgress, BatchTarget, Confidence, Detector, DetectorConfig,
    MasscanConfig, MasscanPipeline, MasscanScanner, PipelineAsnTask, PipelineOptions,
    SpeedTestConfig, SpeedTester, Target,
};
use clap::{Parser, Subcommand};
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Txt,
    Csv,
    Json,
}

impl FromStr for OutputFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "txt" | "text" => Ok(Self::Txt),
            "csv" => Ok(Self::Csv),
            "json" | "j" => Ok(Self::Json),
            other => anyhow::bail!("unknown format: {other}, expected txt|csv|json"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub input: Option<PathBuf>,
    #[serde(default)]
    pub output: Option<PathBuf>,
    #[serde(default)]
    pub format: Option<OutputFormat>,

    #[serde(default)]
    pub targets: Vec<String>,

    #[serde(default = "cf_concurrency")]
    pub concurrency: usize,

    #[serde(default)]
    pub adaptive: bool,
    #[serde(default = "cf_a_min")]
    pub a_min: usize,
    #[serde(default = "cf_a_max")]
    pub a_max: usize,
    #[serde(default = "cf_a_initial")]
    pub a_initial: usize,
    #[serde(default = "cf_a_window")]
    pub a_window: usize,

    #[serde(default)]
    pub progress: bool,
    #[serde(default)]
    pub speedtest: bool,
    #[serde(default = "cf_speedtest_url_path")]
    pub speedtest_url_path: String,
    #[serde(default = "cf_speedtest_threads")]
    pub speedtest_threads: usize,
    #[serde(default = "cf_speedtest_timeout_secs")]
    pub speedtest_timeout_secs: u64,
    #[serde(default = "cf_speedtest_concurrency")]
    pub speedtest_concurrency: usize,

    #[serde(default)]
    pub fast: bool,
    #[serde(default = "cf_probe_timeout_secs")]
    pub probe_timeout_secs: u64,
    #[serde(default)]
    pub governor_report: bool,
    #[serde(default)]
    pub no_governor: bool,
    #[serde(default = "cf_tls_session_cache")]
    pub tls_session_cache: usize,
    #[serde(default)]
    pub speedtest_0rtt: bool,

    #[serde(default)]
    pub bench: bool,
    #[serde(default)]
    pub bench_quick: bool,

    #[serde(default = "cf_grace_seconds")]
    pub grace_seconds: u64,
}

fn cf_concurrency() -> usize {
    10
}
fn cf_a_min() -> usize {
    1
}
fn cf_a_max() -> usize {
    128
}
fn cf_a_initial() -> usize {
    16
}
fn cf_a_window() -> usize {
    10
}
fn cf_speedtest_url_path() -> String {
    "/cdn-cgi/trace".into()
}
fn cf_speedtest_threads() -> usize {
    3
}
fn cf_speedtest_timeout_secs() -> u64 {
    5
}
fn cf_speedtest_concurrency() -> usize {
    8
}
fn cf_probe_timeout_secs() -> u64 {
    3
}
fn cf_tls_session_cache() -> usize {
    256
}
fn cf_grace_seconds() -> u64 {
    30
}

impl Default for ConfigFile {
    fn default() -> Self {
        Self {
            domain: None,
            input: None,
            output: None,
            format: None,
            targets: Vec::new(),
            concurrency: cf_concurrency(),
            adaptive: false,
            a_min: cf_a_min(),
            a_max: cf_a_max(),
            a_initial: cf_a_initial(),
            a_window: cf_a_window(),
            progress: false,
            speedtest: false,
            speedtest_url_path: cf_speedtest_url_path(),
            speedtest_threads: cf_speedtest_threads(),
            speedtest_timeout_secs: cf_speedtest_timeout_secs(),
            speedtest_concurrency: cf_speedtest_concurrency(),
            fast: false,
            probe_timeout_secs: cf_probe_timeout_secs(),
            governor_report: false,
            no_governor: false,
            tls_session_cache: cf_tls_session_cache(),
            speedtest_0rtt: false,
            bench: false,
            bench_quick: false,
            grace_seconds: cf_grace_seconds(),
        }
    }
}

#[derive(Debug, Subcommand)]
enum MasscanCmd {
    #[command(name = "single-asn", about = "Scan a single ASN with masscan")]
    SingleAsn {
        #[arg(long, default_value_t = 45102, help = "ASN number to scan")]
        asn: u32,
        #[arg(long, help = "Enable TLS (default: yes)")]
        tls: Option<bool>,
        #[arg(long, help = "Ports to scan, e.g. 443, 443,8443, 1-65535")]
        port: Option<String>,
    },
    #[command(name = "batch-asn", about = "Scan multiple ASNs from a list file")]
    BatchAsn {
        #[arg(
            short = 'f',
            long = "file",
            default_value = "as.txt",
            help = "ASN list file, format ASN:PORT:TLS per line"
        )]
        filename: PathBuf,
    },
    #[command(name = "single-ip", about = "Scan a single IP address")]
    SingleIp {
        #[arg(long, help = "IP address to scan")]
        ip: Option<IpAddr>,
        #[arg(long, help = "Enable TLS (default: yes)")]
        tls: Option<bool>,
        #[arg(long, help = "Ports to scan, e.g. 1-65535")]
        port: Option<String>,
    },
    #[command(name = "batch-ip", about = "Scan multiple IPs from a list file")]
    BatchIp {
        #[arg(
            short = 'f',
            long = "file",
            default_value = "ips.txt",
            help = "IP list file, one IP per line"
        )]
        filename: PathBuf,
        #[arg(long, help = "Enable TLS (default: yes)")]
        tls: Option<bool>,
        #[arg(long, help = "Ports to scan, e.g. 1-65535")]
        port: Option<String>,
    },
    #[command(
        name = "clear-cache",
        about = "Clear ASN cache, interface setting, and temp files"
    )]
    ClearCache,
}

#[derive(Debug, Parser)]
#[command(
    name = "cfrp-detector",
    version,
    about = "Cloudflare edge detector and network quality probe (Go-compatible CLI)"
)]
struct Cli {
    #[arg(
        short = 'C',
        long = "config",
        value_name = "FILE",
        help = "TOML configuration file. Env vars override config file values, CLI flags override env vars"
    )]
    config: Option<PathBuf>,

    #[arg(
        long = "grace-seconds",
        default_value_t = 30,
        help = "Grace period after SIGINT/SIGTERM to let in-flight probes finish before emitting partial results"
    )]
    grace_seconds: u64,

    #[arg(
        short,
        long,
        help = "Hostname / SNI used for probing (e.g. example.com)"
    )]
    domain: Option<String>,

    #[arg(
        short = 'i',
        long = "input",
        value_name = "FILE",
        help = "Input file with one target per line, or JSON array of targets"
    )]
    input: Option<PathBuf>,

    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Write results to file instead of stdout"
    )]
    output: Option<PathBuf>,

    #[arg(
        short = 'f',
        long = "format",
        value_name = "FORMAT",
        help = "Output format: txt, csv, json (default: infer from output extension, else json)"
    )]
    format: Option<OutputFormat>,

    #[arg(
        short = 'c',
        long = "concurrency",
        default_value_t = 10,
        help = "Initial worker concurrency (for adaptive, this is ignored in favour of --a-initial). For masscan: CF-edge detection thread count."
    )]
    concurrency: usize,

    #[arg(
        short = 'a',
        long = "adaptive",
        help = "Enable adaptive concurrency governor"
    )]
    adaptive: bool,

    #[arg(
        long = "a-min",
        default_value_t = 1,
        help = "Adaptive: minimum concurrency"
    )]
    a_min: usize,

    #[arg(
        long = "a-max",
        default_value_t = 128,
        help = "Adaptive: maximum concurrency"
    )]
    a_max: usize,

    #[arg(
        long = "a-initial",
        default_value_t = 16,
        help = "Adaptive: starting concurrency"
    )]
    a_initial: usize,

    #[arg(
        long = "a-window",
        default_value_t = 10,
        help = "Adaptive: sliding window of recent probes"
    )]
    a_window: usize,

    #[arg(
        short = 'p',
        long = "progress",
        help = "Show an interactive progress bar on stderr"
    )]
    progress: bool,

    #[arg(
        short = 's',
        long = "speedtest",
        help = "After detection, run a download speed-test on every edge target"
    )]
    speedtest: bool,

    #[arg(
        long = "speedtest-url",
        default_value = "/cdn-cgi/trace",
        help = "URL path used for the speed-test payload (used with --domain)"
    )]
    speedtest_url_path: String,

    #[arg(
        short = 't',
        long = "threads",
        default_value_t = 3,
        help = "Speedtest: concurrent download threads per target"
    )]
    speedtest_threads: usize,

    #[arg(
        long = "speedtest-timeout",
        default_value_t = 5,
        help = "Speedtest: timeout in seconds per target"
    )]
    speedtest_timeout_secs: u64,

    #[arg(
        long = "speedtest-concurrency",
        default_value_t = 8,
        help = "Speedtest: concurrent targets under test"
    )]
    speedtest_concurrency: usize,

    #[arg(
        long = "fast",
        help = "Fast one-shot mode: only takes a single positional target, skips batch logic"
    )]
    fast: bool,

    #[arg(
        long = "timeout",
        default_value_t = 3,
        help = "Probe request timeout in seconds (per target, HTTPS+HTTP)"
    )]
    probe_timeout_secs: u64,

    #[arg(
        long = "bench",
        help = "Run an in-process micro-benchmark suite (governor + connector baseline) and print a Go-compatible JSON report to stdout"
    )]
    bench: bool,

    #[arg(
        long = "bench-quick",
        help = "Same as --bench but with smaller sample sizes (for CI smoke test)"
    )]
    bench_quick: bool,

    #[arg(
        long = "governor-report",
        help = "Print final FD/governor snapshot on stderr after batch detection completes"
    )]
    governor_report: bool,

    #[arg(
        long = "no-governor",
        help = "Disable the FD/resource-aware concurrency governor (run with original cap only)"
    )]
    no_governor: bool,

    #[arg(
        long = "tls-session-cache",
        default_value_t = 256,
        help = "Maximum TLS session cache entries (for session resumption across connections)"
    )]
    tls_session_cache: usize,

    #[arg(
        long = "speedtest-0rtt",
        help = "Enable TLS 0-RTT early data in the speed-test (requires TLS session cache warmup on the same endpoint first)"
    )]
    speedtest_0rtt: bool,

    #[arg(
        long = "interface",
        help = "Network interface used by masscan (e.g. eth0). If omitted, auto-detected or loaded from setting.txt"
    )]
    interface: Option<String>,

    #[arg(
        long = "rate",
        default_value_t = 10000,
        help = "masscan pps packet rate (default 10000)"
    )]
    rate: u64,

    #[arg(
        long = "masscan-bin",
        value_name = "FILE",
        help = "Path to masscan binary (default: ./masscan if present, otherwise 'masscan' on PATH)"
    )]
    masscan_binary: Option<PathBuf>,

    #[arg(
        long = "asn-cache-dir",
        default_value = "asn",
        help = "Directory used for caching ASN CIDR lists (default: ./asn)"
    )]
    asn_cache_dir: PathBuf,

    #[arg(
        long = "iface-setting-file",
        default_value = "setting.txt",
        help = "Path to the file persisting the default network interface (default: ./setting.txt)"
    )]
    iface_setting_file: PathBuf,

    #[arg(
        long = "output-dir",
        default_value = ".",
        help = "Directory where masscan pipeline CSV outputs are written (default: current dir)"
    )]
    output_dir: PathBuf,

    #[command(subcommand)]
    masscan: Option<MasscanCmd>,

    #[arg(
        value_name = "TARGET",
        help = "Targets in form ip[:port] or [ipv6]:port"
    )]
    targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InputTarget {
    ip: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct ExportRecord {
    target: String,
    ip: String,
    port: u16,
    is_cloudflare_edge: bool,
    is_tls: bool,
    is_usable: bool,
    status_code: Option<u16>,
    colo: Option<String>,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    latency_ms: Option<u128>,
    download_speed_bytes_per_sec: Option<u64>,
    confidence: String,
    confidence_reason: String,
    reasons: Vec<String>,
    error: Option<String>,
}

impl ExportRecord {
    fn build(br: &cfrp_detector::BatchResult, speed_bps: Option<u64>) -> Self {
        let r = br.result.as_ref();
        let edge = r.and_then(|x| x.edge_info.as_ref());
        Self {
            target: br.target.to_string(),
            ip: br.target.ip.to_string(),
            port: br.target.port,
            is_cloudflare_edge: r.map(|x| x.is_cloudflare_edge).unwrap_or(false),
            is_tls: r.map(|x| x.is_tls).unwrap_or(false),
            is_usable: r.map(|x| x.is_usable).unwrap_or(false),
            status_code: r.and_then(|x| x.http_status_code),
            colo: edge.and_then(|x| x.colo_code.clone()),
            country: edge.and_then(|x| x.country.clone()),
            region: edge.and_then(|x| x.region.clone()),
            city: edge.and_then(|x| x.city.clone()),
            latency_ms: edge.and_then(|x| x.latency.map(|d| d.as_millis())),
            download_speed_bytes_per_sec: speed_bps
                .or_else(|| edge.and_then(|x| x.download_speed_bytes_per_sec)),
            confidence: r
                .map(|x| format!("{:?}", x.confidence))
                .unwrap_or_else(|| format!("{:?}", Confidence::None)),
            confidence_reason: r.map(|x| x.confidence_reason.clone()).unwrap_or_default(),
            reasons: r.map(|x| x.reasons.clone()).unwrap_or_default(),
            error: br.error.clone(),
        }
    }

    fn txt_line(&self) -> String {
        fn k<T: std::fmt::Display>(key: &str, v: &Option<T>) -> String {
            match v {
                Some(x) => format!(" {key}={x}"),
                None => String::new(),
            }
        }
        let reasons_joined = if self.reasons.is_empty() {
            String::new()
        } else {
            format!(" reasons=[{}]", self.reasons.join("; "))
        };
        format!(
            "{} edge={} tls={} usable={} conf={}{}{}{}{}{}{}{}{}{}",
            self.target,
            bool_yn(self.is_cloudflare_edge),
            bool_yn(self.is_tls),
            bool_yn(self.is_usable),
            self.confidence,
            k("status", &self.status_code),
            k("colo", &self.colo),
            k("country", &self.country),
            k("region", &self.region),
            k("city", &self.city),
            self.latency_ms
                .map(|ms| format!(" latency_ms={}", ms))
                .unwrap_or_default(),
            self.download_speed_bytes_per_sec
                .map(|bps| format!(" bps={}", bps))
                .unwrap_or_default(),
            reasons_joined,
            self.error
                .as_ref()
                .map(|e| format!(" error=\"{}\"", e.replace('"', "\\\"")))
                .unwrap_or_default(),
        )
    }
}

fn bool_yn(v: bool) -> &'static str {
    if v { "Y" } else { "N" }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InProcessBaselineResult {
    name: String,
    avg_ns: u128,
    min_ns: u128,
    max_ns: u128,
    ops_per_sec: f64,
    #[serde(default)]
    throughput_bps: Option<u64>,
    #[serde(default)]
    extra: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct InProcessBaselineSuite {
    results: Vec<InProcessBaselineResult>,
    generated_at: Option<String>,
    rust_version: Option<String>,
    os: Option<String>,
    arch: Option<String>,
}

fn run_in_process_bench(quick: bool) -> InProcessBaselineSuite {
    use cfrp_detector::governor::{
        MockFdCounter, ResourceGovernor, ResourceGovernorConfig, classify_resource_error,
    };
    use cfrp_detector::{ConnectorConfig, DetectorConfig, PinnedConnector, ProbeConfig};
    use std::time::{Instant, SystemTime};

    let iterations = if quick { 2_000 } else { 50_000 };
    let warmup = if quick { 50 } else { 500 };

    fn bench_one<F: FnMut()>(mut f: F, iters: usize, warmup: usize) -> (u128, u128, u128) {
        for _ in 0..warmup {
            f();
        }
        let mut min = u128::MAX;
        let mut max = u128::MIN;
        let total_start = Instant::now();
        for _ in 0..iters {
            let s = Instant::now();
            f();
            let d = s.elapsed().as_nanos();
            if d < min {
                min = d;
            }
            if d > max {
                max = d;
            }
        }
        let total_ns = total_start.elapsed().as_nanos();
        let avg = total_ns / iters.max(1) as u128;
        (avg, min, max)
    }

    let mut results: Vec<InProcessBaselineResult> = Vec::new();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| format!("unixtime={}", d.as_secs()))
        .ok();

    // Scenario 1: Governor cap_concurrency (baseline: Go sync.Mutex + ring)
    {
        let cfg = ResourceGovernorConfig::default();
        let mock = MockFdCounter::new(400, 1024);
        let gov = ResourceGovernor::new(cfg, mock);
        for _ in 0..5_000 {
            gov.record_outcome(false);
        }
        let (avg, min, max) = bench_one(
            || {
                let (capped, _snap) = gov.cap_concurrency(64);
                std::hint::black_box(capped);
            },
            iterations,
            warmup,
        );
        let mut extra = std::collections::HashMap::new();
        extra.insert("go_baseline_hint_ns".into(), "2500".into());
        extra.insert(
            "baseline_component".into(),
            "go-cfrp-detector/pkg/governor".into(),
        );
        results.push(InProcessBaselineResult {
            name: "governor.cap_concurrency".into(),
            avg_ns: avg,
            min_ns: min,
            max_ns: max,
            ops_per_sec: if avg > 0 {
                1_000_000_000.0 / avg as f64
            } else {
                0.0
            },
            extra,
            ..Default::default()
        });
    }

    // Scenario 2: classify_resource_error (Go strings.Contains + switch)
    {
        let io_emfile = std::io::Error::from_raw_os_error(24);
        let e = cfrp_detector::DetectorError::Io(io_emfile);
        let (avg, min, max) = bench_one(
            || {
                let b = classify_resource_error(&e);
                std::hint::black_box(b);
            },
            iterations,
            warmup,
        );
        let mut extra = std::collections::HashMap::new();
        extra.insert("go_baseline_hint_ns".into(), "180".into());
        extra.insert(
            "baseline_component".into(),
            "go-cfrp-detector/pkg/governor".into(),
        );
        results.push(InProcessBaselineResult {
            name: "governor.classify_resource_error_EMFILE".into(),
            avg_ns: avg,
            min_ns: min,
            max_ns: max,
            ops_per_sec: if avg > 0 {
                1_000_000_000.0 / avg as f64
            } else {
                0.0
            },
            extra,
            ..Default::default()
        });
    }

    // Scenario 3: PinnedConnector::new default (Go tls.Config + x509.VerifyOptions)
    {
        let (avg, min, max) = bench_one(
            || {
                let c = PinnedConnector::new(ConnectorConfig::default()).unwrap();
                std::hint::black_box(c.tls_session_cache_len());
            },
            iterations / 50,
            warmup / 5,
        );
        let mut extra = std::collections::HashMap::new();
        extra.insert("go_baseline_hint_ns".into(), "450000".into());
        extra.insert(
            "baseline_component".into(),
            "go-cfrp-detector/pkg/connector".into(),
        );
        results.push(InProcessBaselineResult {
            name: "connector.PinnedConnector_new_default".into(),
            avg_ns: avg,
            min_ns: min,
            max_ns: max,
            ops_per_sec: if avg > 0 {
                1_000_000_000.0 / avg as f64
            } else {
                0.0
            },
            extra,
            ..Default::default()
        });
    }

    // Scenario 4: ProbeConfig -> PinnedClientConfig conversion
    {
        let p = ProbeConfig::default();
        let (avg, min, max) = bench_one(
            || {
                let pinned = p.to_pinned();
                std::hint::black_box(pinned);
            },
            iterations,
            warmup,
        );
        let mut extra = std::collections::HashMap::new();
        extra.insert("go_baseline_hint_ns".into(), "80".into());
        extra.insert(
            "baseline_component".into(),
            "go-cfrp-detector/internal/config".into(),
        );
        results.push(InProcessBaselineResult {
            name: "probe.ProbeConfig_to_pinned".into(),
            avg_ns: avg,
            min_ns: min,
            max_ns: max,
            ops_per_sec: if avg > 0 {
                1_000_000_000.0 / avg as f64
            } else {
                0.0
            },
            extra,
            ..Default::default()
        });
    }

    // Scenario 5: DetectorConfig default clone (vs Go struct copy + slices)
    {
        let d = DetectorConfig::default();
        let (avg, min, max) = bench_one(
            || {
                let cloned = d.clone();
                std::hint::black_box(cloned.max_concurrency);
            },
            iterations,
            warmup,
        );
        let mut extra = std::collections::HashMap::new();
        extra.insert("go_baseline_hint_ns".into(), "40".into());
        extra.insert(
            "baseline_component".into(),
            "go-cfrp-detector/pkg/detector".into(),
        );
        results.push(InProcessBaselineResult {
            name: "detector.DetectorConfig_default_clone".into(),
            avg_ns: avg,
            min_ns: min,
            max_ns: max,
            ops_per_sec: if avg > 0 {
                1_000_000_000.0 / avg as f64
            } else {
                0.0
            },
            extra,
            ..Default::default()
        });
    }

    InProcessBaselineSuite {
        results,
        generated_at: now,
        rust_version: Some(
            option_env!("RUSTC_VERSION")
                .map(|v| format!("rustc {}", v))
                .unwrap_or_else(|| "rustc unknown".into()),
        ),
        os: Some(std::env::consts::OS.into()),
        arch: Some(std::env::consts::ARCH.into()),
    }
}

fn merge_config(cli: &Cli) -> Result<ConfigFile> {
    let defaults = ConfigFile::default();
    let mut fig = Figment::from(Serialized::defaults(&defaults));
    if let Some(path) = cli.config.as_ref() {
        if !path.exists() {
            anyhow::bail!("config file not found: {}", path.display());
        }
        fig = fig.admerge(Toml::file(path));
    }
    fig = fig.admerge(Env::prefixed("CFRP_").split("_").filter(|k| k != "TARGETS"));
    let cfg: ConfigFile = fig
        .extract()
        .context("merge env + config file into ConfigFile")?;

    let mut cli_targets: Vec<String> = cli.targets.clone();
    let mut merged = if cli.config.is_some() {
        let mut t = cfg.targets.clone();
        t.append(&mut cli_targets);
        ConfigFile { targets: t, ..cfg }
    } else {
        ConfigFile {
            targets: cli_targets,
            ..cfg
        }
    };

    if cli.domain.is_some() {
        merged.domain = cli.domain.clone();
    }
    if cli.input.is_some() {
        merged.input = cli.input.clone();
    }
    if cli.output.is_some() {
        merged.output = cli.output.clone();
    }
    if cli.format.is_some() {
        merged.format = cli.format;
    }

    let args = std::env::args().collect::<Vec<_>>();

    merged.adaptive = merged.adaptive || cli.adaptive;
    merged.fast = merged.fast || cli.fast;
    merged.speedtest = merged.speedtest || cli.speedtest;
    merged.progress = merged.progress || cli.progress;
    merged.governor_report = merged.governor_report || cli.governor_report;
    merged.no_governor = merged.no_governor || cli.no_governor;
    merged.speedtest_0rtt = merged.speedtest_0rtt || cli.speedtest_0rtt;
    merged.bench = merged.bench || cli.bench;
    merged.bench_quick = merged.bench_quick || cli.bench_quick;

    merged.concurrency = cli.concurrency;
    merged.a_min = cli.a_min;
    merged.a_max = cli.a_max;
    merged.a_initial = cli.a_initial;
    merged.a_window = cli.a_window;
    merged.speedtest_threads = cli.speedtest_threads;
    merged.speedtest_timeout_secs = cli.speedtest_timeout_secs;
    merged.speedtest_concurrency = cli.speedtest_concurrency;
    merged.probe_timeout_secs = cli.probe_timeout_secs;
    merged.tls_session_cache = cli.tls_session_cache;
    merged.grace_seconds = cli.grace_seconds;
    if args
        .iter()
        .any(|a| a == "--speedtest-url" || a.starts_with("--speedtest-url="))
    {
        merged.speedtest_url_path = cli.speedtest_url_path.clone();
    }

    Ok(merged)
}

fn build_signals_token(
    grace_seconds: u64,
) -> (
    CancellationToken,
    std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>,
) {
    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();
    let fut = async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigint = match signal(SignalKind::interrupt()) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return false,
            };
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
                _ = cancel_child.cancelled() => { return false; }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = &cancel_child;
            let mut ctrlc = tokio::signal::windows::ctrl_c().ok()?;
            ctrlc.recv().await?;
        }
        eprintln!(
            "[shutdown] signal received; cancelling new probes, waiting {grace_seconds}s grace period for in-flight work..."
        );
        cancel_child.cancel();
        tokio::time::sleep(Duration::from_secs(grace_seconds)).await;
        true
    };
    (cancel, Box::pin(fut))
}

fn build_masscan_scanner(cli: &Cli) -> MasscanScanner {
    let mut mcfg = MasscanConfig::new();
    mcfg.interface = cli.interface.clone();
    mcfg.rate = cli.rate;
    mcfg.masscan_binary_path = cli.masscan_binary.clone();
    mcfg.asn_cache_dir = cli.asn_cache_dir.clone();
    mcfg.iface_setting_file = cli.iface_setting_file.clone();
    MasscanScanner::new(mcfg)
}

fn build_pipeline_options(cli: &Cli, cfg_merged: &ConfigFile) -> PipelineOptions {
    PipelineOptions {
        domain: cfg_merged.domain.clone(),
        concurrency: if cli.concurrency != 10 {
            cli.concurrency
        } else {
            cfg_merged.concurrency.max(100)
        },
        speedtest: cfg_merged.speedtest,
        speedtest_threads: cfg_merged.speedtest_threads,
        speedtest_url_path: cfg_merged.speedtest_url_path.clone(),
        speedtest_concurrency: cfg_merged.speedtest_concurrency,
        output_dir: cli.output_dir.clone(),
        adaptive_min: cfg_merged.a_min,
        adaptive_max: cfg_merged.a_max,
        probe_timeout_secs: cfg_merged.probe_timeout_secs,
        tls_session_cache: cfg_merged.tls_session_cache,
    }
}

async fn run_masscan_subcommand(cli: &Cli, cfg_merged: &ConfigFile) -> Result<bool> {
    let Some(mcmd) = cli.masscan.as_ref() else {
        return Ok(false);
    };
    match mcmd {
        MasscanCmd::ClearCache => {
            let asn_dir = cli.asn_cache_dir.clone();
            let setting = cli.iface_setting_file.clone();
            cfrp_detector::clear_cache(&asn_dir, &setting)?;
            println!(
                "masscan cache cleared: asn_dir={}, setting={}",
                asn_dir.display(),
                setting.display()
            );
            Ok(true)
        }
        MasscanCmd::SingleAsn { asn, tls, port } => {
            let tls = tls.unwrap_or(true);
            let default_port = if tls { "443" } else { "80" };
            let port_str = port.as_deref().unwrap_or(default_port).to_string();
            let scanner = build_masscan_scanner(cli);
            scanner.check_masscan_available()?;
            let pipeline = MasscanPipeline::new(build_pipeline_options(cli, cfg_merged));
            let started = std::time::Instant::now();
            let out = pipeline
                .run_single_asn(&scanner, *asn, &port_str, tls)
                .await?;
            println!(
                "single-asn AS{} done: open={} edges={} masscan_sec={} detect_sec={} output={} total_sec={}",
                asn,
                out.open_ports_count,
                out.cloudflare_edges_count,
                out.masscan_duration_secs,
                out.detection_duration_secs,
                out.output_path.display(),
                started.elapsed().as_secs()
            );
            Ok(true)
        }
        MasscanCmd::BatchAsn { filename } => {
            let tasks_raw = MasscanScanner::read_asn_task_file(filename)?;
            if tasks_raw.is_empty() {
                anyhow::bail!("no ASN tasks found in {}", filename.display());
            }
            let tasks: Vec<PipelineAsnTask> =
                tasks_raw.into_iter().map(PipelineAsnTask::from).collect();
            let scanner = build_masscan_scanner(cli);
            scanner.check_masscan_available()?;
            let pipeline = MasscanPipeline::new(build_pipeline_options(cli, cfg_merged));
            let started = std::time::Instant::now();
            let result = pipeline.run_batch_asn(&scanner, tasks).await?;
            for o in &result.outputs {
                println!(
                    "batch-asn {}: open={} edges={} masscan_sec={} detect_sec={} output={}",
                    o.label,
                    o.open_ports_count,
                    o.cloudflare_edges_count,
                    o.masscan_duration_secs,
                    o.detection_duration_secs,
                    o.output_path.display()
                );
            }
            println!(
                "batch-asn finished {} tasks in {}s",
                result.outputs.len(),
                started.elapsed().as_secs()
            );
            Ok(true)
        }
        MasscanCmd::SingleIp { ip, tls, port } => {
            let target_ip = ip.unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(172, 67, 73, 54)));
            let tls = tls.unwrap_or(true);
            let default_port = if tls { "1-65535" } else { "1-65535" };
            let port_str = port.as_deref().unwrap_or(default_port).to_string();
            let scanner = build_masscan_scanner(cli);
            scanner.check_masscan_available()?;
            let pipeline = MasscanPipeline::new(build_pipeline_options(cli, cfg_merged));
            let started = std::time::Instant::now();
            let out = pipeline
                .run_single_ip(&scanner, target_ip, &port_str, tls)
                .await?;
            println!(
                "single-ip {} done: open={} edges={} masscan_sec={} detect_sec={} output={} total_sec={}",
                target_ip,
                out.open_ports_count,
                out.cloudflare_edges_count,
                out.masscan_duration_secs,
                out.detection_duration_secs,
                out.output_path.display(),
                started.elapsed().as_secs()
            );
            Ok(true)
        }
        MasscanCmd::BatchIp {
            filename,
            tls,
            port,
        } => {
            let ips = MasscanScanner::read_ip_list_file(filename)?;
            if ips.is_empty() {
                anyhow::bail!("no IPs found in {}", filename.display());
            }
            let tls = tls.unwrap_or(true);
            let default_port = if tls { "1-65535" } else { "1-65535" };
            let port_str = port.as_deref().unwrap_or(default_port).to_string();
            let scanner = build_masscan_scanner(cli);
            scanner.check_masscan_available()?;
            let pipeline = MasscanPipeline::new(build_pipeline_options(cli, cfg_merged));
            let started = std::time::Instant::now();
            let out = pipeline
                .run_batch_ip(&scanner, &ips, &port_str, tls)
                .await?;
            println!(
                "batch-ip {} done: open={} edges={} masscan_sec={} detect_sec={} output={} total_sec={}",
                filename.display(),
                out.open_ports_count,
                out.cloudflare_edges_count,
                out.masscan_duration_secs,
                out.detection_duration_secs,
                out.output_path.display(),
                started.elapsed().as_secs()
            );
            Ok(true)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .compact()
        .init();
    let cli = Cli::parse();
    let cfg_merged = merge_config(&cli).context("merge layered config (file + env + cli)")?;

    if run_masscan_subcommand(&cli, &cfg_merged).await? {
        return Ok(());
    }

    if cfg_merged.bench || cfg_merged.bench_quick {
        let report = run_in_process_bench(cfg_merged.bench_quick);
        match cfg_merged.format.unwrap_or(OutputFormat::Json) {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            OutputFormat::Csv | OutputFormat::Txt => {
                let stdout = std::io::stdout();
                let mut out = stdout.lock();
                writeln!(
                    out,
                    "{:<45} {:>18} {:>18} {:>10}",
                    "SCENARIO", "AVG_NS", "GO_HINT_NS", "RATIO"
                )?;
                for r in &report.results {
                    let go_hint = r
                        .extra
                        .get("go_baseline_hint_ns")
                        .and_then(|s| s.parse::<u128>().ok())
                        .unwrap_or_default();
                    let ratio = if r.avg_ns > 0 && go_hint > 0 {
                        format!("{:.2}x", go_hint as f64 / r.avg_ns as f64)
                    } else {
                        String::from("n/a")
                    };
                    writeln!(
                        out,
                        "{:<45} {:>18} {:>18} {:>10}",
                        r.name, r.avg_ns, go_hint, ratio
                    )?;
                }
            }
        }
        return Ok(());
    }

    let targets = collect_targets_from_merged(&cfg_merged)?;
    if targets.is_empty() {
        anyhow::bail!(
            "no targets supplied; pass positional TARGET, CFRP_TARGETS env, or use -i FILE"
        );
    }

    if cfg_merged.fast {
        if targets.len() != 1 {
            anyhow::bail!(
                "--fast mode requires exactly one target (got {})",
                targets.len()
            );
        }
        let t = &targets[0];
        let result = Detector::detect_oneshot(t, cfg_merged.domain.as_deref())
            .await
            .context("one-shot detection failed")?;
        let br = cfrp_detector::BatchResult {
            id: 0,
            target: t.clone(),
            result: Some(result),
            error: None,
        };
        let records = vec![ExportRecord::build(&br, None)];
        return emit_records(&cfg_merged, &records);
    }

    let (cancel, signal_watch) = build_signals_token(cfg_merged.grace_seconds);
    let signal_handle = tokio::spawn(signal_watch);

    let mut cfg = DetectorConfig::default();
    cfg.probe.request_timeout = Duration::from_secs(cfg_merged.probe_timeout_secs);
    cfg.probe.tls_session_cache_size = cfg_merged.tls_session_cache;
    cfg.probe.allow_0rtt_speedtest = cfg_merged.speedtest_0rtt;
    cfg.governor_enabled = !cfg_merged.no_governor;
    let user_concurrency = cfg_merged.concurrency.max(1);
    cfg.max_concurrency = user_concurrency;
    cfg.governor.user_max_concurrency = user_concurrency;
    cfg.governor.fd_safety_headroom = (cfg_merged.tls_session_cache / 8).max(32);
    let connect_timeout = cfg.probe.connect_timeout;
    let detector = Detector::new(cfg).await.context("initialize detector")?;

    let batch: Vec<BatchTarget> = targets
        .iter()
        .cloned()
        .enumerate()
        .map(|(id, target)| BatchTarget { target, id })
        .collect();

    let pb: Option<ProgressBar> = if cfg_merged.progress {
        let bar = ProgressBar::new(batch.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) c={msg}",
            )
            .expect("progress template must be valid indicatif syntax")
            .progress_chars("=>-"),
        );
        Some(bar)
    } else {
        None
    };

    let adaptive_cfg = AdaptiveConfig {
        enabled: cfg_merged.adaptive,
        initial: cfg_merged.a_initial,
        min: cfg_merged.a_min,
        max: cfg_merged.a_max,
        window: cfg_merged.a_window,
    };

    let results = {
        let cancel_b = cancel.clone();
        let domain = cfg_merged.domain.clone();
        let concurrency = cfg_merged.concurrency;
        let pb_clone = pb.clone();
        if let Some(bar) = pb_clone.as_ref() {
            let bar_c = bar.clone();
            detector
                .detect_batch_with_cancel(
                    &batch,
                    domain.as_deref(),
                    concurrency,
                    adaptive_cfg,
                    cancel_b,
                    move |p: BatchProgress| {
                        bar_c.set_position(p.completed as u64);
                        bar_c.set_message(format!("{}", p.current_concurrency));
                        if p.completed >= p.total {
                            bar_c.finish_with_message("done");
                        }
                    },
                )
                .await
        } else {
            detector
                .detect_batch_with_cancel(
                    &batch,
                    domain.as_deref(),
                    concurrency,
                    adaptive_cfg,
                    cancel_b,
                    |_| {},
                )
                .await
        }
    };
    signal_handle.abort();

    if let Some(pb) = pb.as_ref() {
        let done_count = results
            .iter()
            .filter(|r| r.result.is_some() || r.error.is_some())
            .count();
        let total = results.len();
        let status_tag = if cancel.is_cancelled() {
            "cancelled"
        } else {
            "done"
        };
        pb.finish_with_message(format!("{status_tag} {done_count}/{total}"));
    }

    let speed_cancel = cancel.clone();
    let speed_bps_per_target: std::collections::HashMap<String, u64> = if cfg_merged.speedtest
        && !speed_cancel.is_cancelled()
    {
        if let Some(bar) = pb.as_ref() {
            bar.reset();
            bar.set_length(results.len() as u64);
            bar.set_message("speedtest");
        }
        let speed_cfg = SpeedTestConfig {
            timeout: Duration::from_secs(cfg_merged.speedtest_timeout_secs),
            threads_per_target: cfg_merged.speedtest_threads.max(1),
            concurrency: cfg_merged.speedtest_concurrency.max(1),
        };
        let domain = cfg_merged
            .domain
            .clone()
            .unwrap_or_else(|| "www.cloudflare.com".to_string());
        let host = domain.as_str();
        let speed_targets: Vec<Target> = results
            .iter()
            .filter(|r| {
                r.result
                    .as_ref()
                    .map(|d| d.is_cloudflare_edge && d.is_tls)
                    .unwrap_or(false)
            })
            .map(|r| r.target.clone())
            .collect();
        let mut map = std::collections::HashMap::new();
        use futures::{StreamExt, stream};
        let host_owned = host.to_string();
        let session_cache = cfg_merged.tls_session_cache.max(128);
        let enable_0rtt = cfg_merged.speedtest_0rtt;
        let mut conn_cfg = cfrp_detector::ConnectorConfig::default();
        conn_cfg.connect_timeout = connect_timeout;
        conn_cfg.request_timeout = speed_cfg.timeout;
        conn_cfg.tls_session_cache_max_entries = session_cache;
        conn_cfg.tls_session_cache_size = session_cache;
        conn_cfg.enable_0rtt = enable_0rtt;
        let conn = Arc::new(
            cfrp_detector::PinnedConnector::new(conn_cfg)
                .context("build pinned connector for speedtest")?,
        );
        let stream = stream::iter(speed_targets.into_iter().enumerate())
            .map(|(i, target)| {
                let cfg_inner = speed_cfg.clone();
                let pb_opt = pb.clone();
                let conn_c = conn.clone();
                let sni_c = host_owned.clone();
                let path_c = cfg_merged.speedtest_url_path.clone();
                let sc = speed_cancel.clone();
                async move {
                    if sc.is_cancelled() {
                        return None;
                    }
                    let use_tls = target.port != 80;
                    let tester =
                        SpeedTester::with_connector(conn_c, use_tls, sni_c.clone(), sni_c.clone());
                    if enable_0rtt {
                        tester.set_0rtt_enabled(true);
                    }
                    let res = tester
                        .test_with_warmup(&target, &path_c, &cfg_inner)
                        .await
                        .ok();
                    if let Some(pb) = pb_opt {
                        pb.inc(1);
                    }
                    res.map(|r| (target, r.bytes_per_second)).or_else(|| {
                        let _ = i;
                        None
                    })
                }
            })
            .buffer_unordered(speed_cfg.concurrency.max(1));
        let outcomes: Vec<_> = stream.collect().await;
        let total_targets = outcomes.len();
        for (t, bps) in outcomes.into_iter().flatten() {
            map.insert(t.to_string(), bps);
        }
        if let Some(bar) = pb.as_ref() {
            bar.finish_with_message("speedtest done");
        }
        if cfg_merged.governor_report {
            eprintln!(
                "[speedtest] session_cache_len={} 0rtt_enabled={} targets_tested={}",
                conn.tls_session_cache_len(),
                enable_0rtt,
                total_targets
            );
        }
        map
    } else {
        std::collections::HashMap::new()
    };

    if cfg_merged.governor_report {
        if let Some(gov) = detector.governor() {
            let (_, snap) = gov.cap_concurrency(1);
            eprintln!(
                "[governor] active={} fd_used={}/{} fd_budget={} fd_ratio={:.3} errors={}/{} cap_proposed→{} err_ratio={:.3} throttled_fd={} throttled_err={}",
                snap.active,
                snap.fd_used,
                snap.fd_limit,
                snap.fd_budget,
                snap.fd_ratio,
                snap.resource_errors,
                snap.resource_error_ratio,
                snap.capped_concurrency,
                snap.resource_error_ratio,
                snap.throttled_due_to_fd,
                snap.throttled_due_to_resource_errors,
            );
        } else {
            eprintln!("[governor] governor_disabled_by_cli=true");
        }
    }

    let mut records: Vec<ExportRecord> = Vec::with_capacity(results.len());
    for br in &results {
        let bps = speed_bps_per_target.get(&br.target.to_string()).copied();
        records.push(ExportRecord::build(br, bps));
    }

    emit_records(&cfg_merged, &records)
}

fn collect_targets_from_merged(cfg: &ConfigFile) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let default_port = 443;
    for raw in &cfg.targets {
        if let Some(t) = parse_target(raw, default_port)? {
            targets.push(t);
        }
    }
    if let Some(input_path) = cfg.input.as_ref() {
        let data = fs::read_to_string(input_path)
            .with_context(|| format!("read input file {}", input_path.display()))?;
        if input_path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("json"))
        {
            let trimmed = data.trim();
            if let Ok(items) = serde_json::from_str::<Vec<InputTarget>>(trimmed) {
                for x in items {
                    let ip = IpAddr::from_str(&x.ip).with_context(|| {
                        format!("invalid ip {} in {}", x.ip, input_path.display())
                    })?;
                    targets.push(Target::new(ip, x.port));
                }
            } else if let Ok(items) = serde_json::from_str::<Vec<String>>(trimmed) {
                for x in items {
                    if let Some(t) = parse_target(&x, default_port)? {
                        targets.push(t);
                    }
                }
            } else {
                anyhow::bail!("invalid JSON input format in {}", input_path.display());
            }
        } else if input_path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("csv"))
        {
            let mut rdr = csv::Reader::from_reader(data.as_bytes());
            for (i, row) in rdr.deserialize().enumerate() {
                let r: CsvInputRow = match row {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("skip csv row {}: {}", i, e);
                        continue;
                    }
                };
                let ip =
                    IpAddr::from_str(&r.ip).with_context(|| format!("csv row {} invalid ip", i))?;
                let port = r.port.unwrap_or(default_port);
                targets.push(Target::new(ip, port));
            }
        } else {
            for line in data.lines() {
                let s = line.split('#').next().unwrap_or(line).trim();
                if let Some(t) = parse_target(s, default_port)? {
                    targets.push(t);
                }
            }
        }
    }

    Ok(targets)
}

fn infer_format(cfg: &ConfigFile) -> OutputFormat {
    if let Some(f) = cfg.format {
        return f;
    }
    if let Some(p) = cfg.output.as_ref()
        && let Some(ext) = p.extension().and_then(|x| x.to_str())
    {
        match ext.to_ascii_lowercase().as_str() {
            "txt" | "text" => return OutputFormat::Txt,
            "csv" => return OutputFormat::Csv,
            _ => {}
        }
    }
    OutputFormat::Json
}

fn emit_records(cfg: &ConfigFile, records: &[ExportRecord]) -> Result<()> {
    let fmt = infer_format(cfg);
    let mut sink: Box<dyn Write> = if let Some(path) = cfg.output.as_ref() {
        Box::new(
            fs::File::create(path)
                .with_context(|| format!("open output file {}", path.display()))?,
        )
    } else {
        Box::new(std::io::stdout())
    };
    match fmt {
        OutputFormat::Json => {
            serde_json::to_writer_pretty(&mut sink, records)?;
            sink.write_all(b"\n")?;
        }
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(sink);
            for r in records {
                let row = CsvRow::from(r);
                wtr.serialize(row)?;
            }
            wtr.flush()?;
        }
        OutputFormat::Txt => {
            for r in records {
                writeln!(sink, "{}", r.txt_line())?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct CsvRow<'a> {
    target: &'a str,
    ip: &'a str,
    port: u16,
    is_cloudflare_edge: bool,
    is_tls: bool,
    is_usable: bool,
    status_code: Option<u16>,
    colo: &'a str,
    country: &'a str,
    region: &'a str,
    city: &'a str,
    latency_ms: Option<u128>,
    download_speed_bytes_per_sec: Option<u64>,
    confidence: &'a str,
    confidence_reason: &'a str,
    reasons: String,
    error: &'a str,
}

#[derive(Debug, Deserialize)]
struct CsvInputRow {
    ip: String,
    port: Option<u16>,
}

impl<'a> From<&'a ExportRecord> for CsvRow<'a> {
    fn from(r: &'a ExportRecord) -> Self {
        Self {
            target: &r.target,
            ip: &r.ip,
            port: r.port,
            is_cloudflare_edge: r.is_cloudflare_edge,
            is_tls: r.is_tls,
            is_usable: r.is_usable,
            status_code: r.status_code,
            colo: r.colo.as_deref().unwrap_or(""),
            country: r.country.as_deref().unwrap_or(""),
            region: r.region.as_deref().unwrap_or(""),
            city: r.city.as_deref().unwrap_or(""),
            latency_ms: r.latency_ms,
            download_speed_bytes_per_sec: r.download_speed_bytes_per_sec,
            confidence: &r.confidence,
            confidence_reason: &r.confidence_reason,
            reasons: r.reasons.join("; "),
            error: r.error.as_deref().unwrap_or(""),
        }
    }
}

fn parse_target(raw: &str, default_port: u16) -> Result<Option<Target>> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if let Ok(addr) = std::net::SocketAddr::from_str(s) {
        return Ok(Some(Target::new(addr.ip(), addr.port())));
    }
    if let Ok(ip) = IpAddr::from_str(s) {
        return Ok(Some(Target::new(ip, default_port)));
    }
    if let Some((ip, port)) = s.rsplit_once(':') {
        return Ok(Some(Target::new(
            IpAddr::from_str(ip.trim_matches(['[', ']']))?,
            port.parse()?,
        )));
    }
    anyhow::bail!("invalid target: {s}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parser_has_masscan_subcommands() {
        let cmd = Cli::command();
        let help_text = {
            let mut buf = Vec::new();
            cmd.clone().write_help(&mut buf).unwrap();
            String::from_utf8(buf).unwrap()
        };
        assert!(
            help_text.contains("masscan"),
            "help should mention masscan subcommands"
        );
    }

    #[test]
    fn cli_parse_masscan_clear_cache() {
        let args = &[
            "cfrp-detector",
            "--asn-cache-dir",
            "/tmp/asn",
            "--iface-setting-file",
            "/tmp/if.txt",
            "clear-cache",
        ];
        let cli = Cli::try_parse_from(args).expect("parse clear-cache");
        let cmd = cli.masscan.as_ref().expect("has masscan sub");
        assert!(matches!(cmd, MasscanCmd::ClearCache));
        assert_eq!(cli.asn_cache_dir, PathBuf::from("/tmp/asn"));
        assert_eq!(cli.iface_setting_file, PathBuf::from("/tmp/if.txt"));
    }

    #[test]
    fn cli_parse_masscan_single_asn_defaults() {
        let args = &["cfrp-detector", "single-asn"];
        let cli = Cli::try_parse_from(args).expect("parse single-asn defaults");
        let cmd = cli.masscan.as_ref().expect("has sub");
        let MasscanCmd::SingleAsn { asn, tls, port } = cmd else {
            unreachable!("expected SingleAsn variant, got {cmd:?}");
        };
        assert_eq!(*asn, 45102);
        assert!(tls.is_none());
        assert!(port.is_none());
        assert_eq!(cli.rate, 10000);
        assert_eq!(cli.concurrency, 10);
    }

    #[test]
    fn cli_parse_masscan_single_asn_explicit() {
        let args = &[
            "cfrp-detector",
            "--rate",
            "50000",
            "--concurrency",
            "300",
            "--domain",
            "example.com",
            "single-asn",
            "--asn",
            "132203",
            "--tls",
            "true",
            "--port",
            "443,8443",
        ];
        let cli = Cli::try_parse_from(args).expect("parse single-asn explicit");
        assert_eq!(cli.rate, 50000);
        assert_eq!(cli.concurrency, 300);
        assert_eq!(cli.domain.as_deref(), Some("example.com"));
        let MasscanCmd::SingleAsn { asn, tls, port } = cli.masscan.as_ref().expect("has sub")
        else {
            unreachable!("expected SingleAsn variant");
        };
        assert_eq!(*asn, 132203);
        assert_eq!(*tls, Some(true));
        assert_eq!(port.as_deref(), Some("443,8443"));
    }

    #[test]
    fn cli_parse_masscan_batch_asn() {
        let args = &["cfrp-detector", "batch-asn", "-f", "custom_asn.txt"];
        let cli = Cli::try_parse_from(args).expect("parse batch-asn");
        let MasscanCmd::BatchAsn { filename } = cli.masscan.as_ref().expect("sub") else {
            unreachable!("expected BatchAsn variant");
        };
        assert_eq!(filename, &PathBuf::from("custom_asn.txt"));
    }

    #[test]
    fn cli_parse_masscan_batch_asn_default_file() {
        let args = &["cfrp-detector", "batch-asn"];
        let cli = Cli::try_parse_from(args).expect("parse batch-asn default");
        let MasscanCmd::BatchAsn { filename } = cli.masscan.as_ref().expect("sub") else {
            unreachable!("expected BatchAsn variant");
        };
        assert_eq!(filename, &PathBuf::from("as.txt"));
    }

    #[test]
    fn cli_parse_masscan_single_ip_default() {
        let args = &["cfrp-detector", "single-ip"];
        let cli = Cli::try_parse_from(args).expect("parse single-ip default");
        let MasscanCmd::SingleIp { ip, tls, port } = cli.masscan.as_ref().expect("sub") else {
            unreachable!("expected SingleIp variant");
        };
        assert!(ip.is_none());
        assert!(tls.is_none());
        assert!(port.is_none());
    }

    #[test]
    fn cli_parse_masscan_single_ip_explicit() {
        let args = &[
            "cfrp-detector",
            "--interface",
            "eth1",
            "single-ip",
            "--ip",
            "10.0.0.1",
            "--tls",
            "false",
            "--port",
            "80,8080",
        ];
        let cli = Cli::try_parse_from(args).expect("parse single-ip explicit");
        assert_eq!(cli.interface.as_deref(), Some("eth1"));
        let MasscanCmd::SingleIp { ip, tls, port } = cli.masscan.as_ref().expect("sub") else {
            unreachable!("expected SingleIp variant");
        };
        assert_eq!(*ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(*tls, Some(false));
        assert_eq!(port.as_deref(), Some("80,8080"));
    }

    #[test]
    fn cli_parse_masscan_batch_ip() {
        let args = &[
            "cfrp-detector",
            "--output-dir",
            "/tmp/out",
            "--masscan-bin",
            "/usr/local/bin/masscan",
            "batch-ip",
            "-f",
            "my_ips.txt",
            "--tls",
            "true",
            "--port",
            "443",
        ];
        let cli = Cli::try_parse_from(args).expect("parse batch-ip");
        assert_eq!(cli.output_dir, PathBuf::from("/tmp/out"));
        assert_eq!(
            cli.masscan_binary.as_deref(),
            Some(PathBuf::from("/usr/local/bin/masscan").as_path())
        );
        let MasscanCmd::BatchIp {
            filename,
            tls,
            port,
        } = cli.masscan.as_ref().expect("sub")
        else {
            unreachable!("expected BatchIp variant");
        };
        assert_eq!(filename, &PathBuf::from("my_ips.txt"));
        assert_eq!(*tls, Some(true));
        assert_eq!(port.as_deref(), Some("443"));
    }

    #[test]
    fn cli_parse_masscan_batch_ip_default_file() {
        let args = &["cfrp-detector", "batch-ip"];
        let cli = Cli::try_parse_from(args).expect("parse batch-ip default");
        let MasscanCmd::BatchIp {
            filename,
            tls,
            port,
        } = cli.masscan.as_ref().expect("sub")
        else {
            unreachable!("expected BatchIp variant");
        };
        assert_eq!(filename, &PathBuf::from("ips.txt"));
        assert!(tls.is_none());
        assert!(port.is_none());
    }

    #[test]
    fn build_masscan_scanner_preserves_flags() {
        let args = &[
            "cfrp-detector",
            "--rate",
            "25000",
            "--interface",
            "enp0s3",
            "--asn-cache-dir",
            "/a/cache",
            "--iface-setting-file",
            "/a/s.txt",
            "--masscan-bin",
            "/bin/ms",
            "single-asn",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let scanner = build_masscan_scanner(&cli);
        assert_eq!(scanner.cfg.rate, 25000);
        assert_eq!(scanner.cfg.interface.as_deref(), Some("enp0s3"));
        assert_eq!(scanner.cfg.asn_cache_dir, PathBuf::from("/a/cache"));
        assert_eq!(scanner.cfg.iface_setting_file, PathBuf::from("/a/s.txt"));
        assert_eq!(
            scanner.cfg.masscan_binary_path.as_deref(),
            Some(PathBuf::from("/bin/ms").as_path())
        );
    }

    #[test]
    fn build_pipeline_options_inherits_detection_flags() {
        let cli = Cli::try_parse_from([
            "cfrp-detector",
            "--output-dir",
            "/tmp/outs",
            "--timeout",
            "5",
            "--tls-session-cache",
            "512",
            "--a-min",
            "4",
            "--a-max",
            "200",
            "--concurrency",
            "150",
            "single-asn",
        ])
        .unwrap();
        let cfg = merge_config(&cli).unwrap();
        let opts = build_pipeline_options(&cli, &cfg);
        assert_eq!(opts.probe_timeout_secs, 5);
        assert_eq!(opts.tls_session_cache, 512);
        assert_eq!(opts.adaptive_min, 4);
        assert_eq!(opts.adaptive_max, 200);
        assert_eq!(opts.concurrency, 150);
        assert_eq!(opts.output_dir, PathBuf::from("/tmp/outs"));
    }

    #[test]
    fn main_help_no_panic() {
        let args = &["cfrp-detector", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err(), "--help should cause a clap exit");
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn single_asn_help_no_panic() {
        let args = &["cfrp-detector", "single-asn", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn batch_asn_help_no_panic() {
        let args = &["cfrp-detector", "batch-asn", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn single_ip_help_no_panic() {
        let args = &["cfrp-detector", "single-ip", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn batch_ip_help_no_panic() {
        let args = &["cfrp-detector", "batch-ip", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn clear_cache_help_no_panic() {
        let args = &["cfrp-detector", "clear-cache", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }
}
