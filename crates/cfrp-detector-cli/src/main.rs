use anyhow::{Context, Result};
use cfrp_detector::{
    AdaptiveConfig, BatchProgress, BatchTarget, Confidence, Detector, DetectorConfig,
    MasscanConfig, MasscanPipeline, MasscanScanner, PipelineAsnTask, PipelineOptions,
    SpeedTestConfig, SpeedTester, Target,
};
use clap::{CommandFactory, Parser, Subcommand};
use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, net::IpAddr, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
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
#[serde(default)]
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
    pub speedtest_only: bool,

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
            speedtest_only: false,
            bench: false,
            bench_quick: false,
            grace_seconds: cf_grace_seconds(),
        }
    }
}

#[derive(Debug, Clone, Parser)]
struct GlobalArgs {
    #[arg(
        short = 'C',
        long = "config",
        value_name = "FILE",
        global = true,
        help = "TOML configuration file. Env vars override config file values, CLI flags override env vars"
    )]
    config: Option<PathBuf>,

    #[arg(
        long = "grace-seconds",
        default_value_t = 30,
        global = true,
        help = "Grace period after SIGINT/SIGTERM to let in-flight probes finish before emitting partial results"
    )]
    grace_seconds: u64,
}

#[derive(Debug, Clone, Parser, Default)]
struct DetectArgs {
    #[arg(
        short = 'd',
        long = "domain",
        help = "Hostname / SNI used for probing (e.g. example.com)"
    )]
    pub domain: Option<String>,

    #[arg(
        short = 'i',
        long = "input",
        value_name = "FILE",
        help = "Input file with one target per line, or JSON array of targets"
    )]
    pub input: Option<PathBuf>,

    #[arg(
        short = 'o',
        long = "output",
        value_name = "FILE",
        help = "Write results to file instead of stdout"
    )]
    pub output: Option<PathBuf>,

    #[arg(
        short = 'f',
        long = "format",
        value_name = "FORMAT",
        help = "Output format: txt, csv, json (default: infer from output extension, else json)"
    )]
    pub format: Option<OutputFormat>,

    #[arg(
        short = 'c',
        long = "concurrency",
        default_value_t = 10,
        help = "Initial worker concurrency (for adaptive mode, this is ignored in favour of --a-initial)"
    )]
    pub concurrency: usize,

    #[arg(
        short = 'a',
        long = "adaptive",
        help = "Enable adaptive concurrency governor"
    )]
    pub adaptive: bool,

    #[arg(
        long = "a-min",
        default_value_t = 1,
        help = "Adaptive: minimum concurrency"
    )]
    pub a_min: usize,

    #[arg(
        long = "a-max",
        default_value_t = 128,
        help = "Adaptive: maximum concurrency"
    )]
    pub a_max: usize,

    #[arg(
        long = "a-initial",
        default_value_t = 16,
        help = "Adaptive: starting concurrency"
    )]
    pub a_initial: usize,

    #[arg(
        long = "a-window",
        default_value_t = 10,
        help = "Adaptive: sliding window of recent probes"
    )]
    pub a_window: usize,

    #[arg(
        short = 'p',
        long = "progress",
        help = "Show an interactive progress bar on stderr"
    )]
    pub progress: bool,

    #[arg(
        long = "fast",
        help = "Fast one-shot mode: only takes a single positional target, skips batch logic"
    )]
    pub fast: bool,

    #[arg(
        long = "timeout",
        default_value_t = 3,
        help = "Probe request timeout in seconds (per target, HTTPS+HTTP)"
    )]
    pub probe_timeout_secs: u64,

    #[arg(
        long = "bench",
        help = "Run an in-process micro-benchmark suite (governor + connector baseline) and print a Go-compatible JSON report to stdout"
    )]
    pub bench: bool,

    #[arg(
        long = "bench-quick",
        help = "Same as --bench but with smaller sample sizes (for CI smoke test)"
    )]
    pub bench_quick: bool,

    #[arg(
        long = "governor-report",
        help = "Print final FD/governor snapshot on stderr after batch detection completes"
    )]
    pub governor_report: bool,

    #[arg(
        long = "no-governor",
        help = "Disable the FD/resource-aware concurrency governor (run with original cap only)"
    )]
    pub no_governor: bool,

    #[arg(
        long = "tls-session-cache",
        default_value_t = 256,
        help = "Maximum TLS session cache entries (for session resumption across connections)"
    )]
    pub tls_session_cache: usize,

    #[arg(
        short = 's',
        long = "speed",
        help = "After successful detection, run a download speed-test on confirmed Cloudflare edge targets"
    )]
    pub speedtest: bool,

    #[arg(
        long = "speedtest-url",
        default_value = "/cdn-cgi/trace",
        help = "URL path used for the speed-test payload (used with --domain)"
    )]
    pub speedtest_url_path: String,

    #[arg(
        long = "speedtest-threads",
        default_value_t = 3,
        help = "Speedtest: concurrent download threads per target"
    )]
    pub speedtest_threads: usize,

    #[arg(
        long = "speedtest-timeout",
        default_value_t = 5,
        help = "Speedtest: timeout in seconds per target"
    )]
    pub speedtest_timeout_secs: u64,

    #[arg(
        long = "speedtest-concurrency",
        default_value_t = 8,
        help = "Speedtest: concurrent targets under test"
    )]
    pub speedtest_concurrency: usize,

    #[arg(
        long = "enable-0rtt",
        help = "Enable TLS 0-RTT early data for speedtest (requires TLS session cache warmup on the same endpoint first)"
    )]
    pub enable_0rtt: bool,

    #[arg(
        value_name = "TARGET",
        help = "Targets in form ip[:port] or [ipv6]:port. Default port: 443"
    )]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Parser, Default)]
struct SpeedTestArgs {
    #[arg(
        short = 'd',
        long = "domain",
        help = "Hostname / SNI used for the download connection (e.g. speed.cloudflare.com)"
    )]
    pub domain: Option<String>,

    #[arg(
        short = 'i',
        long = "input",
        value_name = "FILE",
        help = "Input file with one target per line, or JSON array of targets"
    )]
    pub input: Option<PathBuf>,

    #[arg(
        short = 'o',
        long = "output",
        value_name = "FILE",
        help = "Write speed-test results to file instead of stdout"
    )]
    pub output: Option<PathBuf>,

    #[arg(
        short = 'f',
        long = "format",
        value_name = "FORMAT",
        help = "Output format: txt, csv, json (default: infer from output extension, else json)"
    )]
    pub format: Option<OutputFormat>,

    #[arg(
        long = "url",
        default_value = "/cdn-cgi/trace",
        help = "URL path used for the download payload"
    )]
    pub url_path: String,

    #[arg(
        short = 't',
        long = "threads",
        default_value_t = 3,
        help = "Concurrent download threads per target"
    )]
    pub threads: usize,

    #[arg(
        long = "timeout",
        default_value_t = 5,
        help = "Timeout in seconds per target"
    )]
    pub timeout_secs: u64,

    #[arg(
        short = 'C',
        long = "concurrency",
        default_value_t = 8,
        help = "Concurrent targets under test"
    )]
    pub concurrency: usize,

    #[arg(
        long = "enable-0rtt",
        help = "Enable TLS 0-RTT early data (requires TLS session cache warmup on the same endpoint first)"
    )]
    pub enable_0rtt: bool,

    #[arg(
        long = "tls-session-cache",
        default_value_t = 256,
        help = "Maximum TLS session cache entries (for session resumption across connections)"
    )]
    pub tls_session_cache: usize,

    #[arg(
        short = 'p',
        long = "progress",
        help = "Show an interactive progress bar on stderr"
    )]
    pub progress: bool,

    #[arg(
        value_name = "TARGET",
        help = "Targets in form ip[:port] or [ipv6]:port. Default port: 443"
    )]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Parser, Default)]
struct ScanDetectArgs {
    #[arg(
        short = 'd',
        long = "domain",
        help = "Hostname / SNI used for probing (e.g. example.com)"
    )]
    pub domain: Option<String>,

    #[arg(
        short = 'c',
        long = "concurrency",
        default_value_t = 10,
        help = "Initial worker concurrency (for adaptive mode, this is ignored in favour of --a-initial)"
    )]
    pub concurrency: usize,

    #[arg(
        short = 'a',
        long = "adaptive",
        help = "Enable adaptive concurrency governor"
    )]
    pub adaptive: bool,

    #[arg(
        long = "a-min",
        default_value_t = 1,
        help = "Adaptive: minimum concurrency"
    )]
    pub a_min: usize,

    #[arg(
        long = "a-max",
        default_value_t = 128,
        help = "Adaptive: maximum concurrency"
    )]
    pub a_max: usize,

    #[arg(
        long = "a-initial",
        default_value_t = 16,
        help = "Adaptive: starting concurrency"
    )]
    pub a_initial: usize,

    #[arg(
        long = "a-window",
        default_value_t = 10,
        help = "Adaptive: sliding window of recent probes"
    )]
    pub a_window: usize,

    #[arg(
        short = 'p',
        long = "progress",
        help = "Show an interactive progress bar on stderr"
    )]
    pub progress: bool,

    #[arg(
        long = "timeout",
        default_value_t = 3,
        help = "Probe request timeout in seconds (per target, HTTPS+HTTP)"
    )]
    pub probe_timeout_secs: u64,

    #[arg(
        long = "governor-report",
        help = "Print final FD/governor snapshot on stderr after batch detection completes"
    )]
    pub governor_report: bool,

    #[arg(
        long = "no-governor",
        help = "Disable the FD/resource-aware concurrency governor (run with original cap only)"
    )]
    pub no_governor: bool,

    #[arg(
        long = "tls-session-cache",
        default_value_t = 256,
        help = "Maximum TLS session cache entries (for session resumption across connections)"
    )]
    pub tls_session_cache: usize,
}

#[derive(Debug, Clone, Parser, Default)]
struct ScanSpeedTestArgs {
    #[arg(
        short = 's',
        long = "speedtest",
        help = "After detection, run a download speed-test on confirmed Cloudflare edge targets"
    )]
    pub enabled: bool,

    #[arg(
        short = 't',
        long = "threads",
        default_value_t = 3,
        help = "Speedtest: concurrent download threads per target"
    )]
    pub threads: usize,

    #[arg(
        long = "speedtest-url",
        default_value = "/cdn-cgi/trace",
        help = "URL path used for the speed-test payload (used with --domain)"
    )]
    pub url_path: String,

    #[arg(
        long = "speedtest-timeout",
        default_value_t = 5,
        help = "Speedtest: timeout in seconds per target"
    )]
    pub timeout_secs: u64,

    #[arg(
        long = "speedtest-concurrency",
        default_value_t = 8,
        help = "Speedtest: concurrent targets under test"
    )]
    pub speedtest_concurrency: usize,
}

#[derive(Debug, Clone, Parser, Default)]
struct ScanEngineArgs {
    #[arg(
        long = "interface",
        help = "Network interface used by masscan (e.g. eth0). If omitted, auto-detected or loaded from setting.txt"
    )]
    pub interface: Option<String>,

    #[arg(
        long = "rate",
        default_value_t = 10000,
        help = "masscan pps packet rate (default 10000)"
    )]
    pub rate: u64,

    #[arg(
        long = "masscan-bin",
        value_name = "FILE",
        help = "Path to masscan binary (default: ./masscan if present, otherwise 'masscan' on PATH)"
    )]
    pub masscan_binary: Option<PathBuf>,

    #[arg(
        long = "asn-cache-dir",
        default_value = "asn",
        help = "Directory used for caching ASN CIDR lists (default: ./asn)"
    )]
    pub asn_cache_dir: PathBuf,

    #[arg(
        long = "iface-setting-file",
        default_value = "setting.txt",
        help = "Path to the file persisting the default network interface (default: ./setting.txt)"
    )]
    pub iface_setting_file: PathBuf,

    #[arg(
        long = "output-dir",
        default_value = ".",
        help = "Directory where scan pipeline CSV outputs are written (default: current dir)"
    )]
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone, Subcommand)]
enum ScanCmd {
    #[command(
        about = "Scan a single ASN with masscan, then run Cloudflare edge detection + optional speedtest",
        long_about = "Retrieves all CIDR prefixes for the given ASN, runs masscan port scan, \
                     probes every open port to detect Cloudflare edge nodes, optionally runs speed-tests."
    )]
    Asn {
        #[arg(help = "ASN number (without AS prefix, e.g. 45102)")]
        asn: u32,

        #[arg(
            long,
            help = "TLS hint for the detector pipeline (true = HTTPS, false = HTTP, default: true)"
        )]
        tls: Option<bool>,

        #[arg(
            long,
            default_value = "443",
            help = "Ports to scan, e.g. 443 | 443,8443,2053 | 1-65535 (default: 443)"
        )]
        port: String,

        #[command(flatten)]
        speedtest: ScanSpeedTestArgs,

        #[command(flatten)]
        detect: ScanDetectArgs,

        #[command(flatten)]
        engine: ScanEngineArgs,
    },

    #[command(
        about = "Scan multiple ASNs from a task file, then detect + optional speedtest",
        long_about = "Reads a task file with format `ASN:PORT:TLS` per line (e.g. 45102:443:true).\n\
                     Runs each ASN scan sequentially, writing per-ASN CSVs to the output dir."
    )]
    Asns {
        #[arg(
            short = 'f',
            long = "file",
            default_value = "as.txt",
            help = "ASN task file. Format: ASN:PORT:TLS per line (e.g. 13335:443:true)"
        )]
        filename: PathBuf,

        #[command(flatten)]
        speedtest: ScanSpeedTestArgs,

        #[command(flatten)]
        detect: ScanDetectArgs,

        #[command(flatten)]
        engine: ScanEngineArgs,
    },

    #[command(
        about = "Scan a single IP's ports, then detect + optional speedtest",
        long_about = "Runs masscan against a single IP to find open ports, then probes each \
                     open port to determine whether it's a Cloudflare edge node."
    )]
    Ip {
        #[arg(help = "IPv4 or IPv6 address to scan")]
        ip: IpAddr,

        #[arg(
            long,
            help = "TLS hint for the detector pipeline (true = HTTPS, false = HTTP, default: true)"
        )]
        tls: Option<bool>,

        #[arg(
            long,
            default_value = "1-65535",
            help = "Ports to scan, e.g. 443 | 443,8443 | 1-65535 (default: full range 1-65535)"
        )]
        port: String,

        #[command(flatten)]
        speedtest: ScanSpeedTestArgs,

        #[command(flatten)]
        detect: ScanDetectArgs,

        #[command(flatten)]
        engine: ScanEngineArgs,
    },

    #[command(
        about = "Scan multiple IPs from a list file, then detect + optional speedtest",
        long_about = "Reads one IP per line from the list file, runs masscan port scan on each, \
                     then probes every open port for Cloudflare edge detection."
    )]
    Ips {
        #[arg(
            short = 'f',
            long = "file",
            default_value = "ips.txt",
            help = "IP list file: one IPv4 or IPv6 address per line"
        )]
        filename: PathBuf,

        #[arg(
            long,
            help = "TLS hint for the detector pipeline (true = HTTPS, false = HTTP, default: true)"
        )]
        tls: Option<bool>,

        #[arg(
            long,
            default_value = "1-65535",
            help = "Ports to scan, e.g. 443 | 443,8443 | 1-65535 (default: full range 1-65535)"
        )]
        port: String,

        #[command(flatten)]
        speedtest: ScanSpeedTestArgs,

        #[command(flatten)]
        detect: ScanDetectArgs,

        #[command(flatten)]
        engine: ScanEngineArgs,
    },

    #[command(
        about = "Clear ASN cache directory, saved interface setting file, and temp artifacts"
    )]
    ClearCache {
        #[command(flatten)]
        engine: ScanEngineArgs,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(
        about = "Detect Cloudflare edge nodes on the given targets",
        long_about = "Probes one or more `ip:port` targets to determine whether they are Cloudflare \
                     edge nodes. Detects the colo (data-center), region, latency, and TLS status. \
                     This command does not perform port scanning or speed testing; use the \
                     `speedtest` command for quality measurements or `scan` for masscan-based discovery."
    )]
    Detect(DetectArgs),

    #[command(
        about = "Run download speed-tests against the given targets",
        long_about = "Performs concurrent download speed-tests against the supplied targets to measure \
                     bandwidth, latency (connect / TLS handshake / TTFB), and TLS handshake details. \
                     This command does not detect Cloudflare edge traits; if you need that, run \
                     `detect` first and pass its output as input."
    )]
    SpeedTest(SpeedTestArgs),

    #[command(
        about = "masscan-based port scan → detect → optional speedtest pipeline",
        long_about = "Uses masscan to perform high-speed SYN scans first, then pipes every open \
                     port through the Cloudflare detector. Useful for large-scale discovery \
                     across ASNs or IP ranges."
    )]
    #[command(subcommand)]
    Scan(ScanCmd),
}

#[derive(Debug, Parser)]
#[command(
    name = "cfrp-detector",
    version,
    about = "Cloudflare edge detector and network quality probe",
    after_help = concat!(
        "EXAMPLES:\n",
        "  # Detect if an IP:port is a Cloudflare edge\n",
        "  cfrp-detector detect 104.16.132.229:443\n",
        "\n",
        "  # Batch detect targets from a file with progress bar\n",
        "  cfrp-detector detect -i targets.txt -p\n",
        "\n",
        "  # Run a speed-test against known endpoints\n",
        "  cfrp-detector speedtest 1.1.1.1:443 104.16.132.229:443 -d speed.cloudflare.com -p\n",
        "\n",
        "  # Speed-test a batch of targets from detect JSON/CSV output\n",
        "  cfrp-detector speedtest -i detect_results.json -o speeds.csv -f csv\n",
        "\n",
        "  # Scan an entire ASN for Cloudflare edges on port 443, then speed-test\n",
        "  cfrp-detector scan asn 13335 --port 443 -s\n",
        "\n",
        "  # Full-port scan a specific IP, write results to /tmp/out\n",
        "  cfrp-detector scan ip 1.1.1.1 --port 1-65535 --output-dir /tmp/out\n",
    ),
    propagate_version = true,
)]
struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InputTarget {
    ip: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct ExportRecord {
    id: usize,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    speedtest_elapsed_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    speedtest_connect_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    speedtest_tls_handshake_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    speedtest_ttfb_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    speedtest_handshake: Option<String>,
    confidence: String,
    confidence_reason: String,
    reasons: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct SpeedExport {
    bytes_per_second: Option<u64>,
    elapsed_ms: Option<u128>,
    connect_ms: Option<u128>,
    tls_handshake_ms: Option<u128>,
    ttfb_ms: Option<u128>,
    handshake: Option<String>,
}

impl From<&cfrp_detector::SpeedTestResult> for SpeedExport {
    fn from(sr: &cfrp_detector::SpeedTestResult) -> Self {
        Self {
            bytes_per_second: Some(sr.bytes_per_second),
            elapsed_ms: Some(sr.elapsed.as_millis()),
            connect_ms: sr.connect_latency.map(|d| d.as_millis()),
            tls_handshake_ms: sr.tls_handshake_latency.map(|d| d.as_millis()),
            ttfb_ms: sr.ttfb_latency.map(|d| d.as_millis()),
            handshake: sr.handshake_type.as_ref().map(|h| format!("{:?}", h)),
        }
    }
}

impl ExportRecord {
    fn build(br: &cfrp_detector::BatchResult, speed: Option<SpeedExport>) -> Self {
        let r = br.result.as_ref();
        let edge = r.and_then(|x| x.edge_info.as_ref());
        let speed_bps = speed
            .as_ref()
            .and_then(|s| s.bytes_per_second)
            .or_else(|| edge.and_then(|x| x.download_speed_bytes_per_sec));
        Self {
            id: br.id,
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
            download_speed_bytes_per_sec: speed_bps,
            speedtest_elapsed_ms: speed.as_ref().and_then(|s| s.elapsed_ms),
            speedtest_connect_ms: speed.as_ref().and_then(|s| s.connect_ms),
            speedtest_tls_handshake_ms: speed.as_ref().and_then(|s| s.tls_handshake_ms),
            speedtest_ttfb_ms: speed.as_ref().and_then(|s| s.ttfb_ms),
            speedtest_handshake: speed.as_ref().and_then(|s| s.handshake.clone()),
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
        let speed_detail = if self.download_speed_bytes_per_sec.is_some() {
            let mut parts = Vec::new();
            if let Some(elapsed) = self.speedtest_elapsed_ms {
                parts.push(format!("sp_elapsed={}ms", elapsed));
            }
            if let Some(c) = self.speedtest_connect_ms {
                parts.push(format!("sp_tcp={}ms", c));
            }
            if let Some(t) = self.speedtest_tls_handshake_ms {
                parts.push(format!("sp_tls={}ms", t));
            }
            if let Some(ttfb) = self.speedtest_ttfb_ms {
                parts.push(format!("sp_ttfb={}ms", ttfb));
            }
            if let Some(h) = self.speedtest_handshake.as_ref() {
                parts.push(format!("sp_hs={}", h));
            }
            if parts.is_empty() {
                String::new()
            } else {
                format!(" {}", parts.join(" "))
            }
        } else {
            String::new()
        };
        format!(
            "#{:<5} {} edge={} tls={} usable={} conf={}{}{}{}{}{}{}{}{}{}{}",
            self.id,
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
            speed_detail,
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

fn merge_config(cli: &Cli, detect: &DetectArgs) -> Result<ConfigFile> {
    let defaults = ConfigFile::default();
    let mut fig = Figment::from(Serialized::defaults(&defaults));
    if let Some(path) = cli.global.config.as_ref() {
        if !path.exists() {
            anyhow::bail!("config file not found: {}", path.display());
        }
        fig = fig.admerge(Toml::file(path));
    }
    fig = fig.admerge(Env::prefixed("CFRP_").split("_").filter(|k| {
        matches!(
            k.as_str(),
            "DOMAIN"
                | "INPUT"
                | "OUTPUT"
                | "FORMAT"
                | "CONCURRENCY"
                | "ADAPTIVE"
                | "A_MIN"
                | "A_MAX"
                | "A_INITIAL"
                | "A_WINDOW"
                | "PROGRESS"
                | "SPEEDTEST"
                | "SPEEDTEST_URL_PATH"
                | "SPEEDTEST_THREADS"
                | "SPEEDTEST_TIMEOUT_SECS"
                | "SPEEDTEST_CONCURRENCY"
                | "FAST"
                | "PROBE_TIMEOUT_SECS"
                | "GOVERNOR_REPORT"
                | "NO_GOVERNOR"
                | "TLS_SESSION_CACHE"
                | "SPEEDTEST_0RTT"
                | "SPEEDTEST_ONLY"
                | "BENCH"
                | "BENCH_QUICK"
                | "GRACE_SECONDS"
        )
    }));
    let cfg: ConfigFile = fig
        .extract()
        .context("merge env + config file into ConfigFile")?;

    let mut cli_targets: Vec<String> = detect.targets.clone();
    let mut merged = if cli.global.config.is_some() {
        let mut t = cfg.targets.clone();
        t.append(&mut cli_targets);
        ConfigFile { targets: t, ..cfg }
    } else {
        ConfigFile {
            targets: cli_targets,
            ..cfg
        }
    };

    if detect.domain.is_some() {
        merged.domain = detect.domain.clone();
    }
    if detect.input.is_some() {
        merged.input = detect.input.clone();
    }
    if detect.output.is_some() {
        merged.output = detect.output.clone();
    }
    if detect.format.is_some() {
        merged.format = detect.format;
    }

    merged.adaptive = merged.adaptive || detect.adaptive;
    merged.fast = merged.fast || detect.fast;
    merged.progress = merged.progress || detect.progress;
    merged.governor_report = merged.governor_report || detect.governor_report;
    merged.no_governor = merged.no_governor || detect.no_governor;
    merged.bench = merged.bench || detect.bench;
    merged.bench_quick = merged.bench_quick || detect.bench_quick;

    merged.speedtest = merged.speedtest || detect.speedtest;
    merged.speedtest_0rtt = merged.speedtest_0rtt || detect.enable_0rtt;

    merged.concurrency = detect.concurrency;
    merged.a_min = detect.a_min;
    merged.a_max = detect.a_max;
    merged.a_initial = detect.a_initial;
    merged.a_window = detect.a_window;
    merged.probe_timeout_secs = detect.probe_timeout_secs;
    merged.tls_session_cache = detect.tls_session_cache;
    merged.grace_seconds = cli.global.grace_seconds;

    let args: Vec<String> = std::env::args().collect();
    if args
        .iter()
        .any(|a| a == "--speedtest-threads" || a.starts_with("--speedtest-threads="))
    {
        merged.speedtest_threads = detect.speedtest_threads;
    }
    if args
        .iter()
        .any(|a| a == "--speedtest-timeout" || a.starts_with("--speedtest-timeout="))
    {
        merged.speedtest_timeout_secs = detect.speedtest_timeout_secs;
    }
    if args
        .iter()
        .any(|a| a == "--speedtest-concurrency" || a.starts_with("--speedtest-concurrency="))
    {
        merged.speedtest_concurrency = detect.speedtest_concurrency;
    }
    if args
        .iter()
        .any(|a| a == "--speedtest-url" || a.starts_with("--speedtest-url="))
    {
        merged.speedtest_url_path = detect.speedtest_url_path.clone();
    }

    Ok(merged)
}

fn merge_speedtest_config(cli: &Cli, st: &SpeedTestArgs) -> Result<ConfigFile> {
    let defaults = ConfigFile::default();
    let mut fig = Figment::from(Serialized::defaults(&defaults));
    if let Some(path) = cli.global.config.as_ref() {
        if !path.exists() {
            anyhow::bail!("config file not found: {}", path.display());
        }
        fig = fig.admerge(Toml::file(path));
    }
    fig = fig.admerge(Env::prefixed("CFRP_").split("_").filter(|k| {
        matches!(
            k.as_str(),
            "DOMAIN"
                | "INPUT"
                | "OUTPUT"
                | "FORMAT"
                | "PROGRESS"
                | "SPEEDTEST_URL_PATH"
                | "SPEEDTEST_THREADS"
                | "SPEEDTEST_TIMEOUT_SECS"
                | "SPEEDTEST_CONCURRENCY"
                | "TLS_SESSION_CACHE"
                | "SPEEDTEST_0RTT"
                | "GRACE_SECONDS"
        )
    }));
    let mut cfg: ConfigFile = fig
        .extract()
        .context("merge env + config file into speedtest ConfigFile")?;

    let mut cli_targets: Vec<String> = st.targets.clone();
    cfg = if cli.global.config.is_some() {
        let mut t = cfg.targets.clone();
        t.append(&mut cli_targets);
        ConfigFile { targets: t, ..cfg }
    } else {
        ConfigFile {
            targets: cli_targets,
            ..cfg
        }
    };

    if st.domain.is_some() {
        cfg.domain = st.domain.clone();
    }
    if st.input.is_some() {
        cfg.input = st.input.clone();
    }
    if st.output.is_some() {
        cfg.output = st.output.clone();
    }
    if st.format.is_some() {
        cfg.format = st.format;
    }
    cfg.progress = cfg.progress || st.progress;
    cfg.speedtest = true;
    cfg.speedtest_only = true;
    cfg.speedtest_0rtt = cfg.speedtest_0rtt || st.enable_0rtt;

    cfg.speedtest_threads = st.threads;
    cfg.speedtest_timeout_secs = st.timeout_secs;
    cfg.speedtest_concurrency = st.concurrency;
    cfg.tls_session_cache = st.tls_session_cache;
    cfg.grace_seconds = cli.global.grace_seconds;

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--url" || a.starts_with("--url=")) {
        cfg.speedtest_url_path = st.url_path.clone();
    }

    Ok(cfg)
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

fn build_masscan_scanner(engine: &ScanEngineArgs) -> MasscanScanner {
    let mut mcfg = MasscanConfig::new();
    mcfg.interface = engine.interface.clone();
    mcfg.rate = engine.rate;
    mcfg.masscan_binary_path = engine.masscan_binary.clone();
    mcfg.asn_cache_dir = engine.asn_cache_dir.clone();
    mcfg.iface_setting_file = engine.iface_setting_file.clone();
    MasscanScanner::new(mcfg)
}

fn merge_scan_config(
    cli: &Cli,
    detect: &ScanDetectArgs,
    st: Option<&ScanSpeedTestArgs>,
) -> Result<ConfigFile> {
    let defaults = ConfigFile::default();
    let mut fig = Figment::from(Serialized::defaults(&defaults));
    if let Some(path) = cli.global.config.as_ref() {
        if !path.exists() {
            anyhow::bail!("config file not found: {}", path.display());
        }
        fig = fig.admerge(Toml::file(path));
    }
    fig = fig.admerge(Env::prefixed("CFRP_").split("_").filter(|k| {
        matches!(
            k.as_str(),
            "DOMAIN"
                | "CONCURRENCY"
                | "ADAPTIVE"
                | "A_MIN"
                | "A_MAX"
                | "A_INITIAL"
                | "A_WINDOW"
                | "PROGRESS"
                | "SPEEDTEST"
                | "SPEEDTEST_URL_PATH"
                | "SPEEDTEST_THREADS"
                | "SPEEDTEST_TIMEOUT_SECS"
                | "SPEEDTEST_CONCURRENCY"
                | "PROBE_TIMEOUT_SECS"
                | "GOVERNOR_REPORT"
                | "NO_GOVERNOR"
                | "TLS_SESSION_CACHE"
                | "GRACE_SECONDS"
        )
    }));
    let mut cfg: ConfigFile = fig
        .extract()
        .context("merge env + config file into scan ConfigFile")?;

    if detect.domain.is_some() {
        cfg.domain = detect.domain.clone();
    }

    cfg.adaptive = cfg.adaptive || detect.adaptive;
    cfg.progress = cfg.progress || detect.progress;
    cfg.governor_report = cfg.governor_report || detect.governor_report;
    cfg.no_governor = cfg.no_governor || detect.no_governor;

    cfg.concurrency = detect.concurrency;
    cfg.a_min = detect.a_min;
    cfg.a_max = detect.a_max;
    cfg.a_initial = detect.a_initial;
    cfg.a_window = detect.a_window;
    cfg.probe_timeout_secs = detect.probe_timeout_secs;
    cfg.tls_session_cache = detect.tls_session_cache;
    cfg.grace_seconds = cli.global.grace_seconds;

    if let Some(st) = st {
        cfg.speedtest = cfg.speedtest || st.enabled;
        cfg.speedtest_threads = st.threads;
        cfg.speedtest_timeout_secs = st.timeout_secs;
        cfg.speedtest_concurrency = st.speedtest_concurrency;
        let args: Vec<String> = std::env::args().collect();
        if args
            .iter()
            .any(|a| a == "--speedtest-url" || a.starts_with("--speedtest-url="))
        {
            cfg.speedtest_url_path = st.url_path.clone();
        }
    }

    Ok(cfg)
}

fn build_pipeline_options(
    engine: &ScanEngineArgs,
    detect: &ScanDetectArgs,
    cfg_merged: &ConfigFile,
    force_speedtest: bool,
) -> PipelineOptions {
    PipelineOptions {
        domain: cfg_merged.domain.clone(),
        concurrency: if detect.concurrency != 10 {
            detect.concurrency
        } else {
            cfg_merged.concurrency.max(100)
        },
        speedtest: cfg_merged.speedtest || force_speedtest,
        speedtest_threads: cfg_merged.speedtest_threads,
        speedtest_url_path: cfg_merged.speedtest_url_path.clone(),
        speedtest_concurrency: cfg_merged.speedtest_concurrency,
        output_dir: engine.output_dir.clone(),
        adaptive_min: cfg_merged.a_min,
        adaptive_max: cfg_merged.a_max,
        probe_timeout_secs: cfg_merged.probe_timeout_secs,
        tls_session_cache: cfg_merged.tls_session_cache,
    }
}

async fn run_scan_command(cli: &Cli, cmd: ScanCmd) -> Result<()> {
    match cmd {
        ScanCmd::ClearCache { engine } => {
            let asn_dir = engine.asn_cache_dir.clone();
            let setting = engine.iface_setting_file.clone();
            cfrp_detector::clear_cache(&asn_dir, &setting)?;
            println!(
                "scan cache cleared: asn_dir={}, setting={}",
                asn_dir.display(),
                setting.display()
            );
            Ok(())
        }
        ScanCmd::Asn {
            asn,
            tls,
            port,
            speedtest,
            detect,
            engine,
        } => {
            let cfg_merged = merge_scan_config(cli, &detect, Some(&speedtest))?;
            let tls = tls.unwrap_or(true);
            let port_str = port;
            let scanner = build_masscan_scanner(&engine);
            scanner.check_masscan_available()?;
            let pipeline = MasscanPipeline::new(build_pipeline_options(
                &engine,
                &detect,
                &cfg_merged,
                speedtest.enabled,
            ));
            let started = std::time::Instant::now();
            let out = pipeline
                .run_single_asn(&scanner, asn, &port_str, tls)
                .await?;
            println!(
                "scan asn AS{} done: open={} edges={} masscan_sec={} detect_sec={} output={} total_sec={}",
                asn,
                out.open_ports_count,
                out.cloudflare_edges_count,
                out.masscan_duration_secs,
                out.detection_duration_secs,
                out.output_path.display(),
                started.elapsed().as_secs()
            );
            Ok(())
        }
        ScanCmd::Asns {
            filename,
            speedtest,
            detect,
            engine,
        } => {
            let cfg_merged = merge_scan_config(cli, &detect, Some(&speedtest))?;
            let tasks_raw = MasscanScanner::read_asn_task_file(&filename)?;
            if tasks_raw.is_empty() {
                anyhow::bail!("no ASN tasks found in {}", filename.display());
            }
            let tasks: Vec<PipelineAsnTask> =
                tasks_raw.into_iter().map(PipelineAsnTask::from).collect();
            let scanner = build_masscan_scanner(&engine);
            scanner.check_masscan_available()?;
            let pipeline = MasscanPipeline::new(build_pipeline_options(
                &engine,
                &detect,
                &cfg_merged,
                speedtest.enabled,
            ));
            let started = std::time::Instant::now();
            let result = pipeline.run_batch_asn(&scanner, tasks).await?;
            for o in &result.outputs {
                println!(
                    "scan asns {}: open={} edges={} masscan_sec={} detect_sec={} output={}",
                    o.label,
                    o.open_ports_count,
                    o.cloudflare_edges_count,
                    o.masscan_duration_secs,
                    o.detection_duration_secs,
                    o.output_path.display()
                );
            }
            println!(
                "scan asns finished {} tasks in {}s",
                result.outputs.len(),
                started.elapsed().as_secs()
            );
            Ok(())
        }
        ScanCmd::Ip {
            ip,
            tls,
            port,
            speedtest,
            detect,
            engine,
        } => {
            let cfg_merged = merge_scan_config(cli, &detect, Some(&speedtest))?;
            let tls = tls.unwrap_or(true);
            let port_str = port;
            let scanner = build_masscan_scanner(&engine);
            scanner.check_masscan_available()?;
            let pipeline = MasscanPipeline::new(build_pipeline_options(
                &engine,
                &detect,
                &cfg_merged,
                speedtest.enabled,
            ));
            let started = std::time::Instant::now();
            let out = pipeline.run_single_ip(&scanner, ip, &port_str, tls).await?;
            println!(
                "scan ip {} done: open={} edges={} masscan_sec={} detect_sec={} output={} total_sec={}",
                ip,
                out.open_ports_count,
                out.cloudflare_edges_count,
                out.masscan_duration_secs,
                out.detection_duration_secs,
                out.output_path.display(),
                started.elapsed().as_secs()
            );
            Ok(())
        }
        ScanCmd::Ips {
            filename,
            tls,
            port,
            speedtest,
            detect,
            engine,
        } => {
            let cfg_merged = merge_scan_config(cli, &detect, Some(&speedtest))?;
            let ips = MasscanScanner::read_ip_list_file(&filename)?;
            if ips.is_empty() {
                anyhow::bail!("no IPs found in {}", filename.display());
            }
            let tls = tls.unwrap_or(true);
            let port_str = port;
            let scanner = build_masscan_scanner(&engine);
            scanner.check_masscan_available()?;
            let pipeline = MasscanPipeline::new(build_pipeline_options(
                &engine,
                &detect,
                &cfg_merged,
                speedtest.enabled,
            ));
            let started = std::time::Instant::now();
            let out = pipeline
                .run_batch_ip(&scanner, &ips, &port_str, tls)
                .await?;
            println!(
                "scan ips {} done: open={} edges={} masscan_sec={} detect_sec={} output={} total_sec={}",
                filename.display(),
                out.open_ports_count,
                out.cloudflare_edges_count,
                out.masscan_duration_secs,
                out.detection_duration_secs,
                out.output_path.display(),
                started.elapsed().as_secs()
            );
            Ok(())
        }
    }
}

async fn run_detect_command(cli: &Cli, detect: DetectArgs) -> Result<()> {
    let cfg_merged = merge_config(cli, &detect)?;

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
        if std::env::args().count() == 1 {
            Cli::command().print_help()?;
            std::process::exit(0);
        }
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
        let speed_export = if cfg_merged.speedtest {
            let (cancel, _) = build_signals_token(cfg_merged.grace_seconds);
            let connect_timeout = DetectorConfig::default().probe.connect_timeout;
            let mut tls_hints = std::collections::HashMap::new();
            tls_hints.insert(
                t.to_string(),
                br.result
                    .as_ref()
                    .map(|r| r.is_tls)
                    .unwrap_or(cfrp_detector::guess_tls_by_port(t.port)),
            );
            let mut map = run_speedtests(
                vec![t.clone()],
                &tls_hints,
                &cfg_merged,
                connect_timeout,
                None,
                cancel,
            )
            .await?;
            map.remove(&t.to_string())
        } else {
            None
        };
        let records = vec![ExportRecord::build(&br, speed_export)];
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

    let speed_results: std::collections::HashMap<String, SpeedExport> = if cfg_merged.speedtest {
        let (st_cancel, _) = build_signals_token(cfg_merged.grace_seconds);
        let mut tls_hints = std::collections::HashMap::new();
        let mut speed_targets = Vec::new();
        for br in &results {
            let Some(r) = br.result.as_ref() else {
                continue;
            };
            if !r.is_cloudflare_edge {
                continue;
            }
            tls_hints.insert(br.target.to_string(), r.is_tls);
            speed_targets.push(br.target.clone());
        }
        if !speed_targets.is_empty() {
            let pb_st = if cfg_merged.progress {
                let bar = ProgressBar::new(speed_targets.len() as u64);
                bar.set_style(
                        ProgressStyle::with_template(
                            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.magenta/purple}] {pos}/{len} ({eta}) [speedtest]",
                        )
                        .expect("progress template must be valid indicatif syntax")
                        .progress_chars("=>-"),
                    );
                Some(bar)
            } else {
                None
            };
            run_speedtests(
                speed_targets,
                &tls_hints,
                &cfg_merged,
                connect_timeout,
                pb_st.clone(),
                st_cancel,
            )
            .await?
        } else {
            std::collections::HashMap::new()
        }
    } else {
        std::collections::HashMap::new()
    };

    let mut records: Vec<ExportRecord> = Vec::with_capacity(results.len());
    for br in &results {
        let speed_export = speed_results.get(&br.target.to_string()).cloned();
        records.push(ExportRecord::build(br, speed_export));
    }

    emit_records(&cfg_merged, &records)
}

async fn run_speedtest_command(cli: &Cli, st: SpeedTestArgs) -> Result<()> {
    let cfg_merged = merge_speedtest_config(cli, &st)?;

    let targets = collect_targets_from_merged(&cfg_merged)?;
    if targets.is_empty() {
        anyhow::bail!(
            "no targets supplied; pass positional TARGET, CFRP_TARGETS env, or use -i FILE"
        );
    }

    let (cancel, signal_watch) = build_signals_token(cfg_merged.grace_seconds);
    let signal_handle = tokio::spawn(signal_watch);

    let pb: Option<ProgressBar> = if cfg_merged.progress {
        let bar = ProgressBar::new(targets.len() as u64);
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

    let connect_timeout = DetectorConfig::default().probe.connect_timeout;
    let empty_tls_hints = std::collections::HashMap::new();
    let speed_results = run_speedtests(
        targets.clone(),
        &empty_tls_hints,
        &cfg_merged,
        connect_timeout,
        pb.clone(),
        cancel.clone(),
    )
    .await?;
    signal_handle.abort();

    if let Some(pb) = pb.as_ref() {
        if cancel.is_cancelled() {
            pb.finish_with_message("cancelled");
        }
    }

    let mut records: Vec<ExportRecord> = Vec::with_capacity(targets.len());
    for (id, t) in targets.iter().enumerate() {
        let key = t.to_string();
        let speed_export = speed_results.get(&key).cloned();
        let is_tls_hint = speed_export.is_some() || cfrp_detector::guess_tls_by_port(t.port);
        let br = cfrp_detector::BatchResult {
            id,
            target: t.clone(),
            result: Some(cfrp_detector::DetectionResult {
                is_cloudflare_edge: false,
                is_tls: is_tls_hint,
                is_usable: speed_export.is_some(),
                http_status_code: None,
                edge_info: None,
                confidence: cfrp_detector::Confidence::None,
                confidence_reason: String::from("speedtest command: edge detection skipped"),
                reasons: if speed_export.is_some() {
                    vec![String::from("speedtest succeeded")]
                } else {
                    vec![String::from("speedtest command: edge detection skipped")]
                },
            }),
            error: if speed_export.is_none() {
                Some(String::from("speedtest failed or cancelled"))
            } else {
                None
            },
        };
        records.push(ExportRecord::build(&br, speed_export));
    }
    emit_records(&cfg_merged, &records)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .compact()
        .init();
    let cli = Cli::parse();
    match &cli.command {
        Command::Detect(detect) => run_detect_command(&cli, detect.clone()).await,
        Command::SpeedTest(st) => run_speedtest_command(&cli, st.clone()).await,
        Command::Scan(scan) => run_scan_command(&cli, scan.clone()).await,
    }
}

fn collect_targets_from_merged(cfg: &ConfigFile) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let default_port = 443;
    for raw in &cfg.targets {
        if let Some(t) = parse_target(raw, default_port)? {
            targets.push(t);
        }
    }
    if let Ok(env_val) = std::env::var("CFRP_TARGETS") {
        for part in env_val.split(|c: char| c == ',' || c.is_whitespace()) {
            let s = part.trim();
            if s.is_empty() {
                continue;
            }
            if let Some(t) = parse_target(s, default_port)? {
                targets.push(t);
            }
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

fn build_speedtest_config(
    cfg_merged: &ConfigFile,
    connect_timeout: Duration,
) -> Result<(
    SpeedTestConfig,
    Arc<cfrp_detector::PinnedConnector>,
    String,
    String,
)> {
    let speed_cfg = SpeedTestConfig {
        timeout: Duration::from_secs(cfg_merged.speedtest_timeout_secs),
        threads_per_target: cfg_merged.speedtest_threads.max(1),
        concurrency: cfg_merged.speedtest_concurrency.max(1),
    };
    let domain = cfg_merged
        .domain
        .clone()
        .unwrap_or_else(|| "www.cloudflare.com".to_string());
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
    Ok((
        speed_cfg,
        conn,
        domain,
        cfg_merged.speedtest_url_path.clone(),
    ))
}

async fn run_speedtests(
    targets: Vec<Target>,
    tls_hints: &std::collections::HashMap<String, bool>,
    cfg_merged: &ConfigFile,
    connect_timeout: Duration,
    pb: Option<ProgressBar>,
    cancel: CancellationToken,
) -> Result<std::collections::HashMap<String, SpeedExport>> {
    if targets.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    if let Some(bar) = pb.as_ref() {
        bar.reset();
        bar.set_length(targets.len() as u64);
        bar.set_message("speedtest");
    }
    let (speed_cfg, conn, sni, path) = build_speedtest_config(cfg_merged, connect_timeout)?;
    let enable_0rtt = cfg_merged.speedtest_0rtt;
    let session_cache_len_for_report = conn.tls_session_cache_len();
    use futures::{StreamExt, stream};
    let stream = stream::iter(targets.into_iter())
        .map(|target| {
            let cfg_inner = speed_cfg.clone();
            let pb_opt = pb.clone();
            let conn_c = conn.clone();
            let sni_c = sni.clone();
            let path_c = path.clone();
            let sc = cancel.clone();
            let use_tls = tls_hints
                .get(&target.to_string())
                .copied()
                .unwrap_or_else(|| cfrp_detector::guess_tls_by_port(target.port));
            async move {
                if sc.is_cancelled() {
                    return None;
                }
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
                res.map(|r| (target, SpeedExport::from(&r)))
            }
        })
        .buffer_unordered(speed_cfg.concurrency.max(1));
    let outcomes: Vec<_> = stream.collect().await;
    let total_targets = outcomes.len();
    let mut map = std::collections::HashMap::new();
    for (t, se) in outcomes.into_iter().flatten() {
        map.insert(t.to_string(), se);
    }
    if let Some(bar) = pb.as_ref() {
        bar.finish_with_message("speedtest done");
    }
    if cfg_merged.governor_report {
        eprintln!(
            "[speedtest] session_cache_len={} 0rtt_enabled={} targets_tested={}",
            session_cache_len_for_report, enable_0rtt, total_targets
        );
    }
    Ok(map)
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
    id: usize,
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
    speedtest_elapsed_ms: Option<u128>,
    speedtest_connect_ms: Option<u128>,
    speedtest_tls_handshake_ms: Option<u128>,
    speedtest_ttfb_ms: Option<u128>,
    speedtest_handshake: &'a str,
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
            id: r.id,
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
            speedtest_elapsed_ms: r.speedtest_elapsed_ms,
            speedtest_connect_ms: r.speedtest_connect_ms,
            speedtest_tls_handshake_ms: r.speedtest_tls_handshake_ms,
            speedtest_ttfb_ms: r.speedtest_ttfb_ms,
            speedtest_handshake: r.speedtest_handshake.as_deref().unwrap_or(""),
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
    use std::net::Ipv4Addr;

    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_parser_has_scan_and_detect() {
        let cmd = Cli::command();
        let help_text = {
            let mut buf = Vec::new();
            cmd.clone().write_help(&mut buf).unwrap();
            String::from_utf8(buf).unwrap()
        };
        assert!(
            help_text.contains("detect"),
            "help should mention detect subcommand"
        );
        assert!(
            help_text.contains("scan"),
            "help should mention scan subcommand"
        );
    }

    #[test]
    fn scan_clear_cache_with_engine_args() {
        let args = &[
            "cfrp-detector",
            "scan",
            "clear-cache",
            "--asn-cache-dir",
            "/tmp/asn",
            "--iface-setting-file",
            "/tmp/if.txt",
        ];
        let cli = Cli::try_parse_from(args).expect("parse scan clear-cache");
        match cli.command {
            Command::Scan(ScanCmd::ClearCache { engine }) => {
                assert_eq!(engine.asn_cache_dir, PathBuf::from("/tmp/asn"));
                assert_eq!(engine.iface_setting_file, PathBuf::from("/tmp/if.txt"));
            }
            other => unreachable!("expected Scan ClearCache, got {other:?}"),
        }
    }

    #[test]
    fn scan_asn_with_defaults() {
        let args = &["cfrp-detector", "scan", "asn", "45102"];
        let cli = Cli::try_parse_from(args).expect("parse scan asn defaults");
        match cli.command {
            Command::Scan(ScanCmd::Asn {
                asn,
                tls,
                port,
                speedtest,
                engine,
                ..
            }) => {
                assert_eq!(asn, 45102);
                assert!(tls.is_none());
                assert_eq!(port, "443");
                assert!(!speedtest.enabled);
                assert_eq!(engine.rate, 10000);
            }
            other => unreachable!("expected Scan Asn, got {other:?}"),
        }
    }

    #[test]
    fn scan_asn_explicit_options() {
        let args = &[
            "cfrp-detector",
            "scan",
            "asn",
            "132203",
            "--tls",
            "true",
            "--port",
            "443,8443",
            "-s",
            "--rate",
            "50000",
            "--concurrency",
            "300",
            "--domain",
            "example.com",
        ];
        let cli = Cli::try_parse_from(args).expect("parse scan asn explicit");
        match cli.command {
            Command::Scan(ScanCmd::Asn {
                asn,
                tls,
                port,
                speedtest,
                detect,
                engine,
            }) => {
                assert_eq!(asn, 132203);
                assert_eq!(tls, Some(true));
                assert_eq!(port, "443,8443");
                assert!(speedtest.enabled);
                assert_eq!(engine.rate, 50000);
                assert_eq!(detect.concurrency, 300);
                assert_eq!(detect.domain.as_deref(), Some("example.com"));
            }
            other => unreachable!("expected Scan Asn, got {other:?}"),
        }
    }

    #[test]
    fn scan_asns_custom_file() {
        let args = &["cfrp-detector", "scan", "asns", "-f", "custom_asn.txt"];
        let cli = Cli::try_parse_from(args).expect("parse scan asns custom");
        match cli.command {
            Command::Scan(ScanCmd::Asns { filename, .. }) => {
                assert_eq!(filename, PathBuf::from("custom_asn.txt"));
            }
            other => unreachable!("expected Scan Asns, got {other:?}"),
        }
    }

    #[test]
    fn scan_asns_default_file() {
        let args = &["cfrp-detector", "scan", "asns"];
        let cli = Cli::try_parse_from(args).expect("parse scan asns default");
        match cli.command {
            Command::Scan(ScanCmd::Asns { filename, .. }) => {
                assert_eq!(filename, PathBuf::from("as.txt"));
            }
            other => unreachable!("expected Scan Asns, got {other:?}"),
        }
    }

    #[test]
    fn scan_ip_defaults() {
        let args = &["cfrp-detector", "scan", "ip", "127.0.0.1"];
        let cli = Cli::try_parse_from(args).expect("parse scan ip default");
        match cli.command {
            Command::Scan(ScanCmd::Ip { ip, tls, port, .. }) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                assert!(tls.is_none());
                assert_eq!(port, "1-65535");
            }
            other => unreachable!("expected Scan Ip, got {other:?}"),
        }
    }

    #[test]
    fn scan_ip_explicit_options() {
        let args = &[
            "cfrp-detector",
            "scan",
            "ip",
            "10.0.0.1",
            "--tls",
            "false",
            "--port",
            "80,8080",
            "-s",
            "--interface",
            "eth1",
        ];
        let cli = Cli::try_parse_from(args).expect("parse scan ip explicit");
        match cli.command {
            Command::Scan(ScanCmd::Ip {
                ip,
                tls,
                port,
                speedtest,
                engine,
                ..
            }) => {
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
                assert_eq!(tls, Some(false));
                assert_eq!(port, "80,8080");
                assert!(speedtest.enabled);
                assert_eq!(engine.interface.as_deref(), Some("eth1"));
            }
            other => unreachable!("expected Scan Ip, got {other:?}"),
        }
    }

    #[test]
    fn scan_ips_custom_file() {
        let args = &[
            "cfrp-detector",
            "scan",
            "ips",
            "-f",
            "my_ips.txt",
            "--tls",
            "true",
            "--port",
            "443",
            "-s",
            "--output-dir",
            "/tmp/out",
            "--masscan-bin",
            "/usr/local/bin/masscan",
        ];
        let cli = Cli::try_parse_from(args).expect("parse scan ips");
        match cli.command {
            Command::Scan(ScanCmd::Ips {
                filename,
                tls,
                port,
                speedtest,
                engine,
                ..
            }) => {
                assert_eq!(filename, PathBuf::from("my_ips.txt"));
                assert_eq!(tls, Some(true));
                assert_eq!(port, "443");
                assert!(speedtest.enabled);
                assert_eq!(engine.output_dir, PathBuf::from("/tmp/out"));
                assert_eq!(
                    engine.masscan_binary.as_deref(),
                    Some(PathBuf::from("/usr/local/bin/masscan").as_path())
                );
            }
            other => unreachable!("expected Scan Ips, got {other:?}"),
        }
    }

    #[test]
    fn scan_ips_default_file() {
        let args = &["cfrp-detector", "scan", "ips"];
        let cli = Cli::try_parse_from(args).expect("parse scan ips default");
        match cli.command {
            Command::Scan(ScanCmd::Ips {
                filename,
                tls,
                port,
                ..
            }) => {
                assert_eq!(filename, PathBuf::from("ips.txt"));
                assert!(tls.is_none());
                assert_eq!(port, "1-65535");
            }
            other => unreachable!("expected Scan Ips, got {other:?}"),
        }
    }

    #[test]
    fn build_masscan_scanner_from_engine_args() {
        let args = &[
            "cfrp-detector",
            "scan",
            "asn",
            "45102",
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
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let engine = match cli.command {
            Command::Scan(ScanCmd::Asn { engine, .. }) => engine,
            _ => unreachable!(),
        };
        let scanner = build_masscan_scanner(&engine);
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
    fn build_pipeline_options_using_new_args() {
        let args = [
            "cfrp-detector",
            "scan",
            "asn",
            "45102",
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
        ];
        let cli = Cli::try_parse_from(&args).unwrap();
        let (detect, engine) = match &cli.command {
            Command::Scan(ScanCmd::Asn { detect, engine, .. }) => (detect.clone(), engine.clone()),
            _ => unreachable!(),
        };
        let cfg = merge_scan_config(&cli, &detect, None).unwrap();
        let opts = build_pipeline_options(&engine, &detect, &cfg, false);
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
    fn detect_help_no_panic() {
        let args = &["cfrp-detector", "detect", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn scan_help_no_panic() {
        let args = &["cfrp-detector", "scan", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn scan_asn_help_no_panic() {
        let args = &["cfrp-detector", "scan", "asn", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn scan_asns_help_no_panic() {
        let args = &["cfrp-detector", "scan", "asns", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn scan_ip_help_no_panic() {
        let args = &["cfrp-detector", "scan", "ip", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn scan_ips_help_no_panic() {
        let args = &["cfrp-detector", "scan", "ips", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn scan_clear_cache_help_no_panic() {
        let args = &["cfrp-detector", "scan", "clear-cache", "--help"];
        let res = Cli::try_parse_from(args);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn scan_asn_parses_correctly() {
        let args = &["cfrp-detector", "scan", "asn", "13335"];
        let cli = Cli::try_parse_from(args).expect("parse scan asn");
        match cli.command {
            Command::Scan(ScanCmd::Asn { asn, .. }) => assert_eq!(asn, 13335),
            other => unreachable!("expected Scan Asn, got {other:?}"),
        }
    }

    #[test]
    fn detect_subcommand_with_targets() {
        let args = &[
            "cfrp-detector",
            "detect",
            "-s",
            "1.1.1.1:443",
            "1.0.0.1:8443",
        ];
        let cli = Cli::try_parse_from(args).expect("parse detect with targets");
        match cli.command {
            Command::Detect(d) => {
                assert!(d.speedtest);
                assert_eq!(d.targets.len(), 2);
            }
            other => unreachable!("expected Detect, got {other:?}"),
        }
    }
}
