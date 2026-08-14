use anyhow::{Context, Result};
use cfrp_detector::{
    AdaptiveConfig, BatchProgress, BatchTarget, Confidence, Detector,
    DetectorConfig, SpeedTestConfig, SpeedTester, Target,
};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

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

#[derive(Debug, Parser)]
#[command(
    name = "cfrp-detector",
    version,
    about = "Cloudflare edge detector and network quality probe (Go-compatible CLI)"
)]
struct Cli {
    #[arg(short, long, help = "Hostname / SNI used for probing (e.g. example.com)")]
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
        help = "Initial worker concurrency (for adaptive, this is ignored in favour of --a-initial)"
    )]
    concurrency: usize,

    #[arg(short = 'a', long = "adaptive", help = "Enable adaptive concurrency governor")]
    adaptive: bool,

    #[arg(long = "a-min", default_value_t = 1, help = "Adaptive: minimum concurrency")]
    a_min: usize,

    #[arg(long = "a-max", default_value_t = 128, help = "Adaptive: maximum concurrency")]
    a_max: usize,

    #[arg(long = "a-initial", default_value_t = 16, help = "Adaptive: starting concurrency")]
    a_initial: usize,

    #[arg(long = "a-window", default_value_t = 10, help = "Adaptive: sliding window of recent probes")]
    a_window: usize,

    #[arg(short = 'p', long = "progress", help = "Show an interactive progress bar on stderr")]
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

    #[arg(value_name = "TARGET", help = "Targets in form ip[:port] or [ipv6]:port")]
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
            download_speed_bytes_per_sec: speed_bps.or_else(|| edge.and_then(|x| x.download_speed_bytes_per_sec)),
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_writer(std::io::stderr)
        .compact()
        .init();
    let cli = Cli::parse();
    let targets = collect_targets(&cli)?;
    if targets.is_empty() {
        anyhow::bail!("no targets supplied; pass positional TARGET or use -i FILE");
    }

    if cli.fast {
        if targets.len() != 1 {
            anyhow::bail!("--fast mode requires exactly one target (got {})", targets.len());
        }
        let t = &targets[0];
        let result = Detector::detect_oneshot(t, cli.domain.as_deref())
            .await
            .context("one-shot detection failed")?;
        let br = cfrp_detector::BatchResult {
            target: t.clone(),
            result: Some(result),
            error: None,
        };
        let records = vec![ExportRecord::build(&br, None)];
        return emit_records(&cli, &records);
    }

    let mut cfg = DetectorConfig::default();
    cfg.probe.request_timeout = Duration::from_secs(cli.probe_timeout_secs);
    let connect_timeout = cfg.probe.connect_timeout;
    let detector = Detector::new(cfg).await.context("initialize detector")?;

    let batch: Vec<BatchTarget> = targets
        .iter()
        .cloned()
        .map(|target| BatchTarget { target })
        .collect();

    let pb: Option<ProgressBar> = if cli.progress {
        let bar = ProgressBar::new(batch.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) c={msg}",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        Some(bar)
    } else {
        None
    };

    let adaptive_cfg = AdaptiveConfig {
        enabled: cli.adaptive,
        initial: cli.a_initial,
        min: cli.a_min,
        max: cli.a_max,
        window: cli.a_window,
    };

    let results = if let Some(bar) = pb.as_ref() {
        let bar_c = bar.clone();
        detector
            .detect_batch_with_progress(
                &batch,
                cli.domain.as_deref(),
                cli.concurrency,
                adaptive_cfg,
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
            .detect_batch_with_progress(
                &batch,
                cli.domain.as_deref(),
                cli.concurrency,
                adaptive_cfg,
                |_| {},
            )
            .await
    };

    let speed_bps_per_target: std::collections::HashMap<String, u64> = if cli.speedtest {
        if let Some(bar) = pb.as_ref() {
            bar.reset();
            bar.set_length(results.len() as u64);
            bar.set_message("speedtest");
        }
        let speed_cfg = SpeedTestConfig {
            timeout: Duration::from_secs(cli.speedtest_timeout_secs),
            threads_per_target: cli.speedtest_threads.max(1),
            concurrency: cli.speedtest_concurrency.max(1),
        };
        let domain = cli
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
        let stream = stream::iter(speed_targets.into_iter().enumerate())
            .map(|(i, target)| {
                let url = format!(
                    "https://{}:{}{}",
                    host_owned, target.port, cli.speedtest_url_path
                );
                let addr = std::net::SocketAddr::new(target.ip, target.port);
                let cfg_inner = speed_cfg.clone();
                let pb_opt = pb.clone();
                let host_for_resolve = host_owned.clone();
                async move {
                    let resolved_client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .connect_timeout(connect_timeout)
                        .timeout(cfg_inner.timeout)
                        .redirect(reqwest::redirect::Policy::none())
                        .resolve(&host_for_resolve, addr)
                        .build()
                        .ok()?;
                    let tester = SpeedTester::new(resolved_client);
                    let res = tester.test(&target, &url, &cfg_inner).await.ok();
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
        for (t, bps) in outcomes.into_iter().flatten() {
            map.insert(t.to_string(), bps);
        }
        if let Some(bar) = pb.as_ref() {
            bar.finish_with_message("speedtest done");
        }
        map
    } else {
        std::collections::HashMap::new()
    };

    let mut records: Vec<ExportRecord> = Vec::with_capacity(results.len());
    for br in &results {
        let bps = speed_bps_per_target.get(&br.target.to_string()).copied();
        records.push(ExportRecord::build(br, bps));
    }

    emit_records(&cli, &records)
}

fn infer_format(cli: &Cli) -> OutputFormat {
    if let Some(f) = cli.format {
        return f;
    }
    if let Some(p) = cli.output.as_ref() {
        if let Some(ext) = p.extension().and_then(|x| x.to_str()) {
            match ext.to_ascii_lowercase().as_str() {
                "txt" | "text" => return OutputFormat::Txt,
                "csv" => return OutputFormat::Csv,
                _ => {}
            }
        }
    }
    OutputFormat::Json
}

fn emit_records(cli: &Cli, records: &[ExportRecord]) -> Result<()> {
    let fmt = infer_format(cli);
    let mut sink: Box<dyn Write> = if let Some(path) = cli.output.as_ref() {
        Box::new(fs::File::create(path).with_context(|| format!("open output file {}", path.display()))?)
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

fn collect_targets(cli: &Cli) -> Result<Vec<Target>> {
    let mut out = Vec::new();
    for raw in &cli.targets {
        if let Some(t) = parse_target(raw, 443)? {
            out.push(t);
        }
    }
    if let Some(path) = &cli.input {
        let data = fs::read_to_string(path).with_context(|| format!("read input file {}", path.display()))?;
        if path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("json"))
        {
            if let Ok(items) = serde_json::from_str::<Vec<InputTarget>>(&data) {
                for x in items {
                    out.push(Target::new(IpAddr::from_str(&x.ip)?, x.port));
                }
            } else if let Ok(items) = serde_json::from_str::<Vec<String>>(&data) {
                for x in items {
                    if let Some(t) = parse_target(&x, 443)? {
                        out.push(t);
                    }
                }
            } else {
                anyhow::bail!("invalid JSON input format in {}", path.display());
            }
        } else if path
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
                let ip = IpAddr::from_str(&r.ip).with_context(|| format!("csv row {} invalid ip", i))?;
                let port = r.port.unwrap_or(443);
                out.push(Target::new(ip, port));
            }
        } else {
            for line in data.lines() {
                let s = line.split('#').next().unwrap_or(line).trim();
                if let Some(t) = parse_target(s, 443)? {
                    out.push(t);
                }
            }
        }
    }
    Ok(out)
}

#[derive(Debug, Deserialize)]
struct CsvInputRow {
    ip: String,
    port: Option<u16>,
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