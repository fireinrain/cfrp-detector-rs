use anyhow::{Context, Result};
use cfrp_detector::{BatchTarget, Detector, DetectorConfig, Target};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{fs, net::IpAddr, path::PathBuf, str::FromStr};

#[derive(Debug, Parser)]
#[command(
    name = "cfrp-detector",
    version,
    about = "Cloudflare edge detector and network quality probe"
)]
struct Cli {
    #[arg(short, long)]
    domain: Option<String>,
    #[arg(short = 'i', long)]
    input: Option<PathBuf>,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(short = 'c', long, default_value_t = 10)]
    concurrency: usize,
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InputTarget {
    ip: String,
    port: u16,
}

#[derive(Debug, Clone, Serialize)]
struct ExportRecord {
    ip: String,
    port: u16,
    is_cloudflare_edge: bool,
    is_tls: bool,
    is_usable: bool,
    status_code: Option<u16>,
    colo: Option<String>,
    country: Option<String>,
    city: Option<String>,
    latency_ms: Option<u128>,
    confidence: String,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();
    let cli = Cli::parse();
    let targets = collect_targets(&cli)?;
    if targets.is_empty() {
        anyhow::bail!("no targets supplied");
    }
    let detector = Detector::new(DetectorConfig::default())
        .await
        .context("initialize detector")?;
    let batch: Vec<BatchTarget> = targets
        .iter()
        .cloned()
        .map(|target| BatchTarget { target })
        .collect();
    let results = detector
        .detect_batch(&batch, cli.domain.as_deref(), cli.concurrency)
        .await;
    let records: Vec<_> = results
        .iter()
        .map(|r| ExportRecord {
            ip: r.target.ip.to_string(),
            port: r.target.port,
            is_cloudflare_edge: r
                .result
                .as_ref()
                .map(|x| x.is_cloudflare_edge)
                .unwrap_or(false),
            is_tls: r.result.as_ref().map(|x| x.is_tls).unwrap_or(false),
            is_usable: r.result.as_ref().map(|x| x.is_usable).unwrap_or(false),
            status_code: r.result.as_ref().and_then(|x| x.http_status_code),
            colo: r
                .result
                .as_ref()
                .and_then(|x| x.edge_info.as_ref())
                .and_then(|x| x.colo_code.clone()),
            country: r
                .result
                .as_ref()
                .and_then(|x| x.edge_info.as_ref())
                .and_then(|x| x.country.clone()),
            city: r
                .result
                .as_ref()
                .and_then(|x| x.edge_info.as_ref())
                .and_then(|x| x.city.clone()),
            latency_ms: r
                .result
                .as_ref()
                .and_then(|x| x.edge_info.as_ref())
                .and_then(|x| x.latency.map(|d| d.as_millis())),
            confidence: r
                .result
                .as_ref()
                .map(|x| format!("{:?}", x.confidence))
                .unwrap_or_else(|| "None".into()),
            error: r.error.clone(),
        })
        .collect();
    if let Some(path) = cli.output {
        fs::write(path, serde_json::to_vec_pretty(&records)?)?;
    } else {
        println!("{}", serde_json::to_string_pretty(&records)?);
    }
    Ok(())
}

fn collect_targets(cli: &Cli) -> Result<Vec<Target>> {
    let mut out = Vec::new();
    for raw in &cli.targets {
        if let Some(t) = parse_target(raw, 443)? {
            out.push(t);
        }
    }
    if let Some(path) = &cli.input {
        let data = fs::read_to_string(path)?;
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
                anyhow::bail!("invalid JSON input format");
            }
        } else {
            for line in data.lines() {
                if let Some(t) = parse_target(line, 443)? {
                    out.push(t);
                }
            }
        }
    }
    Ok(out)
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