use crate::{
    BatchResult, BatchTarget, Detector, DetectorConfig, OpenPort, SpeedTestConfig, SpeedTester,
    Target,
};
use crate::{PinnedClientConfig, Result};
use csv::Writer as CsvWriter;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipelineOptions {
    pub domain: Option<String>,
    pub concurrency: usize,
    pub speedtest: bool,
    pub speedtest_threads: usize,
    pub speedtest_url_path: String,
    pub speedtest_concurrency: usize,
    pub output_dir: PathBuf,
    pub adaptive_min: usize,
    pub adaptive_max: usize,
    pub probe_timeout_secs: u64,
    pub tls_session_cache: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineAsnTask {
    pub asn: u32,
    pub ports: String,
    pub tls: bool,
}

impl From<crate::AsnTask> for PipelineAsnTask {
    fn from(t: crate::AsnTask) -> Self {
        Self {
            asn: t.asn,
            ports: t.ports,
            tls: t.tls,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineOutput {
    pub label: String,
    pub tls_flag: bool,
    pub ports: String,
    pub output_path: PathBuf,
    pub masscan_duration_secs: u64,
    pub detection_duration_secs: u64,
    pub open_ports_count: usize,
    pub detection_results_count: usize,
    pub cloudflare_edges_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    pub outputs: Vec<PipelineOutput>,
    pub total_duration_secs: u64,
}

pub struct MasscanPipeline {
    pub opts: PipelineOptions,
}

impl MasscanPipeline {
    pub fn new(opts: PipelineOptions) -> Self {
        Self { opts }
    }

    pub fn build_output_filename(label: &str, tls: bool, ports: &str) -> String {
        let tls_str = if tls { "true" } else { "false" };
        let safe_ports = ports
            .replace('-', "to")
            .replace(',', "-")
            .replace('/', "to");
        format!("{}-{}-{}.csv", label, tls_str, safe_ports)
    }

    fn open_ports_to_targets(open_ports: &[OpenPort], tls_hint: bool) -> Vec<Target> {
        open_ports
            .iter()
            .map(|op| {
                let port = if op.port == 0 {
                    if tls_hint { 443 } else { 80 }
                } else {
                    op.port
                };
                Target::new(op.ip, port)
            })
            .collect()
    }

    async fn run_detection(&self, targets: &[Target], _tls_hint: bool) -> Result<Vec<BatchResult>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }
        let max_conc = self.opts.concurrency.max(1);
        let mut dcfg = DetectorConfig::default();
        dcfg.probe.request_timeout = Duration::from_secs(self.opts.probe_timeout_secs);
        dcfg.probe.tls_session_cache_size = self.opts.tls_session_cache;
        dcfg.max_concurrency = max_conc.max(dcfg.max_concurrency);
        dcfg.governor.fd_safety_headroom = (self.opts.tls_session_cache / 8).max(32);
        let detector = Detector::new(dcfg).await?;
        let batch: Vec<BatchTarget> = targets
            .iter()
            .cloned()
            .enumerate()
            .map(|(id, target)| BatchTarget { target, id })
            .collect();
        let adaptive = crate::AdaptiveConfig {
            enabled: true,
            initial: max_conc,
            min: self.opts.adaptive_min.max(1),
            max: self.opts.adaptive_max.max(max_conc),
            window: 10,
        };
        let cancel = tokio_util::sync::CancellationToken::new();
        let results = detector
            .detect_batch_with_cancel(
                &batch,
                self.opts.domain.as_deref(),
                max_conc,
                adaptive,
                cancel,
                |_| {},
            )
            .await;
        Ok(results)
    }

    async fn run_speedtest(
        &self,
        results: &[BatchResult],
    ) -> Result<std::collections::HashMap<String, u64>> {
        if !self.opts.speedtest {
            return Ok(Default::default());
        }
        let domain = self
            .opts
            .domain
            .clone()
            .unwrap_or_else(|| "www.cloudflare.com".to_string());
        let speed_cfg = SpeedTestConfig {
            timeout: Duration::from_secs(5),
            threads_per_target: self.opts.speedtest_threads.max(1),
            concurrency: self.opts.speedtest_concurrency.max(1),
        };
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
        if speed_targets.is_empty() {
            return Ok(map);
        }
        let mut conn_cfg = PinnedClientConfig::default();
        conn_cfg.connect_timeout = Duration::from_secs(2);
        conn_cfg.request_timeout = Duration::from_secs(5);
        let session_cache = self.opts.tls_session_cache.max(128);
        conn_cfg.tls_session_cache_max_entries = session_cache;
        conn_cfg.tls_session_cache_size = session_cache;
        let conn = Arc::new(crate::PinnedConnector::new(conn_cfg)?);
        use futures::stream::{self, StreamExt};
        let stream = stream::iter(speed_targets)
            .map(|target| {
                let cfg_inner = speed_cfg.clone();
                let conn_c = conn.clone();
                let sni_c = domain.clone();
                let host_c = domain.clone();
                let path_c = self.opts.speedtest_url_path.clone();
                async move {
                    let use_tls = target.port != 80;
                    let tester =
                        SpeedTester::with_connector(conn_c, use_tls, sni_c.clone(), host_c.clone());
                    let res = tester.test(&target, &path_c, &cfg_inner).await.ok()?;
                    Some((target, res.bytes_per_second))
                }
            })
            .buffer_unordered(speed_cfg.concurrency.max(1));
        let outcomes: Vec<_> = stream.collect().await;
        for (t, bps) in outcomes.into_iter().flatten() {
            map.insert(t.to_string(), bps);
        }
        Ok(map)
    }

    fn write_csv_output(
        &self,
        path: &Path,
        results: &[BatchResult],
        speed: &std::collections::HashMap<String, u64>,
    ) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut wtr = CsvWriter::from_path(path)?;
        for br in results {
            let speed_bps = speed.get(&br.target.to_string()).copied();
            let record = ExportCsvRow::from_batch(br, speed_bps);
            wtr.serialize(record)?;
        }
        wtr.flush()?;
        Ok(())
    }

    pub async fn process_open_ports(
        &self,
        open_ports: Vec<OpenPort>,
        label: &str,
        ports: &str,
        tls: bool,
    ) -> Result<PipelineOutput> {
        let started = Instant::now();
        let targets = Self::open_ports_to_targets(&open_ports, tls);
        let detection_results = self.run_detection(&targets, tls).await?;
        let speed_map = self.run_speedtest(&detection_results).await?;
        let filename = Self::build_output_filename(label, tls, ports);
        let output_path = self.opts.output_dir.join(&filename);
        self.write_csv_output(&output_path, &detection_results, &speed_map)?;
        let elapsed = started.elapsed().as_secs();
        let cf_count = detection_results
            .iter()
            .filter(|r| {
                r.result
                    .as_ref()
                    .map(|d| d.is_cloudflare_edge)
                    .unwrap_or(false)
            })
            .count();
        Ok(PipelineOutput {
            label: label.to_string(),
            tls_flag: tls,
            ports: ports.to_string(),
            output_path,
            masscan_duration_secs: 0,
            detection_duration_secs: elapsed,
            open_ports_count: open_ports.len(),
            detection_results_count: detection_results.len(),
            cloudflare_edges_count: cf_count,
        })
    }

    pub async fn run_single_asn(
        &self,
        scanner: &crate::MasscanScanner,
        asn: u32,
        ports: &str,
        tls: bool,
    ) -> Result<PipelineOutput> {
        let scan_start = Instant::now();
        let cidrs = scanner.fetch_asn_cidrs(asn).await?;
        let open_ports = scanner.scan_cidrs(&cidrs, ports).await?;
        let scan_secs = scan_start.elapsed().as_secs();
        let label = format!("AS{}", asn);
        let mut out = self
            .process_open_ports(open_ports, &label, ports, tls)
            .await?;
        out.masscan_duration_secs = scan_secs;
        Ok(out)
    }

    pub async fn run_batch_asn(
        &self,
        scanner: &crate::MasscanScanner,
        tasks: Vec<PipelineAsnTask>,
    ) -> Result<PipelineResult> {
        let start = Instant::now();
        let mut outputs = Vec::with_capacity(tasks.len());
        for task in tasks {
            match self
                .run_single_asn(scanner, task.asn, &task.ports, task.tls)
                .await
            {
                Ok(o) => outputs.push(o),
                Err(e) => tracing::warn!("ASN {} failed: {}", task.asn, e),
            }
        }
        Ok(PipelineResult {
            outputs,
            total_duration_secs: start.elapsed().as_secs(),
        })
    }

    pub async fn run_single_ip(
        &self,
        scanner: &crate::MasscanScanner,
        ip: IpAddr,
        ports: &str,
        tls: bool,
    ) -> Result<PipelineOutput> {
        let scan_start = Instant::now();
        let open_ports = scanner.scan_single_ip(ip, ports).await?;
        let scan_secs = scan_start.elapsed().as_secs();
        let label = format!("IP{}", ip);
        let mut out = self
            .process_open_ports(open_ports, &label, ports, tls)
            .await?;
        out.masscan_duration_secs = scan_secs;
        Ok(out)
    }

    pub async fn run_batch_ip(
        &self,
        scanner: &crate::MasscanScanner,
        ips: &[IpAddr],
        ports: &str,
        tls: bool,
    ) -> Result<PipelineOutput> {
        let scan_start = Instant::now();
        let open_ports = scanner.scan_ips(ips, ports).await?;
        let scan_secs = scan_start.elapsed().as_secs();
        let label = format!("IPbatch-{}", ips.len());
        let mut out = self
            .process_open_ports(open_ports, &label, ports, tls)
            .await?;
        out.masscan_duration_secs = scan_secs;
        Ok(out)
    }
}

#[derive(Debug, Clone, Serialize)]
struct ExportCsvRow {
    target: String,
    ip: String,
    port: u16,
    is_cloudflare_edge: bool,
    is_tls: bool,
    is_usable: bool,
    status_code: String,
    colo: String,
    country: String,
    region: String,
    city: String,
    latency_ms: String,
    download_speed_bytes_per_sec: String,
    confidence: String,
    confidence_reason: String,
    reasons: String,
    error: String,
}

impl ExportCsvRow {
    fn from_batch(br: &BatchResult, speed_bps: Option<u64>) -> Self {
        let r = br.result.as_ref();
        let edge = r.and_then(|x| x.edge_info.as_ref());
        let dsbps = speed_bps
            .or_else(|| edge.and_then(|x| x.download_speed_bytes_per_sec))
            .map(|b| b.to_string())
            .unwrap_or_default();
        Self {
            target: br.target.to_string(),
            ip: br.target.ip.to_string(),
            port: br.target.port,
            is_cloudflare_edge: r.map(|x| x.is_cloudflare_edge).unwrap_or(false),
            is_tls: r.map(|x| x.is_tls).unwrap_or(false),
            is_usable: r.map(|x| x.is_usable).unwrap_or(false),
            status_code: r
                .and_then(|x| x.http_status_code)
                .map(|c| c.to_string())
                .unwrap_or_default(),
            colo: edge.and_then(|x| x.colo_code.clone()).unwrap_or_default(),
            country: edge.and_then(|x| x.country.clone()).unwrap_or_default(),
            region: edge.and_then(|x| x.region.clone()).unwrap_or_default(),
            city: edge.and_then(|x| x.city.clone()).unwrap_or_default(),
            latency_ms: edge
                .and_then(|x| x.latency)
                .map(|d| d.as_millis().to_string())
                .unwrap_or_default(),
            download_speed_bytes_per_sec: dsbps,
            confidence: r
                .map(|x| match x.confidence {
                    crate::Confidence::None => "NONE".to_string(),
                    crate::Confidence::Low => "LOW".to_string(),
                    crate::Confidence::Medium => "MEDIUM".to_string(),
                    crate::Confidence::High => "HIGH".to_string(),
                })
                .unwrap_or_else(|| "NONE".to_string()),
            confidence_reason: r.map(|x| x.confidence_reason.clone()).unwrap_or_default(),
            reasons: r.map(|x| x.reasons.join("; ")).unwrap_or_default(),
            error: br.error.clone().unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn pipeline_options_default_values() {
        let opts = PipelineOptions::default();
        assert!(!opts.speedtest);
        assert_eq!(opts.speedtest_threads, 0);
        assert_eq!(opts.concurrency, 0);
        assert_eq!(opts.speedtest_url_path, "");
        assert_eq!(opts.output_dir, PathBuf::from(""));
        assert_eq!(opts.probe_timeout_secs, 0);
        assert_eq!(opts.tls_session_cache, 0);
    }

    #[test]
    fn build_output_filename_safe_chars() {
        assert_eq!(
            MasscanPipeline::build_output_filename("AS45102", true, "443"),
            "AS45102-true-443.csv"
        );
        assert_eq!(
            MasscanPipeline::build_output_filename("AS1", false, "443,8443"),
            "AS1-false-443-8443.csv"
        );
        assert_eq!(
            MasscanPipeline::build_output_filename("IP-batch", true, "1-65535"),
            "IP-batch-true-1to65535.csv"
        );
    }

    #[test]
    fn open_ports_to_targets_maps_ip_and_port() {
        let ops = vec![
            OpenPort {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 443,
            },
            OpenPort {
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: 80,
            },
        ];
        let ts = MasscanPipeline::open_ports_to_targets(&ops, true);
        assert_eq!(ts.len(), 2);
        assert_eq!(ts[0].port, 443);
        assert_eq!(ts[1].port, 80);
    }

    #[test]
    fn open_ports_to_targets_handles_zero_port() {
        let ops = vec![OpenPort {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 0,
        }];
        let ts_tls = MasscanPipeline::open_ports_to_targets(&ops, true);
        assert_eq!(ts_tls[0].port, 443);
        let ts_plain = MasscanPipeline::open_ports_to_targets(&ops, false);
        assert_eq!(ts_plain[0].port, 80);
    }

    #[test]
    fn pipeline_asn_task_from_crate_asn_task() {
        let raw = crate::AsnTask {
            asn: 45102,
            ports: "443".into(),
            tls: true,
        };
        let t: PipelineAsnTask = raw.into();
        assert_eq!(t.asn, 45102);
        assert_eq!(t.ports, "443");
        assert!(t.tls);
    }

    #[test]
    fn pipeline_result_and_output_fields() {
        let out = PipelineOutput {
            label: "AS45102".into(),
            tls_flag: true,
            ports: "443".into(),
            output_path: PathBuf::from("AS45102-true-443.csv"),
            masscan_duration_secs: 10,
            detection_duration_secs: 20,
            open_ports_count: 100,
            detection_results_count: 100,
            cloudflare_edges_count: 75,
        };
        let res = PipelineResult {
            outputs: vec![out],
            total_duration_secs: 30,
        };
        assert_eq!(res.outputs.len(), 1);
        assert_eq!(res.outputs[0].cloudflare_edges_count, 75);
        assert_eq!(res.total_duration_secs, 30);
    }

    #[test]
    fn new_pipeline_stores_opts() {
        let opts = PipelineOptions {
            concurrency: 50,
            output_dir: PathBuf::from("/tmp/out"),
            ..Default::default()
        };
        let p = MasscanPipeline::new(opts.clone());
        assert_eq!(p.opts.concurrency, 50);
        assert_eq!(p.opts.output_dir, PathBuf::from("/tmp/out"));
    }

    #[tokio::test]
    async fn write_csv_output_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let opts = PipelineOptions {
            output_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let p = MasscanPipeline::new(opts);
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let result = BatchResult {
            id: 0,
            target: target.clone(),
            result: Some(crate::DetectionResult {
                is_cloudflare_edge: true,
                is_tls: true,
                is_usable: true,
                confidence: crate::Confidence::High,
                confidence_reason: "test".into(),
                ..Default::default()
            }),
            error: None,
        };
        let results = vec![result];
        let speed = std::collections::HashMap::new();
        let path = dir.path().join("out.csv");
        p.write_csv_output(&path, &results, &speed).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("127.0.0.1"));
        assert!(content.contains("true"));
        assert!(content.contains("HIGH"));
    }

    #[tokio::test]
    async fn write_csv_output_creates_nested_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let opts = PipelineOptions {
            output_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let p = MasscanPipeline::new(opts);
        let nested = dir.path().join("a").join("b").join("deep.csv");
        let results: Vec<BatchResult> = Vec::new();
        let speed = std::collections::HashMap::new();
        p.write_csv_output(&nested, &results, &speed).unwrap();
        assert!(nested.exists());
    }

    #[tokio::test]
    async fn write_csv_output_handles_error_results() {
        let dir = tempfile::tempdir().unwrap();
        let opts = PipelineOptions {
            output_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let p = MasscanPipeline::new(opts);
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80);
        let err_result = BatchResult {
            id: 0,
            target: target.clone(),
            result: None,
            error: Some("connection refused".into()),
        };
        let ok_result = BatchResult {
            id: 1,
            target: Target::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 443),
            result: Some(crate::DetectionResult {
                is_cloudflare_edge: false,
                is_tls: true,
                is_usable: false,
                confidence: crate::Confidence::None,
                confidence_reason: String::new(),
                reasons: vec!["no cf header".into(), "no ray".into()],
                edge_info: None,
                http_status_code: Some(503),
            }),
            error: None,
        };
        let speed_map = std::collections::HashMap::from([(target.to_string(), 5_000_000u64)]);
        let path = dir.path().join("mixed.csv");
        p.write_csv_output(&path, &[err_result, ok_result], &speed_map)
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("connection refused"));
        assert!(content.contains("no cf header; no ray"));
        assert!(content.contains("503"));
        assert!(content.contains("NONE"));
        assert!(content.contains("5000000"));
    }

    #[tokio::test]
    async fn write_csv_output_handles_edge_info() {
        use std::time::Duration;
        let dir = tempfile::tempdir().unwrap();
        let opts = PipelineOptions {
            output_dir: dir.path().to_path_buf(),
            ..Default::default()
        };
        let p = MasscanPipeline::new(opts);
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 229)), 443);
        let result = BatchResult {
            id: 0,
            target: target.clone(),
            result: Some(crate::DetectionResult {
                is_cloudflare_edge: true,
                is_tls: true,
                is_usable: true,
                confidence: crate::Confidence::Medium,
                confidence_reason: "matched headers".into(),
                reasons: vec!["ray present".into()],
                edge_info: Some(crate::EdgeInfo {
                    colo_code: Some("LAX".into()),
                    country: Some("US".into()),
                    region: Some("CA".into()),
                    city: Some("Los Angeles".into()),
                    latency: Some(Duration::from_millis(13)),
                    download_speed_bytes_per_sec: Some(25_000_000),
                }),
                http_status_code: Some(200),
            }),
            error: None,
        };
        let path = dir.path().join("edge.csv");
        p.write_csv_output(&path, &[result], &Default::default())
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("LAX"));
        assert!(content.contains("US"));
        assert!(content.contains("CA"));
        assert!(content.contains("Los Angeles"));
        assert!(content.contains("13"));
        assert!(content.contains("25000000"));
        assert!(content.contains("200"));
        assert!(content.contains("MEDIUM"));
    }

    #[test]
    fn export_csv_row_owned_no_lifetime_trap() {
        use std::time::Duration;
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
        let br = BatchResult {
            id: 99,
            target: target.clone(),
            result: Some(crate::DetectionResult {
                is_cloudflare_edge: true,
                is_tls: true,
                is_usable: true,
                confidence: crate::Confidence::Low,
                confidence_reason: "r".into(),
                reasons: vec!["a".into(), "b".into()],
                edge_info: Some(crate::EdgeInfo {
                    colo_code: Some("SIN".into()),
                    latency: Some(Duration::from_micros(5_123)),
                    ..Default::default()
                }),
                http_status_code: Some(403),
            }),
            error: Some("boom".into()),
        };
        let row = {
            let r_ref = &br;
            ExportCsvRow::from_batch(r_ref, Some(123456))
        };
        assert_eq!(row.target, target.to_string());
        assert_eq!(row.ip, "1.1.1.1");
        assert_eq!(row.port, 443);
        assert!(row.is_cloudflare_edge);
        assert!(row.is_tls);
        assert!(row.is_usable);
        assert_eq!(row.status_code, "403");
        assert_eq!(row.colo, "SIN");
        assert_eq!(row.confidence, "LOW");
        assert_eq!(row.confidence_reason, "r");
        assert_eq!(row.reasons, "a; b");
        assert_eq!(row.error, "boom");
        assert_eq!(row.latency_ms, "5");
        assert_eq!(row.download_speed_bytes_per_sec, "123456");
    }

    #[test]
    fn export_csv_row_defaults_when_result_none() {
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let br = BatchResult {
            id: 0,
            target: target.clone(),
            result: None,
            error: None,
        };
        let row = ExportCsvRow::from_batch(&br, None);
        assert_eq!(row.target, target.to_string());
        assert_eq!(row.ip, "8.8.8.8");
        assert_eq!(row.port, 53);
        assert!(!row.is_cloudflare_edge);
        assert!(!row.is_tls);
        assert!(!row.is_usable);
        assert!(row.status_code.is_empty());
        assert!(row.colo.is_empty());
        assert!(row.country.is_empty());
        assert!(row.region.is_empty());
        assert!(row.city.is_empty());
        assert!(row.latency_ms.is_empty());
        assert!(row.download_speed_bytes_per_sec.is_empty());
        assert_eq!(row.confidence, "NONE");
        assert!(row.confidence_reason.is_empty());
        assert!(row.reasons.is_empty());
        assert!(row.error.is_empty());
    }

    #[test]
    fn export_csv_row_speed_prefers_explicit_over_edge_info() {
        use std::time::Duration;
        let target = Target::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
        let br = BatchResult {
            id: 0,
            target,
            result: Some(crate::DetectionResult {
                is_cloudflare_edge: true,
                is_tls: true,
                is_usable: true,
                confidence: crate::Confidence::High,
                confidence_reason: "x".into(),
                reasons: Vec::new(),
                edge_info: Some(crate::EdgeInfo {
                    download_speed_bytes_per_sec: Some(1_000_000),
                    latency: Some(Duration::from_millis(7)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            error: None,
        };
        let with_explicit = ExportCsvRow::from_batch(&br, Some(9_999_999));
        assert_eq!(with_explicit.download_speed_bytes_per_sec, "9999999");
        let without_explicit = ExportCsvRow::from_batch(&br, None);
        assert_eq!(without_explicit.download_speed_bytes_per_sec, "1000000");
    }

    #[test]
    fn pipeline_asn_task_from_impl_roundtrip() {
        let original = crate::AsnTask {
            asn: 13335,
            ports: "443,8443,2053".into(),
            tls: false,
        };
        let task: PipelineAsnTask = original.clone().into();
        assert_eq!(task.asn, original.asn);
        assert_eq!(task.ports, original.ports);
        assert_eq!(task.tls, original.tls);
    }

    #[test]
    fn pipeline_output_fields_serializable() {
        let out = PipelineOutput {
            label: "AS13335".into(),
            tls_flag: true,
            ports: "443".into(),
            output_path: PathBuf::from("results/AS13335-true-443.csv"),
            masscan_duration_secs: 12,
            detection_duration_secs: 58,
            open_ports_count: 1024,
            detection_results_count: 1024,
            cloudflare_edges_count: 311,
        };
        let json = serde_json::to_string(&out).unwrap();
        let back: PipelineOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.label, out.label);
        assert_eq!(back.cloudflare_edges_count, out.cloudflare_edges_count);
        assert_eq!(back.masscan_duration_secs, out.masscan_duration_secs);
    }

    #[test]
    fn pipeline_result_aggregate() {
        let res = PipelineResult {
            outputs: vec![
                PipelineOutput {
                    label: "A".into(),
                    tls_flag: true,
                    ports: "443".into(),
                    output_path: PathBuf::from("a.csv"),
                    masscan_duration_secs: 1,
                    detection_duration_secs: 2,
                    open_ports_count: 10,
                    detection_results_count: 10,
                    cloudflare_edges_count: 5,
                },
                PipelineOutput {
                    label: "B".into(),
                    tls_flag: false,
                    ports: "80".into(),
                    output_path: PathBuf::from("b.csv"),
                    masscan_duration_secs: 3,
                    detection_duration_secs: 4,
                    open_ports_count: 20,
                    detection_results_count: 20,
                    cloudflare_edges_count: 8,
                },
            ],
            total_duration_secs: 10,
        };
        let json = serde_json::to_string(&res).unwrap();
        let back: PipelineResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_duration_secs, 10);
        assert_eq!(back.outputs.len(), 2);
        assert_eq!(back.outputs[0].cloudflare_edges_count, 5);
        assert_eq!(back.outputs[1].cloudflare_edges_count, 8);
    }

    #[test]
    fn build_output_filename_replaces_three_special_chars() {
        assert_eq!(
            MasscanPipeline::build_output_filename("X", false, "80,443,2053,8443"),
            "X-false-80-443-2053-8443.csv"
        );
        assert_eq!(
            MasscanPipeline::build_output_filename("X", true, "8080/8443"),
            "X-true-8080to8443.csv"
        );
        assert_eq!(
            MasscanPipeline::build_output_filename("X", true, "1-65535/1024,2048"),
            "X-true-1to65535to1024-2048.csv"
        );
    }
}
