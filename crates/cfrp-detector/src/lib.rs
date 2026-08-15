//! Cloudflare edge detection and network quality probing.
//!
//! This crate implements a multi-layer detection pipeline to decide whether a
//! given `(IP, port)` is actually a Cloudflare edge POP, and then optionally
//! runs a multi-threaded throughput speed test against the host to measure
//! real-world download speed.
//!
//! # Architecture
//!
//! The library is organised around a few core components:
//!
//! * **[`Detector`]** — orchestrator that pulls together every layer below and
//!   produces a [`DetectionResult`] with a [`Confidence`] score.
//! * **[`CloudflareRanges`]** + **[`LocationStore`]** — cached data sources
//!   loaded from the official Cloudflare CIDR lists and a community-maintained
//!   colo code → geography mapping.
//! * **[`ProbeEngine`]** (inside `probe`) — TLS + HTTP probes that check for
//!   Cloudflare-specific response headers and certificate fingerprints.
//! * **[`SpeedTester`]** — multi-threaded byte-range downloader that measures
//!   effective throughput to a specific colo.
//! * **[`MasscanScanner`]** *(optional)* — drives an external `masscan` process
//!   for large-scale SYN scans before feeding the results into batch detection.
//!
//! # Example
//!
//! ```no_run
//! # use cfrp_detector::{Detector, DetectorConfig, Target, parse_target};
//! # use std::net::{IpAddr, Ipv4Addr};
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. 构建默认配置的检测器 (首次加载会下载 CF CIDR 和 colo 数据)
//! let detector = Detector::new(DetectorConfig::default()).await?;
//!
//! // 2a. 用 Target::new 构造 (IP + port)
//! let cf_dns = Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);
//!
//! // 2b. 或者用 parse_target 从字符串解析
//! let cf_home = parse_target("104.16.132.229:443", 443).map_err(|e| e.to_string())?;
//!
//! // 3. 单独探测
//! let res = detector.detect(&cf_home, None).await?;
//! let colo = res.edge_info.as_ref().and_then(|e| e.colo_code.as_deref()).unwrap_or("?");
//! println!("{:?}  colo={} edge={}", res.confidence, colo, res.is_cloudflare_edge);
//! # Ok(())
//! # }
//! ```

pub mod cache;
pub mod cidr;
pub mod connector;
pub mod detector;
pub mod error;
pub mod governor;
pub mod location;
pub mod masscan;
pub mod masscan_pipeline;
pub mod model;
pub mod probe;
pub mod speedtest;

pub use cache::{CacheConfig, FileCache};
pub use cidr::{CidrSource, CloudflareCidrs, CloudflareRanges};
pub use connector::{
    ConnectorConfig, HandshakeType, PinnedClientConfig, PinnedConnector, PinnedDownload, Timing,
    build_rustls_client_config, build_rustls_client_config_sized, connect_tcp, connect_tls,
};
pub use detector::{AdaptiveConfig, BatchProgress, Detector, DetectorConfig, GovernorFeedback};
pub use error::{DetectorError, Result, RetryConfig, is_retryable_error};
pub use governor::{
    FdCounter, GovernorSnapshot, MockFdCounter, ResourceGovernor, ResourceGovernorConfig,
    ResourceKind, SystemFdCounter, classify_resource_error,
};
pub use location::{CfLocation, LocationSource, LocationStore};
pub use masscan::{
    AsnTask, MasscanConfig, MasscanScanner, NetworkInterface, OpenPort, ScanMode,
    ScanPipelineConfig, clear_cache, parse_masscan_output,
};
pub use masscan_pipeline::{
    MasscanPipeline, PipelineAsnTask, PipelineOptions, PipelineOutput, PipelineResult,
    guess_tls_by_port,
};
pub use model::{
    BatchResult, BatchTarget, Confidence, DetectionResult, EdgeInfo, Protocol, Target, parse_target,
};
pub use probe::ProbeConfig;
pub use speedtest::{SpeedTestConfig, SpeedTestResult, SpeedTester};
