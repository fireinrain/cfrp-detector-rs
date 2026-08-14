//! Cloudflare edge detection and network quality probing.
//!
//! The crate intentionally separates configuration, data sources, probing,
//! classification and orchestration so the same engine can be embedded in a
//! server or exposed through the CLI.

pub mod cache;
pub mod cidr;
pub mod connector;
pub mod detector;
pub mod error;
pub mod governor;
pub mod location;
pub mod model;
pub mod probe;
pub mod speedtest;

pub use cache::{CacheConfig, FileCache};
pub use cidr::{CidrSource, CloudflareCidrs, CloudflareRanges};
pub use connector::{ConnectorConfig, HandshakeType, PinnedClientConfig, PinnedConnector, PinnedDownload, Timing, build_rustls_client_config, build_rustls_client_config_sized, connect_tcp, connect_tls};
pub use detector::{AdaptiveConfig, BatchProgress, Detector, DetectorConfig, GovernorFeedback};
pub use error::{DetectorError, Result, RetryConfig, is_retryable_error};
pub use governor::{FdCounter, GovernorSnapshot, MockFdCounter, ResourceGovernor, ResourceGovernorConfig, ResourceKind, SystemFdCounter, classify_resource_error};
pub use location::{CfLocation, LocationSource, LocationStore};
pub use model::{BatchResult, BatchTarget, Confidence, DetectionResult, EdgeInfo, Protocol, Target};
pub use probe::ProbeConfig;
pub use speedtest::{SpeedTestConfig, SpeedTestResult, SpeedTester};