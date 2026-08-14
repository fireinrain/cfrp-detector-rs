//! Cloudflare edge detection and network quality probing.
//!
//! The crate intentionally separates configuration, data sources, probing,
//! classification and orchestration so the same engine can be embedded in a
//! server or exposed through the CLI.

mod cache;
mod cidr;
mod detector;
mod error;
mod location;
mod model;
mod probe;
mod speedtest;

pub use cache::{CacheConfig, FileCache};
pub use cidr::{CidrSource, CloudflareRanges};
pub use detector::{Detector, DetectorConfig};
pub use error::{DetectorError, Result};
pub use location::{CfLocation, LocationSource,LocationStore};
pub use model::{
    BatchResult, BatchTarget, Confidence, DetectionResult, EdgeInfo, Protocol, Target,
};
pub use probe::ProbeConfig;
pub use speedtest::{SpeedTestConfig, SpeedTestResult, SpeedTester};
