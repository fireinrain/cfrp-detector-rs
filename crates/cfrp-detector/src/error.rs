//! Error types and retry helpers used across the library.
//!
//! All fallible public APIs return [`Result<T>`] alias backed by the
//! [`DetectorError`] enum. Classification helpers (`is_retryable_error`) are
//! provided so that callers can implement their own retry loops, and a
//! built-in [`RetryConfig`] struct captures common exponential-backoff knobs.

use thiserror::Error;

/// Convenience alias for `Result<T, DetectorError>` used throughout the crate.
pub type Result<T> = std::result::Result<T, DetectorError>;

/// Exponential-backoff retry configuration used by optional retry helpers.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Maximum number of attempts before giving up (≥1).
    pub max_attempts: usize,
    /// Initial backoff in milliseconds before the first retry.
    pub initial_backoff_ms: u64,
    /// Cap on backoff interval between attempts.
    pub max_backoff_ms: u64,
    /// Multiplier applied to the backoff after each failed attempt.
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 50,
            max_backoff_ms: 1000,
            backoff_multiplier: 2.0,
        }
    }
}

/// Unified error type for the `cfrp-detector` crate.
///
/// Covers input validation, network / TLS / HTTP failures, (de)serialisation
/// issues, data-source fetching, and a transparent retry-wrapper variant.
/// Implements [`thiserror::Error`] with human-readable messages suitable for
/// CLI output.
#[derive(Debug, Error)]
pub enum DetectorError {
    /// Target string / endpoint could not be parsed as a valid `ip[:port]`.
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    /// IP address literal is malformed.
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    /// TCP port is outside the valid range `1..=65535`.
    #[error("invalid port: {0}")]
    InvalidPort(u16),
    /// Wraps [`reqwest::Error`] for high-level HTTP operations.
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    /// Raw TCP / socket-level I/O errors.
    #[error("network I/O error: {0}")]
    NetworkIo(std::io::Error),
    /// TLS handshake / certificate / cipher-suite errors.
    #[error("TLS error: {0}")]
    Tls(String),
    /// Generic filesystem I/O errors (cache, config, outputs).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON (de)serialisation failures.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// CSV (de)serialisation failures.
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    /// Protocol-level HTTP errors (unexpected status, malformed headers, etc.).
    #[error("HTTP error: {0}")]
    Http(String),
    /// External data sources (CIDR ranges, ASN lists, colo maps) unavailable.
    #[error("data source error: {0}")]
    DataSource(String),
    /// Wrapper indicating that all retries have been exhausted; `source` holds
    /// the final underlying error and `attempts` counts tries made.
    #[error("retries exceeded after {attempts} attempts: {source}")]
    RetriesExceeded {
        /// The error that caused the final attempt to fail.
        source: Box<DetectorError>,
        /// Total number of attempts executed.
        attempts: usize,
    },
}

/// Returns `true` if the given error typically deserves a retry (network
/// timeouts, transient I/O hiccups, and 5xx-class HTTP problems).
///
/// Deterministic validation errors, serialisation bugs, etc. always return
/// `false` so that callers do not waste effort retrying them.
pub fn is_retryable_error(err: &DetectorError) -> bool {
    match err {
        DetectorError::Network(rw_err) => {
            if rw_err.is_timeout() {
                return true;
            }
            if rw_err.is_connect() || rw_err.is_request() {
                let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(rw_err);
                while let Some(e) = cause {
                    if let Some(io_src) = e.downcast_ref::<std::io::Error>()
                        && matches_io_transient(io_src)
                    {
                        return true;
                    }
                    cause = e.source();
                }
            }
            let msg = rw_err.to_string();
            msg.contains("connection reset")
                || msg.contains("broken pipe")
                || msg.contains("Connection refused")
                || msg.contains("timed out")
                || msg.contains("timeout")
        }
        DetectorError::NetworkIo(io_err) => matches_io_transient(io_err),
        DetectorError::Http(msg) => {
            msg.contains("timed out")
                || msg.contains("timeout")
                || msg.contains("connection reset")
                || msg.contains("broken pipe")
                || msg.contains("Connection refused")
                || msg.contains("speedtest timed out")
        }
        DetectorError::Tls(msg) => {
            msg.contains("connection reset")
                || msg.contains("timed out")
                || msg.contains("broken pipe")
                || msg.contains("Connection refused")
        }
        DetectorError::Io(io_err) => matches_io_transient(io_err),
        DetectorError::RetriesExceeded { source, .. } => is_retryable_error(source),
        _ => false,
    }
}

fn matches_io_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        TimedOut
            | WouldBlock
            | BrokenPipe
            | Interrupted
            | ConnectionRefused
            | ConnectionReset
            | AddrNotAvailable
    ) || {
        let raw_os = e.raw_os_error().unwrap_or(0);
        matches_os_transient(raw_os)
    }
}

fn matches_os_transient(code: i32) -> bool {
    const ETIMEDOUT: i32 = 60;
    const ECONNRESET: i32 = 104;
    const ECONNREFUSED: i32 = 61;
    const EADDRINUSE: i32 = 98;
    const EADDRNOTAVAIL: i32 = 99;
    const ENOTCONN: i32 = 107;
    const EPIPE: i32 = 32;
    const EINTR: i32 = 4;
    matches!(
        code,
        ETIMEDOUT
            | ECONNRESET
            | ECONNREFUSED
            | EADDRINUSE
            | EADDRNOTAVAIL
            | ENOTCONN
            | EPIPE
            | EINTR
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_invalid_target_display() {
        let e = DetectorError::InvalidTarget("bad".into());
        assert_eq!(e.to_string(), "invalid target: bad");
    }

    #[test]
    fn error_invalid_ip_display() {
        let e = DetectorError::InvalidIp("999.1.1.1".into());
        assert_eq!(e.to_string(), "invalid IP address: 999.1.1.1");
    }

    #[test]
    fn error_invalid_port_display() {
        let e = DetectorError::InvalidPort(0);
        assert_eq!(e.to_string(), "invalid port: 0");
    }

    #[test]
    fn error_http_display() {
        let e = DetectorError::Http("timeout".into());
        assert_eq!(e.to_string(), "HTTP error: timeout");
    }

    #[test]
    fn error_data_source_display() {
        let e = DetectorError::DataSource("missing".into());
        assert_eq!(e.to_string(), "data source error: missing");
    }

    #[test]
    fn error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: DetectorError = io_err.into();
        assert!(e.to_string().contains("I/O error"));
    }

    #[test]
    fn error_from_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let e: DetectorError = json_err.into();
        assert!(e.to_string().contains("JSON error"));
    }

    #[test]
    fn result_type_alias_works() {
        let r: Result<i32> = Ok(42);
        assert_eq!(r.unwrap(), 42);
        let r: Result<i32> = Err(DetectorError::InvalidPort(0));
        assert!(r.is_err());
    }
}
