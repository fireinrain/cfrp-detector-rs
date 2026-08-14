use thiserror::Error;

pub type Result<T> = std::result::Result<T, DetectorError>;

#[derive(Debug, Error)]
pub enum DetectorError {
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid port: {0}")]
    InvalidPort(u16),
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("data source error: {0}")]
    DataSource(String),
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