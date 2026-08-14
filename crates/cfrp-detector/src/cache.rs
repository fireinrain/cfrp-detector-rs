use crate::{DetectorError, Result, RetryConfig, is_retryable_error};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tokio::{fs, io::AsyncWriteExt, time::sleep};

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub directory: PathBuf,
    pub max_age: Duration,
    pub retry: RetryConfig,
    pub retry_on_429: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("data/cfrpdata"),
            max_age: Duration::from_secs(7 * 24 * 3600),
            retry: RetryConfig {
                max_attempts: 3,
                initial_backoff_ms: 500,
                max_backoff_ms: 5000,
                backoff_multiplier: 2.0,
            },
            retry_on_429: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileCache {
    pub cfg: CacheConfig,
}

impl FileCache {
    pub fn new(cfg: CacheConfig) -> Self {
        Self { cfg }
    }

    pub async fn load_or_fetch(
        &self,
        prefix: &str,
        extension: &str,
        url: &str,
        max_age: Duration,
        client: &reqwest::Client,
    ) -> Result<Vec<u8>> {
        fs::create_dir_all(&self.cfg.directory).await?;
        if let Some(path) = self.find_fresh(prefix, extension, max_age).await? {
            return Ok(fs::read(path).await?);
        }
        let bytes = self.fetch_with_retry(url, client).await?;
        let name = format!("{}-{}{}", prefix, chrono_like_date(), extension);
        let path = self.cfg.directory.join(name);
        let mut file = fs::File::create(&path).await?;
        file.write_all(&bytes).await?;
        file.flush().await?;
        self.cleanup(prefix, extension, &path).await;
        Ok(bytes)
    }

    async fn fetch_with_retry(&self, url: &str, client: &reqwest::Client) -> Result<Vec<u8>> {
        let policy = &self.cfg.retry;
        let mut last_err: Option<DetectorError> = None;
        let mut backoff_ms = policy.initial_backoff_ms;

        for attempt in 1..=policy.max_attempts {
            match self.fetch_once(url, client).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    let should_retry = self.should_retry_error(&e);
                    if !should_retry || attempt == policy.max_attempts {
                        last_err = Some(e);
                        break;
                    }
                    last_err = Some(e);
                    let jitter = (backoff_ms as f64 * 0.3 * (rand_like_jitter() - 0.5)) as i64;
                    let delay_ms = (backoff_ms as i64 + jitter).max(0) as u64;
                    sleep(Duration::from_millis(delay_ms)).await;
                    backoff_ms = ((backoff_ms as f64 * policy.backoff_multiplier) as u64)
                        .min(policy.max_backoff_ms);
                }
            }
        }

        let attempts = policy.max_attempts;
        let source = Box::new(last_err.unwrap_or_else(|| {
            DetectorError::DataSource("unknown error after retries".into())
        }));
        Err(DetectorError::RetriesExceeded { source, attempts })
    }

    async fn fetch_once(&self, url: &str, client: &reqwest::Client) -> Result<Vec<u8>> {
        let resp = client.get(url).send().await?;
        let status = resp.status();
        if status.is_success() {
            Ok(resp.bytes().await?.to_vec())
        } else {
            let status_code = status.as_u16();
            let msg = format!("HTTP {} when fetching {}", status_code, url);
            Err(DetectorError::Http(msg))
        }
    }

    fn should_retry_error(&self, err: &DetectorError) -> bool {
        if is_retryable_error(err) {
            return true;
        }
        if let DetectorError::Http(msg) = err {
            if msg.contains("HTTP 5") {
                return true;
            }
            if self.cfg.retry_on_429 && msg.contains("HTTP 429") {
                return true;
            }
        }
        false
    }

    async fn find_fresh(
        &self,
        prefix: &str,
        extension: &str,
        max_age: Duration,
    ) -> Result<Option<PathBuf>> {
        let mut dir = fs::read_dir(&self.cfg.directory).await?;
        let mut latest: Option<(PathBuf, SystemTime)> = None;
        while let Some(entry) = dir.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(&format!("{}-", prefix)) || !name.ends_with(extension) {
                continue;
            }
            let modified = entry
                .metadata()
                .await?
                .modified()
                .unwrap_or(SystemTime::UNIX_EPOCH);
            if latest.as_ref().map(|(_, t)| modified > *t).unwrap_or(true) {
                latest = Some((entry.path(), modified));
            }
        }
        if let Some((path, modified)) = latest {
            if modified.elapsed().unwrap_or(Duration::MAX) <= max_age {
                return Ok(Some(path));
            }
        }
        Ok(None)
    }

    async fn cleanup(&self, prefix: &str, extension: &str, keep: &Path) {
        let Ok(mut dir) = fs::read_dir(&self.cfg.directory).await else {
            return;
        };
        while let Ok(Some(entry)) = dir.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&format!("{}-", prefix))
                && name.ends_with(extension)
                && entry.path() != keep
            {
                let _ = fs::remove_file(entry.path()).await;
            }
        }
    }
}

fn chrono_like_date() -> String {
    let days = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400;
    format!("day-{}", days)
}

fn rand_like_jitter() -> f64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut h = DefaultHasher::new();
    SystemTime::now().hash(&mut h);
    let nonce = COUNTER.fetch_add(0x517c_c15b_d185_4c0d, Ordering::Relaxed);
    h.write_u64(nonce);
    let val = h.finish();
    (val as f64) / (u64::MAX as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_config_default_values() {
        let cfg = CacheConfig::default();
        assert_eq!(cfg.directory, PathBuf::from("data/cfrpdata"));
        assert_eq!(cfg.max_age, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(cfg.retry.max_attempts, 3);
        assert_eq!(cfg.retry.initial_backoff_ms, 500);
        assert!(cfg.retry_on_429);
    }

    #[test]
    fn cache_config_clone() {
        let cfg = CacheConfig {
            directory: PathBuf::from("/tmp/test"),
            max_age: Duration::from_secs(60),
            retry: RetryConfig::default(),
            retry_on_429: false,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg.directory, cfg2.directory);
        assert_eq!(cfg.max_age, cfg2.max_age);
        assert_eq!(cfg.retry_on_429, cfg2.retry_on_429);
    }

    #[test]
    fn file_cache_new_constructs() {
        let cfg = CacheConfig::default();
        let cache = FileCache::new(cfg.clone());
        assert_eq!(cache.cfg.directory, cfg.directory);
    }

    #[test]
    fn chrono_like_date_format() {
        let s = chrono_like_date();
        assert!(s.starts_with("day-"));
        let days_part = &s[4..];
        assert!(days_part.parse::<u64>().is_ok());
    }

    #[test]
    fn rand_like_jitter_within_unit_range() {
        for _ in 0..10 {
            let j = rand_like_jitter();
            assert!((0.0..=1.0).contains(&j), "jitter out of range: {}", j);
        }
    }

    #[test]
    fn should_retry_error_5xx() {
        let cfg = CacheConfig::default();
        let cache = FileCache::new(cfg);
        let e503 = DetectorError::Http("HTTP 503 when fetching /x".into());
        assert!(cache.should_retry_error(&e503));
        let e404 = DetectorError::Http("HTTP 404 when fetching /x".into());
        assert!(!cache.should_retry_error(&e404));
    }

    #[test]
    fn should_retry_error_429_when_enabled() {
        let mut cfg = CacheConfig::default();
        cfg.retry_on_429 = true;
        let cache = FileCache::new(cfg);
        let e429 = DetectorError::Http("HTTP 429 when fetching /x".into());
        assert!(cache.should_retry_error(&e429));

        let mut cfg_no = CacheConfig::default();
        cfg_no.retry_on_429 = false;
        let cache_no = FileCache::new(cfg_no);
        assert!(!cache_no.should_retry_error(&e429));
    }

    #[test]
    fn retries_exceeded_error_display() {
        let e = DetectorError::RetriesExceeded {
            source: Box::new(DetectorError::Http("HTTP 503".into())),
            attempts: 3,
        };
        let msg = e.to_string();
        assert!(msg.contains("3 attempts"));
        assert!(msg.contains("HTTP 503"));
    }

    #[tokio::test]
    async fn file_cache_cleanup_does_not_panic_on_missing_dir() {
        let cfg = CacheConfig {
            directory: PathBuf::from("/tmp/nonexistent-cfrp-cache-dir"),
            max_age: Duration::from_secs(60),
            retry: RetryConfig::default(),
            retry_on_429: true,
        };
        let cache = FileCache::new(cfg);
        let keep = PathBuf::from("/tmp/nonexistent-cfrp-cache-dir/keep.txt");
        cache.cleanup("ips-v4", ".txt", &keep).await;
    }
}