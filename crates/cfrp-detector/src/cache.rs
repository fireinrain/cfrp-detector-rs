use crate::Result;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tokio::{fs, io::AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub directory: PathBuf,
    pub max_age: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("data/cfrpdata"),
            max_age: Duration::from_secs(7 * 24 * 3600),
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
        let bytes = client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec();
        let name = format!("{}-{}{}", prefix, chrono_like_date(), extension);
        let path = self.cfg.directory.join(name);
        let mut file = fs::File::create(&path).await?;
        file.write_all(&bytes).await?;
        file.flush().await?;
        self.cleanup(prefix, extension, &path).await;
        Ok(bytes)
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
    // Stable dependency-free UTC date string via UNIX days. Precise wall-clock
    // naming is not part of the public API; file modification time is the TTL.
    let days = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400;
    format!("day-{}", days)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_config_default_values() {
        let cfg = CacheConfig::default();
        assert_eq!(cfg.directory, PathBuf::from("data/cfrpdata"));
        assert_eq!(cfg.max_age, Duration::from_secs(7 * 24 * 3600));
    }

    #[test]
    fn cache_config_clone() {
        let cfg = CacheConfig {
            directory: PathBuf::from("/tmp/test"),
            max_age: Duration::from_secs(60),
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg.directory, cfg2.directory);
        assert_eq!(cfg.max_age, cfg2.max_age);
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

    #[tokio::test]
    async fn file_cache_cleanup_does_not_panic_on_missing_dir() {
        let cfg = CacheConfig {
            directory: PathBuf::from("/tmp/nonexistent-cfrp-cache-dir"),
            max_age: Duration::from_secs(60),
        };
        let cache = FileCache::new(cfg);
        let keep = PathBuf::from("/tmp/nonexistent-cfrp-cache-dir/keep.txt");
        cache.cleanup("ips-v4", ".txt", &keep).await;
    }
}