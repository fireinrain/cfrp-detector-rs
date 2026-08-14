use cfrp_detector::{CacheConfig, FileCache, RetryConfig};
use std::path::PathBuf;
use std::time::Duration;

#[test]
fn cache_config_new_path_and_age() {
    let cfg = CacheConfig {
        directory: PathBuf::from("/tmp/cfrp-test"),
        max_age: Duration::from_secs(3600),
        retry: RetryConfig::default(),
        retry_on_429: true,
    };
    assert_eq!(cfg.directory.to_str().unwrap(), "/tmp/cfrp-test");
    assert_eq!(cfg.max_age, Duration::from_secs(3600));
}

#[test]
fn cache_config_directory_default_exists_subpath() {
    let cfg = CacheConfig::default();
    let path = cfg.directory.to_string_lossy();
    assert!(path.contains("cfrpdata"));
    assert!(!path.is_empty());
}

#[test]
fn cache_config_default_max_age_is_one_week() {
    let cfg = CacheConfig::default();
    let expected = Duration::from_secs(7 * 24 * 60 * 60);
    assert_eq!(cfg.max_age, expected);
}

#[test]
fn file_cache_accepts_cfg_ref() {
    let cfg = CacheConfig {
        directory: PathBuf::from("/tmp/should-not-be-created"),
        max_age: Duration::from_millis(10),
        retry: RetryConfig::default(),
        retry_on_429: true,
    };
    let cache = FileCache::new(cfg.clone());
    assert_eq!(cache.cfg.directory, cfg.directory);
    assert_eq!(cache.cfg.max_age, cfg.max_age);
}

#[test]
fn cache_config_is_clonable_copyable_independent() {
    let mut a = CacheConfig::default();
    let b = a.clone();
    a.directory = PathBuf::from("/tmp/modified");
    assert_ne!(a.directory, b.directory);
}

#[test]
fn zero_max_age_is_allowed() {
    let cfg = CacheConfig {
        directory: PathBuf::from("/tmp/cfrp-zero"),
        max_age: Duration::ZERO,
        retry: RetryConfig::default(),
        retry_on_429: false,
    };
    assert!(cfg.max_age.is_zero());
}
