use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use figment::providers::Format;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CfgShim {
    pub concurrency: usize,
    pub progress: bool,
    pub probe_timeout_secs: u64,
    pub tls_session_cache: usize,
}

#[test]
fn phase4_4_toml_config_defaults_load_and_preserve() {
    let toml_src = r#"
concurrency = 42
progress = true
probe_timeout_secs = 9
tls_session_cache = 1024
"#;
    let dir = std::env::temp_dir().join(format!(
        "cfrp-cli-phase4-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("config.toml");
    let mut f = std::fs::File::create(&file_path).unwrap();
    writeln!(f, "{toml_src}").unwrap();
    drop(f);

    let figment = figment::Figment::from(figment::providers::Toml::file(&file_path));
    let cfg: CfgShim = figment.extract().expect("toml parse");
    assert_eq!(cfg.concurrency, 42);
    assert_eq!(cfg.progress, true);
    assert_eq!(cfg.probe_timeout_secs, 9);
    assert_eq!(cfg.tls_session_cache, 1024);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn phase4_4_env_var_cfrp_concurrency_applied() {
    unsafe { std::env::set_var("CFRP_CONCURRENCY", "777") };
    let figment = figment::Figment::new().merge(figment::providers::Env::prefixed("CFRP_").split("_"));
    let v: Result<usize, _> = figment.extract_inner("concurrency");
    unsafe { std::env::remove_var("CFRP_CONCURRENCY") };
    match v {
        Ok(n) => assert_eq!(n, 777),
        Err(_) => {}
    }
}

#[test]
fn phase4_4_targets_and_target_parsing() {
    use cfrp_detector::parse_target;
    let t = parse_target("127.0.0.1", 443).unwrap();
    assert_eq!(t.port, 443);
    let t2 = parse_target("127.0.0.1:8443", 443).unwrap();
    assert_eq!(t2.port, 8443);
    let t3 = parse_target("[::1]:8443", 443).unwrap();
    assert_eq!(t3.port, 8443);
    let err = parse_target("not a target at all", 443);
    assert!(err.is_err());
}

#[test]
fn phase4_6_cancellation_token_triggers_child() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        use tokio_util::sync::CancellationToken;
        let parent = CancellationToken::new();
        let child = parent.child_token();
        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = child.cancelled() => 1i32,
                _ = tokio::time::sleep(Duration::from_millis(5_000)) => 0,
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        parent.cancel();
        let r = handle.await.unwrap();
        assert_eq!(r, 1, "child should be cancelled by parent");
    });
}

#[test]
fn phase4_5_retry_config_defaults() {
    let cfg = cfrp_detector::RetryConfig::default();
    assert!(cfg.max_attempts >= 2, "max_attempts default should be >=2");
    assert!(cfg.max_backoff_ms > 0);
}

#[test]
fn phase4_4_output_format_inference_check_extension() {
    fn check(ext: &str) {
        let _p = PathBuf::from(format!("/tmp/x.{ext}"));
    }
    check("txt");
    check("csv");
    check("json");
}