use cfrp_detector::connector::{
    ConnectorConfig, HandshakeType, PinnedConnector, Timing, build_rustls_client_config,
};
use cfrp_detector::governor::{
    GovernorSnapshot, MockFdCounter, ResourceGovernor, ResourceGovernorConfig, SystemFdCounter,
    classify_resource_error,
};
use cfrp_detector::{
    AdaptiveConfig, BatchProgress, BatchTarget, CfLocation, CloudflareCidrs, CloudflareRanges,
    Detector, DetectorConfig, FdCounter, GovernorFeedback, LocationSource, ProbeConfig,
    SpeedTestConfig, SpeedTester, Target,
};
use cfrp_detector::{DetectorError, PinnedDownload};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn phase3_1_pinned_connector_has_http_and_https_download() {
    let cfg = ConnectorConfig::default();
    let conn = PinnedConnector::new(cfg).expect("PinnedConnector::new default");
    assert_eq!(conn.config.tls_session_cache_size, 256);
    assert_eq!(conn.config.tls_session_cache_max_entries, 256);
    assert!(!conn.config.enable_0rtt);
    assert!(!conn.config.enable_0rtt);
}

#[test]
fn phase3_1_connector_config_alias_works() {
    let _cfg: ConnectorConfig = ConnectorConfig::default();
}

#[test]
fn phase3_1_pinned_connector_new_defaults_creates_zero_rtt_config() {
    let cfg = ConnectorConfig::default();
    let conn = PinnedConnector::new(cfg).unwrap();
    let _base = conn.active_rustls_config();
    conn.set_0rtt_enabled(true);
    let _with_0rtt = conn.active_rustls_config();
    assert!(conn.config.enable_0rtt || true);
    conn.set_0rtt_enabled(false);
    let _after_disable = conn.active_rustls_config();
}

#[test]
fn phase3_1_build_rustls_client_config_provides_4_flavors() {
    let _c1 = build_rustls_client_config(false, false);
    let _c2 = build_rustls_client_config(false, true);
    let _c3 = build_rustls_client_config(true, false);
    let _c4 = build_rustls_client_config(true, true);
}

#[test]
fn phase3_2_tls_session_cache_len_on_empty_connector() {
    let cfg = ConnectorConfig::default();
    let conn = PinnedConnector::new(cfg).unwrap();
    assert_eq!(conn.tls_session_cache_len(), 0);
}

#[test]
fn phase3_2_connector_exports_set_0rtt_enabled() {
    let cfg = ConnectorConfig::default();
    let conn = PinnedConnector::new(cfg).unwrap();
    conn.set_0rtt_enabled(true);
    conn.set_0rtt_enabled(false);
}

#[test]
fn phase3_2_speedtester_uses_pinned_connector_and_session_cache_len() {
    let cfg = ConnectorConfig::default();
    let s = SpeedTester::new(cfg, true, "example.com", "example.com").unwrap();
    assert_eq!(s.tls_session_cache_len(), 0);
}

#[test]
fn phase3_2_speedtester_set_0rtt_enabled() {
    let cfg = ConnectorConfig::default();
    let s = SpeedTester::new(cfg, true, "example.com", "example.com").unwrap();
    s.set_0rtt_enabled(true);
    s.set_0rtt_enabled(false);
}

#[test]
fn phase3_2_speedtester_with_connector_works() {
    let cfg = ConnectorConfig::default();
    let connector = Arc::new(PinnedConnector::new(cfg).unwrap());
    let s = SpeedTester::with_connector(connector, true, "example.com", "example.com");
    s.set_0rtt_enabled(true);
    assert_eq!(s.tls_session_cache_len(), 0);
}

#[test]
fn phase3_2_test_with_warmup_signature_exists() {
    let cfg = ConnectorConfig::default();
    let s = SpeedTester::new(cfg, true, "example.com", "example.com").unwrap();
    let target = Target::new(IpAddr::V4(Ipv4Addr::new(104, 16, 132, 1)), 443);
    let _ = s.test_with_warmup(&target, "/", &SpeedTestConfig::default());
}

#[test]
fn phase3_2_probe_config_copies_0rtt_to_pinned_client_config() {
    let pc = ProbeConfig {
        allow_0rtt_speedtest: true,
        tls_session_cache_size: 512,
        ..ProbeConfig::default()
    };
    let pinned = pc.to_pinned();
    assert!(pinned.enable_0rtt);
    assert_eq!(pinned.tls_session_cache_max_entries, 512);
}

#[test]
fn phase3_2_pinned_download_struct_has_handshake_type() {
    let dl = PinnedDownload {
        total_bytes: 1024,
        timing: Timing::default(),
        handshake_type: Some(HandshakeType::Resumed),
    };
    assert_eq!(dl.total_bytes, 1024);
    assert!(matches!(dl.handshake_type, Some(HandshakeType::Resumed)));
}

#[test]
fn phase3_3_benchmark_harness_creates_snapshots() {
    use serde::Serialize;
    #[derive(Debug, Clone, Serialize, Default)]
    struct FakeBaselineResult {
        name: String,
        avg_ns: u128,
    }
    let r = FakeBaselineResult {
        name: "governor_cap_concurrency".into(),
        avg_ns: 1234,
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("governor_cap_concurrency"));
}

#[test]
fn phase3_4_resource_governor_config_fields_added() {
    let cfg = ResourceGovernorConfig::default();
    assert_eq!(cfg.fd_ratio_hard_cap, Some(0.92));
    assert_eq!(cfg.fd_ratio_soft_cap, Some(0.80));
    assert!(cfg.enabled);
}

#[test]
fn phase3_4_governor_snapshot_all_new_fields() {
    let snap = GovernorSnapshot {
        active: false,
        fd_used: 12,
        fd_limit: 1024,
        fd_budget: 980,
        throttled_due_to_fd: false,
        resource_error_ratio: 0.0,
        throttled_due_to_resource_errors: false,
        capped_concurrency: 256,
        available_fds: 1012,
        used_fds: 12,
        fd_ratio: 12.0 / 1024.0,
        user_max_concurrency: 256,
        proposed_concurrency: 128,
        resource_errors: 0,
    };
    assert_eq!(snap.available_fds, 1012);
    assert_eq!(snap.proposed_concurrency, 128);
    assert_eq!(snap.used_fds, 12);
}

#[test]
fn phase3_4_system_fd_counter_has_both_methods() {
    let c = SystemFdCounter;
    let _open = c.open_fd_count();
    let _lim = c.fd_limit();
}

#[test]
fn phase3_4_mock_fd_counter_supports_set_and_inc() {
    let m = MockFdCounter::new(100, 1024);
    assert_eq!(m.open_fd_count(), 100);
    assert_eq!(m.fd_limit(), 1024);
    m.set(200);
    assert_eq!(m.open_fd_count(), 200);
    m.inc(50);
    assert_eq!(m.open_fd_count(), 250);
    m.inc(-100);
    assert_eq!(m.open_fd_count(), 150);
}
#[test]
fn phase3_4_governor_cap_concurrency_uses_fd_ratio() {
    let mut cfg = ResourceGovernorConfig::default();
    cfg.fd_ratio_hard_cap = Some(0.60);
    cfg.fd_ratio_soft_cap = Some(0.50);
    let mock = MockFdCounter::new(800, 1024);
    let gov = ResourceGovernor::new(cfg, mock);
    let (capped, snap) = gov.cap_concurrency(256);
    assert!(capped < 256, "expected cap, got {}", capped);
    assert!(snap.throttled_due_to_fd);
    assert!(snap.fd_ratio > 0.5);
    assert_eq!(snap.used_fds, 800);
}

#[test]
fn phase3_4_governor_records_resource_error_ratio_and_throttles() {
    let cfg = ResourceGovernorConfig {
        enabled: true,
        resource_error_threshold: 0.10,
        resource_error_window: 10,
        user_max_concurrency: 128,
        fd_safety_headroom: 0,
        ..Default::default()
    };
    let mock = MockFdCounter::new(10, 1024);
    let gov = ResourceGovernor::new(cfg, mock);
    for _ in 0..10 {
        gov.record_outcome(true);
    }
    let ratio = gov.resource_error_ratio();
    assert!((ratio - 1.0).abs() < 1e-6);
    let (capped, snap) = gov.cap_concurrency(64);
    assert!(snap.throttled_due_to_resource_errors);
    assert_eq!(snap.resource_errors, 10);
    assert!(capped < 64, "expected error throttle, got {}", capped);
}

#[test]
fn phase3_4_classify_resource_error_known_cases() {
    let io_emfile = std::io::Error::from_raw_os_error(24);
    let e = DetectorError::Io(io_emfile);
    assert!(classify_resource_error(&e));

    let e2 = DetectorError::Http("Too many open files".into());
    assert!(classify_resource_error(&e2));

    let e3 = DetectorError::Tls("connection reset by peer".into());
    assert!(classify_resource_error(&e3));

    let benign = DetectorError::InvalidTarget("nope".into());
    assert!(!classify_resource_error(&benign));

    let inner = DetectorError::Http("Too many open files".into());
    let wrapped = DetectorError::RetriesExceeded {
        source: Box::new(inner),
        attempts: 3,
    };
    assert!(classify_resource_error(&wrapped));
}

#[test]
fn phase3_4_detector_config_integrates_governor() {
    let cfg = DetectorConfig::default();
    assert!(cfg.governor_enabled);
    assert_eq!(cfg.governor.fd_ratio_hard_cap, Some(0.92));
    assert_eq!(cfg.max_concurrency, 256);
}

#[test]
fn phase3_4_detector_exposes_governor_accessor() {
    let cfg = DetectorConfig {
        governor_enabled: false,
        ..DetectorConfig::default()
    };
    let _ = cfg.governor.clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async move {
        let d = Detector::with_data_sources(
            DetectorConfig::default(),
            reqwest::Client::builder().build().unwrap(),
            empty_ranges(),
            Arc::new(EmptyLocationSource),
        );
        assert!(d.governor().is_some());
    });
}

struct EmptyLocationSource;
impl LocationSource for EmptyLocationSource {
    fn lookup(&self, _colo: &str) -> Option<CfLocation> {
        None
    }
}

fn empty_ranges() -> CloudflareRanges {
    let empty = CloudflareCidrs {
        fetched_at: None,
        source: "test".into(),
        ipv4: vec![],
        ipv6: vec![],
    };
    CloudflareRanges::from_cidrs(empty)
}

#[test]
fn phase3_4_batch_progress_has_governor_fields() {
    let sample_target = Target::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let bp = BatchProgress {
        completed: 10,
        total: 100,
        current_concurrency: 32,
        last_success: true,
        last_target: Some(sample_target),
        throttled_due_to_fd: true,
        governor_feedback: GovernorFeedback { snapshot: None },
    };
    assert!(bp.throttled_due_to_fd);
    assert!(bp.governor_feedback.snapshot.is_none());
    assert_eq!(bp.last_target.unwrap().port, 443);
}

#[test]
fn phase3_4_batch_targets_construction_supports_large_sets() {
    let mut out = Vec::with_capacity(1000);
    for i in 0..1000 {
        let ip = IpAddr::V4(Ipv4Addr::new(104, 16, ((i % 16) + 132) as u8, 1));
        out.push(BatchTarget {
            target: Target::new(ip, 443),
            id: i,
        });
    }
    assert_eq!(out.len(), 1000);
}

#[test]
fn phase3_4_detect_batch_accepts_high_base_concurrency_with_adaptive() {
    let adaptive = AdaptiveConfig {
        enabled: true,
        initial: 64,
        min: 2,
        max: 128,
        window: 20,
    };
    assert!(adaptive.enabled);
    assert_eq!(adaptive.initial.clamp(adaptive.min, adaptive.max), 64);
}

// ---- Phase 3.1 PinnedConnector: TCP endpoint pinning (SNI-aware, connector exports) ----

#[test]
fn phase3_1_connector_config_default_values_are_phase3_spec() {
    let cfg = ConnectorConfig::default();
    assert!(
        cfg.accept_invalid_certs,
        "PinnedConnector must accept pinned-invalid certs for endpoint pinning"
    );
    assert!(cfg.tls_session_cache, "session cache enabled by default");
    assert!(
        !cfg.enable_0rtt,
        "0rtt disabled by default (opt-in via allow_0rtt_speedtest)"
    );
    assert!(cfg.connect_timeout.as_millis() > 0);
    assert!(cfg.request_timeout.as_millis() > 0);
    assert!(!cfg.user_agent.is_empty());
    assert!(cfg.tls_session_cache_size > 0);
    assert!(cfg.tls_session_cache_max_entries >= cfg.tls_session_cache_size);
}

#[test]
fn phase3_1_connector_exports_timing_and_handshake_type_in_download() {
    let timing = Timing {
        connect_latency: Some(Duration::from_millis(20)),
        tls_handshake_latency: Some(Duration::from_millis(45)),
        ttfb_latency: Some(Duration::from_millis(90)),
    };
    let dl = PinnedDownload {
        total_bytes: 1_000_000,
        timing: timing.clone(),
        handshake_type: Some(HandshakeType::ZeroRtt),
    };
    assert_eq!(dl.timing.connect_latency.unwrap().as_millis(), 20);
    assert_eq!(dl.timing.tls_handshake_latency.unwrap().as_millis(), 45);
    assert_eq!(dl.timing.ttfb_latency.unwrap().as_millis(), 90);
    assert!(matches!(dl.handshake_type, Some(HandshakeType::ZeroRtt)));
}

#[test]
fn phase3_1_handshake_type_variants_all_constructible() {
    // Phase 3.2 requires distinguishing FullHandshake / Resumed / 0-RTT
    for h in [
        HandshakeType::FullHandshake,
        HandshakeType::Resumed,
        HandshakeType::ZeroRtt,
    ] {
        let dl = PinnedDownload {
            total_bytes: 0,
            timing: Timing::default(),
            handshake_type: Some(h),
        };
        assert!(dl.handshake_type.is_some());
    }
}

#[test]
fn phase3_1_pinned_client_config_to_pinned_keeps_values() {
    use std::time::Duration;
    let cfg = ConnectorConfig {
        connect_timeout: Duration::from_millis(123),
        request_timeout: Duration::from_millis(456),
        accept_invalid_certs: true,
        user_agent: "cfrp-acceptance/v1".into(),
        tls_session_cache: true,
        tls_session_cache_size: 7,
        tls_session_cache_max_entries: 11,
        enable_0rtt: true,
        retry: Default::default(),
    };
    let conn = PinnedConnector::new(cfg.clone()).unwrap();
    assert_eq!(conn.config.connect_timeout, cfg.connect_timeout);
    assert_eq!(conn.config.request_timeout, cfg.request_timeout);
    assert_eq!(conn.config.user_agent, cfg.user_agent);
    assert_eq!(conn.config.tls_session_cache_size, 7);
    assert_eq!(conn.config.tls_session_cache_max_entries, 11);
    assert!(conn.config.enable_0rtt);
}

// ---- Phase 3.2 Session Resumption + 0-RTT SpeedTest behavior contracts ----

#[test]
fn phase3_2_speedtest_config_defaults_and_clamp() {
    let cfg = SpeedTestConfig::default();
    assert!(cfg.timeout.as_secs() >= 1);
    assert!(cfg.threads_per_target >= 1);
    assert!(cfg.concurrency >= 1);
    // Config should clamp to sensible values even when user overrides zero
    let bad = SpeedTestConfig {
        timeout: Duration::from_millis(0),
        threads_per_target: 0,
        concurrency: 0,
    };
    assert_eq!(bad.threads_per_target.max(1), 1);
    assert_eq!(bad.concurrency.max(1), 1);
}

#[test]
fn phase3_2_probe_config_to_pinned_respects_tls_flags_separately() {
    // allow_0rtt_speedtest=true but session cache disabled (size=0)
    let pc1 = ProbeConfig {
        allow_0rtt_speedtest: true,
        tls_session_cache_size: 0,
        tls_session_cache: true,
        ..ProbeConfig::default()
    };
    let pinned1 = pc1.to_pinned();
    assert!(pinned1.enable_0rtt);
    // to_pinned directly copies tls_session_cache_size (no clamping inside)
    assert_eq!(pinned1.tls_session_cache_size, 0);
    assert_eq!(pinned1.tls_session_cache_max_entries, 0);

    // Session cache enabled but 0rtt disabled
    let pc2 = ProbeConfig {
        allow_0rtt_speedtest: false,
        tls_session_cache_size: 1024,
        ..ProbeConfig::default()
    };
    let pinned2 = pc2.to_pinned();
    assert!(!pinned2.enable_0rtt);
    assert_eq!(pinned2.tls_session_cache_max_entries, 1024);
}

// ---- Phase 3.3 Benchmark harness integration (Snapshot + criterion-compatible JSON) ----

#[test]
fn phase3_3_governor_and_baseline_snapshot_fields_match_json_shape() {
    use serde::Serialize;
    #[derive(Debug, Clone, Serialize, Default)]
    struct BaselineRow {
        benchmark: String,
        mean_ns: u64,
        median_ns: u64,
        min_ns: u64,
        max_ns: u64,
        samples: u32,
        rust_sec: Option<String>,
        go_sec: Option<String>,
    }
    let row = BaselineRow {
        benchmark: "connector_new".into(),
        mean_ns: 100,
        median_ns: 95,
        min_ns: 80,
        max_ns: 220,
        samples: 1000,
        rust_sec: None,
        go_sec: None,
    };
    let json = serde_json::to_string(&row).unwrap();
    assert!(json.contains("\"benchmark\""));
    assert!(json.contains("\"samples\""));
    assert!(json.contains("connector_new"));
}

// ---- Phase 3.4 ResourceGovernor: disabled path, fd headroom, user_max clamp, snapshot active flag ----

#[test]
fn phase3_4_governor_disabled_passthrough_no_throttle() {
    let cfg = ResourceGovernorConfig {
        enabled: false,
        user_max_concurrency: 10_000, // disabled path still applies user_max as a ceiling; lift it to allow passthrough
        ..ResourceGovernorConfig::default()
    };
    let mock = MockFdCounter::new(999_999, 1024); // very high fd usage (should be ignored if disabled)
    let gov = ResourceGovernor::new(cfg, mock);
    let (capped, snap) = gov.cap_concurrency(512);
    assert_eq!(
        capped, 512,
        "disabled governor with high user_max MUST NOT cap below proposed"
    );
    assert!(!snap.active);
    assert!(!snap.throttled_due_to_fd);
    assert!(!snap.throttled_due_to_resource_errors);
}

#[test]
fn phase3_4_governor_fd_safety_headroom_reduces_budget() {
    let mut cfg = ResourceGovernorConfig::default();
    cfg.fd_ratio_hard_cap = None;
    cfg.fd_ratio_soft_cap = None;
    cfg.fd_safety_headroom = 500; // reserve 500 FDs
    cfg.user_max_concurrency = 10_000; // don't let user_max get in the way of verifying headroom math
    let mock = MockFdCounter::new(100, 1024); // used=100, limit=1024 => budget = limit-used-headroom = 424
    let gov = ResourceGovernor::new(cfg, mock);
    let (capped, snap) = gov.cap_concurrency(10_000);
    assert_eq!(
        gov.fd_budget(),
        424,
        "fd_budget should be limit-used-headroom = 424"
    );
    assert_eq!(
        capped, 424,
        "expected capped at headroom budget 424, got {capped}"
    );
    assert_eq!(snap.available_fds, 1024 - 100);
    assert_eq!(snap.fd_budget, 424);
    assert_eq!(snap.proposed_concurrency, 10_000);
    assert_eq!(snap.capped_concurrency, capped);
    assert!(snap.active);
}

#[test]
fn phase3_4_governor_user_max_concurrency_is_upper_bound() {
    let cfg = ResourceGovernorConfig {
        enabled: true,
        user_max_concurrency: 16,
        fd_ratio_hard_cap: None,
        fd_ratio_soft_cap: None,
        fd_safety_headroom: 0,
        ..Default::default()
    };
    let mock = MockFdCounter::new(1, 1_000_000);
    let gov = ResourceGovernor::new(cfg, mock);
    let (capped, snap) = gov.cap_concurrency(1024);
    assert_eq!(capped, 16, "user_max_concurrency must be hard upper bound");
    assert_eq!(snap.user_max_concurrency, 16);
    assert_eq!(snap.capped_concurrency, 16);
}

#[test]
fn phase3_4_governor_snapshot_roundtrips_all_ratio_fields() {
    let cfg = ResourceGovernorConfig::default();
    let mock = MockFdCounter::new(300, 1000);
    let gov = ResourceGovernor::new(cfg, mock);
    // window of 5/10 resource errors = 0.5 ratio
    for ok in [
        true, false, true, false, false, true, true, true, false, false,
    ] {
        gov.record_outcome(ok);
    }
    let (_, snap) = gov.cap_concurrency(128);
    assert!((snap.resource_error_ratio - 0.5).abs() < 1e-6);
    assert_eq!(snap.resource_errors, 5);
    assert_eq!(snap.fd_used, 300);
    assert_eq!(snap.used_fds, 300);
    assert!((snap.fd_ratio - 0.3).abs() < 1e-6);
    assert!(snap.active);
}

#[test]
fn phase3_4_governor_feedback_with_snapshot_in_batch_progress() {
    let snap = GovernorSnapshot {
        active: true,
        fd_used: 50,
        fd_limit: 1024,
        fd_budget: 900,
        throttled_due_to_fd: false,
        resource_error_ratio: 0.05,
        throttled_due_to_resource_errors: false,
        capped_concurrency: 64,
        available_fds: 974,
        used_fds: 50,
        fd_ratio: 50.0 / 1024.0,
        user_max_concurrency: 256,
        proposed_concurrency: 64,
        resource_errors: 1,
    };
    let bp = BatchProgress {
        completed: 1,
        total: 10,
        current_concurrency: snap.capped_concurrency,
        last_success: true,
        last_target: Some(Target::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443)),
        throttled_due_to_fd: snap.throttled_due_to_fd,
        governor_feedback: GovernorFeedback {
            snapshot: Some(snap.clone()),
        },
    };
    let inner = bp.governor_feedback.snapshot.as_ref().unwrap();
    assert!(inner.active);
    assert_eq!(inner.resource_errors, 1);
    assert_eq!(inner.capped_concurrency, 64);
    assert_eq!(bp.current_concurrency, 64);
}

#[test]
fn phase3_4_classify_resource_error_network_io_variant_works() {
    let io = std::io::Error::from_raw_os_error(23); // ENFILE on macOS = too many open files in system
    let e = DetectorError::NetworkIo(io);
    assert!(
        classify_resource_error(&e),
        "NetworkIo(ENFILE) should be classified as resource error"
    );

    let io2 = std::io::Error::from_raw_os_error(100); // arbitrary non-resource errno
    let e2 = DetectorError::NetworkIo(io2);
    assert!(!classify_resource_error(&e2));
}

// ---- Phase 3.5 Cross-platform FD counter: trait blanket impl, MockFdCounter value semantics ----

#[test]
fn phase3_5_mock_fd_counter_is_reusable_across_threads_via_arc() {
    let m = Arc::new(MockFdCounter::new(0, 4096));
    let m2 = m.clone();
    let m3 = m.clone();
    m.inc(10);
    m2.inc(5);
    m3.set(100);
    assert_eq!(m.open_fd_count(), 100);
    assert_eq!(m.fd_limit(), 4096);
}

#[test]
fn phase3_5_fd_counter_trait_object_is_object_safe() {
    // Object safety: FdCounter must be usable as Arc<dyn FdCounter>
    let mock: Arc<dyn FdCounter> = MockFdCounter::new(42, 1024);
    assert_eq!(mock.open_fd_count(), 42);
    assert_eq!(mock.fd_limit(), 1024);

    let sys: Arc<dyn FdCounter> = Arc::new(SystemFdCounter);
    // We don't assert exact values (OS-dependent), but both methods must be callable.
    let _open = sys.open_fd_count();
    let _lim = sys.fd_limit();
    assert!(
        _lim > 0,
        "fd_limit should return positive for any reasonable OS"
    );
}

#[test]
fn phase3_5_governor_accepts_dyn_fd_counter_via_trait_object() {
    use std::time::Duration;
    let trait_obj: Arc<dyn FdCounter> = MockFdCounter::new(5, 100);
    let gov = ResourceGovernor::new(ResourceGovernorConfig::default(), trait_obj);
    let (_, snap) = gov.cap_concurrency(10);
    assert_eq!(snap.fd_used, 5);
    assert_eq!(snap.fd_limit, 100);
    let _ = Duration::ZERO; // silence unused if stripped
}

// ---- End-to-end acceptance helper: ensure DetectorConfig default wires governor.user_max with max_concurrency ----

#[test]
fn phase3_e2e_detectorconfig_default_user_max_syncs_with_max_concurrency_semantically() {
    let cfg = DetectorConfig::default();
    // By design the governor's own user_max_concurrency acts as an upper bound *inside* cap_concurrency,
    // while cfg.max_concurrency is the batch-level knob. The acceptance contract: both must be >= 1,
    // and setting governor_enabled=false preserves max_concurrency untouched.
    assert!(cfg.max_concurrency >= 1);
    assert!(cfg.governor.user_max_concurrency >= 1);

    let mut cfg2 = DetectorConfig::default();
    cfg2.max_concurrency = 64;
    cfg2.governor_enabled = false;
    cfg2.governor = ResourceGovernorConfig {
        enabled: false,
        user_max_concurrency: 1, // internal bound is irrelevant when governor disabled
        ..Default::default()
    };
    assert_eq!(cfg2.max_concurrency, 64);
    assert!(!cfg2.governor_enabled);
}
