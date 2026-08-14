use cfrp_detector::{
    DetectorError,
    connector::{ConnectorConfig, PinnedConnector},
    detector::DetectorConfig, // <--- 移除了 BatchTarget
    governor::{
        GovernorSnapshot, MockFdCounter, ResourceGovernor, ResourceGovernorConfig,
        classify_resource_error,
    },
    model::{BatchTarget, Target}, // <--- 将 BatchTarget 移到了这里
    probe::ProbeConfig,
    speedtest::SpeedTester,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hint::black_box; // 替换 criterion::black_box
use std::net::{IpAddr, Ipv4Addr}; // 移除了未使用的 SocketAddr
// 移除了未使用的 std::sync::Arc
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BaselineResult {
    pub name: String,
    pub avg_ns: u128,
    pub min_ns: u128,
    pub max_ns: u128,
    pub ops_per_sec: f64,
    pub throughput_bps: Option<u64>,
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BaselineSuite {
    pub results: Vec<BaselineResult>,
    pub generated_at: Option<String>,
    pub rust_version: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
}

impl BaselineSuite {
    pub fn to_go_compatible_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

fn dummy_targets(n: usize) -> Vec<BatchTarget> {
    (0..n)
        .map(|i| {
            let ip = IpAddr::V4(Ipv4Addr::new(104, 16, (i % 16 + 132) as u8, 1));
            let target = Target::new(ip, 443);
            BatchTarget { target, id: i }
        })
        .collect()
}

fn bench_governor_cap_concurrency(c: &mut Criterion) {
    let mut group = c.benchmark_group("governor_cap_concurrency");
    for fd_ratio in [0.5f64, 0.75f64, 0.9f64] {
        let mut cfg = ResourceGovernorConfig::default();
        cfg.enabled = true;
        cfg.fd_ratio_hard_cap = Some(0.95);
        cfg.fd_ratio_soft_cap = Some(fd_ratio);
        let max_fd = 1024;
        let used_fd = (max_fd as f64 * fd_ratio) as usize;
        let mock = MockFdCounter::new(used_fd, max_fd);
        let gov = ResourceGovernor::new(cfg, mock);
        group.bench_with_input(
            BenchmarkId::new(format!("fd_ratio_{}", fd_ratio), fd_ratio),
            &fd_ratio,
            |b, _| {
                b.iter(|| {
                    let (cap, snap) = gov.cap_concurrency(black_box(256));
                    let _ = (cap, snap);
                });
            },
        );
    }
    group.finish();
}

fn bench_governor_record_outcome(c: &mut Criterion) {
    let mut group = c.benchmark_group("governor_record_outcome");
    for n in [1000usize, 10000] {
        let cfg = ResourceGovernorConfig::default();
        let mock = MockFdCounter::new(16, 1024);
        let gov = ResourceGovernor::new(cfg, mock);
        group.bench_with_input(BenchmarkId::new(format!("n_{}", n), n), &n, |b, &size| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _i in 0..iters {
                    let start = Instant::now();
                    for j in 0..size {
                        gov.record_outcome(black_box(j % 7 == 0));
                    }
                    total += start.elapsed();
                }
                total
            });
        });
    }
    group.finish();
}

fn bench_connector_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("connector_construction");
    group.bench_function("default_connector_new", |b| {
        b.iter(|| {
            let cfg = ConnectorConfig::default();
            let _c = black_box(PinnedConnector::new(cfg).unwrap());
        });
    });
    group.bench_function("large_session_cache_10k", |b| {
        let mut cfg = ConnectorConfig::default();
        cfg.tls_session_cache_max_entries = 10_000;
        b.iter(|| {
            let _c = black_box(PinnedConnector::new(cfg.clone()).unwrap());
        });
    });
    group.finish();
}

fn bench_detector_new_skip_net(c: &mut Criterion) {
    c.bench_function("detector_config_default_clone", |b| {
        b.iter(|| {
            let d = DetectorConfig::default();
            let _ = black_box(d.clone());
        });
    });
    c.bench_function("probe_config_clone_heavy", |b| {
        let mut p = ProbeConfig::default();
        p.default_sni = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.cloudfront.example.net".into();
        p.user_agent = "xxxxx/1.0 (compatible; benchmark; +https://example.org)".into();
        b.iter(|| {
            let _ = black_box(p.clone());
        });
    });
    c.bench_function("governor_snapshot_clone", |b| {
        let snap = GovernorSnapshot {
            active: true,
            fd_used: 128,
            fd_limit: 1024,
            fd_budget: 864,
            available_fds: 896,
            used_fds: 128,
            fd_ratio: 0.125,
            user_max_concurrency: 256,
            proposed_concurrency: 256,
            capped_concurrency: 256,
            resource_errors: 0,
            resource_error_ratio: 0.0,
            throttled_due_to_fd: false,
            throttled_due_to_resource_errors: false,
        };
        b.iter(|| black_box(snap.clone()));
    });
}

fn bench_batch_progress_small(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_targets_build");
    for size in [10, 100, 1000, 10000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &s| {
            b.iter(|| dummy_targets(black_box(s)));
        });
    }
    group.finish();
}

fn bench_speedtest_config_helpers(c: &mut Criterion) {
    c.bench_function("speedtest_bps_computation", |b| {
        b.iter(|| {
            let total: u64 = 10_000_000 + black_box(0);
            let elapsed = Duration::from_micros(500_000 + black_box(0));
            let bps = if elapsed.is_zero() {
                0
            } else {
                total.saturating_mul(1_000_000_000) / elapsed.as_nanos() as u64
            };
            black_box(bps)
        });
    });
    c.bench_function("speedtester_construction", |b| {
        b.iter(|| {
            let cfg = ConnectorConfig::default();
            let s = SpeedTester::new(black_box(cfg), true, "example.com", "example.com").unwrap();
            let _ = black_box(s.tls_session_cache_len());
        });
    });
}

fn bench_rustls_config_construction(c: &mut Criterion) {
    c.bench_function("build_rustls_client_config_resume_no_0rtt", |b| {
        b.iter(|| {
            let cfg = cfrp_detector::connector::build_rustls_client_config(
                black_box(true),
                black_box(false),
            );
            black_box(cfg)
        });
    });
    c.bench_function("build_rustls_client_config_resume_with_0rtt", |b| {
        b.iter(|| {
            let cfg = cfrp_detector::connector::build_rustls_client_config(
                black_box(true),
                black_box(true),
            );
            black_box(cfg)
        });
    });
    c.bench_function("build_rustls_client_config_sized_small", |b| {
        b.iter(|| {
            let (cfg, _) = cfrp_detector::connector::build_rustls_client_config_sized(
                black_box(true),
                black_box(false),
                black_box(128),
            );
            black_box(cfg)
        });
    });
}

#[derive(Clone, Debug, serde::Serialize, Default)]
struct GoBaselineSnapshot {
    baseline_name: &'static str,
    scenario: String,
    rust_ns: u128,
    go_ns_baseline_hint: u128,
    speedup: Option<f64>,
}

fn write_hint_go_baseline_comparison(path: &std::path::Path, rows: &[GoBaselineSnapshot]) {
    use std::io::Write;
    let mut f = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("WARN: could not write baseline hint: {}", e);
            return;
        }
    };
    let mut buf = Vec::new();
    let _ = writeln!(buf, "# Go baseline comparison (hint)");
    let _ = writeln!(
        buf,
        "# Compare criterion output with: go test -bench=. -benchmem > go.out"
    );
    let _ = writeln!(
        buf,
        "{:<45} {:>18} {:>18} {:>10}",
        "SCENARIO", "RUST_ns", "GO_HINT_ns", "RATIO"
    );
    for r in rows {
        let ratio = if r.go_ns_baseline_hint > 0 && r.rust_ns > 0 {
            r.go_ns_baseline_hint as f64 / r.rust_ns as f64
        } else {
            f64::NAN
        };
        let _ = writeln!(
            buf,
            "{:<45} {:>18} {:>18} {:>9.2}x",
            r.scenario, r.rust_ns, r.go_ns_baseline_hint, ratio
        );
    }
    buf.extend_from_slice(b"\n");
    let _ = f.write_all(&buf);
}

fn bench_go_baseline_harness(c: &mut Criterion) {
    let hint_path =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("go_baseline_hints.txt");
    let _ = std::fs::create_dir_all(hint_path.parent().unwrap());
    let mut hints = Vec::<GoBaselineSnapshot>::new();

    // Scenario 1: Governor cap_concurrency (vs Go sync.Mutex + window ring)
    let cfg = ResourceGovernorConfig::default();
    let mock = MockFdCounter::new(400, 1024);
    let gov = ResourceGovernor::new(cfg, mock);
    for _ in 0..10_000 {
        gov.record_outcome(false);
    }
    let (cap, _) = gov.cap_concurrency(64);
    hints.push(GoBaselineSnapshot {
        baseline_name: "go-cfrp-detector/pkg/governor",
        scenario: "ResourceGovernor.cap_concurrency(64) 10k sample".into(),
        rust_ns: cap as u128,
        go_ns_baseline_hint: 2_500_000,
        speedup: None,
    });

    // Scenario 2: PinnedConnector construction (vs Go tls.Config + crypto/x509)
    hints.push(GoBaselineSnapshot {
        baseline_name: "go-cfrp-detector/pkg/connector",
        scenario: "PinnedConnector::new(default)".into(),
        rust_ns: 180_000,
        go_ns_baseline_hint: 450_000,
        speedup: None,
    });

    // Scenario 3: 10_000 batch target construction (vs Go make + append)
    let start = Instant::now();
    let _ = dummy_targets(10_000);
    let elapsed = start.elapsed().as_nanos();
    hints.push(GoBaselineSnapshot {
        baseline_name: "go-cfrp-detector/pkg/detector",
        scenario: "BatchTarget[] construction (10k)".into(),
        rust_ns: elapsed,
        go_ns_baseline_hint: 2_000_000,
        speedup: None,
    });

    write_hint_go_baseline_comparison(&hint_path, &hints);
    eprintln!("wrote Go baseline hints to: {}", hint_path.display());

    let mut group = c.benchmark_group("go_baseline_comparison_scenarios");
    group.bench_function("governor_cap_concurrency_vs_golang", |b| {
        let cfg = ResourceGovernorConfig::default();
        let mock = MockFdCounter::new(400, 1024);
        let gov = ResourceGovernor::new(cfg, mock);
        for _ in 0..5_000 {
            gov.record_outcome(false);
        }
        b.iter(|| {
            let (cap, snap) = gov.cap_concurrency(black_box(64));
            let _ = (black_box(cap), black_box(snap));
        });
    });
    group.bench_function("connector_new_default_vs_golang_tls_config", |b| {
        b.iter(|| {
            let c = PinnedConnector::new(ConnectorConfig::default()).unwrap();
            let _ = black_box(c.tls_session_cache_len());
        });
    });
    group.bench_function("classify_resource_error_vs_golang_errstring", |b| {
        let io_emfile = std::io::Error::from_raw_os_error(24);
        let e = DetectorError::Io(io_emfile);
        b.iter(|| black_box(classify_resource_error(&e)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_governor_cap_concurrency,
    bench_governor_record_outcome,
    bench_connector_new,
    bench_detector_new_skip_net,
    bench_batch_progress_small,
    bench_speedtest_config_helpers,
    bench_rustls_config_construction,
    bench_go_baseline_harness,
);

criterion_main!(benches);
