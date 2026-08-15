//! ResourceGovernor — FD and OS resource aware concurrency governor.
//!
//! This module implements Phase 3.4. It extends the simple success-rate-based
//! adaptive concurrency in `Detector` with three additional constraints:
//!
//! 1. User / configuration `max_concurrency` (already present).
//! 2. Process-level FD headroom: `rlimit_nofile - current_open_fds - safety_headroom`.
//! 3. Sliding-window ratio of resource-class errors (EMFILE / ENFILE / ECONNRESET ...).
//!
//! Cross-platform FD counting is abstracted through `FdCounter` trait so tests
//! can drive the governor with synthetic sequences (e.g. "FD approaching
//! ceiling → concurrency drops → FD releases → concurrency recovers").

use crate::DetectorError;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Classification tags for the governor's "resource class" diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// File-descriptor pressure: too many sockets open simultaneously.
    Fd,
    /// Kernel accept-backlog pressure (socket queue overflow, `ECONNRESET` bursts).
    Backlog,
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceKind::Fd => write!(f, "fd"),
            ResourceKind::Backlog => write!(f, "backlog"),
        }
    }
}

/// Pluggable file-descriptor meter. The default [`SystemFdCounter`] reads `/proc/self/fd`
/// (Linux) or `/dev/fd` (macOS); tests can inject [`MockFdCounter`] to drive synthetic
/// FD-pressure scenarios deterministically.
pub trait FdCounter: Send + Sync {
    /// Number of file descriptors *currently* open by the process.
    fn open_fd_count(&self) -> usize;
    /// Soft limit on open file descriptors (`RLIMIT_NOFILE` / rlimit equivalent).
    fn fd_limit(&self) -> usize;
}

/// Default production [`FdCounter`] implementation using OS-level fd directories.
pub struct SystemFdCounter;

#[cfg(target_os = "linux")]
impl FdCounter for SystemFdCounter {
    fn open_fd_count(&self) -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    fn fd_limit(&self) -> usize {
        rlimit_nofile_soft().unwrap_or(1024)
    }
}

#[cfg(target_os = "macos")]
impl FdCounter for SystemFdCounter {
    fn open_fd_count(&self) -> usize {
        std::fs::read_dir("/dev/fd")
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    fn fd_limit(&self) -> usize {
        rlimit_nofile_soft().unwrap_or(256)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl FdCounter for SystemFdCounter {
    fn open_fd_count(&self) -> usize {
        0
    }
    fn fd_limit(&self) -> usize {
        512
    }
}

fn rlimit_nofile_soft() -> Option<usize> {
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            Some(rlim.rlim_cur as usize)
        } else {
            None
        }
    }
}

/// Default safety margin (in FDs) kept in hand so we never starve logging, files, etc.
pub const DEFAULT_SAFETY_HEADROOM: usize = 32;
/// Resource errors in the sliding window exceeding this ratio halve proposed concurrency.
pub const DEFAULT_RESOURCE_ERROR_THRESHOLD: f64 = 0.10;
/// Outcome samples retained in the sliding error window (time-proportional).
pub const DEFAULT_RESOURCE_WINDOW: usize = 50;
/// FD sampling rate; samples cached for this long to avoid hammering `/proc/self/fd`.
pub const DEFAULT_RESOURCE_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// Tunables for [`ResourceGovernor`]: on/off, headroom, caps, error thresholds, polling.
#[derive(Debug, Clone)]
pub struct ResourceGovernorConfig {
    /// When `false` the governor simply clamps to `user_max_concurrency` — no FD logic runs.
    pub enabled: bool,
    /// FDs reserved for non-network use (log files, temp files, internal channels…).
    pub fd_safety_headroom: usize,
    /// Fraction of recent errors that must be resource-class to trigger throttling (0..1).
    pub resource_error_threshold: f64,
    /// How many of the most recent outcomes are kept for ratio calculation.
    pub resource_error_window: usize,
    /// Minimum time between two actual OS fd-count samples.
    pub resource_sample_interval: Duration,
    /// User-visible concurrency ceiling (the governor never exceeds this value).
    pub user_max_concurrency: usize,
    /// Optional hard FD-ratio threshold; ratios above this aggressively throttle to 25%.
    pub fd_ratio_hard_cap: Option<f64>,
    /// Optional soft FD-ratio threshold; ratios above this linearly reduce concurrency.
    pub fd_ratio_soft_cap: Option<f64>,
}

impl Default for ResourceGovernorConfig {
    /// Defaults: enabled, 32 FDs headroom, 10% error threshold, 256 user max, 0.8 soft / 0.92 hard caps.
    fn default() -> Self {
        Self {
            enabled: true,
            fd_safety_headroom: DEFAULT_SAFETY_HEADROOM,
            resource_error_threshold: DEFAULT_RESOURCE_ERROR_THRESHOLD,
            resource_error_window: DEFAULT_RESOURCE_WINDOW,
            resource_sample_interval: DEFAULT_RESOURCE_SAMPLE_INTERVAL,
            user_max_concurrency: 256,
            fd_ratio_hard_cap: Some(0.92),
            fd_ratio_soft_cap: Some(0.80),
        }
    }
}

/// Debug / metrics snapshot produced by [`ResourceGovernor::cap_concurrency`]. Can be
/// serialised to JSON or logged to the tracing pipeline to observe the governor in
/// production without exposing internal mutex state directly.
#[derive(Debug, Clone, Default)]
pub struct GovernorSnapshot {
    /// `false` when the governor was disabled via config.
    pub active: bool,
    /// Open FD count at sample time.
    pub fd_used: usize,
    /// OS `RLIMIT_NOFILE` soft limit.
    pub fd_limit: usize,
    /// `fd_limit - fd_used - headroom`, saturated into a usable budget.
    pub fd_budget: usize,
    /// `true` when we reduced concurrency *because* of fd headroom / ratio limits.
    pub throttled_due_to_fd: bool,
    /// 0..1 fraction of recent outcomes flagged by [`classify_resource_error`].
    pub resource_error_ratio: f64,
    /// `true` when we halved concurrency because the error ratio crossed the threshold.
    pub throttled_due_to_resource_errors: bool,
    /// Final concurrency value after applying all governor constraints.
    pub capped_concurrency: usize,
    /// Convenience: `fd_limit - fd_used` (raw headroom, before applying safety margin).
    pub available_fds: usize,
    /// Alias of `fd_used` for downstream JSON consumers.
    pub used_fds: usize,
    /// fd_used / fd_limit (0..1).
    pub fd_ratio: f64,
    /// Echo of the user-visible cap for log correlation.
    pub user_max_concurrency: usize,
    /// Concurrency the caller *wanted* before the governor clamped it.
    pub proposed_concurrency: usize,
    /// Absolute count of resource-class errors inside the current sliding window.
    pub resource_errors: usize,
}

/// FD + error-aware concurrency limiter. Designed to be cheap to clone / share via [`Arc`]
/// and polled on every scheduling decision from the detector's worker loop.
pub struct ResourceGovernor {
    config: ResourceGovernorConfig,
    fd_counter: Arc<dyn FdCounter>,
    error_window: Mutex<VecDeque<(Instant, bool)>>,
    last_sample: Mutex<Option<(Instant, usize)>>,
}

impl ResourceGovernor {
    /// Creates a new governor. `fd_counter` is typically [`SystemFdCounter`] in production
    /// or [`MockFdCounter`] when writing unit tests.
    pub fn new(config: ResourceGovernorConfig, fd_counter: Arc<dyn FdCounter>) -> Self {
        let error_window_capacity = config.resource_error_window.max(1);
        Self {
            config,
            fd_counter,
            error_window: Mutex::new(VecDeque::with_capacity(error_window_capacity)),
            last_sample: Mutex::new(None),
        }
    }

    /// Computes the remaining FD budget: `limit − current_open − safety_headroom`,
    /// saturating at 1 so workers never fully stall. Samples the live FD counter only
    /// once every `resource_sample_interval` to keep the call O(1) on hot paths.
    pub fn fd_budget(&self) -> usize {
        if !self.config.enabled {
            return self.config.user_max_concurrency;
        }
        let limit = self.fd_counter.fd_limit();
        let now = Instant::now();
        let used = {
            let mut last = self.last_sample.lock();

            match *last {
                Some((t, v)) if now.duration_since(t) < self.config.resource_sample_interval => v,
                _ => {
                    let v = self.fd_counter.open_fd_count();
                    *last = Some((now, v));
                    v
                }
            }
        };
        let headroom = self.config.fd_safety_headroom;
        let budget = limit.saturating_sub(used).saturating_sub(headroom);
        budget.min(self.config.user_max_concurrency).max(1)
    }

    /// Appends one result entry into the sliding error window. Callers should pass
    /// `classify_resource_error(&err)` as the boolean so the ratio reflects OS-level
    /// pressure signals only (not 4xx HTTP responses or genuine Cloudflare negatives).
    pub fn record_outcome(&self, is_resource_error: bool) {
        if !self.config.enabled {
            return;
        }
        let now = Instant::now();
        let cap = self.config.resource_error_window.max(1);
        let mut w = self.error_window.lock();
        w.push_back((now, is_resource_error));
        while w.len() > cap {
            w.pop_front();
        }
    }

    /// Returns the current resource-error ratio (0..1) of the window; 0.0 when no samples yet.
    pub fn resource_error_ratio(&self) -> f64 {
        let w = self.error_window.lock();
        let n = w.len();
        if n == 0 {
            return 0.0;
        }
        let errs = w.iter().filter(|(_, e)| *e).count();
        errs as f64 / n as f64
    }

    /// Applies every constraint (user cap → fd budget → soft/hard fd-ratio caps → error-ratio
    /// halving) to `proposed`, returning the safe concurrency *and* a full metrics snapshot
    /// for logging / debugging. Guaranteed to return ≥ 1 so workers never stall.
    pub fn cap_concurrency(&self, proposed: usize) -> (usize, GovernorSnapshot) {
        if !self.config.enabled {
            let capped = proposed.min(self.config.user_max_concurrency).max(1);
            return (
                capped,
                GovernorSnapshot {
                    active: false,
                    capped_concurrency: capped,
                    proposed_concurrency: proposed,
                    user_max_concurrency: self.config.user_max_concurrency,
                    ..Default::default()
                },
            );
        }
        let fd_budget = self.fd_budget();
        let fd_used = self.fd_counter.open_fd_count();
        let fd_limit = self.fd_counter.fd_limit();
        let fd_ratio = if fd_limit == 0 {
            0.0
        } else {
            fd_used as f64 / fd_limit as f64
        };
        let error_ratio = self.resource_error_ratio();
        let mut capped = proposed
            .min(fd_budget)
            .min(self.config.user_max_concurrency);
        let mut throttled_due_to_fd = capped < proposed;

        if let Some(hard) = self.config.fd_ratio_hard_cap
            && fd_ratio >= hard
        {
            let reduced = (fd_limit.saturating_sub(fd_used) as f64 * 0.25).floor() as usize;
            let reduced = reduced.max(1);
            if reduced < capped {
                capped = reduced;
                throttled_due_to_fd = true;
            }
        }
        if let Some(soft) = self.config.fd_ratio_soft_cap
            && fd_ratio >= soft
        {
            let factor = (1.0 - (fd_ratio - soft) / (1.0 - soft)).max(0.25);
            let reduced = (capped as f64 * factor).floor() as usize;
            let reduced = reduced.max(1);
            if reduced < capped {
                capped = reduced;
                throttled_due_to_fd = true;
            }
        }

        let mut throttled_due_to_res_errors = false;
        if error_ratio > self.config.resource_error_threshold {
            let reduced = (capped as f64 * 0.5).floor() as usize;
            let reduced = reduced.max(1);
            if reduced < capped {
                capped = reduced;
                throttled_due_to_res_errors = true;
            }
        }

        capped = capped.max(1);
        let snap = GovernorSnapshot {
            active: true,
            fd_used,
            fd_limit,
            fd_budget,
            throttled_due_to_fd,
            resource_error_ratio: error_ratio,
            throttled_due_to_resource_errors: throttled_due_to_res_errors,
            capped_concurrency: capped,
            available_fds: fd_limit.saturating_sub(fd_used),
            used_fds: fd_used,
            fd_ratio,
            user_max_concurrency: self.config.user_max_concurrency,
            proposed_concurrency: proposed,
            resource_errors: self.error_window.lock().iter().filter(|(_, e)| *e).count(),
        };
        (capped, snap)
    }
}

/// Recursively classifies a [`DetectorError`] as "resource class" or not. Resource-class
/// errors include EMFILE / ENFILE (fd exhaustion), ECONNRESET / EPIPE (accept-backlog
/// overflow), EADDRINUSE (ephemeral-port starvation) and similar transient OS-level
/// signals. Pure application failures like HTTP 403 or TLS-alert-level errors return
/// `false` because backing off concurrency would not help.
pub fn classify_resource_error(err: &DetectorError) -> bool {
    match err {
        DetectorError::Network(rw_err) => {
            if rw_err.is_timeout() {
                return false;
            }
            if rw_err.is_connect() || rw_err.is_request() {
                let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(rw_err);
                while let Some(e) = cause {
                    if let Some(io_src) = e.downcast_ref::<std::io::Error>()
                        && matches_io_resource_kind(io_src)
                    {
                        return true;
                    }
                    cause = e.source();
                }
            }
            let msg = rw_err.to_string();
            msg.contains("Too many open files")
                || msg.contains("EMFILE")
                || msg.contains("ENFILE")
                || msg.contains("connection reset")
                || msg.contains("broken pipe")
        }
        DetectorError::NetworkIo(io_err) => matches_io_resource_kind(io_err),
        DetectorError::Http(msg) => {
            msg.contains("Too many open files")
                || msg.contains("EMFILE")
                || msg.contains("ENFILE")
                || msg.contains("timed out")
                || msg.contains("semaphore closed")
        }
        DetectorError::Tls(msg) => {
            msg.contains("open files")
                || msg.contains("EMFILE")
                || msg.contains("connection reset")
                || msg.contains("timed out")
        }
        DetectorError::Io(io_err) => matches_io_resource_kind(io_err),
        DetectorError::RetriesExceeded { source, .. } => classify_resource_error(source),
        _ => false,
    }
}

fn matches_io_resource_kind(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        WouldBlock | AddrNotAvailable | BrokenPipe | OutOfMemory
    ) || {
        let raw_os = e.raw_os_error().unwrap_or(0);
        matches_os_resource(raw_os)
    }
}

fn matches_os_resource(code: i32) -> bool {
    const EMFILE: i32 = 24;
    const ENFILE: i32 = 23;
    const ECONNRESET: i32 = 104;
    const EADDRINUSE: i32 = 98;
    const EADDRNOTAVAIL: i32 = 99;
    const ENOTCONN: i32 = 107;
    matches!(
        code,
        EMFILE | ENFILE | ECONNRESET | EADDRINUSE | EADDRNOTAVAIL | ENOTCONN
    )
}

/// Deterministic [`FdCounter`] for tests. Exposes a shared mutable used-count plus a
/// fixed limit; unit tests call [`set`](Self::set) / [`inc`](Self::inc) to drive the
/// governor through specific FD-pressure regimes without needing root or real sockets.
pub struct MockFdCounter {
    /// Exposed live "used" counter. Tests may hold the lock to freeze reads if needed.
    pub used: parking_lot::Mutex<usize>,
    /// Fixed FD limit reported by [`FdCounter::fd_limit`].
    pub limit: usize,
}

impl MockFdCounter {
    /// Wraps a fresh mock counter inside an [`Arc`], ready to hand to [`ResourceGovernor::new`].
    pub fn new(initial_used: usize, limit: usize) -> Arc<Self> {
        Arc::new(Self {
            used: parking_lot::Mutex::new(initial_used),
            limit,
        })
    }
    /// Overwrites the used counter with an absolute value.
    pub fn set(&self, used: usize) {
        *self.used.lock() = used;
    }
    /// Increments (positive `delta`) or decrements (negative `delta`) the used counter,
    /// saturating at zero on the low side to avoid underflow.
    pub fn inc(&self, delta: isize) {
        let mut guard = self.used.lock();
        if delta >= 0 {
            *guard = guard.saturating_add(delta as usize);
        } else {
            *guard = guard.saturating_sub((-delta) as usize);
        }
    }
}

impl FdCounter for MockFdCounter {
    fn open_fd_count(&self) -> usize {
        *self.used.lock()
    }
    fn fd_limit(&self) -> usize {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_kind_display_works() {
        assert_eq!(ResourceKind::Fd.to_string(), "fd");
        assert_eq!(ResourceKind::Backlog.to_string(), "backlog");
    }

    #[test]
    fn governor_default_config_sane() {
        let cfg = ResourceGovernorConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.fd_safety_headroom, DEFAULT_SAFETY_HEADROOM);
        assert!((cfg.resource_error_threshold - 0.10).abs() < 1e-9);
    }

    #[test]
    fn governor_disabled_passes_user_through() {
        let mock = MockFdCounter::new(10_000, 128);
        let cfg = ResourceGovernorConfig {
            enabled: false,
            user_max_concurrency: 64,
            ..Default::default()
        };
        let gov = ResourceGovernor::new(cfg, mock);
        let (capped, snap) = gov.cap_concurrency(usize::MAX);
        assert_eq!(capped, 64);
        assert!(!snap.active);
    }

    #[test]
    fn fd_budget_respects_headroom() {
        let mock = MockFdCounter::new(60, 128);
        let cfg = ResourceGovernorConfig {
            enabled: true,
            fd_safety_headroom: 32,
            user_max_concurrency: 256,
            ..Default::default()
        };
        let gov = ResourceGovernor::new(cfg, mock);
        assert_eq!(gov.fd_budget(), 128 - 60 - 32);
    }

    #[test]
    fn fd_budget_saturates_to_1() {
        let mock = MockFdCounter::new(10_000, 128);
        let cfg = ResourceGovernorConfig {
            enabled: true,
            fd_safety_headroom: 1,
            user_max_concurrency: 256,
            ..Default::default()
        };
        let gov = ResourceGovernor::new(cfg, mock);
        assert!(gov.fd_budget() >= 1);
    }

    #[test]
    fn governor_throttles_on_fd_pressure() {
        let mock = MockFdCounter::new(110, 128);
        let cfg = ResourceGovernorConfig {
            enabled: true,
            fd_safety_headroom: 10,
            user_max_concurrency: 256,
            ..Default::default()
        };
        let gov = ResourceGovernor::new(cfg, mock);
        let (capped, snap) = gov.cap_concurrency(128);
        assert!(capped < 128, "expected FD throttle, got {}", capped);
        assert!(snap.throttled_due_to_fd);
    }

    #[test]
    fn governor_throttles_on_resource_error_ratio() {
        let mock = MockFdCounter::new(10, 128);
        let cfg = ResourceGovernorConfig {
            enabled: true,
            fd_safety_headroom: 10,
            resource_error_threshold: 0.10,
            resource_error_window: 10,
            user_max_concurrency: 256,
            ..Default::default()
        };
        let gov = ResourceGovernor::new(cfg, mock);
        for _ in 0..6 {
            gov.record_outcome(true);
        }
        for _ in 0..4 {
            gov.record_outcome(false);
        }
        assert!(gov.resource_error_ratio() > 0.10);
        let (capped, snap) = gov.cap_concurrency(100);
        assert!(
            snap.throttled_due_to_resource_errors,
            "expected resource error throttle, snap={:?}",
            snap
        );
        assert!(capped < 100);
        assert!(capped >= 1);
    }

    #[test]
    fn resource_error_classify_emfile_like() {
        let io = std::io::Error::from_raw_os_error(24);
        let err = DetectorError::NetworkIo(io);
        assert!(classify_resource_error(&err));
    }

    #[test]
    fn resource_error_does_not_classify_normal_error() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err = DetectorError::NetworkIo(io);
        assert!(!classify_resource_error(&err));
    }

    #[test]
    fn mock_fd_counter_increments_and_decrements() {
        let m = MockFdCounter::new(10, 128);
        m.inc(5);
        assert_eq!(m.open_fd_count(), 15);
        m.inc(-20);
        assert_eq!(m.open_fd_count(), 0);
        m.set(100);
        assert_eq!(m.open_fd_count(), 100);
    }

    #[test]
    fn snapshot_defaults_are_all_off() {
        let s = GovernorSnapshot::default();
        assert!(!s.active);
        assert_eq!(s.fd_used, 0);
        assert_eq!(s.capped_concurrency, 0);
    }
}
