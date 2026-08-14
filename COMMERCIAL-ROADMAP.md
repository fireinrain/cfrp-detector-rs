# Commercial implementation roadmap

## Phase 1 — completed in this delivery
- workspace + library + CLI separation
- typed IP/port/domain models
- official Cloudflare IPv4/IPv6 CIDR loading
- local TTL cache
- Cloudflare colo metadata loading
- bounded asynchronous detection
- deterministic batch result ordering
- HTTPS SNI-safe probing through per-target resolver pinning
- JSON output foundation
- unit tests for CIDR membership and IPv6 formatting

## Phase 2 — compatibility
- exact Go CLI input grammar compatibility
- TXT/CSV/JSON export parity
- progress reporting
- adaptive concurrency
- full speedtest API parity
- fast one-shot detector

## Phase 3 — performance
- custom DNS/connector abstraction with connection pooling
- direct IP pinning for speedtest while preserving SNI
- reusable TLS sessions where safe
- benchmark harness against the Go baseline
- FD/resource-aware concurrency governor

## Phase 4 — production hardening
- mock-server integration suite
- property/fuzz tests for target parsing and trace parsing
- structured tracing + metrics
- config file + environment variables
- retry/backoff policy only for metadata downloads, not probes
- graceful shutdown/cancellation
- CI: fmt/check/clippy/test/bench + cross compilation
- reproducible release artifacts, SBOM and signing
