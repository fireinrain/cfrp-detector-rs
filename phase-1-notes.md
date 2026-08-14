# Phase 1 migration notes

## Mapped from Go

- `Result` -> `DetectionResult`
- `BatchTarget` -> `Target` + `BatchTarget`
- `EdgeInfo` -> `EdgeInfo`
- `Detect` -> `Detector::detect`
- `DetectBatch`/`AutoDetectBatch` -> `Detector::detect_batch`
- `IsCloudflareIP` -> `CidrSource::contains`
- `FetchEdgeInfo` -> `Detector::fetch_edge_info`
- `fetchOrLoad` -> `FileCache::load_or_fetch`
- `ProbeHTTP`/TLS probing -> `ProbeEngine`

## Behavior intentionally improved

- IPv6 parsing supports `[addr]:port` safely.
- Batch output is deterministic and keeps input order.
- HTTP/TLS client creation is centralized.
- stdout logging is removed from the core library.
- confidence is represented as an enum instead of free-form strings.

## Known next phases

1. Exact IP-pinned HTTP/S TLS connector for speed-test and fast detection.
2. Full CLI parity: TXT/CSV/JSON output, speedtest flags, adaptive concurrency and progress reporting.
3. Offline deterministic tests with local mock servers and fixture CIDRs/locations.
4. Benchmarks, fuzzing for target parsing, and property tests.
5. release packaging, cross compilation, CI, SBOM/signing and operational metrics.
