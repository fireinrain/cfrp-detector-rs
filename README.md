# CFRP Detector — Rust Rewrite

Rust rewrite of the original `cfrp-detector` Go project.

## Architecture

- `cfrp-detector`: reusable library
  - typed domain models
  - Cloudflare CIDR source + local cache
  - Colo/location source + local cache
  - TLS/HTTP probing
  - batch orchestration with bounded concurrency
  - speed-test abstraction
- `cfrp-detector-cli`: CLI adapter only; business logic stays in the library.
- `data/`: seed/cache-compatible Cloudflare data copied from the original project.

## Phase 1 scope

This version implements the production-oriented foundation and the standard detector path. It deliberately leaves the original "fast detector" connection-pinning optimization as a separate phase, because a safe Rust implementation should use a custom connector/resolver rather than duplicate a socket into a generic HTTP client.

## Design rules

1. No process-global mutable business state.
2. Network timeouts are explicit and bounded.
3. Batch results preserve input order even though work executes out of order.
4. IPv4/IPv6 target parsing is typed through `IpAddr`/`SocketAddr`.
5. Library code does not print to stdout; CLI owns presentation.
6. Cache and remote data sources are isolated behind types/traits.

## Build

Requires a current stable Rust toolchain. Run:

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
