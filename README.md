# Mewser

Mewser is a cross-platform, text-first web browser designed for unreliable, high-latency, and bandwidth-constrained network environments.

Its primary purpose is to deliver useful web content over a DNS tunnel using the selected MasterDNS transport, eliminating nonessential data transfer and maximizing resilience during network interruptions.

## Core Flow

1. The user requests a URL.
2. An explicit routing policy determines whether the destination is domestic/direct-listed or requires tunneled transport.
3. Direct-listed sites connect normally through the native platform web engine.
4. All other destinations route through the DNS tunnel to a remote Server Gateway.
5. The Gateway fetches the target web page, parses content, and extracts clean, readable text and hyperlinks.
6. The client renders readable text and links immediately without loading images.
7. Images can be fetched individually upon explicit user request.
8. Parsed pages are cached locally to remain accessible during network dropouts.

## Target Platforms & Architecture

Mewser pairs native client frontends with a shared Rust networking core:

- **Windows**: C# / WinUI 3, using WebView2 for standard web rendering.
- **Linux**: Rust with GTK4 / libadwaita, evaluating WebKitGTK for standard web rendering.
- **Android**: Kotlin / Jetpack Compose, with Android WebView or GeckoView for standard web rendering.
- **Shared Core**: Rust, providing a stable interface for routing, request policies, tunnel transport abstraction, cache management, and network state.
- **Server Gateway**: A lightweight service running on remote infrastructure to fetch and process web content safely.
- *Apple platforms (macOS / iOS) are currently out of scope.*

## Current Status

- **Phase**: Phase 0 (Foundation & Shared Core Spike).
- **Foundation**: Repository structure, engineering constraints, and architectural specifications established.
- **Shared Core**: Routing policy, request validation, SSRF defenses, and tunnel adapter abstraction implemented in Rust (`crates/mewser-core`).
- **MasterDNS**: Transport integration isolated behind an adapter pending protocol verification.
- **Native UIs**: Deferred until platform build environments and shared core contracts are finalized.

## Getting Started

### Prerequisites

- Rust toolchain (1.80+ recommended; verified with 1.92.0).

### Build & Test Shared Core

All builds and tests should be run from the repository root:

```bash
# Check shared core
cargo check -p mewser-core

# Run test suite
cargo test -p mewser-core
```

*Note on disk usage: When building in resource-constrained environments, ensure build artifacts remain on the dedicated project partition.*

## Documentation

- [Engineering Rules & Constraints](AGENTS.md)
- [System Architecture](docs/architecture.md)
- [Implementation Roadmap](docs/roadmap.md)
- [ADR 0001: Locked MVP Scope](docs/decisions/0001-mvp-scope.md)

## License

GNU General Public License v3.0 (see [LICENSE](LICENSE)).
