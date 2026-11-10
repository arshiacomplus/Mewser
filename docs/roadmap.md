# Mewser Implementation Roadmap

This roadmap defines the implementation phases for Mewser. Each phase is scoped to a verifiable milestone with concrete acceptance criteria.

---

## Phase 0: Foundation & Shared Core Routing Spike (Active)

**Objective**: Establish repository standards, enforce storage and security boundaries, and implement a testable shared-core routing engine.

- [x] Configure repository baseline (`.gitignore`, `.editorconfig`, `AGENTS.md`, `README.md`).
- [x] Document system architecture and locked MVP boundaries (`docs/architecture.md`, `docs/decisions/0001-mvp-scope.md`).
- [x] Inspect local host environment, disk space, and installed toolchains.
- [x] Implement minimal shared Rust core (`mewser-core`):
  - Strict URL routing policy (direct domestic vs tunneled external).
  - Explicit non-fallback guarantee when tunnel routes fail.
  - Basic SSRF address validation and scheme checking.
  - Abstract `TunnelAdapter` trait.
- [x] Verify shared core unit tests within storage constraints.

**Acceptance Criteria**:
- All build artifacts and caches remain on `/mnt/D84AE43F4AE41C4E`.
- `cargo test -p mewser-core` passes with zero compiler warnings and zero failures.
- No production servers or credentials are referenced.

---

## Phase 1: Server Gateway Prototype & Content Extraction

**Objective**: Build a standalone, resource-efficient Gateway service capable of safely fetching web pages and extracting clean text and links.

- [ ] Implement safe HTTP fetcher enforcing TLS verification and SSRF host filtering.
- [ ] Implement HTML content extractor (title, structured headings, paragraphs, hyperlinks).
- [ ] Implement image placeholder generation with unique asset IDs.
- [ ] Define compact payload serialization format (binary or compressed structured text).
- [ ] Create automated test suite for Gateway extraction with simulated HTML fixtures.

**Acceptance Criteria**:
- Gateway rejects private IP targets, cloud metadata endpoints, and non-HTTP schemes with explicit errors.
- Extracted text payloads achieve >80% size reduction compared to raw HTML + assets.
- All unit and integration tests run offline against static HTML fixtures.

---

## Phase 2: MasterDNS Protocol Verification & Tunnel Adapter

**Objective**: Verify the specific MasterDNS version, transport behavior, and client/server interface, then implement the concrete `TunnelAdapter`.

- [ ] Inspect and document local MasterDNS configuration, daemon interfaces, and transport mechanism (avoiding unverified assumptions).
- [ ] Implement `MasterDnsAdapter` adhering to the `TunnelAdapter` trait.
- [ ] Handle packet chunking, reassembly, framing, and timeouts over high-latency DNS channels.
- [ ] Verify tunnel loopback or local staging transmission between test client and Gateway.

**Acceptance Criteria**:
- Transport adapter successfully transmits an extracted test payload over a local DNS tunnel without packet corruption.
- Core logic remains completely decoupled from MasterDNS daemon internals.
- No production secrets or VPS endpoints are committed.

---

## Phase 3: Client Integration & Local Cache

**Objective**: Connect the shared core and tunnel adapter to a testable Linux client harness and establish local persistent caching.

- [ ] Implement bounded local cache store (storing extracted text pages with LRU eviction).
- [ ] Create Linux client UI / test harness (Rust with GTK4 or lightweight terminal UI pending GTK4 dependencies).
- [ ] Verify offline retrieval: cached pages load seamlessly when disconnected.
- [ ] Implement on-demand single-image fetch pipeline.

**Acceptance Criteria**:
- Browsing cached pages works with network disconnected.
- Requested image is fetched only upon user trigger.
- Memory and disk footprint stay within pre-allocated bounds.

---

## Phase 4: Platform Frontends (Android & Windows)

**Objective**: Deliver platform-native frontends utilizing the shared core.

- [ ] Expose shared core via C-ABI / FFI bindings.
- [ ] Implement Android frontend in Kotlin / Jetpack Compose with JNI bridge.
- [ ] Implement Windows frontend in C# / WinUI 3 with P/Invoke bridge.
- [ ] Verify dual-mode switching (Standard Web Mode via native WebView vs Resilient Text Mode).

**Acceptance Criteria**:
- Shared networking and routing logic is shared directly without code duplication in client frontends.
- Android and Windows builds pass independent UI validation on target platforms.

---

## Phase 5: Hardening, Metrics & Release

**Objective**: Validate performance under harsh network simulation and prepare for release.

- [ ] Benchmark latency and data transfer under simulated packet loss (>30%) and jitter (>2000ms).
- [ ] Audit error handling and ensure fail-closed guarantees across all failure points.
- [ ] Package initial release artifacts with clear configuration guides.

**Acceptance Criteria**:
- End-to-end resilience confirmed under high loss / high latency.
- Usable release build delivered for target platforms.
