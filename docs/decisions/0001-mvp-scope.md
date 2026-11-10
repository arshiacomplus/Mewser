# ADR 0001: Locked MVP Scope and Architecture Boundaries

- **Status**: Accepted
- **Date**: 2026-10-27
- **Deciders**: Product Owner (User), Architecture (ChatGPT), Implementation (Antigravity)

## Context & Problem Statement

Standard web browsers are designed for high-bandwidth, low-latency, and reliable connections. In severely throttled, high-latency, and disrupted network environments, modern web pages (often exceeding 5–10 MB of scripts, styles, fonts, and tracking assets) fail to load entirely.

Mewser aims to provide reliable access to critical web content over a DNS tunnel using MasterDNS transport. However, DNS tunneling provides very limited bandwidth (often < 10–50 kbps) and high packet latency. Directly tunneling raw web traffic through a standard browser engine causes severe timeouts, unbounded memory growth, and unusable experiences.

We must define a strict, production-oriented MVP scope that delivers a functional and resilient browsing experience without scope creep.

## Decision Drivers

- **Usability over feature count**: A fast, readable page delivered reliably beats a stalled full-engine render.
- **Strict bandwidth minimization**: Nonessential data (scripts, telemetry, ads, decorative images) must not traverse the DNS tunnel.
- **Fail-safe traffic isolation**: Traffic designated for tunneled transit must never leak to direct network interfaces upon tunnel failure.
- **Cross-platform maintainability**: Core routing, policy, and caching logic must not be implemented separately on every platform.
- **Decoupling from unverified tools**: MasterDNS integration details must remain isolated behind an adapter until exact protocol versions are verified.

## Considered Options

- **Option A (Generic Proxy Browser)**: Route standard browser engine traffic through a SOCKS5/HTTP proxy over DNS.
  *Rejected*: Uncompressed assets and client-side JavaScript execution overload the DNS tunnel, leading to timeouts and unworkable performance.
- **Option B (Text-Only Terminal Browser)**: Build a Lynx/w3m-like terminal client only.
  *Rejected*: Fails to satisfy target platform UX expectations (Windows, Android, Linux desktop) and prevents on-demand image view or standard web fallback for domestic sites.
- **Option C (Dual-Mode Native Frontend + Shared Core + Server Gateway)**: Native platform frontends (Windows WinUI 3, Linux GTK4, Android Compose) paired with a shared Rust networking core and a remote Server Gateway that extracts readable text and links for text-mode browsing, while retaining native WebView engines for direct-listed sites.
  *Accepted*: Meets usability, cross-platform, resilience, and bandwidth requirements.

## Decision Outcome

We lock the following scope for the Mewser MVP:

1. **Dual Modes**:
   - **Resilient Text Mode**: Primary mode over DNS tunnel. Gateway extracts clean readability text, headings, and links. Client displays structured content instantly.
   - **Standard Web Mode**: Uses native platform browser engine (WebView2 / WebKitGTK / Android WebView) for direct-listed domestic sites or unconstrained connections.
2. **Strict Routing Policy**:
   - Explicit domain matching for domestic/direct destinations vs foreign/tunneled destinations.
   - **Non-Fallback Rule**: If a route is marked for tunnel transit, tunnel failure must fail closed with an explicit error. Falling back to direct access is strictly forbidden.
3. **Manual Asset Retrieval**:
   - Images and media are omitted from the initial text response.
   - Images are represented by discrete placeholders that can be fetched individually upon user request.
4. **Server Gateway Extraction**:
   - Remote Gateway fetches external pages, enforces strict SSRF defenses (blocking loopback, private IP, link-local, and cloud metadata targets), validates TLS certificates, and returns compact structured content.
5. **Shared Rust Core**:
   - All routing, policy validation, tunnel abstraction, and local caching are implemented once in Rust (`mewser-core`) and consumed by platform frontends via clean FFI.
6. **MasterDNS Adapter**:
   - MasterDNS is integrated strictly behind an abstract `TunnelAdapter` trait to avoid premature assumptions regarding daemon interfaces, CLI flags, or CNAME behaviors.

## Explicit Exclusions for MVP

The following items are out of scope:
- **Apple Platforms**: macOS and iOS are not supported in MVP.
- **Automatic Image Prefetching**: Auto-loading images or media streams over the tunnel is prohibited.
- **Client-Side JavaScript in Text Mode**: Text mode renders extracted semantic HTML/text; dynamic client JS execution is omitted.
- **Video & Audio Streaming**: Multimedia streaming over DNS tunnel is out of scope.
- **Browser Extensions & Add-ons**: No extension API or WebExtensions support.
- **Cloud Account & Sync Services**: Bookmarks and history remain strictly local; no remote user accounts or cross-device synchronization.
- **Direct Production VPS Operations**: No production servers or credentials are to be provisioned or modified during initial development phases.

## Consequences & Verification

- **Positive**: Clear boundary lines; lightweight DNS payload; guaranteed traffic isolation; single source of truth for routing.
- **Negative**: Requires maintaining a remote Gateway service alongside client builds.
- **Verification**: Verified via automated unit tests in `mewser-core` testing direct vs tunnel routing, SSRF rejection, and zero fallback on failure.
