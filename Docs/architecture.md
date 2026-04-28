# Architecture V2 — Persistent Multiplexed Tunnel via Domain-Fronted Cloud Run

> **Status:** Proposal / Design Doc  
> **Authors:** Design discussion between repo maintainer and Devin  
> **Date:** 2026-04-28

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Current Architecture (V1)](#2-current-architecture-v1)
3. [Why V1 Cannot Solve CAPTCHA / Fingerprint Problems](#3-why-v1-cannot-solve-captcha--fingerprint-problems)
4. [Design Constraint](#4-design-constraint)
5. [V2 Architecture Overview](#5-v2-architecture-overview)
6. [Layer-by-Layer Design](#6-layer-by-layer-design)
7. [Dual-Lane Traffic Split](#7-dual-lane-traffic-split)
8. [CAPTCHA / Anti-Bot Defeat at the Exit](#8-captcha--anti-bot-defeat-at-the-exit)
9. [Failure Modes and Mitigations](#9-failure-modes-and-mitigations)
10. [Comparison Table](#10-comparison-table)
11. [Concrete Implementation Plan](#11-concrete-implementation-plan)
12. [Advanced Optimizations](#12-advanced-optimizations)
13. [Open Questions](#13-open-questions)

---

## 1. Problem Statement

The current relay architecture (GAS → Cloudflare Worker) suffers from three
categories of issues:

1. **CAPTCHA infinite loops** — Anti-bot systems (Cloudflare Turnstile,
   hCaptcha, DataDome, PerimeterX) serve JS challenges that must execute in a
   real browser. The relay does a one-shot `fetch()` with no JS engine, no DOM,
   and no cookie continuity. The challenge page is returned to the user's
   browser, which tries to solve it and POST back, but the session/cookie/TLS
   fingerprint doesn't match across hops → the site re-challenges → infinite
   loop.

2. **High latency** — Every relayed request is a full HTTP round-trip through
   GAS (300–800 ms overhead), plus base64 encoding/decoding, no streaming, and
   a fresh TLS handshake per logical request.

3. **Quota and payload caps** — GAS `UrlFetchApp` allows ~20k calls/day (free
   tier), 30 s execution timeout, and ~50 MB response cap. This makes video
   streaming, large downloads, and high-traffic browsing impractical.

An alternative approach (FlowDriver-style: write raw packets to Google Drive,
server polls and responds) solves some problems but introduces 1–3 s RTT per
exchange due to polling and Drive write/read latency.

**Goal:** Design an architecture that provides normal interactive browsing
behavior (sub-200 ms RTT, streaming, arbitrary protocols) while surviving in an
environment where only one Google IP is reachable.

---

## 2. Current Architecture (V1)

```
Client browser
  │  HTTP/HTTPS
  ▼
Local proxy (proxy_server.py, MITM for HTTPS)
  │  Repackages each request as JSON: {u, m, h, b, ct, r}
  │  TLS: SNI=www.google.com, Host=script.google.com
  ▼
Google Front End (GFE) at a single open IP
  │  Routes by Host header
  ▼
Google Apps Script (Code.gs)
  │  UrlFetchApp.fetch(WORKER_URL, {JSON payload})
  ▼
Cloudflare Worker (worker.js)
  │  fetch(targetUrl) → target site
  │  Returns {s, h, b} (status, headers, base64 body)
  ▼
Response bubbles back: CF Worker → GAS → GFE → local proxy → browser
```

**Key limitation:** Every browser request becomes a separate GAS invocation and
CF Worker fetch. No connection reuse, no streaming, no state.

---

## 3. Why V1 Cannot Solve CAPTCHA / Fingerprint Problems

Even if the CF Worker is replaced with a custom VPS running identical logic,
CAPTCHAs persist because of:

| Factor | Why it triggers CAPTCHA |
|--------|------------------------|
| **No JS execution at exit** | Turnstile/hCaptcha require running challenge JS (canvas, WebGL, timing, audio fingerprint). A raw `fetch()` never generates the token. |
| **Broken cookie/session continuity** | `cf_clearance` cookies are bound to the IP + UA + JA3 that solved the challenge. Stateless relaying invalidates them. |
| **TLS fingerprint mismatch** | Anti-bot systems fingerprint JA3/JA4 (TLS ClientHello) and HTTP/2 SETTINGS. The relay's HTTP client (Node `undici`, Python `requests`) has a well-known non-browser signature. |
| **Header order / missing Sec-Fetch-*** | WAFs key on exact header ordering and the presence of `Sec-Fetch-Dest`, `Sec-Ch-Ua-*` headers that raw HTTP clients don't produce correctly. |
| **Datacenter IP reputation** | CF Worker IPs *and* generic VPS IPs (DigitalOcean, Hetzner, OVH) are on every bot blocklist. Only residential/mobile IPs help, and even then the above factors still trigger challenges. |

**Conclusion:** The fix requires a real browser fingerprint reaching the target
site, persistent per-session state, and optionally residential egress IPs.

---

## 4. Design Constraint

> The DPI/firewall permits exactly **one** outbound target: TCP to a single
> Google IP on port 443. The TLS ClientHello SNI must equal `www.google.com`.
> All other traffic is blocked. Plaintext is inspected. Inside the TLS tunnel,
> the firewall has no visibility.

Under this constraint, we need a Google service that:

1. Shares GFE (reachable from the same Google IP via Host-header routing),
2. Supports **persistent bidirectional byte streams** (not request/response),
3. Allows running arbitrary code on the server side.

**Winner: Google Cloud Run** — accepts WebSocket / HTTP/2 bidi-streaming /
gRPC bidi-streaming, is fronted through GFE, and runs your container. The repo
already has a `google_fronting` mode in `core/domain_fronter.py` that targets
`*.run.app` via Host-header rewriting. V2 upgrades this from one-shot HTTP to a
persistent multiplexed stream.

---

## 5. V2 Architecture Overview

```
Browser (any site)
  │  HTTP / HTTPS / arbitrary TCP
  ▼
Local proxy (upgraded proxy_server.py)
  │  Encapsulates each TCP stream as a multiplexed "channel" frame
  │  Maintains ONE persistent connection to GFE
  │
  │  TLS{ SNI=www.google.com, ALPN=h2 }
  ▼
Google Front End (GFE) at the one open IP
  │  Routes by Host header
  ▼
Host: <your-service>.run.app
  │
  ▼
Cloud Run container (your code)
  ├── Multiplex demuxer (yamux / smux)
  ├── Per-stream handler:
  │   ├── SOCKS5 handshake → net.Dial (raw TCP to any host:port)
  │   ├── OR: Playwright-stealth headless browser for CAPTCHA sites
  │   └── Per-client cookie jar keyed by opaque session ID
  ├── Egress options:
  │   ├── Direct (Cloud Run IP)
  │   ├── Cloud NAT → static IP
  │   └── Residential proxy chain (optional)
  └── DNS resolver (DoH to 8.8.8.8, no client DNS leak)
```

**One TLS handshake → one HTTP/2 connection → thousands of multiplexed streams
→ sub-100 ms RTT to any site.**

---

## 6. Layer-by-Layer Design

### L0 — Outer TLS + SNI Fronting

- Standard TLS 1.3 to `IP_G:443`, SNI = `www.google.com`.
- Firewall sees normal Google traffic.
- **TLS 1.3 0-RTT resumption:** On reconnects, skip the 1-RTT handshake.
  Store session tickets locally. Reconnect latency ≈ 0.
- **Certificate pinning (optional):** Pin Google's root CA to detect MITM by
  the firewall. If the cert doesn't match, abort and alert the user.

### L1 — Carrier Protocol

The persistent bidirectional stream inside the TLS connection. Ranked by
reliability through GFE:

| Priority | Protocol | Pros | Cons |
|----------|----------|------|------|
| **1** | **HTTP/2 streaming POST + chunked response** | Most reliable across GFE. No Upgrade dance. Two half-duplex streams compose into full-duplex. | Must reconnect every ~5 min due to GFE idle limits. Some GFE configs buffer POST bodies. |
| **2** | **gRPC bidi-stream** | Same h2 wire format. Protobuf framing, flow control, mature libs (`grpc-go`, `grpc-python`). Looks like normal `application/grpc` traffic. | Slightly heavier setup. |
| **3** | **WebSocket** | Simplest framing. Cloud Run supports it. | GFE can be finicky with `Upgrade:` over fronted SNI. Test in target env. |
| **4** | **HTTP/3 (QUIC) over UDP/443** | 0-RTT, no head-of-line blocking, mobility-friendly. DPI struggles with QUIC. | Likely blocked (UDP). Probe first. If it works, this is the best option. |

**Recommendation:** Start with HTTP/2 streaming POST (#1) for maximum
compatibility. Add gRPC bidi (#2) as a tested alternative. Probe QUIC (#4) as
a high-upside option.

### L2 — Stream Multiplexer

Inside the carrier, run a lightweight stream-multiplexer so that hundreds of
concurrent browser connections share the one carrier stream without
head-of-line blocking.

**Recommended:** [yamux](https://github.com/hashicorp/yamux) (Go) or
[smux](https://github.com/xtaci/smux) (Go). For Python/Node clients, a
minimal yamux implementation (~200 LOC) is sufficient.

```
Carrier stream (one HTTP/2 POST body)
  ├── Stream 0x01: browser tab 1 → CNN.com
  ├── Stream 0x02: browser tab 2 → GitHub.com
  ├── Stream 0x03: CSS subresource for CNN
  ├── Stream 0x04: JS subresource for CNN
  ├── ...
  └── Stream 0xFF: DNS query
```

**Benefit:** Opening a page that fires 80 subresource requests doesn't open 80
TLS handshakes to GFE — it opens 80 lightweight streams over the one warm
tunnel. This typically cuts page-load time by 3–5×.

### L3 — Inner Protocol (SOCKS5)

Inside each multiplexed stream, run a **SOCKS5 handshake**.

```
Client stream → SOCKS5 CONNECT example.com:443 → Cloud Run dials out → raw TCP relay
```

This makes the system **protocol-agnostic**: HTTP, HTTPS, SSH, SMTP, IMAP, DNS,
raw TCP — anything works. Existing battle-tested implementations:
Trojan-Go, V2Ray, Shadowsocks-2022 all use variants of this pattern. Their
wire formats can be borrowed directly.

### L4 — Egress Hardening (Anti-Bot / CAPTCHA Defeat)

See [Section 8](#8-captcha--anti-bot-defeat-at-the-exit) for the full design.
Summary: run a headless browser (Playwright-stealth / camoufox) inside the
Cloud Run container for CAPTCHA-protected sites, with a per-client persistent
cookie jar and Chrome TLS fingerprint impersonation via `curl_cffi`.

### L5 — DNS Tunneling

All DNS from the client is tunneled through the same multiplexed stream to a
resolver inside the Cloud Run container (e.g., `8.8.8.8` via DoH). This
prevents DNS leaks to the firewall.

Implementation: the local proxy intercepts DNS (UDP/53, DoH) and forwards as a
dedicated multiplex stream. The container resolves and returns.

---

## 7. Dual-Lane Traffic Split

Large payloads (video, downloads) should not compete with interactive requests
on the multiplex stream.

```
                          ┌─── Interactive lane (multiplex ws/h2)
Local proxy ──────────────┤     Small requests, low latency
                          │
                          └─── Bulk lane (GCS via storage.googleapis.com)
                                Large downloads (>1 MB)
                                Cloud Run uploads to GCS bucket
                                Client pulls via HTTP Range requests
                                through same fronted TLS channel
```

`storage.googleapis.com` is also frontable from `www.google.com` SNI through
the same GFE. Benefits:

- Multi-GB streaming, CDN-cached.
- No Cloud Run egress charges for bulk data.
- Parallel Range requests for high throughput.
- Head-of-line blocking on the interactive lane is eliminated.

**Threshold:** the local proxy routes responses > 1 MB to the bulk lane.
Configurable.

---

## 8. CAPTCHA / Anti-Bot Defeat at the Exit

The only way to reliably pass modern CAPTCHAs is to present a **real browser
fingerprint** to the target site.

### 8.1 — Headless Browser Pool

Inside the Cloud Run container, run a pool of headless Chromium instances via
Playwright with stealth patches:

- [playwright-extra + stealth plugin](https://github.com/nicholasgasior/playwright-extra-go)
  or [camoufox](https://github.com/daijro/camoufox) (Firefox-based, harder to
  fingerprint)
- [patchright](https://github.com/nicholasgasior/patchright) (patched
  Playwright that bypasses detection)

Each browser instance provides:

- Real Chrome/Firefox JA3/JA4 TLS fingerprint
- Real HTTP/2 SETTINGS/WINDOW_UPDATE fingerprint
- Full JS execution for challenge solving
- Canvas, WebGL, audio fingerprinting passes
- Correct `Sec-Fetch-*`, `Sec-Ch-Ua-*` headers

### 8.2 — Per-Client Session Pinning

```json
{
  "sid": "abc123",
  "u": "https://example.com/page",
  "m": "GET",
  "h": { "Accept-Language": "en-US" }
}
```

The `sid` (session ID) maps to a persistent context:

- **Cookie jar** (per-domain, per-session)
- **Browser context** (if headless is active for that session)
- **UA string** (locked for the session)
- **TLS fingerprint** (consistent across requests)

Once a CAPTCHA is solved, the `cf_clearance` cookie is stored in the jar and
reused for subsequent requests — no re-challenge.

### 8.3 — Routing Decision

Not all sites need a headless browser (expensive: ~500 MB RAM, ~2–5 s/page).
The exit node should route intelligently:

```
Incoming request
  │
  ├── Known clean site (no anti-bot) → direct fetch via curl_cffi
  │     (Chrome JA3 impersonation, ~50 ms)
  │
  ├── Known CAPTCHA site → headless browser pool
  │     (full JS execution, ~2–5 s first load, then cookie reuse)
  │
  └── Unknown → try curl_cffi first
        ├── 200 OK → done
        └── 403 / challenge HTML detected → retry via headless browser
```

Maintain a learned blocklist of domains that require headless. Persist across
sessions.

### 8.4 — Residential Proxy Chain (Optional)

For the most aggressive anti-bot systems (DataDome, PerimeterX on
high-value sites), even a correct browser fingerprint from a datacenter IP gets
blocked. Chain the headless browser's egress through a residential proxy:

```
Headless browser → residential proxy (Bright Data / IPRoyal / Smartproxy) → target
```

This defeats IP-reputation checks. Cost: ~$1–5 per GB depending on provider.

---

## 9. Failure Modes and Mitigations

| Failure Mode | Impact | Mitigation |
|--------------|--------|------------|
| **GFE drops fronted `*.run.app`** | Total outage | Fallback to `*.appspot.com`, `firebaseio.com` (WebSocket), `firestore.googleapis.com` (gRPC bidi). All are GFE-fronted. |
| **Active TLS MITM by firewall** | Cert mismatch detected | Pin Google root CA. Alert user. If they MITM for all Google, they can also see our Host header — no solution exists at that point. |
| **GFE idle timeout (h2 stream killed at ~5 min)** | Stream drops | Heartbeat ping every 30–60 s. Auto-reconnect with TLS 0-RTT. Transparent to the multiplex layer above. |
| **Cloud Run cold start (~2 s)** | First request of session is slow | Set `min-instances=1` (~$5/mo). Or use Cloud Functions Gen2 (same GFE, similar cold start). |
| **Cloud Run request timeout** | Stream killed at 60 min (Gen2) or 5 min (Gen1) | Use Gen2. Reconnect transparently at 55 min. Yamux sessions survive reconnects. |
| **GAS UrlFetchApp quota (if GAS is kept for anything)** | 20k/day cap | V2 eliminates GAS from the data path entirely. GAS is only needed if used as a bootstrap/fallback channel. |
| **Headless browser OOM in Cloud Run** | Container crashes | Limit pool size to available RAM / 500 MB. Evict idle contexts. Use Cloud Run with 4+ GB RAM config. |
| **Residential proxy downtime** | CAPTCHA sites fail | Direct fallback (datacenter IP). May get challenged but won't loop — headless browser still solves it, just slower. |

---

## 10. Comparison Table

| | V1: GAS + CF Worker | FlowDriver (Drive) | **V2: Fronted Cloud Run + Multiplex** |
|---|---|---|---|
| RTT per request | 500–1500 ms | 1000–3000 ms | **40–150 ms** |
| Persistent connection | No | No | **Yes (hours)** |
| Streaming responses | No (base64 buffer) | No | **Yes (binary frames)** |
| Concurrency | 6 GAS workers, batch only | Serial | **Unlimited multiplexed streams** |
| Daily request cap | 20k UrlFetch | Drive API quota | **Your wallet** |
| Max payload | ~50 MB (GAS cap) | 5 GB (Drive, slow) | **Unlimited (streamed)** |
| Arbitrary TCP (SSH, etc.) | No | Partially | **Yes (SOCKS5)** |
| CAPTCHA handling | Infinite loop | Infinite loop | **Headless browser at exit** |
| TLS fingerprint | CF Worker's (flagged) | Server's (flagged) | **Chrome-impersonated** |
| Cookie persistence | None | None | **Per-session jar** |
| DNS leakage | Yes | Yes | **No (tunneled DoH)** |

---

## 11. Concrete Implementation Plan

### Phase 1 — Minimum Viable Tunnel (2–3 days)

1. **Cloud Run service** (`tunnel-server/`):
   - Go or Node HTTP/2 server.
   - Accepts a streaming POST to `/tunnel`.
   - Demuxes yamux frames into per-stream goroutines.
   - Each stream: SOCKS5 handshake → `net.Dial` to target → blind relay.
   - ~300 LOC.

2. **Local proxy upgrade** (`core/domain_fronter.py`):
   - New mode: `cloud_run_h2`.
   - Opens one TLS + h2 connection to GFE, keeps it alive.
   - Streaming POST body carries yamux-framed data.
   - `core/proxy_server.py`: hand each CONNECT stream into a yamux session
     instead of the current per-request relay.

3. **DNS tunneling**:
   - Local proxy intercepts DNS.
   - Forwards as a dedicated yamux stream.
   - Cloud Run resolves via `8.8.8.8`.

4. **Config**:
   ```json
   {
     "mode": "cloud_run_h2",
     "google_ip": "216.239.38.120",
     "front_domain": "www.google.com",
     "worker_host": "your-service-abc123.run.app",
     "auth_key": "...",
     "listen_host": "127.0.0.1",
     "listen_port": 8085
   }
   ```

### Phase 2 — CAPTCHA Defeat (1–2 days)

5. **Playwright-stealth integration** in the Cloud Run container:
   - Install Chromium + Playwright.
   - On CAPTCHA-detected responses (403 + challenge HTML pattern match),
     retry through headless browser.
   - Store solved cookies in per-`sid` jar.

6. **curl_cffi for non-CAPTCHA sites**:
   - Default egress uses `curl_cffi` with Chrome JA3 impersonation.
   - ~50 ms per request, low resource usage.

### Phase 3 — Production Hardening (1–2 days)

7. **Bulk lane via GCS**: upload large responses to a GCS bucket, client
   pulls via Range requests through the same fronted TLS.

8. **Heartbeat + auto-reconnect**: ping every 30 s, transparent reconnect
   on carrier drop.

9. **Residential proxy option**: configurable upstream proxy for the
   headless browser pool.

10. **Monitoring**: request latency histogram, CAPTCHA solve rate, multiplex
    stream count, carrier reconnect count.

### Phase 4 — Exotic Optimizations (optional)

11. **QUIC probe + HTTP/3 carrier** if UDP/443 is open.
12. **Speculative subresource prefetch** in the local proxy.
13. **Brotli/zstd inner-stream compression.**
14. **Firebase Realtime Database as fallback carrier.**

---

## 12. Advanced Optimizations

### Speculative Subresource Prefetch

The local proxy parses HTML responses inline and identifies `<link>`,
`<script>`, `<img>` URLs. It immediately issues fetch requests for these
through the multiplex before the browser even parses the HTML. This hides one
full RTT per subresource and makes page loads feel near-native.

### Connection Coalescing

Multiple users behind the same local network can share a single warm TLS
session and yamux carrier to Cloud Run. The server demuxes by `sid`. This
amortizes TLS handshake cost and DNS cache across users.

### Side-Channel Keepalive

Use Google's connectivity-check endpoint (`clients4.google.com/generate_204`)
as a lightweight ping to keep TLS session resumption tickets fresh without
consuming Cloud Run CPU minutes.

### Inner-Stream Compression

GFE handles outer TLS but the inner yamux frames are uncompressed. Adding
brotli-11 on text/HTML responses before they leave the container can reduce
bytes 3–5× for text-heavy pages, directly reducing transfer time on the
carrier.

---

## 13. Open Questions

1. **GFE fronting durability:** How long will `*.run.app` remain frontable from
   `www.google.com` SNI? This should be probed regularly. Fallback hosts
   (`*.appspot.com`, `firebaseio.com`, `firestore.googleapis.com`) should be
   tested and documented.

2. **Cloud Run Gen2 vs Gen1:** Gen2 supports 60-min request timeout and
   WebSocket natively. Gen1 is limited to 5 min. The design assumes Gen2.

3. **QUIC availability:** Does the target firewall permit UDP/443 to the
   Google IP? If yes, HTTP/3 is strictly superior. A probe script should be
   included in the repo.

4. **Headless browser resource budget:** How many concurrent headless contexts
   can a Cloud Run instance sustain? Depends on RAM allocation. With 4 GB RAM,
   expect ~6–8 concurrent Chromium contexts.

5. **Residential proxy cost model:** At ~$2–5/GB, residential proxies add
   significant cost for heavy browsing. Should be optional and limited to
   known-difficult domains.

6. **Legal and AUP considerations:** Cloud Run, GCS, and Firebase all have
   acceptable use policies. Running a generic proxy relay may violate them.
   The operator assumes responsibility for compliance.
