# PMT-DFC — Persistent Multiplexed Tunnel via Domain-Fronted Cloud Run

A production-grade implementation of the architecture described in
[`Docs/architecture.md`](Docs/architecture.md): a long-lived, multiplexed
TCP tunnel where the outer transport is a TLS connection to
`www.google.com` (SNI fronting) and the inner backend is a
[Google Cloud Run](https://cloud.google.com/run) service routed by
HTTP `Host` header. Each tunnel can carry hundreds of concurrent inner
streams (browser tabs, SSH sessions, etc.) over a single TLS handshake.

> **Read this first.** Domain fronting on Google's infrastructure is not
> officially supported and may stop working at any time. **Always run
> `pmt-probe` before deploying** to verify that fronting still reaches
> Cloud Run on your network. If the probe fails, the tunnel will fail —
> no software change can fix that.
>
> **AUP risk.** Cloud Run's terms of service prohibit "open proxy"
> services. Operators who run this should restrict access to known users
> via the PSK, disable per-request structured logging, and bear in mind
> that GCP can suspend projects whose traffic patterns look proxy-ish.
> Use at your own risk.

---

## What's in this repo

| Path | Purpose |
|------|---------|
| `cmd/server`     | Cloud Run-side endpoint. Accepts authenticated HTTP/2 streaming-POST tunnels, multiplexes with [yamux](https://github.com/hashicorp/yamux), parses SOCKS5 from each inner stream, and dials out. |
| `cmd/client`     | Local-side endpoint. Exposes a SOCKS5 listener on `127.0.0.1:8085` (or wherever you point browsers at) and forwards each connection over the persistent fronted carrier. |
| `cmd/probe`      | Standalone tool that verifies SNI=front / Host=worker still reaches your Cloud Run service. Run before deploy and on a periodic basis. |
| `internal/auth`  | HMAC-SHA256 PSK authentication with timestamp + replay-nonce protection. |
| `internal/dialer`| TCP+TLS dialer that splits SNI from inner Host. |
| `internal/tunnel`| Yamux carrier (server handler + auto-reconnecting client). Documents the in-flight-stream-loss semantics on reconnects honestly. |
| `internal/socks` | Minimal SOCKS5 (RFC 1928) — CONNECT only, DOMAIN/IPv4/IPv6, no auth (the carrier is already authenticated). |
| `internal/exit`  | Egress dialers. `Direct` (net.Dial) is the only Phase 1 implementation; the `Headless` placeholder documents the Phase 2 chromedp/Playwright design. |
| `internal/proxy` | Local SOCKS5 listener that forwards bytes to fresh yamux streams. |
| `internal/cookiejar`, `internal/bulk` | Phase 2/3 stubs (per-`sid` cookie store; GCS bulk-lane offload). Documented but not implemented. |
| `deploy/`        | `Dockerfile` (distroless), `cloudbuild.yaml`, `deploy.sh`. |
| `examples/`      | `client-config.json` template. |

## Roadmap (v0 → v1)

| Phase | Status | Notes |
|-------|--------|-------|
| **1. Carrier + multiplex + SOCKS5 + direct egress** | **shipped (this PR)** | HTTP/2 streaming POST + yamux + SOCKS5 + `net.Dial`. Auto-reconnect with explicit in-flight stream loss. |
| 2. Headless-browser exit + per-`sid` cookie jar    | designed, stubbed | For CAPTCHA-protected sites (Cloudflare Turnstile, hCaptcha, DataDome). chromedp pool inside container. |
| 3. Dual-lane bulk offload via GCS                  | designed, stubbed | Avoids HOL blocking for >1 MiB responses; reduces Cloud Run egress cost. |
| 4. gRPC bidi-stream alternative carrier            | not started      | More reliable through GFE in some configs; trade-off is a proto-codegen build step. |
| 5. QUIC / HTTP/3 carrier (probe-gated)             | not started      | Best path latency-wise if UDP/443 is allowed by the firewall. |

Speculative subresource prefetch and connection coalescing across users
(suggested in §12 of the architecture doc) are intentionally **not on
the roadmap** — see review notes in the corresponding PR for reasoning.

---

## Quickstart

### 0. Is this approach even feasible from MY network?

Run **before** spending any time or money on Cloud Run. There are two
ways, both equivalent — pick whichever runs on the censored machine:

**(a) Bash + curl + openssl, no Go required:**

```sh
bash scripts/preflight.sh
# or, with a pinned IP if DNS is hostile on your network:
FRONT_IP=142.251.150.119 bash scripts/preflight.sh
```

**(b) Single Go binary (use this if you can copy `pmt-probe` over):**

```sh
make probe
./bin/pmt-probe --mode=all --front=www.google.com
# pinned IP variant:
./bin/pmt-probe --mode=all --front=www.google.com --front-ip=142.251.150.119
```

Both run the same five-step feasibility battery and require zero GCP
infrastructure:

| # | Test | What it proves |
|---|------|---------------|
| 1 | TCP `443` to a Google IP | Your firewall lets you reach Google at all. |
| 2 | TLS handshake, SNI=front, ALPN=h2 | No TLS MITM by your firewall. |
| 3 | HTTPS GET `https://www.google.com/` | The front itself is reachable end-to-end. |
| 4 | SNI=front, **Host=`clients4.google.com`**, `GET /generate_204` → expect **204** | GFE still routes by `Host` header across origins. |
| 5 | SNI=front, **Host=`nonexistent-<rand>-uc.a.run.app`**, `GET /` → expect **Cloud Run-style 404** | GFE will route a fronted request to Cloud Run specifically. |

If all five PASS: deploy with confidence. If step 4 or 5 fails: GFE no
longer accepts the SNI/Host split for that path — you can try alternate
fronts (`*.appspot.com`, `*.firebaseapp.com`, `*.gstatic.com`,
`fonts.googleapis.com`) by changing `--front` / `FRONT`. If none work,
domain fronting on Google's infrastructure is broken on your network
and **no software change in this repo can fix that** — abort and
reconsider the approach.

### 1. Build the binaries

```sh
make build
```

Produces `bin/pmt-server`, `bin/pmt-client`, and `bin/pmt-probe`.

### 2. Probe an actual deployed worker (after step 3)

```sh
./bin/pmt-probe \
  --mode=worker \
  --front www.google.com \
  --worker your-svc-abc123-uc.a.run.app \
  --path /healthz
```

A 200 from `/healthz` proves the full path SNI=front → GFE → your
Cloud Run service works.

### 3. Deploy the server

See [`Docs/deployment.md`](Docs/deployment.md) for the full guide. TL;DR:

```sh
PROJECT_ID=my-project \
REGION=us-central1 \
SERVICE=pmt-tunnel \
  ./deploy/deploy.sh
```

The script:
* Enables required APIs.
* Creates an Artifact Registry repo and a Secret Manager entry holding
  the PSK (it generates one for you on first run — copy it).
* Builds the image with Cloud Build.
* Deploys with `--use-http2 --execution-environment=gen2
  --no-cpu-throttling` and the PSK mounted from Secret Manager.

### 4. Configure and run the client

Copy `examples/client-config.json` to `client.json` (which is
`.gitignore`d) and fill in the `worker_host` (the Cloud Run hostname
without the `https://`) and the `auth_key` (the PSK from step 3):

```sh
cp examples/client-config.json client.json
$EDITOR client.json
./bin/pmt-client --config client.json
```

Now point a SOCKS5 client at `127.0.0.1:8085`. For Firefox:

* Settings → Network Settings → Manual proxy → SOCKS Host
  `127.0.0.1` Port `8085`, SOCKS v5,
  **Proxy DNS when using SOCKS v5: ✓** (this is what prevents DNS leaks).

Verify with `curl -x socks5h://127.0.0.1:8085 https://ifconfig.me`. The
returned IP should be a Google Cloud Run egress IP.

---

## How the layers compose

```
 Browser                       Local proxy                       Cloud Run
 ─────────                     ───────────                       ─────────
 SOCKS5 ─┐                                                  ┌─ SOCKS5 parse
         ├─► yamux stream  ───►  yamux client  ───►  yamux server  ───┤
         │                                                            │
         │             one HTTP/2 streaming POST body                 │
         │  ◄───── chunked HTTP/2 response body  ◄─────────────────── │
         │                                                            │
         │       outer TLS, SNI=www.google.com, ALPN=h2               │
         │                                                            │
 ────────┴────────────────────  GFE / Google IP  ────────────────────┴────
                                         routes by Host header
```

* **One TLS handshake** per (user, server) pair.
* **One HTTP/2 connection** per TLS handshake.
* **One yamux session** per HTTP/2 connection.
* **N yamux streams** per session — one per browser tab / DNS lookup /
  inner connection.

## Reconnect semantics (read this)

When the carrier breaks (GFE idle timeout ~5 min, Cloud Run instance
roll, network blip), the client redials transparently. **Yamux streams
that were in flight at the moment of the break are NOT resumed** —
their callers get `io.EOF`, just like any TCP reset. This is
intentional; resuming SOCKS5 / raw TCP across a new carrier is not
possible without protocol-level support that neither offers. The next
request opens a fresh stream over the new carrier.

If you need bulletproof long-running uploads, run them inside an
application that already handles connection resets (e.g. `rsync`, an
S3 multipart client, an SSH `mosh`-style overlay).

## Authentication

* PSK shared between server (`PMT_AUTH_KEY` env var) and client
  (`auth_key` in config).
* Each new carrier sends `Authorization: PMT <token>` where
  `token = base64( ts || nonce || HMAC-SHA256(psk, ts || nonce) )`.
* Server enforces ±60s clock skew and rejects replayed nonces from a
  bounded LRU.
* Rotation: change the secret in Secret Manager and redeploy. Clients
  using the old PSK will get 401 on next reconnect.

A future revision can swap this for mTLS or signed JWTs without
changing the carrier shape.

## Security and operations

* The server image is `distroless/static-debian12:nonroot` — no shell,
  no package manager, no setuid bits.
* The server keeps response bodies open for the lifetime of the
  carrier. Cloud Run Gen2 supports up to 60-minute requests; the
  server emits an application-level keepalive every 30s by default.
* Per-request structured logging is **off** for tunnel data — the
  server only logs auth failures, dial failures, and lifecycle events.
  This is a deliberate decision so that user traffic patterns are not
  written to Stackdriver.
* `min-instances=1` is the default in `deploy.sh`. This costs ~$5–15/mo
  baseline (more with Always-On CPU), in exchange for predictable
  latency. Set it to 0 if you can tolerate cold starts.

## Testing

```sh
go test ./...
```

The test suite covers:

* `internal/auth`    — token sign/verify, replay rejection, skew, eviction.
* `internal/socks`   — RFC 1928 handshake parser, edge cases, error codes.
* `internal/tunnel`  — full HTTP/2-streaming-POST + yamux + SOCKS5 +
  echo egress integration through both a raw HTTP server and the real
  `tunnel.Client` on TLS.

## License

MIT. See [`LICENSE`](LICENSE).
