# PMT-DFC — Domain-Fronted Covert Tunnel

Tunnel network traffic through Google's infrastructure using domain fronting.
Your firewall sees `www.google.com`; behind the scenes, a free relay (Google Apps Script or Cloudflare Worker) forwards your traffic to a VPS that connects to the real internet.

```
Browser / app
    ↓ SOCKS5 (127.0.0.1:8085)
pmt-client (your machine)
    ↓ TLS (SNI = www.google.com, IP = 216.239.38.120)
    ↓ Host = script.google.com  (inside TLS — firewall can't see this)
Google Front End
    ↓ routes by Host header
Apps Script relay (your free Google account)
    ↓ UrlFetch → your VPS
pmt-server (VPS, €4/mo)
    ↓ real TCP connections
Internet
```

Two relay options — both free:

| Relay | Cost | Setup | Quota |
|-------|------|-------|-------|
| **Google Apps Script** | Free | Deploy Code.gs via browser | 20K calls/day/account (batched) |
| **Cloudflare Worker** | Free tier | `wrangler deploy` | 100K requests/day |

---

## § 0 — Is this feasible from MY network?

Before deploying anything, test whether domain fronting works:

```powershell
# Windows (pre-built binary):
.\pmt-probe.exe --mode=sweep --front-ip=216.239.38.120

# Linux/Mac:
FRONT_IP=216.239.38.120 bash scripts/preflight.sh sweep
```

If at least one SNI row says `FRONTING WORKS`, proceed. If all say `DO NOT USE`, try `--mode=targets` to see which Google product families GFE will route to from your network.

---

## § 1 — Quick Start

### Prerequisites
- A cheap VPS (Hetzner CX11 €4/mo, any provider works) — reachable from Google, not from your network
- A Google account (for Apps Script relay) OR a Cloudflare account (for Worker relay)
- Go 1.25+ to build from source, OR use pre-built binaries from Releases

### Step 1: Deploy the VPS tunnel-node

```bash
# SSH into your VPS, then:
git clone https://github.com/easyfast2008/PMT-DFC.git
cd PMT-DFC

# Generate a strong auth key:
AUTH_KEY=$(openssl rand -hex 24)
echo "Your auth key: $AUTH_KEY"

# Option A: Docker (recommended)
docker build -f deploy/Dockerfile -t pmt-server .
docker run -d --name pmt-server --restart unless-stopped \
  -p 8080:8080 -e PMT_AUTH_KEY="$AUTH_KEY" pmt-server

# Option B: Direct binary
make server
PMT_AUTH_KEY="$AUTH_KEY" ./bin/pmt-server

# Option C: One-shot install script
bash deploy/install-vps.sh "$AUTH_KEY"
```

Verify: `curl http://localhost:8080/health` → `ok`

### Step 2: Deploy the relay (choose one)

#### Option A: Google Apps Script (recommended — zero cost, proven)

1. Open https://script.google.com, sign in, create a new project.
2. Delete the default code and paste the contents of [`relay/apps-script/Code.gs`](relay/apps-script/Code.gs).
3. Edit `TUNNEL_SERVER_URL` → `http://YOUR_VPS_IP:8080`
4. Edit `AUTH_KEY` → the same key from Step 1.
5. **Deploy → New deployment → Web app** → Execute as: Me, Access: Anyone.
6. Copy the **Deployment ID** (long random string in the deployment URL).

#### Option B: Cloudflare Worker (alternative — also free)

```bash
cd relay/cloudflare-worker
# Edit wrangler.toml: set TUNNEL_SERVER_URL and AUTH_KEY
npm install -g wrangler
wrangler login
wrangler deploy
# Note your Worker URL: https://pmt-relay.YOUR-ACCOUNT.workers.dev
```

### Step 3: Configure the client

Create `client.json`:

```json
{
  "listen": "127.0.0.1:8085",
  "relay": "apps_script",
  "script_id": "YOUR_DEPLOYMENT_ID_FROM_STEP_2",
  "auth_key": "YOUR_AUTH_KEY_FROM_STEP_1",
  "front_domain": "www.google.com",
  "front_ip": "216.239.38.120"
}
```

For Cloudflare Worker relay instead:

```json
{
  "listen": "127.0.0.1:8085",
  "relay": "cloudflare_worker",
  "worker_url": "https://pmt-relay.YOUR-ACCOUNT.workers.dev",
  "auth_key": "YOUR_AUTH_KEY_FROM_STEP_1",
  "front_domain": "www.google.com",
  "front_ip": "216.239.38.120"
}
```

### Step 4: Run the client

```bash
make client
./bin/pmt-client --config client.json
```

### Step 5: Use it

Set your browser's SOCKS5 proxy to `127.0.0.1:8085`. Or test with curl:

```bash
curl --proxy socks5h://127.0.0.1:8085 https://ifconfig.me
```

---

## § 2 — Architecture

### Data flow

```
Client (censored network)
  │
  │ SOCKS5 connection from browser
  ↓
pmt-client
  │ Parses SOCKS5 handshake, extracts target host:port
  │ Batches multiple sessions into one JSON request
  │ Sends via fronted TLS (SNI=www.google.com) to relay
  ↓
Google Front End / Cloudflare Edge
  │ Routes by HTTP Host header
  ↓
Relay (Apps Script or CF Worker)
  │ Forwards JSON payload to VPS via UrlFetch / fetch()
  ↓
pmt-server (VPS tunnel-node)
  │ Manages persistent TCP sessions to real targets
  │ Returns response data in JSON batch
  ↓
Real Internet
```

### Batch protocol

```
POST /tunnel/batch
{
  "k": "auth_key",
  "ops": [
    {"op": "connect", "sid": "abc123", "host": "example.com", "port": 443},
    {"op": "data",    "sid": "def456", "d": "base64..."},
    {"op": "close",   "sid": "ghi789"}
  ]
}
→ {
  "r": [
    {"sid": "abc123", "d": "base64-initial-response..."},
    {"sid": "def456", "d": "base64-response-data..."},
    {"sid": "ghi789", "eof": true}
  ]
}
```

Wire-compatible with [MhR's tunnel-node](https://github.com/therealaleph/MasterHttpRelayVPN-RUST/tree/main/tunnel-node) batch format.

### Why two relay options?

| | Apps Script | Cloudflare Worker |
|---|---|---|
| Works from Iran? | Yes (proven) | Needs testing |
| Setup | Browser only, no CLI | `wrangler deploy` |
| Cost | Free | Free tier (100K req/day) |
| Latency | ~2-5s round-trip | ~0.5-2s round-trip |
| Quota | 20K UrlFetch/day/account | 100K requests/day |
| Scale | Multiple Google accounts | Paid plan ($5/mo) |

---

## § 3 — Preflight Probe

The `pmt-probe` tool tests whether domain fronting works from your network:

```bash
# Full 5-step battery for one SNI:
./bin/pmt-probe --mode=all --front=www.google.com --front-ip=216.239.38.120

# Sweep all 13 known-working Google SNIs:
./bin/pmt-probe --mode=sweep --front-ip=216.239.38.120

# Test which Google product families GFE will route to:
./bin/pmt-probe --mode=targets --front-ip=216.239.38.120
```

---

## § 4 — Phase 2 Roadmap (planned)

- **Per-session cookie jar** on VPS — persistent cookies across requests within a session
- **curl_cffi integration** — JA3/JA4 fingerprint impersonation for anti-bot bypass
- **Headless Chromium pool** — CAPTCHA solver for JS-challenge sites
- **Google Drive bulk lane** — high-throughput path via Drive API for large downloads (FlowDriver pattern)
- **Multi-deployment pipelining** — multiple Apps Script deployments for higher concurrency

---

## § 5 — Credits

- [MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN) by @masterking32 — original Apps Script relay concept
- [MasterHttpRelayVPN-RUST](https://github.com/therealaleph/MasterHttpRelayVPN-RUST) by @therealaleph — Rust port with batch tunnel-node
- [FlowDriver](https://github.com/NullLatency/FlowDriver) by @NullLatency — Google Drive as covert transport

---

## License

MIT. See [LICENSE](LICENSE).
