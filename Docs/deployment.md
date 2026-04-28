# PMT-DFC Deployment Guide

End-to-end deployment for PMT-DFC: VPS tunnel-node + relay (Apps Script or Cloudflare Worker) + client.

## Prerequisites

- **VPS**: any cheap Linux box (Hetzner CX11 €4/mo, OVH, Vultr, etc.). Must have a public IP and outbound internet. Does NOT need to be reachable from your censored network — only from Google's or Cloudflare's egress.
- **Google account** (for Apps Script relay) OR **Cloudflare account** (for Worker relay).
- **Local machine**: Linux/macOS/Windows. Go 1.25+ to build, or use prebuilt releases.

## Architecture overview

```
client → fronted TLS → GFE/CF Edge → relay → VPS tunnel-node → internet
```

The relay is a free, fronted entry point. The VPS does the actual TCP work.

---

## 1. VPS tunnel-node setup

### Option A: Docker (recommended)

```bash
ssh root@your-vps-ip
git clone https://github.com/easyfast2008/PMT-DFC.git
cd PMT-DFC

AUTH_KEY=$(openssl rand -hex 24)
echo "AUTH_KEY=$AUTH_KEY" | tee /root/pmt-auth.env  # save it

docker build -f deploy/Dockerfile -t pmt-server .
docker run -d --name pmt-server --restart unless-stopped \
  -p 8080:8080 \
  -e PMT_AUTH_KEY="$AUTH_KEY" \
  pmt-server
```

### Option B: One-shot installer

```bash
ssh root@your-vps-ip
AUTH_KEY=$(openssl rand -hex 24)
echo "AUTH_KEY=$AUTH_KEY"
git clone https://github.com/easyfast2008/PMT-DFC.git
cd PMT-DFC
bash deploy/install-vps.sh "$AUTH_KEY"
```

This builds from source (requires Go), creates a systemd service, and opens the firewall.

### Option C: Manual

```bash
make server
sudo cp bin/pmt-server /usr/local/bin/
sudo PMT_AUTH_KEY=$AUTH_KEY pmt-server
```

### Verify

```bash
curl http://localhost:8080/health
# → ok

# From another machine:
curl http://your-vps-ip:8080/health
# → ok
```

### TLS / HTTPS (optional but recommended)

The relay forwards over HTTPS. For Apps Script `UrlFetchApp` you can use plain HTTP (it accepts both), but Cloudflare Workers require HTTPS to `fetch()` a backend.

Use Caddy as a reverse proxy with automatic Let's Encrypt:

```bash
sudo apt install caddy
sudo tee /etc/caddy/Caddyfile <<EOF
your-vps-domain.com {
    reverse_proxy localhost:8080
}
EOF
sudo systemctl restart caddy
```

Then point your relay's `TUNNEL_SERVER_URL` at `https://your-vps-domain.com`.

---

## 2. Relay setup

### Option A: Apps Script (free, proven from censored networks)

1. Visit https://script.google.com
2. Create a new project.
3. Delete the default `Code.gs` content; paste from this repo's [`relay/apps-script/Code.gs`](../relay/apps-script/Code.gs).
4. Edit two constants at the top:
   - `TUNNEL_SERVER_URL = "https://your-vps-domain.com"` (or `http://YOUR_VPS_IP:8080`)
   - `AUTH_KEY = "..."` — same as VPS PMT_AUTH_KEY
5. Click **Deploy → New deployment**.
6. Settings:
   - Type: **Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**
7. Authorize the script (Google will prompt).
8. Copy the **Deployment ID** from the deployment URL. It looks like:
   `AKfycbz...long_string`
9. Save the Deployment ID for client config.

#### Multiple deployments for higher quota

Apps Script free quota: 20,000 UrlFetch calls/day per Google account. To scale:
- Create the same deployment in **separate Google accounts**.
- List all Deployment IDs in client config under `script_ids`.
- The client rotates between them, multiplying daily quota.

### Option B: Cloudflare Worker (free tier: 100K req/day)

```bash
cd relay/cloudflare-worker
# Edit wrangler.toml: set TUNNEL_SERVER_URL = "https://your-vps-domain.com"
# Set AUTH_KEY (or use `wrangler secret put AUTH_KEY` for production)

npm install -g wrangler
wrangler login         # opens browser for auth
wrangler deploy
```

Wrangler prints your Worker URL: `https://pmt-relay.YOUR-ACCOUNT.workers.dev`. Save it for client config.

---

## 3. Client setup

### Build

```bash
git clone https://github.com/easyfast2008/PMT-DFC.git
cd PMT-DFC
make client    # produces bin/pmt-client
```

For Windows:
```bash
GOOS=windows GOARCH=amd64 go build -o bin/pmt-client.exe ./cmd/client
```

### Configure

Create `client.json` next to the binary:

```json
{
  "listen": "127.0.0.1:8085",
  "relay": "apps_script",
  "script_id": "YOUR_DEPLOYMENT_ID",
  "auth_key": "YOUR_AUTH_KEY",
  "front_domain": "www.google.com",
  "front_ip": "216.239.38.120",
  "batch_interval_ms": 100
}
```

Or for Cloudflare Worker:
```json
{
  "listen": "127.0.0.1:8085",
  "relay": "cloudflare_worker",
  "worker_url": "https://pmt-relay.YOUR-ACCOUNT.workers.dev",
  "auth_key": "YOUR_AUTH_KEY",
  "front_domain": "www.google.com",
  "front_ip": "216.239.38.120"
}
```

### Run

```bash
./bin/pmt-client --config client.json
```

The client listens on `127.0.0.1:8085` for SOCKS5. Configure your browser/app to use this proxy.

```bash
# Test:
curl --proxy socks5h://127.0.0.1:8085 https://ifconfig.me
```

---

## 4. Cost

### Apps Script + VPS path
- Apps Script: **$0** (free, no GCP billing required)
- VPS: **€4/mo** (Hetzner CX11 — 20 TB egress included)
- **Total: ~€4/mo**

### Cloudflare Worker + VPS path
- CF Worker free tier: **$0** (100K req/day)
- VPS: **€4/mo**
- **Total: ~€4/mo**

### Scaling beyond free tiers
- Apps Script: free up to 20K calls/day/account. Use multiple accounts (free) to scale to ~100K+ calls/day.
- Cloudflare Workers: paid plan is **$5/mo** for 10M requests/month + unlimited duration.
- VPS bandwidth: 20 TB/mo included on Hetzner CX11. Most users will never hit this.

---

## 5. Troubleshooting

### Client can't reach relay
1. Run preflight: `./pmt-probe --mode=sweep --front-ip=216.239.38.120`
2. If all SNIs fail step 5: try `--mode=targets` to see which Google products are reachable
3. If `appspot.com` is BLOCKED-GEO from your network too: this approach won't work; consider a different transport

### "unauthorized" from server
- Auth key mismatch. Ensure all three (VPS, relay, client) use the **exact same** key.

### "connect: timeout" on every request
- VPS is unreachable from the relay's egress. Check VPS firewall (`ufw allow 8080/tcp`).
- For Cloudflare Worker: VPS must have HTTPS + valid cert (CF Workers can't `fetch()` self-signed).

### High latency
- Apps Script adds ~2-5s round-trip per batch. Increase `batch_interval_ms` to 200-500 to reduce request count.
- Or switch to Cloudflare Worker (~0.5-2s round-trip).
