# Deployment Guide

This document walks through deploying PMT-DFC end-to-end on Google
Cloud Run, then configuring a local client.

## 0. Prerequisites

* A GCP project with billing enabled.
* `gcloud` authenticated as a principal that can create services in
  Cloud Run, Artifact Registry repos, Secret Manager secrets, and grant
  IAM bindings on those resources. The `Owner` role is sufficient; for
  least-privilege, the union of `roles/run.admin`,
  `roles/artifactregistry.admin`, `roles/secretmanager.admin`, and
  `roles/cloudbuild.builds.editor` works.
* `docker` (only if you want to run the server image locally).
* `openssl` (only if you want to generate a fresh PSK manually).

## 1. Pre-deployment feasibility battery

**Run this before deploying anything.** It does not require a Cloud
Run service to exist — it tests the path the tunnel will use against
well-known Google endpoints.

```sh
# from the censored network where the client will run:
bash scripts/preflight.sh

# or, equivalently, the Go binary:
./bin/pmt-probe --mode=all --front=www.google.com
```

Both run a five-step battery:

1. **TCP/443 to the front IP** — proves you can reach Google at all.
2. **TLS handshake with SNI=front, ALPN=h2** — proves no TLS MITM and
   that h2 is reachable.
3. **HTTPS GET to the front itself** — sanity that the front is up.
4. **SNI=front, Host=`clients4.google.com` `/generate_204`** — must
   return 204. Proves GFE still routes by `Host` across origins.
5. **SNI=front, Host=`nonexistent-<rand>-uc.a.run.app` `/`** — must
   return a Cloud Run-style 4xx. Proves GFE routes fronted requests
   into the Cloud Run frontend specifically. (404 is the expected
   status because the random hostname has no service behind it; what
   matters is that the response *came from Cloud Run*, not Google's
   own front HTML.)

If steps 1–3 fail, your network blocks Google or MITMs TLS — abort.
If 4 fails but 1–3 pass, GFE no longer accepts cross-origin Host
routing; try alternate fronts (`*.appspot.com`, `*.firebaseapp.com`,
`*.gstatic.com`, `fonts.googleapis.com`) by changing `--front` / the
`FRONT` env var.
If 5 fails specifically, GFE still routes by Host but not into Cloud
Run from this front — try the alternate fronts above; some are more
willing to route into `*.run.app` than others.
If 4 *and* 5 fail under all fronts, fronting is dead on this network
and no software in this repo can rescue it. Abort.

### Pinning a Google IP

Both probes will use system DNS by default. On hostile networks DNS
itself may be poisoned. Pass an IP explicitly:

```sh
FRONT_IP=142.251.150.119 bash scripts/preflight.sh
./bin/pmt-probe --mode=all --front-ip=142.251.150.119
```

Find a working Google IP from a clean network with
`dig www.google.com +short` and try a few — Google has hundreds of
GFE IPs, and your firewall may permit only some of them.

## 2. One-shot deploy

```sh
PROJECT_ID=my-project \
REGION=us-central1 \
SERVICE=pmt-tunnel \
  ./deploy/deploy.sh
```

The script is idempotent. On first run it generates a fresh PSK, prints
it once, and stores it in Secret Manager. On subsequent runs it reuses
the existing secret and just rolls a new revision.

When it finishes, it prints the Cloud Run URL — note the hostname.

## 3. Re-probe with your real worker

```sh
./bin/pmt-probe \
  --front www.google.com \
  --worker pmt-tunnel-abc123-uc.a.run.app \
  --path /healthz
```

This proves end-to-end fronting reaches your specific service.

## 4. Configure the client

```sh
cp examples/client-config.json client.json
```

Edit `client.json`:

```json
{
  "front_domain": "www.google.com",
  "front_ip": "",
  "front_port": 443,
  "worker_host": "pmt-tunnel-abc123-uc.a.run.app",
  "tunnel_path": "/tunnel",
  "auth_key": "<PSK from step 2>",
  "listen": "127.0.0.1:8085",
  "log_level": "info"
}
```

Notes:

* `front_ip` is optional but recommended in environments where DNS is
  censored. Pin a Google IP that your network can reach (e.g. one of
  the Google Front End IPs from `dns.google.com` or
  `connectivitycheck.gstatic.com`). If unset, the system resolver is
  used to resolve `front_domain`.
* `front_domain` is the SNI value the firewall observes. It does not
  need to match `worker_host`.

## 5. Run the client and validate

```sh
./bin/pmt-client --config client.json
```

Then in another shell:

```sh
curl --proxy socks5h://127.0.0.1:8085 https://ifconfig.me
```

The returned IP should be a Google Cloud Run egress IP (Google's
own range), not your local public IP. If it matches your local IP,
something is wrong (most likely the proxy isn't being used).

For Firefox / Chromium, point them at SOCKS5 `127.0.0.1:8085` and
**enable remote DNS** (Firefox calls this "Proxy DNS when using
SOCKS v5"). This routes name resolution through the tunnel and avoids
DNS leaks to the censoring resolver.

## 6. Browser TLS and CAPTCHAs

Because each browser stream is a raw TCP relay (SOCKS5 inner +
`net.Dial` exit), the browser performs TLS to the *target* itself.
The target sees:

* a Cloud Run egress IP,
* the browser's real JA3/JA4 fingerprint,
* the browser's real cookie jar.

This is enough for clean sites. CAPTCHA-protected sites that block
data-center IPs will still challenge or block — see the headless-exit
roadmap in `Docs/architecture.md` §8.

## 7. Operational notes

* **Latency**: cold starts are ~1–3s with `min-instances=0`. Set it to
  1 (default in `deploy.sh`) for production. Once warm, end-to-end
  RTT to popular sites is typically 40–150ms.
* **Cost**: 1 Cloud Run instance with 1 vCPU + 512 MiB pinned warm
  ≈ $15–25/month before any traffic. Add per-request CPU + egress
  for actual usage. Compare with alternatives before enabling
  `min-instances`.
* **Carrier reconnects**: every reconnect breaks in-flight streams.
  Watch the client log for `tunnel: carrier closed; reconnecting` —
  if it happens more than a few times an hour, something on the
  network path is killing long-lived h2 streams.
* **Rotation**: to rotate the PSK, add a new version to Secret Manager
  and redeploy. Old clients will get 401s on their next reconnect and
  fail loudly.
* **Killing the service**: `gcloud run services delete $SERVICE
  --region=$REGION`. Secret + Artifact Registry repo persist; remove
  manually if desired.

## 8. Troubleshooting

| Symptom | Likely cause |
|--------|--------------|
| `pmt-client` exits with `tls handshake: ...` | Firewall blocks TLS to Google IP, or DNS isn't resolving the front. Try setting `front_ip` to a known Google IP. |
| Probe returns 200 with `<html>` | GFE intercepted; fronting broken. Try alternate front domains. |
| Probe returns 401 from worker | PSK mismatch (probe doesn't authenticate; this means GFE *did* route correctly to your worker — fronting works! Just expected 401 if you probed `/tunnel`). |
| Browser opens but pages hang | Likely DNS leak — verify "Proxy DNS when using SOCKS v5" is on. |
| Tunnel works but sites still CAPTCHA | Datacenter IP rep; need Phase 2 headless exit (not yet implemented). Use a different exit strategy in the meantime. |
| `tunnel: carrier closed; reconnecting` every few seconds | Server returning 401 (PSK mismatch), 426 (HTTP/1 by mistake), or your local clock is skewed >60s. |
