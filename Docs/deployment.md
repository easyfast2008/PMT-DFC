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

## 1. Pre-deployment fronting probe

Before deploying anything, verify that SNI fronting still reaches Cloud
Run on your client network. Use a `*.run.app` host you already know
exists (any service in any project — the probe just needs to confirm
GFE routes by Host).

```sh
./bin/pmt-probe \
  --front www.google.com \
  --worker some-known-service-abc123-uc.a.run.app \
  --path / --expect 404
```

* **PASS** → GFE routes by Host header. Continue.
* **FAIL with `got status 200`** and a `www.google.com` body → GFE
  ignored the Host header and served the front. Fronting is broken
  on your network. Try alternate fronts (`*.appspot.com`,
  `*.firebaseapp.com`, `*.firebaseio.com`) by changing `--front`. If
  none work, abort: this design cannot function without fronting.
* **FAIL with TLS error** → Your firewall is blocking TLS to the
  Google IP, or doing TLS MITM. Abort.

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
