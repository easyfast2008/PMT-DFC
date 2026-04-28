#!/usr/bin/env bash
#
# preflight.sh — answer "is domain-fronted Cloud Run feasible from MY
# network?" using only curl + openssl, without standing up any GCP
# infrastructure.
#
# Run this from the censored / restricted network you intend to deploy
# the tunnel from. It performs five tests in order:
#
#   1. TCP/443 reachability to a Google IP.
#   2. TLS handshake to the front (SNI=$FRONT), checking ALPN and cert.
#   3. HTTPS to the front itself (sanity).
#   4. Cross-origin Host routing: SNI=$FRONT, Host=clients4.google.com.
#      A 204 proves GFE still routes by Host across origins.
#   5. *.run.app routing: SNI=$FRONT, Host=<random>.run.app.
#      A Cloud Run-style 404 proves Cloud Run is reachable via fronting.
#
# Configuration via env:
#   FRONT     front domain — SNI value the firewall sees. Default: www.google.com.
#   FRONT_IP  optional fixed IP for the front. Strongly recommended on
#             censored networks where DNS is hostile. Find one with e.g.
#             `dig www.google.com @8.8.8.8 +short` from a clean network.
#   PORT      front port. Default: 443.
#   TIMEOUT   per-step timeout in seconds. Default: 10.
#
# Exit codes:
#   0  all tests passed → fronting is feasible
#   1  network/TLS error before any test could conclude
#   2  GFE intercepted somewhere → fronting is broken on this network
#   3  bad usage / missing tools

set -uo pipefail

FRONT="${FRONT:-www.google.com}"
FRONT_IP="${FRONT_IP:-}"
PORT="${PORT:-443}"
TIMEOUT="${TIMEOUT:-10}"

c_ok="\033[0;32m"
c_warn="\033[0;33m"
c_err="\033[0;31m"
c_dim="\033[2m"
c_off="\033[0m"

if ! command -v curl >/dev/null; then echo "preflight: curl not found" >&2; exit 3; fi
if ! command -v openssl >/dev/null; then echo "preflight: openssl not found" >&2; exit 3; fi

# Resolve front IP if not given. Done from THIS network — if DNS is censored
# the result may be a poisoned IP, in which case set FRONT_IP yourself.
if [[ -z "$FRONT_IP" ]]; then
  # Prefer IPv4 (more universally reachable through firewalls); fall back to
  # whatever getent returns.
  FRONT_IP="$(getent ahostsv4 "$FRONT" 2>/dev/null | awk 'NR==1{print $1}')"
  if [[ -z "$FRONT_IP" ]]; then
    FRONT_IP="$(getent hosts "$FRONT" 2>/dev/null | awk 'NR==1{print $1}')"
  fi
  if [[ -z "$FRONT_IP" ]]; then
    echo -e "${c_err}preflight: could not resolve $FRONT and FRONT_IP not set${c_off}" >&2
    exit 1
  fi
fi

echo -e "${c_dim}front=$FRONT  front_ip=$FRONT_IP  port=$PORT${c_off}"
echo

fail=0
pass=0
mark_pass() { pass=$((pass+1)); echo -e "  ${c_ok}PASS${c_off}"; }
mark_fail() { fail=$((fail+1)); echo -e "  ${c_err}FAIL${c_off}: $*"; }

# 1. TCP reachability.
echo -e "[1/5] TCP/443 to $FRONT_IP"
if timeout "$TIMEOUT" bash -c ">/dev/tcp/$FRONT_IP/$PORT" 2>/dev/null; then
  mark_pass
else
  mark_fail "TCP connect to $FRONT_IP:$PORT failed — your firewall blocks the Google IP outright"
  exit 1
fi

# 2. TLS handshake to the front.
echo -e "[2/5] TLS handshake (SNI=$FRONT)"
tls_out=$(timeout "$TIMEOUT" openssl s_client \
  -connect "$FRONT_IP:$PORT" \
  -servername "$FRONT" \
  -alpn h2 </dev/null 2>&1 || true)
if echo "$tls_out" | grep -qE '(SSL handshake has read|Verify return code: 0)'; then
  echo "$tls_out" | grep -E 'subject=|issuer=|Protocol|Cipher|Verify return code|ALPN' | head -8 | sed 's/^/  /'
  if echo "$tls_out" | grep -qiE 'verify error|self.signed|unable to get'; then
    mark_fail "cert verification failed — likely TLS MITM by your firewall"
    exit 2
  fi
  mark_pass
else
  mark_fail "TLS handshake failed"
  echo "$tls_out" | tail -15 | sed 's/^/  /'
  exit 1
fi

# 3. HTTPS to the front itself.
echo -e "[3/5] HTTPS GET https://$FRONT/ (sanity)"
status=$(timeout "$TIMEOUT" curl -s -o /dev/null -w '%{http_code}' \
  --resolve "$FRONT:$PORT:$FRONT_IP" \
  --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
  "https://$FRONT/" || echo 000)
echo "  status=$status"
if [[ "$status" =~ ^(2|3) ]]; then
  mark_pass
else
  mark_fail "front itself did not return 2xx/3xx"
fi

# 4. Cross-origin Host routing.
echo -e "[4/5] cross-origin: SNI=$FRONT, Host=clients4.google.com /generate_204"
status=$(timeout "$TIMEOUT" curl -s -o /dev/null -w '%{http_code}' \
  --resolve "$FRONT:$PORT:$FRONT_IP" \
  --connect-to "clients4.google.com:$PORT:$FRONT:$PORT" \
  --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
  "https://clients4.google.com/generate_204" || echo 000)
echo "  status=$status"
if [[ "$status" == "204" ]]; then
  mark_pass
else
  mark_fail "cross-origin Host routing did not return 204 — GFE may not be routing by Host any more"
fi

# 5. run.app routing — non-existent service.
fake_host="nonexistent-$(openssl rand -hex 6)-uc.a.run.app"
echo -e "[5/5] run.app: SNI=$FRONT, Host=$fake_host /"
hdr_file="$(mktemp)"
body_file="$(mktemp)"
trap "rm -f $hdr_file $body_file" EXIT
status=$(timeout "$TIMEOUT" curl -s -D "$hdr_file" -o "$body_file" -w '%{http_code}' \
  --resolve "$FRONT:$PORT:$FRONT_IP" \
  --connect-to "$fake_host:$PORT:$FRONT:$PORT" \
  --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
  "https://$fake_host/" || echo 000)
server_hdr=$(awk -F': ' 'tolower($1)=="server"{print tolower($2)}' "$hdr_file" | tr -d '\r' | head -1)
echo "  status=$status  server=$server_hdr"
body_lower=$(tr '[:upper:]' '[:lower:]' < "$body_file" | head -c 4096)
runappish=0
case "$body_lower" in
  *"cloud run"*|*"run.app"*|*"the requested url"*) runappish=1 ;;
esac
case "$server_hdr" in
  *"google frontend"*|*"frontend"*) runappish=1 ;;
esac
if [[ "$status" =~ ^4 ]] && [[ "$runappish" == "1" ]]; then
  mark_pass
elif [[ "$status" == "200" ]]; then
  mark_fail "got 200 from a non-existent run.app host — GFE served the front instead of routing to Cloud Run"
else
  mark_fail "did not get a Cloud Run-style 4xx (status=$status server=$server_hdr)"
fi

echo
echo "---- summary ----"
echo "pass: $pass / 5"
echo "fail: $fail / 5"
if [[ "$fail" == "0" ]]; then
  echo -e "${c_ok}feasible${c_off}: domain-fronted Cloud Run should work on this network."
  exit 0
fi
echo -e "${c_err}not feasible${c_off}: at least one critical step failed; do not deploy."
exit 2
