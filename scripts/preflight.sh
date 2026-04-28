#!/usr/bin/env bash
#
# preflight.sh — answer "is domain-fronted Cloud Run feasible from MY
# network?" using only curl + openssl, without standing up any GCP
# infrastructure.
#
# Two modes:
#
#   MODE=single (default)
#     Runs the five-test feasibility battery against ONE front (SNI):
#       1. TCP/443 reachability to the front IP.
#       2. TLS handshake to the front (SNI=$FRONT, ALPN=h2 hinted).
#       3. HTTPS GET to the front itself (sanity).
#       4. Cross-origin Host routing: SNI=$FRONT, Host=clients4.google.com.
#          A 204 proves GFE still routes by Host across origins.
#       5. *.run.app routing: SNI=$FRONT, Host=<random>.run.app.
#          A Cloud Run-style 4xx proves Cloud Run is reachable via fronting.
#
#   MODE=sweep
#     Runs the same battery against MANY SNIs sharing one $FRONT_IP and
#     prints a pass/fail matrix with verdict per row.
#
# Configuration via env or first arg:
#   MODE      single | sweep. Default: single (or first CLI arg if "sweep").
#   FRONT     front domain — SNI value the firewall sees. Default: www.google.com.
#   FRONT_IP  optional fixed IP for the front. STRONGLY recommended on
#             censored networks where DNS is hostile.
#   FRONTS    sweep mode only — comma-separated SNI list. Default is the
#             baked-in Google login subdomain list.
#   PORT      front port. Default: 443.
#   TIMEOUT   per-step timeout in seconds. Default: 10.
#
# Exit codes:
#   0  all tests passed (single mode), or at least one front was feasible (sweep)
#   1  network/TLS error before any test could conclude
#   2  GFE intercepted somewhere → fronting is broken on this network
#   3  bad usage / missing tools

set -uo pipefail

FRONT="${FRONT:-www.google.com}"
FRONT_IP="${FRONT_IP:-}"
PORT="${PORT:-443}"
TIMEOUT="${TIMEOUT:-10}"
MODE="${MODE:-${1:-single}}"
DEFAULT_FRONTS="www.google.com,mail.google.com,drive.google.com,docs.google.com,calendar.google.com,accounts.google.com,scholar.google.com,maps.google.com,chat.google.com,translate.google.com,play.google.com,lens.google.com,chromewebstore.google.com"
FRONTS="${FRONTS:-$DEFAULT_FRONTS}"

c_ok="\033[0;32m"
c_err="\033[0;31m"
c_dim="\033[2m"
c_off="\033[0m"

if ! command -v curl >/dev/null; then echo "preflight: curl not found" >&2; exit 3; fi
if ! command -v openssl >/dev/null; then echo "preflight: openssl not found" >&2; exit 3; fi

# Resolve the front IP if not pinned. On hostile networks DNS may be
# poisoned, so prefer pinning FRONT_IP yourself.
if [[ -z "$FRONT_IP" ]]; then
  FRONT_IP="$(getent ahostsv4 "$FRONT" 2>/dev/null | awk 'NR==1{print $1}')"
  if [[ -z "$FRONT_IP" ]]; then
    FRONT_IP="$(getent hosts "$FRONT" 2>/dev/null | awk 'NR==1{print $1}')"
  fi
  if [[ -z "$FRONT_IP" ]]; then
    echo -e "${c_err}preflight: could not resolve $FRONT and FRONT_IP not set${c_off}" >&2
    exit 1
  fi
fi

# ------ test primitives ------
# Each returns 0/1; on failure prints a one-line error to stderr.

test_tcp() {
  timeout "$TIMEOUT" bash -c ">/dev/tcp/$FRONT_IP/$PORT" 2>/dev/null
}

test_tls() {
  local sni="$1"
  local out
  out=$(timeout "$TIMEOUT" openssl s_client \
    -connect "$FRONT_IP:$PORT" -servername "$sni" -alpn h2 \
    </dev/null 2>&1 || true)
  echo "$out" | grep -qE '(SSL handshake has read|Verify return code: 0)' || return 1
  echo "$out" | grep -qiE 'verify error|self.signed|unable to get' && return 1
  return 0
}

test_front() {
  local sni="$1"
  local status
  status=$(timeout "$TIMEOUT" curl -s -o /dev/null -w '%{http_code}' \
    --resolve "$sni:$PORT:$FRONT_IP" \
    --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
    "https://$sni/" || echo 000)
  [[ "$status" =~ ^(2|3) ]]
}

test_cross() {
  local sni="$1"
  local status
  status=$(timeout "$TIMEOUT" curl -s -o /dev/null -w '%{http_code}' \
    --resolve "$sni:$PORT:$FRONT_IP" \
    --connect-to "clients4.google.com:$PORT:$sni:$PORT" \
    --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
    "https://clients4.google.com/generate_204" || echo 000)
  [[ "$status" == "204" ]]
}

test_runapp() {
  local sni="$1"
  local fake="nonexistent-$(openssl rand -hex 6)-uc.a.run.app"
  local hdr_file body_file status server_hdr body_lower
  hdr_file=$(mktemp); body_file=$(mktemp)
  status=$(timeout "$TIMEOUT" curl -s -D "$hdr_file" -o "$body_file" -w '%{http_code}' \
    --resolve "$sni:$PORT:$FRONT_IP" \
    --connect-to "$fake:$PORT:$sni:$PORT" \
    --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" \
    "https://$fake/" || echo 000)
  server_hdr=$(awk -F': ' 'tolower($1)=="server"{print tolower($2)}' "$hdr_file" | tr -d '\r' | head -1)
  body_lower=$(tr '[:upper:]' '[:lower:]' < "$body_file" | head -c 4096)
  rm -f "$hdr_file" "$body_file"
  case "$body_lower$server_hdr" in
    *"cloud run"*|*"run.app"*|*"the requested url"*|*"google frontend"*|*"frontend"*) ;;
    *) [[ "$status" == "200" ]] && return 1 ;;
  esac
  [[ "$status" =~ ^4 ]]
}

# ------ runners ------

run_single() {
  local sni="$1"
  local fail=0 pass=0
  echo -e "${c_dim}front=$sni  front_ip=$FRONT_IP  port=$PORT${c_off}"
  echo
  echo -e "[1/5] TCP/443 to $FRONT_IP"
  if test_tcp; then echo -e "  ${c_ok}PASS${c_off}"; pass=$((pass+1));
  else echo -e "  ${c_err}FAIL${c_off}: TCP connect failed — firewall blocks the Google IP"; exit 1; fi
  echo -e "[2/5] TLS handshake (SNI=$sni, ALPN=h2 hinted)"
  if test_tls "$sni"; then echo -e "  ${c_ok}PASS${c_off}"; pass=$((pass+1));
  else echo -e "  ${c_err}FAIL${c_off}: TLS handshake / cert verify failed (likely TLS MITM)"; exit 2; fi
  echo -e "[3/5] HTTPS GET https://$sni/"
  if test_front "$sni"; then echo -e "  ${c_ok}PASS${c_off}"; pass=$((pass+1));
  else echo -e "  ${c_err}FAIL${c_off}: front did not return 2xx/3xx"; fail=$((fail+1)); fi
  echo -e "[4/5] cross-origin: SNI=$sni, Host=clients4.google.com /generate_204"
  if test_cross "$sni"; then echo -e "  ${c_ok}PASS${c_off}"; pass=$((pass+1));
  else echo -e "  ${c_err}FAIL${c_off}: GFE no longer routes by Host across origins"; fail=$((fail+1)); fi
  echo -e "[5/5] run.app routing: SNI=$sni, Host=<random>-uc.a.run.app /"
  if test_runapp "$sni"; then echo -e "  ${c_ok}PASS${c_off}"; pass=$((pass+1));
  else echo -e "  ${c_err}FAIL${c_off}: GFE did not route to Cloud Run"; fail=$((fail+1)); fi
  echo
  echo "---- summary ----"
  echo "pass: $pass / 5"
  echo "fail: $fail / 5"
  if [[ "$fail" == "0" ]]; then
    echo -e "${c_ok}feasible${c_off}: domain-fronted Cloud Run should work on this network."
    exit 0
  fi
  echo -e "${c_err}NOT feasible${c_off}: at least one critical step failed; do not deploy."
  exit 2
}

run_sweep() {
  echo -e "${c_dim}sweep front_ip=$FRONT_IP  port=$PORT${c_off}"
  echo
  printf '%-30s  %-3s %-3s %-5s %-5s %-6s  %s\n' "SNI" "tcp" "tls" "front" "cross" "runapp" "verdict"
  printf '%-30s  %-3s %-3s %-5s %-5s %-6s  %s\n' "------------------------------" "---" "---" "-----" "-----" "------" "-------"
  local any_ok=0
  IFS=',' read -ra list <<< "$FRONTS"
  for raw in "${list[@]}"; do
    local sni; sni=$(echo "$raw" | tr -d ' ')
    [[ -z "$sni" ]] && continue
    local r_tcp r_tls r_front r_cross r_run verdict
    if test_tcp;        then r_tcp=ok;   else r_tcp=X; fi
    if test_tls "$sni"; then r_tls=ok;   else r_tls=X; fi
    if test_front "$sni"; then r_front=ok; else r_front=X; fi
    if test_cross "$sni"; then r_cross=ok; else r_cross=X; fi
    if test_runapp "$sni"; then r_run=ok; else r_run=X; fi
    if [[ "$r_tcp" == "X" ]] || [[ "$r_tls" == "X" ]]; then
      verdict="BLOCKED"
    elif [[ "$r_cross" == "X" ]] || [[ "$r_run" == "X" ]]; then
      verdict="DO NOT USE"
    else
      verdict="FRONTING WORKS"
      any_ok=1
    fi
    printf '%-30s  %-3s %-3s %-5s %-5s %-6s  %s\n' "$sni" "$r_tcp" "$r_tls" "$r_front" "$r_cross" "$r_run" "$verdict"
  done
  echo
  if [[ "$any_ok" == "1" ]]; then
    echo -e "${c_ok}feasible${c_off}: at least one front passed all five tests; pick any FRONTING WORKS row."
    exit 0
  fi
  echo -e "${c_err}NOT feasible${c_off}: no front passed; fronting is dead on this network for this IP."
  exit 2
}

case "$MODE" in
  single)
    run_single "$FRONT"
    ;;
  sweep)
    run_sweep
    ;;
  *)
    echo "unknown MODE=$MODE (use single or sweep)" >&2
    exit 3
    ;;
esac
