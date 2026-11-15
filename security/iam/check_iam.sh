#!/usr/bin/env bash
# Proves the IAM layer against the live stack and prints the counts.
#
#   bash security/iam/check_iam.sh [--project cfl-iam] [--no-up] [--no-browser]
#
# It starts the iam profile in its own compose project (unless --no-up), waits for Keycloak and the proxy to answer, then runs:
#   1  a curl check that an unauthenticated request is redirected to the login
#   2  shots.cjs: the same flow in a real Chromium, with a screenshot per step (docs/security/iam/*.png)
#   3  check_iam.py: every other check (wrong password, no OTP, wrong OTP, viewer 403, admin 200, token lifespan, lockout)
# Exit code 0 only when every check passes. It stops nothing it did not start: use `docker compose -p <project> --profile iam down`.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

PROJECT="cfl-iam"; UP=1; BROWSER=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --no-up) UP=0; shift ;;
    --no-browser) BROWSER=0; shift ;;
    *) echo "unknown argument: $1" >&2; exit 3 ;;
  esac
done

bash security/iam/setup.sh
if [[ $UP -eq 1 ]]; then
  docker compose -p "$PROJECT" --profile iam up -d --build || { echo "docker compose up failed" >&2; exit 3; }
fi

echo "waiting for Keycloak's realm and the proxy"
for i in $(seq 1 90); do
  kc=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8180/realms/camera-fleet/.well-known/openid-configuration || true)
  px=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4180/ping || true)
  [[ "$kc" == "200" && "$px" == "200" ]] && { echo "ready after ${i} s (keycloak $kc, proxy $px)"; break; }
  [[ $i -eq 90 ]] && { echo "not ready after 90 s (keycloak $kc, proxy $px)" >&2; exit 3; }
  sleep 1
done

fail=0
total=0; passed=0

echo "1. curl: an unauthenticated request"
loc=$(curl -s -o /dev/null -D - http://127.0.0.1:4180/ | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
total=$((total + 1))
if [[ "$loc" == http://localhost:8180/realms/camera-fleet/protocol/openid-connect/auth* ]]; then
  passed=$((passed + 1)); echo "  PASS  redirected to the Keycloak login   [${loc:0:70}]"
else
  fail=1; echo "  FAIL  not redirected to the login   [${loc}]"
fi

python security/iam/check_iam.py --reset-only || exit 3

if [[ $BROWSER -eq 1 ]]; then
  echo "2. real Chromium"
  if [[ -z "${PLAYWRIGHT_PATH:-}" ]]; then
    PLAYWRIGHT_PATH="$(node -e "try{console.log(require.resolve('playwright'))}catch(e){}" 2>/dev/null)"
    export PLAYWRIGHT_PATH
  fi
  out=$(node security/iam/shots.cjs docs/security/iam 2>&1); rc=$?
  echo "$out" | sed 's/^/  /'
  n=$(echo "$out" | grep -E -c '^(PASS|FAIL) ')
  p=$(echo "$out" | grep -c '^PASS ')
  total=$((total + n)); passed=$((passed + p))
  [[ $rc -eq 0 ]] || fail=1
  python security/iam/check_iam.py --reset-only || exit 3
fi

echo "3. the protocol checks"
out=$(python security/iam/check_iam.py --save docs/security/iam/check_iam_run.txt 2>&1); rc=$?
echo "$out" | sed 's/^/  /'
n=$(echo "$out" | grep -E -c '^  (PASS|FAIL)  ')
p=$(echo "$out" | grep -c '^  PASS  ')
total=$((total + n)); passed=$((passed + p))
[[ $rc -eq 0 ]] || fail=1

echo "live IAM checks passed: $passed of $total"
exit $fail
