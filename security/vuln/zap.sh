#!/usr/bin/env bash
# Runs an OWASP ZAP baseline scan (official image, pinned) against the lab's own HTTP services and nothing else.
# The baseline scan is passive: ZAP spiders the target and reads every response with its passive rules. It sends no attack payloads.
#
#   bash security/vuln/zap.sh --project cfl-iam                    # scan the hub and, if it answers, the SSO proxy of that compose project
#   bash security/vuln/zap.sh --project cfl-iam --out docs/security/vuln/zap/rescan --only hub
#   bash security/vuln/zap.sh --check-scope http://127.0.0.1:8100  # only run the scope guard (no Docker); exit 2 if refused
#
# Scope guard: security/vuln/scope_guard.sh, the same function scan.sh uses (loopback and the lab's own Docker subnets only, IP
# literals only, host names refused except localhost). It runs on every target before anything is sent, and a single refused target
# stops the whole run.
#
# Exit codes: 0 scan finished (alerts or not, they are data, not a failure; ZAP's own 1 and 2 mean alerts), 1 the scan itself failed
# (ZAP exit 3 or no JSON report), 2 a target was refused, 3 a prerequisite is missing (Docker, the project's containers).
set -uo pipefail

ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:2.17.0}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=security/vuln/scope_guard.sh
source "$HERE/scope_guard.sh"

usage() { sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

PROJECT=""; OUT="$ROOT/docs/security/vuln/zap"; EXTRA=(); CHECK_ONLY=0; ONLY=""; SPIDER_MINS=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;                      # hub or oauth2-proxy: scan just that service, e.g. to check a fix
    --spider-minutes) SPIDER_MINS="$2"; shift 2 ;;
    --target) EXTRA+=("$2"); shift 2 ;;
    --check-scope) CHECK_ONLY=1; EXTRA+=("$2"); shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 3 ;;
  esac
done

# --- the scope guard runs before anything else, on every target, including the ones passed by hand
for t in "${EXTRA[@]+"${EXTRA[@]}"}"; do
  scope_ok "$t" || exit 2
done
if [[ $CHECK_ONLY -eq 1 ]]; then echo "in scope: ${EXTRA[*]}"; exit 0; fi
[[ -n "$PROJECT" ]] || { echo "--project <compose project name> is required" >&2; exit 3; }
[[ -z "$ONLY" || "$ONLY" == "hub" || "$ONLY" == "oauth2-proxy" ]] || { echo "--only takes hub or oauth2-proxy" >&2; exit 3; }
[[ "$SPIDER_MINS" =~ ^[0-9]{1,2}$ ]] || { echo "--spider-minutes takes a whole number" >&2; exit 3; }

command -v docker >/dev/null 2>&1 || { echo "docker is not installed or not on PATH" >&2; exit 3; }

# --- find the project's own containers (never anything else) and build the target list from their addresses
container_ip() {   # container_ip <service> <network suffix>
  docker ps --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$1" --format '{{.Names}}' | head -n1 | while read -r name; do
    [[ -n "$name" ]] && docker inspect "$name" --format "{{ (index .NetworkSettings.Networks \"${PROJECT}_$2\").IPAddress }}" 2>/dev/null
  done
}
LABELS=(); TARGETS=(); NETS=(); MODES=()
add_target() {   # add_target <service> <network> <port> <label> [path] [zap-baseline mode flags]
  [[ -z "$ONLY" || "$ONLY" == "$1" ]] || return 0
  local ip; ip="$(container_ip "$1" "$2")"
  if [[ -n "$ip" ]]; then
    LABELS+=("$1"); TARGETS+=("http://$ip:$3${5:-}"); NETS+=("${PROJECT}_$2"); MODES+=("${6-}"); echo "target: $4 -> http://$ip:$3${5:-}"
  else
    echo "skipped: $4 (no running '$1' container in project $PROJECT)"
  fi
}
add_target hub wan 8000 "monitor (FastAPI, the dashboard and API)" "" "-j"
# the proxy answers / with a redirect to http://localhost:8180, which the scanner container cannot reach, so ZAP cannot start there;
# /ping answers 200 itself, so that is where the scan of the proxy starts
add_target oauth2-proxy iam 4180 "SSO proxy (oauth2-proxy), from its /ping page" /ping "--autooff"
for t in "${EXTRA[@]+"${EXTRA[@]}"}"; do LABELS+=("extra$((${#LABELS[@]} + 1))"); TARGETS+=("$t"); NETS+=("${PROJECT}_wan"); MODES+=("-j"); done
[[ ${#TARGETS[@]} -gt 0 ]] || { echo "no lab service is running in project $PROJECT; start it first" >&2; exit 3; }
for t in "${TARGETS[@]}"; do scope_ok "$t" || exit 2; done     # again, on the final list

mkdir -p "$OUT"
HOST_OUT="$(cd "$OUT" && { pwd -W 2>/dev/null || pwd; })"   # docker.exe wants a Windows path for `docker cp` under Git Bash
export MSYS_NO_PATHCONV=1
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "zap image: $ZAP_IMAGE   started: $STAMP"

# ZAP's own settings: no update check and no telemetry call from inside the scanner. The reports are copied out with `docker cp`
# instead of a bind mount, so the folder's permissions on the host never matter.
ZAP_OPTS="-config start.checkForUpdates=false -config telemetry.enabled=false"
FAILED=0; : > "$OUT/zap_run.log"
for i in "${!TARGETS[@]}"; do
  label="${LABELS[$i]}"; target="${TARGETS[$i]}"
  rm -f "$OUT/zap_$label.json" "$OUT/zap_$label.html" "$OUT/zap_$label.md"
  echo "== $label: $target" | tee -a "$OUT/zap_run.log"
  CID="$(docker create --network "${NETS[$i]}" "$ZAP_IMAGE" sh -c "mkdir -p /zap/wrk && cd /zap && zap-baseline.py -t '$target' -m $SPIDER_MINS ${MODES[$i]} \
    -J zap_$label.json -r zap_$label.html -w zap_$label.md -z '$ZAP_OPTS'" 2>/dev/null)" || { echo "could not create the ZAP container" >&2; exit 1; }
  docker start -a "$CID" >> "$OUT/zap_run.log" 2>&1
  RC=$?
  # zap-baseline.py: 0 clean, 1 a rule set to FAIL fired, 2 warnings, 3 anything else. 1 and 2 are findings, so they are data.
  for ext in json html md; do docker cp "$CID:/zap/wrk/zap_$label.$ext" "$HOST_OUT/zap_$label.$ext" >/dev/null 2>&1; done
  docker rm -f "$CID" >/dev/null 2>&1
  echo "zap exit code for $label: $RC" | tee -a "$OUT/zap_run.log"
  if [[ $RC -gt 2 || ! -s "$OUT/zap_$label.json" ]]; then
    echo "ZAP failed on $label (exit code $RC or no JSON report); see $OUT/zap_run.log" >&2
    tail -n 20 "$OUT/zap_run.log" >&2
    FAILED=1
  fi
done
[[ $FAILED -eq 0 ]] || exit 1

# the numbers in the summary are read from the JSON reports by zap_summary.py, not typed
PY=""   # on Windows `python3` can be the Store stub that only prints an install hint, so each candidate is run once
for cand in python3 python py; do command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys' >/dev/null 2>&1 && { PY="$cand"; break; }; done
[[ -n "$PY" ]] || { echo "python is needed to write the summary" >&2; exit 3; }
{
  echo "scan: OWASP ZAP baseline, passive ($ZAP_IMAGE) $STAMP"
  echo "project: $PROJECT"
  for i in "${!TARGETS[@]}"; do
    echo "target: ${TARGETS[$i]} (${LABELS[$i]})"
    ( unset MSYS_NO_PATHCONV; "$PY" "$HERE/zap_summary.py" "$OUT/zap_${LABELS[$i]}.json" )   # a Windows python needs Git Bash to convert the paths
  done
} > "$OUT/zap_summary.txt"
cat "$OUT/zap_summary.txt"
exit 0
