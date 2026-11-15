#!/usr/bin/env bash
# Runs the Nuclei scanner (official image, pinned) against the lab's own exposed services and nothing else.
#
#   bash security/vuln/scan.sh --project cfl-iam                    # scan the services of that compose project
#   bash security/vuln/scan.sh --project cfl-iam --out docs/security/vuln
#   bash security/vuln/scan.sh --check-scope http://127.0.0.1:8100  # only run the scope guard (no Docker); exit 2 if refused
#
# Scope guard: every target must be http(s) with an IP literal that is on a loopback address (127.0.0.0/8, ::1) or inside one of
# the lab's own Docker subnets from docker-compose.yml (wan 172.30.0.0/24, site 10.20.0.0/24, db 10.40.0.0/24, iam 10.50.0.0/24,
# tunnel 10.8.0.0/24). A host NAME is refused unless it is `localhost`, because a name can resolve anywhere. A single refused
# target stops the whole run before anything is sent.
#
# Exit codes: 0 scan finished (findings or not, they are data, not a failure), 1 the scan itself failed, 2 a target was refused,
# 3 a prerequisite is missing (Docker, the project's containers).
set -uo pipefail

NUCLEI_IMAGE="${NUCLEI_IMAGE:-projectdiscovery/nuclei:v3.11.1}"
LAB_CIDRS=("127.0.0.0/8" "172.30.0.0/24" "10.20.0.0/24" "10.40.0.0/24" "10.50.0.0/24" "10.8.0.0/24")
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

ip_to_int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a << 24) | (b << 16) | (c << 8) | d )); }

in_cidr() {   # in_cidr <ipv4> <cidr>
  local ip="$1" net="${2%/*}" bits="${2#*/}"
  local mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  [[ $(( $(ip_to_int "$ip") & mask )) -eq $(( $(ip_to_int "$net") & mask )) ]]
}

# scope_ok <url>: prints the reason on stderr when it refuses. Returns 0 only for an http(s) URL on a loopback or lab address.
scope_ok() {
  local url="$1"
  if [[ ! "$url" =~ ^https?://([^/:@?#]+|\[[0-9a-fA-F:]+\])(:[0-9]{1,5})?(/[^[:space:]]*)?$ ]]; then
    echo "refused: '$url' is not a plain http(s) URL (no credentials, no spaces, an explicit host)" >&2; return 1
  fi
  local host="${BASH_REMATCH[1]}"
  host="${host#[}"; host="${host%]}"
  if [[ "$host" == "localhost" || "$host" == "::1" ]]; then return 0; fi
  if [[ "$host" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    local o
    for o in "${BASH_REMATCH[@]:1:4}"; do
      # a leading zero is read as octal by some tools (010.050.0.1 would be 8.40.0.1), so it is refused rather than guessed
      if [[ ${#o} -gt 1 && "$o" == 0* ]] || (( 10#$o > 255 )); then echo "refused: '$host' is not a plain dotted-decimal IPv4 address" >&2; return 1; fi
    done
    local cidr
    for cidr in "${LAB_CIDRS[@]}"; do
      if in_cidr "$(printf '%d.%d.%d.%d' "$((10#${BASH_REMATCH[1]}))" "$((10#${BASH_REMATCH[2]}))" "$((10#${BASH_REMATCH[3]}))" "$((10#${BASH_REMATCH[4]}))")" "$cidr"; then return 0; fi
    done
    echo "refused: $host is not on a loopback address or in the lab's subnets (${LAB_CIDRS[*]})" >&2; return 1
  fi
  echo "refused: '$host' is a host name; only localhost or an IP literal inside the lab are allowed" >&2; return 1
}

usage() { sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

PROJECT=""; OUT="$ROOT/docs/security/vuln"; EXTRA=(); CHECK_ONLY=0; TEMPLATE_IDS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --template-id) TEMPLATE_IDS="$2"; shift 2 ;;      # run only these templates, e.g. to check a fix (comma separated)
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

command -v docker >/dev/null 2>&1 || { echo "docker is not installed or not on PATH" >&2; exit 3; }

# --- find the project's own containers (never anything else) and build the target list from their addresses
container_ip() {   # container_ip <service> <network suffix>
  docker ps --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.service=$1" --format '{{.Names}}' | head -n1 | while read -r name; do
    [[ -n "$name" ]] && docker inspect "$name" --format "{{ (index .NetworkSettings.Networks \"${PROJECT}_$2\").IPAddress }}" 2>/dev/null
  done
}
TARGETS=(); NETS=()
add_target() {   # add_target <service> <network> <port> <label>
  local ip; ip="$(container_ip "$1" "$2")"
  if [[ -n "$ip" ]]; then
    TARGETS+=("http://$ip:$3"); echo "target: $4 -> http://$ip:$3"
    [[ " ${NETS[*]-} " == *" ${PROJECT}_$2 "* ]] || NETS+=("${PROJECT}_$2")
  else
    echo "skipped: $4 (no running '$1' container in project $PROJECT)"
  fi
}
add_target hub wan 8000 "monitor (FastAPI, the dashboard and API)"
add_target oauth2-proxy iam 4180 "SSO proxy (oauth2-proxy)"
add_target keycloak iam 8080 "identity provider (Keycloak)"
for t in "${EXTRA[@]+"${EXTRA[@]}"}"; do TARGETS+=("$t"); done
[[ ${#TARGETS[@]} -gt 0 ]] || { echo "no lab service is running in project $PROJECT; start it first" >&2; exit 3; }
for t in "${TARGETS[@]}"; do scope_ok "$t" || exit 2; done     # again, on the final list

mkdir -p "$OUT"; rm -f "$OUT/nuclei_results.jsonl" "$OUT/nuclei_summary.txt"
HOST_OUT="$(cd "$OUT" && { pwd -W 2>/dev/null || pwd; })"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%s\n' "${TARGETS[@]}" > "$OUT/.targets.txt"
HOST_TARGETS="$(cd "$OUT" && { pwd -W 2>/dev/null || pwd; })/.targets.txt"
export MSYS_NO_PATHCONV=1

# templates live in a named volume so a second run does not download them again
CID="$(docker create --network "${NETS[0]}" -v "cfl-nuclei-templates:/root/nuclei-templates" -v "$HOST_OUT:/out" \
  "$NUCLEI_IMAGE" -l /out/.targets.txt -jsonl -o /out/nuclei_results.jsonl \
  -rate-limit 40 -concurrency 10 -timeout 10 -retries 1 -no-color -no-interactsh \
  -etags dos,fuzz -exclude-severity unknown ${TEMPLATE_IDS:+-id "$TEMPLATE_IDS"} 2>/dev/null)" || { echo "could not create the nuclei container" >&2; exit 1; }
for n in "${NETS[@]:1}"; do docker network connect "$n" "$CID" || { docker rm -f "$CID" >/dev/null; echo "could not attach nuclei to $n" >&2; exit 1; }; done
echo "nuclei image: $NUCLEI_IMAGE   started: $STAMP"

docker start -a "$CID" > "$OUT/nuclei_run.log" 2>&1
RC=$?
VER="$(docker run --rm "$NUCLEI_IMAGE" -version 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\r' | grep -i 'Engine Version' | head -n1)"
docker rm -f "$CID" >/dev/null 2>&1
rm -f "$OUT/.targets.txt"

if [[ $RC -ne 0 ]]; then
  echo "nuclei failed with exit code $RC; see $OUT/nuclei_run.log" >&2
  tail -n 20 "$OUT/nuclei_run.log" >&2
  exit 1
fi

COUNT=0; [[ -s "$OUT/nuclei_results.jsonl" ]] && COUNT="$(wc -l < "$OUT/nuclei_results.jsonl" | tr -d ' ')"
{
  echo "scan: nuclei ($NUCLEI_IMAGE) $STAMP"
  echo "version output: $VER"
  echo "project: $PROJECT"
  printf 'target: %s\n' "${TARGETS[@]}"
  echo "findings: $COUNT (JSON lines in nuclei_results.jsonl)"
} > "$OUT/nuclei_summary.txt"
cat "$OUT/nuclei_summary.txt"
exit 0
