#!/usr/bin/env bash
# The scope guard shared by the scanners (scan.sh for Nuclei, zap.sh for OWASP ZAP). Sourced, never run on its own.
#
# A target must be http(s) with an IP literal on a loopback address (127.0.0.0/8, ::1) or inside one of the lab's own Docker subnets
# from docker-compose.yml (wan 172.30.0.0/24, site 10.20.0.0/24, db 10.40.0.0/24, iam 10.50.0.0/24, tunnel 10.8.0.0/24). A host NAME is
# refused unless it is `localhost`, because a name can resolve anywhere. security/tests/test_scan_scope.py runs the same cases against
# both scanners, so the two cannot drift apart.
LAB_CIDRS=("127.0.0.0/8" "172.30.0.0/24" "10.20.0.0/24" "10.40.0.0/24" "10.50.0.0/24" "10.8.0.0/24")

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
