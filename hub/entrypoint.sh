#!/bin/sh
# The platform side. It is the WireGuard hub (it listens, the site routers dial in) and it runs the fleet monitor.
set -eu

TUNNEL_IP="10.8.0.1"
EDGE_TUNNEL_IP="10.8.0.2"

mkdir -p /keys
if [ ! -s /keys/hub.key ]; then
  umask 077
  wg genkey > /keys/hub.key
  wg pubkey < /keys/hub.key > /keys/hub.pub
fi
echo "hub: waiting for the edge's public key"
until [ -s /keys/edge.pub ]; do sleep 1; done

ip link add wg0 type wireguard
wg set wg0 private-key /keys/hub.key listen-port 51820 \
  peer "$(cat /keys/edge.pub)" allowed-ips "${EDGE_TUNNEL_IP}/32"
ip addr add "${TUNNEL_IP}/24" dev wg0
ip link set wg0 mtu 1380 up
echo "hub: wg0 up on ${TUNNEL_IP}, waiting for the edge to dial in"

exec python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level info
