#!/bin/sh
# The site router. It dials OUT to the hub (so it works from behind any NAT, like a 4G router would), keeps the
# tunnel alive with a persistent keepalive, and exposes exactly two camera ports to the tunnel through DNAT.
set -eu

HUB_ENDPOINT="hub:51820"
TUNNEL_IP="10.8.0.2"
HUB_TUNNEL_IP="10.8.0.1"
CAMERA_IP="10.20.0.10"
PORTS="8554,8889"          # RTSP and the WebRTC signalling page. Nothing else is reachable.

mkdir -p /keys
if [ ! -s /keys/edge.key ]; then
  umask 077
  wg genkey > /keys/edge.key
  wg pubkey < /keys/edge.key > /keys/edge.pub
fi
echo "edge: waiting for the hub's public key"
until [ -s /keys/hub.pub ]; do sleep 1; done

ip link add wg0 type wireguard
wg set wg0 private-key /keys/edge.key \
  peer "$(cat /keys/hub.pub)" endpoint "$HUB_ENDPOINT" allowed-ips "${HUB_TUNNEL_IP}/32" persistent-keepalive 10
ip addr add "${TUNNEL_IP}/24" dev wg0
ip link set wg0 mtu 1380 up

SITE_DEV="$(ip -o -4 addr show | awk '/10\.20\.0\.2\// {print $2}')"
echo "edge: site interface is ${SITE_DEV}"

# --- firewall: default deny, then only what the design needs -------------------------------------------------------
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i wg0 -p icmp -j ACCEPT                       # ping across the tunnel is allowed
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i wg0 -o "$SITE_DEV" -d "$CAMERA_IP" -p tcp -m multiport --dports "$PORTS" -j ACCEPT
# --- NAT: the hub dials the edge's tunnel address, the edge forwards to the camera and masquerades the source ------
iptables -t nat -A PREROUTING -i wg0 -p tcp -m multiport --dports "$PORTS" -j DNAT --to-destination "$CAMERA_IP"
iptables -t nat -A POSTROUTING -o "$SITE_DEV" -j MASQUERADE

echo "edge: up. tunnel ${TUNNEL_IP} -> hub ${HUB_TUNNEL_IP}, forwarding tcp ${PORTS} to ${CAMERA_IP}"
exec sleep infinity
