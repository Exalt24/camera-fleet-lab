FROM alpine:3.24
RUN apk add --no-cache wireguard-tools iproute2 iptables iputils tcpdump conntrack-tools bind-tools
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
