# Debugging notes

Two faults injected into the lab, how each one looks from the outside, the commands that separate them, and the one
wrong assumption I made on the way. All command output below is copied from `docs/debugging_capture.txt`, which
`scripts/capture_debugging.py` writes from a real run; nothing here is remembered or tidied.

The two faults look identical to a person who only has a stream URL: the video stops. They have different causes and
different fixes, which is why the monitor checks layer by layer (tunnel, then port, then video).

## Fault A: the VPN drops

**Cause injected:** WireGuard UDP is blocked on the site router (`iptables -I OUTPUT 1 -p udp --dport 51820 -j DROP`).
It stands in for a 4G link going away, a carrier blocking the port, or the router losing its route.

**What the monitor shows:** the first symptom is a stalled stream, so for one cycle it reports `degraded`
(`ffprobe timed out`), because packets already in flight still cross. The next cycle the ping through the tunnel gets no
answer and it reports `tunnel_down` ("no packet crosses the VPN"), and the port and video layers are not even checked.
Across two end-to-end runs that took **13 s** and **4 s** from the block to `tunnel_down` (it depends where in the 5 s
probe cycle the block lands).

**Commands that confirm it, and what they printed:**

```
$ docker compose exec edge iptables -L OUTPUT -n -v      # the DROP rule's packet counter
Chain OUTPUT (policy ACCEPT 6320 packets, 5218K bytes)
    3   432 DROP       17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:51820
```

The counter is the useful part: the edge **is** trying to send WireGuard packets and the firewall is eating them.

```
$ docker compose exec edge timeout 8 tcpdump -ni eth0 -c 6 udp port 51820
0 packets captured
```

Nothing at all crosses the edge's WAN interface on the WireGuard port. That is consistent with a dead path, but on its own
it does not say *which* end stopped, so the counter above is what points at the local firewall.

**Recovery:** remove the rule and WireGuard re-handshakes without anyone touching it. `scripts/measure_recovery.py`
blocks for 40 s, unblocks, and sees a fresh handshake on both ends in about **5 s**.

## Fault B: the NAT rule disappears, the tunnel is healthy

**Cause injected:** the DNAT rule that forwards the tunnel address to the camera is deleted
(`iptables -t nat -D PREROUTING ...`). It stands in for a config push that wipes the rules, a router reboot that loses
them, or someone "cleaning up" the firewall.

**What the monitor shows:** `blocked`, detected after **8 s**. The tunnel layer is green (the ping crosses), the port layer
is red with `tcp connect timed out (packets dropped, not refused)`, and the video layer is not checked.

**Commands that confirm it:**

```
$ docker compose exec edge timeout 9 tcpdump -ni wg0 -c 8 'tcp port 8554 or icmp'
18:58:54.492082 IP 10.8.0.1 > 10.8.0.2: ICMP echo request, id 346, seq 1, length 64
18:58:54.492144 IP 10.8.0.2 > 10.8.0.1: ICMP echo reply, id 346, seq 1, length 64
18:58:54.492795 IP 10.8.0.1.57300 > 10.8.0.2.8554: Flags [S], seq 2530819566, ...
18:58:55.513997 IP 10.8.0.1.57300 > 10.8.0.2.8554: Flags [S], seq 2530819566, ...
18:58:56.538078 IP 10.8.0.1.57300 > 10.8.0.2.8554: Flags [S], seq 2530819566, ...
```

That capture is the whole diagnosis. The ping is answered, so the VPN is fine. The SYN to port 8554 arrives and is
**retransmitted at 1 s and 2 s with no SYN-ACK and no RST**, so something on the edge is dropping it silently instead of
refusing it. A closed port would have answered with a reset. Silence points at a firewall policy or a missing forward, not
at the camera.

```
$ docker compose exec edge iptables -t nat -L PREROUTING -n -v
Chain PREROUTING (policy ACCEPT 49 packets, 3684 bytes)
 pkts bytes target     prot opt in     out     source               destination
```

The NAT chain is empty: there is no rule left that translates the tunnel address to the camera. Restoring it
(`iptables -t nat -A PREROUTING ...`) brought the stream back after **8 s**.

## Telling the two apart, in one sentence

If a ping through the tunnel still works but the port is silent, it is **not** the VPN. Fault A and fault B both end
in "the video stopped", but only fault A breaks the ping.

## The wrong assumption (found by measuring)

My first version of the monitor called the tunnel *stale* when the last WireGuard handshake was older than 30 s. I had
reasoned: "persistent keepalive is 10 s, so a healthy tunnel is never more than 30 s from a handshake." That is false.

The probe history said so before I understood why:

```
18:36:13  state=down  tcp=True  rtsp=True  handshake_age=32.8
18:37:49  state=up    tcp=True  rtsp=True  handshake_age=8.8
18:40:15  state=down  tcp=True  rtsp=True  handshake_age=32.7
```

`state=down` with `tcp=True rtsp=True`: a camera streaming fine, reported dead, then "recovering" on its own every couple of
minutes. Persistent keepalive sends an empty packet to hold the NAT mapping open; it does **not** start a new handshake.
WireGuard re-handshakes roughly every 120 s while traffic flows, and a session cannot outlive 180 s, so a healthy tunnel's
handshake age wanders from 0 up to about 3 minutes.

The same bug also hid fault A's recovery from my first end-to-end run: after the VPN came back the monitor stayed "down"
for most of each rekey cycle, so the check that waited for `up` timed out at 90 s while the tunnel had recovered in 5 s.

**The fix** was to stop inferring tunnel health from a timestamp and send a packet through it (a ping), and to keep the
handshake age as information. `test_a_healthy_tunnel_with_an_old_handshake_is_still_up` pins it, and a 5.5-minute no-fault
soak (`scripts/soak_summary.py`) now shows 43 probes, all `up`, with the handshake age climbing to 118 s and resetting
twice.

## Other things the lab caught

- **The monitor was silent.** uvicorn configures only its own loggers, so the application's `INFO` lines never appeared. I
  found out because I went to read the probe log to debug the problem above and there was nothing in it.
- **A dependency with no wheel for the Python version** (`asyncmy` on 3.13) failed to compile in the image build, and a
  pre-ping crash with the replacement driver pair needed a newer SQLAlchemy.
- **The first end-to-end run failed 4 of 15 checks.** Two were my test or image bugs (no `ping` in the hub image, a `302`
  before the WebRTC page's `200`) and two came from the model error above (the recovery check and the "tunnel still fresh" check).
- **A unit test that passed on Linux failed on Windows**, because Windows retries SYNs to a closed local port for about 2 s
  so "refused" looks like a timeout. It is skipped on Windows with the reason written beside it.
