# camera-fleet-lab

[![CI](https://github.com/Exalt24/camera-fleet-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/Exalt24/camera-fleet-lab/actions/workflows/ci.yml)

Docker model of a remote camera site behind a WireGuard VPN, with a monitor that says which layer broke.

![the monitor through a VPN drop and a missing NAT rule, 60 seconds](docs/demo.gif)

*The dashboard through both faults: the VPN drops (`tunnel down`), recovers, then the NAT rule disappears (`blocked`) while the tunnel stays healthy. Full-quality clip: [`docs/demo.mp4`](docs/demo.mp4).*

**Proof:** `scripts/verify.py` runs 16 end-to-end checks and injects both faults. In `docs/last_run.json` (one run on one machine) the monitor called the VPN drop `tunnel_down` after 4 s. It called the removed NAT rule `blocked` after 8 s. An earlier run, which I did not save, took 13 s for the VPN drop.

Everything runs in Docker on one machine: kernel WireGuard, `iptables` NAT and firewall, an RTSP camera, an async FastAPI monitor, MariaDB and a mosquitto MQTT broker for the smart lock slice.

The site router dials out and holds its NAT mapping open with a persistent keepalive, the way a 4G router has to. The camera sits on an `internal` network the hub is not on. The only path to it is the tunnel, and only TCP 8554 (RTSP) and 8889 (the WebRTC page) are forwarded.

The networking is real Linux behaviour, arranged as a Docker model of the remote site (see [Scope and next steps](#scope-and-next-steps)).

[`DEBUGGING.md`](DEBUGGING.md) has the two injected faults and the commands used to tell them apart. It also covers the wrong assumption I made and measured my way out of.

## The idea: probe in layers

```
tunnel  ->  port (NAT)  ->  video
```

Each layer fails for a different reason and needs a different fix. The monitor checks them in order and reports the
first one that fails:

| State | Meaning | Where to look |
|---|---|---|
| `up` | video decodes through the tunnel | nothing |
| `degraded` | the port answers but no video decodes | the camera or its encoder |
| `blocked` | packets cross the VPN, the camera port is silent | the NAT rule, the firewall, the camera being off |
| `tunnel_down` | no packet crosses the VPN at all | WireGuard, keys, endpoint, the 4G link |

## Topology

The camera sits on a network the hub is not on. The only way to it is the tunnel and one DNAT rule.

```mermaid
flowchart LR
  subgraph platform["Platform side"]
    hub["hub<br/>FastAPI monitor + WireGuard 10.8.0.1"]
    db[("MariaDB<br/>probe history")]
  end
  subgraph site["Site (internal network 10.20.0.0/24, no route out)"]
    edge["edge router<br/>WireGuard 10.8.0.2<br/>default-deny firewall + NAT"]
    cam["camera 10.20.0.10<br/>RTSP 8554, WebRTC page 8889"]
  end
  hub -- "WireGuard UDP 51820 (the edge dials out, keepalive 10 s)" --- edge
  edge -- "DNAT tcp 8554, 8889 then masquerade" --> cam
  hub --> db
```

Probe order on every cycle: ping through the tunnel, then a TCP connect to the camera port, then `ffprobe` over RTSP.
The first layer that fails is the one reported.

## Run it

Needs Docker with a kernel that has WireGuard (Docker Desktop's WSL2 kernel does). From this folder:

```
docker compose up -d --build
python scripts/verify.py          # 16 end-to-end checks, injects both faults, exit 0 only if all pass
# then open http://127.0.0.1:8100/ in a browser for the live dashboard
python scripts/measure_recovery.py 40     # block the VPN for 40 s and time the recovery
cd hub && pip install -r requirements.txt && pytest      # offline unit tests, no Docker needed
```

Short captioned screen recording of both faults: [`docs/demo.mp4`](docs/demo.mp4).

## Measured results

The first five rows are from `docs/last_run.json`, one run on one machine, so read them as orders of magnitude, not benchmarks. The 40 s block and the soak rows come from `scripts/measure_recovery.py` and `scripts/soak_summary.py`, which print to the terminal, and I did not save their output. The lock and doormat rows come from saved run files.

| Check | Result |
|---|---|
| Camera reachable only through the tunnel (no direct route from the hub) | pass |
| Stream decodes through the tunnel | h264 640x360 |
| Non-forwarded port on the site router | silently dropped |
| **Fault A**: WireGuard UDP blocked | detected as `tunnel_down` after **4 s** in the saved run (an earlier, unsaved run took 13 s: it depends where in the 5 s probe cycle the block lands, and whether the first symptom is a stalled stream that reads `degraded` for one cycle), recovered by itself **6.1 s** after unblocking |
| **Fault B**: DNAT rule removed (tunnel healthy) | detected as `blocked` after **8 s**, recovered **8.1 s** after the rule was restored |
| A 40 s VPN block, then unblocked | fresh handshake on both ends within **about 5 s** |
| Smart lock slice (`iot/`, one run, saved in `docs/iot/`) | 456 tests pass; 133 of 133 deliberate breakages turn a test red; the diagnosis tool named the induced layer in 17 of 17 runs |
| Smart doormat firmware (`esp32/`, one run, saved in `esp32/docs/test-runs/`) | 101 Unity tests and 61 host tests pass; 77 of 77 deliberate breakages turn a test red; the firmware boots in Espressif QEMU and prints the same 36 trace lines as the host build; the Wokwi simulator greeted a simulated step |
| No-fault soak, about 5.5 minutes (`scripts/soak_summary.py`) | 43 probes, every one `up`; the handshake age climbed to 118 s and reset twice (two WireGuard rekeys). The first version's 30 s threshold would have called most of this "down" |

`verify.py`: **16/16** checks. `pytest`: 22 passed, 1 skipped (the skip is OS-specific, see below).

## What I got wrong (and how the stack showed me)

These are real. Items 1, 3 and 4 are pinned by a test or a check. Item 2 was found and fixed without a regression test.

1. **I assumed persistent keepalive refreshes the WireGuard handshake. It doesn't.** My first version called the tunnel
   "stale" when the last handshake was older than 30 s. The probe history showed `state=down` with
   `tcp=True rtsp=True`. A working camera was reported dead, flapping every couple of minutes. Persistent keepalive only holds
   the NAT mapping open. WireGuard re-handshakes about every 120 s and a session lives up to 180 s. So a *healthy*
   tunnel's handshake age cycles from 0 to roughly 3 minutes. The monitor now decides whether the tunnel works by sending
   a packet through it (a ping). It reports the handshake age as information only. Regression test:
   `test_a_healthy_tunnel_with_an_old_handshake_is_still_up`.
2. **Three smaller finds**, fixed without a regression test: the monitor's `INFO` logs were silently dropped, `asyncmy` has no Python 3.13 wheel (I switched to `aiomysql`), and SQLAlchemy's pool pre-ping crashed with that driver pair (the hub pins 2.1 now). More in [`DEBUGGING.md`](DEBUGGING.md).
3. **The first end-to-end run failed 4 of 15 checks** (an observation from that day, no output saved). Two were my test or image bugs: the hub image had no `ping`, and the
   WebRTC page answers `302` before `200`. The other two came from the wrong model in item 1 (the recovery check and the
   "tunnel still fresh" check).
4. **A closed-port unit test passed on Linux and failed on Windows.** Windows keeps retrying SYNs to a closed local
   port for about 2 s, so it looks like a timeout. The test is skipped on Windows with the reason written next to it.

## Security layer

`security/` adds log correlation, a playbook responder and a Junos configuration reviewer to this lab. It was built and tested against this Docker model of a camera site, planted and generated logs, and sample Junos configurations written from Juniper's documentation. The long version is in [`docs/security.md`](docs/security.md) and [`security/README.md`](security/README.md).

- **SIEM.** The Wazuh manager (4.14.10) runs behind `--profile security`, so `docker compose up` and `verify.py` are unchanged. Seven custom rules join the monitor's state changes, the edge router's firewall drops and an ssh log (the ssh log and one of the two sweeps are generated). In `wazuh-logtest` the 5 planted logs fired the expected rules and the 2 benign logs fired none. `scripts/verify_security.py` ran 51 checks against the live lab, all passing.
- **Responder.** `security/respond.py` runs a YAML playbook per alert (enrich, notify, block, ticket), defaults to a dry run and keeps a hash-chained audit trail. On the 9 live alerts `--apply` blocked the two generated attacker addresses with `iptables` (read back, then removed). 52 tests, and 13 of 13 deliberate breakages turned a test red.
- **Junos review.** `security/junos_review.py` checks 16 things in a configuration read as text. It found 27 of the 27 planted faults across four sample configs and nothing on the two clean ones, and 16 of 16 rule-removal mutants turned a test red. It was written from Juniper's documentation and never run against a Junos device.
- [`security/COMPLIANCE-MAP.md`](security/COMPLIANCE-MAP.md) maps each rule to a NIST CSF 2.0 subcategory, a HIPAA Security Rule citation, a SOC 2 criterion and NYDFS 23 NYCRR 500 sections. It is a reference mapping, not legal advice.

## Vulnerability assessment and IAM

`security/vuln/` and `security/iam/` add a vulnerability scan with CVE triage, and single sign on with a TOTP code. They were built and tested against the Docker model of the camera site, saved real NVD, CISA KEV and FIRST EPSS answers, and two sample users. The long version is in [`docs/vuln-and-iam.md`](docs/vuln-and-iam.md).

- **Scans.** `security/vuln/scan.sh` runs Nuclei v3.11.1 with its 11,288 community templates behind a scope guard that refuses any target outside loopback and this repo's subnets (75 tests). It found 20 matches, all severity info: 12 fixed, 3 accepted with a written reason (no TLS on loopback) and 5 that only describe the service; a re-run found exactly the 3 accepted. It reached Keycloak and the SSO proxy only up to their first redirect. A passive ZAP 2.17.0 baseline scan found 10 alert types, none High; I fixed the 3 real ones on the hub and a rerun found 2 Informational alerts.
- **CVE triage.** `security/vuln/cve_triage.py` builds a 15 component inventory, asks NVD, the CISA catalogue and EPSS, and ranks by known exploited, EPSS, CVSS, then reachability. It works offline from saved answers. 3 components have no CPE entry, so they are reported UNKNOWN, not clean. Of 59 first matches, 42 are findings (41 FFmpeg, 1 Python), none known exploited.
- **IAM.** Keycloak 26.8.2 (dev mode, `--profile iam`) and oauth2-proxy v7.15.6 put the dashboard behind single sign on with a required TOTP code, two roles, a 60 second access token and brute force detection; `security/iam/check_iam.sh` passed 39 of 39 live checks. The sample users, for this lab only, are `viewer.sample` (`ViewerSample-2026`) and `admin.sample` (`AdminSample-2026`).
- **Tests and limits.** 179 new offline tests and 41 new mutants, each of which turns a test red (70 of 70 across the security layer). Keycloak is in dev mode over plain HTTP, and NVD matches upstream versions, so a patched Debian package can show CVEs that are already fixed.

## Smart lock integration

`iot/` adds an IoT integration slice: a simulated MQTT smart lock on a real mosquitto broker, a stand in for a lock maker's cloud API written from a stated contract, a connector service that keeps a record in sync with both, and a diagnosis tool that names the layer that broke. It is all simulated: no real lock, vendor account or radio, and no Zigbee or Z-Wave. The write up is [`docs/iot.md`](docs/iot.md).

- **Connector and diagnosis.** The connector refreshes OAuth tokens one caller at a time, honours Retry-After, verifies signed webhooks inside a replay window, drops duplicate events, repairs a missed webhook by polling, and keeps tokens and access codes encrypted at rest and out of every log. `iot/iotlab/diagnose.py` probes broker, device, vendor cloud, OAuth, webhook and connector in order. 133 mutants of the guards each turn a test red.

## Smart doormat firmware

`esp32/` adds ESP32 firmware and a phone control page for a smart doormat: a step on a pressure pad triggers a greeting with sound, animated eyes and an LED effect, and the mat takes commands over REST, WebSocket, MQTT and BLE. It was tested in simulation (host tests, Espressif's QEMU, the Wokwi simulator) and **has never been flashed to hardware**. Write up: [`esp32/README.md`](esp32/README.md). Wiring and flashing: [`esp32/docs/setup-guide.md`](esp32/docs/setup-guide.md).

- **Firmware and page.** The device logic is C++ with no Arduino headers, so the same code runs on the board, in the tests and under QEMU. MQTT uses this repo's mosquitto broker with two new users in its access list. 101 Unity test cases and 61 host tests pass, 77 of 77 deliberate breakages of its guards turn a test red, and QEMU prints the same 36 trace lines as the host build. The camera driver, BLE and the I2S audio code compile and were not run.

## Layout

```
docker-compose.yml        the four containers and three networks
camera/mediamtx.yml       the stand-in camera (RTSP + WebRTC, ffmpeg test pattern)
edge/                     the site router: WireGuard, iptables NAT + firewall
hub/app/                  FastAPI monitor: probe.py (layers), db.py (pool), main.py (API), dashboard.html
hub/tests/                offline tests for the probe layer
scripts/verify.py         end-to-end proof, both faults
demo/record.mjs           Playwright recording of the dashboard through both faults
docs/                     last_run.json, demo.gif, demo.mp4, security.md, vuln-and-iam.md, iot.md and the run files of each slice
security/                 Wazuh rules and decoders, sensors, playbooks, respond.py, junos_review.py, vuln/ (Nuclei, ZAP, CVE triage), iam/ (Keycloak realm, checks), tests
iot/                      the smart lock slice: lock simulator, vendor cloud stand-in, connector, diagnosis tool, tests (iot/README.md)
esp32/                    the smart doormat slice: lib/doormat_core (device logic), firmware/, web/ (control page), host/ (emulation), tests/, qemu/, wokwi/ (esp32/README.md)
```

## Scope and next steps

- **One machine.** Docker networks stand in for the internet, the site LAN and a 4G link. Next steps: model carrier-grade NAT, packet loss, MTU black holes and radio behaviour. Then run real router firmware.
- **The camera is ffmpeg's test pattern served by MediaMTX.** Next steps: ONVIF discovery and vendor cameras (Hikvision, Dahua, Uniview).
- **One camera and one site.** The monitor models a single device. A fleet adds a camera registry, per-site peers and
  scheduling.
- **The doormat firmware has never run on a board.** What each simulator did and did not cover is in [`esp32/README.md`](esp32/README.md#limits).
- The credentials in `docker-compose.yml` are local values. The database is only reachable on an internal
  network.
