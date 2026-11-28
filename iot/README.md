# iot/

A smart lock integration slice for the camera fleet lab: a simulated lock that speaks MQTT, a stand in for a lock manufacturer's cloud API, a connector that keeps a third party record in sync with both, and a diagnosis tool that says which layer broke. Everything is a simulation. No real lock, no real vendor account and no radio hardware was used. The long write up, with what the runs showed and what I got wrong, is [`docs/iot.md`](../docs/iot.md).

```
lock simulator --MQTT QoS 1--> mosquitto --> vendor cloud stand in --webhook, REST--> connector --> SQLite record
        \                          |                                                      ^
         \_________ state, status (retained, last will) ________________________________/  (the connector also reads the broker directly)
```

## Run it

Needs Python 3.12 or newer and Docker (only for the real mosquitto broker, which the tests start and remove themselves).

```
cd iot
pip install -r requirements.txt
python -m pytest -q                                   # unit, table, property, broker and end to end tests
python tests/run_mutations.py --jobs 8                # every guard broken one at a time, a test must go red
python scripts/capture_diagnosis.py                   # the diagnosis tool against one induced fault at a time
python -m iotlab.broker up                            # a broker of your own, credentials in iot/state/broker.json (gitignored)
python -m iotlab.broker down                          # remove every container this folder started
```

Tests that need Docker skip with a reason when it is not running. The mutation run starts one broker and shares it, and starts three more from a deliberately weakened config.

## Layout

```
iotlab/lock_sim.py           the MQTT smart lock: commands, retained state, last will, low battery, jam and hang faults
iotlab/link.py               a TCP forwarder that cuts, blackholes or flaps the link between a lock and the broker
iotlab/vendor_cloud.py       the stand in for a manufacturer's cloud: OAuth, REST, rate limits, codes, signed webhook, event feed
iotlab/connector/            the integration: vendor_client (tokens, retries), webhook (signature, replay window), sync (the record),
                             store (SQLite), crypto (Fernet vault), safelog (no secret in a log), normalize, mqtt_listener, app (service)
iotlab/diagnose.py           the layer diagnosis tool
iotlab/broker.py             starts mosquitto in Docker with a generated password file
mosquitto/                   the broker config and the per user access list
tests/                       the tests, the shared harness and run_mutations.py
scripts/capture_diagnosis.py the diagnosis run that docs/iot/diagnosis_run.txt came from
docs/                        contract.md (what the stand in is written from), diagnosis.md, zigbee-zwave.md
```

## Handling of credentials

- Broker passwords are random per broker, held in memory and, for `python -m iotlab.broker up`, in a gitignored file. Anonymous clients are refused, and every broker user is limited by `mosquitto/acl.conf`.
- The connector keeps its OAuth tokens, the webhook secret and every access code only as Fernet ciphertext. The key comes from `CONNECTOR_KEYS` (one or more, the first encrypts, all decrypt, so it can be rotated) or a key file created readable by its owner only.
- A token, a code or a secret is never put in a log line or an exception message. Logging goes through a redacting wrapper, and the tests search every log and the database file for every credential a run produced.
- The access code API returns a code once, at creation. The connector's own API never returns a stored code again, and a revoked or expired code is wiped from the record.

## Limits

The vendor is a stand in written from a contract I stated, so the connector would need a mapping layer and its own tests against any real vendor. The mosquitto image warns that the generated config files are more open than it would like (it only warns in 2.0). Zigbee and Z-Wave are not built: see [`docs/zigbee-zwave.md`](docs/zigbee-zwave.md).
