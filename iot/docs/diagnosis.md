# The diagnosis tool: which layer broke

`python -m iotlab.diagnose` is the lock integration's version of the camera monitor. The camera monitor checks `tunnel, then port, then video` and reports the first layer that fails. This one checks the layers a lock's data crosses, in the order it crosses them, and reports the first one that fails with the evidence that says so.

```
broker -> device -> vendor_cloud -> oauth -> webhook -> connector
```

```
DIAG_MQTT_PASSWORD=... python -m iotlab.diagnose --symptom lock_offline --lock lock-1 \
    --broker 127.0.0.1:1883 --vendor http://127.0.0.1:8200 --connector http://127.0.0.1:8300      # add --json for a machine report
```

The exit code is 0 when no layer failed and 1 when one did. The broker user and password come from `DIAG_MQTT_USER` and `DIAG_MQTT_PASSWORD` and are never printed.

## Symptoms and the layers each one can pass through

| Symptom | Layers probed, in order |
|---|---|
| `lock_offline` (the lock shows offline) | broker, device, vendor_cloud, oauth, connector |
| `unlock_unconfirmed` (a command was sent and nothing confirmed it) | broker, device, vendor_cloud, oauth, webhook, connector |
| `codes_not_syncing` | vendor_cloud, oauth, connector |
| `webhook_silence` | vendor_cloud, oauth, webhook, connector |

Every layer in the list is probed and printed. The verdict is the **first** one that fails, because a later layer that also fails is downstream of the cause. A layer that cannot be probed (the connector is down, so its token state cannot be read) is `unknown`, and an unknown is never read as healthy.

## What each layer checks, and what counts as failing

| Layer | Probe | Fails when |
|---|---|---|
| `broker` | connect with the diagnosis user, then publish to a topic of its own and wait for it to come back | nothing answers on the port, the login is refused, or the broker accepts the connection but does not deliver a message |
| `device` | read the retained `status` and `state` of the lock, then send one `report` command and wait for the lock to echo its id | no status was ever kept for the lock, the status is the last will `offline`, or it says `online` and never answers the report (firmware hung) |
| `vendor_cloud` | the vendor's `/healthz`, and a live call through the connector | no answer, a 5xx, a 429 (with its Retry-After), the API failing while the health route is green, or the vendor showing the lock offline while the broker shows it online |
| `oauth` | the connector's grant state and a live call | no grant, a grant marked `needs_reauth`, tokens the vendor rejects even after a refresh, or a 403 for a missing scope (named) |
| `webhook` | the connector's webhook counters and the vendor's own delivery log | no webhook registered, deliveries rejected as `bad_signature` or `stale_timestamp`, the vendor's attempts failing, or events that reached the connector only by polling |
| `connector` | `/healthz` and `/diag` | it does not answer, its reconcile loop stalled, its last sync failed (the error class is shown, never the message) or is old, a command is stuck pending while everything before it is healthy, its MQTT subscription is down, or its record says offline while the vendor says online |

A low battery is reported on the `device` line as a note. It is a warning and not a fault.

## Read only

Every probe only reads, with one exception: the device probe sends a `report` command. A `report` makes a lock publish its state again and changes nothing on the door or in its battery. A test sends every symptom's probes and checks the simulated lock never applied a command.

The connector's `/diag` route carries counters and states, no token, no code and no secret. A test searches every report for every password, token, webhook secret and access code the run produced.

## Where the evidence comes from

The tool reaches the broker and the vendor's health route itself. Everything about the OAuth grant, the webhook counters and the sync state it reads from the connector's `/diag` route, which also makes the live calls to the vendor with the connector's own token (one attempt each, so a diagnosis never sits in a retry loop). That keeps the tool from ever holding a token.

## What was proven, and the limits

`iot/tests/test_diagnose.py` induces each fault on a real broker with the whole slice running and requires the tool to name that layer, with a healthy baseline that must name nothing. Real output for each induced fault is in [`docs/iot/diagnosis_run.txt`](../../docs/iot/diagnosis_run.txt). The limits: the faults are induced by this repository's own switches, so they cover the failure modes I thought of and not the ones a real vendor would add. The vendor is a stand in, and the lock is a simulator behind a TCP forwarder, not a radio link.
