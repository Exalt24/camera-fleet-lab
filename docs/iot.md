# Smart lock integration slice: design notes and what the runs showed

`iot/` adds an IoT integration slice to the camera fleet lab, for the kind of job where a smart lock or access control device has to be connected to a manufacturer's platform and a third party system. It was built and tested against a simulated lock, a stand in for a manufacturer's cloud that I wrote from a stated contract, and a real mosquitto broker in Docker. **No real lock, no real vendor account, no real vendor network call and no radio hardware was used.** The code is in [`iot/`](../iot), the contract the stand in follows is [`iot/docs/contract.md`](../iot/docs/contract.md), and the run files are in [`docs/iot/`](iot).

## What is in it

| Part | File | What it does |
|---|---|---|
| Lock simulator | `iot/iotlab/lock_sim.py` | Speaks MQTT QoS 1 through mosquitto: a command topic, a retained state topic, a retained status topic with a last will for offline, a low battery report, and jam and hang faults |
| Flaky link | `iot/iotlab/link.py` | A TCP forwarder between the lock and the broker that can cut the link, silently blackhole it, or flap it from a seeded generator |
| Manufacturer cloud stand in | `iot/iotlab/vendor_cloud.py` | OAuth 2.0 authorization code with rotating refresh tokens and expiry, REST for locks, commands and temporary codes, rate limiting with Retry-After, lock objects whose fields disagree, an HMAC signed webhook with retries, and an event feed |
| Connector | `iot/iotlab/connector/` | Keeps a SQLite record of locks, codes, events and commands in sync with the cloud and with the lock's own MQTT topics |
| Diagnosis tool | `iot/iotlab/diagnose.py` | Given a symptom, probes broker, device, vendor cloud, OAuth, webhook and connector in data order and names the first layer that fails, with evidence |
| Broker | `iot/iotlab/broker.py`, `iot/mosquitto/` | A real mosquitto 2.0.22 container with a generated password file and a per user access list |

## How the connector copes

- **Tokens.** Refreshed shortly before expiry and again after a 401, by one caller at a time: ten threads that see an expired token cause one refresh. Refresh tokens rotate, so a second refresh with the spent token would be read by the vendor as a replay and would end the grant. The new access token and the new refresh token are written in one statement. `invalid_grant` ends in `needs_reauth` with no retry loop. A vendor outage during a refresh is retried and does not end the grant.
- **Retries.** A 429 waits for `Retry-After` (seconds or an HTTP date) and is raised, not slept, when the wait is over a cap. A 5xx or a network error is retried with exponential backoff and jitter. A POST is retried only when it carries an `Idempotency-Key`, so a code whose answer was lost is not created twice and an unlock is not sent twice.
- **Webhooks.** The raw body is verified with an HMAC in constant time, a timestamp more than 300 seconds off is refused in both directions (the replay window), and the vendor's event id is the primary key of the events table, so a duplicate delivery changes nothing. An event applies to a lock only if its per lock sequence is newer than the lock's, so a late or replayed event cannot roll a lock back.
- **A missed webhook.** The poll cursor is advanced only by polling and never by a webhook, so a webhook for event 10 does not skip events 8 and 9. A snapshot cannot roll a lock back to an older sequence than a webhook already applied. If the feed has dropped what was missed (`410`), the connector resumes from the feed's head and the snapshot repairs the state.
- **Incomplete and inconsistent fields.** Three lock shapes name state, battery, online, firmware and time differently. A field that is missing or out of range is unknown, never 0 and never clipped, and a field the vendor leaves out keeps its previous value.
- **Credentials.** Tokens, the webhook secret and access codes are stored only as Fernet ciphertext. No token, code or secret is put in a log line or exception message (a redacting logger plus a test that searches every log and the database file). The connector's own API returns a code once, at creation, and a revoked or expired code is wiped from the record.

## What was proven

All counts below are from runs on one Windows machine with Docker Desktop. The run files are in [`docs/iot/`](iot).

- **Tests.** `cd iot && python -m pytest -q` ended `456 passed in 216.14s` ([`docs/iot/pytest_run.txt`](iot/pytest_run.txt)). By area: the webhook signature and replay window (32, table tests), the credential vault, the record and field normalisation (84), the vendor client's token and retry rules against a scripted vendor (52), the stand in against its contract (44), the connector against the stand in over HTTP (51), a seeded property test of the event projection (120 worlds, see below), the lock simulator on a real broker (26), the whole slice on a real broker (7) and the diagnosis tool against induced faults (40).
- **Property test.** Each of 120 seeded worlds mixes several locks, six event types, events delivered out of order and 0 to 3 times each over two sources, with snapshots landing at random moments. At every step a repeated event id changes nothing, a lock's sequence never goes down and a held state is one the lock really passed through, and after one snapshot the record equals the vendor's truth.
- **Real broker.** Against mosquitto 2.0.22 in Docker: retained state reaches a late subscriber, the last will is published and retained when the link is cut or silently blackholed and the lock reconnects, a command published while the lock is away is lost (a clean session), a seeded flapping link ends consistent, and the broker's access list stops a lock writing another lock's topics, stops the connector forging state and refuses anonymous and wrong password clients.
- **Mutation controls.** `python iot/tests/run_mutations.py --group all --jobs 8` copies the tree, breaks one guard at a time and runs the tests meant to notice: **133 of 133 mutants turned a test red** (88 in the connector, vendor stand in and helpers, 10 in the lock simulator, 32 in the diagnosis tool, 3 in the broker config), with the unchanged code green first in each group ([`docs/iot/mutation_run.txt`](iot/mutation_run.txt)). Two mutants survived the first run and were fixed: a branch of the diagnosis tool whose test only looked for "503" in the wording (the test now pins the wording), and a branch that could never run (removed). The first run of the broker group also reported all three mutants missed, because my harness imported the real broker module instead of the mutated copy. That was the harness, and it now starts the mutated broker in a child process.
- **Diagnosis.** `python iot/scripts/capture_diagnosis.py` induces one fault at a time on a healthy slice and prints the tool's own report ([`docs/iot/diagnosis_run.txt`](iot/diagnosis_run.txt)): 17 of 17 runs named the induced layer (4 healthy runs named nothing; hung lock, cut link, vendor down, rate limited, vendor view wrong, lost scope, revoked grant, signing secret mismatch, paused delivery before and after polling repaired the state, dead webhook address, connector down and a stopped broker each named their own layer). The faults are the ones this repository can induce.

## What I got wrong on the way

These were found by the tests, not by reading.

1. **The first expired feed handling never recovered.** On a `410` the connector set its poll cursor to the highest event it had stored, which is the old position, so the next poll was a `410` again, forever. A test that reconciled twice found it. It now reads the feed's head and resumes from there.
2. **A paused webhook was not paused.** The fault switch was read by the delivery thread, so a test that flipped it back straight after emitting an event raced the thread and the event was delivered after all. The decision is now taken when the event happens.
3. **A code made through the connector was never synced.** The code sync visits the locks in the record, and creating a code did not make sure its lock was in the record. Creating a code now does.
4. **The diagnosis read the OAuth record before its own live probe.** A probe that ended the grant showed `ok` on the first run, and a missing scope showed as `None`. The record is read after the probes now. A branch that blamed a failing token refresh turned out to be unreachable, because a refresh that fails is caught first as a vendor problem, so I removed it and added a test for the token endpoint failing.
5. **The mosquitto image changes the owner of its config folder**, so a read only mount fails with `Unable to open pwfile`. The config is mounted writable. The image still warns that the files are more open than it would like (a warning in 2.0).
6. **A Windows closed port takes about two seconds to fail**, as in item 6 of the main list. A delivery to a dead port takes about eight seconds for four attempts, and the test waits for that.
7. **The connector called the vendor about every lock on the broker.** Its MQTT listener made a record for any lock id it heard, and the code sync visited every record, so with dozens of retained locks on a shared test broker the sync hit the vendor's rate limit and a test failed now and then. Only a lock the vendor has told the connector about (a listing, an event or a code) is synced now, and a test pins it.
8. **My own watcher could not read the topics it watched**, because the diagnosis user's access list is read only for state and status. The access list was doing its job. Tests now use a separate `observer` user that no service is given.

## Not proven, and limits

- **Real vendors.** The stand in follows a contract I wrote. A real vendor's API, docs and quirks were not read, so a real integration needs its own mapping and its own tests.
- **Radios.** Zigbee and Z-Wave are not built and no radio was used: [`iot/docs/zigbee-zwave.md`](../iot/docs/zigbee-zwave.md) says what the bridge would be. Bluetooth and Wi-Fi provisioning of a lock are not modelled.
- **Codes on the lock.** The stand in never pushes access codes to the lock, so how a code reaches a device, and what happens when that fails, is untested.
- **Faults.** The diagnosis tool is proven against the faults this repository can induce. A failure I did not think of may be named wrongly or not at all.
- **CI.** CI runs the tests and checks that every mutant still applies. The full mutation run takes about 10 minutes here and is run by hand, and its output is saved.
- **Python version.** I ran Python 3.13 here. CI uses 3.12, and the code does not use anything newer, but the first CI run is the only evidence for 3.12.
- **One machine, one run.** Timings in the run files are one run, and the flapping link test is seeded but its timing depends on the machine.
