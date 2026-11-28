# The contract the stand in is written from

`iot/iotlab/vendor_cloud.py` stands in for a smart lock manufacturer's cloud. **It is not any real vendor's API and no real vendor was contacted.** I wrote this contract to resemble the way such APIs behave (an OAuth 2.0 grant, a REST resource per lock, temporary access codes, a signed webhook) and to be incomplete and inconsistent in the places real documentation tends to be. The connector was then built and tested against the contract, so a real vendor would need its own mapping layer and its own tests. Nothing here was checked against a real lock.

## Authentication: OAuth 2.0 authorization code

| Step | Request | Answer |
|---|---|---|
| Authorize | `GET /oauth/authorize?response_type=code&client_id&redirect_uri&scope&state` | `302` to the registered `redirect_uri` with `code` and the same `state`. An unknown client or an unregistered redirect address gets a `400` and no redirect |
| Exchange | `POST /oauth/token`, form `grant_type=authorization_code&code&redirect_uri`, client id and secret in HTTP Basic (or in the form) | `access_token`, `refresh_token`, `expires_in` (3600 by default), `scope`. The code works once, for 60 seconds, and only with the same `redirect_uri`. Using a code twice revokes the tokens it made |
| Refresh | `POST /oauth/token`, form `grant_type=refresh_token&refresh_token` | New `access_token` **and a new `refresh_token`**. Refresh tokens rotate: the old one is spent, and presenting it again revokes the whole grant (`invalid_grant`) |
| Use | `Authorization: Bearer <access_token>` | `401 invalid_token` when unknown, revoked or expired. `403 insufficient_scope` (with `required_scope`) when the grant lacks the scope for the route |

Scopes: `locks:read`, `locks:write`, `codes:read`, `codes:write`, `webhooks:write`. Errors are `{"error": "<code>", "error_description": "..."}`.

## Rate limiting

A fixed window per access token (100 requests per 60 seconds by default). Past the limit the answer is `429` with `Retry-After`: whole seconds, or an HTTP date when the vendor is in its date mode. A `429` is sent before anything runs, so repeating the request is always safe.

## REST resources

| Route | Scope | Notes |
|---|---|---|
| `GET /healthz` | none | `200` when the cloud is up |
| `GET /v1/locks?limit&cursor` | `locks:read` | `{"data": [...], "next_cursor": "..." or null}` |
| `GET /v1/locks/{id}` | `locks:read` | one lock |
| `POST /v1/locks/{id}/lock`, `.../unlock` | `locks:write` | `202` with a command (`pending`). `409 lock_offline` when the lock is not connected. Honours `Idempotency-Key`: the same key returns the same command |
| `GET /v1/commands/{id}` | `locks:read` | `pending`, `confirmed`, `failed` (the lock jammed) or `timed_out` (no answer within 30 seconds) |
| `POST /v1/locks/{id}/codes` | `codes:write` | body `name`, `starts_at`, `ends_at` (ISO 8601). The six digit `code` is in this answer **only**. At most 30 days, at most 4 live codes per lock (`409 code_slots_full`). Honours `Idempotency-Key` |
| `GET /v1/locks/{id}/codes` | `codes:read` | status (`scheduled`, `active`, `expired`, `revoked`) and times, never the code |
| `DELETE /v1/locks/{id}/codes/{code_id}` | `codes:write` | `204`, also when it was already revoked |
| `POST /v1/webhooks` | `webhooks:write` | body `url`. The signing `secret` is in this answer only. A second call replaces the registration and gives a new secret |
| `GET /v1/webhooks/{id}/deliveries` | `webhooks:write` | the vendor's own delivery log: attempt, status or error |
| `GET /v1/events?since_seq&limit` | `locks:read` | the event feed, oldest first, plus `latest_seq`. `410 cursor_expired` when the part asked for was already dropped |

### Fields that disagree on purpose

The three lock shapes below are in the stand in so the connector has to cope. A field the vendor leaves out is unknown, and an out of range value is unknown too.

| Fact | Shape a | Shape b | Shape c |
|---|---|---|---|
| State | `"state": "LOCKED"` | `"locked": true` (plus `"jammed": true` when jammed) | `"lock_state": "locked"` |
| Battery | `"battery_level": 87` | `"battery_pct": 87` | `"battery": "87%"`, key absent when never reported |
| Online | `"online": true` | `"connected": true` | `"online": 1` |
| Firmware | `"firmware": "1.4.2"` | not present | `"fw": "1.4.2"` |
| Updated | epoch seconds | ISO 8601 | ISO 8601 under another name |

The answer to creating a code gives `starts_at` and `ends_at` as epoch seconds, while the list gives them as ISO 8601.

## Webhook

Events: `lock.locked`, `lock.unlocked`, `lock.jammed`, `lock.online`, `lock.offline`, `lock.battery_low`. A delivery is a `POST` of this body:

```
{"id": "evt_...", "type": "lock.unlocked", "lock_id": "...", "occurred_at": "2026-11-28T10:00:00Z",
 "seq": 41, "lock_seq": 7, "data": {"state": "unlocked", "command_id": "cmd_...", "source": "remote"}}
```

`seq` numbers every event the vendor emits. `lock_seq` numbers the events of one lock. `source` is `remote` (a command) or `manual` (the thumbturn).

Headers: `X-Vendor-Timestamp` (epoch seconds), `X-Vendor-Event-Id`, and `X-Vendor-Signature: v1=<hex>` where the hex is `HMAC-SHA256(secret, "<timestamp>.<raw body>")`. The receiver must:

1. read the raw body, not a re encoded copy
2. compare the signature in constant time (several `v1=` values may be present during a secret rotation)
3. refuse a timestamp more than 300 seconds from its own clock, in the past or the future (the replay window)
4. treat the event id as the idempotency key

Delivery is **at least once**. A non 2xx answer is retried (4 attempts, doubling the wait), so duplicates are normal. Order is not guaranteed across retries, which is why `lock_seq` exists. Polling `GET /v1/events` finds what a webhook missed.

## MQTT, between the lock and the broker

Every message is QoS 1. The client id of a lock is its id, and the broker's access list lets it write only its own topics.

| Topic | Direction | Payload |
|---|---|---|
| `locks/<id>/cmd` | to the lock | `{"cmd_id": "...", "action": "lock" or "unlock" or "report"}`. A repeated `cmd_id` is ignored. `report` makes the lock publish its state and changes nothing on the door |
| `locks/<id>/state` | from the lock, retained | `{"lock": "locked"/"unlocked"/"jammed", "battery": 0..100, "battery_low": bool, "last_cmd": "...", "seq": n, "ts": epoch}` |
| `locks/<id>/status` | from the lock, retained | `online` when it connects. The broker publishes the last will `offline` when the connection dies without a clean disconnect |
| `locks/<id>/event` | from the lock | `{"type": "battery_low", "battery": n}`, once each time the battery crosses 20 percent |

Broker users (see `iot/mosquitto/acl.conf`): `device` (a lock, limited by `%c` to its own topics), `vendor` and `connector` (read state, status and events, write commands), `diag` (read, one harmless report command, and a `diag/#` topic for the round trip test) and `observer` (tests and debugging only). Anonymous clients are refused.

A lock connects with a clean session, so **a command published while the lock is away is lost, not queued**. The vendor then reports it as `timed_out` after 30 seconds. This is deliberate: it is the "unlock never confirmed" case the diagnosis tool has to explain.

## What the stand in does not do

It never pushes access codes to the lock, there is no firmware update, no user model, no audit log and no per user permission. The lab routes under `/_lab/` (fault switches for the tests) are not part of the contract.
