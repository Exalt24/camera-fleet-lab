"""The connector against the vendor stand-in over real HTTP, with no MQTT and no Docker (the locks' messages are handed to the vendor
directly). These are the integration rules: duplicates, replays, missed webhooks, token expiry, revocation, rate limits, retries that
must not repeat a side effect, and what is and is not on disk or in a log."""
from __future__ import annotations

import json
import logging
import threading
import time

import httpx
import pytest

from harness import FakeClock, Stack, wait_until
from iotlab.connector.vendor_client import RateLimited, ReauthRequired, VendorError, VendorUnavailable
from iotlab.connector.webhook import WebhookRejected
from iotlab.vendor_cloud import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign


@pytest.fixture
def stack(tmp_path):
    clock = FakeClock(time.time())
    s = Stack(None, tmp_path, shapes=("a", "b", "c"), clock=clock, vendor_cfg={"access_ttl": 1000, "page_size": 2},
              sleeper=lambda secs: clock.advance(secs))
    s.clock_obj = clock
    s.authorize()
    s.register_webhook()
    yield s
    s.close()


def turn(stack, lock_id, state, last_cmd=None, battery=80):
    stack.lock_says(lock_id, lock=state, battery=battery, last_cmd=last_cmd)


def webhooks_settled(stack, n, timeout=5.0):
    wait_until(lambda: stack.store.count_events("webhook") >= n, timeout=timeout, what=f"{n} webhook events")


# ---- the snapshot, with three shapes and pagination ---------------------------------------------------------------------------------------
def test_three_differently_shaped_locks_land_in_one_shape_across_pages(stack):
    assert stack.conn.sync_locks() == 3
    rows = {r["id"]: r for r in stack.store.list_locks()}
    assert len(rows) == 3
    a, b, c = (rows[i] for i in stack.lock_ids)
    assert (a["state"], a["battery"], a["online"], a["firmware"]) == ("locked", 80, 1, "1.4.2")
    assert (b["state"], b["battery"], b["online"], b["firmware"]) == ("locked", 80, 1, None)          # shape b has no firmware: unknown, not blank
    assert (c["state"], c["battery"], c["online"]) == ("locked", 80, 1)                                  # "80%" became 80


def test_a_field_the_vendor_leaves_out_keeps_its_previous_value(stack):
    stack.conn.sync_locks()
    lid = stack.lock_ids[2]
    stack.cloud.locks[lid].battery = None                                  # shape c then omits the battery key entirely
    stack.cloud.locks[lid].firmware = None
    stack.conn.sync_locks()
    row = stack.store.get_lock(lid)
    assert row["battery"] == 80 and row["firmware"] == "1.4.2", "an omitted field is not written as 0 or blank"


# ---- webhooks ---------------------------------------------------------------------------------------------------------------------------
def test_a_manual_turn_reaches_the_record_by_webhook(stack):
    lid = stack.lock_id
    turn(stack, lid, "unlocked")
    wait_until(lambda: stack.store.get_lock(lid) and stack.store.get_lock(lid)["state"] == "unlocked", what="the webhook to update the record")
    row = stack.store.get_lock(lid)
    assert row["lock_seq"] == 1 and stack.store.count_events("webhook") == 1


def test_a_duplicate_delivery_changes_nothing(stack):
    stack.cloud.faults["duplicate_deliveries"] = True
    lid = stack.lock_id
    turn(stack, lid, "unlocked")
    wait_until(lambda: int(stack.store.meta_get("webhook_duplicates", "0")) >= 1, what="the duplicate to arrive")
    assert stack.store.count_events() == 1 and stack.store.get_lock(lid)["lock_seq"] == 1


def test_the_same_signed_event_posted_ten_times_at_once_is_applied_once(stack):
    stack.cloud.faults["drop_webhooks"] = True                              # the vendor's own push is off; this test posts by hand
    lid = stack.lock_id
    turn(stack, lid, "unlocked")
    evt = stack.cloud.events[-1]
    body = json.dumps(evt, separators=(",", ":")).encode()
    secret = stack.cloud.webhook["secret"]
    ts = int(stack.clock())
    headers = {TIMESTAMP_HEADER: str(ts), SIGNATURE_HEADER: sign(secret, ts, body), "Content-Type": "application/json"}
    results = []

    def post():
        results.append(httpx.post(stack.conn_srv.url + "/webhooks/vendor", content=body, headers=headers).json()["result"])

    threads = [threading.Thread(target=post) for _ in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results) == ["applied"] + ["duplicate"] * 9 and stack.store.count_events() == 1


def test_events_that_arrive_out_of_order_do_not_roll_the_lock_back(stack):
    lid = stack.lock_id
    stack.cloud.faults["drop_webhooks"] = True
    turn(stack, lid, "unlocked")
    turn(stack, lid, "locked")
    first, second = stack.cloud.events[-2], stack.cloud.events[-1]
    assert stack.conn.apply_event(second, "webhook") == "applied"
    assert stack.conn.apply_event(first, "webhook") == "stale"               # recorded, but it is older than what we hold
    assert stack.store.get_lock(lid)["state"] == "locked" and stack.store.count_events() == 2


def test_a_forged_or_unsigned_post_is_refused_and_counted(stack):
    url = stack.conn_srv.url + "/webhooks/vendor"
    evt = json.dumps({"id": "evt_forged", "type": "lock.unlocked", "lock_id": stack.lock_id, "occurred_at": "2026-11-28T10:00:00Z", "seq": 99, "lock_seq": 99}).encode()
    ts = str(int(stack.clock()))
    assert httpx.post(url, content=evt).status_code == 401
    assert httpx.post(url, content=evt, headers={TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sign("whsec_guess", ts, evt)}).status_code == 401
    assert stack.store.count_events() == 0
    rejected = stack.store.meta_prefix("webhook_rejected:")
    assert int(rejected["bad_signature"]) == 1 and int(rejected["missing_headers"]) == 1


def test_a_captured_delivery_replayed_later_is_refused_as_stale(stack):
    lid = stack.lock_id
    turn(stack, lid, "unlocked")
    webhooks_settled(stack, 1)
    stack.clock_obj.advance(400)                                             # past the 300 s window
    with_conn = stack.cloud.replay_captured(stack.cloud.events[-1]["id"])
    assert with_conn == 400
    assert int(stack.store.meta_prefix("webhook_rejected:")["stale_timestamp"]) == 1 and stack.store.count_events() == 1


def test_a_vendor_whose_clock_is_far_off_is_rejected_as_stale_even_when_genuine(stack):
    stack.cloud.clock = lambda: time.time() - 3600                         # the vendor's clock runs an hour slow
    turn(stack, stack.lock_id, "unlocked")
    wait_until(lambda: int(stack.store.meta_prefix("webhook_rejected:").get("stale_timestamp", "0")) >= 1, what="a stale rejection")
    assert stack.store.count_events() == 0


def test_a_malformed_body_with_a_valid_signature_is_refused_without_a_crash(stack):
    url = stack.conn_srv.url + "/webhooks/vendor"
    for body in (b"not json", b"[]", json.dumps({"id": "e", "type": "t"}).encode(), json.dumps({"id": "e", "type": "t", "lock_id": "l", "seq": "1", "lock_seq": 1,
                                                                                                    "occurred_at": "2026-11-28T10:00:00Z"}).encode()):
        ts = str(int(stack.clock()))
        r = httpx.post(url, content=body, headers={TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sign(stack.cloud.webhook["secret"], ts, body)})
        assert r.status_code == 400 and r.json()["error"] == "malformed_body"


def test_receive_webhook_without_a_registered_secret_refuses(tmp_path):
    s = Stack(None, tmp_path)
    try:
        with pytest.raises(WebhookRejected) as exc:
            s.conn.receive_webhook({}, b"{}")
        assert exc.value.reason == "no_secret"
    finally:
        s.close()


# ---- a missed webhook is repaired by polling ------------------------------------------------------------------------------------------------
def test_a_missed_webhook_is_found_by_the_next_reconcile(stack):
    lid = stack.lock_id
    stack.conn.sync_locks()
    stack.cloud.faults["drop_webhooks"] = True
    turn(stack, lid, "unlocked")
    time.sleep(0.2)
    assert stack.store.get_lock(lid)["state"] == "locked", "the push never came, so the record is stale"
    summary = stack.conn.reconcile()
    assert summary["events"]["applied"] == 1
    row = stack.store.get_lock(lid)
    assert row["state"] == "unlocked" and stack.store.count_events("poll") == 1


def test_a_webhook_for_a_later_event_does_not_skip_an_earlier_missed_one(stack):
    lid = stack.lock_id
    stack.conn.sync_locks()
    stack.cloud.faults["drop_webhooks"] = True
    turn(stack, lid, "unlocked")                                               # event 1: missed
    turn(stack, lid, "locked")                                                 # event 2: will arrive
    second = stack.cloud.events[-1]
    stack.cloud.faults["drop_webhooks"] = False
    stack.cloud._queue.put(second)                                             # only event 2 is delivered
    webhooks_settled(stack, 1)
    summary = stack.conn.reconcile()
    assert summary["events"] == {"applied": 0, "duplicate": 1, "stale": 1, "expired": False}
    assert stack.store.count_events() == 2, "event 1 must still be fetched even though event 2 was already seen"
    assert int(stack.store.meta_get("event_cursor")) == 2


def test_reconcile_twice_applies_nothing_the_second_time(stack):
    stack.conn.sync_locks()
    turn(stack, stack.lock_id, "unlocked")
    stack.conn.reconcile()
    again = stack.conn.reconcile()
    assert again["events"]["applied"] == 0 and again["events"]["stale"] == 0


def test_a_feed_that_dropped_what_we_missed_falls_back_to_the_snapshot(tmp_path):
    clock = FakeClock(time.time())
    s = Stack(None, tmp_path, shapes=("a",), clock=clock, vendor_cfg={"event_retention": 2})
    try:
        s.authorize()
        s.cloud.faults["drop_webhooks"] = True
        turn(s, s.lock_id, "unlocked")
        s.conn.reconcile()                                                       # the cursor now stands at event 1
        for state in ("unlocked", "locked", "unlocked", "locked", "unlocked"):
            turn(s, s.lock_id, state)
        out = s.conn.reconcile()
        assert out["events"]["expired"] is True
        assert s.store.get_lock(s.lock_id)["state"] == "unlocked", "the snapshot repaired what the feed could no longer tell"
        assert s.conn.reconcile()["events"]["expired"] is False, "the cursor moved on, so it does not expire again"
    finally:
        s.close()


def test_a_snapshot_cannot_roll_a_lock_back_to_an_older_sequence(stack):
    lid = stack.lock_id
    stack.cloud.faults["drop_webhooks"] = True
    turn(stack, lid, "unlocked")
    stack.conn.apply_event(stack.cloud.events[-1], "webhook")
    stale_view = dict(stack.cloud.render(stack.cloud.locks[lid]))
    stale_view.update(seq=0, state="LOCKED")                                   # a lagging read replica
    from iotlab.connector.normalize import normalize_lock
    stack.conn._apply_snapshot(normalize_lock(stale_view))
    assert stack.store.get_lock(lid)["state"] == "unlocked" and stack.store.get_lock(lid)["lock_seq"] == 1


def test_a_lock_object_the_connector_cannot_read_is_skipped_and_counted(stack):
    stack.cloud.add_lock("lock-odd", "Odd", "a")
    stack.cloud.locks["lock-odd"].id = ""                                      # an object with no id in the listing
    stack.conn.sync_locks()
    assert int(stack.store.meta_get("locks_skipped_unreadable", "0")) == 1 and len(stack.store.list_locks()) == 3


# ---- tokens -----------------------------------------------------------------------------------------------------------------------------
def test_an_expired_access_token_is_refreshed_and_the_vendor_sees_the_rotated_token(stack):
    before = stack.store.get_oauth()["refresh_token_enc"]
    stack.clock_obj.advance(990)                                               # 1000 s lifetime, 30 s skew
    stack.conn.sync_locks()
    assert stack.svc.client.refreshes == 1 and stack.store.get_oauth()["refresh_token_enc"] != before
    stack.clock_obj.advance(990)
    stack.conn.sync_locks()
    assert stack.svc.client.refreshes == 2, "the second refresh used the rotated token, so the vendor did not call it a replay"
    assert stack.store.get_oauth()["status"] == "ok"


def test_a_revoked_grant_ends_in_needs_reauth_and_stops_calling_the_vendor(stack):
    httpx.post(stack.cloud_srv.url + "/_lab/action", json={"action": "revoke_tokens"})
    with pytest.raises(ReauthRequired):
        stack.conn.sync_locks()
    assert stack.store.get_oauth()["status"] == "needs_reauth"
    with pytest.raises(ReauthRequired):
        stack.conn.sync_locks()
    diag = stack.conn.diagnostics(stack.lock_id)
    assert diag["oauth"]["status"] == "needs_reauth" and diag["vendor"]["locks"]["error"] == "reauth_required"


def test_a_missing_scope_is_named_and_the_grant_stays_usable(stack):
    httpx.post(stack.cloud_srv.url + "/_lab/action", json={"action": "strip_scopes", "scopes": ["codes:write", "codes:read"]})
    lid = stack.lock_id
    with pytest.raises(VendorError) as exc:
        stack.conn.create_code(lid, "guest", time.time(), time.time() + 3600)
    assert exc.value.status == 403 and exc.value.code == "insufficient_scope"
    assert stack.store.get_oauth()["status"] == "ok" and stack.store.get_oauth()["last_error"] == "insufficient_scope:codes:write"
    assert stack.conn.sync_locks() == 3


# ---- rate limits -----------------------------------------------------------------------------------------------------------------------------
def test_a_rate_limited_call_waits_the_vendors_retry_after_and_then_succeeds(tmp_path):
    clock = FakeClock(time.time())
    slept: list[float] = []

    def sleeper(secs):
        slept.append(secs)
        clock.advance(secs)

    s = Stack(None, tmp_path, shapes=("a",), clock=clock, vendor_cfg={"rate_limit": (2, 4.0), "access_ttl": 100000}, sleeper=sleeper)
    try:
        s.authorize()
        s.conn.sync_locks()
        s.conn.sync_locks()
        assert s.conn.sync_locks() == 1                                      # the third call inside the window was told to wait
        assert len(slept) == 1 and 1 <= slept[0] <= 4 and slept[0] == float(int(slept[0]))
    finally:
        s.close()


def test_a_very_long_retry_after_is_surfaced_not_slept(tmp_path):
    s = Stack(None, tmp_path, shapes=("a",), vendor_cfg={"access_ttl": 100000})
    try:
        s.authorize()
        s.cloud.faults["rate_limit_hard"] = 3600
        with pytest.raises(RateLimited) as exc:
            s.conn.sync_locks()
        assert exc.value.retry_after == 3600
        assert s.conn.diagnostics()["vendor"]["locks"]["error"] == "rate_limited"
    finally:
        s.close()


# ---- retries that must not repeat a side effect ------------------------------------------------------------------------------------------------
def test_a_code_whose_answer_was_lost_is_not_created_twice(stack):
    stack.cloud.faults["fail_after_commit"] = 1
    lid = stack.lock_id
    made = stack.conn.create_code(lid, "guest", time.time(), time.time() + 3600)
    assert len([c for c in stack.cloud.codes.values() if c["lock_id"] == lid]) == 1
    assert len(stack.store.list_codes(lid)) == 1 and made["code"] == stack.cloud.codes[made["id"]]["code"]


def test_an_unlock_whose_answer_was_lost_is_not_sent_twice(stack):
    stack.cloud.faults["fail_after_commit"] = 1
    cmd = stack.conn.send_command(stack.lock_id, "unlock")
    assert len(stack.cloud.commands) == 1 and stack.store.get_command(cmd["id"])["status"] == "pending"


def test_a_vendor_that_stays_down_surfaces_as_unavailable_not_as_a_hang(stack):
    stack.cloud.faults["down"] = True
    with pytest.raises(VendorUnavailable):
        stack.conn.sync_locks()


def test_an_invalid_command_action_is_refused_before_any_call(stack):
    with pytest.raises(ValueError):
        stack.conn.send_command(stack.lock_id, "explode")


def test_a_command_to_an_offline_lock_is_a_clear_vendor_error(stack):
    stack.lock_status(stack.lock_id, False)
    with pytest.raises(VendorError) as exc:
        stack.conn.send_command(stack.lock_id, "unlock")
    assert exc.value.code == "lock_offline" and not stack.store.pending_commands()


def test_a_command_is_confirmed_by_the_vendor_poll_when_nothing_else_told_us(stack):
    cmd = stack.conn.send_command(stack.lock_id, "unlock")
    stack.cloud.faults["drop_webhooks"] = True
    turn(stack, stack.lock_id, "unlocked", last_cmd=cmd["id"])
    assert stack.store.get_command(cmd["id"])["status"] == "pending"
    assert stack.conn.refresh_command(cmd["id"])["status"] == "confirmed"
    assert stack.store.get_command(cmd["id"])["confirmed_by"] == "poll"


def test_a_jam_reaches_the_command_as_failed_through_the_webhook(stack):
    cmd = stack.conn.send_command(stack.lock_id, "unlock")
    turn(stack, stack.lock_id, "jammed", last_cmd=cmd["id"])
    wait_until(lambda: stack.store.get_command(cmd["id"])["status"] == "failed", what="the failed command")
    assert stack.store.get_lock(stack.lock_id)["state"] == "jammed"


# ---- access codes -------------------------------------------------------------------------------------------------------------------------------
def test_a_code_is_returned_once_stored_encrypted_and_wiped_when_revoked(stack):
    lid = stack.lock_id
    made = stack.conn.create_code(lid, "guest", time.time(), time.time() + 3600)
    row = stack.store.get_code(made["id"])
    assert row["code_enc"] and made["code"] not in row["code_enc"] and stack.conn.code_plaintext(made["id"]) == made["code"]
    revoked = stack.conn.revoke_code(made["id"])
    assert revoked["status"] == "revoked" and revoked["code_enc"] is None and stack.cloud.codes[made["id"]]["revoked_at"] is not None


def test_revoking_a_code_the_vendor_no_longer_has_still_succeeds_locally(stack):
    lid = stack.lock_id
    made = stack.conn.create_code(lid, "guest", time.time(), time.time() + 3600)
    del stack.cloud.codes[made["id"]]
    assert stack.conn.revoke_code(made["id"])["status"] == "revoked"


def test_a_revoke_that_the_vendor_refused_does_not_mark_the_code_revoked_locally(stack):
    made = stack.conn.create_code(stack.lock_id, "guest", time.time(), time.time() + 3600)
    stack.cloud.faults["down"] = True
    with pytest.raises(VendorUnavailable):
        stack.conn.revoke_code(made["id"])
    assert stack.store.get_code(made["id"])["status"] != "revoked"


def test_a_window_that_ends_before_it_starts_is_refused_before_any_call(stack):
    with pytest.raises(ValueError):
        stack.conn.create_code(stack.lock_id, "g", 1000.0, 1000.0)


def test_a_malformed_code_answer_is_not_stored(stack):
    real = stack.cloud.code_view
    stack.cloud.code_view = lambda c: {k: v for k, v in real(c).items() if k != "id"}
    with pytest.raises(VendorError) as exc:
        stack.conn.create_code(stack.lock_id, "g", time.time(), time.time() + 3600)
    assert exc.value.code == "malformed_code_response" and not stack.store.list_codes()


def test_sync_codes_learns_codes_made_elsewhere_and_marks_the_ones_that_vanished(stack):
    lid = stack.lock_id
    stack.conn.sync_locks()
    mine = stack.conn.create_code(lid, "mine", time.time(), time.time() + 3600)
    other = stack.cloud.codes
    other["ac_foreign"] = {"id": "ac_foreign", "lock_id": lid, "name": "made in the vendor app", "code": "111111", "starts_at": time.time() - 10,
                           "ends_at": time.time() + 3600, "revoked_at": None}
    del stack.cloud.codes[mine["id"]]
    out = stack.conn.sync_codes()
    foreign = stack.store.get_code("ac_foreign")
    assert foreign["origin"] == "vendor" and foreign["code_enc"] is None and foreign["status"] == "active"
    assert stack.store.get_code(mine["id"])["status"] == "missing" and out["changed"] == 2


def test_sync_codes_drops_the_stored_code_once_the_vendor_says_it_expired(stack):
    clock = stack.clock_obj
    made = stack.conn.create_code(stack.lock_id, "short", clock() - 10, clock() + 100)
    assert stack.store.get_code(made["id"])["code_enc"]
    clock.advance(200)
    stack.cloud.clock = clock
    stack.conn.sync_codes()
    row = stack.store.get_code(made["id"])
    assert row["status"] == "expired" and row["code_enc"] is None


def test_a_revoke_that_did_not_reach_the_vendor_is_repeated_by_the_sync(stack):
    lid = stack.lock_id
    made = stack.conn.create_code(lid, "guest", time.time(), time.time() + 3600)
    stack.store.update_code(made["id"], status="revoked", revoked_at=time.time(), code_enc=None)      # we recorded it, the vendor never heard
    assert stack.conn.sync_codes()["healed"] == 1
    assert stack.cloud.codes[made["id"]]["revoked_at"] is not None


# ---- what is and is not exposed -----------------------------------------------------------------------------------------------------------------
def test_the_rest_api_never_returns_a_stored_code_after_creation(stack):
    lid = stack.lock_id
    body = {"name": "guest", "starts_at": time.time(), "ends_at": time.time() + 3600}
    made = httpx.post(f"{stack.conn_srv.url}/locks/{lid}/codes", json=body)
    assert made.status_code == 201 and len(made.json()["code"]) == 6 and made.headers["cache-control"] == "no-store"
    listed = httpx.get(f"{stack.conn_srv.url}/locks/{lid}/codes").text
    assert made.json()["code"] not in listed and "code_enc" not in listed and '"held":true' in listed.replace(" ", "")
    assert httpx.delete(f"{stack.conn_srv.url}/codes/{made.json()['id']}").json()["status"] == "revoked"
    assert httpx.delete(f"{stack.conn_srv.url}/codes/ac_nope").status_code == 404


def test_the_rest_api_reports_vendor_trouble_without_internal_detail(stack):
    stack.cloud.faults["down"] = True
    r = httpx.post(f"{stack.conn_srv.url}/locks/{stack.lock_id}/commands", json={"action": "unlock"})
    assert r.status_code == 503 and r.json() == {"error": "vendor_unavailable"}
    assert httpx.post(f"{stack.conn_srv.url}/locks/{stack.lock_id}/commands", json={"action": "explode"}).status_code == 400


def test_nothing_secret_is_on_disk_in_plaintext(stack):
    lid = stack.lock_id
    made = stack.conn.create_code(lid, "guest", time.time(), time.time() + 3600)
    turn(stack, lid, "unlocked")
    webhooks_settled(stack, 1)
    raw = b"".join(p.read_bytes() for p in stack.db_path.parent.glob(stack.db_path.name + "*"))
    plaintexts = list(stack.cloud.access) + list(stack.cloud.refresh) + [stack.cloud.webhook["secret"], made["code"], stack.client_secret]
    for secret in plaintexts:
        assert secret.encode() not in raw, "a credential is on disk in plaintext"


def test_no_token_secret_or_code_reaches_any_log_line(stack, caplog):
    caplog.set_level(logging.DEBUG)
    lid = stack.lock_id
    stack.clock_obj.advance(990)
    stack.conn.sync_locks()                                                 # a refresh
    made = stack.conn.create_code(lid, "guest", time.time(), time.time() + 3600)
    httpx.post(stack.conn_srv.url + "/webhooks/vendor", content=b"x", headers={TIMESTAMP_HEADER: "1", SIGNATURE_HEADER: "v1=00"})       # a rejection
    httpx.post(stack.cloud_srv.url + "/_lab/action", json={"action": "revoke_tokens"})
    with pytest.raises(ReauthRequired):
        stack.conn.sync_locks()
    stack.conn.diagnostics(lid)
    blob = caplog.text
    secrets_in_play = list(stack.cloud.access) + list(stack.cloud.refresh) + [stack.cloud.webhook["secret"], made["code"], stack.client_secret]
    assert len(secrets_in_play) > 4
    for secret in secrets_in_play:
        assert secret not in blob


def test_the_diagnostics_route_carries_no_secret(stack):
    stack.conn.create_code(stack.lock_id, "guest", time.time(), time.time() + 3600)
    text = httpx.get(stack.conn_srv.url + "/diag", params={"lock": stack.lock_id}, timeout=15).text
    for secret in list(stack.cloud.access) + list(stack.cloud.refresh) + [stack.cloud.webhook["secret"], stack.client_secret]:
        assert secret not in text
    assert "token_enc" not in text and "code_enc" not in text


# ---- the loop ---------------------------------------------------------------------------------------------------------------------------
def test_the_reconcile_loop_survives_an_error_and_records_it(tmp_path):
    s = Stack(None, tmp_path, shapes=("a",), reconcile_interval=0.1, start_loop=True)
    try:
        wait_until(lambda: s.store.meta_get("last_sync_error"), what="the loop to record not being authorized")
        assert "ReauthRequired" in s.store.meta_get("last_sync_error")
        s.authorize()
        wait_until(lambda: s.store.meta_get("last_sync_at") and s.store.meta_get("last_sync_error") == "", what="a clean sync after authorizing")
        assert s.store.meta_get("loop_tick_at")
    finally:
        s.close()


# ---- the locks' own MQTT messages and the vendor's other events, fed directly ---------------------------------------------------------------------
def test_malformed_mqtt_messages_are_counted_and_change_nothing(stack):
    lid = stack.lock_id
    stack.conn.sync_locks()
    for doc in (None, [], {"x": 1}, {"lock": "ajar"}, "locked"):
        stack.conn.on_mqtt_state(lid, doc)
    stack.conn.on_mqtt_status(lid, "maybe")
    row = stack.store.get_lock(lid)
    assert int(stack.store.meta_get("mqtt_malformed")) == 6
    assert row["mqtt_state"] is None and row["mqtt_online"] is None


def test_an_mqtt_echo_settles_only_the_command_of_the_lock_it_came_from(stack):
    a, b = stack.lock_ids[0], stack.lock_ids[1]
    cmd = stack.conn.send_command(a, "unlock")
    stack.conn.on_mqtt_state(b, {"lock": "unlocked", "last_cmd": cmd["id"]})
    assert stack.store.get_command(cmd["id"])["status"] == "pending", "another lock's echo must not confirm this command"
    stack.conn.on_mqtt_state(a, {"lock": "unlocked", "last_cmd": cmd["id"]})
    assert stack.store.get_command(cmd["id"])["status"] == "confirmed"


@pytest.mark.parametrize("action,end_state,want", [("unlock", "unlocked", "confirmed"), ("unlock", "jammed", "failed"), ("lock", "unlocked", "failed"), ("lock", "locked", "confirmed")])
def test_the_end_state_decides_whether_a_command_worked(stack, action, end_state, want):
    cmd = stack.conn.send_command(stack.lock_id, action)
    stack.conn.on_mqtt_state(stack.lock_id, {"lock": end_state, "last_cmd": cmd["id"]})
    assert stack.store.get_command(cmd["id"])["status"] == want


def test_battery_low_and_online_offline_events_update_the_record(stack):
    lid = stack.lock_id
    stack.cloud._on_mqtt(None, None, type("M", (), {"topic": f"locks/{lid}/event", "payload": b'{"type":"battery_low","battery":12}'})())
    wait_until(lambda: stack.store.get_lock(lid) and stack.store.get_lock(lid)["battery_low"] == 1, what="the battery_low event")
    assert stack.store.get_lock(lid)["battery"] == 12
    stack.lock_status(lid, False)
    wait_until(lambda: stack.store.get_lock(lid)["online"] == 0, what="the offline event")
    stack.lock_status(lid, True)
    wait_until(lambda: stack.store.get_lock(lid)["online"] == 1, what="the online event")
