"""Offline tests for security/iam/realm-camera-fleet.json and the compose wiring around it. No Docker, no Keycloak.

They pin the settings the live proof (check_iam.py) relies on: every user must set up a TOTP code, the access token lives a short
time, brute force detection is on and locks within ten failures, the two roles exist, only the one test client may use the password
grant, and no client secret is committed (the realm file holds a ${PLACEHOLDER} that Keycloak fills from the gitignored .env).

The realm file is read from REALM_PATH when set, so run_mutations.py can run these same tests against a copy with one setting removed
and require a red run.
    python -m pytest security/tests/test_iam_realm.py -q
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
REALM_FILE = Path(os.environ.get("REALM_PATH") or ROOT / "security" / "iam" / "realm-camera-fleet.json")
MAX_TOKEN_LIFESPAN_S = 300
MAX_FAILURES_BEFORE_LOCK = 10


@pytest.fixture(scope="module")
def realm() -> dict:
    return json.loads(REALM_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def clients(realm):
    return {c["clientId"]: c for c in realm.get("clients", [])}


def test_there_are_exactly_two_sample_users(realm):
    assert [u["username"] for u in realm["users"]] == ["viewer.sample", "admin.sample"]


def test_every_user_must_configure_otp(realm):
    for user in realm["users"]:
        assert "CONFIGURE_TOTP" in user.get("requiredActions", []), f"{user['username']} is not required to configure OTP"


def test_the_configure_otp_action_is_enabled_and_default_for_new_users(realm):
    actions = {a["alias"]: a for a in realm.get("requiredActions", [])}
    assert actions["CONFIGURE_TOTP"]["enabled"] is True
    assert actions["CONFIGURE_TOTP"]["defaultAction"] is True


def test_otp_policy_is_time_based_six_digits(realm):
    assert realm["otpPolicyType"] == "totp" and realm["otpPolicyDigits"] == 6 and realm["otpPolicyPeriod"] == 30


def test_the_access_token_lifespan_is_short(realm):
    life = realm["accessTokenLifespan"]
    assert 0 < life <= MAX_TOKEN_LIFESPAN_S, f"access token lifespan is {life} s"


def test_brute_force_detection_is_on_and_locks_within_ten_failures(realm):
    assert realm["bruteForceProtected"] is True
    assert 0 < realm["failureFactor"] <= MAX_FAILURES_BEFORE_LOCK
    assert realm["waitIncrementSeconds"] > 0 or realm.get("permanentLockout") is True


def test_the_two_roles_exist_and_admin_includes_viewer(realm):
    roles = {r["name"]: r for r in realm["roles"]["realm"]}
    assert {"fleet-viewer", "fleet-admin"} <= set(roles)
    assert roles["fleet-admin"].get("composite") is True
    assert "fleet-viewer" in roles["fleet-admin"]["composites"]["realm"]


def test_each_sample_user_has_the_role_that_matches_the_name(realm):
    users = {u["username"]: u for u in realm["users"]}
    assert users["viewer.sample"]["realmRoles"] == ["fleet-viewer"]
    assert users["admin.sample"]["realmRoles"] == ["fleet-admin"]


def test_no_client_secret_is_committed(realm):
    for client in realm["clients"]:
        secret = client.get("secret")
        if client.get("publicClient"):
            assert secret is None, f"public client {client['clientId']} carries a secret"
        else:
            assert isinstance(secret, str) and re.fullmatch(r"\$\{[A-Z0-9_]+\}", secret), f"{client['clientId']} holds a literal secret"


def test_no_secret_sits_anywhere_else_in_the_realm_file(realm):
    text = REALM_FILE.read_text(encoding="utf-8")
    assert not re.search(r'"(?:secret|registrationAccessToken|clientSecret)"\s*:\s*"(?!\$\{)[^"]+"', text)


def test_only_the_check_client_may_use_the_password_grant(realm):
    for cid, c in clients(realm).items():
        if cid == "cfl-check":
            assert c["publicClient"] is True and c["directAccessGrantsEnabled"] is True and not c.get("redirectUris") and c["standardFlowEnabled"] is False
        else:
            assert c.get("directAccessGrantsEnabled") is False, f"{cid} allows the password grant"


def test_the_dashboard_client_uses_the_code_flow_with_pkce_on_loopback_only(realm):
    c = clients(realm)["camera-fleet-dashboard"]
    assert c["standardFlowEnabled"] is True and c["implicitFlowEnabled"] is False
    assert c["attributes"]["pkce.code.challenge.method"] == "S256"
    assert c["redirectUris"] and all(u.startswith("http://127.0.0.1:") and "*" not in u for u in c["redirectUris"])


def test_the_sample_passwords_are_permanent_and_not_empty(realm):
    for u in realm["users"]:
        cred = u["credentials"][0]
        assert cred["type"] == "password" and cred["value"] and cred["temporary"] is False


# ---- the compose wiring ------------------------------------------------------------------------------------------------
def test_keycloak_and_the_proxy_are_behind_the_iam_profile_only(compose):
    for name in ("keycloak", "oauth2-proxy"):
        assert compose["services"][name]["profiles"] == ["iam"]


def test_images_are_pinned_to_a_full_version(compose):
    for name in ("keycloak", "oauth2-proxy"):
        tag = compose["services"][name]["image"].split(":")[1]
        assert re.fullmatch(r"v?\d+\.\d+\.\d+", tag), f"{name} image tag {tag} is not a full version"


def test_compose_holds_no_literal_client_or_cookie_secret(compose):
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert not re.search(r"(?i)(client[-_]secret|cookie[-_]secret)\s*[=:]\s*[^\s$]", text)
    for name in ("keycloak", "oauth2-proxy"):
        env_files = compose["services"][name].get("env_file") or []
        assert any("security/iam/.env" in (e["path"] if isinstance(e, dict) else e) for e in env_files)


def test_the_generated_env_file_is_gitignored():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").split()
    assert ".env" in ignored


def test_oauth2_proxy_only_lets_the_two_roles_in(compose):
    cmd = compose["services"]["oauth2-proxy"]["command"]
    assert "--allowed-role=fleet-viewer" in cmd and "--allowed-role=fleet-admin" in cmd
    assert "--provider=keycloak-oidc" in cmd


def test_the_hub_trusts_role_headers_only_from_the_proxys_address(compose):
    proxy_ip = compose["services"]["oauth2-proxy"]["networks"]["wan"]["ipv4_address"]
    assert compose["services"]["hub"]["environment"]["TRUSTED_PROXY_IP"] == proxy_ip
