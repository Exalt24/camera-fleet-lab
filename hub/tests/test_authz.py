"""Offline tests for the role check behind the SSO proxy. The headers are only believed from the proxy's own address."""
import importlib

import pytest
from fastapi.testclient import TestClient

from app import authz

PROXY = "172.30.0.30"


def test_roles_come_from_the_header_when_the_peer_is_the_proxy():
    user, roles = authz.identity({"x-forwarded-user": "admin.sample", "x-forwarded-groups": "fleet-admin,fleet-viewer"}, PROXY, PROXY)
    assert user == "admin.sample" and roles == {"fleet-admin", "fleet-viewer"}


def test_the_user_name_header_wins_over_the_opaque_subject_id():
    user, _ = authz.identity({"x-forwarded-user": "f024cfda-69e5", "x-forwarded-preferred-username": "viewer.sample", "x-forwarded-groups": "fleet-viewer"}, PROXY, PROXY)
    assert user == "viewer.sample"


def test_the_same_headers_from_any_other_peer_are_ignored():
    # a request to the published port can carry any header it likes
    user, roles = authz.identity({"x-forwarded-user": "admin.sample", "x-forwarded-groups": "fleet-admin"}, "172.30.0.1", PROXY)
    assert user is None and roles == frozenset()


def test_nobody_is_trusted_when_no_proxy_is_configured():
    user, roles = authz.identity({"x-forwarded-groups": "fleet-admin"}, PROXY, None)
    assert user is None and roles == frozenset()


def test_a_missing_peer_or_header_is_no_role_not_a_crash():
    assert authz.identity({}, PROXY, PROXY) == (None, frozenset())
    assert authz.identity({"x-forwarded-groups": "fleet-admin"}, None, PROXY) == (None, frozenset())


def test_groups_with_spaces_and_a_role_prefix_are_normalised():
    _, roles = authz.identity({"x-forwarded-groups": " role:fleet-admin , fleet-viewer"}, PROXY, PROXY)
    assert authz.is_admin(roles) and "fleet-viewer" in roles


def test_a_viewer_is_not_an_admin():
    assert not authz.is_admin(frozenset({"fleet-viewer"}))
    assert not authz.is_admin(frozenset())


def _client(monkeypatch, trusted):
    monkeypatch.setenv("DATABASE_URL", "mysql+aiomysql://x:y@nowhere/none")
    monkeypatch.setenv("TRUSTED_PROXY_IP", trusted)
    from app import main
    importlib.reload(main)
    return TestClient(main.app)          # no `with`, so the lifespan (database, probe loop) does not start


@pytest.fixture()
def client(monkeypatch):
    return _client(monkeypatch, "testclient")    # the Starlette test client reports its peer as "testclient"


def test_admin_route_refuses_a_viewer_and_a_request_with_no_roles(client):
    assert client.get("/admin/probe-config").status_code == 403
    assert client.get("/admin/probe-config", headers={"X-Forwarded-Groups": "fleet-viewer"}).status_code == 403


def test_admin_route_answers_an_admin(client):
    r = client.get("/admin/probe-config", headers={"X-Forwarded-User": "admin.sample", "X-Forwarded-Groups": "fleet-admin"})
    assert r.status_code == 200 and r.json()["camera"] == "cam1"


def test_whoami_reports_the_proxy_identity(client):
    r = client.get("/whoami", headers={"X-Forwarded-User": "viewer.sample", "X-Forwarded-Groups": "fleet-viewer"})
    assert r.json() == {"user": "viewer.sample", "roles": ["fleet-viewer"]}


def test_the_admin_route_is_closed_when_the_peer_is_not_the_proxy(monkeypatch):
    c = _client(monkeypatch, "172.30.0.30")
    assert c.get("/admin/probe-config", headers={"X-Forwarded-Groups": "fleet-admin"}).status_code == 403


def test_every_answer_carries_the_security_headers(client):
    r = client.get("/whoami")
    for name in ("X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy", "Permissions-Policy"):
        assert name in r.headers, name
    assert r.headers["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_the_dashboard_policy_has_no_unsafe_inline_and_carries_the_hash_of_the_served_script(client):
    # the hash in the header is the one a browser computes over the script text of the page the hub actually serves
    import base64
    import hashlib
    import re
    r = client.get("/")
    csp = r.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp
    script = re.search(r"<script>(.*?)</script>", r.text, re.S).group(1)
    assert "'sha256-" + base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode() + "'" in csp


def test_a_json_answer_gets_the_allow_nothing_policy_and_every_answer_is_no_store(client):
    r = client.get("/whoami")
    assert r.headers["Content-Security-Policy"] == "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    for path in ("/whoami", "/", "/admin/probe-config", "/nope"):
        assert client.get(path).headers["Cache-Control"] == "no-store", path


def test_the_api_docs_are_off_by_default(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path
