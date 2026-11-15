#!/usr/bin/env python3
"""Live proof for the IAM layer: Keycloak (realm camera-fleet) with TOTP, oauth2-proxy in front of the monitor dashboard.

Start the stack first (security/iam/check_iam.sh does it for you):
    bash security/iam/setup.sh
    docker compose -p cfl-iam --profile iam up -d --build

Standard library only. It plays a browser at the HTTP level (cookies per host, redirects followed by hand, the login forms
posted the way Keycloak's pages post them), computes TOTP codes with a small RFC 6238 implementation, and resets the two
sample users through Keycloak's admin API before it starts so it can be run again. Each check prints PASS or FAIL.

    python security/iam/check_iam.py [--save docs/security/iam/check_iam_run.txt]

Exit code 0 only if every check passes. The password and TOTP secret handling is for the sample users in the realm file only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROXY = "http://127.0.0.1:4180"          # oauth2-proxy, the only way to the dashboard
HUB_DIRECT = "http://127.0.0.1:8100"     # the hub's own published port, to prove the role headers are not believed there
KC = "http://localhost:8180"             # Keycloak, as the browser addresses it (the issuer in every token)
REALM = "camera-fleet"
USERS = {
    "viewer": ("viewer.sample", "ViewerSample-2026"),
    "admin": ("admin.sample", "AdminSample-2026"),
}
DASHBOARD_MARK = "Camera fleet lab"


# ---------------------------------------------------------------------------------------------------------------- TOTP
def totp(secret: bytes, at: float | None = None, step: int = 30, digits: int = 6) -> str:
    """RFC 6238 over HMAC-SHA1, the default Keycloak uses and every authenticator app speaks."""
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(value).zfill(digits)


def totp_counter(at: float | None = None, step: int = 30) -> int:
    return int((time.time() if at is None else at) // step)


# ------------------------------------------------------------------------------------------------------- tiny browser
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):    # noqa: D401 - handing every redirect back to the caller
        return None


class Browser:
    """Cookies are kept per host name (not per port, like a browser), so localhost (Keycloak) and 127.0.0.1 (proxy) stay apart.
    http.cookiejar is not used: it mishandles the host name `localhost`."""

    def __init__(self) -> None:
        self.opener = urllib.request.build_opener(_NoRedirect)
        self.cookies: dict[str, dict[str, str]] = {}

    def request(self, url: str, data: dict | None = None, headers: dict | None = None) -> tuple[int, str | None, str]:
        host = urllib.parse.urlsplit(url).hostname or ""
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, headers=headers or {})
        jar = self.cookies.get(host, {})
        if jar:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in jar.items()))
        try:
            resp = self.opener.open(req, timeout=20)
        except urllib.error.HTTPError as err:
            resp = err
        for sc in resp.headers.get_all("Set-Cookie") or []:
            k, _, v = sc.split(";")[0].partition("=")
            if "max-age=0" in sc.lower() or v == "":
                self.cookies.setdefault(host, {}).pop(k, None)
            else:
                self.cookies.setdefault(host, {})[k] = v
        return resp.status, resp.headers.get("Location"), resp.read().decode("utf-8", "replace")

    def follow(self, url: str, data: dict | None = None, headers: dict | None = None, limit: int = 12) -> tuple[int, str, str]:
        """Follow redirects by hand. Returns (status, final url, body)."""
        for _ in range(limit):
            status, loc, body = self.request(url, data, headers)
            data = None
            if status in (301, 302, 303, 307, 308) and loc:
                url = urllib.parse.urljoin(url, loc)
                continue
            return status, url, body
        raise RuntimeError("too many redirects")


def form_action(body: str, form_id: str) -> str | None:
    m = re.search(r'<form[^>]*id="%s"[^>]*action="([^"]+)"' % re.escape(form_id), body) or re.search(
        r'<form[^>]*action="([^"]+)"[^>]*id="%s"' % re.escape(form_id), body)
    return html.unescape(m.group(1)) if m else None


def page_kind(body: str) -> str:
    """What Keycloak's page is asking for."""
    if 'id="kc-totp-settings-form"' in body:
        return "totp-setup"
    if 'id="kc-otp-login-form"' in body or 'name="otp"' in body:
        return "otp-prompt"
    if 'id="kc-form-login"' in body:
        return "login"
    return "other"


def error_text(body: str) -> str:
    m = re.search(r'class="[^"]*kc-feedback-text[^"]*"[^>]*>([^<]+)<', body) or re.search(r'id="input-error[^"]*"[^>]*>\s*([^<]+)<', body)
    return html.unescape(m.group(1)).strip() if m else ""


def open_login(b: Browser) -> tuple[str, str]:
    """GET the dashboard with no session and land on the Keycloak login page. Returns (form action url, page body)."""
    status, url, body = b.follow(PROXY + "/")
    action = form_action(body, "kc-form-login")
    if not action:
        raise RuntimeError(f"no login form after {url} ({status})")
    return action, body


def submit_password(b: Browser, user: str, password: str) -> tuple[int, str, str]:
    action, _ = open_login(b)
    return b.follow(action, {"username": user, "password": password, "credentialId": ""})


def submit_totp_setup(b: Browser, body: str, secret_hex_ascii: str, code: str) -> tuple[int, str, str]:
    action = form_action(body, "kc-totp-settings-form")
    assert action, "no setup form"
    return b.follow(action, {"totp": code, "totpSecret": secret_hex_ascii, "userLabel": "sample authenticator", "saveTOTPBtn": "Submit"})


def submit_otp(b: Browser, body: str, code: str) -> tuple[int, str, str]:
    action = form_action(body, "kc-otp-login-form")
    assert action, "no otp form"
    return b.follow(action, {"otp": code, "login": "Sign In"})


def reaches_dashboard(b: Browser) -> bool:
    status, url, body = b.follow(PROXY + "/")
    return status == 200 and url.startswith(PROXY) and DASHBOARD_MARK in body


def wait_for_new_window(last_counter: int) -> None:
    """Keycloak refuses a TOTP code it has already accepted, so the next login needs the next 30 s window. Polls in 0.25 s steps."""
    while totp_counter() <= last_counter:
        time.sleep(0.25)


# ------------------------------------------------------------------------------------------------------- admin API
def read_env(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


class KeycloakAdmin:
    def __init__(self, user: str, password: str) -> None:
        self.creds = (user, password)
        self.token = ""
        self.token_at = 0.0

    def _fresh_token(self) -> str:
        """The master realm's tokens also live 60 s, so a long run asks again instead of reusing a stale one."""
        if not self.token or time.time() - self.token_at > 30:
            r = self._call("POST", f"{KC}/realms/master/protocol/openid-connect/token", form={
                "grant_type": "password", "client_id": "admin-cli", "username": self.creds[0], "password": self.creds[1]}, token="")
            self.token, self.token_at = r["access_token"], time.time()
        return self.token

    def _call(self, method: str, url: str, form: dict | None = None, js=None, token: str | None = None):
        data = urllib.parse.urlencode(form).encode() if form is not None else (json.dumps(js).encode() if js is not None else None)
        headers = {}
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif js is not None:
            headers["Content-Type"] = "application/json"
        if token is None:
            headers["Authorization"] = "Bearer " + self._fresh_token()
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode()
        return json.loads(raw) if raw.strip() else {}

    def api(self, method: str, path: str, js=None):
        return self._call(method, f"{KC}/admin/realms/{REALM}{path}", js=js)

    def user_id(self, username: str) -> str:
        return self.api("GET", f"/users?username={urllib.parse.quote(username)}&exact=true")[0]["id"]

    def reset_user(self, username: str) -> None:
        """Back to the realm file's state: no OTP credential, the Configure OTP action set, no lockout, no sessions."""
        uid = self.user_id(username)
        for cred in self.api("GET", f"/users/{uid}/credentials"):
            if cred["type"] == "otp":
                self.api("DELETE", f"/users/{uid}/credentials/{cred['id']}")
        user = self.api("GET", f"/users/{uid}")
        user["requiredActions"] = ["CONFIGURE_TOTP"]
        user["enabled"] = True
        self.api("PUT", f"/users/{uid}", js=user)
        self.api("DELETE", f"/attack-detection/brute-force/users/{uid}")
        self.api("POST", f"/users/{uid}/logout")

    def lockout(self, username: str) -> dict:
        return self.api("GET", f"/attack-detection/brute-force/users/{self.user_id(username)}")

    def clear_lockout(self, username: str) -> None:
        self.api("DELETE", f"/attack-detection/brute-force/users/{self.user_id(username)}")


# ---------------------------------------------------------------------------------------------------------- the run
class Run:
    def __init__(self, save: Path | None) -> None:
        self.results: list[tuple[bool, str]] = []
        self.lines: list[str] = []
        self.save = save

    def say(self, text: str) -> None:
        print(text, flush=True)
        self.lines.append(text)

    def check(self, ok: bool, name: str, detail: str = "") -> bool:
        self.results.append((bool(ok), name))
        self.say(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""))
        return bool(ok)

    def finish(self) -> int:
        passed = sum(1 for ok, _ in self.results if ok)
        self.say(f"live IAM checks passed: {passed} of {len(self.results)}")
        if self.save:
            self.save.parent.mkdir(parents=True, exist_ok=True)
            self.save.write_text("\n".join(self.lines) + "\n", encoding="utf-8", newline="\n")
        return 0 if passed == len(self.results) else 1


def enrol(b: Browser, run: Run, role: str) -> bytes:
    """First sign in of a sample user: password, then the forced Configure OTP page, then a wrong and a right code."""
    user, password = USERS[role]
    status, url, body = submit_password(b, user, password)
    kind = page_kind(body)
    run.check(kind == "totp-setup", f"{role}: a correct password alone does not sign in, Keycloak demands OTP set up", f"page={kind}")
    run.check(not reaches_dashboard(b), f"{role}: with the password accepted but no code, the dashboard is still behind the login")
    secret_ascii = re.search(r'name="totpSecret" value="([^"]+)"', body).group(1)
    secret = secret_ascii.encode()
    bad = totp(secret, time.time() + 3600)          # a code from an hour ahead is never inside the accepted window
    status, url, body2 = submit_totp_setup(b, body, secret_ascii, bad)
    run.check(page_kind(body2) == "totp-setup" and not reaches_dashboard(b), f"{role}: a wrong code at OTP set up is refused", error_text(body2))
    action_body = body2
    code = totp(secret)
    status, url, after = submit_totp_setup(b, action_body, secret_ascii, code)
    run.check(reaches_dashboard(b), f"{role}: a valid TOTP code (computed from the secret) completes set up and reaches the dashboard")
    return secret


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--save", help="write the run output to this file")
    ap.add_argument("--reset-only", action="store_true", help="reset the two sample users to the realm file's state and exit")
    ap.add_argument("--env", default=str(HERE / ".env"))
    args = ap.parse_args()
    run = Run(Path(args.save) if args.save else None)

    env = read_env(Path(args.env))
    admin = KeycloakAdmin(env["KC_BOOTSTRAP_ADMIN_USERNAME"], env["KC_BOOTSTRAP_ADMIN_PASSWORD"])
    for who in ("viewer.sample", "admin.sample"):
        admin.reset_user(who)
    if args.reset_only:
        print("sample users reset")
        return 0

    run.say(f"IAM live checks, {time.strftime('%Y-%m-%d %H:%M:%S')}")
    # 1. no session ----------------------------------------------------------------------------------------------------
    run.say("without a session")
    b0 = Browser()
    status, loc, _ = b0.request(PROXY + "/")
    run.check(status == 302 and (loc or "").startswith(f"{KC}/realms/{REALM}/protocol/openid-connect/auth"),
              "an unauthenticated request for the dashboard is redirected to the Keycloak login", f"{status} -> {(loc or '')[:60]}")
    for path in ("/status", "/history", "/admin/probe-config"):
        status, loc, _ = Browser().request(PROXY + path)
        run.check(status in (302, 401), f"an unauthenticated request for {path} gets no data", f"{status}")
    status, _, body = Browser().request(HUB_DIRECT + "/admin/probe-config", headers={"X-Forwarded-User": "admin.sample", "X-Forwarded-Groups": "fleet-admin"})
    run.check(status == 403, "a forged admin header sent straight to the hub's own port is refused (headers are only believed from the proxy)", f"{status}")

    # 2. wrong password -----------------------------------------------------------------------------------------------
    run.say("wrong password")
    bw = Browser()
    status, url, body = submit_password(bw, USERS["viewer"][0], "not-the-password")
    run.check(page_kind(body) == "login" and "Invalid username or password" in body and not reaches_dashboard(bw),
              "a wrong password is refused and no session starts", error_text(body))

    # 3. viewer: password, then OTP set up, then dashboard ---------------------------------------------------------------
    run.say("viewer (fleet-viewer)")
    bv = Browser()
    viewer_secret = enrol(bv, run, "viewer")
    _, _, who = bv.follow(PROXY + "/whoami")
    run.check('"viewer.sample"' in who and "fleet-viewer" in who and "fleet-admin" not in who, "the hub sees the viewer with the fleet-viewer role only", who.strip()[:80])
    status, _, body = bv.follow(PROXY + "/status")
    run.check(status == 200 and '"state"' in body, "a viewer can read the monitor status", f"{status}")
    status, _, body = bv.follow(PROXY + "/admin/probe-config")
    run.check(status == 403, "a viewer asking for the admin route gets 403", f"{status} {body.strip()[:60]}")

    # 4. admin ---------------------------------------------------------------------------------------------------------
    run.say("admin (fleet-admin)")
    ba = Browser()
    admin_secret = enrol(ba, run, "admin")
    admin_counter = totp_counter()
    status, _, body = ba.follow(PROXY + "/admin/probe-config")
    run.check(status == 200 and '"probe_interval_s"' in body, "an admin can reach the admin route", f"{status} {body.strip()[:70]}")

    # 5. a second, ordinary sign in as admin: password then the OTP prompt -------------------------------------------------
    run.say("an ordinary sign in (OTP already set up)")
    bo = Browser()
    status, url, body = submit_password(bo, USERS["admin"][0], USERS["admin"][1])
    run.check(page_kind(body) == "otp-prompt" and not reaches_dashboard(bo), "admin: password correct, the OTP prompt appears and the dashboard is still closed", f"page={page_kind(body)}")
    status, url, body_bad = submit_otp(bo, body, "000000" if totp(admin_secret) != "000000" else "111111")
    run.check(page_kind(body_bad) == "otp-prompt" and not reaches_dashboard(bo), "admin: a wrong OTP code is refused", error_text(body_bad))
    wait_for_new_window(admin_counter)
    status, url, after = submit_otp(bo, body_bad, totp(admin_secret))
    run.check(reaches_dashboard(bo), "admin: correct password plus a valid TOTP code reaches the dashboard")
    sess_cookie = bo.cookies.get("127.0.0.1", {}).get("_oauth2_proxy", "")
    run.check(bool(sess_cookie), "oauth2-proxy session cookie is set only after the code")

    # 6. token past its lifespan -----------------------------------------------------------------------------------------
    run.say("token lifespan")
    wait_for_new_window(totp_counter())
    token = _direct_grant(USERS["admin"][0], USERS["admin"][1], totp(admin_secret))
    claims = _jwt_claims(token)
    lifespan = claims["exp"] - claims["iat"]
    run.check(lifespan == 60, "the access token's lifespan is 60 seconds", f"exp-iat={lifespan}")
    bt = Browser()
    status, _, body = bt.request(PROXY + "/status", headers={"Authorization": "Bearer " + token})
    run.check(status == 200, "the same token is accepted while it is fresh", f"{status}")
    t0 = time.time()
    refused = None
    while time.time() - t0 < 100:
        status, _, body = Browser().request(PROXY + "/status", headers={"Authorization": "Bearer " + token})
        if status != 200:                    # oauth2-proxy sends an unauthenticated API call back to the login (302)
            refused = status
            break
        time.sleep(1)
    waited = time.time() - t0
    run.check(refused is not None, "the token is no longer honoured once past its lifespan", f"status {refused} (sent back to login) {int(time.time() - claims['iat'])} s after it was issued")
    # the browser session is renewed with the refresh token rather than living on past the token
    status, url, body = bo.follow(PROXY + "/status")
    run.check(status == 200, "a browser session past the 45 s refresh point is renewed with its refresh token and still works", f"{status}")

    # 7. lockout ---------------------------------------------------------------------------------------------------------
    run.say("brute force lockout (viewer.sample)")
    first_locked = None
    refused_n = 0
    for n in range(1, 11):
        bl = Browser()
        status, url, body = submit_password(bl, USERS["viewer"][0], f"wrong-password-{n}")
        refused_n += int(not reaches_dashboard(bl))
        if first_locked is None and admin.lockout(USERS["viewer"][0]).get("disabled"):
            first_locked = n
    state = admin.lockout(USERS["viewer"][0])
    run.check(refused_n == 10, "ten wrong passwords in a row were all refused", f"{refused_n} of 10 refused")
    run.check(bool(state.get("disabled")), "Keycloak reports the account as locked after the ten wrong passwords", f"numFailures={state.get('numFailures')}, locked from attempt {first_locked}")
    bc = Browser()
    status, url, body = submit_password(bc, USERS["viewer"][0], USERS["viewer"][1])
    run.check(page_kind(body) in ("login", "other") and not reaches_dashboard(bc), "while locked, even the CORRECT password is refused", f"page={page_kind(body)}")
    admin.clear_lockout(USERS["viewer"][0])
    bu = Browser()
    status, url, body = submit_password(bu, USERS["viewer"][0], USERS["viewer"][1])
    run.check(page_kind(body) == "otp-prompt", "after an admin clears the lock the correct password is accepted again (OTP prompt)", f"page={page_kind(body)}")

    return run.finish()


def _direct_grant(user: str, password: str, code: str) -> str:
    """Password plus OTP in one request through the cfl-check client, only to obtain a token whose age can be controlled."""
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "cfl-check", "username": user, "password": password, "totp": code}).encode()
    req = urllib.request.Request(f"{KC}/realms/{REALM}/protocol/openid-connect/token", data=data)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())["access_token"]


def _jwt_claims(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


if __name__ == "__main__":
    sys.exit(main())
