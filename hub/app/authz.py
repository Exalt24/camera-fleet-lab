"""Role check for the routes that sit behind the SSO proxy (security/iam/).

oauth2-proxy authenticates the user against Keycloak and sets headers on the request it forwards: X-Forwarded-Preferred-Username
(the Keycloak user name; X-Forwarded-User only holds the opaque subject id) and X-Forwarded-Groups (the realm roles from the token, comma separated). A header is only believed when the TCP peer is the proxy's
fixed address on the wan network. Anything else, including a request to the published port that carries the same headers, is
treated as having no roles. With no TRUSTED_PROXY_IP set nobody is trusted, so the base stack behaves exactly as before.
"""
from __future__ import annotations

from collections.abc import Mapping

ADMIN_ROLE = "fleet-admin"
VIEWER_ROLE = "fleet-viewer"


def identity(headers: Mapping[str, str], peer_ip: str | None, trusted_proxy_ip: str | None) -> tuple[str | None, frozenset[str]]:
    """Returns (user, roles). An untrusted peer or a missing header gives (None, no roles)."""
    if not trusted_proxy_ip or not peer_ip or peer_ip != trusted_proxy_ip:
        return None, frozenset()
    user = (headers.get("x-forwarded-preferred-username") or headers.get("x-forwarded-user") or "").strip() or None
    raw = headers.get("x-forwarded-groups") or ""
    roles = frozenset(r.strip().removeprefix("role:") for r in raw.split(",") if r.strip())
    return user, roles


def is_admin(roles: frozenset[str]) -> bool:
    return ADMIN_ROLE in roles
