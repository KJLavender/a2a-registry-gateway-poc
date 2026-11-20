"""Keycloak token-exchange delegation (preview in 26.8) for the PoC: setup and client helpers.

Delegation lets a user consent to "agent-gateway may act for me". The user's token then carries
`may_act`, and agent-gateway can exchange it (with its own service-account token as actor_token)
for a token that carries `act`. See tests/test_keycloak_delegation.py for what this does and does
not cover in a multi-hop chain.
"""
from __future__ import annotations

import html
import re
import secrets
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit

from poc.common.identity import ACCESS_TOKEN_TYPE, DEV_PASSWORD, TOKEN_EXCHANGE
from poc.common.web import http
from poc.keycloak_realm import DELEGATING_CLIENT, DELEGATION_REDIRECT
from poc.settings import Settings

ACTOR = "agent-gateway"


def _admin_headers(settings: Settings) -> dict[str, str]:
    status, body, _ = http("POST", f"{settings.idp_url}/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})
    if status != 200:
        raise RuntimeError(f"Keycloak admin login failed: {body}")
    return {"Authorization": f"Bearer {body['access_token']}"}


def ensure_delegation_permission(settings: Settings, actor: str = ACTOR) -> None:
    """FGAP v2: let `actor` (its service account) act for any user of the realm. Idempotent."""
    headers = _admin_headers(settings)
    admin = f"{settings.idp_url}/admin/realms/poc"
    perms_client = http("GET", f"{admin}/clients?clientId=admin-permissions", headers=headers)[1][0]["id"]
    server = f"{admin}/clients/{perms_client}/authz/resource-server"
    actor_id = http("GET", f"{admin}/clients?clientId={actor}", headers=headers)[1][0]["id"]
    policy_name = f"actor {actor}"
    policies = http("GET", f"{server}/policy?name={quote(policy_name)}", headers=headers)[1] or []
    policy = next((p for p in policies if p["name"] == policy_name), None)
    if policy is None:
        status, policy, _ = http("POST", f"{server}/policy/client", headers=headers,
                                 json_body={"name": policy_name, "clients": [actor_id], "logic": "POSITIVE"})
        if status not in (200, 201):
            raise RuntimeError(f"creating client policy failed: {status} {policy}")
    perm_name = f"{actor} may act for all users"
    existing = http("GET", f"{server}/permission?name={quote(perm_name)}", headers=headers)[1] or []
    if not any(p["name"] == perm_name for p in existing):
        status, body, _ = http("POST", f"{server}/permission/scope", headers=headers, json_body={
            "name": perm_name, "resourceType": "Users", "scopes": ["delegate"], "policies": [policy["id"]],
            "decisionStrategy": "UNANIMOUS"})
        if status not in (200, 201):
            raise RuntimeError(f"creating delegation permission failed: {status} {body}")


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def browser_login(settings: Settings, username: str, scope: str) -> dict[str, Any]:
    """Authorization code flow with the login form and the consent screen filled in, as a user would."""
    # Keycloak marks its login cookies Secure; browsers still send them to http://localhost but
    # Python's CookieJar does not, so keep them by hand.
    cookies: dict[str, str] = {}
    opener = urlrequest.build_opener(urlrequest.ProxyHandler({}), _NoRedirect)

    def call(url: str, form: dict[str, str] | None = None) -> tuple[int, str, str]:
        data = urlencode(form).encode() if form is not None else None
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())} if cookies else {}
        try:
            with opener.open(urlrequest.Request(url, data=data, headers=headers), timeout=15) as resp:
                status, body, location, set_cookies = resp.status, resp.read(), "", resp.headers.get_all("Set-Cookie")
        except urlerror.HTTPError as e:  # 302 lands here because redirects are not followed
            location = e.headers.get("Location", "")
            status, body, set_cookies = e.code, e.read(), e.headers.get_all("Set-Cookie")
        for raw in set_cookies or []:
            name, _, value = raw.split(";", 1)[0].partition("=")
            cookies[name.strip()] = value.strip()
        return status, body.decode("utf-8", "replace"), location

    def form_of(page: str, base: str) -> tuple[str, dict[str, str]]:
        action = html.unescape(re.search(r'<form[^>]*action="([^"]+)"', page).group(1))
        hidden = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page))
        return urljoin(base, action), {k: html.unescape(v) for k, v in hidden.items()}

    auth = f"{settings.issuer}/protocol/openid-connect/auth?" + urlencode({
        "client_id": DELEGATING_CLIENT, "response_type": "code", "redirect_uri": DELEGATION_REDIRECT,
        "scope": scope, "state": secrets.token_hex(8)})
    status, page, location = call(auth)
    steps = 0
    while not location.startswith(DELEGATION_REDIRECT) and steps < 5:
        steps += 1
        if status in (301, 302, 303):
            status, page, location = call(urljoin(auth, location))
            continue
        action, fields = form_of(page, auth)
        if 'name="password"' in page:
            fields.update({"username": username, "password": DEV_PASSWORD, "credentialId": ""})
        else:  # consent screen
            fields["accept"] = "Yes"
        status, page, location = call(action, fields)
    code = parse_qs(urlsplit(location).query).get("code", [""])[0]
    if not code:
        raise RuntimeError(f"login did not return a code (HTTP {status}): {page[:300]}")
    status, body, _ = http("POST", settings.token_endpoint, form={
        "grant_type": "authorization_code", "code": code, "redirect_uri": DELEGATION_REDIRECT,
        "client_id": DELEGATING_CLIENT})
    if status != 200:
        raise RuntimeError(f"code exchange failed: {body}")
    return body


def service_token(settings: Settings, client_id: str) -> str:
    status, body, _ = http("POST", settings.token_endpoint, form={
        "grant_type": "client_credentials", "client_id": client_id,
        "client_secret": settings.client_secret(client_id)})
    if status != 200:
        raise RuntimeError(f"client_credentials for {client_id} failed: {body}")
    return body["access_token"]


def exchange(settings: Settings, client_id: str, subject_token: str, audience: str,
             actor_token: str | None = None) -> tuple[int, Any]:
    form = {"grant_type": TOKEN_EXCHANGE, "client_id": client_id, "client_secret": settings.client_secret(client_id),
            "subject_token": subject_token, "subject_token_type": ACCESS_TOKEN_TYPE, "audience": audience}
    if actor_token:
        form.update({"actor_token": actor_token, "actor_token_type": ACCESS_TOKEN_TYPE})
    status, body, _ = http("POST", settings.token_endpoint, form=form)
    return status, body
