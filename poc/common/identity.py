"""Token verification, principals, and an RFC 8693 token-exchange client."""
from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from poc.common import jwt
from poc.common.jwt import TokenError
from poc.common.web import http
from poc.settings import Settings

DEV_PASSWORD = "dev-password"  # every demo user, in both the mock IdP and the Keycloak realm
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

Verifier = Callable[[str, str], dict[str, Any]]


class JwksCache:
    """Fetches the IdP's JWKS on demand and again when an unknown key id shows up."""

    def __init__(self, jwks_uri: str):
        self.jwks_uri = jwks_uri
        self._keys: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def find(self, kid: str) -> dict[str, Any] | None:
        with self._lock:
            if kid not in self._keys:
                status, body, _ = http("GET", self.jwks_uri, timeout=5)
                if status == 200:
                    self._keys = {k["kid"]: k for k in body.get("keys", [])}
            return self._keys.get(kid)


def make_verifier(settings: Settings) -> Verifier:
    keys = JwksCache(settings.jwks_uri)

    def verify(token: str, audience: str) -> dict[str, Any]:
        return jwt.decode(token, keys.find, audience=audience, issuer=settings.issuer)
    return verify


def actor_chain(claims: dict[str, Any]) -> list[str]:
    """Delegation path from the most recent actor back to the original client (RFC 8693 `act`)."""
    chain: list[str] = []
    act = claims.get("act")
    while isinstance(act, dict):
        chain.append(act.get("sub", "?"))
        act = act.get("act")
    if not chain and claims.get("azp"):
        chain.append(claims["azp"])
    return chain


@dataclass(frozen=True)
class Principal:
    sub: str
    username: str
    name: str
    groups: tuple[str, ...]
    roles: tuple[str, ...]
    actors: tuple[str, ...]  # most recent actor first; last item is the client the user signed in with
    origin_claim: str = ""

    @property
    def origin_client(self) -> str:
        """The runtime the user signed in with. Keycloak carries it as `origin_client` (no `act` chain)."""
        return self.origin_claim or (self.actors[-1] if self.actors else "")

    @property
    def origin_scope(self) -> str:
        return f"origin-{self.origin_client}"

    @property
    def immediate_actor(self) -> str:
        return self.actors[0] if self.actors else ""

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> "Principal":
        username = claims.get("preferred_username", claims["sub"])
        return cls(claims["sub"], username, claims.get("name", username), tuple(claims.get("groups", [])),
                   tuple(claims.get("roles", [])), tuple(actor_chain(claims)), claims.get("origin_client", ""))


class TokenExchanger:
    """Exchanges an incoming token for a narrowly scoped one instead of forwarding it."""

    def __init__(self, settings: Settings, client_id: str):
        self.settings = settings
        self.client_id = client_id
        self.client_secret = settings.client_secret(client_id)
        self._cache: dict[tuple[str, str, str], tuple[str, float]] = {}
        self._lock = threading.Lock()

    def exchange(self, subject_token: str, audience: str, scope: str = "") -> str:
        key = (hashlib.sha256(subject_token.encode()).hexdigest(), audience, scope)
        with self._lock:
            cached = self._cache.get(key)
        if cached and cached[1] - 30 > time.time():
            return cached[0]
        status, body, _ = http("POST", self.settings.token_endpoint, form={
            "grant_type": TOKEN_EXCHANGE,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "subject_token": subject_token,
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "audience": audience,
            **({"scope": scope} if scope else {}),
        })
        if status != 200:
            raise TokenError(f"token exchange to {audience} failed: {body}")
        token = body["access_token"]
        with self._lock:
            self._cache[key] = (token, jwt.unverified_claims(token)["exp"])
        return token


def login(settings: Settings, username: str, client_id: str) -> str:
    """Dev-only stand-in for the SSO login a frontend would do against Keycloak."""
    status, body, _ = http("POST", settings.token_endpoint, form={
        "grant_type": "password", "username": username, "password": DEV_PASSWORD, "client_id": client_id})
    if status != 200:
        raise TokenError(f"login failed: {body}")
    return body["access_token"]
