"""Mock identity provider standing in for Keycloak (dev only). Signs RS256, publishes a JWKS.

- `password` grant: issues a user token for a runtime client (simulates SSO; no password check).
- RFC 8693 token exchange: services swap the token they received for one bound to the next
  hop's audience, with the delegation path recorded in nested `act` claims.
"""
from __future__ import annotations

import base64
import fnmatch
import hmac
import json
import time
import uuid
from typing import Any

from poc.common import jwt
from poc.common.identity import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE
from poc.common.jwt import TokenError
from poc.common.web import Request, Response
from poc.settings import Settings

USER_TOKEN_TTL = 8 * 3600
EXCHANGED_TOKEN_TTL = 300


class ExchangeError(Exception):
    def __init__(self, code: str, description: str):
        super().__init__(description)
        self.code = code


class IdentityProvider:
    def __init__(self, settings: Settings):
        self.settings = settings
        directory = settings.load("users.json")
        self.users: dict[str, Any] = directory["users"]
        self.clients: dict[str, Any] = directory["clients"]
        self.key = self._load_key()

    def _load_key(self) -> jwt.RsaKey:
        """Signing key lives in var/ (git-ignored) and is reused across restarts."""
        path = self.settings.var_dir / "idp_signing_key.json"
        if path.exists():
            return jwt.RsaKey.from_dict(json.loads(path.read_text(encoding="utf-8")))
        key = jwt.RsaKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(key.to_dict()), encoding="utf-8")
        return key

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.key.public_jwk()]}

    def _sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode(claims, self.key)

    def issue_user_token(self, username: str, client_id: str) -> str:
        user = self.users.get(username)
        if user is None:
            raise ExchangeError("invalid_grant", f"unknown user {username!r}")
        if self.clients.get(client_id, {}).get("type") != "runtime":
            raise ExchangeError("invalid_client", f"unknown runtime client {client_id!r}")
        now = int(time.time())
        return self._sign({
            "iss": self.settings.issuer, "sub": username, "aud": "agent-gateway", "azp": client_id,
            "iat": now, "exp": now + USER_TOKEN_TTL, "jti": str(uuid.uuid4()),
            "name": user["name"], "groups": user["groups"], "roles": user["roles"],
        })

    def exchange(self, client_id: str, client_secret: str, subject_token: str, audience: str) -> str:
        client = self.clients.get(client_id, {})
        if client.get("type") != "service" or not hmac.compare_digest(client.get("secret", ""), client_secret):
            raise ExchangeError("invalid_client", "client authentication failed")
        rules = client.get("exchange", {})
        try:
            claims = jwt.decode(subject_token, lambda kid: self.key.public_jwk() if kid == self.key.kid else None,
                                audience=rules.get("from", []), issuer=self.settings.issuer)
        except TokenError as e:
            raise ExchangeError("invalid_grant", f"subject token rejected: {e}") from e
        if not any(fnmatch.fnmatchcase(audience, pattern) for pattern in rules.get("to", [])):
            raise ExchangeError("invalid_target", f"{client_id} may not obtain tokens for {audience!r}")
        now = int(time.time())
        exchanged = {k: claims[k] for k in ("sub", "name", "groups", "roles") if k in claims}
        exchanged.update({
            "iss": self.settings.issuer, "aud": audience, "azp": client_id,
            "iat": now, "exp": min(claims["exp"], now + EXCHANGED_TOKEN_TTL), "jti": str(uuid.uuid4()),
            "act": {"sub": client_id, "act": claims.get("act") or {"sub": claims["azp"]}},
        })
        return self._sign(exchanged)


def make_app(idp: IdentityProvider):
    token_path = idp.settings.token_endpoint.removeprefix(idp.settings.idp_url)
    discovery_path = idp.settings.issuer.removeprefix(idp.settings.idp_url) + "/.well-known/openid-configuration"
    jwks_path = idp.settings.jwks_uri.removeprefix(idp.settings.idp_url)

    def app(req: Request) -> Response:
        if req.method == "GET" and req.path == discovery_path:
            return Response(200, {
                "issuer": idp.settings.issuer,
                "token_endpoint": idp.settings.token_endpoint,
                "jwks_uri": idp.settings.jwks_uri,
                "grant_types_supported": ["password", TOKEN_EXCHANGE],
                "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            })
        if req.method == "GET" and req.path == jwks_path:
            return Response(200, idp.jwks())
        if req.method == "POST" and req.path == token_path:
            form = req.form()
            basic = req.headers.get("authorization", "")
            if basic[:6].lower() == "basic ":  # client_secret_basic (what agentgateway sends)
                client_id, _, secret = base64.b64decode(basic[6:]).decode("utf-8").partition(":")
                form.setdefault("client_id", client_id)
                form.setdefault("client_secret", secret)
            grant = form.get("grant_type")
            try:
                if grant == "password":
                    token = idp.issue_user_token(form.get("username", ""), form.get("client_id", ""))
                elif grant == TOKEN_EXCHANGE:
                    token = idp.exchange(form.get("client_id", ""), form.get("client_secret", ""),
                                         form.get("subject_token", ""), form.get("audience", ""))
                else:
                    return Response(400, {"error": "unsupported_grant_type"})
            except ExchangeError as e:
                return Response(401 if e.code == "invalid_client" else 400,
                                {"error": e.code, "error_description": str(e)})
            claims = jwt.unverified_claims(token)
            return Response(200, {"access_token": token, "token_type": "Bearer",
                                  "issued_token_type": ACCESS_TOKEN_TYPE,
                                  "expires_in": claims["exp"] - int(time.time())})
        return Response(404, {"error": "not found"})

    return app
