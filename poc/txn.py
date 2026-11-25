"""Transaction Token Service (draft-ietf-oauth-transaction-tokens).

A Txn-Token is a short-lived JWT minted once, at the edge of the trust domain (the Agent Gateway),
for each request that comes in from outside. It then travels unchanged in the `Txn-Token` header
through every internal hop (gateway > registry > gateway > agent), so every hop can read from one
signed source:

  sub                   the user
  tctx.origin_client    the runtime the user started from (delegation policy needs it)
  scope                 what the request is for: the MCP tool or method that started it
  txn                   one id for the whole call chain, written to every hop's spans

Access tokens still come from the IdP, one per hop and bound to that hop's audience (RFC 8693).
Keycloak's exchange drops the origin runtime after the first hop, and its delegation (`act`) works
for one hop only, so the call context rides in the Txn-Token instead.

Routes
  GET  /jwks     signing keys
  POST /token    RFC 8693 request with requested_token_type=urn:ietf:params:oauth:token-type:txn_token.
                 Only edge workloads may ask, and only with a token from outside the trust domain.
                 With subject_token_type=txn_token it issues a replacement (draft §7.4): same txn, user and
                 origin, a new purpose, and `tctx.agents` extended by the agent that is delegating.

When an agent asks another agent for help, it calls the gateway with its own token for the gateway and the
Txn-Token it received. The gateway replaces that token, adding the calling agent to `tctx.agents`. The
policy reads that list to refuse cycles (an agent already in the chain) and chains that are too deep.
"""
from __future__ import annotations

import base64
import dataclasses
import hmac
import json
import time
import uuid
from typing import Any

from poc.common import jwt
from poc.common.a2a import is_continuation, is_new_task
from poc.common.identity import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE, JwksCache, Principal, Verifier
from poc.common.jwt import TokenError
from poc.common.web import Request, Response, http
from poc.settings import Settings

TXN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:txn_token"
JWT_TYP = "txntoken+jwt"
TRUST_DOMAIN = "poc.internal"
HEADER = "txn-token"  # request header names are lower-cased by poc.common.web
TTL = 300
EDGE_WORKLOADS = ("agent-gateway",)  # may ask for Txn-Tokens
INTERNAL_WORKLOADS = ("agent-gateway", "agent-registry")  # their calls must carry one (as do agents')
EDGE_A2A = "a2a"  # purpose of an A2A call that came straight from outside (no MCP tool behind it)

# Which A2A calls a transaction may make, by the purpose it was minted for. The registry acts on
# behalf of one MCP request; it cannot start a task while serving a search, for example.
_PURPOSE_A2A = {
    "invoke_agent": lambda rpc: is_new_task(rpc),
    "provide_input": lambda rpc: is_continuation(rpc),
    "cancel_task": lambda rpc: rpc.get("method") == "CancelTask",
    "resources/read": lambda rpc: rpc.get("method") == "GetTask",
    EDGE_A2A: lambda rpc: True,
}


def is_internal(actor: str) -> bool:
    """A workload inside the trust domain: the registry, the gateway, or an agent (client agent:<id>)."""
    return actor in INTERNAL_WORKLOADS or actor.startswith("agent:")


def purpose_allows(purpose: str, rpc: Any) -> bool:
    check = _PURPOSE_A2A.get(purpose)
    return bool(check and isinstance(rpc, dict) and check(rpc))


def mcp_purpose(method: str, params: Any) -> str:
    if method == "tools/call" and isinstance(params, dict):
        return str(params.get("name", ""))
    return method


class TxnTokenService:
    def __init__(self, settings: Settings, verify: Verifier):
        self.settings = settings
        self.verify = verify
        self.key = self._load_key()

    def _load_key(self) -> jwt.RsaKey:
        path = self.settings.var_dir / "txn_signing_key.json"
        if path.exists():
            return jwt.RsaKey.from_dict(json.loads(path.read_text(encoding="utf-8")))
        key = jwt.RsaKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(key.to_dict()), encoding="utf-8")
        return key

    def __call__(self, req: Request) -> Response:
        if req.method == "GET" and req.path == "/jwks":
            return Response(200, {"keys": [self.key.public_jwk()]})
        if req.method == "POST" and req.path == "/token":
            return self._token(req)
        if req.method == "GET" and req.path == "/healthz":
            return Response(200, {"status": "ok"})
        return Response(404, {"error": "not found"})

    def _token(self, req: Request) -> Response:
        form = req.form()
        basic = req.headers.get("authorization", "")
        if basic[:6].lower() == "basic ":
            try:
                client_id, _, secret = base64.b64decode(basic[6:], validate=True).decode("utf-8").partition(":")
            except ValueError:  # binascii.Error and UnicodeDecodeError are ValueErrors
                return _oauth_error(401, "invalid_client", "malformed client credentials")
            form.setdefault("client_id", client_id)
            form.setdefault("client_secret", secret)
        client_id = form.get("client_id", "")
        if client_id not in EDGE_WORKLOADS or not hmac.compare_digest(
                form.get("client_secret", "").encode("utf-8"), self.settings.client_secret(client_id).encode("utf-8")):
            return _oauth_error(401, "invalid_client", "only edge workloads may request transaction tokens")
        if form.get("grant_type") != TOKEN_EXCHANGE or form.get("requested_token_type") != TXN_TOKEN_TYPE \
                or form.get("audience") != TRUST_DOMAIN \
                or form.get("subject_token_type") not in (ACCESS_TOKEN_TYPE, TXN_TOKEN_TYPE):
            return _oauth_error(400, "invalid_request", "expected a token exchange for a txn_token "
                                                        f"with audience {TRUST_DOMAIN}")
        if form["subject_token_type"] == TXN_TOKEN_TYPE:
            return self._replace(form, client_id)
        try:
            p = Principal.from_claims(self.verify(form.get("subject_token", ""), "agent-gateway"))
        except TokenError as e:
            return _oauth_error(400, "invalid_grant", f"subject token: {e}")
        if is_internal(p.immediate_actor):
            # A token minted for an internal hop already belongs to a transaction; minting a new one
            # would let that hop pick its own context.
            return _oauth_error(400, "invalid_grant", "subject token comes from inside the trust domain")
        try:
            rctx = json.loads(jwt.unb64url(form["request_context"])) if form.get("request_context") else {}
        except ValueError:
            return _oauth_error(400, "invalid_request", "request_context must be base64url JSON")
        now = int(time.time())
        claims = {
            "iss": self.settings.txn_url, "aud": TRUST_DOMAIN, "iat": now, "exp": now + TTL,
            "txn": str(uuid.uuid4()), "sub": p.sub, "scope": form.get("scope", ""), "req_wl": client_id,
            "tctx": {"origin_client": p.origin_client, "user": p.username},
            "rctx": {k: v for k, v in rctx.items() if isinstance(v, str)} if isinstance(rctx, dict) else {},
        }
        return self._issue(claims)

    def _issue(self, claims: dict[str, Any]) -> Response:
        return Response(200, {"access_token": jwt.encode(claims, self.key, typ=JWT_TYP),
                              "issued_token_type": TXN_TOKEN_TYPE, "token_type": "N_A",
                              "expires_in": max(0, claims["exp"] - int(time.time()))})

    def _replace(self, form: dict[str, str], client_id: str) -> Response:
        """A replacement keeps txn, sub and origin; it may only add the delegating agent and a purpose."""
        try:
            old = jwt.decode(form.get("subject_token", ""),
                             lambda kid: self.key.public_jwk() if kid == self.key.kid else None,
                             audience=TRUST_DOMAIN, issuer=self.settings.txn_url, typ=JWT_TYP)
            details = json.loads(jwt.unb64url(form.get("request_details", "")))
        except (TokenError, ValueError) as e:
            return _oauth_error(400, "invalid_grant", f"subject txn token: {e}")
        agent = details.get("delegating_agent") if isinstance(details, dict) else None
        if not isinstance(agent, str) or not agent:
            return _oauth_error(400, "invalid_request", "request_details.delegating_agent is required")
        now = int(time.time())
        tctx = dict(old["tctx"], agents=[*old["tctx"].get("agents", []), agent])
        claims = dict(old, iat=now, exp=min(old["exp"], now + TTL), scope=form.get("scope", ""), req_wl=client_id,
                      tctx=tctx)  # never outlives the token it replaces
        return self._issue(claims)


def _oauth_error(status: int, code: str, description: str) -> Response:
    return Response(status, {"error": code, "error_description": description})


class TxnVerifier:
    def __init__(self, settings: Settings):
        self.issuer = settings.txn_url
        self.keys = JwksCache(f"{settings.txn_url}/jwks")

    def verify(self, token: str) -> dict[str, Any]:
        claims = jwt.decode(token, self.keys.find, audience=TRUST_DOMAIN, issuer=self.issuer, typ=JWT_TYP)
        if not isinstance(claims.get("tctx"), dict) or not claims.get("txn"):
            raise TokenError("transaction token without context")
        return claims

    def bind(self, principal: Principal, token: str) -> Principal:
        """The caller's principal with the call context taken from the Txn-Token."""
        claims = self.verify(token)
        if claims.get("sub") != principal.sub:
            raise TokenError("transaction token belongs to another user")
        return dataclasses.replace(principal, origin_claim=str(claims["tctx"].get("origin_client", "")),
                                   txn=claims["txn"], purpose=str(claims.get("scope", "")),
                                   agent_chain=tuple(str(a) for a in claims["tctx"].get("agents", [])))


class TxnGate:
    """What a gateway does with transaction tokens; shared by poc/gateway.py and poc/pdp.py.

    - A caller from inside the trust domain (a token minted for the registry) must bring the Txn-Token
      of the request it is working on.
    - An agent calling another agent brings the Txn-Token it received; the gateway replaces it so that
      the token says this agent is now delegating.
    - A caller from outside gets a new one; anything it sent in the header is ignored.
    """

    def __init__(self, settings: Settings, client_id: str = "agent-gateway"):
        self.settings = settings
        self.client_id = client_id
        self.client_secret = settings.client_secret(client_id)
        self.verifier = TxnVerifier(settings)

    def mint(self, subject_token: str, purpose: str) -> str:
        status, body, _ = http("POST", f"{self.settings.txn_url}/token", form={
            "grant_type": TOKEN_EXCHANGE, "client_id": self.client_id, "client_secret": self.client_secret,
            "requested_token_type": TXN_TOKEN_TYPE, "audience": TRUST_DOMAIN, "scope": purpose,
            "subject_token": subject_token, "subject_token_type": ACCESS_TOKEN_TYPE,
        })
        if status != 200 or not isinstance(body, dict):
            raise TokenError(f"transaction token refused: {body}")
        return body["access_token"]

    def replace(self, txn_token: str, delegating_agent: str, purpose: str) -> str:
        details = jwt.b64url(json.dumps({"delegating_agent": delegating_agent}).encode())
        status, body, _ = http("POST", f"{self.settings.txn_url}/token", form={
            "grant_type": TOKEN_EXCHANGE, "client_id": self.client_id, "client_secret": self.client_secret,
            "requested_token_type": TXN_TOKEN_TYPE, "audience": TRUST_DOMAIN, "scope": purpose,
            "subject_token": txn_token, "subject_token_type": TXN_TOKEN_TYPE, "request_details": details,
        })
        if status != 200 or not isinstance(body, dict):
            raise TokenError(f"replacement transaction token refused: {body}")
        return body["access_token"]

    def establish(self, p: Principal, bearer: str, incoming: str, edge_purpose: str) -> tuple[Principal, str]:
        actor = p.immediate_actor
        if is_internal(actor):
            if not incoming:
                raise TokenError("calls from inside the trust domain need a Txn-Token")
            self.verifier.bind(p, incoming)  # same user before anything is replaced
            token = self.replace(incoming, actor.removeprefix("agent:"), edge_purpose) \
                if actor.startswith("agent:") else incoming
        else:
            token = self.mint(bearer, edge_purpose)
        return self.verifier.bind(p, token), token
