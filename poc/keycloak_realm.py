"""Generate a Keycloak realm import (keycloak/realm-poc.json) from config/users.json and policy.json.

Keycloak's standard token exchange (GA since 26.2) does not add an `act` claim, and the exchanged
token's `azp` becomes the service that asked for it, so after the first hop the access token no longer
shows which runtime started the request. That context travels in the Txn-Token instead (poc/txn.py);
Keycloak only issues the per-hop access tokens.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from poc.settings import ROOT, Settings

DEV_PASSWORD = "dev-password"
TOKEN_LIFESPAN = 8 * 3600
# Client a user signs in with when they consent to "agent-gateway may act for me" (delegation preview).
DELEGATING_CLIENT = "orchestrator-delegated"
DELEGATION_REDIRECT = "http://127.0.0.1:18999/callback"  # never served; the login helper reads the code from it


def _mapper(name: str, kind: str, **config: str) -> dict[str, Any]:
    return {"name": name, "protocol": "openid-connect", "protocolMapper": kind,
            "config": {"access.token.claim": "true", "id.token.claim": "false",
                       "introspection.token.claim": "true", **config}}


def _audience(client_id: str) -> dict[str, Any]:
    return _mapper(f"aud-{client_id}", "oidc-audience-mapper", **{"included.client.audience": client_id})


CLAIM_MAPPERS = [
    _mapper("sub", "oidc-sub-mapper"),
    _mapper("username", "oidc-usermodel-property-mapper", **{
        "user.attribute": "username", "claim.name": "preferred_username", "jsonType.label": "String"}),
    _mapper("name", "oidc-full-name-mapper"),
    _mapper("groups", "oidc-group-membership-mapper", **{"claim.name": "groups", "full.path": "false"}),
    _mapper("roles", "oidc-usermodel-realm-role-mapper", **{
        "claim.name": "roles", "multivalued": "true", "jsonType.label": "String"}),
]


# Same as the scope Keycloak creates when token-exchange-delegation is on. Listed here because a realm
# import with its own clientScopes does not get the built-in ones.
DELEGATION_CLIENT_SCOPE = {
    "name": "delegation:client", "protocol": "openid-connect",
    "description": "OpenID Connect scope for agent/client token exchange delegation",
    "attributes": {"include.in.token.scope": "true", "parameterized.scope.type": "client-delegation",
                   "display.on.consent.screen": "true", "always.display.consent": "true",
                   "is.parameterized.scope": "true", "consent.screen.text": "${clientDelegationScopeConsentText}"},
    "protocolMappers": [
        _mapper("client may_act client_id", "oidc-parameterized-scope-mapper",
                **{"claim.name": "may_act.client_id", "jsonType.label": "String"}),
        {"name": "client delegation audience", "protocol": "openid-connect",
         "protocolMapper": "oidc-parameterized-scope-audience-mapper",
         "config": {"access.token.claim": "true", "introspection.token.claim": "true"}},
        _mapper("client may_act sub", "oidc-parameterized-scope-client-sub-mapper",
                **{"claim.name": "may_act.sub", "jsonType.label": "String"}),
    ],
}


def _service_client(client_id: str, secret: str, audiences: list[str],
                    service_account: bool = False) -> dict[str, Any]:
    return {
        "clientId": client_id, "enabled": True, "publicClient": False, "secret": secret,
        "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": service_account,
        "attributes": {"standard.token.exchange.enabled": "true"},
        "fullScopeAllowed": True,
        "defaultClientScopes": ["poc-claims"], "optionalClientScopes": [],
        "protocolMappers": [_audience(a) for a in audiences],
    }


def build(settings: Settings) -> dict[str, Any]:
    directory = settings.load("users.json")
    policy = settings.load("policy.json")
    runtimes = sorted(policy["runtimes"])
    groups = sorted({g for u in directory["users"].values() for g in u["groups"]})
    roles = sorted({r for u in directory["users"].values() for r in u["roles"]})
    agent_clients = [f"agent:{a}" for a in settings.agent_ports]

    users = []
    for username, user in directory["users"].items():
        first, _, last = user["name"].partition(" ")
        users.append({
            "username": username, "enabled": True, "firstName": first, "lastName": last or first,
            "email": f"{username}@example.com", "emailVerified": True,
            "credentials": [{"type": "password", "value": DEV_PASSWORD, "temporary": False}],
            "groups": [f"/{g}" for g in user["groups"]], "realmRoles": user["roles"],
        })

    client_scopes = [{"name": "poc-claims", "protocol": "openid-connect",
                      "attributes": {"include.in.token.scope": "false"}, "protocolMappers": CLAIM_MAPPERS},
                     DELEGATION_CLIENT_SCOPE]

    clients = []
    for runtime in runtimes:  # what a user signs in with (password grant stands in for SSO)
        clients.append({
            "clientId": runtime, "enabled": True, "publicClient": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": True,
            "fullScopeAllowed": True,
            "defaultClientScopes": ["poc-claims"], "optionalClientScopes": [],
            "protocolMappers": [_audience("agent-gateway")],
        })
    secrets = {c: v["secret"] for c, v in directory["clients"].items() if v.get("type") == "service"}
    # agent-gateway gets a service account: it is the actor in delegated exchanges
    clients.append(_service_client("agent-gateway", secrets["agent-gateway"], ["agent-registry", *agent_clients],
                                   service_account=True))
    clients.append({  # delegation needs a consent screen, so this one uses the browser login flow
        "clientId": DELEGATING_CLIENT, "enabled": True, "publicClient": True, "consentRequired": True,
        "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "redirectUris": [DELEGATION_REDIRECT], "fullScopeAllowed": True,
        "defaultClientScopes": ["poc-claims"],
        "optionalClientScopes": ["delegation:client"],
        "protocolMappers": [_audience("agent-gateway")],
    })
    clients.append(_service_client("agent-registry", secrets["agent-registry"], ["agent-gateway"],
                                   service_account=True))  # only used to show a wrong actor is refused
    for client_id in agent_clients:  # an agent swaps the token it got for one to the gateway (asking agents)
        clients.append(_service_client(client_id, directory["clients"]["agent:*"]["secret"], ["agent-gateway"]))

    return {
        "realm": "poc", "enabled": True,
        "adminPermissionsEnabled": True,  # FGAP v2, where delegation permissions live
        "accessTokenLifespan": TOKEN_LIFESPAN, "ssoSessionIdleTimeout": TOKEN_LIFESPAN,
        "ssoSessionMaxLifespan": TOKEN_LIFESPAN + 3600,
        "groups": [{"name": g} for g in groups],
        "roles": {"realm": [{"name": r} for r in roles]},
        "clientScopes": client_scopes,
        "defaultDefaultClientScopes": [], "defaultOptionalClientScopes": [],
        "users": users, "clients": clients,
    }


def write(settings: Settings, path: Path = ROOT / "keycloak" / "realm-poc.json") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build(settings), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


if __name__ == "__main__":
    print(write(Settings()))
