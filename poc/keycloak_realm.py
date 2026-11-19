"""Generate a Keycloak realm import (keycloak/realm-poc.json) from config/users.json and policy.json.

Keycloak's standard token exchange (GA since 26.2) does not add an `act` claim, and the exchanged
token's `azp` becomes the service that asked for it. To keep "which runtime started this" across
hops, each runtime gets an `origin-<runtime>` client scope with a hardcoded `origin_client` claim.
Services that exchange tokens request `scope=origin-<runtime>` so the claim survives every hop.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from poc.settings import ROOT, Settings

DEV_PASSWORD = "dev-password"
TOKEN_LIFESPAN = 8 * 3600


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


def _service_client(client_id: str, secret: str, audiences: list[str], origin_scopes: list[str]) -> dict[str, Any]:
    return {
        "clientId": client_id, "enabled": True, "publicClient": False, "secret": secret,
        "standardFlowEnabled": False, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
        "attributes": {"standard.token.exchange.enabled": "true"},
        "fullScopeAllowed": True,
        "defaultClientScopes": ["poc-claims"], "optionalClientScopes": origin_scopes,
        "protocolMappers": [_audience(a) for a in audiences],
    }


def build(settings: Settings) -> dict[str, Any]:
    directory = settings.load("users.json")
    policy = settings.load("policy.json")
    runtimes = sorted(policy["runtimes"])
    origin_scopes = [f"origin-{r}" for r in runtimes]
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
                      "attributes": {"include.in.token.scope": "false"}, "protocolMappers": CLAIM_MAPPERS}]
    for runtime in runtimes:
        client_scopes.append({
            "name": f"origin-{runtime}", "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false"},
            "protocolMappers": [_mapper("origin", "oidc-hardcoded-claim-mapper", **{
                "claim.name": "origin_client", "claim.value": runtime, "jsonType.label": "String"})],
        })

    clients = []
    for runtime in runtimes:  # what a user signs in with (password grant stands in for SSO)
        clients.append({
            "clientId": runtime, "enabled": True, "publicClient": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": True,
            "fullScopeAllowed": True,
            "defaultClientScopes": ["poc-claims", f"origin-{runtime}"], "optionalClientScopes": [],
            "protocolMappers": [_audience("agent-gateway")],
        })
    secrets = {c: v["secret"] for c, v in directory["clients"].items() if v.get("type") == "service"}
    clients.append(_service_client("agent-gateway", secrets["agent-gateway"], ["agent-registry", *agent_clients],
                                   origin_scopes))
    clients.append(_service_client("agent-registry", secrets["agent-registry"], ["agent-gateway"], origin_scopes))
    for client_id in agent_clients:  # audiences only; they never request tokens
        clients.append({"clientId": client_id, "enabled": True, "publicClient": False,
                        "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                        "defaultClientScopes": [], "optionalClientScopes": []})

    return {
        "realm": "poc", "enabled": True,
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
