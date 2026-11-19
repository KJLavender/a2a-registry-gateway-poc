"""Generate an agentgateway config from config/policy.json, so both gateways share one policy file.

Mapping
  tools/list + tools/call  -> mcpAuthorization CEL rules (agentgateway filters tools/list by the same rules)
  A2A invocation           -> per-agent route `authorization` CEL rule (visibility + delegation + user rule)
  token exchange           -> backendAuth.oauthTokenExchange against the mock IdP (RFC 8693)
What CEL cannot express here: approval_required (no approval flow) and task ownership
(the gateway cannot see A2A task owners); those stay with the registry and the agents.
"""
from __future__ import annotations

import json
from typing import Any

from poc.settings import Settings


def _list(values: list[str]) -> str:
    return json.dumps(sorted(values))


def origin_client(depth: int = 4) -> str:
    """CEL: the client the user signed in with, found at the bottom of the RFC 8693 `act` chain."""
    def walk(path: str, remaining: int) -> str:
        if remaining == 0:
            return f"{path}.sub"
        return f"(has({path}.act) ? {walk(path + '.act', remaining - 1)} : {path}.sub)"
    return f"(has(jwt.act) ? {walk('jwt.act', depth)} : jwt.azp)"


def user_rule(rule: dict[str, Any]) -> str:
    """CEL for {"allow_groups": [...], "allow_roles": [...]} (approval_groups cannot be expressed)."""
    parts = []
    if rule.get("allow_groups"):
        parts.append(f"{_list(rule['allow_groups'])}.exists(g, g in jwt.groups)")
    if rule.get("allow_roles"):
        parts.append(f"{_list(rule['allow_roles'])}.exists(r, r in jwt.roles)")
    return "(" + " || ".join(parts) + ")" if parts else "false"


def mcp_rules(policy: dict[str, Any]) -> list[dict[str, str]]:
    origin = origin_client()
    runtimes_by_tool: dict[str, list[str]] = {}
    for runtime, cfg in policy["runtimes"].items():
        for tool in {t for s in cfg["tool_sets"] for t in policy["tool_sets"].get(s, [])}:
            runtimes_by_tool.setdefault(tool, []).append(runtime)
    rules = []
    for tool, runtimes in sorted(runtimes_by_tool.items()):
        rule = policy["tool_call"].get(tool, policy["tool_call"]["default"])
        rules.append({"allow": f'mcp.tool.name == "{tool}" && {origin} in {_list(runtimes)} && {user_rule(rule)}'})
    # Task resources: only for runtimes that can delegate (ownership is checked by the registry)
    delegating = runtimes_by_tool.get("invoke_agent", [])
    rules.append({"allow": f"has(mcp.resource) && {origin} in {_list(delegating)}"})
    return rules


def a2a_rule(policy: dict[str, Any], agent_id: str) -> str:
    agent = policy["agents"].get(agent_id)
    if agent is None:
        return "false"
    callers = [c for c, targets in policy["delegation"].items() if "*" in targets or agent_id in targets]
    runtimes = [r for r, cfg in policy["runtimes"].items() if cfg.get("agent_id") in callers]
    parts = [f"{origin_client()} in {_list(runtimes)}", user_rule(agent["invoke"])]
    if agent.get("visibility") == "hidden":
        parts.insert(0, f"{_list(agent.get('visible_to_groups', []))}.exists(g, g in jwt.groups)")
    return " && ".join(parts)


def build(settings: Settings) -> dict[str, Any]:
    policy = settings.load("policy.json")
    jwt_auth = {"mode": "strict", "issuer": settings.issuer, "audiences": ["agent-gateway"],
                "jwks": {"url": settings.jwks_uri}}

    def exchange(audience: str) -> dict[str, Any]:
        return {"backendAuth": {"oauthTokenExchange": {
            "host": f"{settings.host}:{settings.idp_port}",
            "path": settings.token_endpoint.removeprefix(settings.idp_url),
            "clientAuth": {"clientId": "agent-gateway", "clientSecret": settings.client_secret("agent-gateway"),
                           "method": "clientSecretBasic"},
            "audiences": [audience],
            # jwtAuth strips the inbound token, so name the validated one explicitly
            "subjectToken": {"source": {"expression": "jwt.rawToken.unredacted()"}},
        }}}

    routes: list[dict[str, Any]] = [
        {"name": "healthz", "matches": [{"path": {"exact": "/healthz"}}],
         "policies": {"directResponse": {"status": 200, "body": list(b'{"status": "ok"}')}}},
        {"name": "mcp", "matches": [{"path": {"exact": "/mcp"}}],
         "policies": {"jwtAuth": jwt_auth, "mcpAuthorization": {"rules": mcp_rules(policy)}},
         "backends": [{"mcp": {"statefulMode": "stateless", "prefixMode": "never",
                               "targets": [{"name": "registry", "mcp": {"host": f"{settings.registry_url}/mcp"}}]},
                       "policies": exchange("agent-registry")}]},
    ]
    for agent_id, port in settings.agent_ports.items():
        routes.append({
            "name": f"a2a-{agent_id}",
            "matches": [{"path": {"pathPrefix": f"/agents/{agent_id}/"}}],
            "policies": {"jwtAuth": jwt_auth,
                         "authorization": {"rules": [{"allow": a2a_rule(policy, agent_id)}]},
                         "urlRewrite": {"path": {"prefix": "/"}},
                         "a2a": {}},
            "backends": [{"host": f"{settings.host}:{port}", "policies": exchange(f"agent:{agent_id}")}],
        })
    return {"binds": [{"port": settings.gateway_port, "listeners": [{"routes": routes}]}]}


def write(settings: Settings) -> str:
    path = settings.var_dir / "agentgateway.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    # JSON is valid YAML; agentgateway reads it as-is
    path.write_text(json.dumps(build(settings), indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)
