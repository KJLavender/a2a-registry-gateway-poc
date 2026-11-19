"""Agent Gateway: one policy enforcement point for MCP and A2A traffic.

Routes
  POST /mcp                                        MCP gateway (aggregates built-in + registry tools)
  GET  /agents/{agent_id}/.well-known/agent-card.json   per-agent card, rewritten to the gateway URL
  POST /agents/{agent_id}/a2a                      A2A JSON-RPC proxy with authoritative authorization
  POST /internal/access-check                      access indications for the registry (not authoritative)

Policies enforced here
  1. tools/list   : capability distribution by runtime (workload) identity (tools come from the registry)
  2. tools/call   : tool authorization by user claims
  3. A2A invoke   : delegation policy (caller agent -> target) + user authorization, re-checked on every call
  4. task access  : GetTask / CancelTask / resources/read only for the task owner
"""
from __future__ import annotations

import re
import secrets
import threading
from typing import Any

from poc.common import trace
from poc.common.a2a import POLICY_DENIED, TASK_NOT_FOUND
from poc.common.identity import Principal, TokenExchanger, Verifier
from poc.common.jwt import TokenError
from poc.common.mcp import RESOURCE_NOT_FOUND, McpContext, McpServer, serve_mcp, tool_result
from poc.common.web import Request, Response, RpcError, http, rpc_call, rpc_response
from poc.policy import APPROVAL, Decision, PolicyStore
from poc.registry import parse_task_uri
from poc.settings import Settings

COMPONENT = "agent-gateway"
_AGENT_ROUTE = re.compile(r"^/agents/([a-z0-9-]+)/(a2a|\.well-known/agent-card\.json)$")

class GatewayMcp(McpServer):
    name = "agent-gateway"
    instructions = ("Company Agent Gateway. If search_agents is available, use it to find expert agents, "
                    "invoke_agent to delegate, and read the returned resource_uri to wait for results.")

    def __init__(self, gateway: "AgentGateway"):
        self.gw = gateway

    def _allowed(self, ctx: McpContext) -> set[str]:
        return self.gw.policy.distributed_tools(ctx.principal.origin_client)

    def _delegation_enabled(self, ctx: McpContext) -> bool:
        return "invoke_agent" in self._allowed(ctx)

    def list_tools(self, ctx: McpContext) -> list[dict[str, Any]]:
        allowed = self._allowed(ctx)
        with trace.span("gateway tools/list", COMPONENT, ctx.traceparent,
                        runtime=ctx.principal.origin_client) as sp:
            tools = [t for t in self.gw.registry_tools(ctx) if t["name"] in allowed] if allowed else []
            sp.set(distributed=",".join(t["name"] for t in tools))
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any], ctx: McpContext) -> dict[str, Any]:
        if name not in self._allowed(ctx):
            raise RpcError(-32602, f"Unknown tool: {name}")  # not distributed to this runtime
        p = ctx.principal
        with trace.span(f"gateway tools/call {name}", COMPONENT, ctx.traceparent,
                        user=p.username, runtime=p.origin_client) as sp:
            decision = self.gw.policy.tool_call(p, name)
            sp.set(policy_effect=decision.effect, policy_rule=decision.rule, decision_id=decision.decision_id)
            if not decision.allowed:
                return tool_result({"error": "denied by gateway policy", **decision.to_dict()}, is_error=True)
            return self.gw.forward_mcp("tools/call", {"name": name, "arguments": arguments}, ctx, sp)

    def list_resource_templates(self, ctx: McpContext) -> list[dict[str, Any]]:
        if not self._delegation_enabled(ctx):
            return []
        with trace.span("gateway resources/templates/list", COMPONENT, ctx.traceparent) as sp:
            return self.gw.forward_mcp("resources/templates/list", {}, ctx, sp)["resourceTemplates"]

    def list_resources(self, ctx: McpContext) -> list[dict[str, Any]]:
        if not self._delegation_enabled(ctx):
            return []
        with trace.span("gateway resources/list", COMPONENT, ctx.traceparent) as sp:
            return self.gw.forward_mcp("resources/list", {}, ctx, sp)["resources"]

    def read_resource(self, uri: str, ctx: McpContext) -> dict[str, Any]:
        if not self._delegation_enabled(ctx):
            raise RpcError(RESOURCE_NOT_FOUND, "Resource not found", {"uri": uri})
        agent_id, task_id, _ = parse_task_uri(uri)
        with trace.span("gateway resources/read", COMPONENT, ctx.traceparent,
                        user=ctx.principal.username, task_id=task_id) as sp:
            if not self.gw.owns(ctx.principal, agent_id, task_id):
                sp.set(policy_effect="deny", reason="not task owner")
                raise RpcError(RESOURCE_NOT_FOUND, "Resource not found", {"uri": uri})
            return self.gw.forward_mcp("resources/read", {"uri": uri}, ctx, sp)


class AgentGateway:
    def __init__(self, settings: Settings, policy: PolicyStore, verify: Verifier, exchanger: TokenExchanger):
        self.settings = settings
        self.policy = policy
        self.verify = verify
        self.exchanger = exchanger
        self.mcp = GatewayMcp(self)
        self._task_owner: dict[str, tuple[str, str]] = {}  # task_id -> (agent_id, user)
        self._lock = threading.Lock()
        self._registry_tools: list[dict[str, Any]] | None = None
        self.approvals: list[dict[str, Any]] = []

    # --- HTTP -------------------------------------------------------------------

    def __call__(self, req: Request) -> Response:
        if req.path == "/mcp":
            return serve_mcp(self.mcp, req, self._authenticate)
        m = _AGENT_ROUTE.match(req.path)
        if m and m.group(1) in self.settings.agent_ports:
            if m.group(2) == "a2a" and req.method == "POST":
                return self._a2a(req, m.group(1))
            if req.method == "GET":
                return self._card(req, m.group(1))
        if req.method == "POST" and req.path == "/internal/access-check":
            return self._access_check(req)
        if req.method == "GET" and req.path == "/healthz":
            return Response(200, {"status": "ok"})
        return Response(404, {"error": "not found"})

    def _authenticate(self, req: Request) -> Principal | Response:
        try:
            return Principal.from_claims(self.verify(req.bearer or "", "agent-gateway"))
        except TokenError as e:
            return Response(401, {"error": f"unauthorized: {e}"}, {"WWW-Authenticate": "Bearer"})

    # --- MCP upstream (registry) ---------------------------------------------------

    def forward_mcp(self, method: str, params: dict[str, Any], ctx: McpContext, sp: trace.Span) -> Any:
        token = self.exchanger.exchange(ctx.token, "agent-registry", ctx.principal.origin_scope)
        params = dict(params, _meta={"traceparent": sp.traceparent})  # MCP SEP-414
        return rpc_call(f"{self.settings.registry_url}/mcp", method, params,
                        headers={"Authorization": f"Bearer {token}", "traceparent": sp.traceparent},
                        timeout=self.settings.resource_wait_seconds + 15)

    def registry_tools(self, ctx: McpContext) -> list[dict[str, Any]]:
        if self._registry_tools is None:
            with trace.span("gateway registry tools/list", COMPONENT, ctx.traceparent) as sp:
                self._registry_tools = self.forward_mcp("tools/list", {}, ctx, sp)["tools"]
        return self._registry_tools

    # --- task ownership ---------------------------------------------------------------

    def owns(self, p: Principal, agent_id: str, task_id: str) -> bool:
        with self._lock:
            return self._task_owner.get(task_id) == (agent_id, p.sub)

    # --- A2A ---------------------------------------------------------------------

    def _card(self, req: Request, agent_id: str) -> Response:
        p = self._authenticate(req)
        if isinstance(p, Response):
            return p
        if not self.policy.visible(p, agent_id):
            return Response(404, {"error": "not found"})
        status, card, _ = http("GET", f"{self.settings.agent_url(agent_id)}/.well-known/agent-card.json", timeout=5)
        if status != 200:
            return Response(502, {"error": "agent card unavailable"})
        for interface in card.get("supportedInterfaces", []):
            interface["url"] = f"{self.settings.gateway_url}/agents/{agent_id}/a2a"
        return Response(200, card)

    def _deny(self, rid: Any, decision: Decision, status: int = 403, **extra: Any) -> Response:
        return Response(status, rpc_response(rid, error=RpcError(
            POLICY_DENIED, f"Request refused by Agent Gateway policy: {decision.reason}",
            {**decision.to_dict(), **extra})))

    def _a2a(self, req: Request, agent_id: str) -> Response:
        try:
            msg = req.json()
        except ValueError:
            return Response(400, rpc_response(None, error=RpcError(-32700, "parse error")))
        rid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
        p = self._authenticate(req)
        if isinstance(p, Response):
            return p
        with trace.span(f"gateway a2a {method}", COMPONENT, req.headers.get("traceparent"), agent_id=agent_id,
                        user=p.username, delegation_path=" > ".join(p.actors)) as sp:
            new_task = method == "SendMessage" and not (params.get("message") or {}).get("taskId")
            if new_task:
                if not self.policy.visible(p, agent_id):
                    sp.set(policy_effect="deny", reason="agent hidden from user")
                    return Response(404, rpc_response(rid, error=RpcError(-32601, "agent not found")))
                decision = self.policy.invocation(p, agent_id)  # authoritative, every time
                sp.set(policy_effect=decision.effect, policy_rule=decision.rule, decision_id=decision.decision_id)
                if decision.effect == APPROVAL:
                    approval_id = self._open_approval(p, agent_id, decision)
                    sp.set(approval_request_id=approval_id)
                    return self._deny(rid, decision, approval_request_id=approval_id)
                if not decision.allowed:
                    return self._deny(rid, decision)
            elif method in ("SendMessage", "GetTask", "CancelTask"):
                task_id = params.get("id") if method != "SendMessage" else params["message"]["taskId"]
                if not self.owns(p, agent_id, task_id):
                    sp.set(policy_effect="deny", reason="not task owner")
                    return Response(200, rpc_response(rid, error=RpcError(TASK_NOT_FOUND, "task not found")))
            agent_token = self.exchanger.exchange(req.bearer or "", f"agent:{agent_id}", p.origin_scope)
            headers = {"Authorization": f"Bearer {agent_token}", "traceparent": sp.traceparent}
            if req.headers.get("a2a-version"):
                headers["A2A-Version"] = req.headers["a2a-version"]
            status, body, _ = http("POST", f"{self.settings.agent_url(agent_id)}/a2a", json_body=msg,
                                   headers=headers, timeout=90)
            task = (body or {}).get("result", {}) if isinstance(body, dict) else {}
            task = task.get("task", task)
            if new_task and isinstance(task, dict) and task.get("id"):
                with self._lock:
                    self._task_owner[task["id"]] = (agent_id, p.sub)
            if isinstance(task, dict) and task.get("status"):
                sp.set(task_id=task.get("id"), state=task["status"]["state"])
            return Response(status, body)

    def _open_approval(self, p: Principal, agent_id: str, decision: Decision) -> str:
        approval_id = f"APR-{secrets.token_hex(3).upper()}"
        with self._lock:
            self.approvals.append({"approval_request_id": approval_id, "user": p.sub, "agent_id": agent_id,
                                   "decision_id": decision.decision_id, "status": "pending"})
        return approval_id

    def _access_check(self, req: Request) -> Response:
        """Indications for search results. Never a substitute for the check in `_a2a`."""
        p = self._authenticate(req)
        if isinstance(p, Response):
            return p
        if p.immediate_actor != "agent-registry":
            return Response(403, {"error": "only the agent registry may call this endpoint"})
        with trace.span("gateway access-check", COMPONENT, req.headers.get("traceparent"), user=p.username) as sp:
            out = {agent_id: self.policy.access_indication(p, agent_id)
                   for agent_id in req.json().get("agent_ids", [])}
            sp.set(checked=len(out))
        return Response(200, out)
