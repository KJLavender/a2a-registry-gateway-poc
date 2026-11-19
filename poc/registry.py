"""Agent Registry: governed catalog + search, exposed as an MCP server.

- `search_agents`  : task intent -> candidates, each with an access indication from the gateway
- `invoke_agent`   : creates an A2A Task through the gateway and returns at once (taskId + resource URI)
- `provide_input`  : continues an INPUT_REQUIRED task
- `cancel_task`    : explicit A2A CancelTask (a resource read timeout never cancels)
- resource `a2a-task://{agent_id}/{task_id}` : blocking read that projects the A2A Task state

The registry never calls agents directly: every A2A call goes back through the Agent Gateway,
which makes the authoritative policy decision.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import sqlite3
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

from poc.common import trace
from poc.common.a2a import (
    A2A_VERSION, AUTH_REQUIRED, CANCELED, COMPLETED, FAILED, IN_PROGRESS, INPUT_REQUIRED, POLICY_DENIED,
    REJECTED, ROLE_USER, TERMINAL, message_text, text_message,
)
from poc.common.identity import Principal, TokenExchanger, Verifier
from poc.common.jwt import TokenError
from poc.common.mcp import RESOURCE_NOT_FOUND, McpContext, McpServer, serve_mcp, tool_result
from poc.common.web import Request, Response, RpcError, http, rpc_call
from poc.policy import PolicyStore
from poc.search import AgentIndex
from poc.settings import Settings

log = logging.getLogger("poc.registry")
COMPONENT = "agent-registry"
URI_SCHEME = "a2a-task://"
REQUIRED_CARD_FIELDS = ("name", "description", "version", "supportedInterfaces", "capabilities",
                        "defaultInputModes", "defaultOutputModes", "skills")
REQUIRED_SKILL_FIELDS = ("id", "name", "description", "tags")

NEXT_ACTION = {
    "TASK_STATE_SUBMITTED": "Task is still running. Read this resource again to keep waiting.",
    "TASK_STATE_WORKING": "Task is still running. Read this resource again to keep waiting.",
    INPUT_REQUIRED: "The agent needs more information. Answer with provide_input(task_id, message); "
                    "ask the user only if you cannot supply it yourself.",
    AUTH_REQUIRED: "The agent needs extra authorization that this runtime cannot grant. Tell the user.",
    COMPLETED: "Done. Use the artifacts and status message as the result.",
    FAILED: "Task failed. Do not retry automatically if the request has side effects.",
    CANCELED: "Task was canceled.",
    REJECTED: "The agent rejected the task.",
}

TOOLS = [
    {
        "name": "whoami",
        "title": "Who am I",
        "description": "Show the signed-in user, runtime and delegation path as the gateway passed them on.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "search_agents",
        "title": "Search expert agents",
        "description": "Find expert agents in the company catalog that fit a task. Each result has an `access` "
                       "status: allowed, denied (the capability exists but this user may not use it), "
                       "approval_required, or unknown. An empty list means no matching agent exists.",
        "inputSchema": {"type": "object", "properties": {
            "query": {"type": "string", "description": "What the user needs, in natural language."},
            "top_k": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5}},
            "required": ["query"]},
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "invoke_agent",
        "title": "Delegate a task to an agent",
        "description": "Create an A2A task on an agent returned by search_agents. Returns immediately with "
                       "task_id and resource_uri; read resource_uri (resources/read) to wait for progress and results.",
        "inputSchema": {"type": "object", "properties": {
            "agent_id": {"type": "string"},
            "message": {"type": "string", "description": "Self-contained task description for the agent."},
            "context_id": {"type": "string", "description": "Optional A2A contextId to group related tasks."}},
            "required": ["agent_id", "message"]},
        "annotations": {"readOnlyHint": False, "openWorldHint": False},
    },
    {
        "name": "provide_input",
        "title": "Answer an agent's question",
        "description": "Continue a task in TASK_STATE_INPUT_REQUIRED with the requested information.",
        "inputSchema": {"type": "object", "properties": {
            "task_id": {"type": "string"}, "message": {"type": "string"}},
            "required": ["task_id", "message"]},
    },
    {
        "name": "cancel_task",
        "title": "Cancel a delegated task",
        "description": "Ask the agent to cancel a running task.",
        "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}, "required": ["task_id"]},
        "annotations": {"destructiveHint": True},
    },
]


def validate_card(card: Any) -> list[str]:
    if not isinstance(card, dict):
        return ["card is not a JSON object"]
    problems = [f"missing {f}" for f in REQUIRED_CARD_FIELDS if not card.get(f)]
    for i, skill in enumerate(card.get("skills") or []):
        problems += [f"skills[{i}] missing {f}" for f in REQUIRED_SKILL_FIELDS if not skill.get(f)]
    return problems


class TaskStore:
    """Task correlation: which user created which A2A task on which agent (survives reconnects)."""

    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.execute("""CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY, agent_id TEXT, owner TEXT, context_id TEXT,
                trace_id TEXT, created_at REAL, last_state TEXT)""")

    def add(self, task_id: str, agent_id: str, owner: str, context_id: str, trace_id: str, state: str) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO tasks VALUES (?,?,?,?,?,?,?)",
                             (task_id, agent_id, owner, context_id, trace_id, time.time(), state))

    def get(self, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute("SELECT task_id, agent_id, owner, context_id, last_state FROM tasks "
                                   "WHERE task_id = ?", (task_id,)).fetchone()
        return dict(zip(("task_id", "agent_id", "owner", "context_id", "last_state"), row)) if row else None

    def update_state(self, task_id: str, state: str) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE tasks SET last_state = ? WHERE task_id = ?", (state, task_id))

    def for_owner(self, owner: str, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT task_id, agent_id, last_state FROM tasks WHERE owner = ? "
                                    "ORDER BY created_at DESC LIMIT ?", (owner, limit)).fetchall()
        return [dict(zip(("task_id", "agent_id", "last_state"), r)) for r in rows]


class Catalog:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.entries = {e["agent_id"]: e for e in settings.load("agents.json")["agents"]}
        self.cards: dict[str, dict[str, Any]] = {}
        self.rejected: dict[str, list[str]] = {}
        self.index = AgentIndex()

    def sync(self) -> None:
        """Pull cards only from governed entries; invalid cards are rejected, not indexed."""
        for agent_id in self.entries:
            url = f"{self.settings.agent_url(agent_id)}/.well-known/agent-card.json"
            status, card, _ = http("GET", url, timeout=5)
            problems = [f"HTTP {status}"] if status != 200 else validate_card(card)
            if problems:
                self.rejected[agent_id] = problems
                log.warning("agent card for %s rejected: %s", agent_id, problems)
                continue
            self.cards[agent_id] = card
            self.index.add(agent_id, card)

    def a2a_endpoint(self, agent_id: str) -> str:
        return f"{self.settings.gateway_url}/agents/{agent_id}/a2a"

    def card_url(self, agent_id: str) -> str:
        return f"{self.settings.gateway_url}/agents/{agent_id}/.well-known/agent-card.json"


def parse_task_uri(uri: str) -> tuple[str, str, float | None]:
    parts = urlsplit(uri)
    if not uri.startswith(URI_SCHEME) or not parts.netloc or not parts.path.strip("/"):
        raise RpcError(RESOURCE_NOT_FOUND, "Resource not found", {"uri": uri})
    wait = parse_qs(parts.query).get("wait")
    return parts.netloc, parts.path.strip("/"), float(wait[0]) if wait else None


def task_view(agent_id: str, task: dict[str, Any]) -> dict[str, Any]:
    """Project an A2A Task for an LLM without flattening states, questions or artifacts."""
    state = task["status"]["state"]
    artifacts = []
    for a in task.get("artifacts", []):
        item: dict[str, Any] = {"name": a.get("name"), "description": a.get("description")}
        texts = [p["text"] for p in a.get("parts", []) if "text" in p]
        data = [p["data"] for p in a.get("parts", []) if "data" in p]
        if texts:
            item["text"] = "\n".join(texts)
        if data:
            item["data"] = data[0] if len(data) == 1 else data
        artifacts.append(item)
    history = [{"role": "user" if m.get("role") == ROLE_USER else "agent", "text": message_text(m)}
               for m in task.get("history", [])[-6:]]
    return {
        "task_id": task["id"], "agent_id": agent_id, "context_id": task.get("contextId"),
        "state": state, "terminal": state in TERMINAL,
        "status_message": message_text(task["status"].get("message")),
        "artifacts": artifacts, "history_tail": history,
        "next_action": NEXT_ACTION.get(state, ""),
    }


class AgentRegistry(McpServer):
    name = "agent-registry"
    instructions = ("Use search_agents to find an expert agent, invoke_agent to delegate, then read the returned "
                    "resource_uri until the task is terminal or needs input.")

    def __init__(self, settings: Settings, verify: Verifier, exchanger: TokenExchanger):
        self.settings = settings
        self.verify = verify
        self.exchanger = exchanger
        self.catalog = Catalog(settings)
        # Used for whoami and, behind agentgateway, for search access indications.
        self.policy = PolicyStore(settings.config_dir / "policy.json")
        settings.var_dir.mkdir(parents=True, exist_ok=True)
        self.tasks = TaskStore(str(settings.var_dir / "registry.db"))

    # --- HTTP -------------------------------------------------------------------

    def __call__(self, req: Request) -> Response:
        if req.path == "/mcp":
            return serve_mcp(self, req, self._authenticate)
        if req.method == "GET" and req.path == "/healthz":
            return Response(200, {"status": "ok", "agents": sorted(self.catalog.cards),
                                  "rejected": self.catalog.rejected})
        return Response(404, {"error": "not found"})

    def _authenticate(self, req: Request) -> Principal | Response:
        try:
            claims = self.verify(req.bearer or "", "agent-registry")
            principal = Principal.from_claims(claims)
            # agentgateway + Keycloak: the token has no origin_client and no act chain, so the gateway
            # sends the runtime it validated as a header. Accept it only on tokens minted for the gateway.
            header = req.headers.get("x-origin-client", "")
            if header and claims.get("azp") == "agent-gateway" and not claims.get("origin_client") \
                    and "act" not in claims:
                principal = dataclasses.replace(principal, origin_claim=header)
            return principal
        except TokenError as e:
            return Response(401, {"error": f"unauthorized: {e}"}, {"WWW-Authenticate": "Bearer"})

    # --- calls back into the gateway ------------------------------------------------

    def _gateway_headers(self, ctx: McpContext, sp: trace.Span) -> dict[str, str]:
        token = self.exchanger.exchange(ctx.token, "agent-gateway", ctx.principal.origin_scope)
        return {"Authorization": f"Bearer {token}", "A2A-Version": A2A_VERSION, "traceparent": sp.traceparent}

    def _a2a(self, agent_id: str, method: str, params: dict[str, Any], ctx: McpContext, sp: trace.Span) -> Any:
        return rpc_call(self.catalog.a2a_endpoint(agent_id), method, params, headers=self._gateway_headers(ctx, sp))

    def _access(self, agent_ids: list[str], ctx: McpContext, sp: trace.Span) -> dict[str, Any] | None:
        if self.settings.gateway_impl == "agentgateway":
            # agentgateway has no indication endpoint; evaluate the same policy file locally.
            # It is only an indication: agentgateway's CEL rules make the real decision.
            return {a: self.policy.access_indication(ctx.principal, a) for a in agent_ids}
        status, body, _ = http("POST", f"{self.settings.gateway_url}/internal/access-check",
                               json_body={"agent_ids": agent_ids}, headers=self._gateway_headers(ctx, sp))
        return body if status == 200 and isinstance(body, dict) else None

    # --- MCP tools -------------------------------------------------------------------

    def list_tools(self, ctx: McpContext) -> list[dict[str, Any]]:
        return TOOLS

    def call_tool(self, name: str, arguments: dict[str, Any], ctx: McpContext) -> dict[str, Any]:
        handler = {"whoami": self._whoami, "search_agents": self._search, "invoke_agent": self._invoke,
                   "provide_input": self._provide_input, "cancel_task": self._cancel}.get(name)
        if handler is None:
            raise RpcError(-32602, f"Unknown tool: {name}")
        with trace.span(f"registry {name}", COMPONENT, ctx.traceparent, user=ctx.principal.username) as sp:
            try:
                return handler(arguments, ctx, sp)
            except RpcError as e:
                sp.set(error_code=e.code)
                payload = {"error": e.message, **(e.data if isinstance(e.data, dict) else {})}
                return tool_result(payload, is_error=True)

    def _whoami(self, args: dict[str, Any], ctx: McpContext, sp: trace.Span) -> dict[str, Any]:
        p = ctx.principal
        return tool_result({"user": p.username, "name": p.name, "groups": list(p.groups), "roles": list(p.roles),
                            "runtime": p.origin_client, "caller_agent": self.policy.caller_agent(p.origin_client),
                            "delegation_path": list(p.actors)})

    def _search(self, args: dict[str, Any], ctx: McpContext, sp: trace.Span) -> dict[str, Any]:
        query = str(args.get("query", "")).strip()
        top_k = max(1, min(int(args.get("top_k", 5)), 10))
        hits = self.catalog.index.search(query, top_k * 2)
        access = self._access([h[0] for h in hits], ctx, sp) if hits else {}
        matches = []
        for agent_id, score, terms in hits:
            if access is None:
                status: dict[str, Any] = {"visible": True, "access": "unknown", "reason": "access check unavailable"}
            else:
                status = access.get(agent_id, {"visible": False})
            if not status.get("visible"):
                continue  # hidden agents are never disclosed, not even as "denied"
            card = self.catalog.cards[agent_id]
            matches.append({
                "agent_id": agent_id, "name": card["name"], "description": card["description"],
                "skills": [{"name": s["name"], "description": s["description"]} for s in card["skills"]],
                "owner": self.catalog.entries[agent_id].get("owner"),
                "relevance": score, "matched_terms": terms,
                "access": status["access"], "access_reason": status.get("reason"),
            })
        matches = matches[:top_k]
        if not matches:
            result, note = "no_matching_agent", "目錄中沒有符合這個需求的 Agent。"
        elif any(m["access"] == "allowed" for m in matches):
            result, note = "ok", "access 為 allowed 的 Agent 可以直接 invoke_agent。"
        else:
            result, note = "matches_without_access", "有相關的 Agent，但目前使用者沒有直接調用的權限。"
        sp.set(query_chars=len(query), result=result, matches=",".join(m["agent_id"] for m in matches))
        return tool_result({"result": result, "note": note, "matches": matches,
                            "search_mode": "keyword-bm25"})

    def _invoke(self, args: dict[str, Any], ctx: McpContext, sp: trace.Span) -> dict[str, Any]:
        agent_id = str(args.get("agent_id", ""))
        text = str(args.get("message", "")).strip()
        if not text:
            raise RpcError(-32602, "message is required")
        unknown = RpcError(-32602, f"unknown agent_id {agent_id!r}")
        if agent_id not in self.catalog.cards:
            raise unknown
        visibility = self._access([agent_id], ctx, sp) or {}
        if not visibility.get(agent_id, {"visible": True}).get("visible"):
            raise unknown  # hidden from this user: same answer as "does not exist"
        message = text_message(ROLE_USER, text, context_id=args.get("context_id"))
        sp.set(agent_id=agent_id)
        try:
            result = self._a2a(agent_id, "SendMessage",
                               {"message": message, "configuration": {"returnImmediately": True}}, ctx, sp)
        except RpcError as e:
            if e.http_status == 404:
                raise unknown from e
            if e.http_status == 403 and e.code != POLICY_DENIED:  # a gateway without JSON-RPC error bodies
                raise RpcError(POLICY_DENIED, "Request refused by Agent Gateway policy",
                               {"effect": "deny", "gateway_response": e.data}) from e
            raise
        task = result["task"]
        state = task["status"]["state"]
        self.tasks.add(task["id"], agent_id, ctx.principal.sub, task.get("contextId", ""), sp.trace_id, state)
        sp.set(task_id=task["id"], state=state)
        return tool_result({
            "task_id": task["id"], "agent_id": agent_id, "context_id": task.get("contextId"),
            "state": state, "resource_uri": f"{URI_SCHEME}{agent_id}/{task['id']}",
            "next_action": "Read resource_uri to wait for progress and results.",
        })

    def _owned(self, task_id: str, ctx: McpContext) -> dict[str, Any]:
        row = self.tasks.get(task_id)
        if row is None or row["owner"] != ctx.principal.sub:
            raise RpcError(-32602, "unknown task_id")
        return row

    def _provide_input(self, args: dict[str, Any], ctx: McpContext, sp: trace.Span) -> dict[str, Any]:
        row = self._owned(str(args.get("task_id", "")), ctx)
        message = text_message(ROLE_USER, str(args.get("message", "")), task_id=row["task_id"],
                               context_id=row["context_id"])
        task = self._a2a(row["agent_id"], "SendMessage",
                         {"message": message, "configuration": {"returnImmediately": True}}, ctx, sp)["task"]
        self.tasks.update_state(task["id"], task["status"]["state"])
        sp.set(task_id=task["id"], state=task["status"]["state"])
        return tool_result({"task_id": task["id"], "state": task["status"]["state"],
                            "resource_uri": f"{URI_SCHEME}{row['agent_id']}/{task['id']}"})

    def _cancel(self, args: dict[str, Any], ctx: McpContext, sp: trace.Span) -> dict[str, Any]:
        row = self._owned(str(args.get("task_id", "")), ctx)
        task = self._a2a(row["agent_id"], "CancelTask", {"id": row["task_id"]}, ctx, sp)
        self.tasks.update_state(task["id"], task["status"]["state"])
        sp.set(task_id=task["id"], state=task["status"]["state"])
        return tool_result({"task_id": task["id"], "state": task["status"]["state"]})

    # --- MCP resources ---------------------------------------------------------------

    def list_resource_templates(self, ctx: McpContext) -> list[dict[str, Any]]:
        return [{"uriTemplate": URI_SCHEME + "{agent_id}/{task_id}", "name": "a2a-task",
                 "title": "A2A task state",
                 "description": "Live state, questions and artifacts of a delegated A2A task. "
                                "A read waits (bounded) for the next state change.",
                 "mimeType": "application/json"}]

    def list_resources(self, ctx: McpContext) -> list[dict[str, Any]]:
        return [{"uri": f"{URI_SCHEME}{t['agent_id']}/{t['task_id']}", "name": f"{t['agent_id']}:{t['task_id'][:8]}",
                 "description": f"last known state {t['last_state']}", "mimeType": "application/json"}
                for t in self.tasks.for_owner(ctx.principal.sub)]

    def read_resource(self, uri: str, ctx: McpContext) -> dict[str, Any]:
        agent_id, task_id, wait = parse_task_uri(uri)
        row = self.tasks.get(task_id)
        if row is None or row["owner"] != ctx.principal.sub or row["agent_id"] != agent_id:
            raise RpcError(RESOURCE_NOT_FOUND, "Resource not found", {"uri": uri})
        budget = self.settings.resource_wait_seconds if wait is None else min(wait, self.settings.resource_wait_seconds)
        with trace.span("registry resources/read", COMPONENT, ctx.traceparent, task_id=task_id) as sp:
            deadline = time.time() + budget
            polls = 0
            while True:
                task = self._a2a(agent_id, "GetTask", {"id": task_id, "historyLength": 10}, ctx, sp)
                polls += 1
                if task["status"]["state"] not in IN_PROGRESS or time.time() >= deadline:
                    break
                time.sleep(0.5)  # wait loop stays here, not in the LLM
            self.tasks.update_state(task_id, task["status"]["state"])
            sp.set(state=task["status"]["state"], polls=polls)
        view = task_view(agent_id, task)
        return {"contents": [{"uri": uri, "mimeType": "application/json",
                              "text": json.dumps(view, ensure_ascii=False, indent=2)}]}
