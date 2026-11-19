"""Demo orchestrating runtime: an MCP client that delegates through the Agent Gateway.

It plays the Frontend + ACP client + agent runtime roles: sign in, open a
session (initialize + tools/list), then for one user request: search -> choose -> invoke ->
read the task resource until it finishes, answering INPUT_REQUIRED when it can.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from poc import llm
from poc.common import trace
from poc.common.a2a import INPUT_REQUIRED
from poc.common.identity import login
from poc.common.web import RpcError, http
from poc.settings import Settings

COMPONENT = "runtime"


def _from_sse(text: str, rid: str) -> Any:
    """Streamable HTTP may answer with an SSE stream; pick the JSON-RPC response for our request id."""
    for event in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].lstrip() for line in event.split("\n") if line.startswith("data:"))
        if data:
            message = json.loads(data)
            if isinstance(message, dict) and message.get("id") == rid:
                return message
    return None


class McpClient:
    def __init__(self, url: str, token: str, protocol_version: str = "2025-11-25"):
        self.url = url
        self.token = token
        self.protocol_version = protocol_version
        self.session_id: str | None = None
        self.extra_headers: dict[str, str] = {}

    def _post(self, payload: dict[str, Any], timeout: float) -> tuple[int, Any, dict[str, str]]:
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": self.protocol_version}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        headers.update(self.extra_headers)
        return http("POST", self.url, json_body=payload, headers=headers, timeout=timeout)

    def request(self, method: str, params: dict[str, Any] | None = None, *, traceparent: str | None = None,
                timeout: float = 60) -> Any:
        params = dict(params or {})
        if traceparent:
            params["_meta"] = {"traceparent": traceparent}  # MCP SEP-414
        rid = str(uuid.uuid4())
        status, body, headers = self._post({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}, timeout)
        if isinstance(body, str) and headers.get("content-type", "").startswith("text/event-stream"):
            body = _from_sse(body, rid)
        if isinstance(body, dict) and "error" in body:
            err = body["error"]
            raise RpcError(err.get("code", -32603), err.get("message", ""), err.get("data"), http_status=status)
        if status != 200 or not isinstance(body, dict):
            raise RpcError(-32603, f"HTTP {status}: {body}", http_status=status)
        if "mcp-session-id" in headers:
            self.session_id = headers["mcp-session-id"]
        return body["result"]

    def initialize(self, traceparent: str | None = None) -> dict[str, Any]:
        result = self.request("initialize", {"protocolVersion": self.protocol_version, "capabilities": {},
                                             "clientInfo": {"name": "poc-runtime", "version": "0.1.0"}},
                              traceparent=traceparent)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"}, 10)
        return result

    def list_tools(self, traceparent: str | None = None) -> list[dict[str, Any]]:
        return self.request("tools/list", traceparent=traceparent)["tools"]

    def call_tool(self, name: str, arguments: dict[str, Any], traceparent: str | None = None) -> tuple[dict[str, Any], bool]:
        result = self.request("tools/call", {"name": name, "arguments": arguments}, traceparent=traceparent)
        payload = result.get("structuredContent") or json.loads(result["content"][0]["text"])
        return payload, bool(result.get("isError"))

    def read_resource(self, uri: str, traceparent: str | None = None) -> dict[str, Any]:
        result = self.request("resources/read", {"uri": uri}, traceparent=traceparent, timeout=120)
        return json.loads(result["contents"][0]["text"])


@dataclass
class Outcome:
    status: str  # completed | failed | canceled | no_match | no_access | approval_required | input_required | no_capability
    trace_id: str
    agent_id: str | None = None
    task_id: str | None = None
    text: str = ""
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    matches: list[dict[str, Any]] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)


def choose_agent(prompt: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    """LLM picks among allowed candidates when POC_LLM=claude; otherwise the top-ranked one."""
    if llm.enabled() and len(candidates) > 1:
        schema = {"type": "object", "properties": {"agent_id": {"type": "string"}, "reason": {"type": "string"}},
                  "required": ["agent_id", "reason"]}
        listing = json.dumps([{k: c[k] for k in ("agent_id", "name", "description")} for c in candidates],
                             ensure_ascii=False)
        try:
            picked = llm.complete("Pick the single best agent for the request. Only use agent_id values from the list.",
                                  f"Request: {prompt}\nCandidates: {listing}", schema)
            for c in candidates:
                if c["agent_id"] == picked.get("agent_id"):
                    return c
        except Exception:
            pass
    return candidates[0]


def ask(settings: Settings, user: str, prompt: str, *, client: str = "orchestrator-runtime",
        answers: list[str] | None = None, say: Callable[[str], None] = print,
        on_task: Callable[[McpClient, str], None] | None = None) -> Outcome:
    answers = list(answers or [])
    token = login(settings, user, client)
    with trace.span("frontend request", "frontend", user=user, runtime=client) as root:
        mcp = McpClient(f"{settings.gateway_url}/mcp", token)
        with trace.span("acp session/new", COMPONENT) as sp:
            mcp.initialize(sp.traceparent)
            tools = {t["name"] for t in mcp.list_tools(sp.traceparent)}
        if "search_agents" not in tools:
            say(f"  這個 Runtime（{client}）沒有被分發 multi-agent 工具，只拿到：{sorted(tools)}")
            return Outcome("no_capability", root.trace_id, detail={"tools": sorted(tools)})

        with trace.span("acp session/prompt (agent turn)", COMPONENT) as turn:
            found, _ = mcp.call_tool("search_agents", {"query": prompt}, turn.traceparent)
            matches = found["matches"]
            for m in matches:
                say(f"  候選：{m['agent_id']:<18} 相關度 {m['relevance']:<6} 權限 {m['access']}")
            if not matches:
                say("  → 目錄裡沒有符合的 Agent")
                return Outcome("no_match", root.trace_id)
            allowed = [m for m in matches if m["access"] == "allowed"]
            if not allowed:
                needs_approval = [m for m in matches if m["access"] == "approval_required"]
                if not needs_approval:
                    for m in matches:
                        say(f"  → 能力存在但你目前沒有權限：{m['name']}（{m['access_reason']}）")
                    return Outcome("no_access", root.trace_id, matches=matches)
                allowed = needs_approval
            chosen = choose_agent(prompt, allowed)
            say(f"  → 委派給 {chosen['agent_id']}")
            inv, is_error = mcp.call_tool("invoke_agent", {"agent_id": chosen["agent_id"], "message": prompt},
                                          turn.traceparent)
            if is_error:
                status = "approval_required" if inv.get("approval_request_id") else "no_access"
                say(f"  → Gateway 拒絕：{inv.get('reason') or inv.get('error')}（{inv.get('approval_request_id') or inv.get('decision_id') or inv.get('effect')}）")
                return Outcome(status, root.trace_id, agent_id=chosen["agent_id"], matches=matches, detail=inv)
            task_id, uri = inv["task_id"], inv["resource_uri"]
            say(f"  → 已建立 A2A Task {task_id[:8]}…（invoke_agent 立即返回，狀態 {inv['state']}）")
            if on_task:
                on_task(mcp, task_id)
            last_message = None
            while True:
                view = mcp.read_resource(uri, turn.traceparent)
                if view["status_message"] and view["status_message"] != last_message:
                    say(f"    [{view['state'].removeprefix('TASK_STATE_')}] {view['status_message']}")
                    last_message = view["status_message"]
                if view["terminal"]:
                    break
                if view["state"] == INPUT_REQUIRED:
                    if not answers:
                        return Outcome("input_required", root.trace_id, chosen["agent_id"], task_id,
                                       view["status_message"], matches=matches)
                    reply = answers.pop(0)
                    say(f"    ↳ provide_input：{reply}")
                    mcp.call_tool("provide_input", {"task_id": task_id, "message": reply}, turn.traceparent)
            steps = [h["text"] for h in view["history_tail"] if h["role"] == "agent" and h["text"]]
            state = view["state"].removeprefix("TASK_STATE_").lower()
            return Outcome(state, root.trace_id, chosen["agent_id"], task_id, view["status_message"],
                           view["artifacts"], matches, {"steps": steps})
