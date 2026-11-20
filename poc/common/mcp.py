"""Minimal MCP server over Streamable HTTP (JSON responses only, no SSE stream)."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from poc.common.identity import Principal
from poc.common.web import Request, Response, RpcError, rpc_response

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
RESOURCE_NOT_FOUND = -32002


@dataclass
class McpContext:
    principal: Principal
    token: str  # kept only to exchange it; never logged or returned
    traceparent: str | None


def tool_result(payload: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
        "structuredContent": payload,
        "isError": is_error,
    }


class McpServer:
    name = "mcp-server"
    version = "0.1.0"
    instructions: str | None = None

    def list_tools(self, ctx: McpContext) -> list[dict[str, Any]]:
        return []

    def call_tool(self, name: str, arguments: dict[str, Any], ctx: McpContext) -> dict[str, Any]:
        raise RpcError(-32602, f"Unknown tool: {name}")

    def list_resources(self, ctx: McpContext) -> list[dict[str, Any]]:
        return []

    def list_resource_templates(self, ctx: McpContext) -> list[dict[str, Any]]:
        return []

    def read_resource(self, uri: str, ctx: McpContext) -> dict[str, Any]:
        raise RpcError(RESOURCE_NOT_FOUND, "Resource not found", {"uri": uri})

    def handle(self, msg: dict[str, Any], ctx: McpContext) -> dict[str, Any] | None:
        rid = msg.get("id")
        if rid is None:
            return None  # notification (e.g. notifications/initialized)
        method = msg.get("method")
        params = msg.get("params") or {}
        try:
            if method == "initialize":
                requested = params.get("protocolVersion")
                result: Any = {
                    "protocolVersion": requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                    "capabilities": {"tools": {"listChanged": False},
                                     "resources": {"subscribe": False, "listChanged": False}},
                    "serverInfo": {"name": self.name, "version": self.version},
                }
                if self.instructions:
                    result["instructions"] = self.instructions
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": self.list_tools(ctx)}
            elif method == "tools/call":
                result = self.call_tool(params.get("name", ""), params.get("arguments") or {}, ctx)
            elif method == "resources/list":
                result = {"resources": self.list_resources(ctx)}
            elif method == "resources/templates/list":
                result = {"resourceTemplates": self.list_resource_templates(ctx)}
            elif method == "resources/read":
                result = self.read_resource(params.get("uri", ""), ctx)
            elif method == "prompts/list":
                result = {"prompts": []}
            else:
                raise RpcError(-32601, f"Method not found: {method}")
        except RpcError as e:
            return rpc_response(rid, error=e)
        except (ValueError, TypeError) as e:
            return rpc_response(rid, error=RpcError(-32602, f"Invalid params: {e}"))
        return rpc_response(rid, result)


def serve_mcp(server: McpServer, req: Request, authenticate: Callable[[Request], Principal | Response]) -> Response:
    """Streamable HTTP transport: POST carries one JSON-RPC message; GET (SSE) is not offered."""
    if req.method != "POST":
        return Response(405, {"error": "method not allowed"}, {"Allow": "POST"})
    principal = authenticate(req)
    if isinstance(principal, Response):
        return principal
    try:
        msg = req.json()
    except ValueError:
        return Response(400, rpc_response(None, error=RpcError(-32700, "parse error")))
    if not isinstance(msg, dict):
        return Response(400, rpc_response(None, error=RpcError(-32600, "batch requests are not supported")))
    traceparent = ((msg.get("params") or {}).get("_meta") or {}).get("traceparent") or req.headers.get("traceparent")
    reply = server.handle(msg, McpContext(principal, req.bearer or "", traceparent))
    if reply is None:
        return Response(202)
    headers = {"Mcp-Session-Id": uuid.uuid4().hex} if msg.get("method") == "initialize" else {}
    return Response(200, reply, headers)
