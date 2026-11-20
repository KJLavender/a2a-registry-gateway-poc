"""A2A 1.0 constants and message helpers (JSON-RPC binding, proto3 JSON field names)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

A2A_VERSION = "1.0"

SUBMITTED = "TASK_STATE_SUBMITTED"
WORKING = "TASK_STATE_WORKING"
COMPLETED = "TASK_STATE_COMPLETED"
FAILED = "TASK_STATE_FAILED"
CANCELED = "TASK_STATE_CANCELED"
INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
REJECTED = "TASK_STATE_REJECTED"
AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"

TERMINAL = frozenset({COMPLETED, FAILED, CANCELED, REJECTED})
INTERRUPTED = frozenset({INPUT_REQUIRED, AUTH_REQUIRED})
IN_PROGRESS = frozenset({SUBMITTED, WORKING})

ROLE_USER = "ROLE_USER"
ROLE_AGENT = "ROLE_AGENT"

# JSON-RPC error codes (A2A spec §5.4)
TASK_NOT_FOUND = -32001
TASK_NOT_CANCELABLE = -32002
UNSUPPORTED_OPERATION = -32004
VERSION_NOT_SUPPORTED = -32009
INVALID_PARAMS = -32602
METHOD_NOT_FOUND = -32601
# Implementation-defined: request refused by Agent Gateway policy.
POLICY_DENIED = -32000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_id() -> str:
    return str(uuid.uuid4())


def text_message(role: str, text: str, *, task_id: str | None = None, context_id: str | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"messageId": new_id(), "role": role, "parts": [{"text": text}]}
    if task_id:
        message["taskId"] = task_id
    if context_id:
        message["contextId"] = context_id
    return message


def message_text(message: dict[str, Any] | None) -> str:
    if not message:
        return ""
    return "\n".join(p["text"] for p in message.get("parts", []) if "text" in p)


def is_new_task(rpc: Any) -> bool:
    """A2A SendMessage without a taskId starts a new task; with one it continues an existing task."""
    if not isinstance(rpc, dict) or rpc.get("method") != "SendMessage":
        return False
    params = rpc.get("params")
    message = params.get("message") if isinstance(params, dict) else None
    return not (isinstance(message, dict) and message.get("taskId"))


def is_continuation(rpc: Any) -> bool:
    return isinstance(rpc, dict) and rpc.get("method") == "SendMessage" and not is_new_task(rpc)
