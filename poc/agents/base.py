"""Minimal A2A 1.0 agent server (JSON-RPC binding) with an in-memory task store.

Agents only accept tokens whose audience is `agent:<agent_id>`, i.e. tokens the Agent
Gateway obtained through token exchange. A user's own token is rejected here.
"""
from __future__ import annotations

import copy
import threading
import time
from typing import Any, Callable

from poc.common import trace
from poc.common.a2a import (
    A2A_VERSION, CANCELED, COMPLETED, FAILED, INPUT_REQUIRED, INTERRUPTED, INVALID_PARAMS,
    METHOD_NOT_FOUND, ROLE_AGENT, SUBMITTED, TASK_NOT_CANCELABLE, TASK_NOT_FOUND, TERMINAL,
    UNSUPPORTED_OPERATION, VERSION_NOT_SUPPORTED, WORKING, message_text, new_id, now_iso, text_message,
)
from poc.common.identity import Verifier, actor_chain
from poc.common.jwt import TokenError
from poc.common.web import Request, Response, RpcError, rpc_response

# How long a blocking SendMessage (returnImmediately=false) may hold the HTTP request.
BLOCKING_SEND_LIMIT = 60.0
# Orphan protection: a task waiting for input fails after this many seconds.
INPUT_WAIT_LIMIT = 300.0


class TaskCanceled(Exception):
    pass


class TaskRecord:
    def __init__(self, first_message: dict[str, Any], owner: str, traceparent: str | None):
        self.id = new_id()
        self.context_id = first_message.get("contextId") or new_id()
        first = dict(first_message, taskId=self.id, contextId=self.context_id)
        self.task: dict[str, Any] = {
            "id": self.id, "contextId": self.context_id,
            "status": {"state": SUBMITTED, "timestamp": now_iso()},
            "artifacts": [], "history": [first],
        }
        self.owner = owner
        self.traceparent = traceparent
        self.cond = threading.Condition()
        self.pending_input: str | None = None
        self.cancel_requested = False

    @property
    def state(self) -> str:
        return self.task["status"]["state"]

    def set_state(self, state: str, text: str | None = None) -> bool:
        with self.cond:
            if self.state in TERMINAL:
                return False
            status: dict[str, Any] = {"state": state, "timestamp": now_iso()}
            if text:
                msg = text_message(ROLE_AGENT, text, task_id=self.id, context_id=self.context_id)
                status["message"] = msg
                self.task["history"].append(msg)
            self.task["status"] = status
            self.cond.notify_all()
            return True

    def wait(self, predicate: Callable[[], bool], timeout: float) -> bool:
        with self.cond:
            return self.cond.wait_for(predicate, timeout)

    def snapshot(self, history_length: int | None = None) -> dict[str, Any]:
        with self.cond:
            task = copy.deepcopy(self.task)
        if history_length is not None:
            task["history"] = task["history"][-history_length:] if history_length > 0 else []
        return task


class TaskContext:
    """What an agent handler sees: the request text plus progress/input/artifact controls."""

    def __init__(self, record: TaskRecord, speed: float):
        self._rec = record
        self.speed = speed

    @property
    def text(self) -> str:
        return message_text(self._rec.task["history"][0])

    @property
    def user(self) -> str:
        return self._rec.owner

    def progress(self, text: str) -> None:
        self._check()
        self._rec.set_state(WORKING, text)

    def ask(self, question: str, timeout: float = INPUT_WAIT_LIMIT) -> str:
        """Move to INPUT_REQUIRED and block until the caller continues the same task."""
        self._check()
        rec = self._rec
        with rec.cond:
            rec.pending_input = None
        rec.set_state(INPUT_REQUIRED, question)
        if not rec.wait(lambda: rec.pending_input is not None or rec.cancel_requested, timeout):
            raise TimeoutError("等待補件逾時")
        self._check()
        with rec.cond:
            answer, rec.pending_input = rec.pending_input or "", None
        rec.set_state(WORKING, "已收到補充資訊，繼續處理")
        return answer

    def artifact(self, name: str, *, text: str | None = None, data: Any = None, description: str = "") -> None:
        parts: list[dict[str, Any]] = []
        if text:
            parts.append({"text": text})
        if data is not None:
            parts.append({"data": data, "mediaType": "application/json"})
        with self._rec.cond:
            self._rec.task["artifacts"].append(
                {"artifactId": new_id(), "name": name, "description": description, "parts": parts})
            self._rec.cond.notify_all()

    def sleep(self, seconds: float) -> None:
        """Simulated work that still reacts to cancellation promptly."""
        rec = self._rec
        rec.wait(lambda: rec.cancel_requested, seconds * self.speed)
        self._check()

    def _check(self) -> None:
        if self._rec.cancel_requested:
            raise TaskCanceled()


Handler = Callable[[TaskContext], str]


class A2AAgent:
    def __init__(self, agent_id: str, card: dict[str, Any], handler: Handler, verify: Verifier, speed: float = 1.0,
                 verify_txn: Callable[[str], dict[str, Any]] | None = None):
        self.agent_id = agent_id
        self.card_template = card
        self.handler = handler
        self.verify = verify
        self.verify_txn = verify_txn  # Txn-Token check (poc/txn.py); None only for stand-alone runs
        self.speed = speed
        self.base_url = ""
        self.tasks: dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        self.component = f"agent:{agent_id}"

    def agent_card(self) -> dict[str, Any]:
        card = copy.deepcopy(self.card_template)
        card["supportedInterfaces"] = [
            {"url": f"{self.base_url}/a2a", "protocolBinding": "JSONRPC", "protocolVersion": A2A_VERSION}]
        return card

    def __call__(self, req: Request) -> Response:
        if req.method == "GET" and req.path == "/.well-known/agent-card.json":
            return Response(200, self.agent_card())
        if req.method == "POST" and req.path == "/a2a":
            return self._rpc(req)
        return Response(404, {"error": "not found"})

    def _rpc(self, req: Request) -> Response:
        try:
            msg = req.json()
        except ValueError:
            return Response(400, rpc_response(None, error=RpcError(-32700, "parse error")))
        rid = msg.get("id")
        try:
            claims = self.verify(req.bearer or "", f"agent:{self.agent_id}")
            txn = self.verify_txn(req.headers.get("txn-token", "")) if self.verify_txn else {}
            if self.verify_txn and txn.get("sub") != claims["sub"]:
                raise TokenError("transaction token belongs to another user")
        except TokenError as e:
            return Response(401, rpc_response(rid, error=RpcError(-32000, f"unauthorized: {e}")),
                            {"WWW-Authenticate": "Bearer"})
        version = req.headers.get("a2a-version") or "0.3"  # spec: empty header means 0.3
        if version.split(".")[0] != A2A_VERSION.split(".")[0]:
            return Response(200, rpc_response(rid, error=RpcError(
                VERSION_NOT_SUPPORTED, f"A2A version {version} is not supported", {"supported": [A2A_VERSION]})))
        method = msg.get("method")
        handler = {"SendMessage": self._send, "GetTask": self._get,
                   "CancelTask": self._cancel, "ListTasks": self._list}.get(method)
        if handler is None:
            return Response(200, rpc_response(rid, error=RpcError(METHOD_NOT_FOUND, f"method {method} not found")))
        with trace.span(f"a2a {method}", self.component, req.headers.get("traceparent"),
                        user=claims.get("preferred_username", claims["sub"]),
                        origin=txn.get("tctx", {}).get("origin_client"), txn=txn.get("txn"),
                        purpose=txn.get("scope"), delegation_path=" > ".join(actor_chain(claims))) as sp:
            try:
                result = handler(msg.get("params") or {}, claims, sp)
            except RpcError as e:
                sp.set(error_code=e.code)
                return Response(200, rpc_response(rid, error=e))
        return Response(200, rpc_response(rid, result))

    def _owned(self, task_id: str, claims: dict[str, Any]) -> TaskRecord:
        with self._lock:
            rec = self.tasks.get(task_id)
        if rec is None or rec.owner != claims["sub"]:
            raise RpcError(TASK_NOT_FOUND, "task not found")
        return rec

    def _send(self, params: dict[str, Any], claims: dict[str, Any], sp: trace.Span) -> dict[str, Any]:
        message = params.get("message")
        if not isinstance(message, dict) or not message.get("parts"):
            raise RpcError(INVALID_PARAMS, "message with parts is required")
        config = params.get("configuration") or {}
        if message.get("taskId"):
            rec = self._owned(message["taskId"], claims)
            with rec.cond:
                if rec.state != INPUT_REQUIRED:
                    raise RpcError(UNSUPPORTED_OPERATION, f"task is {rec.state} and does not accept input")
                rec.task["history"].append(dict(message, contextId=rec.context_id))
                rec.pending_input = message_text(message)
                rec.cond.notify_all()
            rec.wait(lambda: rec.state != INPUT_REQUIRED, 2.0)
        else:
            rec = TaskRecord(message, claims["sub"], sp.traceparent)
            with self._lock:
                self.tasks[rec.id] = rec
            threading.Thread(target=self._run, args=(rec,), name=f"{self.agent_id}-{rec.id[:8]}", daemon=True).start()
        sp.set(task_id=rec.id)
        if not config.get("returnImmediately"):
            rec.wait(lambda: rec.state in TERMINAL | INTERRUPTED, BLOCKING_SEND_LIMIT)
        return {"task": rec.snapshot(config.get("historyLength"))}

    def _get(self, params: dict[str, Any], claims: dict[str, Any], sp: trace.Span) -> dict[str, Any]:
        rec = self._owned(params.get("id", ""), claims)
        sp.set(task_id=rec.id, state=rec.state)
        return rec.snapshot(params.get("historyLength"))

    def _cancel(self, params: dict[str, Any], claims: dict[str, Any], sp: trace.Span) -> dict[str, Any]:
        rec = self._owned(params.get("id", ""), claims)
        with rec.cond:
            if rec.state in TERMINAL:
                raise RpcError(TASK_NOT_CANCELABLE, f"task is already {rec.state}")
            rec.cancel_requested = True
            rec.set_state(CANCELED, "已依要求取消")
        sp.set(task_id=rec.id)
        return rec.snapshot()

    def _list(self, params: dict[str, Any], claims: dict[str, Any], sp: trace.Span) -> dict[str, Any]:
        with self._lock:
            records = [r for r in self.tasks.values() if r.owner == claims["sub"]]
        if params.get("contextId"):
            records = [r for r in records if r.context_id == params["contextId"]]
        if params.get("status"):
            records = [r for r in records if r.state == params["status"]]
        tasks = [r.snapshot(params.get("historyLength", 0)) for r in records]
        return {"tasks": tasks, "nextPageToken": "", "pageSize": len(tasks), "totalSize": len(tasks)}

    def _run(self, rec: TaskRecord) -> None:
        ctx = TaskContext(rec, self.speed)
        with trace.span("agent.execute", self.component, rec.traceparent, task_id=rec.id) as sp:
            started = time.time()
            try:
                rec.set_state(WORKING)
                result = self.handler(ctx)
                rec.set_state(COMPLETED, result)
            except TaskCanceled:
                pass
            except Exception as e:  # agent failure becomes a FAILED task, not a crashed server
                rec.set_state(FAILED, f"處理失敗：{e}")
                sp.set(failure=str(e))
            sp.set(final_state=rec.state, work_seconds=round(time.time() - started, 2))
