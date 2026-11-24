"""An agent built on the official A2A Python SDK (a2a-sdk 1.3), not on poc/agents/base.py.

It shows that an agent written with a real framework joins the same catalog and governance unchanged:
the registry finds it, the gateway decides who may use it, and it checks the same tokens itself.

- Agent logic: `LeaveExecutor`, an SDK `AgentExecutor` (asks for dates when they are missing).
- Protocol: the SDK's JSON-RPC routes, task store and request handler (A2A 1.0).
- Security: `Guard`, an ASGI middleware in front of the SDK app. It checks the access token
  (audience agent:hr-leave) and the Txn-Token, and hands the user to the SDK, whose task store keeps
  each user's tasks apart.

Needs `pip install "a2a-sdk[http-server]" uvicorn`; without them the launcher skips this agent and the
registry lists it as unreachable.
"""
from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from typing import Any, Callable

import uvicorn
from a2a.helpers.proto_helpers import new_data_part, new_text_part
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types import (
    AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill, Role, Task, TaskState, TaskStatus,
)
from starlette.applications import Starlette
from starlette.authentication import AuthCredentials, SimpleUser
from starlette.concurrency import run_in_threadpool

from poc.common import trace
from poc.common.identity import Verifier
from poc.common.jwt import TokenError

AGENT_ID = "hr-leave"
PUBLIC_PATHS = ("/.well-known/agent-card.json",)
_DATES = re.compile(r"\d{1,2}/\d{1,2}")


def agent_card(base_url: str) -> AgentCard:
    return AgentCard(
        name="人資請假助理",
        description="查特休餘額、送出請假申請。Leave balance and leave requests, built on the official A2A SDK.",
        version="1.0.0",
        provider=AgentProvider(organization="HR", url="https://example.com/hr"),
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain", "application/json"],
        skills=[
            AgentSkill(id="leave-balance", name="特休餘額查詢",
                       description="查詢剩餘特休、補休天數與到期日。Annual leave and comp time balance.",
                       tags=["請假", "特休", "補休", "休假", "leave", "vacation", "HR"],
                       examples=["我還剩幾天特休？", "How many vacation days do I have left?"]),
            AgentSkill(id="leave-request", name="請假申請",
                       description="填寫請假單並送主管簽核。Submit a leave request for manager approval.",
                       tags=["請假", "假單", "病假", "事假", "leave request", "time off"],
                       examples=["我想請 12/3 到 12/4 的特休", "幫我送一張病假單"]),
        ],
        supported_interfaces=[AgentInterface(protocol_binding="JSONRPC", protocol_version="1.0",
                                             url=f"{base_url}/a2a")],
    )


class LeaveExecutor(AgentExecutor):
    def __init__(self, speed: float = 1.0):
        self.speed = speed
        self.canceled: set[str] = set()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        headers = (context.call_context.state.get("headers", {}) if context.call_context else {})
        updater = TaskUpdater(event_queue=event_queue, task_id=context.task_id or "",
                              context_id=context.context_id or "")
        with trace.span("agent.execute", f"agent:{AGENT_ID}", headers.get("traceparent")) as sp:
            if context.current_task is None:  # the SDK wants the Task itself before any status update
                await event_queue.enqueue_event(Task(
                    id=context.task_id, context_id=context.context_id,
                    status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED), history=[context.message]))
            await updater.start_work(updater.new_agent_message([new_text_part("讀取假勤資料中…")]))
            await asyncio.sleep(0.6 * self.speed)
            if context.task_id in self.canceled:
                return
            # Only what the user wrote: the agent's own question contains example dates
            history = [p.text for m in (context.current_task.history if context.current_task else [])
                       if m.role == Role.ROLE_USER for p in m.parts if p.text]
            text = " ".join([*history, context.get_user_input()])
            wants_leave = any(w in text for w in ("請假", "休假", "休息", "病假", "事假", "day off", "time off", "leave request"))
            dates = list(dict.fromkeys(_DATES.findall(text)))  # history repeats earlier messages
            if wants_leave and not dates:
                sp.set(outcome="input_required")
                await updater.requires_input(updater.new_agent_message(
                    [new_text_part("要請哪幾天？請用月/日寫，例如 12/3 或 12/3-12/4。")]))
                return
            balance = {"annual_leave_days": 7.5, "comp_time_hours": 6, "annual_leave_expires": "2026-12-31"}
            if wants_leave:
                await updater.add_artifact([new_data_part({"type": "leave-request", "dates": dates,
                                                           "status": "submitted (simulated)", **balance})],
                                           name="leave-request")
                reply = f"已送出 {'、'.join(dates)} 的請假申請給主管（模擬）。剩餘特休 7.5 天。"
            else:
                await updater.add_artifact([new_data_part(balance)], name="leave-balance")
                reply = "剩餘特休 7.5 天，補休 6 小時，特休在 2026-12-31 到期（模擬資料）。"
            sp.set(outcome="completed")
            await updater.complete(updater.new_agent_message([new_text_part(reply)]))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        self.canceled.add(context.task_id or "")
        await TaskUpdater(event_queue=event_queue, task_id=context.task_id or "",
                          context_id=context.context_id or "").cancel()


class Guard:
    """ASGI middleware: the same token checks as poc/agents/base.py, before the SDK sees the request."""

    def __init__(self, app: Any, verify: Verifier, verify_txn: Callable[[str], dict[str, Any]] | None):
        self.app = app
        self.verify = verify
        self.verify_txn = verify_txn

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan" or (scope["type"] == "http" and scope["method"] == "GET"
                                           and scope["path"] in PUBLIC_PATHS):
            await self.app(scope, receive, send)  # the agent card is public; everything else needs tokens
            return
        if scope["type"] != "http":
            return  # no websockets
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        bearer = headers.get("authorization", "")[7:] if headers.get("authorization", "")[:7].lower() == "bearer " else ""
        try:
            claims = await run_in_threadpool(self.verify, bearer, f"agent:{AGENT_ID}")
            txn = await run_in_threadpool(self.verify_txn, headers.get("txn-token", "")) if self.verify_txn else {}
            if self.verify_txn and txn.get("sub") != claims["sub"]:
                raise TokenError("transaction token belongs to another user")
        except TokenError as e:
            await _send_json(send, 401, {"jsonrpc": "2.0", "id": None,
                                         "error": {"code": -32000, "message": f"unauthorized: {e}"}})
            return
        try:
            method = json.loads(body).get("method")
        except (ValueError, AttributeError):
            method = None
        scope["user"] = SimpleUser(claims["sub"])  # the SDK's task store keeps each user's tasks apart
        scope["auth"] = AuthCredentials(["authenticated"])
        with trace.span(f"a2a {method}", f"agent:{AGENT_ID}", headers.get("traceparent"),
                        user=claims.get("preferred_username", claims["sub"]), txn=txn.get("txn"),
                        origin=txn.get("tctx", {}).get("origin_client"), purpose=txn.get("scope"),
                        framework="a2a-sdk") as sp:
            scope["headers"] = [(k, v) for k, v in scope["headers"] if k.lower() != b"traceparent"]
            scope["headers"].append((b"traceparent", sp.traceparent.encode()))
            replayed = False

            async def replay() -> dict[str, Any]:
                nonlocal replayed
                if replayed:
                    return await receive()
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}

            await self.app(scope, replay, send)


async def _send_json(send: Any, status: int, payload: dict[str, Any]) -> None:
    data = json.dumps(payload).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]})
    await send({"type": "http.response.body", "body": data})


def build_app(base_url: str, verify: Verifier, verify_txn: Callable[[str], dict[str, Any]] | None,
              speed: float = 1.0) -> Any:
    card = agent_card(base_url)
    handler = DefaultRequestHandler(agent_executor=LeaveExecutor(speed), task_store=InMemoryTaskStore(),
                                    agent_card=card)
    app = Starlette(routes=[*create_agent_card_routes(agent_card=card),
                            *create_jsonrpc_routes(request_handler=handler, rpc_url="/a2a")])
    return Guard(app, verify, verify_txn)


class SdkAgentServer:
    """Runs the SDK app with uvicorn on a thread; `shutdown`/`server_close` match ThreadingHTTPServer."""

    def __init__(self, app: Any, host: str, port: int):
        self.server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning", lifespan="off"))
        self.thread = threading.Thread(target=self.server.run, name=f"agent-{AGENT_ID}", daemon=True)
        self.thread.start()
        deadline = time.time() + 15
        while not self.server.started:
            if time.time() > deadline or not self.thread.is_alive():
                raise RuntimeError(f"{AGENT_ID} (a2a-sdk) did not start on port {port}")
            time.sleep(0.05)

    def shutdown(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)

    def server_close(self) -> None:
        pass
