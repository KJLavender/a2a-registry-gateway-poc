"""System under test for the A2A TCK (github.com/a2aproject/a2a-tck), built on poc/agents/base.py.

The TCK checks protocol behavior: JSON-RPC errors, task states, artifacts, GetTask/CancelTask/ListTasks.
Its tests tell the agent what to do through the messageId prefix (scenarios/*.feature in the TCK repo);
this module implements those scenarios on the same A2A server the demo agents use.

Authentication is out of scope for the TCK, so this agent accepts any caller as one test user.

    python -m poc.tck_sut --port 18199
    (in a2a-tck) python run_tck.py --sut-host http://127.0.0.1:18199 --transport jsonrpc
"""
from __future__ import annotations

import argparse
import base64
import logging
import time
from typing import Any

from poc.agents.base import A2AAgent, TaskContext, TaskRejected
from poc.common.a2a import ROLE_AGENT, new_id
from poc.common.web import serve

CARD = {
    "name": "TCK system under test",
    "description": "Implements the A2A TCK scenarios on the PoC's A2A server (poc/agents/base.py).",
    "version": "1.0.0",
    "capabilities": {"streaming": False, "pushNotifications": False},
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain", "application/json"],
    "skills": [{"id": "tck", "name": "TCK scenarios", "description": "Behavior selected by messageId prefix.",
                "tags": ["tck"]}],
}


def _prefix(message: dict[str, Any]) -> str:
    return str(message.get("messageId", ""))


def direct_reply(message: dict[str, Any]) -> dict[str, Any] | None:
    if _prefix(message).startswith("tck-message-response"):
        return {"messageId": new_id(), "role": ROLE_AGENT, "parts": [{"text": "Direct message response"}],
                **({"contextId": message["contextId"]} if message.get("contextId") else {})}
    return None


def handle(ctx: TaskContext) -> str:
    prefix = _prefix(ctx.message)
    # Longest prefixes first: tck-artifact-file-url also starts with tck-artifact-file
    if prefix.startswith("tck-artifact-text"):
        ctx.artifact("text", text="Generated text content")
    elif prefix.startswith("tck-artifact-file-url"):
        ctx.artifact("file-url", parts=[{"url": "https://example.com/output.txt", "filename": "output.txt",
                                         "mediaType": "text/plain"}])
    elif prefix.startswith("tck-artifact-file"):
        ctx.artifact("file", parts=[{"raw": base64.b64encode(b"file content").decode(), "filename": "output.txt",
                                     "mediaType": "text/plain"}])
    elif prefix.startswith("tck-artifact-data"):
        ctx.artifact("data", data={"key": "value", "count": 42})
    elif prefix.startswith("tck-input-required"):
        ctx.ask("Please provide input")
    elif prefix.startswith("tck-reject-task"):
        raise TaskRejected("rejected")
    else:  # tck-complete-task and anything else
        return "Hello from TCK"
    return ""


def build(base_url: str) -> A2AAgent:
    agent = A2AAgent("tck-sut", CARD, handle, verify=lambda _token, _aud: {"sub": "tck-user"},
                     direct_reply=direct_reply)
    agent.base_url = base_url
    return agent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=18199)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    server = serve(build(f"http://127.0.0.1:{args.port}"), "127.0.0.1", args.port)
    print(f"TCK SUT on http://127.0.0.1:{args.port} (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
