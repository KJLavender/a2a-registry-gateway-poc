"""System under test for the A2A TCK (github.com/a2aproject/a2a-tck), built on poc/agents/base.py.

The TCK checks protocol behavior: JSON-RPC errors, task states, artifacts, GetTask/CancelTask/ListTasks.
Its tests tell the agent what to do through the messageId prefix (scenarios/*.feature in the TCK repo);
this module implements those scenarios on the same A2A server the demo agents use.

Two ways to run it:

    python -m poc.tck_sut --port 18199                 the agent alone; it accepts any caller as one test user
    python -m poc.tck_sut --port 18199 --via-gateway   the agent behind a full stack (mock IdP, Txn-Tokens,
                                                       POC_GATEWAY decides which gateway), with real token checks
    (in a2a-tck) python run_tck.py --sut-host http://127.0.0.1:18199 --transport jsonrpc

The TCK cannot send credentials, so --via-gateway puts a small test proxy on --port that adds alice's
token to every request and forwards it to the gateway. What it checks: the gateway path does not break
the A2A protocol (routing, error codes, caching headers, parameter spellings).
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib import error as urlerror, request as urlrequest

from poc.agents.base import A2AAgent, TaskContext, TaskRejected
from poc.common.a2a import ROLE_AGENT, new_id
from poc.common.web import Request, Response, free_port, serve

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


# Declared when the agent really checks tokens (A2A 1.0 AgentCard.securitySchemes / securityRequirements)
BEARER = {"securitySchemes": {"bearer": {"httpAuthSecurityScheme": {"scheme": "Bearer", "bearerFormat": "JWT"}}},
          "securityRequirements": [{"schemes": {"bearer": {"list": []}}}]}


def build(base_url: str, verify: Callable[[str, str], dict[str, Any]] | None = None,
          verify_txn: Callable[[str], dict[str, Any]] | None = None) -> A2AAgent:
    card = dict(CARD, **BEARER) if verify else CARD
    agent = A2AAgent("tck-sut", card, handle, verify=verify or (lambda _token, _aud: {"sub": "tck-user"}),
                     direct_reply=direct_reply, verify_txn=verify_txn)
    agent.base_url = base_url
    return agent


def _credential_proxy(target: str, public_url: str, token: str) -> Callable[[Request], Response]:
    """Test-only: forward to `target` with a bearer token, so the TCK can reach an authenticated gateway."""
    opener = urlrequest.build_opener(urlrequest.ProxyHandler({}))
    passed = ("content-type", "a2a-version", "accept", "if-none-match", "a2a-extensions")

    def app(req: Request) -> Response:
        headers = {k: v for k, v in req.headers.items() if k in passed}
        headers["Authorization"] = f"Bearer {token}"
        call = urlrequest.Request(target + req.path, data=req.body or None, method=req.method, headers=headers)
        try:
            with opener.open(call, timeout=60) as resp:
                status, body, got = resp.status, resp.read(), resp.headers
        except urlerror.HTTPError as e:
            status, body, got = e.code, e.read(), e.headers
        out = {k: v for k, v in got.items() if k.lower() in ("content-type", "cache-control", "etag")}
        if req.path.endswith("agent-card.json") and status == 200:
            card = json.loads(body)
            for interface in card.get("supportedInterfaces", []):
                interface["url"] = f"{public_url}/a2a"  # keep the TCK on this proxy, which adds the token
            body = json.dumps(card).encode()
        return Response(status, body, out)
    return app


def run_via_gateway(port: int) -> list[Any]:
    """Start a stack with the TCK agent registered (lifecycle "test": routed, not in search results)."""
    from poc.common.identity import login, make_verifier
    from poc.launcher import start_stack
    from poc.settings import ROOT, Settings
    from poc.txn import TxnVerifier

    tmp = Path(tempfile.mkdtemp(prefix="a2a-tck-"))
    shutil.copytree(ROOT / "config", tmp / "config")
    agents_file, policy_file = tmp / "config" / "agents.json", tmp / "config" / "policy.json"
    agents = json.loads(agents_file.read_text(encoding="utf-8"))
    agents["agents"].append({"agent_id": "tck-sut", "port": free_port(), "owner": "TCK", "lifecycle": "test"})
    agents_file.write_text(json.dumps(agents), encoding="utf-8")
    policy = json.loads(policy_file.read_text(encoding="utf-8"))
    policy["agents"]["tck-sut"] = {"visibility": "listed", "invoke": {"allow_groups": ["employees"]}}
    policy_file.write_text(json.dumps(policy), encoding="utf-8")
    settings = Settings(config_dir=tmp / "config", var_dir=tmp / "var", idp_impl="mock", idp_port=free_port(),
                        gateway_port=free_port(), registry_port=free_port(), pdp_port=free_port(),
                        txn_port=free_port(), agent_ports={a["agent_id"]: free_port() for a in agents["agents"]})
    stack = start_stack(settings)
    agent = build(settings.agent_url("tck-sut"), make_verifier(settings), TxnVerifier(settings).verify)
    public = f"http://127.0.0.1:{port}"
    proxy = _credential_proxy(f"{settings.gateway_url}/agents/tck-sut", public,
                              login(settings, "alice", "orchestrator-runtime"))
    servers = [serve(agent, "127.0.0.1", settings.agent_ports["tck-sut"]), serve(proxy, "127.0.0.1", port)]
    print(f"gateway: {settings.gateway_impl} on {settings.gateway_url}; TCK target: {public}")
    return [stack, *servers]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=18199)
    parser.add_argument("--via-gateway", action="store_true", help="put the agent behind a full stack")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.via_gateway:
        running = run_via_gateway(args.port)
    else:
        running = [serve(build(f"http://127.0.0.1:{args.port}"), "127.0.0.1", args.port)]
    print(f"TCK SUT on http://127.0.0.1:{args.port} (Ctrl+C to stop)", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for item in running:
            item.close() if hasattr(item, "close") and not hasattr(item, "shutdown") else item.shutdown()


if __name__ == "__main__":
    main()
