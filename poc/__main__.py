"""Command line entry point: python -m poc <command>."""
from __future__ import annotations

import argparse
import logging
import sys
import time

from poc.common.web import http
from poc.settings import Settings


def _running(settings: Settings) -> bool:
    try:
        status, _, _ = http("GET", f"{settings.gateway_url}/healthz", timeout=1)
        return status == 200
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", line_buffering=True)  # type: ignore[attr-defined]
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(prog="python -m poc", description="A2A Registry + Gateway PoC")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("up", help="start IdP, agents, registry and gateway; Ctrl+C to stop")
    p_demo = sub.add_parser("demo", help="run the scripted scenarios (starts the stack if needed)")
    p_demo.add_argument("--only", help="run a single scenario number")
    p_token = sub.add_parser("token", help="print a user access token (for Claude Code or curl)")
    p_token.add_argument("user")
    p_token.add_argument("--client", default="orchestrator-runtime")
    p_ask = sub.add_parser("ask", help="send one request through the orchestrating runtime")
    p_ask.add_argument("user")
    p_ask.add_argument("prompt")
    p_ask.add_argument("--client", default="orchestrator-runtime")
    p_ask.add_argument("--answer", action="append", default=[], help="reply used if the agent asks for input")
    p_trace = sub.add_parser("trace", help="show a trace tree (default: latest request)")
    p_trace.add_argument("trace_id", nargs="?")
    args = parser.parse_args(argv)
    settings = Settings()

    if args.command == "trace":
        from poc import traceview
        spans = traceview.load(settings.trace_file)
        trace_id = args.trace_id or traceview.latest_trace_id(spans)
        print(traceview.render(spans, trace_id) if trace_id else "no traces yet")
        return 0

    stack = None
    if args.command == "up" or not _running(settings):
        from poc.launcher import start_stack
        stack = start_stack(settings)
        if args.command != "up":
            print(f"(started an in-process stack; gateway at {settings.gateway_url})")

    try:
        _run(args, settings, stack)
    finally:
        if stack:
            stack.close()
    return 0


def _run(args: argparse.Namespace, settings: Settings, stack) -> None:
    if args.command == "up":
        print(f"IdP       {settings.issuer}")
        print(f"Gateway   {settings.gateway_url}/mcp   (MCP)   {settings.gateway_url}/agents/<id>/a2a   (A2A)"
              f"   [{settings.gateway_impl}]")
        print(f"Registry  {settings.registry_url}/mcp  (behind the gateway)")
        for agent in stack.agents:
            print(f"Agent     {agent.base_url}  {agent.agent_id}")
        print(f"Catalog   indexed={sorted(stack.registry.catalog.cards)} rejected={stack.registry.catalog.rejected}")
        print("Running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return

    if args.command == "token":
        from poc.common.identity import login
        print(login(settings, args.user, args.client))
    elif args.command == "ask":
        from poc import runtime
        out = runtime.ask(settings, args.user, args.prompt, client=args.client, answers=args.answer)
        print(f"\n結果：{out.status}")
        if out.text:
            print(f"回覆：{out.text}")
        for a in out.artifacts:
            print(f"Artifact《{a['name']}》{a.get('text') or a.get('data')}")
        print(f"\ntrace：python -m poc trace {out.trace_id}")
    elif args.command == "demo":
        from poc import demo
        demo.run(settings, args.only)


if __name__ == "__main__":
    raise SystemExit(main())
