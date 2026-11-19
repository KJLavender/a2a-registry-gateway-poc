"""Print one end-to-end trace from var/traces.jsonl as an indented tree."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SHOWN_ATTRS = ("user", "runtime", "agent_id", "delegation_path", "policy_effect", "policy_rule", "decision_id",
               "approval_request_id", "task_id", "state", "final_state", "polls", "result", "matches",
               "distributed", "reason", "failure", "error", "error_code")


def load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def latest_trace_id(spans: list[dict[str, Any]]) -> str | None:
    roots = [s for s in spans if s["component"] == "frontend"]
    return max(roots, key=lambda s: s["start"])["trace_id"] if roots else None


def render(spans: list[dict[str, Any]], trace_id: str) -> str:
    spans = [s for s in spans if s["trace_id"] == trace_id]
    if not spans:
        return f"trace {trace_id} not found"
    ids = {s["span_id"] for s in spans}
    children: dict[str | None, list[dict[str, Any]]] = {}
    for s in spans:
        children.setdefault(s["parent_id"] if s["parent_id"] in ids else None, []).append(s)
    t0 = min(s["start"] for s in spans)
    lines = [f"trace {trace_id}  ({len(spans)} spans)"]

    def walk(parent: str | None, depth: int) -> None:
        for s in sorted(children.get(parent, []), key=lambda x: x["start"]):
            attrs = s["attributes"]
            shown = " ".join(f"{k}={attrs[k]}" for k in SHOWN_ATTRS if k in attrs)
            if isinstance(attrs.get("task_id"), str):
                shown = shown.replace(attrs["task_id"], attrs["task_id"][:8])
            mark = " !" if s["status"] == "error" else ""
            lines.append(f"{'  ' * depth}+{(s['start'] - t0) * 1000:7.0f}ms {(s['end'] - s['start']) * 1000:6.0f}ms "
                         f"[{s['component']}] {s['name']}{mark}  {shown}".rstrip())
            walk(s["span_id"], depth + 1)

    walk(None, 0)
    return "\n".join(lines)
