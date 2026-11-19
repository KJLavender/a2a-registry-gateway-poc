"""Agent Gateway policy decisions (the PDP behind the gateway's enforcement point).

Three separate questions:
  1. capability distribution: which tools does a runtime see in tools/list?
  2. tool call: may this user call this tool?
  3. invocation: may this user, via this caller agent, delegate to this target agent?
"""
from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from poc.common.identity import Principal

ALLOW, DENY, APPROVAL = "allow", "deny", "approval_required"
ACCESS_LABEL = {ALLOW: "allowed", DENY: "denied", APPROVAL: "approval_required"}


@dataclass
class Decision:
    effect: str
    reason: str
    rule: str
    decision_id: str = field(default_factory=lambda: f"pd-{secrets.token_hex(6)}")

    @property
    def allowed(self) -> bool:
        return self.effect == ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {"effect": self.effect, "reason": self.reason, "rule": self.rule, "decision_id": self.decision_id}


def _matches(rule: dict[str, Any], p: Principal) -> bool:
    return bool(set(rule.get("allow_groups", [])) & set(p.groups) or set(rule.get("allow_roles", [])) & set(p.roles))


class PolicyStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._mtime: int | None = None
        self._data: dict[str, Any] = {}

    @property
    def data(self) -> dict[str, Any]:
        mtime = os.stat(self.path).st_mtime_ns
        with self._lock:
            if mtime != self._mtime:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
                self._mtime = mtime
            return self._data

    def caller_agent(self, client_id: str) -> str | None:
        return self.data["runtimes"].get(client_id, {}).get("agent_id")

    def distributed_tools(self, client_id: str) -> set[str]:
        data = self.data
        runtime = data["runtimes"].get(client_id)
        if runtime is None:
            return set()
        return {tool for s in runtime["tool_sets"] for tool in data["tool_sets"].get(s, [])}

    def tool_call(self, p: Principal, tool: str) -> Decision:
        rules = self.data["tool_call"]
        rule = rules.get(tool, rules["default"])
        name = f"tool_call.{tool if tool in rules else 'default'}"
        if _matches(rule, p):
            return Decision(ALLOW, "user matches tool rule", name)
        return Decision(DENY, "user lacks a group/role required for this tool", name)

    def visible(self, p: Principal, agent_id: str) -> bool:
        agent = self.data["agents"].get(agent_id)
        if agent is None:
            return False
        if agent.get("visibility") == "hidden":
            return bool(set(agent.get("visible_to_groups", [])) & set(p.groups))
        return True

    def invocation(self, p: Principal, agent_id: str) -> Decision:
        data = self.data
        caller = self.caller_agent(p.origin_client)
        if caller is None:
            return Decision(DENY, f"unknown caller runtime {p.origin_client!r}", "runtimes")
        targets = data["delegation"].get(caller)
        if targets is None or not ("*" in targets or agent_id in targets):
            return Decision(DENY, f"caller agent {caller!r} may not delegate to {agent_id!r}", f"delegation.{caller}")
        agent = data["agents"].get(agent_id)
        if agent is None:
            return Decision(DENY, "agent is not governed by policy", "agents")
        rule = agent["invoke"]
        if _matches(rule, p):
            return Decision(ALLOW, "user matches invoke rule", f"agents.{agent_id}.invoke")
        if set(rule.get("approval_groups", [])) & set(p.groups):
            return Decision(APPROVAL, "user may invoke after approval", f"agents.{agent_id}.invoke")
        return Decision(DENY, "user lacks a group/role required to invoke this agent", f"agents.{agent_id}.invoke")

    def access_indication(self, p: Principal, agent_id: str) -> dict[str, Any]:
        """What search results may say about an agent. Not a substitute for the invocation check."""
        if not self.visible(p, agent_id):
            return {"visible": False}
        d = self.invocation(p, agent_id)
        return {"visible": True, "access": ACCESS_LABEL[d.effect], "reason": d.reason, "decision_id": d.decision_id}
