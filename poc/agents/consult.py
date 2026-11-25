"""How an agent asks another agent: always through the gateway, for the same user and transaction.

1. Swap the token the agent received (audience agent:<self>) for one to the gateway, as client agent:<self>.
2. Call the gateway's A2A route for the other agent with that token and the Txn-Token it received. The
   gateway replaces the Txn-Token with one that adds this agent to `tctx.agents`, and the policy uses that
   list: this agent's delegation rules, no cycles, a maximum depth (poc/policy.py, delegation_limits).
3. Wait for the other agent's task to finish, up to WAIT seconds.
"""
from __future__ import annotations

import time
from typing import Any

from poc.agents.base import Consult
from poc.common.a2a import A2A_VERSION, IN_PROGRESS, ROLE_USER, text_message
from poc.common.identity import TokenExchanger
from poc.common.web import rpc_call
from poc.settings import Settings

WAIT = 60.0


def make_consult(settings: Settings) -> Consult:
    exchangers: dict[str, TokenExchanger] = {}

    def consult(caller: str, token: str, txn_token: str, target: str, text: str,
                traceparent: str | None) -> dict[str, Any]:
        exchanger = exchangers.setdefault(caller, TokenExchanger(settings, f"agent:{caller}"))
        headers = {"Authorization": f"Bearer {exchanger.exchange(token, 'agent-gateway')}",
                   "A2A-Version": A2A_VERSION, "Txn-Token": txn_token}
        if traceparent:
            headers["traceparent"] = traceparent
        url = f"{settings.gateway_url}/agents/{target}/a2a"
        task = rpc_call(url, "SendMessage", {"message": text_message(ROLE_USER, text),
                                             "configuration": {"returnImmediately": True}}, headers=headers)["task"]
        deadline = time.time() + WAIT
        while task["status"]["state"] in IN_PROGRESS and time.time() < deadline:
            time.sleep(0.5)
            task = rpc_call(url, "GetTask", {"id": task["id"]}, headers=headers)
        return task
    return consult
