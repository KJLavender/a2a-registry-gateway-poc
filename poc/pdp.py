"""Policy Decision Point service: A2A authorization for agentgateway (extAuthz) and the approval API.

Routes
  ANY  /authz/a2a                       agentgateway extAuthz (HTTP). 200 = allow; otherwise the status and
                                        JSON-RPC error body are what the caller sees.
  ANY  /authz/mcp                       agentgateway extAuthz on the MCP route: mints the request's Txn-Token
                                        (poc/txn.py), which agentgateway passes on to the registry.
  GET  /approvals                       pending requests the caller may decide, plus the caller's own
  POST /approvals/{id}/approve|reject   decide a request (approver rule from policy.json; not your own)
  GET  /notifications                   the caller's approval notifications (poc/notify.py)
  POST /notifications/read              {"ids": [...]} marks them read

The built-in gateway uses `A2AAuthorizer` in-process, so both gateways make the same decisions.
"""
from __future__ import annotations

import json
import re
from typing import Any

from poc.approvals import ApprovalError, ApprovalStore
from poc.common import trace
from poc.common.a2a import POLICY_DENIED, is_continuation, is_new_task
from poc.common.identity import Principal, Verifier
from poc.common.jwt import TokenError
from poc.common.web import Request, Response, RpcError, rpc_response
from poc.notify import Notifier
from poc.policy import ALLOW, APPROVAL, Decision, PolicyStore
from poc.settings import Settings
from poc.txn import EDGE_A2A, HEADER as TXN_HEADER, TxnGate, mcp_purpose, purpose_allows

COMPONENT = "policy-decision-point"
_AGENT_PATH = re.compile(r"^/agents/([a-z0-9-]+)/")
_DECIDE_PATH = re.compile(r"^/approvals/(APR-[0-9A-F]+)/(approve|reject)$")
# Same status and body agentgateway returns for a path no route matches, so a hidden agent
# cannot be told apart from one that does not exist.
NOT_FOUND = Response(404, "route not found", {"Content-Type": "text/plain"})


class A2AAuthorizer:
    """A2A rules shared by both gateways. Callers check visibility first (hidden = 404).

    - New task: the full invocation decision, every time (approvals included).
    - Continuing a task (provide_input): refused if the user may no longer invoke the agent at all;
      an approval-gated user may continue the task that was approved.
    - GetTask / CancelTask: allowed here; the agent only serves the task's owner.
    """

    def __init__(self, policy: PolicyStore, approvals: ApprovalStore, notifier: Notifier | None = None):
        self.policy = policy
        self.approvals = approvals
        self.notifier = notifier

    def continuation(self, p: Principal, agent_id: str) -> Decision:
        decision = self.policy.invocation(p, agent_id)
        if decision.effect == APPROVAL:
            return Decision(ALLOW, "continuing a task the user was allowed to start", decision.rule)
        return decision

    def new_task(self, p: Principal, agent_id: str) -> Decision:
        decision = self.policy.invocation(p, agent_id)  # authoritative, every time
        if decision.effect == APPROVAL:
            grant = self.approvals.take_grant(p.sub, agent_id)
            if grant:
                return Decision(ALLOW, f"approved by {grant['decided_by']}", decision.rule,
                                approval_request_id=grant["id"])
            request = self.approvals.open_or_get(p.sub, p.username, agent_id)
            decision.approval_request_id = request["id"]
            if self.notifier:
                self.notifier.approval_requested(request)  # once per request; repeats are ignored
        return decision


def refusal(rid: Any, decision: Decision) -> Response:
    return Response(403, rpc_response(rid, error=RpcError(
        POLICY_DENIED, f"Request refused by Agent Gateway policy: {decision.reason}", decision.to_dict())))


class PolicyDecisionPoint:
    def __init__(self, settings: Settings, policy: PolicyStore, approvals: ApprovalStore, verify: Verifier,
                 notifier: Notifier | None = None):
        self.policy = policy
        self.approvals = approvals
        self.verify = verify
        self.notifier = notifier
        self.txn = TxnGate(settings)  # the PDP is agentgateway's half of the trust-domain edge
        self.authorizer = A2AAuthorizer(policy, approvals, notifier)

    def __call__(self, req: Request) -> Response:
        if req.path == "/authz/a2a":  # agentgateway keeps the original method (GET for agent cards)
            return self._authz(req)
        if req.path == "/authz/mcp":
            return self._authz_mcp(req)
        if req.method == "POST" and req.path == "/approvals/restore":
            return self._restore(req)
        if req.method == "GET" and req.path == "/approvals":
            return self._list(req)
        if req.path == "/notifications" and req.method == "GET":
            return self._inbox(req)
        if req.path == "/notifications/read" and req.method == "POST":
            return self._mark_read(req)
        m = _DECIDE_PATH.match(req.path)
        if req.method == "POST" and m:
            return self._decide(req, m.group(1), m.group(2) == "approve")
        if req.method == "GET" and req.path == "/healthz":
            return Response(200, {"status": "ok"})
        return Response(404, {"error": "not found"})

    def _principal(self, token: str) -> Principal | Response:
        try:
            return Principal.from_claims(self.verify(token, "agent-gateway"))
        except TokenError as e:
            return Response(401, {"error": f"unauthorized: {e}"})

    def _authz(self, req: Request) -> Response:
        # agentgateway sends the validated token and original path as headers, the A2A body as the body
        subject_token = req.headers.get("x-subject-token", "")
        p = self._principal(subject_token)
        if isinstance(p, Response):
            return p
        m = _AGENT_PATH.match(req.headers.get("x-original-path", ""))
        if not m:
            return NOT_FOUND
        agent_id = m.group(1)
        try:
            p, txn_token = self.txn.establish(p, subject_token, req.headers.get(TXN_HEADER, ""), EDGE_A2A)
        except (TokenError, OSError) as e:
            return Response(401, {"error": f"unauthorized: {e}"})
        allow = Response(200, {"allow": True}, {"Txn-Token": txn_token})  # agentgateway passes it to the agent
        try:
            rpc = json.loads(req.body or b"{}")
        except ValueError:
            rpc = {}
        method = rpc.get("method") if isinstance(rpc, dict) else None
        with trace.span(f"pdp authz {method}", COMPONENT, req.headers.get("traceparent"),
                        agent_id=agent_id, user=p.username, txn=p.txn, origin=p.origin_client,
                        purpose=p.purpose) as sp:
            if not self.policy.visible(p, agent_id):
                sp.set(policy_effect="deny", reason="agent hidden from user")
                return NOT_FOUND
            if req.method == "GET":
                return allow  # agent card
            if not purpose_allows(p.purpose, rpc):
                sp.set(policy_effect="deny", reason="outside the transaction's purpose")
                return Response(403, rpc_response(rpc.get("id") if isinstance(rpc, dict) else None, error=RpcError(
                    POLICY_DENIED, f"{method} is outside this transaction's purpose ({p.purpose})")))
            if is_new_task(rpc):
                decision = self.authorizer.new_task(p, agent_id)
            elif is_continuation(rpc):
                decision = self.authorizer.continuation(p, agent_id)
            else:
                return allow  # GetTask/CancelTask: the agent serves the owner only
            sp.set(policy_effect=decision.effect, policy_rule=decision.rule, decision_id=decision.decision_id,
                   approval_request_id=decision.approval_request_id)
            if decision.allowed:
                return allow
            return refusal(rpc.get("id"), decision)

    def _authz_mcp(self, req: Request) -> Response:
        """Edge of the trust domain for MCP: a new Txn-Token for every request from a runtime."""
        subject_token = req.headers.get("x-subject-token", "")
        try:
            rpc = json.loads(req.body or b"{}")
        except ValueError:
            rpc = {}
        purpose = mcp_purpose(rpc.get("method", ""), rpc.get("params")) if isinstance(rpc, dict) else ""
        with trace.span("pdp mint txn-token", COMPONENT, req.headers.get("traceparent"), purpose=purpose) as sp:
            try:
                token = self.txn.mint(subject_token, purpose)
            except (TokenError, OSError) as e:
                sp.set(error=str(e))
                return Response(401, {"error": f"unauthorized: {e}"})
        return Response(200, {"allow": True}, {"Txn-Token": token})

    def _restore(self, req: Request) -> Response:
        """Called by the registry when a call allowed by an approval failed before reaching the agent."""
        p = self._principal(req.bearer or "")
        if isinstance(p, Response):
            return p
        if p.immediate_actor != "agent-registry":
            return Response(403, {"error": "only the agent registry may restore approvals"})
        agent_id = str(req.json().get("agent_id", ""))
        self.approvals.restore_recent(p.sub, agent_id)
        return Response(200, {"restored_for": agent_id})

    def _list(self, req: Request) -> Response:
        p = self._principal(req.bearer or "")
        if isinstance(p, Response):
            return p
        rows = self.approvals.pending()
        return Response(200, {
            "to_decide": [r for r in rows if r["requester_sub"] != p.sub and self.policy.can_approve(p, r["agent_id"])],
            "mine": [r for r in rows if r["requester_sub"] == p.sub],
        })

    def _decide(self, req: Request, approval_id: str, approve: bool) -> Response:
        p = self._principal(req.bearer or "")
        if isinstance(p, Response):
            return p
        row = self.approvals.get(approval_id)
        may = row is not None and self.policy.can_approve(p, row["agent_id"])
        with trace.span("pdp approval decision", COMPONENT, approval_request_id=approval_id, user=p.username,
                        approve=approve) as sp:
            try:
                decided = self.approvals.decide(approval_id, p.sub, p.username, approve, may)
            except ApprovalError as e:
                sp.set(error=str(e))
                return Response(e.status, {"error": str(e)})
        if self.notifier:
            self.notifier.approval_decided(decided)
        return Response(200, decided)

    def _inbox(self, req: Request) -> Response:
        p = self._principal(req.bearer or "")
        if isinstance(p, Response):
            return p
        items = self.notifier.inbox(p.username) if self.notifier else []
        return Response(200, {"notifications": [
            {"id": n["id"], "event": n["event"], "text": n["text"], "approval_id": n["approval_id"],
             "read": n["read_at"] is not None, "webhook": n["webhook_status"]} for n in items]})

    def _mark_read(self, req: Request) -> Response:
        p = self._principal(req.bearer or "")
        if isinstance(p, Response):
            return p
        try:
            ids = req.json().get("ids", [])
        except (ValueError, AttributeError):
            ids = None
        if not isinstance(ids, list) or not all(isinstance(i, int) for i in ids):
            return Response(400, {"error": "ids must be a list of integers"})
        return Response(200, {"marked": self.notifier.mark_read(p.username, ids) if self.notifier else 0})
