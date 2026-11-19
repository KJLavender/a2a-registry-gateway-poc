"""Acceptance tests: discovery, authorization, async tasks, tracing and credential hygiene.

Run: python -m unittest -v                                   (built-in gateway)
     POC_GATEWAY=agentgateway python -m unittest -v          (agentgateway binary)
Where agentgateway behaves differently, the test asserts what it actually does and says why.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from poc import runtime, traceview
from poc.common.a2a import ROLE_USER, text_message
from poc.common.identity import login
from poc.common.web import RpcError, free_port, http
from poc.launcher import Stack, start_stack
from poc.registry import validate_card
from poc.runtime import McpClient
from poc.settings import ROOT, Settings

STACK: Stack
SETTINGS: Settings
_TMP: Path
AGW = Settings(agent_ports={"_": 0}).gateway_impl == "agentgateway"


def setUpModule() -> None:
    global STACK, SETTINGS, _TMP
    _TMP = Path(tempfile.mkdtemp(prefix="a2a-poc-"))
    shutil.copytree(ROOT / "config", _TMP / "config")
    agents = json.loads((_TMP / "config" / "agents.json").read_text(encoding="utf-8"))["agents"]
    SETTINGS = Settings(config_dir=_TMP / "config", var_dir=_TMP / "var",
                        idp_port=free_port(), gateway_port=free_port(), registry_port=free_port(),
                        agent_ports={a["agent_id"]: free_port() for a in agents},
                        speed=0.5, resource_wait_seconds=4)
    STACK = start_stack(SETTINGS)


def tearDownModule() -> None:
    STACK.close()
    shutil.rmtree(_TMP, ignore_errors=True)


def mcp_for(user: str, client: str = "orchestrator-runtime") -> McpClient:
    mcp = McpClient(f"{SETTINGS.gateway_url}/mcp", login(SETTINGS, user, client))
    mcp.initialize()
    return mcp


def read_until_done(mcp: McpClient, uri: str, limit: float = 20) -> dict:
    deadline = time.time() + limit
    while True:
        view = mcp.read_resource(uri)
        if view["terminal"] or view["state"] == "TASK_STATE_INPUT_REQUIRED" or time.time() > deadline:
            return view


class CapabilityDistribution(unittest.TestCase):
    """Only runtimes that need multi-agent delegation get the registry tools."""

    def test_tools_list_depends_on_runtime(self):
        plain = {t["name"] for t in mcp_for("alice", "plain-runtime").list_tools()}
        orchestrator = {t["name"] for t in mcp_for("alice").list_tools()}
        self.assertEqual(plain, {"whoami"})
        self.assertTrue({"search_agents", "invoke_agent", "provide_input", "cancel_task"} <= orchestrator)

    def test_undistributed_tool_cannot_be_called(self):
        plain = mcp_for("alice", "plain-runtime")
        with self.assertRaises(RpcError) as err:
            plain.call_tool("search_agents", {"query": "報表"})
        # builtin: "Unknown tool"; agentgateway: "unknown resource". Both refuse.
        self.assertRegex(err.exception.message.lower(), "unknown (tool|resource)")
        if not AGW:
            self.assertEqual(plain.request("resources/templates/list")["resourceTemplates"], [])


class Discovery(unittest.TestCase):
    def test_search_returns_access_status(self):
        found, _ = mcp_for("alice").call_tool("search_agents", {"query": "幫我分析晨會報表的良率異常"})
        top = found["matches"][0]
        self.assertEqual(top["agent_id"], "report-analyst")
        self.assertEqual(top["access"], "allowed")
        self.assertTrue(top["skills"])

    def test_no_match_differs_from_no_permission(self):
        bob = mcp_for("bob")
        none, _ = bob.call_tool("search_agents", {"query": "明天台北天氣如何"})
        denied, _ = bob.call_tool("search_agents", {"query": "幫我分析晨會報表的良率異常"})
        self.assertEqual(none["result"], "no_matching_agent")
        self.assertEqual(none["matches"], [])
        self.assertEqual(denied["result"], "matches_without_access")
        self.assertEqual(denied["matches"][0]["access"], "denied")

    def test_search_indication_does_not_replace_invocation_check(self):
        alice = mcp_for("alice")
        found, _ = alice.call_tool("search_agents", {"query": "晨會報表"})
        self.assertEqual(found["matches"][0]["access"], "allowed")
        policy_path = SETTINGS.config_dir / "policy.json"
        original = policy_path.read_text(encoding="utf-8")
        try:
            policy = json.loads(original)
            policy["agents"]["report-analyst"]["invoke"] = {"allow_groups": ["nobody"]}
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            # builtin reloads on the next request; agentgateway reloads its regenerated config (~0.4 s)
            time.sleep(1.5 if AGW else 0.05)
            result, is_error = alice.call_tool("invoke_agent", {"agent_id": "report-analyst", "message": "晨會報表"})
            self.assertTrue(is_error)
            self.assertEqual(result["effect"], "deny")
        finally:
            policy_path.write_text(original, encoding="utf-8")
            time.sleep(1.5 if AGW else 0.05)  # let the restored policy take effect before the next test

    def test_hidden_agent_is_never_disclosed(self):
        bob = mcp_for("bob")
        found, _ = bob.call_tool("search_agents", {"query": "調查可疑登入告警 資安鑑識"})
        self.assertNotIn("security-forensics", [m["agent_id"] for m in found["matches"]])
        hidden, e1 = bob.call_tool("invoke_agent", {"agent_id": "security-forensics", "message": "x"})
        missing, e2 = bob.call_tool("invoke_agent", {"agent_id": "no-such-agent", "message": "x"})
        self.assertTrue(e1 and e2)
        self.assertEqual(hidden["error"].replace("security-forensics", "X"), missing["error"].replace("no-such-agent", "X"))
        status, _, _ = http("GET", f"{SETTINGS.gateway_url}/agents/security-forensics/.well-known/agent-card.json",
                            headers={"Authorization": f"Bearer {login(SETTINGS, 'bob', 'orchestrator-runtime')}"})
        # Known gap: agentgateway answers 403 (authorization failed) while an unknown path is 404,
        # so the HTTP status reveals that the hidden agent exists. The registry still hides it.
        self.assertEqual(status, 403 if AGW else 404)
        erin, _ = mcp_for("erin").call_tool("search_agents", {"query": "調查可疑登入告警 資安鑑識"})
        self.assertEqual(erin["matches"][0]["agent_id"], "security-forensics")


class AsyncTasks(unittest.TestCase):
    def test_invoke_returns_immediately_with_durable_reference(self):
        alice = mcp_for("alice")
        started = time.time()
        inv, is_error = alice.call_tool("invoke_agent", {"agent_id": "report-analyst", "message": "分析晨會報表"})
        self.assertFalse(is_error)
        self.assertLess(time.time() - started, 1.0)
        self.assertIn(inv["state"], ("TASK_STATE_SUBMITTED", "TASK_STATE_WORKING"))
        self.assertTrue(inv["resource_uri"].startswith("a2a-task://report-analyst/"))

    def test_reconnect_with_same_task_id(self):
        inv, _ = mcp_for("alice").call_tool("invoke_agent", {"agent_id": "report-analyst", "message": "分析晨會報表"})
        fresh = mcp_for("alice")  # new login, new MCP session
        view = read_until_done(fresh, inv["resource_uri"])
        self.assertEqual(view["state"], "TASK_STATE_COMPLETED")
        self.assertEqual({a["name"] for a in view["artifacts"]}, {"kpi-table", "summary"})

    def test_read_timeout_does_not_cancel_task(self):
        alice = mcp_for("alice")
        inv, _ = alice.call_tool("invoke_agent", {"agent_id": "report-analyst", "message": "分析晨會報表"})
        quick = alice.read_resource(inv["resource_uri"] + "?wait=0.2")
        self.assertFalse(quick["terminal"])
        self.assertEqual(read_until_done(alice, inv["resource_uri"])["state"], "TASK_STATE_COMPLETED")

    def test_input_required_is_not_flattened(self):
        carol = mcp_for("carol")
        inv, _ = carol.call_tool("invoke_agent", {"agent_id": "expense-approver", "message": "申請差旅費報銷"})
        view = read_until_done(carol, inv["resource_uri"])
        self.assertEqual(view["state"], "TASK_STATE_INPUT_REQUIRED")
        self.assertFalse(view["terminal"])
        self.assertIn("金額", view["status_message"])
        carol.call_tool("provide_input", {"task_id": inv["task_id"], "message": "12000 元 差旅"})
        done = read_until_done(carol, inv["resource_uri"])
        self.assertEqual(done["state"], "TASK_STATE_COMPLETED")
        self.assertEqual(done["artifacts"][0]["data"]["amount_twd"], 12000)

    def test_cancel_and_failure_are_distinct_states(self):
        alice = mcp_for("alice")
        inv, _ = alice.call_tool("invoke_agent", {"agent_id": "report-analyst", "message": "分析晨會報表"})
        canceled, _ = alice.call_tool("cancel_task", {"task_id": inv["task_id"]})
        self.assertEqual(canceled["state"], "TASK_STATE_CANCELED")
        again, is_error = alice.call_tool("cancel_task", {"task_id": inv["task_id"]})
        self.assertTrue(is_error)
        self.assertIn("already", again["error"])  # A2A TaskNotCancelableError
        failing, _ = alice.call_tool("invoke_agent", {"agent_id": "report-analyst", "message": "晨會報表 #fail"})
        view = read_until_done(alice, failing["resource_uri"])
        self.assertEqual(view["state"], "TASK_STATE_FAILED")
        self.assertIn("模擬故障", view["status_message"])


class Authorization(unittest.TestCase):
    def test_task_owner_isolation(self):
        inv, _ = mcp_for("alice").call_tool("invoke_agent", {"agent_id": "it-helpdesk", "message": "VPN 連不上"})
        bob = mcp_for("bob")
        with self.assertRaises(RpcError) as err:
            bob.read_resource(inv["resource_uri"])
        self.assertEqual(err.exception.code, -32002)
        _, is_error = bob.call_tool("cancel_task", {"task_id": inv["task_id"]})
        self.assertTrue(is_error)
        status, body, _ = http("POST", f"{SETTINGS.gateway_url}/agents/it-helpdesk/a2a", json_body={
            "jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": inv["task_id"]}}, headers={
            "Authorization": f"Bearer {login(SETTINGS, 'bob', 'orchestrator-runtime')}", "A2A-Version": "1.0"})
        self.assertEqual(body["error"]["code"], -32001)

    def test_delegation_policy_limits_caller_agent(self):
        carol = mcp_for("carol", "report-runtime")
        found, _ = carol.call_tool("search_agents", {"query": "差旅費報銷 12000 元"})
        self.assertEqual(found["matches"][0]["access"], "denied")
        result, is_error = carol.call_tool("invoke_agent", {"agent_id": "expense-approver", "message": "12000 元 差旅"})
        self.assertTrue(is_error)
        self.assertEqual(result["effect"], "deny")
        if not AGW:  # agentgateway's 403 does not say which rule refused the call
            self.assertEqual(result["rule"], "delegation.report-analyst")

    def test_approval_required(self):
        dave = mcp_for("dave")
        found, _ = dave.call_tool("search_agents", {"query": "交通費報銷"})
        self.assertEqual(found["matches"][0]["access"], "approval_required")
        result, is_error = dave.call_tool("invoke_agent", {"agent_id": "expense-approver", "message": "3000 元 交通"})
        self.assertTrue(is_error)
        if AGW:  # CEL rules only allow or deny; there is no approval flow to hand off to
            self.assertEqual(result["effect"], "deny")
        else:
            self.assertEqual(result["effect"], "approval_required")
            self.assertTrue(result["approval_request_id"].startswith("APR-"))

    def test_agent_rejects_user_token(self):
        token = login(SETTINGS, "alice", "orchestrator-runtime")
        status, _, _ = http("POST", f"{SETTINGS.agent_url('it-helpdesk')}/a2a", json_body={
            "jsonrpc": "2.0", "id": 1, "method": "SendMessage",
            "params": {"message": text_message(ROLE_USER, "hi")}},
            headers={"Authorization": f"Bearer {token}", "A2A-Version": "1.0"})
        self.assertEqual(status, 401)

    def test_registry_cannot_mint_agent_tokens(self):
        token = login(SETTINGS, "alice", "orchestrator-runtime")
        status, body, _ = http("POST", SETTINGS.token_endpoint, form={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "client_id": "agent-registry",
            "client_secret": SETTINGS.client_secret("agent-registry"), "subject_token": token,
            "audience": "agent:it-helpdesk"})
        self.assertEqual(status, 400)

    def test_a2a_version_header_required(self):
        status, body, _ = http("POST", f"{SETTINGS.gateway_url}/agents/it-helpdesk/a2a", json_body={
            "jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": text_message(ROLE_USER, "hi")}},
            headers={"Authorization": f"Bearer {login(SETTINGS, 'alice', 'orchestrator-runtime')}"})
        self.assertEqual(body["error"]["code"], -32009)


class Observability(unittest.TestCase):
    def test_end_to_end_trace_and_no_credentials(self):
        out = runtime.ask(SETTINGS, "alice", "幫我分析今天晨會報表的良率異常", say=lambda _: None)
        self.assertEqual(out.status, "completed")
        spans = [s for s in traceview.load(SETTINGS.trace_file) if s["trace_id"] == out.trace_id]
        components = {s["component"] for s in spans}
        expected = {"frontend", "runtime", "agent-registry", "agent:report-analyst"}
        self.assertTrue(expected | ({"agent-gateway"} if not AGW else set()) <= components)
        ids = {s["span_id"] for s in spans}
        orphans = [s for s in spans if s["parent_id"] and s["parent_id"] not in ids]
        if AGW:
            # agentgateway's own spans are not exported to our JSONL; its access log carries the same trace id
            self.assertTrue(all(s["component"].startswith("agent:") for s in orphans))
            gateway_log = (SETTINGS.var_dir / "agentgateway.log").read_text(encoding="utf-8")
            self.assertIn(f"trace.id={out.trace_id}", gateway_log)
            self.assertNotIn("eyJ", gateway_log)
        else:
            self.assertEqual(orphans, [])
        raw = SETTINGS.trace_file.read_text(encoding="utf-8")
        self.assertNotIn("eyJ", raw)  # JWTs start with eyJ
        self.assertNotIn("Bearer", raw)


class Governance(unittest.TestCase):
    def test_invalid_cards_are_rejected(self):
        self.assertIn("missing skills", validate_card({"name": "x", "description": "y"}))
        self.assertEqual(STACK.registry.catalog.rejected, {})
        self.assertEqual(len(STACK.registry.catalog.cards), 4)


if __name__ == "__main__":
    unittest.main()
