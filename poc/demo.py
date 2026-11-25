"""Scripted walkthrough of the demo scenarios."""
from __future__ import annotations

import json
from typing import Callable

from poc import runtime, traceview
from poc.common.identity import login
from poc.common.web import http
from poc.runtime import McpClient
from poc.settings import Settings


def _section(title: str) -> None:
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def _show(outcome: runtime.Outcome) -> None:
    if outcome.detail.get("steps"):
        print(f"  Agent 回報的過程：{' → '.join(outcome.detail['steps'])}")
    print(f"  結果：{outcome.status}")
    if outcome.text:
        print(f"  回覆：{outcome.text}")
    for a in outcome.artifacts:
        body = a.get("text") or json.dumps(a.get("data"), ensure_ascii=False)
        print(f"  Artifact《{a['name']}》{body[:160]}")


def run(settings: Settings, only: str | None = None) -> None:
    def scenario(key: str, title: str, fn: Callable[[], None]) -> None:
        if only is None or only == key:
            _section(f"[{key}] {title}")
            fn()

    def distribution() -> None:
        for client in ("plain-runtime", "orchestrator-runtime"):
            mcp = McpClient(f"{settings.gateway_url}/mcp", login(settings, "alice", client))
            mcp.initialize()
            print(f"  {client:<22} tools/list → {[t['name'] for t in mcp.list_tools()]}")

    report_trace: list[str] = []

    def report_ok() -> None:
        out = runtime.ask(settings, "alice", "幫我分析今天晨會報表的良率異常")
        _show(out)
        report_trace.append(out.trace_id)

    def cancel() -> None:
        def cancel_soon(mcp: McpClient, task_id: str) -> None:
            payload, _ = mcp.call_tool("cancel_task", {"task_id": task_id})
            print(f"    ↳ cancel_task → {payload['state']}")
        _show(runtime.ask(settings, "alice", "分析本週稼動率報表", on_task=cancel_soon))

    scenario("1", "能力分發：只有需要 multi-agent 的 Runtime 才拿到 Registry 工具", distribution)
    scenario("2", "alice（分析部）請晨會報表分析 → 非同步 Task、進度、Artifact", report_ok)
    scenario("3", "bob（製造部）問同一件事 → 能力存在但無權限",
             lambda: _show(runtime.ask(settings, "bob", "幫我分析今天晨會報表的良率異常")))
    scenario("4", "bob 問目錄裡沒有的事 → 沒有符合的 Agent",
             lambda: _show(runtime.ask(settings, "bob", "明天台北天氣如何")))
    scenario("5", "carol（財務、有簽核角色）沒寫金額 → INPUT_REQUIRED → provide_input",
             lambda: _show(runtime.ask(settings, "carol", "幫我申請差旅費報銷", answers=["12000 元 差旅"])))
    def approval() -> None:
        first = runtime.ask(settings, "dave", "幫我申請 3000 元交通費報銷")
        _show(first)
        approval_id = first.detail.get("approval_request_id")
        if not approval_id:
            return
        status, inbox, _ = http("GET", f"{settings.pdp_url}/notifications",
                                headers={"Authorization": f"Bearer {login(settings, 'carol', 'orchestrator-runtime')}"})
        for note in (inbox or {}).get("notifications", []) if status == 200 else []:
            if note["approval_id"] == approval_id:
                print(f"  carol 收到通知：{note['text']}")
        for user in ("dave", "carol"):
            status, body, _ = http("POST", f"{settings.pdp_url}/approvals/{approval_id}/approve",
                                   headers={"Authorization": f"Bearer {login(settings, user, 'orchestrator-runtime')}"})
            print(f"  {user} 核准 {approval_id} → HTTP {status} {body.get('error') or body.get('status')}")
        print("  dave 再試一次：")
        _show(runtime.ask(settings, "dave", "幫我申請 3000 元交通費報銷"))
        print("  dave 第三次（核准只能用一次）：")
        _show(runtime.ask(settings, "dave", "幫我申請 3000 元交通費報銷"))

    scenario("6", "dave（財務、無簽核角色）→ 需要核准 → carol 核准 → 放行一次", approval)
    scenario("7", "資安鑑識 Agent 是隱藏的：bob 完全看不到，erin（SecOps）可以用",
             lambda: (_show(runtime.ask(settings, "bob", "調查昨晚的可疑登入告警")),
                      _show(runtime.ask(settings, "erin", "調查昨晚的可疑登入告警"))))
    scenario("8", "委派政策：報表 Agent 的 Runtime 不可委派給費用簽核 Agent",
             lambda: _show(runtime.ask(settings, "carol", "幫我申請 12000 元差旅費報銷", client="report-runtime")))
    scenario("9", "取消：明確的 cancel_task（Resource 讀取逾時不會取消 Task）", cancel)
    scenario("10", "失敗：Agent 端出錯會成為 FAILED，不會被壓扁成一般文字",
             lambda: _show(runtime.ask(settings, "alice", "分析晨會報表 #fail")))

    def sdk_agent() -> None:
        try:
            import a2a  # noqa: F401  (the hr-leave agent runs only when the SDK is installed)
        except ImportError:
            print("  需要選用套件：pip install -r requirements-extras.txt")
            return
        _show(runtime.ask(settings, "bob", "下禮拜想休息兩天", answers=["12/3-12/4"]))

    scenario("11", "官方 A2A SDK 寫的 Agent（人資請假）一樣被找到、被管控；這句話跟 Agent Card 沒有共同關鍵字",
             sdk_agent)
    scenario("12", "Agent 請教 Agent：報表 Agent 經過 Gateway 請 IT 服務台協助（委派鏈記在 Transaction Token，限層數、禁循環）",
             lambda: _show(runtime.ask(settings, "alice", "幫我分析今天晨會報表的良率異常（我的報表帳號被鎖了）")))

    if report_trace:
        _section("情境 2 的端到端 Trace（Frontend → Runtime → Gateway → Registry → Gateway → Agent）")
        print(traceview.render(traceview.load(settings.trace_file), report_trace[0]))
