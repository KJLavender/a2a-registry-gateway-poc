"""Scripted walkthrough of the demo scenarios."""
from __future__ import annotations

import json
from typing import Callable

from poc import runtime, traceview
from poc.common.identity import login
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
    scenario("6", "dave（財務、無簽核角色）→ 需要額外核准",
             lambda: _show(runtime.ask(settings, "dave", "幫我申請 3000 元交通費報銷")))
    scenario("7", "資安鑑識 Agent 是隱藏的：bob 完全看不到，erin（SecOps）可以用",
             lambda: (_show(runtime.ask(settings, "bob", "調查昨晚的可疑登入告警")),
                      _show(runtime.ask(settings, "erin", "調查昨晚的可疑登入告警"))))
    scenario("8", "委派政策：報表 Agent 的 Runtime 不可委派給費用簽核 Agent",
             lambda: _show(runtime.ask(settings, "carol", "幫我申請 12000 元差旅費報銷", client="report-runtime")))
    scenario("9", "取消：明確的 cancel_task（Resource 讀取逾時不會取消 Task）", cancel)
    scenario("10", "失敗：Agent 端出錯會成為 FAILED，不會被壓扁成一般文字",
             lambda: _show(runtime.ask(settings, "alice", "分析晨會報表 #fail")))

    if report_trace:
        _section("情境 2 的端到端 Trace（Frontend → Runtime → Gateway → Registry → Gateway → Agent）")
        print(traceview.render(traceview.load(settings.trace_file), report_trace[0]))
