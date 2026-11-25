"""Four demo expert agents owned by different (fictional) teams. All data is simulated."""
from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from poc import llm
from poc.agents.base import A2AAgent, Consult, TaskContext
from poc.common.a2a import message_text
from poc.common.web import RpcError
from poc.common.identity import Verifier


def _card(name: str, description: str, skills: list[dict[str, Any]], owner: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "version": "1.0.0",
        "provider": {"organization": owner, "url": "https://example.com"},
        "capabilities": {"streaming": False, "pushNotifications": False},
        "securitySchemes": {"gateway": {"httpAuthSecurityScheme": {
            "scheme": "Bearer", "bearerFormat": "JWT",
            "description": "Call through the Agent Gateway; tokens must be exchanged for audience agent:<id>."}}},
        "securityRequirements": [{"schemes": {"gateway": {"list": []}}}],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": skills,
    }


def _seed(text: str) -> int:
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)


# --- IT helpdesk ---------------------------------------------------------------

IT_CARD = _card(
    "IT 服務台 Agent",
    "處理員工常見 IT 問題：帳號解鎖、密碼重設、MFA、VPN 連線。IT helpdesk for accounts, passwords, MFA and VPN.",
    [
        {"id": "account-unlock", "name": "帳號解鎖與密碼重設",
         "description": "AD 帳號被鎖、忘記密碼、MFA 裝置更換。Account unlock, password reset, MFA device change.",
         "tags": ["IT", "帳號", "密碼", "MFA", "AD", "account", "password", "login"],
         "examples": ["我的 AD 帳號被鎖住了", "How do I reset my password?"]},
        {"id": "vpn", "name": "VPN 連線排除",
         "description": "在家或出差時 VPN 連不上、憑證過期。VPN troubleshooting for remote work.",
         "tags": ["VPN", "網路", "遠端", "network", "remote"],
         "examples": ["在家連不上 VPN"]},
    ],
    "IT Service Desk",
)


def it_helpdesk(ctx: TaskContext) -> str:
    ctx.progress("查詢 IT 知識庫")
    ctx.sleep(1.0)
    text = ctx.text.lower()
    if "vpn" in text:
        answer = "VPN 排除步驟：1) 確認網路可上外網 2) 重新開啟 VPN client 並重新登入 3) 憑證過期請到自助入口重新申請。仍無法連線請回覆錯誤碼。"
    elif any(k in text for k in ("密碼", "鎖", "password", "mfa", "帳號")):
        answer = "帳號處理：請到自助密碼入口驗證 MFA 後重設密碼；帳號被鎖會在 15 分鐘後自動解鎖，急件可撥分機 1234。"
    else:
        ticket = f"IT-{_seed(ctx.text) % 100000:05d}"
        answer = f"已建立 IT 服務單 {ticket}（模擬），服務台會在 4 小時內聯絡你。"
    return llm.generate("你是公司 IT 服務台，用繁體中文、三句以內回答。", ctx.text, answer)


# --- Morning-report analyst -----------------------------------------------------

REPORT_CARD = _card(
    "晨會報表分析 Agent",
    "分析每日晨會報表與產線 KPI（良率、稼動率），找出異常並整理摘要。Analyzes daily KPI reports: yield, OEE, anomalies.",
    [
        {"id": "kpi-analysis", "name": "晨會報表與 KPI 異常分析",
         "description": "讀取晨會報表，計算各產線良率與稼動率，標出異常與可能原因。Daily report KPI anomaly analysis.",
         "tags": ["報表", "晨會", "KPI", "良率", "稼動率", "異常", "report", "yield", "OEE", "analysis"],
         "examples": ["幫我分析今天晨會報表的良率異常", "Summarize yesterday's OEE drop"]},
    ],
    "Analytics",
)


def report_analyst(ctx: TaskContext) -> str:
    if "#fail" in ctx.text:
        ctx.progress("連線報表資料庫")
        ctx.sleep(0.5)
        raise RuntimeError("報表資料庫連線逾時（模擬故障）")
    if any(k in ctx.text for k in ("帳號被鎖", "登不進")):
        # Agents asking agents: the report system needs the user's account, so ask the IT helpdesk first.
        ctx.progress("報表系統要求重新登入，先請 IT 服務台協助")
        try:
            helpdesk = ctx.consult("it-helpdesk", "使用者的報表系統 AD 帳號被鎖住了，請說明怎麼解鎖。")
            note = message_text(helpdesk["status"].get("message")) or helpdesk["status"]["state"]
        except (RpcError, OSError, RuntimeError) as e:  # refused by policy, or the helpdesk is down
            note = f"IT 服務台這次沒有回覆：{getattr(e, 'message', e)}"
        ctx.artifact("it-helpdesk", text=note, description="請教 IT 服務台的結果")
    for label, seconds in (("讀取晨會報表資料 (1/3)", 1.5), ("計算 KPI 與異常偵測 (2/3)", 1.5), ("整理分析摘要 (3/3)", 1.0)):
        ctx.progress(label)
        ctx.sleep(seconds)
    seed = _seed(ctx.text)
    rows = []
    for i, line in enumerate(("L1", "L2", "L3", "L4")):
        y = 93.0 + ((seed >> (i * 4)) % 60) / 10  # 93.0 - 98.9
        oee = 72.0 + ((seed >> (i * 5 + 2)) % 180) / 10  # 72.0 - 89.9
        rows.append({"line": line, "yield_pct": round(y, 1), "oee_pct": round(oee, 1)})
    anomalies = [r for r in rows if r["yield_pct"] < 95.0 or r["oee_pct"] < 75.0]
    if anomalies:
        detail = "、".join(f"{r['line']}（良率 {r['yield_pct']}%、稼動率 {r['oee_pct']}%）" for r in anomalies)
        summary = f"發現 {len(anomalies)} 條產線異常：{detail}。建議先檢查換線紀錄與機台停機原因。"
    else:
        summary = "四條產線良率與稼動率都在目標內，沒有異常。"
    ctx.artifact("kpi-table", data={"rows": rows, "anomalies": [r["line"] for r in anomalies], "simulated": True},
                 description="各產線 KPI（模擬資料）")
    summary = llm.generate("你是製造業數據分析師，用繁體中文寫兩三句摘要，只能根據提供的數據。",
                           f"需求：{ctx.text}\n數據：{rows}", summary)
    ctx.artifact("summary", text=summary, description="分析摘要")
    return summary


# --- Expense approver (has side effects, may need more input) -------------------

EXPENSE_CARD = _card(
    "費用簽核 Agent",
    "建立費用申請並依金額決定簽核路徑。Creates expense requests and routes them for approval.",
    [
        {"id": "expense-approval", "name": "費用申請與簽核",
         "description": "差旅、交通、餐費、設備等費用報銷申請，檢查預算並送出簽核。Expense reimbursement and approval routing.",
         "tags": ["費用", "報銷", "簽核", "預算", "差旅", "expense", "reimbursement", "approval"],
         "examples": ["幫我申請 12000 元差旅費報銷", "Submit an expense claim"]},
    ],
    "Finance",
)

_AMOUNT = re.compile(r"(?:NT\$|\$|新台幣)\s*([\d,]+)|([\d,]+)\s*(?:元|塊|TWD|NTD)", re.IGNORECASE)
_CATEGORIES = ("差旅", "交通", "住宿", "餐費", "設備", "訓練")


def _parse_amount(text: str, allow_bare: bool = False) -> int | None:
    m = _AMOUNT.search(text)
    raw = (m.group(1) or m.group(2)) if m else None
    if raw is None and allow_bare:
        bare = re.search(r"\d[\d,]*", text)
        raw = bare.group(0) if bare else None
    return int(raw.replace(",", "")) if raw else None


def expense_approver(ctx: TaskContext) -> str:
    ctx.progress("檢查費用申請內容")
    text = ctx.text
    amount = _parse_amount(text)
    if amount is None:
        reply = ctx.ask("請提供申請金額（新台幣）與費用類別，例如：12000 元 差旅")
        text = f"{text} {reply}"
        amount = _parse_amount(reply, allow_bare=True)
        if amount is None:
            raise ValueError("仍然缺少申請金額")
    category = next((c for c in _CATEGORIES if c in text), "其他")
    ctx.progress("檢查預算與簽核規則")
    ctx.sleep(1.0)
    route = ["部門主管"] if amount <= 50000 else ["部門主管", "事業處主管"]
    request_id = f"EXP-{_seed(f'{ctx.user}{amount}{category}') % 1000000:06d}"
    ctx.artifact("expense-request", description="費用申請單（模擬，未寫入正式系統）", data={
        "request_id": request_id, "applicant": ctx.user, "amount_twd": amount,
        "category": category, "approval_route": route, "simulated": True})
    return f"已建立費用申請 {request_id}（模擬）：{category} NT${amount:,}，簽核路徑：{' → '.join(route)}。"


# --- Security forensics (hidden from non-SecOps users) --------------------------

SECURITY_CARD = _card(
    "資安鑑識 Agent",
    "分析可疑登入、端點告警與入侵指標 (IOC)。Investigates suspicious logins, endpoint alerts and IOCs.",
    [
        {"id": "incident-forensics", "name": "資安事件鑑識",
         "description": "針對可疑登入與端點告警做時間軸重建與 IOC 比對。Incident timeline reconstruction and IOC matching.",
         "tags": ["資安", "鑑識", "入侵", "可疑登入", "告警", "IOC", "security", "forensics", "incident"],
         "examples": ["調查昨晚的可疑登入告警"]},
    ],
    "SecOps",
)


def security_forensics(ctx: TaskContext) -> str:
    ctx.progress("收集登入紀錄與端點告警")
    ctx.sleep(1.5)
    ctx.artifact("ioc-matches", data={"matched_iocs": [], "hosts_reviewed": 12, "simulated": True},
                 description="IOC 比對結果（模擬）")
    return "已檢查 12 台主機的登入紀錄（模擬），未比對到已知 IOC；建議對異地登入帳號強制重設密碼。"


AGENTS = {
    "it-helpdesk": (IT_CARD, it_helpdesk),
    "report-analyst": (REPORT_CARD, report_analyst),
    "expense-approver": (EXPENSE_CARD, expense_approver),
    "security-forensics": (SECURITY_CARD, security_forensics),
}


def build_agents(verify: Verifier, speed: float, verify_txn: Callable[[str], dict[str, Any]] | None = None,
                 consult: Consult | None = None) -> list[A2AAgent]:
    return [A2AAgent(agent_id, card, handler, verify, speed, verify_txn, consult=consult)
            for agent_id, (card, handler) in AGENTS.items()]
