"""Approval notifications: an outbox next to the approvals, delivered by a background worker.

Events
  approval.requested   to every user who may decide the request (the agent's `approvers` rule in
                       policy.json, never the requester)
  approval.decided     to the requester

Every notification lands in the recipient's inbox (GET /notifications on the PDP, or
`python -m poc inbox --as carol`). With POC_APPROVAL_WEBHOOK set, each one is also POSTed there as JSON
with a `text` field, which is what Slack and Mattermost incoming webhooks accept. A failed post is
retried with backoff, so a chat outage delays a notification instead of losing it.

Recipients are looked up in config/users.json; a real deployment would ask the directory (LDAP, SCIM).
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from poc.approvals import APPROVAL_TTL
from poc.common.identity import Principal
from poc.common.web import http
from poc.policy import PolicyStore
from poc.settings import Settings

log = logging.getLogger("poc.notify")
MAX_ATTEMPTS = 5
_COLUMNS = ("id", "event", "recipient", "approval_id", "text", "payload", "created_at", "read_at",
            "webhook_status", "attempts", "last_error")


class Notifier:
    def __init__(self, settings: Settings, policy: PolicyStore, path: Path):
        self.settings = settings
        self.policy = policy
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, timeout=10)  # shares approvals.db
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.execute("""CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY, event TEXT, recipient TEXT, approval_id TEXT, text TEXT, payload TEXT,
                created_at REAL, read_at REAL, webhook_status TEXT, attempts INTEGER DEFAULT 0,
                next_attempt REAL DEFAULT 0, last_error TEXT,
                UNIQUE (event, approval_id, recipient))""")

    # --- events --------------------------------------------------------------------

    # Both are called from the authorization path: a notification problem is logged, never raised,
    # so the caller still gets its "approval required" answer or its decision.

    def approval_requested(self, row: dict[str, Any]) -> None:
        try:
            for username in self._approvers(row["agent_id"], exclude=row["requester_name"]):
                self._enqueue("approval.requested", username, row,
                              f"{row['requester_name']} 申請使用 {row['agent_id']}（{row['id']}）。"
                              f"核准：python -m poc approve {row['id']} --as {username}")
        except Exception:
            log.exception("could not queue approval.requested for %s", row.get("id"))

    def approval_decided(self, row: dict[str, Any]) -> None:
        try:
            if row["status"] == "approved":
                text = (f"你對 {row['agent_id']} 的申請 {row['id']} 已由 {row['decided_by']} 核准，"
                        f"{APPROVAL_TTL // 60} 分鐘內可以使用一次。")
            else:
                text = f"你對 {row['agent_id']} 的申請 {row['id']} 被 {row['decided_by']} 拒絕。"
            self._enqueue("approval.decided", row["requester_name"], row, text)
        except Exception:
            log.exception("could not queue approval.decided for %s", row.get("id"))

    def _approvers(self, agent_id: str, exclude: str) -> list[str]:
        users = self.settings.load("users.json")["users"]
        return [name for name, u in users.items() if name != exclude and self.policy.can_approve(
            Principal(name, name, u.get("name", name), tuple(u.get("groups", [])), tuple(u.get("roles", [])), ()),
            agent_id)]

    def _enqueue(self, event: str, recipient: str, row: dict[str, Any], text: str) -> None:
        payload = {"text": text, "event": event, "recipient": recipient, "approval_id": row["id"],
                   "agent_id": row["agent_id"], "requester": row["requester_name"], "status": row["status"]}
        status = "pending" if self.settings.approval_webhook else "skipped"
        with self._lock, self._db:  # the unique key makes a repeated event a no-op
            self._db.execute(
                "INSERT OR IGNORE INTO notifications (event, recipient, approval_id, text, payload, created_at, "
                "webhook_status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event, recipient, row["id"], text, json.dumps(payload, ensure_ascii=False), time.time(), status))

    # --- inbox ---------------------------------------------------------------------

    def inbox(self, username: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(f"SELECT {', '.join(_COLUMNS)} FROM notifications WHERE recipient = ? "
                                    "ORDER BY id", (username,)).fetchall()
        out = []
        for r in rows:
            item = dict(zip(_COLUMNS, r))
            item["payload"] = json.loads(item["payload"])
            out.append(item)
        return out

    def mark_read(self, username: str, ids: list[int]) -> int:
        with self._lock, self._db:
            return self._db.executemany(
                "UPDATE notifications SET read_at = ? WHERE id = ? AND recipient = ? AND read_at IS NULL",
                [(time.time(), int(i), username) for i in ids]).rowcount

    # --- webhook delivery ------------------------------------------------------------

    def run(self, stop: threading.Event, interval: float = 0.5) -> None:
        while not stop.wait(interval):
            try:
                self.deliver_due()
            except Exception:  # keep the worker alive whatever one delivery does
                log.exception("notification delivery failed")

    def deliver_due(self) -> None:
        if not self.settings.approval_webhook:
            return
        with self._lock:
            due = self._db.execute("SELECT id, payload, attempts FROM notifications WHERE webhook_status = 'pending' "
                                   "AND next_attempt <= ? ORDER BY id LIMIT 20", (time.time(),)).fetchall()
        for nid, payload, attempts in due:
            try:
                status, body, _ = http("POST", self.settings.approval_webhook, json_body=json.loads(payload), timeout=5)
                error = None if 200 <= status < 300 else f"HTTP {status}"
            except OSError as e:
                error = str(e)
            attempts += 1
            if error is None:
                new_status = "sent"
            else:
                new_status = "failed" if attempts >= MAX_ATTEMPTS else "pending"
                log.warning("approval webhook attempt %d for notification %d failed: %s", attempts, nid, error)
            with self._lock, self._db:
                self._db.execute("UPDATE notifications SET webhook_status = ?, attempts = ?, next_attempt = ?, "
                                 "last_error = ? WHERE id = ?",
                                 (new_status, attempts, time.time() + 2 ** (attempts - 1), error, nid))
