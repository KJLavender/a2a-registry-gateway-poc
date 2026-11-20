"""Approval requests for agents whose policy says "approval_required".

Flow: a requester's invocation is refused with an approval request id; an approver (per the agent's
`approvers` rule in policy.json, never the requester) approves it; the requester's next invocation of
that agent is allowed once, within APPROVAL_TTL.
"""
from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

APPROVAL_TTL = 3600
_COLUMNS = ("id", "requester_sub", "requester_name", "agent_id", "status", "created_at",
            "decided_by", "decided_at", "consumed_at")


class ApprovalError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class ApprovalStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.execute("""CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY, requester_sub TEXT, requester_name TEXT, agent_id TEXT, status TEXT,
                created_at REAL, decided_by TEXT, decided_at REAL, consumed_at REAL)""")
            # At most one pending request per requester and agent, even across processes/connections
            self._db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS one_pending ON approvals (requester_sub, agent_id)
                WHERE status = 'pending'""")

    def _rows(self, where: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(f"SELECT {', '.join(_COLUMNS)} FROM approvals WHERE {where} "
                                    "ORDER BY created_at", args).fetchall()
        return [dict(zip(_COLUMNS, r)) for r in rows]

    def get(self, approval_id: str) -> dict[str, Any] | None:
        rows = self._rows("id = ?", (approval_id,))
        return rows[0] if rows else None

    def open_or_get(self, requester_sub: str, requester_name: str, agent_id: str) -> dict[str, Any]:
        with self._lock, self._db:
            self._db.execute("INSERT OR IGNORE INTO approvals "
                             "(id, requester_sub, requester_name, agent_id, status, created_at) "
                             "VALUES (?, ?, ?, ?, 'pending', ?)",
                             (f"APR-{secrets.token_hex(3).upper()}", requester_sub, requester_name, agent_id,
                              time.time()))
        return self._rows("requester_sub = ? AND agent_id = ? AND status = 'pending'", (requester_sub, agent_id))[0]

    def take_grant(self, requester_sub: str, agent_id: str) -> dict[str, Any] | None:
        """Consume one unexpired approval for this requester and agent, if there is one."""
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT id, decided_by FROM approvals WHERE requester_sub = ? AND agent_id = ? "
                "AND status = 'approved' AND decided_at > ? ORDER BY decided_at LIMIT 1",
                (requester_sub, agent_id, time.time() - APPROVAL_TTL)).fetchone()
            if row is None:
                return None
            used = self._db.execute("UPDATE approvals SET status = 'consumed', consumed_at = ? "
                                    "WHERE id = ? AND status = 'approved'", (time.time(), row[0])).rowcount
        return {"id": row[0], "decided_by": row[1]} if used else None

    def restore(self, approval_id: str) -> None:
        """Give an approval back when the call it was used for never reached the agent."""
        with self._lock, self._db:
            self._db.execute("UPDATE approvals SET status = 'approved', consumed_at = NULL "
                             "WHERE id = ? AND status = 'consumed'", (approval_id,))

    def restore_recent(self, requester_sub: str, agent_id: str, within: float = 60) -> None:
        """Restore the approval this requester used on this agent in the last `within` seconds, if any."""
        rows = self._rows("requester_sub = ? AND agent_id = ? AND status = 'consumed' AND consumed_at > ?",
                          (requester_sub, agent_id, time.time() - within))
        if rows:
            self.restore(rows[-1]["id"])

    def has_grant(self, requester_sub: str, agent_id: str) -> bool:
        return bool(self._rows("requester_sub = ? AND agent_id = ? AND status = 'approved' AND decided_at > ?",
                               (requester_sub, agent_id, time.time() - APPROVAL_TTL)))

    def decide(self, approval_id: str, approver_sub: str, approver_name: str, approve: bool,
               may_approve: bool) -> dict[str, Any]:
        row = self.get(approval_id)
        if row is None or not may_approve:
            raise ApprovalError(404 if row is None else 403, "approval request not found or not yours to decide")
        if row["requester_sub"] == approver_sub:
            raise ApprovalError(403, "requesters cannot approve their own request")
        with self._lock, self._db:  # the status guard makes the decision atomic across connections
            changed = self._db.execute(
                "UPDATE approvals SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'",
                ("approved" if approve else "rejected", approver_name, time.time(), approval_id)).rowcount
        if not changed:
            raise ApprovalError(409, f"approval request is already {(self.get(approval_id) or {}).get('status')}")
        return self.get(approval_id) or {}

    def pending(self) -> list[dict[str, Any]]:
        return self._rows("status = 'pending'", ())
