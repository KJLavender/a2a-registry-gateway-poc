"""Optional LLM backend via the local Claude Code CLI (uses the Claude subscription, no API key).

Disabled by default so the PoC stays deterministic. Enable with POC_LLM=claude;
pick the model with POC_LLM_MODEL (default: sonnet).
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Any

log = logging.getLogger("poc.llm")


def enabled() -> bool:
    return os.environ.get("POC_LLM", "").lower() == "claude"


def complete(system: str, prompt: str, schema: dict[str, Any] | None = None, timeout: float = 180) -> Any:
    exe = shutil.which("claude")
    if exe is None:
        raise RuntimeError("claude CLI not found on PATH")
    cmd = [exe, "-p", "--output-format", "json", "--model", os.environ.get("POC_LLM_MODEL", "sonnet"),
           "--effort", "medium", "--system-prompt", system, "--tools", "", "--setting-sources", "",
           "--no-session-persistence"]
    if schema is not None:
        cmd += ["--json-schema", json.dumps(schema)]
    proc = subprocess.run(cmd, input=prompt, text=True, encoding="utf-8", capture_output=True, timeout=timeout)
    out = json.loads(proc.stdout or "{}")
    if proc.returncode != 0 or out.get("is_error"):
        raise RuntimeError(f"claude CLI failed: {out.get('result') or proc.stderr.strip()}")
    return out.get("structured_output") if schema is not None else out.get("result", "")


def generate(system: str, prompt: str, fallback: str) -> str:
    """LLM text when enabled, otherwise (or on any failure) the deterministic fallback."""
    if not enabled():
        return fallback
    try:
        return str(complete(system, prompt)).strip() or fallback
    except Exception as e:
        log.warning("LLM call failed, using fallback: %s", e)
        return fallback
