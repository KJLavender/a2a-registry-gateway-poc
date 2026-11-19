"""W3C Trace Context propagation with a JSONL span exporter.

Spans are written to var/traces.jsonl. The shape mirrors OpenTelemetry
(trace_id/span_id/parent_id/attributes) so an OTLP exporter can replace it later.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

_local = threading.local()
_write_lock = threading.Lock()
_path: Path | None = None

# Credentials must never reach telemetry.
_FORBIDDEN_KEYS = ("token", "authorization", "secret", "password", "groups", "roles")


def configure(path: Path) -> None:
    global _path
    path.parent.mkdir(parents=True, exist_ok=True)
    _path = path


def parse_traceparent(value: str | None) -> tuple[str | None, str | None]:
    parts = (value or "").split("-")
    if len(parts) == 4 and len(parts[1]) == 32 and len(parts[2]) == 16:
        return parts[1], parts[2]
    return None, None


class Span:
    def __init__(self, name: str, component: str, trace_id: str, parent_id: str | None, attrs: dict[str, Any]):
        self.name = name
        self.component = component
        self.trace_id = trace_id
        self.span_id = secrets.token_hex(8)
        self.parent_id = parent_id
        self.attrs: dict[str, Any] = {}
        self.status = "ok"
        self.start = time.time()
        self.set(**attrs)

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-01"

    def set(self, **attrs: Any) -> None:
        for key, value in attrs.items():
            if value is None or any(f in key.lower() for f in _FORBIDDEN_KEYS):
                continue
            self.attrs[key] = value


def current() -> Span | None:
    return getattr(_local, "span", None)


@contextmanager
def span(name: str, component: str, traceparent: str | None = None, **attrs: Any) -> Iterator[Span]:
    """Start a span. An explicit traceparent wins; otherwise the thread's current span is the parent."""
    parent = current()
    trace_id, parent_id = parse_traceparent(traceparent)
    if trace_id is None and parent is not None:
        trace_id, parent_id = parent.trace_id, parent.span_id
    s = Span(name, component, trace_id or secrets.token_hex(16), parent_id, attrs)
    _local.span = s
    try:
        yield s
    except Exception as e:
        s.status = "error"
        s.set(error=f"{type(e).__name__}: {e}")
        raise
    finally:
        _local.span = parent
        _export(s, time.time())


def _export(s: Span, end: float) -> None:
    if _path is None:
        return
    record = {
        "trace_id": s.trace_id, "span_id": s.span_id, "parent_id": s.parent_id,
        "name": s.name, "component": s.component, "status": s.status,
        "start": s.start, "end": end, "attributes": s.attrs,
    }
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with _write_lock, open(_path, "a", encoding="utf-8") as f:
        f.write(line)
