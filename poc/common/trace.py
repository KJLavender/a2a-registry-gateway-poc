"""W3C Trace Context propagation with two span exporters.

- var/traces.jsonl, always (read by `python -m poc trace` and the tests)
- OTLP/HTTP (JSON encoding) when an endpoint is configured, e.g. Jaeger from
  observability/docker-compose.yml. Each component becomes its own service.name.
"""
from __future__ import annotations

import json
import logging
import queue
import secrets
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

_local = threading.local()
_write_lock = threading.Lock()
_path: Path | None = None
_otlp: "_OtlpExporter | None" = None
log = logging.getLogger("poc.trace")

# Credentials must never reach telemetry.
_FORBIDDEN_KEYS = ("token", "authorization", "secret", "password", "groups", "roles")


def configure(path: Path, otlp_endpoint: str = "") -> None:
    global _path, _otlp
    path.parent.mkdir(parents=True, exist_ok=True)
    _path = path
    if otlp_endpoint and (_otlp is None or _otlp.url != f"{otlp_endpoint.rstrip('/')}/v1/traces"):
        _otlp = _OtlpExporter(otlp_endpoint)


def flush(timeout: float = 5.0) -> None:
    """Wait until queued spans have been sent to the OTLP endpoint (no-op without one)."""
    if _otlp is not None:
        _otlp.flush(timeout)


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
    if _otlp is not None:
        _otlp.submit(record)


def _otlp_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)}


def to_otlp(records: list[dict[str, Any]]) -> dict[str, Any]:
    """OTLP/HTTP JSON body (ids are hex strings, times are nanosecond strings)."""
    by_service: dict[str, list[dict[str, Any]]] = {}
    for r in records:
        span = {
            "traceId": r["trace_id"], "spanId": r["span_id"], "name": r["name"], "kind": 1,
            "startTimeUnixNano": str(int(r["start"] * 1e9)), "endTimeUnixNano": str(int(r["end"] * 1e9)),
            "attributes": [{"key": k, "value": _otlp_value(v)} for k, v in r["attributes"].items()],
            "status": {"code": 2 if r["status"] == "error" else 1},
        }
        if r["parent_id"]:
            span["parentSpanId"] = r["parent_id"]
        by_service.setdefault(r["component"], []).append(span)
    return {"resourceSpans": [
        {"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": service}}]},
         "scopeSpans": [{"scope": {"name": "a2a-poc"}, "spans": spans}]}
        for service, spans in by_service.items()]}


class _OtlpExporter:
    """Batches spans on a background thread so requests never wait on the collector."""

    def __init__(self, endpoint: str):
        self.url = f"{endpoint.rstrip('/')}/v1/traces"
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=10000)
        threading.Thread(target=self._run, name="otlp-exporter", daemon=True).start()

    def submit(self, record: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            pass  # telemetry must never block or break a request

    def flush(self, timeout: float) -> None:
        deadline = time.time() + timeout
        while self._queue.unfinished_tasks and time.time() < deadline:
            time.sleep(0.05)

    def _run(self) -> None:
        from poc.common.web import http  # late import: web does not depend on trace
        while True:
            batch = [self._queue.get()]
            while len(batch) < 200:
                try:
                    batch.append(self._queue.get(timeout=0.5))
                except queue.Empty:
                    break
            try:
                status, body, _ = http("POST", self.url, json_body=to_otlp(batch), timeout=5)
                if status >= 300:
                    log.warning("OTLP export got HTTP %s: %s", status, body)
            except OSError as e:
                log.warning("OTLP export failed: %s", e)
            for _ in batch:
                self._queue.task_done()
