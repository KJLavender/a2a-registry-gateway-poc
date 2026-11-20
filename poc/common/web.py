"""Tiny HTTP server/client and JSON-RPC helpers built on the standard library."""
from __future__ import annotations

import json
import logging
import socket
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import parse_qsl, urlencode, urlsplit

log = logging.getLogger("poc.web")

# Local services only: never route through HTTP(S)_PROXY.
_opener = urlrequest.build_opener(urlrequest.ProxyHandler({}))


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]  # lower-cased names
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8")) if self.body else {}

    def form(self) -> dict[str, str]:
        return dict(parse_qsl(self.body.decode("utf-8")))

    @property
    def bearer(self) -> str | None:
        auth = self.headers.get("authorization", "")
        return auth[7:].strip() if auth[:7].lower() == "bearer " else None


@dataclass
class Response:
    status: int = 200
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)


App = Callable[[Request], Response]


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        # Proxies close idle keep-alive connections; that is not an error worth a traceback.
        import sys
        if isinstance(sys.exc_info()[1], (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)):
            return
        super().handle_error(request, client_address)


def serve(app: App, host: str, port: int) -> ThreadingHTTPServer:
    """Start `app` on a background thread and return the bound server."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            parts = urlsplit(self.path)
            req = Request(self.command, parts.path, dict(parse_qsl(parts.query)),
                          {k.lower(): v for k, v in self.headers.items()}, body)
            try:
                resp = app(req)
            except Exception:
                log.error("unhandled error on %s %s\n%s", req.method, req.path, traceback.format_exc())
                resp = Response(500, {"error": "internal server error"})
            if resp.body is None:
                data = b""
            elif isinstance(resp.body, bytes):
                data = resp.body
            elif isinstance(resp.body, str):
                data = resp.body.encode("utf-8")
                resp.headers.setdefault("Content-Type", "text/plain; charset=utf-8")
            else:
                data = json.dumps(resp.body, ensure_ascii=False).encode("utf-8")
                resp.headers.setdefault("Content-Type", "application/json; charset=utf-8")
            self.send_response(resp.status)
            for name, value in resp.headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if data:
                self.wfile.write(data)

        do_GET = do_POST = do_DELETE = _dispatch

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            pass

    server = _QuietServer((host, port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name=f"http-{port}", daemon=True).start()
    return server


def free_port(host: str = "127.0.0.1") -> int:
    with socket.socket() as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def http(method: str, url: str, *, json_body: Any = None, form: dict[str, str] | None = None,
         headers: dict[str, str] | None = None, timeout: float = 30.0) -> tuple[int, Any, dict[str, str]]:
    """Send a request; returns (status, decoded body, lower-cased headers). Never raises on HTTP errors."""
    data = None
    hdrs = dict(headers or {})
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    elif form is not None:
        data = urlencode(form).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urlrequest.Request(url, data=data, method=method, headers=hdrs)
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status, _decode(resp.read()), {k.lower(): v for k, v in resp.headers.items()}
    except urlerror.HTTPError as e:
        return e.code, _decode(e.read()), {k.lower(): v for k, v in e.headers.items()}


def _decode(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        return raw.decode("utf-8", "replace")


class RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None, http_status: int = 200):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
        self.http_status = http_status

    def to_dict(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            err["data"] = self.data
        return err


def rpc_response(rid: Any, result: Any = None, error: RpcError | None = None) -> dict[str, Any]:
    if error is not None:
        return {"jsonrpc": "2.0", "id": rid, "error": error.to_dict()}
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def rpc_call(url: str, method: str, params: dict[str, Any], *, headers: dict[str, str] | None = None,
             timeout: float = 30.0) -> Any:
    payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}
    status, body, _ = http("POST", url, json_body=payload, headers=headers, timeout=timeout)
    if isinstance(body, dict) and isinstance(body.get("error"), dict):  # a JSON-RPC error, not a plain HTTP one
        e = body["error"]
        raise RpcError(e.get("code", -32603), e.get("message", ""), e.get("data"), http_status=status)
    if status != 200 or not isinstance(body, dict) or "result" not in body:
        raise RpcError(-32603, f"unexpected HTTP {status} from {url}", {"body": body}, http_status=status)
    return body["result"]
