"""Runtime settings shared by every component (ports, URLs, secrets, paths)."""
from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
# Release asset name of the agentgateway binary for this machine (see README for the download command)
_AGENTGATEWAY_ASSET = {
    ("Windows", "AMD64"): "agentgateway-windows-amd64.exe",
    ("Linux", "x86_64"): "agentgateway-linux-amd64",
    ("Linux", "aarch64"): "agentgateway-linux-arm64",
    ("Darwin", "arm64"): "agentgateway-darwin-arm64",
}.get((platform.system(), platform.machine()), "agentgateway")


@dataclass
class Settings:
    config_dir: Path = ROOT / "config"
    var_dir: Path = ROOT / "var"
    host: str = "127.0.0.1"
    # "mock" = poc/idp.py; "keycloak" = Keycloak from keycloak/docker-compose.yml
    idp_impl: str = field(default_factory=lambda: os.environ.get("POC_IDP", "mock"))
    idp_port: int = 0  # 0 = default for idp_impl (mock 18300, keycloak 18080)
    gateway_port: int = 18000
    registry_port: int = 18200
    pdp_port: int = 18400
    txn_port: int = 18500
    agent_ports: dict[str, int] = field(default_factory=dict)
    # "builtin" = poc/gateway.py; "agentgateway" = the agentgateway binary configured from policy.json
    gateway_impl: str = field(default_factory=lambda: os.environ.get("POC_GATEWAY", "builtin"))
    agentgateway_bin: Path = field(default_factory=lambda: Path(os.environ.get(
        "POC_AGENTGATEWAY_BIN", ROOT / "bin" / _AGENTGATEWAY_ASSET)))
    # Multiplier for simulated agent work time (tests use a smaller value).
    speed: float = field(default_factory=lambda: float(os.environ.get("POC_SPEED", "1.0")))
    # OTLP/HTTP endpoint for traces (e.g. Jaeger at http://127.0.0.1:4318); empty = JSONL file only
    otlp_endpoint: str = field(default_factory=lambda: os.environ.get("POC_OTLP_ENDPOINT", ""))
    # Where approval notifications are POSTed (Slack/Mattermost incoming webhook); empty = inbox only
    approval_webhook: str = field(default_factory=lambda: os.environ.get("POC_APPROVAL_WEBHOOK", ""))
    # Upper bound for one blocking Task Resource read; must stay below MCP client timeouts.
    resource_wait_seconds: float = field(default_factory=lambda: float(os.environ.get("POC_RESOURCE_WAIT", "20")))

    def __post_init__(self) -> None:
        if not self.idp_port:
            self.idp_port = 18080 if self.idp_impl == "keycloak" else 18300
        if not self.agent_ports:
            self.agent_ports = {a["agent_id"]: a["port"] for a in self.load("agents.json")["agents"]}

    def load(self, name: str) -> Any:
        return json.loads((self.config_dir / name).read_text(encoding="utf-8"))

    def url(self, port: int) -> str:
        return f"http://{self.host}:{port}"

    @property
    def idp_url(self) -> str:
        return self.url(self.idp_port)

    @property
    def issuer(self) -> str:
        return f"{self.idp_url}/realms/poc"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/token"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"

    @property
    def gateway_url(self) -> str:
        return self.url(self.gateway_port)

    @property
    def registry_url(self) -> str:
        return self.url(self.registry_port)

    @property
    def pdp_url(self) -> str:
        return self.url(self.pdp_port)

    @property
    def txn_url(self) -> str:
        return self.url(self.txn_port)

    def agent_url(self, agent_id: str) -> str:
        return self.url(self.agent_ports[agent_id])

    @property
    def trace_file(self) -> Path:
        return self.var_dir / "traces.jsonl"

    def client_secret(self, client_id: str) -> str:
        return self.load("users.json")["clients"][client_id]["secret"]
