"""Start the whole stack (IdP, agents, registry, gateway) in one process.

With POC_GATEWAY=agentgateway the gateway is the agentgateway binary instead of poc/gateway.py.
"""
from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass, field
from http.server import ThreadingHTTPServer

from poc import agw_config
from poc.agents.base import A2AAgent
from poc.agents.demo import build_agents
from poc.common import trace
from poc.common.identity import TokenExchanger, make_verifier
from poc.common.web import http, serve
from poc.gateway import AgentGateway
from poc.idp import IdentityProvider, make_app
from poc.policy import PolicyStore
from poc.registry import AgentRegistry
from poc.settings import Settings


@dataclass
class Stack:
    settings: Settings
    servers: list[ThreadingHTTPServer]
    agents: list[A2AAgent]
    registry: AgentRegistry
    gateway: AgentGateway | None
    agentgateway: subprocess.Popen | None = None
    _stop: threading.Event = field(default_factory=threading.Event)

    def close(self) -> None:
        self._stop.set()
        if self.agentgateway is not None:
            self.agentgateway.terminate()
            self.agentgateway.wait(timeout=10)
        for server in self.servers:
            server.shutdown()
            server.server_close()


def _wait_healthy(url: str, proc: subprocess.Popen, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"agentgateway exited with code {proc.returncode}; see var/agentgateway.log")
        try:
            if http("GET", url, timeout=1)[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.2)
    raise RuntimeError("agentgateway did not become healthy; see var/agentgateway.log")


def _require_keycloak(settings: Settings) -> None:
    try:
        status = http("GET", f"{settings.issuer}/.well-known/openid-configuration", timeout=3)[0]
    except OSError:
        status = 0
    if status != 200:
        raise RuntimeError(f"Keycloak realm not reachable at {settings.issuer}. Start it with: "
                           "docker compose -f keycloak/docker-compose.yml up -d")


def _start_agentgateway(settings: Settings) -> subprocess.Popen:
    if not settings.agentgateway_bin.exists():
        raise FileNotFoundError(f"agentgateway binary not found at {settings.agentgateway_bin}")
    config = agw_config.write(settings)
    log = open(settings.var_dir / "agentgateway.log", "ab")
    proc = subprocess.Popen([str(settings.agentgateway_bin), "-f", config], stdout=log, stderr=subprocess.STDOUT)
    _wait_healthy(f"{settings.gateway_url}/healthz", proc)
    return proc


def _regenerate_on_policy_change(stack: Stack) -> None:
    """Keep agentgateway's CEL rules in sync with policy.json (agentgateway reloads its config file)."""
    path = stack.settings.config_dir / "policy.json"
    last = path.stat().st_mtime_ns
    while not stack._stop.wait(0.2):
        mtime = path.stat().st_mtime_ns
        if mtime != last:
            last = mtime
            agw_config.write(stack.settings)


def start_stack(settings: Settings) -> Stack:
    settings.var_dir.mkdir(parents=True, exist_ok=True)
    trace.configure(settings.trace_file)
    if settings.idp_impl == "keycloak":
        _require_keycloak(settings)
        servers = []
    else:
        servers = [serve(make_app(IdentityProvider(settings)), settings.host, settings.idp_port)]
    verify = make_verifier(settings)

    agents = build_agents(verify, settings.speed)
    for agent in agents:
        agent.base_url = settings.agent_url(agent.agent_id)
        servers.append(serve(agent, settings.host, settings.agent_ports[agent.agent_id]))

    registry = AgentRegistry(settings, verify, TokenExchanger(settings, "agent-registry"))
    servers.append(serve(registry, settings.host, settings.registry_port))
    registry.catalog.sync()

    if settings.gateway_impl == "agentgateway":
        stack = Stack(settings, servers, agents, registry, None, _start_agentgateway(settings))
        threading.Thread(target=_regenerate_on_policy_change, args=(stack,), daemon=True).start()
        return stack
    gateway = AgentGateway(settings, PolicyStore(settings.config_dir / "policy.json"), verify,
                           TokenExchanger(settings, "agent-gateway"))
    servers.append(serve(gateway, settings.host, settings.gateway_port))
    return Stack(settings, servers, agents, registry, gateway)
