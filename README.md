# A2A Registry + Gateway PoC

**English** | [繁體中文](README.zh-TW.md)

A small, runnable proof of concept for letting AI agents from different teams work together safely. An AI assistant (the "orchestrating agent") can find expert agents owned by other teams, check whether the user is allowed to use them, hand them a task, and wait for the result. A2A (Agent2Agent) is the open protocol agents use to talk to each other. MCP (Model Context Protocol) is the protocol AI assistants use to call tools.

Everything is plain Python 3.11+ standard library. Nothing to install.

## What is in it

```
Claude Code / demo runtime  (MCP client, signed in as a user)
        │  Bearer token
        ▼
Agent Gateway  :18000   one policy check point for MCP and A2A
        │               (poc/gateway.py, or the agentgateway binary)
        │  token exchange (the user's token is never forwarded)
        ▼
Agent Registry :18200   MCP server: search_agents, invoke_agent, provide_input,
        │               cancel_task, resource a2a-task://{agent}/{task}
        │  every A2A call goes back through the gateway
        ▼
Agent Gateway ──► A2A agents :18101-18104 (A2A 1.0, JSON-RPC)
Mock IdP :18300  stands in for Keycloak (RS256 JWT, JWKS, RFC 8693 token exchange)
Keycloak :18080  optional, the real thing (keycloak/docker-compose.yml)
```

| Path | What it does |
|---|---|
| `poc/gateway.py` | Built-in gateway: decides which runtime sees which tools, who may call a tool, who may delegate to which agent, and who owns a task |
| `poc/agw_config.py` | Turns `config/policy.json` into an agentgateway config (CEL rules), so both gateways use one policy file |
| `poc/registry.py` | Agent catalog, keyword search, task correlation (SQLite), blocking task resource |
| `poc/policy.py` + `config/policy.json` | Policy rules. The file is reloaded when it changes |
| `poc/agents/` | A2A 1.0 server and four demo agents (IT helpdesk, KPI report analyst, expense approver, hidden security forensics) |
| `poc/idp.py` + `config/users.json` | Fake users, groups and roles; token exchange rules |
| `poc/keycloak_realm.py` + `keycloak/` | Keycloak realm generated from the same config, and a compose file to run it |
| `poc/common/trace.py` | W3C trace context across every hop, written to `var/traces.jsonl` |
| `tests/test_acceptance.py` | 20 acceptance tests: discovery, authorization, async tasks, tracing |

All agent data is simulated. No real system is touched.

## Try it

```bash
python -m poc demo          # runs 10 scenarios and prints one full trace
python -m unittest -v       # 20 acceptance tests, about 10 seconds
```

What the demo shows:

1. A plain runtime gets only `whoami`. The orchestrator runtime also gets the registry tools.
2. alice (analytics) asks for a KPI report analysis. `invoke_agent` returns at once with a task id; one resource read waits until the task is done.
3. bob asks the same thing. The agent is found but marked `denied`, so he knows the capability exists.
4. bob asks about the weather. No agent matches, which is reported differently from "no permission".
5. carol files an expense without an amount. The task goes to `INPUT_REQUIRED`, she answers, it completes.
6. dave is in finance but lacks the approver role. The gateway returns `approval_required` and an approval request id.
7. The security forensics agent is hidden. bob cannot find it or call it; erin (SecOps) can.
8. The same user through a different runtime (the report agent's) is blocked by the delegation policy.
9. `cancel_task` cancels; a read that times out does not.
10. An agent error becomes `FAILED`, not a normal-looking text answer.

Other commands:

```bash
python -m poc up                                  # keep the stack running
python -m poc ask alice "幫我分析今天晨會報表的良率異常"
python -m poc ask carol "幫我申請差旅費報銷" --answer "12000 元 差旅"
python -m poc trace                               # tree of the latest request
python -m poc token alice                         # print a token for alice
```

## Use Claude Code as the orchestrating agent

Start the stack with `python -m poc up`, then in another terminal:

```bash
claude mcp add --transport http agent-gateway http://127.0.0.1:18000/mcp \
  --header "Authorization: Bearer $(python -m poc token alice)"
```

Ask Claude Code something like "幫我分析今天晨會報表的良率異常，用 agent-gateway 的工具". In our runs with Sonnet it called `search_agents`, `invoke_agent`, then read the task resource once; that read waited about 3 seconds and returned the finished result. Signed in as bob, it stopped at `denied` and explained that the agent exists but he lacks access. Tokens last 8 hours.

## Swap in agentgateway

[agentgateway](https://github.com/agentgateway/agentgateway) is an open source MCP/A2A proxy (Rust, Apache-2.0, hosted by the Agentic AI Foundation). The PoC can use it in place of `poc/gateway.py`. The registry, agents and tests stay the same.

Download the Windows binary (v1.7.0 was tested) into `bin/` and check it:

```bash
gh release download v1.7.0 -R agentgateway/agentgateway -D bin -p "agentgateway-windows-amd64.exe" -p "agentgateway-windows-amd64.exe.sha256"
sha256sum bin/agentgateway-windows-amd64.exe; cat bin/agentgateway-windows-amd64.exe.sha256
```

Then set `POC_GATEWAY=agentgateway`:

```bash
POC_GATEWAY=agentgateway python -m poc demo
POC_GATEWAY=agentgateway python -m unittest -v
```

The launcher writes `var/agentgateway.yaml` from `config/policy.json` and starts the binary. When `policy.json` changes, the config is rewritten and agentgateway reloads it. Its log is `var/agentgateway.log`.

How the policy maps:

- Tool distribution and tool calls become `mcpAuthorization` CEL rules. agentgateway drops tools a caller may not use from `tools/list`, so one rule set covers both.
- Each agent gets an A2A route with an `authorization` CEL rule: visibility, delegation (the runtime is read from the bottom of the token's `act` chain), and the user's groups or roles.
- Token exchange uses the built-in `backendAuth.oauthTokenExchange` against the mock IdP.

All 20 tests pass with both gateways. Where they differ, the tests check what each one actually does:

| Behavior | Built-in gateway | agentgateway |
|---|---|---|
| "Needs approval" | Returns `approval_required` and an approval request id | Plain deny; CEL rules only allow or deny |
| Why a call was refused | Error names the rule and a decision id | 403 without the rule; the reason is only in its log |
| Card of a hidden agent | 404, same as an agent that does not exist | 403, so the status code shows that the agent exists |
| Policy change takes effect | On the next request | About 0.4 s later, after the config file reload |
| Gateway spans | In `var/traces.jsonl` | Not exported there; its access log has the same trace id |
| Task ownership | Checked at the gateway and again in the agent | Only in the registry and the agent; the gateway cannot see task owners |
| Search access hints | Gateway endpoint | The registry evaluates `policy.json` itself (hints only; agentgateway makes the real decision) |

Claude Code also worked through agentgateway in our run: `search_agents`, `invoke_agent`, then one resource read.

## Use a real Keycloak

`keycloak/docker-compose.yml` runs Keycloak 26.8.2 on `127.0.0.1:18080` and imports realm `poc` from `keycloak/realm-poc.json`. That file is generated from `config/users.json` and `config/policy.json` (`python -m poc.keycloak_realm`), so users, groups, roles and clients match the mock IdP. Every demo user's password is `dev-password`.

```bash
docker compose -f keycloak/docker-compose.yml up -d     # with Docker in WSL: run it inside WSL
POC_IDP=keycloak python -m poc demo
POC_IDP=keycloak POC_GATEWAY=agentgateway python -m unittest -v
```

What we learned wiring it up:

- Keycloak's standard token exchange (GA) does not add an `act` claim, and the exchanged token's `azp` becomes the service that asked for it. After the first hop nothing in the token says which runtime started the request, which the delegation policy needs. Keycloak's delegation support (`token-exchange-delegation`) is still a preview feature.
- The PoC keeps the starting runtime with GA features only. Each runtime has an `origin-<runtime>` client scope that adds an `origin_client` claim. The registry and the built-in gateway ask for that scope on every exchange, so the claim survives every hop.
- agentgateway cannot ask for a scope that depends on the caller: `scope` is not allowed in `additionalParams`, and its `scopes` field is fixed. So on its hop to the registry it sends the runtime it validated in an `x-origin-client` header. It overwrites whatever the client sent, and the registry only accepts the header on tokens minted for the gateway (`azp=agent-gateway`) that carry no origin of their own. A test checks that a client cannot spoof it.
- Keycloak refuses to give the registry a token for an agent (`Requested audience not available`), because only the gateway has those audiences. That is the same rule the mock IdP enforces.

All 20 tests pass in all four combinations: mock IdP or Keycloak, built-in gateway or agentgateway. Claude Code also worked against Keycloak + agentgateway; with `whoami` it reported the identity the gateway saw.

## Optional: real LLM answers

Agents use canned text by default so tests stay stable. With `POC_LLM=claude`, agents write their answers and the demo runtime picks agents through the local `claude` CLI (your Claude subscription, no API key). `POC_LLM_MODEL` picks the model, default `sonnet`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `POC_SPEED` | `1.0` | Multiplier for simulated agent work time |
| `POC_RESOURCE_WAIT` | `20` | Max seconds one task resource read waits; keep it below your MCP client's timeout |
| `POC_IDP` | `mock` | `keycloak` to use Keycloak on port 18080 instead of the mock IdP |
| `POC_GATEWAY` | `builtin` | `agentgateway` to use the agentgateway binary instead of `poc/gateway.py` |
| `POC_AGENTGATEWAY_BIN` | `bin/agentgateway-windows-amd64.exe` | Path to the agentgateway binary |

Ports are set in `poc/settings.py` and `config/agents.json`. agentgateway also opens its admin ports 15000, 15020 and 15021.

## What this PoC does not do

- The mock IdP is a stand-in. It signs RS256 tokens and publishes a JWKS like Keycloak, but logins do not check passwords and the signing key is generated into `var/`. The Keycloak setup is dev mode with fixed passwords and secrets.
- Search is keyword-based (BM25 with Chinese bigrams), not embeddings. The `search_agents` contract would stay the same if it were swapped.
- The gateway keeps task ownership in memory. After a restart, old task resources are refused until the task is recreated. The registry's correlation table survives restarts.
- No streaming, push notifications, MCP Tasks, or approval workflow. An approval request only gets an id.
- MCP transport answers with plain JSON; there is no SSE stream.
- It runs as one process with threads (plus the agentgateway process when enabled). Each component already talks to the others over HTTP, so they can be split into separate services. If the Python process is killed instead of stopped with Ctrl+C, the agentgateway process may keep running.
