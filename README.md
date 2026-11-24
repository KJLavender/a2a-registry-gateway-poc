# A2A Registry + Gateway PoC

**English** | [繁體中文](README.zh-TW.md)

A small, runnable proof of concept for letting AI agents from different teams work together safely. An AI assistant (the "orchestrating agent") can find expert agents owned by other teams, check whether the user is allowed to use them, hand them a task, and wait for the result. A2A (Agent2Agent) is the open protocol agents use to talk to each other. MCP (Model Context Protocol) is the protocol AI assistants use to call tools.

The core is plain Python 3.11+ standard library, with nothing to install. Two optional parts need packages (`pip install -r requirements-extras.txt`): semantic search and one agent built on the official A2A Python SDK.

## What is in it

```
Claude Code / demo runtime  (MCP client, signed in as a user)
        │  Bearer token
        ▼
Agent Gateway  :18000   one policy check point for MCP and A2A
        │               (poc/gateway.py, or the agentgateway binary)
        │  token exchange (the user's token is never forwarded)
        │  + a transaction token that says who started the request (Txn-Token service :18500)
        ▼
Agent Registry :18200   MCP server: search_agents, invoke_agent, provide_input,
        │               cancel_task, resource a2a-task://{agent}/{task}
        │  every A2A call goes back through the gateway
        ▼
Agent Gateway ──► A2A agents :18101-18105 (A2A 1.0, JSON-RPC; one of them runs on the official A2A SDK)
Mock IdP :18300  stands in for Keycloak (RS256 JWT, JWKS, RFC 8693 token exchange)
Keycloak :18080  optional, the real thing (keycloak/docker-compose.yml)
```

| Path | What it does |
|---|---|
| `poc/gateway.py` | Built-in gateway: decides which runtime sees which tools, who may call a tool, who may delegate to which agent, and who owns a task |
| `poc/agw_config.py` | Turns `config/policy.json` into an agentgateway config (CEL rules), so both gateways use one policy file |
| `poc/registry.py` + `poc/search.py` | Agent catalog, search (keywords, plus embeddings when installed), task correlation (SQLite), blocking task resource |
| `poc/policy.py` + `config/policy.json` | Policy rules. The file is reloaded when it changes |
| `poc/agents/` | A2A 1.0 server and four demo agents (IT helpdesk, KPI report analyst, expense approver, hidden security forensics), plus `sdk_agent.py`, a leave-request agent built on the official A2A SDK |
| `poc/idp.py` + `config/users.json` | Fake users, groups and roles; token exchange rules |
| `poc/keycloak_realm.py` + `keycloak/` | Keycloak realm generated from the same config, and a compose file to run it |
| `poc/pdp.py` + `poc/approvals.py` + `poc/notify.py` | Policy decision point for A2A calls (used by both gateways), approval requests and their notifications |
| `poc/txn.py` | Transaction Token Service: one signed token per request that carries the user, the runtime and the purpose through every hop |
| `poc/tck_sut.py` | The PoC's A2A server set up for the official A2A TCK (compatibility test kit) |
| `poc/keycloak_delegation.py` | Keycloak delegation setup and a browser-style login for the delegation tests |
| `poc/common/trace.py` | W3C trace context across every hop, written to `var/traces.jsonl` and optionally sent over OTLP |
| `tests/` | 34 acceptance tests (search, authorization, approvals, transaction tokens, async tasks, tracing, the SDK agent), 6 A2A conformance tests and 6 Keycloak delegation tests |

All agent data is simulated. No real system is touched.

## Try it

```bash
python -m poc demo          # runs 11 scenarios and prints one full trace
python -m unittest -v       # about 20 seconds; tests that need optional parts or Keycloak are skipped
```

What the demo shows:

1. A plain runtime gets only `whoami`. The orchestrator runtime also gets the registry tools.
2. alice (analytics) asks for a KPI report analysis. `invoke_agent` returns at once with a task id; one resource read waits until the task is done.
3. bob asks the same thing. The agent is found but marked `denied`, so he knows the capability exists.
4. bob asks about the weather. No agent matches, which is reported differently from "no permission".
5. carol files an expense without an amount. The task goes to `INPUT_REQUIRED`, she answers, it completes.
6. dave is in finance but lacks the approver role. The gateway returns `approval_required` and an approval request id, and carol gets a notification. She approves it, dave's next try goes through, and the one after that needs a new approval.
7. The security forensics agent is hidden. bob cannot find it or call it; erin (SecOps) can.
8. The same user through a different runtime (the report agent's) is blocked by the delegation policy.
9. `cancel_task` cancels; a read that times out does not.
10. An agent error becomes `FAILED`, not a normal-looking text answer.
11. bob writes "下禮拜想休息兩天" ("I want two days off next week"). No word in it appears in any agent card, but semantic search finds the leave agent, which runs on the official A2A SDK. It asks which dates, gets them, and files the request. (Needs the optional packages.)

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

After transaction tokens were added we ran Claude Code (Sonnet, `claude -p`) again through both gateways with four requests: alice's report (completed), bob's report (stopped at `denied` without trying `invoke_agent`), bob's "下禮拜想休息兩天" (it found the leave agent by meaning and filed 12/3-12/4), and `whoami` (it reported the runtime and the transaction id). Both gateways gave the same tool calls and results.

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
- Each agent gets an A2A route whose decision comes from the policy decision point (`poc/pdp.py`) through agentgateway's `extAuthz`. CEL could only allow or deny with a 403; the PDP can also start an approval, answer 404 for hidden agents, and explain refusals. The built-in gateway calls the same code in-process.
- Token exchange uses the built-in `backendAuth.oauthTokenExchange` against the IdP.
- Transaction tokens: the MCP route also calls the PDP through `extAuthz`. The PDP mints the request's Txn-Token and returns it as a response header, and `includeResponseHeaders` makes agentgateway add it to the request it sends to the registry. It replaces anything the client sent in that header.

All tests pass with both gateways. What is still different:

| Behavior | Built-in gateway | agentgateway |
|---|---|---|
| Policy change takes effect | On the next request | Tool rules: about 0.4 s later, after the config file reload. A2A decisions (PDP): next request |
| Gateway spans | In `var/traces.jsonl` | Sent by agentgateway to the OTLP collector (see Jaeger below); not in the JSONL file |
| Task ownership | Checked at the gateway and again in the agent | Only in the registry and the agent; the gateway cannot see task owners |
| Search access hints | Gateway endpoint | The registry evaluates `policy.json` itself (hints only; agentgateway makes the real decision) |
| Agent card with `If-None-Match` | `304 Not Modified` | Always the full card. agentgateway 1.7 rewrites the card body and answered `503` when the agent sent a 304, so the config drops conditional headers on A2A routes |

Claude Code also worked through agentgateway in our run: `search_agents`, `invoke_agent`, then one resource read.

## Approvals

An agent can require approval for some users. In `config/policy.json`, `approval_groups` says who may ask and `approvers` says who may decide. Here dave (finance, no approver role) can use the expense agent only after carol (`expense.approve`) approves:

```bash
python -m poc ask dave "幫我申請 3000 元交通費報銷"   # refused with an id like APR-1A2B3C
python -m poc approvals --as carol                    # what carol can decide
python -m poc approve APR-1A2B3C --as carol           # or --reject
python -m poc ask dave "幫我申請 3000 元交通費報銷"   # allowed once
```

Requesters cannot approve their own request, people without the approver rule cannot approve, and asking again while a request is pending returns the same id. An approval covers one invocation within an hour. Search results show the agent as `approval_required`, and as `allowed` while an approval is waiting to be used.

Notifications: when a request is opened, everyone who may decide it gets one, and the requester gets one when it is decided. They land in an inbox (`python -m poc inbox --as carol`, or `GET /notifications` on the PDP). Set `POC_APPROVAL_WEBHOOK` to a Slack or Mattermost incoming webhook URL and each one is also posted there as JSON with a `text` field. A failed post is retried up to 5 times with growing waits, so a chat outage delays a notification instead of losing it. Approvers are looked up in `config/users.json`; a real setup would ask the company directory.

## Use a real Keycloak

`keycloak/docker-compose.yml` runs Keycloak 26.8.2 on `127.0.0.1:18080` and imports realm `poc` from `keycloak/realm-poc.json`. That file is generated from `config/users.json` and `config/policy.json` (`python -m poc.keycloak_realm`), so users, groups, roles and clients match the mock IdP. Every demo user's password is `dev-password`.

```bash
docker compose -f keycloak/docker-compose.yml up -d     # with Docker in WSL: run it inside WSL
POC_IDP=keycloak python -m poc demo
POC_IDP=keycloak POC_GATEWAY=agentgateway python -m unittest -v
```

What we learned wiring it up:

- Keycloak's standard token exchange (GA) does not add an `act` claim, and the exchanged token's `azp` becomes the service that asked for it. After the first hop nothing in the token says which runtime started the request, which the delegation policy needs. Keycloak's delegation support (`token-exchange-delegation`) is still a preview feature.
- So Keycloak only issues the per-hop access tokens, and the starting runtime travels in a transaction token instead (next section). An earlier version kept it in a custom `origin_client` claim through per-runtime client scopes; agentgateway could not ask for those scopes (`scope` is not allowed in its `additionalParams`), which is part of why that approach was dropped.
- Keycloak refuses to give the registry a token for an agent (`Requested audience not available`), because only the gateway has those audiences. That is the same rule the mock IdP enforces.

All tests pass in all four combinations: mock IdP or Keycloak, built-in gateway or agentgateway. Claude Code also worked against Keycloak + agentgateway; with `whoami` it reported the identity the gateway saw.

### Keycloak delegation (`act` claims)

The compose file also turns on Keycloak's `token-exchange-delegation` preview (with `parameterized-scopes` and fine-grained admin permissions v2). `tests/test_keycloak_delegation.py` shows what it does:

```bash
POC_IDP=keycloak python -m unittest tests.test_keycloak_delegation -v
```

- A user signs in through the browser flow, asks for `delegation:client:agent-gateway` and accepts a consent screen. Their token then carries `may_act`. The test signs in the same way a person would: it fills in the login form and the consent screen.
- agent-gateway exchanges that token, sending its own service-account token as `actor_token`, and gets a token with `act: {client_id: agent-gateway}` for any audience it is allowed (the registry or an agent).
- Another client cannot use that consent. Without a delegate permission for the actor, the `may_act` claim is quietly left out and the login still succeeds.
- A token that carries `act` or `may_act` cannot be exchanged again, by standard exchange or by delegation. So `act` names one actor and cannot grow into a chain like gateway > registry > gateway > agent. Only the holder of the user's original token can mint delegated tokens.
- Standard exchange refuses a user token with `may_act`, so delegation and the PoC's per-hop standard exchange cannot be used on the same token.

So delegation fits a single hop: one agent acting directly for the user. For the multi-hop chain the PoC uses transaction tokens.

## Transaction tokens: who started this, at every hop

A request goes runtime > gateway > registry > gateway > agent. Each hop gets its own access token from the IdP, bound to that hop's audience. Those tokens say who the user is, but after the first exchange they no longer say which runtime started the request, and the delegation policy needs that. `poc/txn.py` follows the IETF draft for OAuth Transaction Tokens (draft-ietf-oauth-transaction-tokens):

- The gateway is the edge. For each MCP request from a runtime it asks the Txn-Token service for a short-lived (5 minutes) signed token with the user (`sub`), the runtime (`tctx.origin_client`), the purpose (`scope`, the MCP tool that started it) and a transaction id (`txn`).
- That token travels unchanged in a `Txn-Token` header: gateway > registry > gateway > agent. The registry and the agents refuse requests without it, and check that it belongs to the same user as the access token.
- Only the gateway may ask for one, and only with a token from outside (the service refuses a token that was minted for the registry). A runtime that sends its own `Txn-Token` header is ignored; the gateway mints a new one.
- The purpose limits what the registry may do with it. During a `search_agents` request it cannot create a task; `invoke_agent` may start one, `provide_input` may only continue one, reading a task resource may only call `GetTask`.
- Every span records the transaction id, so one id ties the audit trail together even across separate traces.

Tests cover each of these, in all four IdP/gateway combinations. The Txn-Token service here is our own small implementation of a draft standard; neither Keycloak nor agentgateway ships one yet.

## See whole traces in Jaeger

Every component writes spans to `var/traces.jsonl` (`python -m poc trace` prints them). To see one request across all services, including agentgateway's own spans, start Jaeger and point the PoC at it:

```bash
docker compose -f observability/docker-compose.yml up -d        # Jaeger UI at http://127.0.0.1:16686
POC_OTLP_ENDPOINT=http://127.0.0.1:4318 POC_GATEWAY=agentgateway python -m poc up
POC_OTLP_ENDPOINT=http://127.0.0.1:4318 python -m poc ask alice "幫我分析今天晨會報表的良率異常"
```

In our run one request became a single trace of 57 spans from six services (frontend, runtime, agentgateway, registry, PDP, agent) with one root and no broken links. Two things were needed for that:

- agentgateway reads the trace context from the HTTP `traceparent` header, not from MCP's `params._meta`, so the runtime sends both. With only `_meta`, every tool call started a new trace once agentgateway tracing was on.
- agentgateway sends spans in batches about every 5 seconds. A process that stops it right away loses the last batch, so the launcher waits before stopping it when an OTLP endpoint is set.

`config.tracing` is deprecated in agentgateway 1.7; the generated config uses `frontendPolicies.tracing`.

## Semantic search (optional)

With `fastembed` installed, `search_agents` combines keyword search (BM25) with embeddings from a small multilingual model (`paraphrase-multilingual-MiniLM-L12-v2`, about 220 MB, downloaded to `.cache/fastembed` on first use). Each skill and each example sentence of an agent card is embedded; the two result lists are merged by rank. `search_mode` in the result says which mode answered. `POC_SEARCH=keyword` turns it off, `hybrid` makes it required.

What it adds, measured on the demo catalog:

- "從家裡沒辦法連上公司內網" (can't reach the company network from home) shares no keyword with the VPN skill; it now finds the IT helpdesk (similarity 0.64).
- "上週出差的計程車錢要怎麼拿回來" (getting taxi money back from a trip) finds the expense agent (0.44).
- Unrelated requests (weather, lunch, stock price) stay below 0.40, under the 0.42 cut-off, so "no matching agent" still works.

Near misses do get through: "幫我訂明天下午的會議室" (book a meeting room) scores 0.52 against the leave agent, and "幫我訂高鐵票" (book a train ticket) 0.52 against expenses. The caller still sees the agent's description and decides, and the gateway still decides access. A real catalog needs its own set of test questions to set the cut-off.

## An agent on the official A2A SDK (optional)

`poc/agents/sdk_agent.py` is a leave-request agent written with the official A2A Python SDK (`a2a-sdk` 1.3.1): the SDK's agent executor, task store and JSON-RPC routes, served by uvicorn. In front of it sits a small ASGI middleware that checks the same two tokens as the other agents (the access token for `agent:hr-leave` and the Txn-Token) and passes the user to the SDK, whose task store keeps each user's tasks apart.

Nothing else had to change: the registry finds it, both gateways govern it, the trace runs through it, and Claude Code can use it. One SDK rule to know: an executor must send the Task itself before any status update, or the SDK fails the request.

## A2A compatibility (TCK)

The A2A project publishes a compatibility test kit, the [A2A TCK](https://github.com/a2aproject/a2a-tck). `poc/tck_sut.py` runs the PoC's A2A server with the behaviors the TCK asks for, and CI runs the TCK against it (JSON-RPC):

```bash
python -m poc.tck_sut --port 18199
# in a clone of a2a-tck (needs Python 3.15; uv can install it):
python run_tck.py --sut-host http://127.0.0.1:18199 --transport jsonrpc
```

The first run had 53 failures. Most came from one bug (`POST /a2a/` with a trailing slash was a 404); the rest were real gaps, now fixed:

- Parameters sent with proto field names (`history_length` instead of `historyLength`) were ignored. Proto3 JSON allows both. The gateway and the PDP now read them the same way as the agents, so `task_id` and `taskId` cannot be judged differently along the chain.
- Streaming, push notification and extended-card methods answered "method not found" (-32601) instead of "unsupported operation" (-32004) or "push notifications not supported" (-32003).
- A message part with a media type the agent does not accept was taken instead of refused with -32005.
- The agent card had no `Cache-Control` or `ETag` header.

Now: 0 failures, 55 MUST requirements passed. What is not tested: gRPC and HTTP+JSON (this server offers JSON-RPC only), streaming, and the authentication requirements (this TCK version has no automated tests for them).

The TCK also runs through each gateway (`python -m poc.tck_sut --via-gateway`, with `POC_GATEWAY` picking the gateway). That starts a full stack with the test agent behind it and real token checks. The TCK cannot send credentials, so a small test proxy adds alice's token to each request. Both gateways give the same result as the agent alone: 0 failures. Running it this way found two gaps in the built-in gateway (no route for `/a2a/` and no caching headers on the card it serves) and the agentgateway 304 problem above. CI runs all three: direct, built-in, agentgateway.

## Optional: real LLM answers

Agents use canned text by default so tests stay stable. With `POC_LLM=claude`, agents write their answers and the demo runtime picks agents through the local `claude` CLI (your Claude subscription, no API key). `POC_LLM_MODEL` picks the model, default `sonnet`.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `POC_SPEED` | `1.0` | Multiplier for simulated agent work time |
| `POC_RESOURCE_WAIT` | `20` | Max seconds one task resource read waits; keep it below your MCP client's timeout |
| `POC_OTLP_ENDPOINT` | empty | OTLP/HTTP collector for traces, e.g. `http://127.0.0.1:4318` (Jaeger) |
| `POC_SEARCH` | `auto` | `keyword`, or `hybrid` to require semantic search; `auto` uses it when `fastembed` is installed |
| `POC_APPROVAL_WEBHOOK` | empty | Where approval notifications are posted (Slack or Mattermost incoming webhook) |
| `POC_IDP` | `mock` | `keycloak` to use Keycloak on port 18080 instead of the mock IdP |
| `POC_GATEWAY` | `builtin` | `agentgateway` to use the agentgateway binary instead of `poc/gateway.py` |
| `POC_AGENTGATEWAY_BIN` | `bin/agentgateway-windows-amd64.exe` | Path to the agentgateway binary |

Ports are set in `poc/settings.py` and `config/agents.json` (gateway 18000, registry 18200, PDP 18400, Txn-Token service 18500, mock IdP 18300, Keycloak 18080, agents 18101-18105). agentgateway also opens its admin ports 15000, 15020 and 15021.

## What this PoC does not do

- The mock IdP is a stand-in. It signs RS256 tokens and publishes a JWKS like Keycloak, but logins do not check passwords and the signing key is generated into `var/`. The Keycloak setup is dev mode with fixed passwords and secrets.
- Semantic search uses a small model tuned by hand on five agents. It has not been tested on a large catalog.
- The gateway keeps task ownership in memory. After a restart, old task resources are refused until the task is recreated. The registry's correlation table survives restarts.
- No streaming, push notifications or MCP Tasks. Approvals are decided through a small HTTP API and CLI, with notifications to an inbox and a webhook; there is no approval web page.
- Transaction tokens follow an IETF draft that may still change. Replacement tokens (a hop asking for a narrower one) are not implemented.
- MCP transport answers with plain JSON; there is no SSE stream.
- It runs as one process with threads (plus the agentgateway process when enabled). Each component already talks to the others over HTTP, so they can be split into separate services. If the Python process is killed instead of stopped with Ctrl+C, the agentgateway process may keep running.
