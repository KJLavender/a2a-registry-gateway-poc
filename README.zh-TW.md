# A2A Registry + Gateway PoC

[English](README.md) | **繁體中文**

這是一個可以直接執行的小型概念驗證，示範不同團隊的 AI Agent 如何安全地互相合作。AI 助理（負責分派工作的 Orchestrating Agent）可以找到其他團隊維護的專家 Agent，確認使用者有沒有權限，把工作交給對方，再等結果回來。A2A（Agent2Agent）是 Agent 之間溝通的開放協議；MCP（Model Context Protocol）是 AI 助理呼叫工具用的協議。

全部只用 Python 3.11 以上的標準函式庫，不用另外安裝套件。

## 裡面有什麼

```
Claude Code / 示範用 runtime（MCP client，以某位使用者身分登入）
        │  Bearer token
        ▼
Agent Gateway  :18000   MCP 和 A2A 共用的政策檢查點
        │               （poc/gateway.py，或 agentgateway 執行檔）
        │  token exchange（不會直接轉傳使用者的 token）
        ▼
Agent Registry :18200   MCP server：search_agents、invoke_agent、provide_input、
        │               cancel_task，以及 resource a2a-task://{agent}/{task}
        │  所有 A2A 呼叫都繞回 Gateway
        ▼
Agent Gateway ──► A2A Agents :18101-18104（A2A 1.0，JSON-RPC）
模擬 IdP :18300  代替 Keycloak（RS256 JWT、JWKS、RFC 8693 token exchange）
Keycloak :18080  選用，真的 Keycloak（keycloak/docker-compose.yml）
```

| 路徑 | 負責什麼 |
|---|---|
| `poc/gateway.py` | 內建 Gateway：決定哪個 runtime 看得到哪些工具、誰可以呼叫工具、誰可以委派給哪個 Agent、Task 屬於誰 |
| `poc/agw_config.py` | 把 `config/policy.json` 轉成 agentgateway 的設定（CEL 規則），兩種 Gateway 共用同一份政策 |
| `poc/registry.py` | Agent 目錄、關鍵字搜尋、Task 對應表（SQLite）、會等待的 Task resource |
| `poc/policy.py` + `config/policy.json` | 政策規則；檔案改了會自動重新載入 |
| `poc/agents/` | A2A 1.0 server 和四個示範 Agent（IT 服務台、晨會報表分析、費用簽核、隱藏的資安鑑識） |
| `poc/idp.py` + `config/users.json` | 假的使用者、群組、角色，以及 token exchange 規則 |
| `poc/keycloak_realm.py` + `keycloak/` | 用同一份設定產生的 Keycloak realm，以及啟動它的 compose 檔 |
| `poc/common/trace.py` | 每一段都帶著 W3C trace context，寫到 `var/traces.jsonl` |
| `tests/test_acceptance.py` | 20 個驗收測試：搜尋、授權、非同步 Task、trace |

所有 Agent 的資料都是模擬的，不會碰到任何真實系統。

## 怎麼跑

```bash
python -m poc demo          # 跑 10 個情境，最後印出一條完整 trace
python -m unittest -v       # 20 個驗收測試，約 10 秒
```

demo 會看到：

1. 一般 runtime 只拿到 `whoami`；負責分派的 runtime 才會多拿到 Registry 的工具。
2. alice（分析部）請 Agent 分析晨會報表。`invoke_agent` 馬上回傳 task id，讀一次 resource 就會等到 Task 完成。
3. bob 問同一件事。Agent 找得到，但標示為 `denied`，他會知道公司其實有這個能力。
4. bob 問天氣。沒有符合的 Agent，這和「沒有權限」是分開回報的。
5. carol 申請費用沒寫金額。Task 進入 `INPUT_REQUIRED`，她補上金額後完成。
6. dave 在財務部但沒有簽核角色。Gateway 回 `approval_required` 和一個核准申請編號。
7. 資安鑑識 Agent 是隱藏的。bob 搜不到也叫不到；erin（SecOps）可以用。
8. 同一個使用者改從另一個 runtime（報表 Agent 的）發出，會被委派政策擋下。
9. `cancel_task` 會取消 Task；讀取逾時則不會。
10. Agent 端出錯會變成 `FAILED`，不會被包成一段看起來正常的文字。

其他指令：

```bash
python -m poc up                                  # 讓整套服務持續執行
python -m poc ask alice "幫我分析今天晨會報表的良率異常"
python -m poc ask carol "幫我申請差旅費報銷" --answer "12000 元 差旅"
python -m poc trace                               # 印出最近一次請求的 trace
python -m poc token alice                         # 印出 alice 的 token
```

## 讓 Claude Code 當 Orchestrating Agent

先用 `python -m poc up` 啟動，再開另一個終端機：

```bash
claude mcp add --transport http agent-gateway http://127.0.0.1:18000/mcp \
  --header "Authorization: Bearer $(python -m poc token alice)"
```

然後問 Claude Code，例如「幫我分析今天晨會報表的良率異常，用 agent-gateway 的工具」。我們用 Sonnet 實測時，它依序呼叫 `search_agents`、`invoke_agent`，再讀一次 Task resource；那一次讀取等了約 3 秒，直接拿到完成的結果。換成 bob 登入時，它看到 `denied` 就停下來，說明這個 Agent 存在但他沒有權限。token 有效 8 小時。

## 換成 agentgateway

[agentgateway](https://github.com/agentgateway/agentgateway) 是開源的 MCP／A2A proxy（Rust 寫的，Apache-2.0 授權，由 Agentic AI Foundation 托管）。這個 PoC 可以用它取代 `poc/gateway.py`，Registry、Agent 和測試都不用改。

先把 Windows 執行檔（測過 v1.7.0）下載到 `bin/` 並比對 sha256：

```bash
gh release download v1.7.0 -R agentgateway/agentgateway -D bin -p "agentgateway-windows-amd64.exe" -p "agentgateway-windows-amd64.exe.sha256"
sha256sum bin/agentgateway-windows-amd64.exe; cat bin/agentgateway-windows-amd64.exe.sha256
```

再設定 `POC_GATEWAY=agentgateway`：

```bash
POC_GATEWAY=agentgateway python -m poc demo
POC_GATEWAY=agentgateway python -m unittest -v
```

launcher 會根據 `config/policy.json` 產生 `var/agentgateway.yaml`，再啟動執行檔。`policy.json` 改了之後設定檔會重新產生，agentgateway 會自動重新載入。它的 log 在 `var/agentgateway.log`。

政策怎麼對應過去：

- 工具分發和工具呼叫變成 `mcpAuthorization` 的 CEL 規則。agentgateway 會把呼叫者不能用的工具從 `tools/list` 拿掉，所以一組規則就涵蓋兩件事。
- 每個 Agent 有一條 A2A route，用 `authorization` 的 CEL 規則檢查：看不看得到、委派政策（從 token 的 `act` 鏈最底層讀出是哪個 runtime）、使用者的群組或角色。
- token exchange 用它內建的 `backendAuth.oauthTokenExchange`，對接模擬 IdP。

兩種 Gateway 都通過全部 20 個測試。行為不一樣的地方，測試會分別檢查各自實際的結果：

| 行為 | 內建 Gateway | agentgateway |
|---|---|---|
| 需要核准 | 回 `approval_required` 和核准申請編號 | 直接拒絕；CEL 規則只有允許和拒絕 |
| 為什麼被拒絕 | 錯誤會寫是哪條規則和決策編號 | 403，沒有規則名稱；原因只在它的 log |
| 隱藏 Agent 的 card | 404，和不存在的 Agent 一樣 | 403，從狀態碼就看得出這個 Agent 存在 |
| 政策改動生效 | 下一個請求就生效 | 約 0.4 秒後，等設定檔重新載入 |
| Gateway 的 span | 在 `var/traces.jsonl` | 不會寫到那裡；它的 access log 有同一個 trace id |
| Task 擁有者檢查 | Gateway 檢查一次，Agent 再檢查一次 | 只有 Registry 和 Agent 檢查；Gateway 看不到 Task 屬於誰 |
| 搜尋結果的權限提示 | Gateway 提供的端點 | Registry 自己讀 `policy.json` 判斷（只是提示，真正的判斷在 agentgateway） |

我們實測時，Claude Code 透過 agentgateway 也能正常運作：`search_agents`、`invoke_agent`，再讀一次 resource。

## 接上真的 Keycloak

`keycloak/docker-compose.yml` 會在 `127.0.0.1:18080` 跑 Keycloak 26.8.2，並從 `keycloak/realm-poc.json` 匯入 realm `poc`。這個檔案是用 `config/users.json` 和 `config/policy.json` 產生的（`python -m poc.keycloak_realm`），所以使用者、群組、角色和 client 都跟模擬 IdP 一致。所有示範帳號的密碼都是 `dev-password`。

```bash
docker compose -f keycloak/docker-compose.yml up -d     # Docker 裝在 WSL 的話，在 WSL 裡執行
POC_IDP=keycloak python -m poc demo
POC_IDP=keycloak POC_GATEWAY=agentgateway python -m unittest -v
```

接起來之後發現的事：

- Keycloak 正式版（GA）的 token exchange 不會加 `act` claim，換發後 token 的 `azp` 會變成提出換發的那個服務。從第二跳開始，token 裡就看不出請求是從哪個 runtime 發起的，但委派政策需要這個資訊。Keycloak 支援委派的功能（`token-exchange-delegation`）目前還是 Preview。
- PoC 只用正式版功能來保留源頭：每個 runtime 有一個 `origin-<runtime>` client scope，會加上 `origin_client` claim。Registry 和內建 Gateway 每次換發都會要求這個 scope，所以每一跳都帶得到。
- agentgateway 沒辦法依呼叫者動態要求 scope：`additionalParams` 不允許 `scope`，`scopes` 欄位又是寫死的。所以它在轉給 Registry 的那一跳，改用 `x-origin-client` header 傳它驗證過的 runtime。它會覆蓋客戶端送來的值，Registry 也只在「發給 Gateway 的 token（`azp=agent-gateway`）且 token 本身沒有源頭資訊」時才採用。有一個測試專門確認客戶端無法偽造。
- Keycloak 會拒絕 Registry 換發 Agent 的 token（`Requested audience not available`），因為只有 Gateway 有那些 audience。這和模擬 IdP 的規則一樣。

四種組合（模擬 IdP 或 Keycloak，內建 Gateway 或 agentgateway）都通過全部 20 個測試。Claude Code 接 Keycloak + agentgateway 也能正常運作，用 `whoami` 回報的是 Gateway 認定的身分。

## 選用：讓 Agent 用真的 LLM 回答

預設 Agent 回固定的文字，測試結果才會穩定。設定 `POC_LLM=claude` 後，Agent 的回覆和 demo runtime 挑選 Agent 都會改用本機的 `claude` CLI（走你的 Claude 訂閱，不需要 API key）。`POC_LLM_MODEL` 可以換模型，預設 `sonnet`。

## 設定

| 環境變數 | 預設 | 說明 |
|---|---|---|
| `POC_SPEED` | `1.0` | 模擬 Agent 工作時間的倍率 |
| `POC_RESOURCE_WAIT` | `20` | 一次 Task resource 讀取最多等幾秒；要小於 MCP client 的逾時設定 |
| `POC_IDP` | `mock` | 設成 `keycloak` 就改用 18080 埠的 Keycloak，不用模擬 IdP |
| `POC_GATEWAY` | `builtin` | 設成 `agentgateway` 就改用 agentgateway 執行檔，不用 `poc/gateway.py` |
| `POC_AGENTGATEWAY_BIN` | `bin/agentgateway-windows-amd64.exe` | agentgateway 執行檔的路徑 |

連接埠設定在 `poc/settings.py` 和 `config/agents.json`。agentgateway 另外會開管理用的 15000、15020、15021 埠。

## 這個 PoC 沒有做的事

- 模擬 IdP 是替代品。它像 Keycloak 一樣簽 RS256 token 並公開 JWKS，但登入不檢查密碼，簽章金鑰是產生在 `var/` 裡的。Keycloak 的設定是開發模式，密碼和 secret 都是固定的。
- 搜尋用關鍵字（BM25 加中文二字詞），不是向量語意搜尋。換掉搜尋方式也不影響 `search_agents` 的介面。
- Gateway 把 Task 的擁有者記在記憶體裡。重啟後，舊 Task 的 resource 會被拒絕；Registry 的對應表則會保留。
- 沒有 streaming、push notification、MCP Tasks，也沒有實際的核准流程，核准申請只會拿到一個編號。
- MCP 傳輸只回一般 JSON，沒有 SSE stream。
- 全部在同一個 process 裡用 thread 執行（啟用時另外加上 agentgateway 的 process）。各元件之間本來就走 HTTP，要拆成獨立服務並不難。如果直接砍掉 Python process 而不是按 Ctrl+C，agentgateway 的 process 可能會留著。
