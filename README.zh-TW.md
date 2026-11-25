# A2A Registry + Gateway PoC

[English](README.md) | **繁體中文**

這是一個可以直接執行的小型概念驗證，示範不同團隊的 AI Agent 如何安全地互相合作。AI 助理（負責分派工作的 Orchestrating Agent）可以找到其他團隊維護的專家 Agent，確認使用者有沒有權限，把工作交給對方，再等結果回來。A2A（Agent2Agent）是 Agent 之間溝通的開放協議；MCP（Model Context Protocol）是 AI 助理呼叫工具用的協議。

核心只用 Python 3.11 以上的標準函式庫，不用另外安裝套件。有兩個選用的部分需要套件（`pip install -r requirements-extras.txt`）：語意搜尋，以及一個用官方 A2A Python SDK 寫的 Agent。

## 裡面有什麼

```
Claude Code / 示範用 runtime（MCP client，以某位使用者身分登入）
        │  Bearer token
        ▼
Agent Gateway  :18000   MCP 和 A2A 共用的政策檢查點
        │               （poc/gateway.py，或 agentgateway 執行檔）
        │  token exchange（不會直接轉傳使用者的 token）
        │  + 一張記錄「這個請求是誰發起的」的 transaction token（Txn-Token 服務 :18500）
        ▼
Agent Registry :18200   MCP server：search_agents、invoke_agent、provide_input、
        │               cancel_task，以及 resource a2a-task://{agent}/{task}
        │  所有 A2A 呼叫都繞回 Gateway
        ▼
Agent Gateway ──► A2A Agents :18101-18105（A2A 1.0，JSON-RPC；其中一個用官方 A2A SDK 寫成）
模擬 IdP :18300  代替 Keycloak（RS256 JWT、JWKS、RFC 8693 token exchange）
Keycloak :18080  選用，真的 Keycloak（keycloak/docker-compose.yml）
```

| 路徑 | 負責什麼 |
|---|---|
| `poc/gateway.py` | 內建 Gateway：決定哪個 runtime 看得到哪些工具、誰可以呼叫工具、誰可以委派給哪個 Agent、Task 屬於誰 |
| `poc/agw_config.py` | 把 `config/policy.json` 轉成 agentgateway 的設定（CEL 規則），兩種 Gateway 共用同一份政策 |
| `poc/registry.py` + `poc/search.py` | Agent 目錄、搜尋（關鍵字，有裝套件時再加上語意向量）、Task 對應表（SQLite）、會等待的 Task resource |
| `poc/policy.py` + `config/policy.json` | 政策規則；檔案改了會自動重新載入 |
| `poc/agents/` | A2A 1.0 server 和四個示範 Agent（IT 服務台、晨會報表分析、費用簽核、隱藏的資安鑑識），以及 `sdk_agent.py`：用官方 A2A SDK 寫的請假 Agent，和 `consult.py`：一個 Agent 怎麼經過 Gateway 請教另一個 Agent |
| `poc/idp.py` + `config/users.json` | 假的使用者、群組、角色，以及 token exchange 規則 |
| `poc/keycloak_realm.py` + `keycloak/` | 用同一份設定產生的 Keycloak realm，以及啟動它的 compose 檔 |
| `poc/pdp.py` + `poc/approvals.py` + `poc/notify.py` | A2A 呼叫的政策決策服務（兩種 Gateway 共用）、核准申請和核准通知 |
| `poc/txn.py` | Transaction Token 服務：每個請求一張簽章過的 token，把使用者、runtime、用途和中間委派過的 Agent 帶過每一跳 |
| `poc/tck_sut.py` | 給官方 A2A TCK（相容性測試工具）測試用的 A2A server 設定 |
| `poc/keycloak_delegation.py` | Keycloak 委派的設定，以及委派測試用的瀏覽器式登入 |
| `poc/common/trace.py` | 每一段都帶著 W3C trace context，寫到 `var/traces.jsonl`，也可以用 OTLP 送出 |
| `tests/` | 49 個驗收測試（搜尋、授權、核准、transaction token、Agent 請教 Agent、非同步 Task、trace、SDK Agent）、6 個 A2A 相容性測試、2 個搜尋測試、6 個 Keycloak 委派測試 |

所有 Agent 的資料都是模擬的，不會碰到任何真實系統。

## 怎麼跑

```bash
python -m poc demo          # 跑 12 個情境，最後印出一條完整 trace
python -m unittest -v       # 約 20 秒；需要選用套件或 Keycloak 的測試會自動略過
```

demo 會看到：

1. 一般 runtime 只拿到 `whoami`；負責分派的 runtime 才會多拿到 Registry 的工具。
2. alice（分析部）請 Agent 分析晨會報表。`invoke_agent` 馬上回傳 task id，讀一次 resource 就會等到 Task 完成。
3. bob 問同一件事。Agent 找得到，但標示為 `denied`，他會知道公司其實有這個能力。
4. bob 問天氣。沒有符合的 Agent，這和「沒有權限」是分開回報的。
5. carol 申請費用沒寫金額。Task 進入 `INPUT_REQUIRED`，她補上金額後完成。
6. dave 在財務部但沒有簽核角色。Gateway 回 `approval_required` 和一個核准申請編號，carol 會收到通知；她核准後 dave 再試就會通過，再下一次又需要新的核准。
7. 資安鑑識 Agent 是隱藏的。bob 搜不到也叫不到；erin（SecOps）可以用。
8. 同一個使用者改從另一個 runtime（報表 Agent 的）發出，會被委派政策擋下。
9. `cancel_task` 會取消 Task；讀取逾時則不會。
10. Agent 端出錯會變成 `FAILED`，不會被包成一段看起來正常的文字。
11. bob 輸入「下禮拜想休息兩天」。這句話裡沒有任何字出現在 Agent Card 上，但語意搜尋找得到請假 Agent（用官方 A2A SDK 寫的）。它反問要請哪幾天，拿到日期後送出申請。（需要選用套件）
12. alice 要報表分析，但說她的報表帳號被鎖了。報表 Agent 經過 Gateway 請教 IT 服務台 Agent（同一筆交易），把對方的回覆放進報告裡。

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

加上 transaction token 之後，我們用 Claude Code（Sonnet，`claude -p`）在兩種 Gateway 上各重跑了四個請求：alice 的報表分析（完成）、bob 的報表分析（看到 `denied` 就停，沒有硬試 `invoke_agent`）、bob 說「下禮拜想休息兩天」（靠語意找到請假 Agent，送出 12/3-12/4 的申請），以及 `whoami`（回報了 runtime 和交易編號）。兩種 Gateway 的工具呼叫順序和結果都一樣。

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
- 每個 Agent 有一條 A2A route，由政策決策服務（`poc/pdp.py`）透過 agentgateway 的 `extAuthz` 判斷。CEL 只能允許或回 403 拒絕；PDP 還能發起核准、對隱藏的 Agent 回 404，並說明拒絕原因。內建 Gateway 在程式內呼叫同一套邏輯。
- token exchange 用它內建的 `backendAuth.oauthTokenExchange`，對接 IdP。
- Transaction token：MCP route 也透過 `extAuthz` 呼叫 PDP。PDP 簽發這個請求的 Txn-Token，放在回應 header 裡，`includeResponseHeaders` 讓 agentgateway 把它加到轉給 Registry 的請求上，並蓋掉客戶端自己送的同名 header。

兩種 Gateway 都通過全部測試。目前還不一樣的地方：

| 行為 | 內建 Gateway | agentgateway |
|---|---|---|
| 政策改動生效 | 下一個請求就生效 | 工具規則：約 0.4 秒後，等設定檔重新載入。A2A 的判斷（PDP）：下一個請求就生效 |
| Gateway 的 span | 在 `var/traces.jsonl` | agentgateway 自己送到 OTLP 收集端（見下面的 Jaeger），不在 JSONL 裡 |
| Task 擁有者檢查 | Gateway 檢查一次，Agent 再檢查一次 | 只有 Registry 和 Agent 檢查；Gateway 看不到 Task 屬於誰 |
| 搜尋結果的權限提示 | Gateway 提供的端點 | Registry 自己讀 `policy.json` 判斷（只是提示，真正的判斷在 agentgateway） |
| 帶 `If-None-Match` 取 Agent Card | 回 `304 Not Modified` | 一律回完整的 card。agentgateway 1.7 會改寫 card 內容，Agent 回 304 時它回了 `503`，所以設定裡在 A2A 路由上拿掉條件式請求的 header |

我們實測時，Claude Code 透過 agentgateway 也能正常運作：`search_agents`、`invoke_agent`，再讀一次 resource。

## 核准流程

有些 Agent 對部分使用者需要先核准。`config/policy.json` 裡的 `approval_groups` 是誰可以申請，`approvers` 是誰可以核准。這裡 dave（財務部、沒有簽核角色）要用費用簽核 Agent，必須先經過 carol（有 `expense.approve`）核准：

```bash
python -m poc ask dave "幫我申請 3000 元交通費報銷"   # 被拒絕，拿到像 APR-1A2B3C 的編號
python -m poc approvals --as carol                    # carol 可以處理的申請
python -m poc approve APR-1A2B3C --as carol           # 或加 --reject
python -m poc ask dave "幫我申請 3000 元交通費報銷"   # 放行一次
```

申請人不能核准自己的申請，沒有核准資格的人也不能核准；申請還在等待時再問一次，會拿到同一個編號。搜尋結果會把這個 Agent 標成 `approval_required`；核准後、還沒用掉之前會標成 `allowed`。

一次核准只對一則完全相同的請求有效，不是對整個 Agent（這個做法參考 agentes.chat 的 tool gateway）：

- 核准會記下目標 Agent、要接續的 Task（如果有）和訊息內容的 SHA-256，以及給核准人看的文字（`python -m poc approvals` 裡的 `summary`，通知裡也會寫）。每次送出都會變的編號不算在內，所以原樣再送一次會對得上。
- 只有那一則訊息能用，一次，一小時內。dave 核准的是「800 元 計程車」，之後改成「80000 元 計程車」就是新的請求，要重新核准。拒絕訊息會寫出他手上的核准對應哪一則請求，換句話說的 AI 助理可以照原樣再送一次。
- 回答 Agent 的追問也要另外核准。費用 Agent 問 dave 金額時，金額正是 carol 要看到的內容，所以 dave 的回答會開一張新的核准申請，寫明是哪個 Task、多少錢。
- 送出核准過的訊息時會重新檢查權限，核准不會蓋過之後的變更：等待期間 dave 被拿掉可以申請核准的群組，或這個 Agent 對他變成隱藏，他就會被拒絕（或被告知沒有這個 Agent），而且核准不會被用掉。
- 沒人處理的申請 24 小時後失效。

通知：申請一建立，所有能核准的人都會收到一則通知；核准或拒絕後，申請人也會收到。通知會進收件匣（`python -m poc inbox --as carol`，或 PDP 的 `GET /notifications`）。設定 `POC_APPROVAL_WEBHOOK` 為 Slack 或 Mattermost 的 incoming webhook 網址，每則通知也會用 JSON（有 `text` 欄位）送過去。送失敗會重試最多 5 次、間隔越來越長，所以聊天服務掛掉只會讓通知晚到，不會弄丟。誰能核准是查 `config/users.json`；正式環境應該查公司的目錄服務。

## 接上真的 Keycloak

`keycloak/docker-compose.yml` 會在 `127.0.0.1:18080` 跑 Keycloak 26.8.2，並從 `keycloak/realm-poc.json` 匯入 realm `poc`。這個檔案是用 `config/users.json` 和 `config/policy.json` 產生的（`python -m poc.keycloak_realm`），所以使用者、群組、角色和 client 都跟模擬 IdP 一致。所有示範帳號的密碼都是 `dev-password`。

```bash
docker compose -f keycloak/docker-compose.yml up -d     # Docker 裝在 WSL 的話，在 WSL 裡執行
POC_IDP=keycloak python -m poc demo
POC_IDP=keycloak POC_GATEWAY=agentgateway python -m unittest -v
```

接起來之後發現的事：

- Keycloak 正式版（GA）的 token exchange 不會加 `act` claim，換發後 token 的 `azp` 會變成提出換發的那個服務。從第二跳開始，token 裡就看不出請求是從哪個 runtime 發起的，但委派政策需要這個資訊。Keycloak 支援委派的功能（`token-exchange-delegation`）目前還是 Preview。
- 所以 Keycloak 只負責每一跳的 access token，發起的 runtime 改放在 transaction token 裡（見下一節）。舊版是用每個 runtime 一個 client scope、把 `origin_client` claim 一路帶下去；但 agentgateway 沒辦法要求這種 scope（它的 `additionalParams` 不允許 `scope`），這也是改掉這個做法的原因之一。
- Keycloak 會拒絕 Registry 換發 Agent 的 token（`Requested audience not available`），因為只有 Gateway 有那些 audience。這和模擬 IdP 的規則一樣。

四種組合（模擬 IdP 或 Keycloak，內建 Gateway 或 agentgateway）都通過全部測試。Claude Code 接 Keycloak + agentgateway 也能正常運作，用 `whoami` 回報的是 Gateway 認定的身分。

### Keycloak 委派（`act` claim）

compose 檔也開啟了 Keycloak 的 `token-exchange-delegation` 預覽功能（加上 `parameterized-scopes` 和 FGAP v2 權限）。`tests/test_keycloak_delegation.py` 驗證它實際的行為：

```bash
POC_IDP=keycloak python -m unittest tests.test_keycloak_delegation -v
```

- 使用者走瀏覽器登入流程，要求 `delegation:client:agent-gateway` 並在同意畫面按下同意，token 裡就會有 `may_act`。測試會像真人一樣填登入表單、按同意。
- agent-gateway 帶著自己 service account 的 token 當 `actor_token` 去換發，就能拿到帶 `act: {client_id: agent-gateway}` 的 token，audience 可以是它被允許的任何對象（Registry 或某個 Agent）。
- 別的 client 不能拿這份同意來用。如果沒有幫 actor 設委派權限，`may_act` 會被默默拿掉，登入照樣成功。
- 帶 `act` 或 `may_act` 的 token 不能再被換發，一般換發和委派換發都不行。所以 `act` 只能記一個執行者，串不成 gateway > registry > gateway > agent 這樣的鏈。只有拿著使用者原始 token 的那一方能換出委派 token。
- 一般換發會拒絕帶 `may_act` 的使用者 token，所以委派和 PoC 每一跳用的一般換發不能用在同一個 token 上。

結論：委派適合單跳，也就是一個 Agent 直接代替使用者做事。多跳流程 PoC 改用 transaction token。

## Transaction token：每一跳都知道是誰發起的

一個請求會經過 runtime > Gateway > Registry > Gateway > Agent。每一跳都向 IdP 換一張只給那一跳用的 access token。這些 token 看得出使用者是誰，但換發一次之後就看不出是哪個 runtime 發起的，而委派政策需要這個資訊。`poc/txn.py` 照 IETF 草案 OAuth Transaction Tokens（draft-ietf-oauth-transaction-tokens）實作：

- Gateway 是信任範圍的入口。runtime 每送一個 MCP 請求，Gateway 就向 Txn-Token 服務要一張短效（5 分鐘）、有簽章的 token，裡面有使用者（`sub`）、runtime（`tctx.origin_client`）、用途（`scope`，也就是發起的 MCP 工具）和一個交易編號（`txn`）。
- 這張 token 放在 `Txn-Token` header，原封不動地經過 Gateway > Registry > Gateway > Agent。Registry 和 Agent 沒收到就拒絕，也會確認它跟 access token 是同一個使用者。
- 只有 Gateway 能申請，而且只能拿外部來的 token 申請（拿發給 Registry 的 token 去申請會被拒絕）。runtime 自己帶 `Txn-Token` header 會被忽略，Gateway 會重新簽一張。
- 用途會限制 Registry 能做的事：處理 `search_agents` 時不能建立 Task；`invoke_agent` 才能建立，`provide_input` 只能接續既有的 Task，讀 Task resource 只能呼叫 `GetTask`。
- 每個 span 都記錄交易編號，就算分成好幾條 trace，也能用同一個編號把稽核紀錄串起來。

以上每一點都有測試，四種 IdP/Gateway 組合都通過。這裡的 Txn-Token 服務是我們自己照草案寫的小型實作，Keycloak 和 agentgateway 目前都還沒有內建。

## Agent 請教 Agent

Agent 可以代表同一個使用者，請另一個 Agent 幫忙（`poc/agents/base.py` 的 `ctx.consult(agent_id, text)`）。示範裡，使用者說報表帳號被鎖時，報表 Agent 會去問 IT 服務台。這個呼叫一定經過 Gateway：

1. Agent 把收到的 token（audience 是 `agent:<自己>`）以 client `agent:<自己>` 換成給 Gateway 的 token。模擬 IdP 和 Keycloak realm 裡每個 Agent 都有這個 client，而且只能換發寄給自己的 token。
2. 帶著這張 token 和收到的 Txn-Token，呼叫 Gateway 上另一個 Agent 的 A2A 路由。
3. Gateway 向 Txn-Token 服務申請替換 token（草案 7.4 節）：交易、使用者、runtime 不變，把呼叫的 Agent 加進 `tctx.agents`。只有 Gateway 能申請替換。
4. 政策把呼叫的 Agent 當成呼叫者，套用它自己的 `delegation` 規則（報表 Agent 可以問 IT 服務台；IT 服務台不能問任何人）。它會拒絕循環（已經在鏈上的 Agent，包含 runtime 對應的 Agent），也會拒絕超過 `config/policy.json` 裡 `delegation_limits.max_agent_depth` 的鏈（預設 2：一個 Agent 問第二個，第二個還能再問一個）。鏈上每個 Agent 都還要符合使用者本人的權限。

每個 span 都記錄委派鏈（`agent_chain`）和交易編號。測試涵蓋完整流程、沒有委派規則的 Agent、循環、層數上限、沒帶 Txn-Token 的呼叫，以及 Agent 想自己申請替換 token。限制：Gateway 相信收到的 token 裡的鏈，所以 Agent 如果留著之前某個 Task 的 token（鏈比較短），在它有效期間（最多 5 分鐘）可以拿來重用。

## 在 Jaeger 看完整的 trace

每個元件都會把 span 寫到 `var/traces.jsonl`（`python -m poc trace` 可以印出來）。如果要在同一個畫面看一個請求經過的所有服務，包含 agentgateway 自己的 span，就啟動 Jaeger 並讓 PoC 送過去：

```bash
docker compose -f observability/docker-compose.yml up -d        # Jaeger 畫面在 http://127.0.0.1:16686
POC_OTLP_ENDPOINT=http://127.0.0.1:4318 POC_GATEWAY=agentgateway python -m poc up
POC_OTLP_ENDPOINT=http://127.0.0.1:4318 python -m poc ask alice "幫我分析今天晨會報表的良率異常"
```

實測一個請求會變成一條 trace：57 個 span、6 個服務（frontend、runtime、agentgateway、registry、PDP、agent），只有一個起點，中間沒有斷掉。要做到這樣，有兩件事要處理：

- agentgateway 是從 HTTP 的 `traceparent` header 讀 trace，不看 MCP 的 `params._meta`，所以 runtime 兩邊都要帶。只帶 `_meta` 的話，一開啟 agentgateway 的 tracing，每個 tool call 都會變成新的一條 trace。
- agentgateway 大約每 5 秒批次送一次 span。如果馬上把它關掉，最後一批會遺失，所以有設定 OTLP 時，launcher 會先等一下再關。

agentgateway 1.7 已經把 `config.tracing` 標為過時，產生的設定改用 `frontendPolicies.tracing`。

## 語意搜尋（選用）

裝了 `fastembed` 之後，`search_agents` 會把關鍵字搜尋（BM25）和一個小型多語言模型（`paraphrase-multilingual-MiniLM-L12-v2`，約 220 MB，第一次用時下載到 `.cache/fastembed`）的向量搜尋合在一起。Agent Card 裡每個 skill、每個範例句都各自轉成向量，兩邊的結果再依排名合併。結果裡的 `search_mode` 會寫是用哪種方式。`POC_SEARCH=keyword` 可以關掉，`hybrid` 則是一定要用。

在示範目錄上實測的效果：

- 「從家裡沒辦法連上公司內網」跟 VPN 那個 skill 沒有共同關鍵字，現在找得到 IT 服務台（相似度 0.64）。
- 「上週出差的計程車錢要怎麼拿回來」找得到費用簽核 Agent（0.44）。
- 無關的問題（天氣、午餐、股價）都在 0.40 以下，低於門檻 0.42，所以「沒有符合的 Agent」照樣成立。

有些相近但不對的會被找出來：「幫我訂明天下午的會議室」對請假 Agent 是 0.52，「幫我訂高鐵票」對費用簽核是 0.52。呼叫端還是會看到 Agent 的說明自己判斷，權限也還是由 Gateway 決定。正式的目錄要準備自己的一組測試問題來訂門檻。

## 用官方 A2A SDK 寫的 Agent（選用）

`poc/agents/sdk_agent.py` 是一個請假 Agent，用官方 A2A Python SDK（`a2a-sdk` 1.3.1）寫成：用 SDK 的 agent executor、task store 和 JSON-RPC 路由，由 uvicorn 執行。前面加了一層小小的 ASGI middleware，檢查跟其他 Agent 一樣的兩張 token（給 `agent:hr-leave` 的 access token 和 Txn-Token），再把使用者交給 SDK；SDK 的 task store 會把每個使用者的 Task 分開。

其他部分完全不用改：Registry 找得到它，兩種 Gateway 都管得到它，trace 也串得起來，Claude Code 也能用。SDK 有一條規則要注意：executor 一定要先送出 Task 本身，才能更新狀態，不然 SDK 會讓這個請求失敗。

## A2A 相容性測試（TCK）

A2A 專案有一套官方相容性測試：[A2A TCK](https://github.com/a2aproject/a2a-tck)。`poc/tck_sut.py` 用 PoC 的 A2A server 實作 TCK 要求的行為，CI 每次都會跑 TCK（JSON-RPC）：

```bash
python -m poc.tck_sut --port 18199
# 在 a2a-tck 的 clone 裡（需要 Python 3.15，可以用 uv 安裝）：
python run_tck.py --sut-host http://127.0.0.1:18199 --transport jsonrpc
```

第一次跑有 53 個失敗。大部分是同一個 bug（`POST /a2a/` 多一個斜線就 404），其他是真的不相容，已經修好：

- 用 proto 欄位原名送的參數（`history_length` 而不是 `historyLength`）會被忽略，但 proto3 JSON 兩種都允許。現在 Gateway 和 PDP 也用跟 Agent 一樣的方式讀，所以 `task_id` 和 `taskId` 在整條路上不會被判斷成不同的東西。
- streaming、push notification、extended card 這些方法回的是「找不到方法」（-32601），應該是「不支援的操作」（-32004）或「不支援 push notification」（-32003）。
- 訊息裡有 Agent 不接受的 media type 時，應該用 -32005 拒絕，原本照單全收。
- Agent Card 沒有 `Cache-Control` 和 `ETag` header。

現在：0 個失敗，55 個 MUST 項目通過。沒測到的有：gRPC 和 HTTP+JSON（這個 server 只提供 JSON-RPC）、streaming，以及驗證相關的要求（這版 TCK 沒有這部分的自動測試）。

TCK 也會經過兩種 Gateway 各跑一次（`python -m poc.tck_sut --via-gateway`，用 `POC_GATEWAY` 選 Gateway）。這會起一整套服務，測試用的 Agent 放在 Gateway 後面，token 檢查都是真的。TCK 沒辦法帶憑證，所以前面放一個測試用的小 proxy，幫每個請求加上 alice 的 token。兩種 Gateway 的結果都跟直接打 Agent 一樣：0 個失敗。這樣跑抓到內建 Gateway 的兩個缺口（沒有 `/a2a/` 的路由、轉出去的 card 沒有快取 header），以及上面 agentgateway 碰到 304 的問題。CI 三種都會跑：直接、內建 Gateway、agentgateway。

## 選用：讓 Agent 用真的 LLM 回答

預設 Agent 回固定的文字，測試結果才會穩定。設定 `POC_LLM=claude` 後，Agent 的回覆和 demo runtime 挑選 Agent 都會改用本機的 `claude` CLI（走你的 Claude 訂閱，不需要 API key）。`POC_LLM_MODEL` 可以換模型，預設 `sonnet`。

## 設定

| 環境變數 | 預設 | 說明 |
|---|---|---|
| `POC_SPEED` | `1.0` | 模擬 Agent 工作時間的倍率 |
| `POC_RESOURCE_WAIT` | `20` | 一次 Task resource 讀取最多等幾秒；要小於 MCP client 的逾時設定 |
| `POC_OTLP_ENDPOINT` | 空 | trace 的 OTLP/HTTP 收集端，例如 `http://127.0.0.1:4318`（Jaeger） |
| `POC_SEARCH` | `auto` | `keyword`，或 `hybrid` 一定要用語意搜尋；`auto` 是有裝 `fastembed` 就用 |
| `POC_APPROVAL_WEBHOOK` | 空 | 核准通知要送到哪裡（Slack 或 Mattermost 的 incoming webhook） |
| `POC_IDP` | `mock` | 設成 `keycloak` 就改用 18080 埠的 Keycloak，不用模擬 IdP |
| `POC_GATEWAY` | `builtin` | 設成 `agentgateway` 就改用 agentgateway 執行檔，不用 `poc/gateway.py` |
| `POC_AGENTGATEWAY_BIN` | `bin/agentgateway-windows-amd64.exe` | agentgateway 執行檔的路徑 |

連接埠設定在 `poc/settings.py` 和 `config/agents.json`（Gateway 18000、Registry 18200、PDP 18400、Txn-Token 服務 18500、模擬 IdP 18300、Keycloak 18080、Agent 18101-18105）。agentgateway 另外會開管理用的 15000、15020、15021 埠。

## 這個 PoC 沒有做的事

- 模擬 IdP 是替代品。它像 Keycloak 一樣簽 RS256 token 並公開 JWKS，但登入不檢查密碼，簽章金鑰是產生在 `var/` 裡的。Keycloak 的設定是開發模式，密碼和 secret 都是固定的。
- 語意搜尋用的是小模型，門檻是在五個 Agent 上手動調的，沒有在大型目錄上測過。
- Gateway 把 Task 的擁有者記在記憶體裡。重啟後，舊 Task 的 resource 會被拒絕；Registry 的對應表則會保留。
- 沒有 streaming、push notification、MCP Tasks。核准是透過一個簡單的 HTTP API 和 CLI 處理，有收件匣和 webhook 通知，但沒有核准網頁。
- Transaction token 依據的是還在變動的 IETF 草案。替換 token 只用來記錄 Agent 的委派；某一跳不能要求一張權限更小的。
- MCP 傳輸只回一般 JSON，沒有 SSE stream。
- 全部在同一個 process 裡用 thread 執行（啟用時另外加上 agentgateway 的 process）。各元件之間本來就走 HTTP，要拆成獨立服務並不難。如果直接砍掉 Python process 而不是按 Ctrl+C，agentgateway 的 process 可能會留著。
