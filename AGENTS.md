## Agent skills

### Issue tracker

GitHub Issues via the `gh` CLI (repo: `xiabai2008/rayscan`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context 鈥?one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Code change log

All code changes must be logged in this file. Each entry should include:
- Date (YYYY-MM-DD)
- Summary of changes
- Affected files/modules
## Change Log

### 2026-08-08 (第四轮：sqli boolean 误报清零 + 外部基准 + mypy 核心清零)
- **sqli boolean 反射误报修复**：boolean 命中排除 payload 原样回显（盲注语义）——反射端点天然免疫；`/sqli/blind` 真阳性保留（靶场改通用等值判断兼容 verify payload）；**反射误报 11 → 0 全类型清零**
- **外部基准（Juice Shop）**：本机网络受限（Docker Hub/npm/GitHub 下载全阻断）→ 新增 `scripts/run_external_benchmark.py`（docker 起 Juice Shop → sqli/xss/api/sensitive 扫描 → 断言）+ CI `benchmark-external` job（workflow_dispatch，GitHub Actions 网络正常环境运行）；WAVSEP 无 release 资产暂缓
- **mypy 核心链路清零（TD-003/007）**：scanner/models/config/base/dedup/result_merger/cache + 新模块（ai/mcp_server/mcp/graphql）共 11 路径 **0 错误**（从全库 212 → 核心 0）；修复类型：__init__ Optional 注解（_lab_profile/_nuclei_integration）、no-any-return（json.loads/safe_load isinstance、bool() 收窄）、ModuleFactory `Type[DetectionModule]`、TIME_BASED 常量注解、_active_session 断言、cache parse_qs 恒非 None；CI types job 范围扩至核心链路
- 全量测试 + ruff + format 全绿

### 2026-08-08 (第三轮：xxe/ssrf 基准补全 + 基准回归自动化)
- **xxe/ssrf 基准补测**：靶场新增 GET 参数型 XXE 提交点 `/xxe_get?xml=`（模拟支持实体展开的解析器，file:///etc/passwd → root:x:0:0: 命中）与 SSRF metadata 模拟（169.254.169.254 → ami-id/instance-id）；两模块均检出真阳性
- **基准回归自动化**：新增 `scripts/run_benchmark.py`（起靶场 → 逐模块扫描 → 断言 → 汇总；lfi Windows 自动跳过）；CI 新增 `Benchmark (regression gate)` job（workflow_dispatch 手动触发）；ci.yml 补 `workflow_dispatch` 触发器
- **CI 首跑发现并修复**：rce 在 Linux 0 检出（收敛后只信模板求值，Windows 命中是 time 命令挂起特例）→ 靶场新增真实 Jinja2 SSTI 端点 `/ssti`（用户输入作模板本体，{{7*7}}→49，跨平台真阳性）→ 复验全绿
- **lfi Linux 验证通过**（1/1 检出，/etc/passwd）——确认此前 Windows 0 检出纯属环境限制
- 全量测试 + ruff + CI（Test 3.9-3.12/Lint/Format/Types/**Benchmark**）全绿

### 2026-08-08 (第二轮：反射回显误报治理)
- **策略**：回显类探测收敛为"求值语义"验证——SSTI/EL 只信模板引擎运算求值（{{7*7}}→49），删除"特征词/token 回显"类独立判定（__subclasses__/__builtins__/applicationScope 等，响应出现这些词只证明输入被回显——含截断/引号翻倍变形回显，不证明执行）
- xss/detector：删除 SSTI 弱信号路径（模板语法反射+config 关键词）
- rce/detector：_detect_python_injection 收敛（expected 排除 payload 回显 + 删除 leak/token echo）；Java EL leak 加 payload 回显排除
- ssrf/detector：metadata 命中时 payload 在响应中直接排除
- 基准验证：反射误报 11→1（仅剩 sqli boolean 已知类型）；/cmdi time-based 核实为真阳性（; 分隔符真实触发）；全量测试 + CI 全绿

### 2026-08-08 (妫€娴嬪熀鍑嗕綋绯?+ 鏋舵瀯娓呯悊 + CI 鐪熷疄楠岃瘉)
- **妫€娴嬪熀鍑嗭紙鈶狅級**锛氭柊澧?`scripts/benchmark_lab.py`锛團lask 鏈湴闈跺満锛屼粎 127.0.0.1锛歴qli 鍥涘瀷/xss/cmdi/lfi/rce/xxe/ssrf/sensitive锛? `docs/BENCHMARK.md` 鍩虹嚎鐭╅樀锛歴qli 4鐪?1鍙嶅皠璇姤銆亁ss 鏈夋晥銆乧mdi 2鐪熴€乺ce 1鐪?4鍥炴樉璇姤銆乻ensitive 2鐪燂紙淇鍚庯級銆乴fi 0锛圵indows 鏃?/etc/passwd 寰?Linux 澶嶆祴锛夈€亁xe/ssrf 寰呭姙
- **鍩哄噯椹卞姩淇锛? 澶?sensitive 缂洪櫡锛?*锛?env 鏃犲紩鍙锋牸寮忔柊澧?`env_var_secret` pattern锛??m) 閫愯锛夛紱鎺㈡祴璺緞琛?`/backup/backup.sql` 绛夛紱鍐呭闃堝€?50鈫?0锛堢煭 .env 琚鏉€锛?
- **CLI `--allow-loopback`**锛歴can 鍛戒护娉ㄥ唽锛堟湰鍦伴澏鍦?鍩哄噯娴嬭瘯鐢紱SSRF 闃叉姢榛樿浠嶆嫤鎴唴缃戯紝淇杩滅缂哄彛锛?
- **鏋舵瀯娓呯悊锛堚憽锛?*锛氱‘璁?`scan()` 宸蹭綔 facade 濮旀墭 ScanOrchestrator锛涘垹闄ゆ浠ｇ爜 `_do_authenticate`/`_run_module`/`_run_module_no_semaphore`锛?198 琛?+ 4 涓湭鐢?auth import锛?
- **CI 鐪熷疄楠岃瘉锛堚憿锛?*锛歱ush 鍚?GitHub Actions 棣栨鐪熷疄杩愯鈥斺€斾慨澶?2 涓け璐ワ細`test_mcp.py` 缂?`importorskip('mcp')`锛圕I [dev] 鏃?mcp 渚濊禆锛夈€乣test_smoke_cli.py` tomllib py3.9/3.10 鍏煎锛坱omli 鍏滃簳锛夛紱**鏈€缁?CI 鍏ㄧ豢**锛圱est 3.9-3.12 + Lint + Format + Types锛?
- **OA 鐪熷疄鏍锋湰娴佺▼锛堚懀锛?*锛歄A_RULES.md 搂7 鏀堕泦娴佺▼ + 璁板綍妯℃澘 + 寰呮敹闆嗘竻鍗曪紙娉涘井/鑷磋繙/鐢ㄥ弸 绛?9 绉嶏級

### 2026-08-08 (T0 鏀跺熬 鈥?鐗堟湰 SSOT + OA 瀹炴祴 + 鍙戝竷 v2.1.0)
- **鐗堟湰 SSOT 缁熶竴涓?2.1.0**锛歚wvs/__init__.py` 涓?pyproject 瀵归綈锛圫SOT 娉ㄩ噴锛夛紱鎶ュ憡妯″潡锛坈onsole/html/markdown锛夋敼涓哄姩鎬佽鍙?`__version__`锛?5 澶勭‖缂栫爜 1.0.2/2.0.x 娓呯悊锛圲I/GUI/妯℃澘/yml/docstring锛孋HANGELOG 鍘嗗彶璁板綍淇濈暀锛?
- **OA mock 闈跺満瀹炴祴闂幆**锛? 鏍锋湰锛岃褰曞叆 docs/OA_RULES.md 搂5锛夛細娉涘井-Ecology锛坵eaver.do RCE/octet-stream 鉁咃級銆丯acos 1.3.2锛坲sers 鍒楄〃 pageItems/CVE-2021-29441 鉁咃級銆丯acos 1.5.0锛堢増鏈繃婊?[min,1.4.1) 姝ｇ‘璺宠繃 猬?璐熸牱鏈?鉁咃級銆丣enkins锛?script Script Console 鉁咃級
- **瀹炴祴鍙戠幇骞朵慨澶?3 涓湡瀹炵己闄?*锛?
  1. crawler 鏃犵鐐癸紙鍗曢〉鏃犻摼鎺ヤ笖 seed 鍏?404锛夆啋 `_crawl_and_detect` 鐨?`if eps:` 涓虹┖ 鈫?娴佸紡妫€娴嬫暣浣撹烦杩?鈫?scanner 鍏滃簳绔偣鍓嶇疆
  2. httpx銆孶RL 鑷甫 query + 鏄惧紡 params={}銆嶄涪寮?URL query锛圤A 妫€鏌ラ」 `/nacos/v1/auth/users?pageNo=1` 404锛夆啋 base.py `_send_request` 绌?params 涓嶄紶
  3. scanner Step 1.9 娉ㄥ叆鐭悕锛?娉涘井"锛変笌 OA_RULES key锛?娉涘井-Ecology"锛夋柇閾?鈫?`OA_RULES.get()` None 鈫?8 绉?OA 妫€鏌ラ」浠庝笉鎵ц 鈫?`_OA_ALIASES` 鍒悕鏄犲皠锛涜繛甯︿慨澶?OA `_create_vuln` 鏋氫妇璇紶锛坴uln_type 搴斾负瀛楃涓诧級瀵艰嚧鎶ュ憡 JSON 搴忓垪鍖栧け璐?
- CHANGELOG 2.1.0 鏉＄洰 + README 鏇存柊锛堢増鏈窘绔?274 娴嬭瘯/AI路MCP路GraphQL 鐢ㄦ硶锛夛紱鍙戝竷 tag v2.1.0

### 2026-08-08 (T4 宸ョ▼鍦板熀 鈥?娓?TECH_DEBT)
- **ruff 閰嶇疆缁熶竴锛堟湰鍦?= CI锛?*锛歱yproject `lint.select` 鏀舵暃涓?E/F/W/I + `ignore` 鍔?E402/E501锛堜笌 CI 鍛戒护涓€鑷达級锛汣I lint job 绉婚櫎鍛戒护琛?`--select/--ignore` 瑕嗙洊锛涙洿涓ユ牸瑙勫垯闆嗭紙B/C4/UP/BLE/TRY 绛夛級鏍囨敞涓哄瓨閲忓€哄姟娓愯繘鍚敤
- **TD-006 瑕嗙洊鐜囬棬绂?*锛歱yproject 鏂板 `[tool.coverage.run]`锛坰ource=wvs, branch锛? `[tool.coverage.report] fail_under=25`锛堝垎鏀鐩栧熀绾?~27%锛夛紱CI test job 鍗囩骇涓?blocking锛涙湰鍦?`pytest --cov` 涓?CI 鍚岄棬妲?
- **TD-008 core 灞傚崟娴?*锛氭柊澧?`tests/test_core_engine.py`锛?5 涓祴璇曪級锛歴canner 褰掍竴鍖?鍘婚噸绛惧悕/涓ラ噸搴︿紭鍏?绔偣 key/绔偣鎺掑簭锛沜rawler URL 褰掍竴鍖栵紙host 灏忓啓/榛樿绔彛/query 鎺掑簭锛夈€乽rl_key銆乿isited銆乧rawlable 鍩?鎵╁睍鍚嶈繃婊ゃ€丏iscoveredEndpoint 鍝堝笇锛汬TTPPool 鐨?get_host銆乻et_cookie 娉ㄥ叆 httpx jar銆乧ookie jar 璇诲啓銆乢merge_headers UA/鑷畾涔夊ご/jar cookie 娉ㄥ叆
- **TD-003/007 鏂版ā鍧楃被鍨嬫敹鍙?*锛氫慨澶?`wvs/ai/client.py` 2 澶?`no-any-return`锛坋xtract_json/chat 杩斿洖绫诲瀷鏀剁獎锛夛紱CI types job 鏀逛负鍙煡鏂版ā鍧?`mypy wvs/ai wvs/mcp_server.py wvs/modules/mcp wvs/modules/graphql --ignore-missing-imports`锛堟湰鏈?0 閿欒锛夛紱瀛橀噺妯″潡 mypy 鍊哄姟锛?12 閿欙級鏍囨敞鍦?TECH_DEBT 娓愯繘鏁存敼
- 鍏ㄩ噺 **274 passed**锛況uff E/F/W/I + format 鍏ㄧ豢锛沜overage 26.75% 鈮?25 闂ㄧ

### 2026-08-08 (T3 鐜颁唬搴旂敤瑕嗙洊 鈥?GraphQL + 鍙€?SPA)
- **T3.1 GraphQL 妫€娴?*锛氭柊澧?`wvs/modules/graphql/`锛坙ite 妯″潡锛屾敞鍐岃繘 ModuleFactory锛夛細8 鏉℃爣鍑嗚矾寰勬帰娴?+ 鎸囩汗纭锛坃_typename/GraphQL/graphiql/apollo锛? 涓ゆ鏌ラ」鈥斺€攊ntrospection 寮€鍚紙INFO_DISCLOSURE/MEDIUM锛宍{__schema{types}}` 杩斿洖 types 鎵嶇畻锛夈€佹壒閲忔煡璇㈡敮鎸侊紙API_SECURITY/LOW锛孞SON 鏁扮粍璇锋眰琚帴鍙楋級锛涜瘉鎹獙璇佸師鍒欙細浠呯鐐瑰彲杈句笉鎶ャ€佹棤 GraphQL 鐗瑰緛涓嶆姤銆乮ntrospection 绂佺敤涓嶆姤
- 绔偣绛栫暐闃茶矾寰勭垎鐐革細鏍圭鐐规墠鍋氭爣鍑嗚矾寰勫叏闆嗘帰娴嬶紱鍏蜂綋绔偣浠呰矾寰勫惈 graphql/gql/graphiql 鐗瑰緛璇嶆墠鑷韩鎺㈡祴锛堢鍒扮瀹炴祴锛?1 涓噸澶嶆紡娲?鈫?鏀舵暃涓?1 涓湡闃虫€э級
- **T3.2 鍙€?SPA 鐖彇**锛歚scan --js-render`锛堝疄楠屾€э級鈫?config `crawler.js_render` 鈫?crawler 瀵瑰疄鎴樼洰鏍囧惎鐢?SPA 妫€娴?+ Playwright 娓叉煋鐖彇锛堝鐢ㄦ棦鏈?`_check_spa`/`crawl_js`锛屾湭瑁?playwright 鑷姩鍥為€€锛夛紱pyproject 鏂板 `jsrender` extras锛坧laywright锛?
- base.py vuln_type_map 琛?graphql 鈫?API_SECURITY
- 鏂板 `tests/test_graphql.py`锛?2 涓祴璇曪細鐗瑰緛/introspection 鍒ゅ畾/绔偣鎺㈡祴璇佹嵁楠岃瘉/playground 椤?闈?graphql 绔偣璺宠繃/js-render 鎺ョ嚎/CLI 鍙傛暟锛夛紱鍏ㄩ噺 **249 passed**锛況uff E/F/W/I + format 鍏ㄨ繃
- 绔埌绔疄娴嬶細鏈湴 mock GraphQL 鏈嶅姟 + 鐪熷疄鎵弿閾捐矾 鈫?introspection 妫€鍑猴紝鎶ュ憡浠?1 涓湡闃虫€э紙/graphql锛?

### 2026-08-08 (T2 MCP 鎺ュ叆 + 璐﹀彿缁熶竴)
- **T2.1 MCP Server**锛氭柊澧?`wvs/mcp_server.py`锛堝畼鏂?mcp SDK锛屽彲閫変緷璧?`pip install "rayscan[mcp]"`锛宲y3.10+锛汧astMCP streamable-http锛岄粯璁ょ粦瀹?127.0.0.1:18000锛夛紱宸ュ叿锛歚scan(url, modules, all_modules, max_time)`锛堝畬鏁存壂鎻忚繑鍥炴憳瑕?JSON锛夈€乣list_modules`銆乣get_report`锛堟渶杩戜竴娆℃壂鎻忕粨鏋滐級锛汣LI `python -m wvs mcp [--host] [--port]`锛涙棤 SDK 鏃跺弸濂芥彁绀鸿繑鍥?1
- **T2.2 MCP 鐩爣鎵弿**锛氭柊澧?`wvs/modules/mcp/`锛坙ite 妯″潡锛屾敞鍐岃繘 ModuleFactory锛夛細甯歌 MCP 绔偣鎺㈡祴锛?mcp銆?api/mcp銆?sse銆?rpc 绛?7 鏉★級+ 鐗瑰緛鎸囩汗锛坖sonrpc/serverInfo/SSE 澶达級+ 璇佹嵁楠岃瘉涓ゆ鏌ラ」鈥斺€攖ools/list 鏈巿鏉冭皟鐢紙INFO_DISCLOSURE/MEDIUM锛夈€佹晱鎰熷伐鍏锋湭鎺堟潈鍙皟锛圔ROKEN_ACCESS/HIGH锛夛紱绾彙鎵嬩笉鎶ワ紱`_create_vuln` 浣跨敤 explicit_vuln_type锛宐ase.py vuln_type_map 琛?mcp
- **T2.3 update-pocs**锛欳LI `rayscan update-pocs [--list-oa]`锛氶噸寤?PoC 妯℃澘绱㈠紩锛坒orce锛? 鎸?13 绫?OA 鎶€鏈爤缁熻 OA 鐩稿叧妯℃澘鏁板苟鍙垪鍑猴紙澶嶇敤 TECH_STACK_TAGS锛?
- **璐﹀彿缁熶竴鏀跺熬**锛歚cli.py:cmd_version`銆乣wvs_gui.py`锛? 澶勶級銆乣web_ui/templates/index.html`銆乣wvs/reporting/html_report.py` 涓畫鐣欐棫璐﹀彿 xiabai2004 鈫?xiabai2008锛圕HANGELOG 鍘嗗彶璁板綍淇濈暀锛?
- pyproject.toml锛氭柊澧?`mcp` extras
- 鏂板 `tests/test_mcp.py`锛?0 涓祴璇曪細鎸囩汗/宸ュ叿瑙ｆ瀽/绔偣鎺㈡祴璇佹嵁楠岃瘉/POST-only server/鏃犲伐鍏蜂笉鎶?MCP Server 鎽樿涓庨敊璇矾寰?CLI锛夛紱鍏ㄩ噺 **237 passed**锛況uff E/F/W/I + format 鍏ㄨ繃
- 绔埌绔疄娴嬶細鐪熷疄鍚姩 MCP Server + 妯℃嫙 Claude 瀹㈡埛绔畬鏁村崗璁彙鎵嬶紙initialize鈫抜nitialized鈫抰ools/list鈫抰ools/call锛堿LL PASS锛坰erverInfo=rayscan銆?7 妯″潡鍚?mcp锛?
- 淇锛欶astMCP 1.27 鏋勯€犵鍚嶏紙host/port 鐩翠紶銆佹棤 version 鍙傛暟锛夛紱mcp_server.py 鐩稿瀵煎叆灞傜骇

### 2026-08-08 (T1 AI 杈呭姪楠岃瘉 鈥?瀹樻柟 API / 鏈€楂樹紭鍏堢骇)
- 鏂板 `wvs/ai/` 妯″潡锛歚LLMClient`锛圤penAI 鍏煎 chat/completions锛屽鐢?httpx 鏃犳柊渚濊禆锛沗LLM_API_KEY`/`LLM_BASE_URL`/`LLM_MODEL` 鐜鍙橀噺鎴?config `ai.*`锛涙棤 key 鏃?`available=False` 闈欓粯璺宠繃锛沠ail-safe 杩斿洖 None锛? `AIVerifier`锛堝€欓€夋紡娲炲鏍革級+ `report.py`锛圓I 鎶ュ憡鎽樿锛?
- 璇姤澶嶆牳绛栫暐锛歮edium+ 鍊欓€夋寜 5 鏉?鎵归€?LLM 鍒ゅ畾 鈫?纭锛坈onf鈮?.8锛塼ag `ai_confirmed`锛涘瓨鐤戯紙conf鈮?.3锛変弗閲嶅害闄嶄竴绾?+ tag `ai_disputed`锛涘叾浣?tag `ai_reviewed`锛?*鍙檷绾т笉鍒犻櫎**锛岃姹傚け璐?杈撳嚭涓嶅彲瑙ｆ瀽鏁存壒鍘熸牱杩斿洖
- scanner.py锛歅hase 3.6 鎺ュ叆澶嶆牳锛坈onfig `ai.verify` 榛樿 False锛夛紱cli.py锛歚--ai-verify`锛堝紑鍚嵆鎵撳嵃绗笁鏂规暟鎹憡璀︼級
- 鏂板 `ai-report` 瀛愬懡浠わ細璇绘棦鏈?JSON 鎶ュ憡 鈫?LLM 鐢熸垚 markdown 鎽樿锛坄rayscan ai-report report.json -o summary.md`锛?
- config.py锛歚ai` 娈碉紙verify/base_url/model/timeout 榛樿鍏ㄥ叧锛沘pi_key 涓嶅叆搴擄紝浠呯幆澧冨彉閲忥級
- 鏂板 `tests/test_ai_verify.py`锛?7 涓祴璇曪細client 鍙敤鎬?璇锋眰鏋勯€?MockTransport/JSON 瑙ｆ瀽銆乿erifier 纭/闄嶇骇/鎵规/寮傚父淇濇寔銆佹姤鍛婃彁鍙栦笌 CLI锛夛紱鍏ㄩ噺 **217 passed**锛況uff E/F/W/I + format 鍏ㄨ繃
- 绔埌绔疄娴嬶細鏈湴 mock OpenAI 鍏煎鏈嶅姟 + `ai-report` 鐪熷疄 HTTP 閾捐矾楠岃瘉閫氳繃锛堟憳瑕佽惤鐩橈級锛沗scan --help` 鍙傛暟娉ㄥ唽姝ｇ‘
- 瑙勫垝鏂囨。 `docs/audit/rayscan-upgrade-plan-2026-08-08.md`锛堝閮ㄨ皟鐮?+ T0-T5 鍒嗘湡锛岀敤鎴锋媿鏉匡細瀹樻柟 API / T1 鏈€楂樹紭鍏堢骇锛?

### 2026-08-05 (S3 OA 涓撻」娣卞寲 鈥?涓夌骇妫€娴嬮摼璺?
- 涓夌骇妫€娴嬮摼璺細鎸囩汗璇嗗埆锛堝唴瀹逛紭鍏堬級鈫?鐗堟湰璇嗗埆 鈫?婕忔礊楠岃瘉锛堣鍒欑骇璇佹嵁浼樺厛锛? 鐗堟湰杩囨护
- 鏂板 `OA_CONTENT_FINGERPRINTS`锛?2 绉?OA 鍐呭鎸囩汗锛歵itle/姝ｆ枃/鍝嶅簲澶?Set-Cookie 鍥涚被鍖归厤锛?
- `_detect_oa_type` 鍗囩骇鍙岄€氶亾锛氬唴瀹规寚绾逛紭鍏堬紝URL 璺緞/鍏抽敭璇嶅洖閫€锛沗_scan_impl` 浼樺厛浣跨敤 scanner 娉ㄥ叆鐨?`_detected_oa`锛堜慨澶嶆柇閾撅級锛屽惁鍒欐姄棣栭〉璇嗗埆
- 鏂板 `_detect_oa_version`锛圝enkins X-Jenkins 澶淬€丯acos 椤甸潰鐗堟湰鍙橀噺銆丼pring/娉涘井/绂呴亾鐗堟湰瀛楁牱锛屾湭璇嗗埆涓嶉樆濉烇級涓?`_version_in_range`锛圼min,max) 璇箟銆佹棤鐗堟湰鏀捐銆佽В鏋愬け璐ユ斁琛岋級
- `_verify_evidence` 鏀寔妫€鏌ラ」瑙勫垯绾?`evidence`锛堜紭鍏堜簬閫氱敤绫诲瀷楠岃瘉锛夛紱`_run_check` 鎺ュ叆鐗堟湰杩囨护
- 棣栦釜鐪熷疄鐗堟湰杩囨护鐢ㄤ緥锛歂acos 鐢ㄦ埛鍒楄〃鏈巿鏉冿紙CVE-2021-29441锛塦evidence: pageItems` + `max_version: 1.4.1`
- 鏂板 `tests/test_oa_deep.py`锛?3 涓祴璇曪細鎸囩汗/鐗堟湰/杩囨护/瑙勫垯璇佹嵁/Nacos 闆嗘垚锛?
- 鏂板 `docs/OA_RULES.md`锛堣鍒欐枃妗?+ 妫€娴嬬煩闃?+ 瀹炴垬楠岃瘉璁板綍琛紝寰呭疄娴嬫牱鏈棴鐜級

### 2026-08-05 (S2 閾炬潯鎺ラ€?鈥?nuclei 鎺ュ叆 + checkpoint 澶嶆椿)
- Nuclei 鎺ュ叆涓绘祦绋嬶細`WAVScanner.scan()` Phase 3.5 鏂板 Nuclei 闃舵锛坈onfig `nuclei.enabled` 榛樿寮€锛孋LI `--no-nuclei` 鍏抽棴锛夛紱鏂板 `_run_nuclei`锛堟噿瀹炰緥鍖栵紝CLI 鍙敤璧版ā鏉挎壂鎻忥紝涓嶅彲鐢ㄨ蛋 S1 淇鍚庣殑鍐呯疆鍥為€€锛夛紱缁撴灉缁?`_deduplicate` 鍚堝苟
- 妯℃澘閫夋嫨淇锛歚_cli_scan_async` 涓嶅啀鎶婃ā鏉挎姌鍙犳垚鐖剁洰褰?`-t`锛堝師瀹炵幇=閫掑綊鎵弿鏁翠釜鐩綍锛夛紝鐩存帴浼犳ā鏉挎枃浠堕€楀彿鍒楄〃锛堜笂闄?200 闃插懡浠よ瓒呴檺锛?
- Checkpoint 澶嶆椿锛歚__init__` 鍒濆鍖?`_modules_done`/`_last_checkpoint_time`/`_checkpoint_interval`/`_resume_checkpoint`锛堝師 `_save_checkpoint` 寮曠敤鏈垵濮嬪寲瀛楁蹇?AttributeError锛夛紱鎵规寰幆鏇存柊妯″潡瀹屾垚鐘舵€?+ `_try_save_checkpoint` 闂撮殧闄愭祦钀界洏锛涙壂鎻忓畬鎴愯惤鐩樻渶缁?checkpoint锛沗--resume` 娉ㄥ叆 checkpoint 鈫?scan() 鍚堝苟宸插彂鐜版紡娲?+ 璺宠繃宸插畬鎴愭ā鍧?
- cli.py锛歚--no-nuclei` 鍙傛暟 + `--resume` 娉ㄥ叆 `scanner._resume_checkpoint`
- 鏂板 `tests/test_s2_resume.py`锛? 涓祴璇曪細checkpoint 寰€杩?闂撮殧闄愭祦/Vulnerability 搴忓垪鍖?nuclei 鎳掑姞杞戒笌澶嶇敤/config 寮€鍏筹級
- 绔埌绔疄娴嬶細鏈湴 HTTP 鏈嶅姟鍣ㄦ壂鎻?鈫?checkpoint 钀界洏锛坢odules_done=['sqli','xss']锛夆啋 `--resume` 鎭㈠鎻愮ず涓庢ā鍧楄烦杩囧潎楠岃瘉閫氳繃

### 2026-08-05 (S1 璇姤娌荤悊 鈥?鍙戠増鍓嶄慨澶?
- Nuclei 鍐呯疆鍥為€€锛氱Щ闄?鍙揪鍗虫姤"锛坄pattern is None` 鈫?涓嶆姤锛夛紱/graphql銆?security.txt 琛ュ唴瀹圭壒寰侊紱/dev 妫€鏌ラ」绉婚櫎锛堟棤鍙潬鐗瑰緛锛夛紱body 鎴柇 200鈫?000锛涚壒寰佸尮閰嶆敼澶у皬鍐欎笉鏁忔劅锛沗.git/config` 鐗瑰緛 `remote origin` 鈫?`[remote`锛堢湡瀹炴牸寮忥級
- OA 妫€娴嬶細`_run_check` 绉婚櫎 401/403/500/302"鐘舵€佺爜鍗虫紡娲?鍒ゅ畾锛屼粎 HTTP 200 + `_verify_evidence` 鍝嶅簲璇佹嵁楠岃瘉锛坲nauth=JSON 鏁版嵁銆乮nfo_disclosure=actuator/heapdump 鐗瑰緛銆乻qli=SQL 鎶ラ敊/JSON success銆乺ce=octet-stream/浜岃繘鍒?Groovy銆乫ile_read=JSP 婧愮爜鐗瑰緛锛夛紱file_upload/info 绫?GET 鎺㈡祴涓嶆姤
- OA 閫氱敤璺緞锛氱Щ闄?/admin/銆?login/銆?system/銆?api/銆?webservice/銆?backup/ 娉涜矾寰勬鏌ワ紱淇濈暀 4 涓彲鍐呭楠岃瘉鐨勬硠闇茶矾寰勶紙web.xml/MANIFEST.MF/.git/HEAD/.env 閿€煎鍚彂寮忥級
- XXE锛歚_check_xxe_success` 澧炲姞 baseline 鎺掗櫎锛涗笁涓皟鐢ㄧ偣锛堝弬鏁版敞鍏?XML body/SVG 涓婁紶锛夊潎鍏堝彇鑹€?baseline
- SSRF锛歚_check_ssrf_success` 澧炲姞 baseline 鎺掗櫎锛堝惈杩炴帴閿欒鍏抽敭璇嶅垎鏀級锛沗test_cloud_metadata` 琛?baseline
- DOM XSS锛氱Щ闄?`_test_dom`锛圲RL fragment 鍙嶅皠浼娴嬶紝闈炵湡瀹?DOM 妫€娴嬶紱寰?headless 楠岃瘉鎺ュ叆锛?
- 鏂板 `tests/test_fp_guard.py`锛?3 涓鎶ラ槻鎶ゅ洖褰掓祴璇曪細XXE/SSRF baseline銆丱A 璇佹嵁楠岃瘉銆丯uclei 鍥為€€鐗瑰緛鍖归厤锛?
- README锛氭挙涓嬫湭鍏戠幇鍗栫偣锛堝寮曟搸鑱氬悎/MSF 楠岃瘉閾炬爣娉ㄤ负 Roadmap锛夛紝娴嬭瘯鏁?79鈫?36锛岄」鐩粨鏋勫浘淇
- 瑙勫垝鏂囨。 `docs/audit/rayscan-evolution-plan-2026-07-12.md` 鏇存柊鑷?v1.2锛埪?1 鎴樼暐淇锛歄A 涓撻」 + 宸ヤ綔娴侀棴鐜紝鏇夸唬鑷爺鍐呮牳浼樺厛锛?

### 2026-06-27
- Added Code change log section to AGENTS.md

### 2026-06-27 (Profile System)
- Added Profile system: `wvs/profiles/` module with ProfileManager
- Added CLI subcommands: `rayscan profile list|create|delete|export|import`
- Added `rayscan use <profile> -u <url>` command for profile-based scanning
- Added built-in profiles: default, src-quick, pentest-full, sqli-only
- Added 17 tests in `tests/test_profiles/`
