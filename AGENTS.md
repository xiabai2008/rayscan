## Agent skills

### Issue tracker

GitHub Issues via the `gh` CLI (repo: `xiabai2008/rayscan`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

### Code change log

All code changes must be logged in this file. Each entry should include:
- Date (YYYY-MM-DD)
- Summary of changes
- Affected files/modules

## Change Log

### 2026-08-08 (检测基准体系 + 架构清理 + CI 真实验证)
- **检测基准（①）**：新增 `scripts/benchmark_lab.py`（Flask 本地靶场，仅 127.0.0.1：sqli 四型/xss/cmdi/lfi/rce/xxe/ssrf/sensitive）+ `docs/BENCHMARK.md` 基线矩阵：sqli 4真+1反射误报、xss 有效、cmdi 2真、rce 1真+4回显误报、sensitive 2真（修复后）、lfi 0（Windows 无 /etc/passwd 待 Linux 复测）、xxe/ssrf 待办
- **基准驱动修复（3 处 sensitive 缺陷）**：.env 无引号格式新增 `env_var_secret` pattern（(?m) 逐行）；探测路径补 `/backup/backup.sql` 等；内容阈值 50→10（短 .env 被误杀）
- **CLI `--allow-loopback`**：scan 命令注册（本地靶场/基准测试用；SSRF 防护默认仍拦截内网，修复远端缺口）
- **架构清理（②）**：确认 `scan()` 已作 facade 委托 ScanOrchestrator；删除死代码 `_do_authenticate`/`_run_module`/`_run_module_no_semaphore`（-198 行 + 4 个未用 auth import）
- **CI 真实验证（③）**：push 后 GitHub Actions 首次真实运行——修复 2 个失败：`test_mcp.py` 缺 `importorskip('mcp')`（CI [dev] 无 mcp 依赖）、`test_smoke_cli.py` tomllib py3.9/3.10 兼容（tomli 兜底）；**最终 CI 全绿**（Test 3.9-3.12 + Lint + Format + Types）
- **OA 真实样本流程（④）**：OA_RULES.md §7 收集流程 + 记录模板 + 待收集清单（泛微/致远/用友 等 9 种）

### 2026-08-08 (T0 收尾 — 版本 SSOT + OA 实测 + 发布 v2.1.0)
- **版本 SSOT 统一为 2.1.0**：`wvs/__init__.py` 与 pyproject 对齐（SSOT 注释）；报告模块（console/html/markdown）改为动态读取 `__version__`；25 处硬编码 1.0.2/2.0.x 清理（UI/GUI/模板/yml/docstring，CHANGELOG 历史记录保留）
- **OA mock 靶场实测闭环**（4 样本，记录入 docs/OA_RULES.md §5）：泛微-Ecology（weaver.do RCE/octet-stream ✅）、Nacos 1.3.2（users 列表 pageItems/CVE-2021-29441 ✅）、Nacos 1.5.0（版本过滤 [min,1.4.1) 正确跳过 ⬜ 负样本 ✅）、Jenkins（/script Script Console ✅）
- **实测发现并修复 3 个真实缺陷**：
  1. crawler 无端点（单页无链接且 seed 全 404）→ `_crawl_and_detect` 的 `if eps:` 为空 → 流式检测整体跳过 → scanner 兜底端点前置
  2. httpx「URL 自带 query + 显式 params={}」丢弃 URL query（OA 检查项 `/nacos/v1/auth/users?pageNo=1` 404）→ base.py `_send_request` 空 params 不传
  3. scanner Step 1.9 注入短名（"泛微"）与 OA_RULES key（"泛微-Ecology"）断链 → `OA_RULES.get()` None → 8 种 OA 检查项从不执行 → `_OA_ALIASES` 别名映射；连带修复 OA `_create_vuln` 枚举误传（vuln_type 应为字符串）导致报告 JSON 序列化失败
- CHANGELOG 2.1.0 条目 + README 更新（版本徽章/274 测试/AI·MCP·GraphQL 用法）；发布 tag v2.1.0

### 2026-08-08 (T4 工程地基 — 清 TECH_DEBT)
- **ruff 配置统一（本地 = CI）**：pyproject `lint.select` 收敛为 E/F/W/I + `ignore` 加 E402/E501（与 CI 命令一致）；CI lint job 移除命令行 `--select/--ignore` 覆盖；更严格规则集（B/C4/UP/BLE/TRY 等）标注为存量债务渐进启用
- **TD-006 覆盖率门禁**：pyproject 新增 `[tool.coverage.run]`（source=wvs, branch）+ `[tool.coverage.report] fail_under=25`（分支覆盖基线 ~27%）；CI test job 升级为 blocking；本地 `pytest --cov` 与 CI 同门槛
- **TD-008 core 层单测**：新增 `tests/test_core_engine.py`（25 个测试）：scanner 归一化/去重签名/严重度优先/端点 key/端点排序；crawler URL 归一化（host 小写/默认端口/query 排序）、url_key、visited、crawlable 域/扩展名过滤、DiscoveredEndpoint 哈希；HTTPPool 的 get_host、set_cookie 注入 httpx jar、cookie jar 读写、_merge_headers UA/自定义头/jar cookie 注入
- **TD-003/007 新模块类型收口**：修复 `wvs/ai/client.py` 2 处 `no-any-return`（extract_json/chat 返回类型收窄）；CI types job 改为只查新模块 `mypy wvs/ai wvs/mcp_server.py wvs/modules/mcp wvs/modules/graphql --ignore-missing-imports`（本机 0 错误）；存量模块 mypy 债务（212 错）标注在 TECH_DEBT 渐进整改
- 全量 **274 passed**；ruff E/F/W/I + format 全绿；coverage 26.75% ≥ 25 门禁

### 2026-08-08 (T3 现代应用覆盖 — GraphQL + 可选 SPA)
- **T3.1 GraphQL 检测**：新增 `wvs/modules/graphql/`（lite 模块，注册进 ModuleFactory）：8 条标准路径探测 + 指纹确认（__typename/GraphQL/graphiql/apollo）+ 两检查项——introspection 开启（INFO_DISCLOSURE/MEDIUM，`{__schema{types}}` 返回 types 才算）、批量查询支持（API_SECURITY/LOW，JSON 数组请求被接受）；证据验证原则：仅端点可达不报、无 GraphQL 特征不报、introspection 禁用不报
- 端点策略防路径爆炸：根端点才做标准路径全集探测；具体端点仅路径含 graphql/gql/graphiql 特征词才自身探测（端到端实测：71 个重复漏洞 → 收敛为 1 个真阳性）
- **T3.2 可选 SPA 爬取**：`scan --js-render`（实验性）→ config `crawler.js_render` → crawler 对实战目标启用 SPA 检测 + Playwright 渲染爬取（复用既有 `_check_spa`/`crawl_js`，未装 playwright 自动回退）；pyproject 新增 `jsrender` extras（playwright）
- base.py vuln_type_map 补 graphql → API_SECURITY
- 新增 `tests/test_graphql.py`（12 个测试：特征/introspection 判定/端点探测证据验证/playground 页/非 graphql 端点跳过/js-render 接线/CLI 参数）；全量 **249 passed**；ruff E/F/W/I + format 全过
- 端到端实测：本地 mock GraphQL 服务 + 真实扫描链路 → introspection 检出，报告仅 1 个真阳性（/graphql）

### 2026-08-08 (T2 MCP 接入 + 账号统一)
- **T2.1 MCP Server**：新增 `wvs/mcp_server.py`（官方 mcp SDK，可选依赖 `pip install "rayscan[mcp]"`，py3.10+；FastMCP streamable-http，默认绑定 127.0.0.1:18000）；工具：`scan(url, modules, all_modules, max_time)`（完整扫描返回摘要 JSON）、`list_modules`、`get_report`（最近一次扫描结果）；CLI `python -m wvs mcp [--host] [--port]`；无 SDK 时友好提示返回 1
- **T2.2 MCP 目标扫描**：新增 `wvs/modules/mcp/`（lite 模块，注册进 ModuleFactory）：常见 MCP 端点探测（/mcp、/api/mcp、/sse、/rpc 等 7 条）+ 特征指纹（jsonrpc/serverInfo/SSE 头）+ 证据验证两检查项——tools/list 未授权调用（INFO_DISCLOSURE/MEDIUM）、敏感工具未授权可调（BROKEN_ACCESS/HIGH）；纯握手不报；`_create_vuln` 使用 explicit_vuln_type，base.py vuln_type_map 补 mcp
- **T2.3 update-pocs**：CLI `rayscan update-pocs [--list-oa]`：重建 PoC 模板索引（force）+ 按 13 类 OA 技术栈统计 OA 相关模板数并可列出（复用 TECH_STACK_TAGS）
- **账号统一收尾**：`cli.py:cmd_version`、`wvs_gui.py`（2 处）、`web_ui/templates/index.html`、`wvs/reporting/html_report.py` 中残留旧账号 xiabai2004 → xiabai2008（CHANGELOG 历史记录保留）
- pyproject.toml：新增 `mcp` extras
- 新增 `tests/test_mcp.py`（20 个测试：指纹/工具解析/端点探测证据验证/POST-only server/无工具不报/MCP Server 摘要与错误路径/CLI）；全量 **237 passed**；ruff E/F/W/I + format 全过
- 端到端实测：真实启动 MCP Server + 模拟 Claude 客户端完整协议握手（initialize→initialized→tools/list→tools/call）ALL PASS（serverInfo=rayscan、17 模块含 mcp）
- 修复：FastMCP 1.27 构造签名（host/port 直传、无 version 参数）；mcp_server.py 相对导入层级

### 2026-08-08 (T1 AI 辅助验证 — 官方 API / 最高优先级)
- 新增 `wvs/ai/` 模块：`LLMClient`（OpenAI 兼容 chat/completions，复用 httpx 无新依赖；`LLM_API_KEY`/`LLM_BASE_URL`/`LLM_MODEL` 环境变量或 config `ai.*`；无 key 时 `available=False` 静默跳过；fail-safe 返回 None）+ `AIVerifier`（候选漏洞复核）+ `report.py`（AI 报告摘要）
- 误报复核策略：medium+ 候选按 5 条/批送 LLM 判定 → 确认（conf≥0.8）tag `ai_confirmed`；存疑（conf≤0.3）严重度降一级 + tag `ai_disputed`；其余 tag `ai_reviewed`；**只降级不删除**，请求失败/输出不可解析整批原样返回
- scanner.py：Phase 3.6 接入复核（config `ai.verify` 默认 False）；cli.py：`--ai-verify`（开启即打印第三方数据告警）
- 新增 `ai-report` 子命令：读既有 JSON 报告 → LLM 生成 markdown 摘要（`rayscan ai-report report.json -o summary.md`）
- config.py：`ai` 段（verify/base_url/model/timeout 默认全关；api_key 不入库，仅环境变量）
- 新增 `tests/test_ai_verify.py`（27 个测试：client 可用性/请求构造/MockTransport/JSON 解析、verifier 确认/降级/批次/异常保持、报告提取与 CLI）；全量 **217 passed**；ruff E/F/W/I + format 全过
- 端到端实测：本地 mock OpenAI 兼容服务 + `ai-report` 真实 HTTP 链路验证通过（摘要落盘）；`scan --help` 参数注册正确
- 规划文档 `docs/audit/rayscan-upgrade-plan-2026-08-08.md`（外部调研 + T0-T5 分期，用户拍板：官方 API / T1 最高优先级）

### 2026-08-05 (S3 OA 专项深化 — 三级检测链路)
- 三级检测链路：指纹识别（内容优先）→ 版本识别 → 漏洞验证（规则级证据优先）+ 版本过滤
- 新增 `OA_CONTENT_FINGERPRINTS`（12 种 OA 内容指纹：title/正文/响应头/Set-Cookie 四类匹配）
- `_detect_oa_type` 升级双通道：内容指纹优先，URL 路径/关键词回退；`_scan_impl` 优先使用 scanner 注入的 `_detected_oa`（修复断链），否则抓首页识别
- 新增 `_detect_oa_version`（Jenkins X-Jenkins 头、Nacos 页面版本变量、Spring/泛微/禅道版本字样，未识别不阻塞）与 `_version_in_range`（[min,max) 语义、无版本放行、解析失败放行）
- `_verify_evidence` 支持检查项规则级 `evidence`（优先于通用类型验证）；`_run_check` 接入版本过滤
- 首个真实版本过滤用例：Nacos 用户列表未授权（CVE-2021-29441）`evidence: pageItems` + `max_version: 1.4.1`
- 新增 `tests/test_oa_deep.py`（23 个测试：指纹/版本/过滤/规则证据/Nacos 集成）
- 新增 `docs/OA_RULES.md`（规则文档 + 检测矩阵 + 实战验证记录表，待实测样本闭环）

### 2026-08-05 (S2 链条接通 — nuclei 接入 + checkpoint 复活)
- Nuclei 接入主流程：`WAVScanner.scan()` Phase 3.5 新增 Nuclei 阶段（config `nuclei.enabled` 默认开，CLI `--no-nuclei` 关闭）；新增 `_run_nuclei`（懒实例化，CLI 可用走模板扫描，不可用走 S1 修复后的内置回退）；结果经 `_deduplicate` 合并
- 模板选择修复：`_cli_scan_async` 不再把模板折叠成父目录 `-t`（原实现=递归扫描整个目录），直接传模板文件逗号列表（上限 200 防命令行超限）
- Checkpoint 复活：`__init__` 初始化 `_modules_done`/`_last_checkpoint_time`/`_checkpoint_interval`/`_resume_checkpoint`（原 `_save_checkpoint` 引用未初始化字段必 AttributeError）；批次循环更新模块完成状态 + `_try_save_checkpoint` 间隔限流落盘；扫描完成落盘最终 checkpoint；`--resume` 注入 checkpoint → scan() 合并已发现漏洞 + 跳过已完成模块
- cli.py：`--no-nuclei` 参数 + `--resume` 注入 `scanner._resume_checkpoint`
- 新增 `tests/test_s2_resume.py`（8 个测试：checkpoint 往返/间隔限流/Vulnerability 序列化/nuclei 懒加载与复用/config 开关）
- 端到端实测：本地 HTTP 服务器扫描 → checkpoint 落盘（modules_done=['sqli','xss']）→ `--resume` 恢复提示与模块跳过均验证通过

### 2026-08-05 (S1 误报治理 — 发版前修复)
- Nuclei 内置回退：移除"可达即报"（`pattern is None` → 不报）；/graphql、/security.txt 补内容特征；/dev 检查项移除（无可靠特征）；body 截断 200→2000；特征匹配改大小写不敏感；`.git/config` 特征 `remote origin` → `[remote`（真实格式）
- OA 检测：`_run_check` 移除 401/403/500/302"状态码即漏洞"判定，仅 HTTP 200 + `_verify_evidence` 响应证据验证（unauth=JSON 数据、info_disclosure=actuator/heapdump 特征、sqli=SQL 报错/JSON success、rce=octet-stream/二进制/Groovy、file_read=JSP 源码特征）；file_upload/info 类 GET 探测不报
- OA 通用路径：移除 /admin/、/login/、/system/、/api/、/webservice/、/backup/ 泛路径检查；保留 4 个可内容验证的泄露路径（web.xml/MANIFEST.MF/.git/HEAD/.env 键值对启发式）
- XXE：`_check_xxe_success` 增加 baseline 排除；三个调用点（参数注入/XML body/SVG 上传）均先取良性 baseline
- SSRF：`_check_ssrf_success` 增加 baseline 排除（含连接错误关键词分支）；`test_cloud_metadata` 补 baseline
- DOM XSS：移除 `_test_dom`（URL fragment 反射伪检测，非真实 DOM 检测；待 headless 验证接入）
- 新增 `tests/test_fp_guard.py`（23 个误报防护回归测试：XXE/SSRF baseline、OA 证据验证、Nuclei 回退特征匹配）
- README：撤下未兑现卖点（多引擎聚合/MSF 验证链标注为 Roadmap），测试数 79→136，项目结构图修正
- 规划文档 `docs/audit/rayscan-evolution-plan-2026-07-12.md` 更新至 v1.2（§11 战略修正：OA 专项 + 工作流闭环，替代自研内核优先）

### 2026-06-27
- Added Code change log section to AGENTS.md

### 2026-06-27 (Profile System)
- Added Profile system: `wvs/profiles/` module with ProfileManager
- Added CLI subcommands: `rayscan profile list|create|delete|export|import`
- Added `rayscan use <profile> -u <url>` command for profile-based scanning
- Added built-in profiles: default, src-quick, pentest-full, sqli-only
- Added 17 tests in `tests/test_profiles/`
