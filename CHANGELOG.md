# Changelog

All notable changes to RayScan (formerly WVS) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

> 📏 **数字口径说明**（自 2026-08-24 起）：对外引用的测试数以 CI `pytest --collect-only` 实测为准，不手写。下方历史条目中的测试数为**当时口径**，可能互相不一致，不作为当前状态的依据。当前实测：**376 collected**（2026-08-25）。

---

## [Unreleased]

### Added — v2.3 T3.4 Nuclei 模板策展

- **策展模式**：`get_templates_for_target(..., curated=True)`——目标指纹命中技术栈时只用 tech 匹配 + CVE 命中的模板，淘汰泛匹配（severity 兜底/misconfig 补充不再注入）；tech 匹配模板全量保留（检出不丢失）；未命中指纹保持通用选择（行为不变）
- **指纹→模板接线**：detector 导出 `OA_TO_TECH` 映射与 `oa_tech_stack_for()`（兼容 scanner 注入短名，纯 YAML 新增 OA 无映射时安全退回通用选择）；scanner `_run_nuclei` 读取 oa 模块 `_detected_oa` → 传 `tech_stack` 给 `NucleiIntegration.scan()`；CLI 分支 tech 命中时走策展（max 200）
- **可审计字段**：`NucleiTemplateManager.last_selection` 记录 `{mode: curated/generic, tech_stack, severities, candidates, selected, truncated, templates[≤50]}`；`NucleiIntegration.last_selection` 透传（含 `builtin-fallback`/`template-dir`/`none` 模式）；`ScanResult.template_selection` 新字段随 `to_dict()` 落盘，JSON 报告 `_build_standard` 输出 `template_selection` 键（未运行 Nuclei 阶段时省略）
- **验收**：新增 `tests/test_nuclei_curation.py`（17 用例：策展只选 tech 模板、数量下降且检出不丢失（策展⊆通用且无泛匹配混入）、无 tech 命中返回空、通用模式不回归、审计字段、integration 透传/回退记录、scanner 接线（含短名/未知名/无 oa 模块）、报告字段有无两态）；全量测试 441 通过

### Added — v2.3 T3.3 OA 规则外部化

- **规则包**：`rules/oa/*.yaml`（12 文件 × 12 种 OA，每文件一种 OA）——`name/paths/keywords/fingerprints/checks` 完整迁移，检查项含 `path/method/params/param_type/type/severity/evidence/min_version/max_version/status_codes` 全部元数据；由一次性脚本从硬编码机械转录 + round-trip 逐字段校验
- **加载器** `wvs/modules/oa/rules_loader.py`：目录优先级 `~/.rayscan/rules/oa/`（用户覆盖，同名 OA 整体替换）> 仓库 `rules/oa/`；校验失败（缺 path/type/severity、未知字段笔误如 evidince）丢弃该检查项并告警（宁漏报不弱化验证语义）；数字形标量（evidence: 54289）自动转 str；`SEVERITY_MAP`/`VULN_TYPE_MAP` 词表移至加载器（schema 与执行共用），detector re-export 保持兼容
- **detector.py 改为执行器**：`OA_RULES`/`OA_CONTENT_FINGERPRINTS` 变为加载结果（保留原名，测试兼容），新增 `OA_RULE_SOURCES`（每 OA 规则来源审计字段）；内置硬编码改名 `BUILTIN_OA_RULES`/`BUILTIN_OA_CONTENT_FINGERPRINTS` 仅作回退——**两个规则目录都无 YAML 时行为与外部化前完全一致**
- **rules 管理**：`DEFAULT_POC_CONFIG` 新增 `oa` 来源（`~/.rayscan/rules/oa/`，`rules status/update` 可见，支持用户放独立 git 仓库增量同步）
- **验收**：新增测试 `tests/test_oa_rules_loader.py`（16 用例：YAML↔内置 parity、缺失回退、纯 YAML 新增 OA、用户覆盖、损坏文件跳过、校验丢弃/类型纠正、header 指纹 null 保留）；黄金矩阵 `--only oa` 双靶标 PASS（oa_vuln 检出 1 / oa_fixed 0 误报，20/20 基线不变）——改的是规则存放处，不是检测行为

### Added — v2.2 T2.4/T2.5 + 检测器真实性修复 + 新模块靶标

- **T2.4 登录态维持**：HTTPPool 会话失效检测（401/重定向到登录页）→ 自动重登回调 → 刷新凭据并重放当前请求；10s 冷却防模块主动 401 探测引发反复登录；重登成功清空 GET 去重缓存；CLI 认证后自动注册回调（`--auth-type` 全类型生效）；新增 `tests/test_session_reauth.py`（3 用例含真实本地服务全链路）
- **T2.5 双账号 IDOR**：`--second-auth "Header: Value"` 注入 B 账号凭据，idor 对象替换命中后用 B 会话实际读取 A 的对象（独立 httpx client 防 cookie 混叠）——确认则升级 HIGH/HIGH，未确认保持 MEDIUM 疑似语义；新增 `tests/test_idor_second_auth.py`（3 用例）；黄金矩阵新增 `idor_confirmed` 靶标
- **黄金矩阵新模块靶标（7 个）**：weakpass（/login 弱口令 + /user/login 强口令护栏）、webshell（/cmd.php 一句话木马）、js_analysis（app.js 密钥泄露 + /jsapp-clean 零发现护栏）、api（CORS 开放 + secret_key 泄露 + /.env）、waf（/waf-protected Cloudflare 形态 + 主靶场零 WAF 护栏）、authbypass（/jwt/profile 弱密钥 JWT 注入链路）、jspathfinder（JS 引用 → fuzz 发现 /.env）
- **黄金矩阵 any-of 语义**：`must_detect_any`（任一命中即过）——cmdi 检出端点随平台 shell 语义不同（Win→/rce、Linux→/cmdi），CI 首跑由此暴露
- **CI Golden Matrix 首跑**：11/12 绿，lfi Linux 漏报门禁 ✓、oa_fixed 版本过滤 ✓

### Fixed — 黄金矩阵暴露的 6 个真实缺陷

- **HTTPPool GET 去重缓存忽略请求头**：缓存键只含 method|url|params——CORS 检测（Origin 头差异）拿到 info 检查的旧响应永远看不到 ACAO（漏检）；authbypass 认证头移除重放同样会命中缓存（误报隐患）；语义头（除 UA 轮换外）现参与缓存键
- **rce Java EL leak 反射误报**：指示词计数未排除"指示词本身来自载荷回显"——反射端点回显载荷里的 org.apache 等词即被计为泄露；现排除载荷内指示词，仅计服务侧新出现的指示词（求值语义）
- **waf 签名管道断裂**：`_match_all_signatures` 读 baseline 的 `cookies`/`status` 键，但 `_send_request` 返回 `status_code` 且不含 cookies——所有 Cookie 型 WAF 签名（__cfduid/AWSALB 等）从未生效；现从 Set-Cookie 头解析 cookie 名；Cloudflare 签名补真实 body 标记（Attention Required）
- **js_analysis 全模块崩溃**：统计行访问不存在的 `vuln_type` 属性 → 单端点扫描抛异常 → 该模块所有发现被静默丢弃（模块自发布以来从未产出过结果）；改用 tags 判定
- **base.py vuln_type_map 缺 5 模块**（js_analysis/jspathfinder/webshell/weakpass/subdomain）→ 每次创建漏洞都走 OTHER 回退告警
- **--modules jspathfinder 静默空转**：config 默认 `enabled: False` + enabled 合成属性（_enabled AND module_config.enabled）→ 显式加载也不执行；`load_module` 现强制启用（用户显式意图优先）
- **weakpass 凭据走 query 而非 body**：`_send_request` 默认 param_type=query，真实登录端点读 body → 改 param_type=body
- **benchmark_lab Werkzeug 版本头**：开发服务器在 WSGI 层后强制覆写 Server 头 → api 模块版本泄露全站刷屏 + waf 的 server:cloudflare 签名被覆盖；自定义 request_handler 隐藏版本串；`strict_slashes=False` 解决扫描器补尾斜杠 404；`_hint` 装饰器透传 Response（修 CORS 端点 500）
- **weakpass/webshell O(N²) 探测**：固定路径探测对每个爬取端点重复执行（30 端点 × 160 请求），补每基址一次守卫

### Added — 黄金靶场矩阵（v2.2 T2.1/T2.2 检测可信度制度化）

- **`scripts/run_golden_matrix.py`**：机器可读期望清单驱动的 FP/FN 双门禁——`must_detect` 精确到 URL 子串（漏报回归即 FAIL）、`must_not_flag` 误报防线（命中即 FAIL）、清单外发现 WARN 提示人工确认；单靶标批量扫描按报告 module 字段归属发现
- **`scripts/golden_matrix.yaml`**：期望清单单一事实源（9 个主靶场模块 + OA 双靶标），修改基线必须登记原因
- **靶场扩展（`scripts/benchmark_lab.py`）**：OA 三级链路靶标（Nacos 1.3.2 漏洞版 / 1.5.0 修复版双实例,响应相同仅版本号不同,专项检验版本过滤器）；idor 靶标（/api/invoice 对象替换 + /api/users page=all 批量泄露 + /api/secure-invoice 403 越权护栏）；误报护栏端点（/safe/api success:false JSON）
- **`docs/BASELINES.md`**：首次建线实测记录（sqli/xss/cmdi/rce/xxe/ssrf/sensitive/idor/oa 全部双向验证通过）
- **CI**：新增 `Golden Matrix (FP/FN gate)` job（workflow_dispatch；per-push 化待靶场分 hub 缩面提速）
- 实测要点：oa_fixed 靶标（同一漏洞响应 + 版本号 1.5.0）0 检出 = 版本过滤 [min,1.4.1) 逻辑有专项回归防线；/api/users 批量泄露检出需靶场双路由注册（扫描器对目录形端点补尾斜杠）

## [2.2.0] - 2026-08-08

### Added
- **AI 辅助验证（T1）**：`scan --ai-verify` 对候选漏洞做 LLM 二次复核（确认/存疑降级，只降不删）；`rayscan ai-report` 用 LLM 生成报告摘要；官方 OpenAI 兼容 API（`LLM_API_KEY`），无 key 静默跳过
- **MCP 接入（T2）**：`python -m wvs mcp` 启动 MCP Server（`pip install "rayscan[mcp]"`，默认 127.0.0.1:18000，供 Claude/ChatGPT 调用 scan/list_modules/get_report）；新增 `mcp` lite 模块检测 MCP server 工具列表泄露与敏感工具未授权调用
- **GraphQL 检测（T3.1）**：`graphql` lite 模块（端点识别 / introspection 开启 / 批量查询，证据验证）
- **可选 SPA 爬取（T3.2）**：`scan --js-render` 对实战目标启用 Playwright 渲染（实验性，`pip install "rayscan[jsrender]"`）
- `rayscan update-pocs [--list-oa]`：重建 PoC 模板索引 + OA 相关模板统计
- 工程地基（T4）：覆盖率门禁（`fail_under=25`，CI blocking）、ruff 配置本地=CI 统一、core 层 +25 单测、新模块 mypy 0 错误
- 测试：190 → **274**（AI 27 / MCP 20 / GraphQL 12 / core 25）

### Fixed
- **crawler 无端点时流式检测整体跳过**（单页无链接且 seed 全 404 时检测模块完全不执行）→ scanner 兜底端点前置
- **httpx 空 params 丢弃 URL 自带 query**（OA 检查项 `/nacos/v1/auth/users?pageNo=1` 缺参 404）→ base.py 空 params 不传
- **OA 短名断链**：scanner 注入"泛微"与 OA_RULES key"泛微-Ecology"不匹配 → 别名映射修复（8 种 OA 检查项此前从不执行）
- **OA `_create_vuln` 枚举误传**导致报告 JSON 序列化失败 → `vuln_type` 传字符串 + `explicit_vuln_type` 传枚举
- 统一账号引用 xiabai2008（cli/wvs_gui/web_ui/html_report 残留清理）

### Changed
- 版本 SSOT：`wvs/__init__.py` = 2.2.0（与 pyproject 一致）；报告模块（console/html/markdown）动态读取 `__version__`，UI 硬编码版本统一
- OA 实测闭环（mock 靶场 4 样本：泛微/Nacos 1.3.2/Nacos 1.5.0 负样本/Jenkins），记录入 docs/OA_RULES.md
- 与远程 v2.1.0（可解释检测/被动扫描/业务逻辑/规则管理/编排层）合并：保留双方功能（AI/MCP/GraphQL + demo/passive/idor/authbypass/rules/编排器）

---

## [Unreleased]

### Added — 被动扫描 HTTPS 解密(TLS 拦截)

- **`rayscan passive --tls-intercept`**:MITM 代理用按需生成的 CA 签发叶证书伪装目标站点,解密 HTTPS 流量进入检测管线(此前 HTTPS 仅隧道转发不检测)
- 新增 `wvs/core/passive/tls_intercept.py`:`CertAuthority`(CA 生成/持久化 `~/.rayscan/ca/`、每主机叶证书签发与缓存、IP 字面量 SAN)、`trust_instructions`(各平台信任 CA 命令提示)
- 解密连接支持 keep-alive:响应按 Content-Length/chunked/EOF 精确截断,`Connection: close` 正确收尾
- 上游保持真实 TLS 校验,自签名/内网目标自动降级为不校验;`cryptography` 缺失时优雅回退纯隧道模式(新 optional extra `rayscan[tls]`)
- 新增 `tests/test_passive_tls.py`(6 用例:CA 往返/叶证书 SAN 与签发链/authority 解析/隧道回退/HTTPS 拦截端到端含 keep-alive)

### Fixed — 被动代理

- **CONNECT 隧道回环 bug(历史缺陷)**:原 `_handle_connect` 响应 200 后把客户端数据原样回环给客户端、从未连接上游——任何 HTTPS 站点经代理均无法打开;现真正连接目标后双向转发,目标不可达返回 502
- `_host_matches` 的 `lstrip("www.")` 会误剥 `web.`/`ww.` 等前缀,改为显式 `www.` 前缀判断

### Changed — CI 门禁做实

- 测试 job 增加 `--cov-fail-under=30` 覆盖率门禁(当前实测 33.5%,此前 CHANGELOG 声称门禁但 CI 实际 non-blocking)
- 用 CI 锁定版 ruff 0.15.21 修复 9 个历史遗留文件格式偏差(`ruff format --check` 门禁转绿)

---

## [2.1.0] - 2026-08-07

### 🚀 升级亮点

- **一键演示 `rayscan demo`**:内置本地靶场(SQLi/XSS,仅 127.0.0.1),启动即自动扫描,实测检出 12 个漏洞,每条附证据链
- **可解释检测 `--explain`**:每个漏洞附 `evidence_chain`(基线差异/命中特征/置信度依据),JSON/SARIF 报告同步输出,可直接作为 SRC 提交证据
- **被动扫描 `rayscan passive`**:零依赖轻量 MITM 代理,分析真实流量覆盖登录后页面,`--target` 域名过滤防误扫
- **业务逻辑检测(新增模块)**:
  - `idor` 越权检测:对象替换(±1/批量)对比 + 批量接口 + 管理端点探测
  - `authbypass` 认证绕过:认证头移除重放 + JWT none/弱密钥 + 默认凭据
- **合规预设 `--preset`**:`gentle`(低速率/浅爬/有限模块/授权提示)等 5 种预设
- **规则管理 `rayscan rules status|init|update`**:检测规则增量更新无需发版(git pull,非 git 优雅降级)
- **社区运营体系**:运营规划、规则贡献三阶段流程(detect→exploit→regression)、Issue/PR 模板、贡献者致谢

### Added

- 架构:新增 `ScanOrchestrator`/`ScanStage` 编排层,`WAVScanner.scan()` 作为 facade 拆分(WAF/靶机认证/OA 检测/去重抽为独立 stage)
- 被动扫描包 `wvs/core/passive/`、演示靶场 `wvs/demo_lab.py`、规则管理 `wvs/core/rule_updater.py`
- CLI 新命令:`demo`、`passive`、`rules`;`scan/use` 新增 `--explain`、`--preset`、`--concurrency`
- 多引擎聚合报告视图:`multi` 结果表新增置信度/来源引擎/★多引擎高可信标记
- `--i-have-permission` 授权确认后真正执行 exploit 验证链(此前仅日志空转)
- CI 覆盖率门禁(`--cov-fail-under=30`);Docker 运行时安装 git 支持规则更新

### Fixed

- `multi` 子命令重复定义且 `main()` 未接线 → 已接入可达
- `HTMLReporter.generate_json` 误用(CLI JSON 报告调用不存在方法)→ 改 `JSONReporter.generate`
- `WAVScanner._vuln_seen` 未初始化 → 扫描去重崩溃
- 报告版本硬编码 "1.0.2" → 动态读取 `__version__`
- `_validate_target_url` SSRF 防护放行参数(默认关闭,仅 demo 本地靶场使用)
- 全局并发 `Semaphore` 跨模块共享(此前每个模块独立新建,未真正限流)

### Changed

- 模块加载保持 `ModuleFactory` 注册表单一事实源;新增模块按 lite 分层注册
- 核心统一 httpx;aiohttp 仅存于 exploit/OOB/Wappalyzer 外围适配层
- 技术债清理:双重 `@staticmethod`、`__all__` 重复导出、类级可变默认值
- 测试套件:新增 6 个测试文件(CLI 冒烟/被动扫描/业务逻辑/编排器/规则报告/Demo 靶场),远程 v2.0 回归套件(OAVersion/fp_guard/s2_resume)全量纳入

### Testing

- 完整测试套件全绿(约 211 用例):远程 v2.0(OA 三级链路/Nuclei/checkpoint/S1 误报治理)+ 本地 Phase 0-4 全量

---

## [2.0.1] - 2026-08-06

### Fixed
- 统一仓库账号引用至 `xiabai2008`：修正 README/CONTRIBUTING/CHANGELOG/LICENSE 及代码内旧账号 `xiabai2004` 链接（badge、clone、Release、版权、Docker 镜像名）
- CI 质量门禁严格化：Lint 与 Format 移除 `continue-on-error`，成为阻断性检查（与 Test 一致）

### Changed
- 移除误提交的本地产物（`.workbuddy/`、`delivery/` 加入 `.gitignore`，保持仓库纯净）
- `SECURITY.md` 支持版本表更新至 2.0.x；新增 `CODE_OF_CONDUCT.md`

---

## [2.0.0] - 2026-08-05

### Added
- **OA 三级检测链路**：内容指纹识别（title/正文/响应头/Set-Cookie，12 种 OA）→ 版本识别（Jenkins X-Jenkins 头、Nacos/Spring/泛微/禅道）→ 规则级响应证据验证 + 版本过滤
- **Nuclei 接入主扫描流程**（默认启用，`--no-nuclei` 关闭）：CLI 可用走智能模板扫描（直接传模板文件），不可用走内置内容特征回退
- **扫描断点恢复**：30 秒间隔 checkpoint 落盘，`--resume` 合并已发现漏洞并跳过已完成模块
- OA/WebShell/弱口令/子域名枚举专项检测（v2.0 功能基线）
- 190 个自动化测试（含 54 个 S1-S3 误报治理与恢复回归测试）

### Fixed（S1 误报治理）
- Nuclei 内置回退移除"可达即报"：无内容特征的检查项（admin 面板等）不再直接报漏洞，需响应特征匹配
- OA 检测移除"状态码即漏洞"：401/403/500/302 不再视为漏洞，仅 HTTP 200 + 响应证据验证
- XXE/SSRF 检测增加 baseline 排除：页面本身含 `/etc/passwd` 特征或解析器错误字样不再误报
- 移除伪 DOM XSS 检测（URL fragment 反射误判，待 headless 浏览器验证后恢复）
- `.git/config` 检测特征修正（`remote origin` → `[remote`，原特征匹配不到真实文件）

### Changed
- README 撤下未兑现卖点：多引擎聚合（AWVS/Nessus）与 MSF 验证链标注为 Roadmap
- 规划文档更新至 v1.2：战略修正为"OA 专项 + 工作流闭环"（详见 `docs/audit/rayscan-evolution-plan-2026-07-12.md` §11）

## [1.0.2] - 2026-05-24

### Added
- 在 Metasploitable 2 靶场完整验证：发现 83 个漏洞（3 medium + 80 low）
- 支持手动设置 DVWA 安全等级（security cookie）以获取最佳扫描结果
- 自动识别 DVWA/Mutillidae 实验室环境并适配认证流程

### Fixed
- `_lab_profile` / `_lab_base_url` 初始化缺失 → 靶机自动识别崩溃（#2）
- `_max_time` 属性命名不一致 → `AttributeError: '_max_time'`（#2）
- `_MODULE_PRIORITY` 常量缺失 → 模块排序 `NameError`（#2）
- `_integrations_enabled` 初始化缺失 → Phase 2b `AttributeError`（#2）
- `hashlib` / `gc` 模块导入缺失 → `NameError: name 'gc' is not defined`（#2）
- `_run_module_concurrent` 方法缺失 → 批处理模块运行崩溃（#2）
- `_deduplicate` 中 `seen` 误用 `Dict` → `dict` object has no attribute `add`（#2）

### Changed
- 批量清理项目根目录的测试临时文件（_*.py / _*.md / checkpoint JSON）

## [1.0.1] - 2026-05-24

### Added
- 未指定 `--output` 时自动保存报告到 `scan_reports/` 目录，并打印完整路径
- `scan_reports/` 目录不存在时自动创建

### Fixed
- 用户运行扫描后找不到结果文件的问题（close #1）

## [1.0.0] - 2026-05-15

### Added
- 正式更名为 RayScan，基于 WVS v19.2 开源发布
- flake8 lint 零警告（修复 413 个 lint 问题）
- Docker 支持（`Dockerfile` + `docker-compose.yml` + `.dockerignore`）
- CI 流水线：GitHub Actions 自动测试 + 依赖安装
- `.pre-commit-config.yaml` 自动化代码检查
- `CONTRIBUTING.md` 贡献指南
- nuclei 路径跨平台支持
- 社区发文模板 `COMMUNITY_POST.md`

### Changed
- 所有硬编码绝对路径替换为相对/可配置路径
- 文件拆分：
  - `sqli/detector.py` 1423 行 → 369 行 + `analyzer.py` + `techniques_mixins.py`
  - `crawler.py` 1172 行 → 967 行 + `crawler_parsers.py`
  - `scanner.py` 1076 行 → 793 行 + `scanner_integrations.py`
- 爬虫限制：种子路径瘦身、每路径前缀 25 页上限、POST 端点采样上限 12
- 扫描加速：XSS 参数采样（最多 4 个）、XSS 存储型跳过 POST 表单、SQLi POST 参数修剪
- CI 现在正确报告测试失败（不再吞错误）

### Testing
- 测试用例：236 → 281 个

---

## WVS v19.2 (pre-RayScan) — 2026-05

### Added
- 超时抢救机制：扫描超时后保存已发现的漏洞
- 扫描恢复：`--resume` 从 checkpoint 恢复
- OOB 检测支持：`--oob-server` 参数
- 认证模块重构：支持 form/bearer/basic/apikey/cookie 五种认证
- GUI 界面 `wvs_gui.py`
- 报告系统：HTML / JSON / CSV / Markdown / Console
- 多格式报告输出

### Changed
- 模块化架构重构，扫描引擎与检测模块解耦
- 报告生成器独立为 `reporting/` 包

### Performance
- 并发端点数提升至 12
- 智能限速：burst/uniform 双模式

---

## WVS v19.0 / v19.1 — 2026-04~05

### Added
- 11 个检测模块：SQLi / XSS / CMDi / LFI / RCE / SSRF / XXE / API / 敏感信息泄露 / WAF / JSPathFinder
- 第三方工具集成：Nuclei、sqlmap、ffuf、Wappalyzer
- 异步扫描引擎（aiohttp）
- 缓存系统（CacheSystem）
- 智能速率限制（RateLimiter）
- 认证插件系统
- CLI 命令行接口
- 批量扫描模式
- WAF 检测与绕过

### Performance
- 并发扫描速度提升 6.21 倍
- 缓存命中率 68%，响应时间减少 52%
- 自适应速率调整，避免触发 429/503

---

## WVS v18.x — 2026-04

### Added
- 高级漏洞检测模块：零日漏洞、逻辑漏洞、API 安全、身份验证绕过
- AdvancedDetectionManager 统一管理框架
- 时间盲注验证算法优化（IQR 异常值检测）
- Nuclei 模板集成与自动更新
- 性能监控仪表板

### Changed
- 从单体架构重构为模块化设计
- 标准化漏洞格式（AdvancedVulnerability）

---

## WVS v15～v17 — 2026-03~04

历史迭代版本，完成基础扫描框架搭建、插件系统、多报告格式、模块化架构重构等基础设施。

---

## WVS v1～v14 — 2025~2026

早期版本开发迭代，构建核心扫描能力。

[1.0.1]: https://github.com/xiabai2008/rayscan/releases/tag/v1.0.1
[1.0.0]: https://github.com/xiabai2008/rayscan/releases/tag/v1.0.0
