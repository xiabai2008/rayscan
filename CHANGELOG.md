# Changelog

All notable changes to RayScan (formerly WVS) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

> 📏 **数字口径说明**（自 2026-08-24 起）：对外引用的测试数以 CI `pytest --collect-only` 实测为准，不手写。下方历史条目中的测试数为**当时口径**，可能互相不一致，不作为当前状态的依据。当前实测：**376 collected**（2026-08-25）。

---

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
