# Changelog

All notable changes to RayScan (formerly WVS) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

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

[1.0.1]: https://github.com/xiabai2004/RayScan/releases/tag/v1.0.1
[1.0.0]: https://github.com/xiabai2004/RayScan/releases/tag/v1.0.0
