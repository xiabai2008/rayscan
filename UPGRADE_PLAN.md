# RayScan 完整升级规划方案

> 项目规模: 27.5K 行 Python (124 文件) | 当前覆盖: 27% | 测试: 197 通过
> 生成日期: 2026-05-11

---

## Tier 1 — 基础质量 (当前阶段)

### 1.1 测试覆盖提升 27% → 60%+ (进行中)

**已完成:**
- Reporting 模块: 0% → ~94% (JSON, CSV, Markdown, HTML, Console)
- LFI detector: 13% → 34% (_check_file_content, payload 提取)
- XSS detector: 11% → 30% (_check_reflection, structural detection)
- CMDI detector: 16% → 28% (false positive 过滤, input reflection 检测)

**余下需测试的 async 模块 (需要 mock HTTP):**

| 模块 | 当前 | 目标 | 工作量 |
|------|------|------|--------|
| `core/scanner.py` (681行) | 19% | 50%+ | 高 |
| `core/crawler.py` (559行) | 24% | 50%+ | 高 |
| `modules/sqli/detector.py` (579行) | 16% | 40%+ | 高 |
| `core/session.py` (281行) | 34% | 60%+ | 中 |
| `core/cache.py` (306行) | 22% | 50%+ | 中 |
| `core/rate_limiter.py` (263行) | 37% | 60%+ | 中 |
| `modules/rce/detector.py` (346行) | 8% | 30%+ | 高 |
| `modules/xxe/detector.py` (186行) | 14% | 30%+ | 中 |
| `modules/ssrf/detector.py` (226行) | 13% | 30%+ | 中 |
| `modules/sensitive/detector.py` (206行) | 15% | 30%+ | 中 |
| `modules/jspathfinder/detector.py` (296行) | 16% | 30%+ | 中 |
| `modules/api/detector.py` (144行) | 16% | 30%+ | 中 |
| `plugins/auth.py` (202行) | 24% | 40%+ | 中 |

**方案:** 使用 `pytest-asyncio` + `unittest.mock.AsyncMock` 来 mock `HTTPPool._request()`，使 async 检测方法的测试无需真实网络。

### 1.2 CI/CD 增强 (已具备基础)

**现状:** GitHub Actions CI 已配置，运行在 ubuntu-latest，测试 Python 3.9-3.12
- ✅ pytest 测试
- ✅ flake8 lint (exit-zero, 宽松配置)
- ✅ Import check / module smoke test

**需改进:**
- [ ] 添加 `pytest-cov` 覆盖率报告，设置最低阈值(如 25%)
- [ ] 添加 `pre-commit` hooks (black/isort 格式化)
- [ ] CI 缓存 pip 依赖加速
- [ ] 添加 `pytest-timeout` 到依赖
- [ ] 添加 Windows/macOS 到 CI matrix
- [ ] 集成 Codecov / Coveralls

### 1.3 print() → logging 改造

**现状:** 约 117 处 `print()` 分布在 14 个文件中
- `wvs/cli.py` (30处) — 使用 `console.print()` (Rich)，这是正常的
- `wvs/config.py` (10处) — 在 `__main__` 测试块中，可保留
- `wvs/reporting/console.py` (22处) — 使用 `self.console.print()`，这是正常的设计
- `wvs/models.py` (9处) — 在 `__main__` 测试块中
- `wvs/exceptions.py` (7处) — 需改为 `logging`
- `wvs/core/oob/dnslog.py` (5处) — 需改为 `logging`
- `wvs/modules/base.py` (11处) — 部分需改为 `logging`
- 其他: `cache.py`, `scanner.py`, `wappalyzer_integration.py`, `engine.py`

**方案:**
1. CLI 层 (`cli.py`) 的 `console.print()` → 保留（这是用户输出）
2. 库代码中的裸 `print()` → 全部替换为 `logger.info() / logger.debug()`
3. `__main__` 测试块中的 `print()` → 可保留（纯测试用）

### 1.4 中英文混杂清理

**现状:** 代码中存在中英文混合:
- 中文文档字符串: `"""命令注入检测模块"""`
- 英文注释: `# P13: Concurrent echo probes`
- 用户输出: 中文 ("扫描完成，未发现漏洞") / 英文混杂
- 日志: 中英文混杂 (`logger.info(f"[CMDi] 开始检测")`)

**方案:**
- 代码中注释和文档 → 统一为英文（国际化标准）
- 日志字符串 → 统一为英文（便于 grep 和日志分析）
- 用户输出（CLI/GUI/报告）→ 保持中文或者提供 i18n 接口
- 建议: 代码注释英文, 日志英文, CLI/报告中文

### 1.5 GUI 文件修复 + 测试

**现状:** `wvs_gui.py` (236行) 有大量修改（git diff 显示 +164/-72），无测试
- 这是 Tkinter GUI，需要手动测试或使用 `pytest-xvfb`

---

## Tier 2 — 架构与性能优化

### 2.1 HTTP 缓存接入

**现状:** `wvs/core/cache.py` (306行, 22%覆盖) 已实现缓存框架但未集成到主流程
- 实现了 `fingerprint()`, `batch_fingerprint()`
- 有 `HTTPCache` 类但尚未被 scanner/crawler 使用

**方案:** 
- 将 `HTTPCache` 集成到 `HTTPPool` 或 `session.py` 中
- 添加 Cache-Control 头感知
- 实现 LRU 淘汰策略

### 2.2 连接池统一

**现状:** 多种 HTTP 客户端混合使用:
- `aiohttp.ClientSession` (异步主客户端)
- `httpx.AsyncClient` (部分模块)
- `requests.Session` (同步代码)

**方案:** 统一为 `httpx.AsyncClient` (支持 HTTP/2, 连接池, 超时控制更好)

### 2.3 RateLimiter 集成

**现状:** `wvs/core/rate_limiter.py` (263行, 37%覆盖) 已实现但可能未与主扫描流程深度集成
- 支持 burst/adaptive 模式
- 需要确认是否在所有模块中生效

**方案:** 
- 审计所有 HTTP 请求路径是否遵守 RateLimiter
- 添加请求前的 `await self.rate_limiter.acquire()` 检查

### 2.4 Payload 配置化

**现状:** Payloads 硬编码在 `wvs/modules/*/payloads.py` 中

**方案:** 
- 将 payloads 从 Python 代码提取到外部 YAML/JSON 配置文件
- 支持用户自定义 payload 目录
- 支持按标签/类型选择 payload 子集

### 2.5 OOB 检测默认集成

**现状:** `wvs/core/oob/` 已实现:
- `oob_manager.py` (140行, 32%)
- `interactsh.py` (131行, 26%) 
- `dnslog.py` (142行, 25%)
- 默认禁用，需环境变量 `WVS_OOB_URL` 开启

**方案:**
- 默认启用 OOB 检测
- 内置公共 interactsh 服务器作为 fallback
- 每个模块的 OOB 检测方法统一为基类接口

---

## Tier 3 — 功能扩展

### 3.1 Docker 容器化

**方案:**
- 创建多阶段 Dockerfile
- 支持 `docker run rayscan scan http://target.com`
- Docker Compose 示例（含 OOB 服务器）
- GitHub Container Registry 自动发布

### 3.2 SARIF 报告集成

**现状:** `JSONReporter.generate_sarif()` 已实现，但未集成到 CLI/CI 流程

**方案:**
- CLI 添加 `--format sarif` 选项
- 与 GitHub Code Scanning 直接集成
- 与其他 SARIF 兼容平台（DefectDojo, CodeClimate）配合

### 3.3 REST API

**方案:**
- 使用 FastAPI 构建 REST API
- 端点: `/scan`, `/results/{id}`, `/modules`, `/config`
- WebSocket 实时进度推送
- Swagger 文档自动生成

### 3.4 Webhook 通知

**方案:**
- 扫描完成时发送 Webhook
- 支持 Slack / Discord / Email
- 可自定义触发条件（如: 仅高危漏洞）

### 3.5 插件系统

**方案:**
- 基于 `DetectionModule` 基类的插件架构已就绪
- 添加 `pip install rayscan-plugin-xxx` 的发现机制
- 插件市场或社区仓库

---

## Tier 4 — 安全加固

### 4.1 凭据管理

**方案:**
- 敏感配置从环境变量/加密文件读取
- 审计日志中屏蔽密码/token
- 报告导出时自动脱敏

### 4.2 Checkpoint 加密

**现状:** `scanner.py` `_save_checkpoint` 使用 JSON 明文存储

**方案:**
- 使用 Fernet (symmetric encryption) 加密 checkpoint 文件
- 密钥从环境变量或 keyring 获取
- 可选: 与扫描目标 hash 绑定，防止 checkpoint 泄露

---

## 实施路线图

```
Week 1-2:    Tier 1 测试覆盖 27% → 50%
Week 3:      Tier 1 print→logging + 中英清理 + CI 改进
Week 4-5:    Tier 2 HTTP缓存 + 连接池统一
Week 6:      Tier 2 RateLimiter + Payload配置化
Week 7-8:    Tier 3 Docker + SARIF接入
Week 9-10:   Tier 3 REST API + Webhook
Week 11:     Tier 4 安全加固
Week 12:     ϵ 阶段 — 集成测试 + 文档 + 发布
```

## 工作量评估

| 层级 | 项数 | 预计工时 | 风险 |
|------|------|----------|------|
| Tier 1 | 5 项 | ~40h | 低 |
| Tier 2 | 5 项 | ~35h | 中 |
| Tier 3 | 5 项 | ~60h | 中高 |
| Tier 4 | 2 项 | ~15h | 低 |
| **总计** | **17 项** | **~150h** | |
