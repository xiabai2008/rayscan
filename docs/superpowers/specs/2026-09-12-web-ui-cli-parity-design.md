# RayScan Web UI 对齐 CLI（v2.3 T3.5）设计

> 日期：2026-09-12 ｜ 状态：已定稿（待实现）
> 路线图：`docs/rayscan-upgrade-roadmap-2026-09-07.md` §v2.3 T3.5
> 验收：UI 可发起带认证的扫描并查看证据链

## 1. 背景与现状

Web UI（`web_ui/app.py` + `web_ui/templates/index.html`）当前只有基础扫描：

| 现状 | 问题 |
|---|---|
| 模块列表前端硬编码 10 个 | 事实有 18 个模块（core + lite），信息过时 |
| 扫描无认证、无 explain | 不能扫登录后目标，看不到证据链 |
| profile / passive 无入口 | 与 CLI 能力脱节 |
| `dashboard` / `history` 两个 tab-pane 无导航可达 | 历史 `_record_scan` 从未被调用，`/api/history` 恒空（audit 已记录死代码） |
| 零测试、不在 ruff/CI 范围 | 回归无保护 |
| 版本号硬编码 2.2.0 | 违反版本 SSOT 规则（AGENTS.md 记录） |

本次决策（brainstorm 已确认）：

1. **passive**：捕获 + 队列闭环，不做代理内联检测（等价 CLI `--no-live-scan` 工作流）
2. **profile**：列表 + 应用 + 保存（不做 export/import/delete）
3. **认证**：五种常用（form / bearer / basic / apikey / cookie），自动启用登录态维持
4. **explain**：结果表展开行明细 + JSON 导出
5. **布局**：分 Tab + 修复死标签 + 模块列表动态化
6. **实现**：方案 A —— 薄 app + 服务层 + 共享核心提取
7. **测试**：端点级测试 + web_ui 纳入 ruff/CI
8. **版本**：完成后升至 2.3.0

## 2. 非目标

- 不做代理内联实时检测（与 T3.1 推荐工作流一致，避免重复做功）
- 不做 profile 的 export / import / delete UI
- 不做高级认证字段（`csrf_fields` / `login_extra` / `success_check` / `fail_check` / 双账号 `--second-auth`）
- 不做多会话并发（沿用「单扫描 + 单被动」单例，重复启动 409）
- 不做 Blueprint / 模板分文件重构（当前规模 YAGNI）
- 不改变现有鉴权模型（session + `X-Api-Token` + CSRF）

## 3. 架构与组件边界

```
web_ui/
  app.py            # Flask 路由 + 鉴权/CSRF + 模板渲染（保持薄）
  sessions.py       # ScanSession（扫描线程+SSE+结果）/ PassiveProxySession（代理线程+统计）
  payloads.py       # 纯函数：请求 JSON → ConfigManager / 模块列表 / 认证 options
  templates/index.html
wvs/plugins/auth.py               # + configure_from_options() / authenticate_and_apply()
wvs/core/passive/queue_scan.py    # 新增：queue_scan 共享实现（自 cli.py 转正）
wvs/cli.py                        # 改为导入共享实现；cmd_scan 认证段改用共享装配函数
tests/test_web_ui.py              # 新增
tests/test_from_proxy.py          # 改用公共 API 导入
```

职责：

- **app.py**：仅 HTTP 层——路由、鉴权、CSRF、请求解析、响应序列化；不写业务逻辑
- **sessions.py**：有状态、线程/事件循环管理、SSE 队列、结果暂存；对 HTTP 层暴露 `start() / stop() / status() / events()`
- **payloads.py**：无状态纯函数，可脱离 Flask 单测——profile 解析与优先级、auth options 解析、模块解析
- **共享提取**：CLI 与 UI 共用同一实现，不复制业务逻辑

## 4. 共享核心提取（行为零变化）

### 4.1 `wvs/core/passive/queue_scan.py`（自 `wvs/cli.py:190-282` 搬运）

```python
def apply_gentle_rate_cap(config: ConfigManager) -> int
def queue_endpoint_to_target(ep) -> ScanTarget
async def scan_proxy_queue(scanner, session, endpoints, target_url: str, concurrency: int, queue_result) -> ScanResult
```

- 函数体逐字搬运；新模块自带 `logger` 与 `Console()`，不 import `wvs.cli`（避免循环依赖）
- `wvs/cli.py` 以导入别名保留私有名（`_apply_gentle_rate_cap = apply_gentle_rate_cap` 等），CLI 内部引用零改动
- `tests/test_from_proxy.py` 改从新模块导入公共名，锁定共享契约

### 4.2 `wvs/plugins/auth.py` 新增

```python
def configure_from_options(auth_manager: AuthManager, options: Dict[str, Any]) -> Tuple[bool, str]
async def authenticate_and_apply(auth_manager: AuthManager, target: ScanTarget, http_pool) -> Tuple[bool, str]
```

`options` schema（缺参/未知类型 → `(False, 错误信息)`）：

| type | 字段 |
|---|---|
| `form` | `login_url`, `username`, `password`（必填）；`login_extra`（`["k=v"]`）、`csrf_fields`、`success_check`、`fail_check`（可选） |
| `bearer` | `token`（必填）；`header_name`（默认 `Authorization`） |
| `basic` | `username`, `password`（必填） |
| `apikey` | `api_key`（必填）；`api_key_header`（默认 `X-API-Key`） |
| `cookie` | `cookies`：`{"k": "v"}` 或 `"k=v; k2=v2"` 字符串（必填） |

`authenticate_and_apply` 复刻 CLI 语义：临时 `httpx.AsyncClient` 认证 → 失败返回 `(False, error)` → `apply_to_target(target)` → cookie 同步进 `HTTPPool` → 注册 T2.4 自动重登回调（重登成功刷新 cookie/header）。凭据不写日志。

`wvs/cli.py::cmd_scan` 认证段（`cli.py:468-564`）改为：

```python
options = _auth_options_from_args(args)   # 本地映射，保持 CLI 文案不变
ok, err = configure_from_options(auth_manager, options)
if ok:
    ok, err = asyncio.run(authenticate_and_apply(auth_manager, target, session))
if not ok:
    console.print(f"[red][X] 认证失败: {err}[/red]"); return 1
```

CLI 的其他输出（认证中/成功 cookie 数/登录态维持提示）保持在 cmd_scan 内打印，输出文案不变。

## 5. 后端 API

所有端点沿用现有鉴权（session 或 `X-Api-Token`）；POST 走 CSRF 校验。

### 5.1 扫描

`POST /api/scan`：

```json
{
  "url": "http://target",
  "modules": ["sqli", "xss"],
  "profile": "gentle",
  "explain": true,
  "from_proxy": false,
  "rate": 15, "timeout": 15, "crawl_depth": 2,
  "crawl_max_urls": 50, "concurrent_endpoints": 10, "insecure": false,
  "auth": {"type": "form", "login_url": "...", "username": "...", "password": "..."}
}
```

- 配置优先级：**profile 先应用 → 请求显式字段覆盖**（与 CLI `use` + 覆盖语义一致）
- 模块解析：`modules` 非空 → 用之；否则 profile 的 `modules.enabled` 非空 → 用之；否则全部 core（`--all-modules` 语义可通过显式传 lite 模块名实现）
- `explain: true` → 模块加载前 `config.set("explain", True)`
- `auth` 存在且解析失败 → 400 不启动；认证执行失败 → SSE `log` ERROR + `done`，不进入扫描
- 认证成功 → 会话维持生效（T2.4）
- `from_proxy: true` → 跳过爬取：读取本服务最近一次被动会话的队列文件 → `filter_for_target` → `apply_gentle_rate_cap` → `scan_proxy_queue`；无可用队列 / 过滤后为空 → 400
- 完成（含超时/异常）→ `_record_scan()` 落账历史（带部分结果）
- SSE `result` 每条漏洞新增：`payload`、`description`、`recommendation`、`evidence_chain`

### 5.2 模块与 Profile

| 端点 | 行为 |
|---|---|
| `GET /api/modules` | `register_all_modules()` + `ModuleFactory` → `[{name, description, category, default_enabled}]`（`default_enabled = category == "core"`） |
| `GET /api/profiles` | `ProfileManager.list_profiles()`（含 `builtin` 标记） |
| `GET /api/profiles/<name>` | profile 详情（`params` + `modules`）；未知 → 404 |
| `POST /api/profiles` | `{name, description, modules, params}` → `save_profile`；名称非法 → 400；与内置同名 → 409（内置优先加载，覆盖无意义） |

### 5.3 被动代理

| 端点 | 行为 |
|---|---|
| `POST /api/passive/start` | `{target, listen, port, tls_intercept, ca_dir, queue_out}`；`target` 必填（避免捕获全量流量）；`queue_out` 只允许 `scan_reports/` 下（防任意文件写）；已有代理运行 → 409；启动失败（端口占用等）→ 500 + 错误信息 |
| `POST /api/passive/stop` | 停止并返回最终统计 |
| `GET /api/passive/status` | `{running, listen, target, tls_intercept, ca_dir, queue_path, requests_captured, endpoints_discovered, queued_endpoints, errors}` |

`PassiveProxySession` 实现：后台线程内 `asyncio.new_event_loop()` + `proxy.start()` + `proxy.serve_forever()`；停止用 `asyncio.run_coroutine_threadsafe(proxy.close(), loop)` + `thread.join(timeout=5)`；无内联检测（`scan_callback=None`）。队列路径落盘由 proxy 负责（增量 + 停止覆盖）。

`target` 过滤沿用 `host_matches` 语义：从 URL 提取 netloc 作为 `target_filter`（与 CLI `cmd_passive` 相同）。

### 5.4 导出与历史

- `GET /api/export/json`：字段补齐 `payload / description / recommendation / evidence_chain`，清理从未填充的 `_found_vulns` 死引用
- `GET /api/history`、`GET /api/stats`：保持现状，依赖 `_record_scan` 接通后有数据

## 6. 前端设计（index.html）

- **导航**：Bootstrap Tab 三项——扫描 / 被动捕获 / 历史；修复现有两个不可达 `tab-pane`
- **扫描 Tab**
  - Profile 行：下拉（`/api/profiles`）+「应用」（拉详情填充表单与模块勾选）+「保存为」（名称/描述对话框 → `POST /api/profiles`，取当前表单 + 勾选模块）
  - 扫描配置卡片新增：explain 开关（默认开）、认证折叠面板（类型下拉 none/form/bearer/basic/apikey/cookie，按类型动态显隐字段）
  - 模块列表：`/api/modules` 动态渲染，保留全选/取消
  - 「从被动队列扫描」复选框：仅当 `/api/passive/status` 报告可用队列时可用
  - 结果表行点击展开详情行：evidence_chain 逐条 `kind / detail`（`data` 折叠 JSON）+ description / recommendation / payload
- **被动捕获 Tab**
  - 表单：目标域（必填，前端硬拦截）、监听地址/端口、TLS 解密开关 + CA 目录（可空 = 默认 `~/.rayscan/ca`）、队列文件（限 `scan_reports/` 内）
  - 启动/停止 + 2s 轮询状态卡片；TLS 开启时展示代理地址与 CA 信任提示
  - 「去扫描队列」→ 切到扫描 Tab、预填目标域并勾选 from_proxy（用户手动点开始，不自动发起）
- **历史 Tab**：现有卡片/列表接上导航；修复 `loadHistory` 与仪表盘可见性
- **版本**：模板统一渲染 `{{ version }}`（`wvs.__version__`），替换硬编码 2.2.0

## 7. 错误处理与安全

- 扫描 worker 异常：SSE ERROR 日志 + `done`，`scanning=False`，历史记录带已有部分结果
- 超时：`asyncio.wait_for(max_scan_time)` 语义保持
- 被动线程异常：`status.errors` 暴露，停止后状态可读；端口占用等启动失败同步返回 500
- `queue_out` 服务端 resolve 后校验位于 `scan_reports/`；`from_proxy` 只读服务端记录的队列路径，不接受客户端路径
- profile 名称由 `ProfileManager` 白名单校验（`^[A-Za-z0-9_-]{1,64}$`）防路径穿越
- 认证凭据仅内存、不回显、不写日志；SSE 只输出成功/失败与 provider 名
- 不新增 URL 校验逻辑（Web UI 现状即不校验；扫描本机靶场是主要用途）

## 8. 测试计划（`tests/test_web_ui.py`）

| # | 用例 |
|---|---|
| 1 | 未授权访问 API → 401；`X-Api-Token` 放行 |
| 2 | 已授权 POST 缺 CSRF → 403 |
| 3 | `payloads`：profile 应用 + 显式覆盖优先级 |
| 4 | `payloads`：五种 auth options 解析；缺参 → 错误 |
| 5 | `GET /api/modules` 返回全部 18 模块、core/lite 标记正确 |
| 6 | profiles：列表（含内置）/ 详情 / 保存（注入 tmp 目录）/ 非法名 400 / 内置同名 409 |
| 7 | 扫描：桩 `WAVScanner`/`HTTPPool` → explain/profile/auth 透传、SSE result 含 evidence_chain |
| 8 | 扫描异常/结束 → `_record_scan` 历史落账 |
| 9 | `GET /api/export/json` 含 evidence_chain |
| 10 | 被动：桩 `PassiveProxy` → start/status/stop、重复 start 409、target 为空 400 |
| 11 | `from_proxy`：无队列 400；临时队列 + 桩模块 → 漏洞并入结果 |
| 12 | `queue_scan` 公共 API 冒烟（`apply_gentle_rate_cap` 返回值语义） |

`tests/test_from_proxy.py` 改公共导入后全量回归。CI：lint/format 命令加 `web_ui/`；`pre-commit` ruff hook 同步覆盖。

## 9. 文档与版本

- `CHANGELOG.md` 新增 T3.5 条目
- 路线图 T3.5 标记完成
- `AGENTS.md` 变更日志条目
- 版本 2.2.0 → 2.3.0：`pyproject.toml`、`wvs/__init__.py` 及全仓版本引用（README 等）按 SSOT 规则更新；`test_version_consistency` 保障一致

## 10. 验收

1. `python web_ui/app.py` → token 登录 → 三 Tab 均可达
2. 不选 profile/认证跑一次扫描：结果表出现漏洞、行可展开证据链、JSON 导出含 `evidence_chain`、历史 Tab 有记录
3. 选 `gentle` profile + form 认证扫描：认证成功日志、配置速率被 profile/显式覆盖语义正确
4. 被动 Tab：启动代理（本机靶场为目标域）→ 浏览器经代理访问 → 状态卡片计数增长、队列文件生成 → 停止 → 「去扫描队列」预填 → from_proxy 扫描检出捕获面漏洞
5. 全量 `pytest` 通过；`ruff check` / `ruff format --check` 覆盖 `web_ui/` 全绿；黄金矩阵不受影响（web_ui 不在扫描链路）
