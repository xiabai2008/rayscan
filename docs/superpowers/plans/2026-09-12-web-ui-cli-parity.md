# RayScan Web UI 对齐 CLI（v2.3 T3.5）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Web UI 接入 passive 捕获队列闭环、profile 应用/保存、五类认证与证据链展示，完成 v2.3 T3.5。

**Architecture:** `web_ui/app.py` 收敛为薄 HTTP 层；新增 `web_ui/sessions.py`（扫描/被动会话线程管理）与 `web_ui/payloads.py`（纯函数配置装配）。CLI 私有实现提取为共享模块（`wvs/core/passive/queue_scan.py` + `wvs/plugins/auth.py` 两个函数），CLI 行为不变。

**Tech Stack:** Flask 3 + SSE、Bootstrap 5.3（CDN）、asyncio/threading、pytest + Flask test client、ruff。

**Spec:** `docs/superpowers/specs/2026-09-12-web-ui-cli-parity-design.md`

---

## 文件结构

| 文件 | 动作 | 职责 |
|---|---|---|
| `wvs/core/passive/queue_scan.py` | 新建 | passive→active 联动共享实现（自 cli.py 搬运） |
| `wvs/plugins/auth.py` | 修改 | +`parse_cookies` / `configure_from_options` / `authenticate_and_apply` |
| `wvs/cli.py` | 修改 | 导入共享实现；cmd_scan 认证段改用共享装配；+`_auth_options_from_args` |
| `web_ui/__init__.py` | 新建 | 空包声明 |
| `web_ui/payloads.py` | 新建 | profile/参数/模块解析纯函数 + 模块目录 |
| `web_ui/sessions.py` | 新建 | `ScanSession` / `PassiveProxySession` / `serialize_vuln` |
| `web_ui/app.py` | 重写 | 路由 + 鉴权/CSRF + wiring（原 ScanSession 移出） |
| `web_ui/templates/index.html` | 修改 | Tab 导航、profile/认证/explain、结果详情行、被动面板 |
| `tests/test_auth_assembly.py` | 新建 | 共享认证装配测试 |
| `tests/test_web_ui.py` | 新建 | payloads / sessions / API 测试 |
| `tests/test_from_proxy.py` | 修改 | 改公共 API 导入 |
| `.github/workflows/ci.yml` | 修改 | ruff 覆盖 `web_ui/` |
| `pyproject.toml` / `wvs/__init__.py` / `README.md` 等 | 修改 | 版本 2.3.0 |
| `CHANGELOG.md` / `docs/rayscan-upgrade-roadmap-2026-09-07.md` / `AGENTS.md` | 修改 | 文档 |

---

### Task 0: 功能分支

- [ ] **Step 1: 创建分支**

```powershell
git checkout -b feat/v23-t35-web-ui
git status
```

Expected: `On branch feat/v23-t35-web-ui`，工作区干净。

---

### Task 1: queue_scan 共享提取（行为零变化）

**Files:**
- Create: `wvs/core/passive/queue_scan.py`
- Modify: `wvs/cli.py:190-282`（删除三个私有函数，改为导入别名）
- Modify: `tests/test_from_proxy.py:23`（改公共导入）

- [ ] **Step 1: 新建 `wvs/core/passive/queue_scan.py`（内容为 cli.py:190-282 逐字搬运，改名公共）**

```python
"""passive→active 联动共享实现（v2.3 T3.1 自 cli.py 转正）。

CLI（`rayscan scan --from-proxy`）与 Web UI（被动捕获队列定向扫描）共用:
- apply_gentle_rate_cap: 联动速率上限取 gentle 预设（用户更低速率优先）
- queue_endpoint_to_target: 队列端点 → ScanTarget（按参数类型分流）
- scan_proxy_queue: 定向主动验证（不爬取，复用已加载模块）
"""

from __future__ import annotations

import asyncio
import logging

from rich.console import Console

from ...config import ConfigManager
from ...models import ScanResult, ScanTarget

logger = logging.getLogger(__name__)
console = Console()


def apply_gentle_rate_cap(config: ConfigManager) -> int:
    """--from-proxy 联动扫描的速率上限取 gentle 预设（被动流量授权面,强制低速）。

    用户显式给出的更低速率先于上限生效(取 min);gentle 预设不可用时回退
    当前默认上限并告警。返回生效速率。
    """
    from ...profiles import ProfileManager

    gentle_rate = None
    try:
        profile = ProfileManager().load_profile("gentle")
        if profile:
            gentle_rate = (profile.get("params") or {}).get("rate")
    except Exception as e:  # noqa: BLE001
        logger.debug("gentle 预设读取失败: %s", e)
    try:
        gentle_rate = int(gentle_rate)
    except (TypeError, ValueError):
        gentle_rate = 0
    if gentle_rate <= 0:
        gentle_rate = int(config.get("max_requests_per_second", 10) or 10)
        console.print(f"[yellow][!] gentle 预设不可用,联动速率回退默认上限 {gentle_rate} req/s[/yellow]")
    current = int(config.get("rate", 10) or 10)
    effective = min(current, gentle_rate)
    config.set("rate", effective)
    config.set("max_requests_per_second", effective)
    return effective


def queue_endpoint_to_target(ep) -> ScanTarget:
    """队列端点 → ScanTarget（按参数类型分流：query→params、body/json→data、cookie→cookies）。"""
    params = {}
    data = {}
    cookies = {}
    ptypes = getattr(ep, "param_types", None) or {}
    for k, v in (getattr(ep, "parameters", None) or {}).items():
        t = ptypes.get(k, "query")
        if t == "cookie":
            cookies[k] = v
        elif t == "query":
            params[k] = v
        else:  # body / json
            data[k] = v
    method = (getattr(ep, "method", None) or "GET").upper()
    return ScanTarget(
        url=getattr(ep, "url", ""),
        methods=[method],
        params=params or None,
        data=data or None,
        cookies=cookies or None,
        param_types=dict(ptypes) or None,
    )


async def scan_proxy_queue(scanner, session, endpoints, target_url: str, concurrency: int, queue_result) -> ScanResult:
    """--from-proxy 定向主动验证：队列端点逐个交给已加载模块（不爬取,复用现有模块）。

    限速由 HTTPPool 内置 RateLimiter 统一执行（联动模式速率上限=gentle 预设）;
    端点间并发由 semaphore 控制（与主动扫描 concurrent_endpoints 同源）。
    发现随做随写入 queue_result（超时/中断可抢救）,返回前去重。
    """
    sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def verify_one(ep):
        async with sem:
            ep_target = queue_endpoint_to_target(ep)
            for mod_name, module in list(scanner._modules.items()):
                try:
                    vulns = await module.scan(ep_target)
                except Exception as e:  # noqa: BLE001
                    logger.debug("[FromProxy] 模块 %s 对 %s 检测失败: %s", mod_name, getattr(ep, "url", ep), e)
                    continue
                for v in vulns or []:
                    if not v.module:
                        v.module = mod_name
                    if isinstance(getattr(v, "context", None), dict):
                        v.context.setdefault("source", "proxy_queue")
                    queue_result.vulnerabilities.append(v)

    await asyncio.gather(*(verify_one(ep) for ep in endpoints))

    seen = set()
    unique = []
    for v in queue_result.vulnerabilities:
        sig = f"{v.type.value}|{v.url or ''}|{v.parameter or ''}|{v.payload or ''}".lower()
        if sig not in seen:
            seen.add(sig)
            unique.append(v)
    queue_result.vulnerabilities = unique
    queue_result.requests_made = session.get_stats().get("total_requests", 0)
    queue_result.modules_run = len(scanner._modules)
    queue_result.endpoints_found = len(endpoints)
    return queue_result
```

- [ ] **Step 2: 删除 `wvs/cli.py:190-282` 的三个函数，在导入区加别名导入**

在 `wvs/cli.py` 的 `from .config import ConfigManager` 之后插入：

```python
from .core.passive.queue_scan import (
    apply_gentle_rate_cap as _apply_gentle_rate_cap,
    queue_endpoint_to_target as _queue_endpoint_to_target,
    scan_proxy_queue as _scan_proxy_queue,
)
```

- [ ] **Step 3: 更新 `tests/test_from_proxy.py` 导入与调用名**

第 23 行改为：

```python
from wvs.core.passive.queue_scan import apply_gentle_rate_cap, queue_endpoint_to_target, scan_proxy_queue
```

全文替换调用名：`_apply_gentle_rate_cap(` → `apply_gentle_rate_cap(`（2 处）、`_queue_endpoint_to_target(` → `queue_endpoint_to_target(`（1 处）、`_scan_proxy_queue(` → `scan_proxy_queue(`（3 处）。文档字符串第 8-9 行的函数名同步去掉下划线。

- [ ] **Step 4: 跑测试验证零变化**

```powershell
python -m pytest tests/test_from_proxy.py -q
```

Expected: `9 passed`（与搬运前一致）。

- [ ] **Step 5: 提交**

```powershell
git add wvs/core/passive/queue_scan.py wvs/cli.py tests/test_from_proxy.py
git commit -m "refactor(v2.3): queue_scan 联动实现自 cli.py 转正为共享模块（T3.5 前置）"
```

---

### Task 2: 认证装配共享函数（TDD）

**Files:**
- Modify: `wvs/plugins/auth.py`（`typing` 增加 `Tuple`；文件末尾追加三个函数）
- Modify: `wvs/cli.py`（+`_auth_options_from_args`；cmd_scan 认证段替换）
- Create: `tests/test_auth_assembly.py`

- [ ] **Step 1: 写失败测试 `tests/test_auth_assembly.py`**

```python
"""认证装配共享函数测试（v2.3 T3.5：CLI 与 Web UI 共用）。

覆盖:
- configure_from_options 五种类型装配 / 缺参报错 / cookie 字符串解析
- authenticate_and_apply 成功注入凭据并注册重登回调；失败返回错误
- _auth_options_from_args 的 CLI 参数映射与旧参数兼容
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from wvs.models import ScanTarget
from wvs.plugins.auth import (
    AuthManager,
    authenticate_and_apply,
    configure_from_options,
    parse_cookies,
)


class _FakePool:
    def __init__(self):
        self.cookies = {}
        self.headers = {}
        self.reauth_handler = None

    def set_cookie(self, url, name, value, domain=None):
        self.cookies[name] = value

    def set_header(self, name, value):
        self.headers[name] = value

    def set_reauth_handler(self, handler):
        self.reauth_handler = handler


class _FakeAuthManager:
    provider_name = "FakeAuth"

    def __init__(self, ok=True, error=None):
        self._ok = ok
        self._error = error
        self.calls = 0

    async def authenticate(self, client):
        self.calls += 1
        return {
            "authenticated": self._ok,
            "cookies": {"sid": "abc"} if self._ok else {},
            "headers": {"X-Token": "t"} if self._ok else {},
            "error": self._error,
        }

    @property
    def is_authenticated(self):
        return self._ok

    @property
    def auth_error(self):
        return self._error

    def apply_to_target(self, target):
        target.cookies.update({"sid": "abc"})
        target.headers.update({"X-Token": "t"})
        return target


def test_parse_cookies_string_and_dict():
    assert parse_cookies("a=1; b=2") == {"a": "1", "b": "2"}
    assert parse_cookies({"a": "1"}) == {"a": "1"}
    assert parse_cookies("") == {}


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({"type": "bearer", "token": "t"}, "BearerTokenAuth"),
        ({"type": "basic", "username": "u", "password": "p"}, "BasicAuth"),
        ({"type": "apikey", "api_key": "k"}, "APIKeyAuth"),
        ({"type": "cookie", "cookies": "a=1; b=2"}, "CookieAuth"),
        (
            {"type": "form", "login_url": "http://x/login", "username": "u", "password": "p"},
            "FormLoginAuth",
        ),
    ],
)
def test_configure_from_options_types(options, expected):
    manager = AuthManager()
    ok, err = configure_from_options(manager, options)
    assert ok, err
    assert manager.provider_name == expected


def test_configure_from_options_missing_args():
    ok, err = configure_from_options(AuthManager(), {"type": "form", "username": "u", "password": "p"})
    assert not ok and "login_url" in err
    ok, err = configure_from_options(AuthManager(), {"type": "bearer"})
    assert not ok and "token" in err
    ok, err = configure_from_options(AuthManager(), {"type": "cookie", "cookies": ""})
    assert not ok and "cookies" in err
    ok, err = configure_from_options(AuthManager(), {"type": "wat"})
    assert not ok and "不支持的认证类型" in err


def test_authenticate_and_apply_success_registers_reauth():
    manager = _FakeAuthManager(ok=True)
    pool = _FakePool()
    target = ScanTarget(url="http://t")
    ok, err = asyncio.run(authenticate_and_apply(manager, target, pool))
    assert ok and err == ""
    assert target.cookies == {"sid": "abc"}
    assert target.headers == {"X-Token": "t"}
    assert pool.cookies == {"sid": "abc"}
    assert callable(pool.reauth_handler)
    assert asyncio.run(pool.reauth_handler()) is True
    assert manager.calls == 2  # 初次认证 + 重登


def test_authenticate_and_apply_failure_returns_error():
    manager = _FakeAuthManager(ok=False, error="bad creds")
    pool = _FakePool()
    ok, err = asyncio.run(authenticate_and_apply(manager, ScanTarget(url="http://t"), pool))
    assert not ok and err == "bad creds"
    assert pool.reauth_handler is None


def test_auth_options_from_args_maps_fields():
    from wvs.cli import _auth_options_from_args

    args = SimpleNamespace(
        auth_type="form",
        login_url="http://x/login",
        username="u",
        password="p",
        token=None,
        cookies=None,
        api_key=None,
        api_key_header="X-API-Key",
        success_check="ok",
        fail_check="bad",
        csrf_fields=["_csrf"],
        login_extra=["tenant=1"],
    )
    options = _auth_options_from_args(args)
    assert options["type"] == "form"
    assert options["login_url"] == "http://x/login"
    assert options["login_extra"] == ["tenant=1"]
    assert options["csrf_fields"] == ["_csrf"]


def test_auth_options_from_args_legacy_and_none():
    from wvs.cli import _auth_options_from_args

    legacy = SimpleNamespace(
        auth_type=None,
        login_url="http://x/login",
        username="u",
        password="p",
        token=None,
        cookies=None,
        api_key=None,
        api_key_header="X-API-Key",
        success_check=None,
        fail_check=None,
        csrf_fields=None,
        login_extra=None,
    )
    assert _auth_options_from_args(legacy)["type"] == "form"

    empty = SimpleNamespace(**{**legacy.__dict__, "login_url": None, "username": None, "password": None})
    assert _auth_options_from_args(empty) is None
```

- [ ] **Step 2: 跑测试确认失败**

```powershell
python -m pytest tests/test_auth_assembly.py -q
```

Expected: FAIL — `ImportError: cannot import name 'authenticate_and_apply'`（或 `cannot import name '_auth_options_from_args'`）。

- [ ] **Step 3: 在 `wvs/plugins/auth.py` 末尾追加实现**

`from typing import ...` 行加入 `Tuple`。文件末尾追加：

```python
def parse_cookies(raw: Any) -> Dict[str, str]:
    """解析 cookie 输入：dict 原样返回；"k=v; k2=v2" 字符串 → dict。"""
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    cookies: Dict[str, str] = {}
    for part in str(raw or "").split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.strip()
            if key:
                cookies[key] = value.strip()
    return cookies


def configure_from_options(auth_manager: "AuthManager", options: Dict[str, Any]) -> Tuple[bool, str]:
    """按 options 字典装配 AuthManager（CLI 与 Web UI 共用）。

    支持 type: form/bearer/basic/apikey/cookie。缺参/未知类型返回 (False, 错误信息)。
    """
    auth_type = str((options or {}).get("type") or "").strip().lower()
    if not auth_type:
        return False, "缺少认证类型 auth.type"
    if auth_type == "form":
        login_url = options.get("login_url")
        username = options.get("username")
        password = options.get("password")
        if not login_url:
            return False, "auth-type form 需要 login_url"
        if not (username and password):
            return False, "auth-type form 需要 username 和 password"
        extra: Dict[str, str] = {}
        for pair in options.get("login_extra") or []:
            if "=" in str(pair):
                key, value = str(pair).split("=", 1)
                extra[key] = value
        form_kwargs: Dict[str, Any] = {"extra_fields": extra}
        if options.get("csrf_fields"):
            form_kwargs["csrf_fields"] = options["csrf_fields"]
        if options.get("success_check"):
            form_kwargs["success_check"] = options["success_check"]
        if options.get("fail_check"):
            form_kwargs["fail_check"] = options["fail_check"]
        auth_manager.configure_form_login(
            login_url=login_url, username=username, password=password, **form_kwargs
        )
    elif auth_type == "bearer":
        if not options.get("token"):
            return False, "auth-type bearer 需要 token"
        auth_manager.configure_bearer(
            token=str(options["token"]), header_name=str(options.get("header_name") or "Authorization")
        )
    elif auth_type == "basic":
        if not (options.get("username") and options.get("password")):
            return False, "auth-type basic 需要 username 和 password"
        auth_manager.configure_basic(username=str(options["username"]), password=str(options["password"]))
    elif auth_type == "apikey":
        if not options.get("api_key"):
            return False, "auth-type apikey 需要 api_key"
        auth_manager.configure_api_key(
            key=str(options["api_key"]), header_name=str(options.get("api_key_header") or "X-API-Key")
        )
    elif auth_type == "cookie":
        cookies = parse_cookies(options.get("cookies"))
        if not cookies:
            return False, "auth-type cookie 需要 cookies"
        auth_manager.configure_cookies(cookies=cookies)
    else:
        return False, f"不支持的认证类型: {auth_type}"
    return True, ""


async def authenticate_and_apply(auth_manager: "AuthManager", target: ScanTarget, http_pool: Any) -> Tuple[bool, str]:
    """执行认证并把凭据注入 target 与 HTTPPool，注册登录态维持回调（T2.4）。

    成功: target.cookies/target.headers 携带认证结果; http_pool 注入 cookie 并注册重登。
    失败: 返回 (False, 错误信息)，不修改 http_pool。
    """
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as tmp_client:
        await auth_manager.authenticate(tmp_client)
    if not auth_manager.is_authenticated:
        return False, auth_manager.auth_error or "认证失败"
    auth_manager.apply_to_target(target)
    for name, value in target.cookies.items():
        http_pool.set_cookie(target.url, name, value)

    async def _reauth_handler() -> bool:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30) as tmp_client:
            result = await auth_manager.authenticate(tmp_client)
        if not result.get("authenticated"):
            return False
        for name, value in (result.get("cookies") or {}).items():
            http_pool.set_cookie(target.url, name, value)
        for name, value in (result.get("headers") or {}).items():
            http_pool.set_header(name, value)
        return True

    http_pool.set_reauth_handler(_reauth_handler)
    return True, ""
```

- [ ] **Step 4: 在 `wvs/cli.py` 增加 `_auth_options_from_args`（放在 `cmd_scan` 之前）**

```python
def _auth_options_from_args(args) -> Optional[Dict[str, Any]]:
    """CLI 认证参数 → 共享 options 字典（None = 未配置认证）。"""
    auth_type = getattr(args, "auth_type", None)
    if (
        not auth_type
        and getattr(args, "username", None)
        and getattr(args, "password", None)
        and getattr(args, "login_url", None)
    ):
        auth_type = "form"  # 旧参数兼容
    if not auth_type:
        return None
    options: Dict[str, Any] = {"type": auth_type}
    for key in (
        "login_url",
        "username",
        "password",
        "token",
        "cookies",
        "api_key",
        "api_key_header",
        "success_check",
        "fail_check",
    ):
        value = getattr(args, key, None)
        if value is not None:
            options[key] = value
    if getattr(args, "login_extra", None):
        options["login_extra"] = list(args.login_extra)
    if getattr(args, "csrf_fields", None):
        options["csrf_fields"] = list(args.csrf_fields)
    return options
```

`wvs/cli.py` 顶部导入行改为：

```python
from .plugins.auth import AuthManager, authenticate_and_apply, configure_from_options
```

`typing` 导入确认含 `Optional, Dict, Any`（cli.py 顶部检查，缺则补）。

- [ ] **Step 5: 替换 cmd_scan 认证段（原 `cli.py:468-564`）**

```python
    # 认证处理（v2.3 T3.5：装配/执行与 Web UI 共享 wvs.plugins.auth）
    target = ScanTarget(url=target_url)
    auth_options = _auth_options_from_args(args)
    if auth_options:
        auth_manager = AuthManager(config)
        ok, err = configure_from_options(auth_manager, auth_options)
        if not ok:
            console.print(f"[red]错误：{err}[/red]")
            return 1
        console.print(f"[cyan][AUTH] 正在执行认证 ({auth_manager.provider_name})...[/cyan]")
        ok, err = asyncio.run(authenticate_and_apply(auth_manager, target, session))
        if not ok:
            console.print(f"[red][X] 认证失败: {err}[/red]")
            return 1
        console.print("[green][OK] 认证成功[/green]")
        console.print(f"[cyan]  已同步 {len(target.cookies)} 个 cookie 到扫描 session[/cyan]")
        console.print("[cyan]  已启用登录态维持（会话失效自动重登）[/cyan]")
```

- [ ] **Step 6: 跑测试**

```powershell
python -m pytest tests/test_auth_assembly.py tests/test_smoke_cli.py tests/test_session_reauth.py tests/test_idor_second_auth.py -q
```

Expected: 全部 PASS。

- [ ] **Step 7: 提交**

```powershell
git add wvs/plugins/auth.py wvs/cli.py tests/test_auth_assembly.py
git commit -m "refactor(v2.3): 认证装配/执行提取为共享函数（configure_from_options/authenticate_and_apply）"
```

---

### Task 3: web_ui/payloads.py（TDD）

**Files:**
- Create: `web_ui/__init__.py`
- Create: `web_ui/payloads.py`
- Create: `tests/test_web_ui.py`（TestPayloads 部分）

- [ ] **Step 1: 建包声明**

`web_ui/__init__.py`：

```python
"""RayScan Web UI（Flask + SSE）。"""
```

- [ ] **Step 2: 写失败测试（新建 `tests/test_web_ui.py`，先放 TestPayloads）**

```python
"""v2.3 T3.5 Web UI 对齐 CLI 测试。

覆盖:
- payloads: profile 应用与显式覆盖优先级、模块解析、模块目录
- ScanSession: explain/认证透传、from_proxy 定向扫描、历史回调
- PassiveProxySession: start/status/stop 状态机、重复启动拒绝
- API: 鉴权/CSRF、profile 保存、扫描校验、被动参数校验、导出证据链
"""

from __future__ import annotations

import pytest

from wvs.config import ConfigManager
from wvs.profiles import ProfileManager

from web_ui import payloads


class TestPayloads:
    def test_profile_then_explicit_override(self, tmp_path):
        manager = ProfileManager(tmp_path)
        manager.save_profile("quick", {"name": "quick", "params": {"rate": 5, "crawl_depth": 1}})
        cfg = ConfigManager()
        name = payloads.apply_scan_config(cfg, {"profile": "quick", "rate": 20, "explain": True}, manager)
        assert name == "quick"
        assert cfg.get("rate") == 20  # 显式覆盖 profile
        assert cfg.get("crawl_depth") == 1  # profile 保留
        assert cfg.get("explain") is True

    def test_unknown_profile_raises(self, tmp_path):
        with pytest.raises(ValueError):
            payloads.apply_scan_config(
                ConfigManager(), {"profile": "nope"}, ProfileManager(tmp_path)
            )

    def test_resolve_scan_modules_precedence(self, tmp_path):
        manager = ProfileManager(tmp_path)
        manager.save_profile("only-xss", {"name": "only-xss", "modules": {"enabled": ["xss"], "disabled": []}})
        assert payloads.resolve_scan_modules({"modules": ["sqli"]}, "only-xss", manager) == ["sqli"]
        assert payloads.resolve_scan_modules({}, "only-xss", manager) == ["xss"]
        assert payloads.resolve_scan_modules({}, None, manager) == []  # 空 = 交给 scanner 默认

    def test_module_catalog_core_and_lite(self):
        catalog = payloads.module_catalog()
        names = {m["name"] for m in catalog}
        assert {"sqli", "xss", "mcp", "graphql"} <= names
        assert len(catalog) >= 18
        assert all(isinstance(m["default_enabled"], bool) for m in catalog)
        first_lite = min((i for i, m in enumerate(catalog) if m["category"] != "core"), default=len(catalog))
        assert all(m["category"] == "core" for m in catalog[:first_lite])
```

- [ ] **Step 3: 跑测试确认失败**

```powershell
python -m pytest tests/test_web_ui.py -q
```

Expected: FAIL — `ModuleNotFoundError: No module named 'web_ui.payloads'`。

- [ ] **Step 4: 实现 `web_ui/payloads.py`**

```python
"""Web UI 请求参数 → 扫描配置（纯函数，可脱离 Flask 单测）。

职责边界:不发起网络请求、不创建会话;只做 profile/参数/模块解析。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from wvs.config import ConfigManager
from wvs.profiles import ProfileManager

# 请求字段 → ConfigManager 键（显式值覆盖 profile）
_OVERRIDE_FIELDS = {
    "rate": "rate",
    "timeout": "timeout",
    "crawl_depth": "crawl_depth",
    "crawl_max_urls": "crawl_max_urls",
    "concurrent_endpoints": "concurrent_endpoints",
}


def apply_scan_config(
    config: ConfigManager, payload: Dict[str, Any], profile_manager: Optional[ProfileManager] = None
) -> Optional[str]:
    """应用 profile 与请求覆盖（profile 先、显式字段后），返回生效 profile 名。

    未知 profile / 非法数值抛 ValueError（调用方转 400）。
    """
    name = str(payload.get("profile") or "").strip()
    if name:
        manager = profile_manager or ProfileManager()
        if not manager.apply_to_config(config, name):
            raise ValueError(f"profile 不存在: {name}")
    for src, dst in _OVERRIDE_FIELDS.items():
        value = payload.get(src)
        if value is None or value == "":
            continue
        try:
            config.set(dst, int(value))
        except (TypeError, ValueError):
            raise ValueError(f"参数 {src} 非法: {value!r}") from None
    if payload.get("insecure"):
        config.set("verify_ssl", False)
    if payload.get("explain"):
        config.set("explain", True)
    return name or None


def resolve_scan_modules(
    payload: Dict[str, Any], profile_name: Optional[str], profile_manager: Optional[ProfileManager] = None
) -> List[str]:
    """模块解析：显式 modules > profile modules.enabled > []（scanner 默认 core）。"""
    explicit = payload.get("modules") or []
    if explicit:
        return [str(m) for m in explicit]
    if profile_name:
        manager = profile_manager or ProfileManager()
        enabled, _disabled = manager.get_profile_modules(profile_name)
        if enabled:
            return [str(m) for m in enabled]
    return []


def module_catalog() -> List[Dict[str, Any]]:
    """全部注册模块目录（core 在前），供前端动态渲染。"""
    from wvs.modules import register_all_modules
    from wvs.modules.base import ModuleFactory

    register_all_modules()
    catalog: List[Dict[str, Any]] = []
    for name in ModuleFactory.list_modules():
        info = ModuleFactory.get_module_info(name)
        if not info:
            continue
        catalog.append(
            {
                "name": name,
                "description": info.description,
                "category": info.category,
                "default_enabled": info.category == "core",
            }
        )
    catalog.sort(key=lambda item: (item["category"] != "core", item["name"]))
    return catalog
```

- [ ] **Step 5: 跑测试 + ruff**

```powershell
python -m pytest tests/test_web_ui.py -q
ruff check --fix tests/test_web_ui.py web_ui/
ruff format tests/test_web_ui.py web_ui/
```

Expected: `4 passed`。

- [ ] **Step 6: 提交**

```powershell
git add web_ui/__init__.py web_ui/payloads.py tests/test_web_ui.py
git commit -m "feat(v2.3): web_ui.payloads — profile/参数/模块解析纯函数（T3.5）"
```

---

### Task 4: web_ui/sessions.py — ScanSession（TDD）

**Files:**
- Create: `web_ui/sessions.py`
- Modify: `tests/test_web_ui.py`（追加 TestScanSession）

- [ ] **Step 1: 写失败测试（追加到 `tests/test_web_ui.py`）**

导入区追加：

```python
import asyncio
import queue as queue_module
import threading
import time
from types import SimpleNamespace

from wvs.core.crawler import DiscoveredEndpoint
from wvs.core.passive import ProxyCaptureQueue
from wvs.models import ScanResult, ScanTarget, Severity, Vulnerability, VulnerabilityType

from web_ui import sessions
```

文件末尾追加：

```python
def _stub_vuln() -> Vulnerability:
    return Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        title="stub",
        url="http://t/a?id=1",
        parameter="id",
        parameter_type="query",
        payload="' OR 1=1",
        evidence="stub evidence",
        severity=Severity.HIGH,
        evidence_chain=[{"kind": "payload", "detail": "sent payload", "data": {"n": 1}}],
    )


class _StubScanner:
    def __init__(self, config, session):
        self.config = config
        self.session = session
        self._modules = {}
        self._loaded_module_names = []
        self._progress_callback = None

    def load_module(self, name):
        async def _scan(target):
            return []

        self._modules[name] = SimpleNamespace(scan=_scan)
        self._loaded_module_names.append(name)
        return True

    async def scan(self, target):
        return ScanResult(
            target=target, vulnerabilities=[_stub_vuln()], endpoints_found=3, requests_made=7
        )


class _StubPool:
    def __init__(self, config):
        self.config = config
        self.closed = False
        self.reauth_handler = None

    def set_cookie(self, url, name, value, domain=None):
        return None

    def set_header(self, name, value):
        return None

    def set_reauth_handler(self, handler):
        self.reauth_handler = handler

    async def close(self):
        self.closed = True

    def get_stats(self):
        return {"total_requests": 0}


def _drain(q):
    out = []
    while not q.empty():
        out.append(q.get_nowait())
    return out


class TestScanSession:
    def _patch(self, monkeypatch):
        monkeypatch.setattr(sessions, "WAVScanner", _StubScanner)
        monkeypatch.setattr(sessions, "HTTPPool", _StubPool)

    def test_run_scan_emits_result_with_evidence_chain(self, monkeypatch):
        self._patch(monkeypatch)
        s = sessions.ScanSession()
        result = asyncio.run(s._run_scan({"url": "http://t"}, ConfigManager(), ["sqli"], None))
        assert result is not None and len(result.vulnerabilities) == 1
        events = _drain(s.queue)
        result_events = [d for t, d in events if t == "result"]
        assert result_events and result_events[0]["vulnerabilities"][0]["evidence_chain"]
        assert result_events[0]["vulnerabilities"][0]["payload"] == "' OR 1=1"

    def test_run_scan_auth_config_error_aborts(self, monkeypatch):
        self._patch(monkeypatch)
        s = sessions.ScanSession()
        result = asyncio.run(
            s._run_scan({"url": "http://t", "auth": {"type": "bearer"}}, ConfigManager(), ["sqli"], None)
        )
        assert result is None
        logs = [d["text"] for t, d in _drain(s.queue) if t == "log"]
        assert any("认证配置错误" in text for text in logs)

    def test_run_from_proxy_uses_queue_endpoints(self, monkeypatch, tmp_path):
        self._patch(monkeypatch)
        capture = ProxyCaptureQueue()
        endpoint = DiscoveredEndpoint(
            url="http://t/user", method="GET", source_url="http://t/user?id=1", is_api=True
        )
        endpoint.parameters = {"id": "1"}
        endpoint.param_types = {"id": "query"}
        capture.enqueue(endpoint)
        path = capture.save(tmp_path / "queue.json")

        s = sessions.ScanSession()
        result = asyncio.run(
            s._run_scan({"url": "http://t", "from_proxy": True}, ConfigManager(), ["sqli"], path)
        )
        assert result is not None
        assert result.endpoints_found == 1
        assert result.modules_run == 1

    def test_run_from_proxy_missing_file_returns_none(self, monkeypatch, tmp_path):
        self._patch(monkeypatch)
        s = sessions.ScanSession()
        result = asyncio.run(
            s._run_scan({"url": "http://t", "from_proxy": True}, ConfigManager(), ["sqli"], tmp_path / "nope.json")
        )
        assert result is None

    def test_start_thread_calls_on_finish_and_done_event(self, monkeypatch):
        self._patch(monkeypatch)
        s = sessions.ScanSession()
        recorded = []
        s.start(
            {"url": "http://t"},
            ConfigManager(),
            ["sqli"],
            on_finish=lambda r, e, p: recorded.append((r, p)),
        )
        events = []
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                typ, _data = s.queue.get(timeout=1)
            except queue_module.Empty:
                continue
            events.append(typ)
            if typ == "done":
                break
        assert "result" in events
        assert events[-1] == "done"
        assert recorded and recorded[0][0] is not None
        assert recorded[0][1]["url"] == "http://t"
```

- [ ] **Step 2: 跑测试确认失败**

```powershell
python -m pytest tests/test_web_ui.py -q
```

Expected: FAIL — `ModuleNotFoundError: No module named 'web_ui.sessions'`。

- [ ] **Step 3: 实现 `web_ui/sessions.py`（首版含 ScanSession；PassiveProxySession 在 Task 5 追加）**

```python
"""Web UI 扫描会话（v2.3 T3.5）。

从 app.py 抽出:线程/事件循环管理、SSE 事件队列、结果序列化、
认证装配（共享 wvs.plugins.auth）、被动队列联动（共享 wvs.core.passive.queue_scan）。
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import re
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.core.passive import ProxyCaptureQueue
from wvs.core.passive.queue_scan import apply_gentle_rate_cap, scan_proxy_queue
from wvs.models import ScanResult, ScanTarget
from wvs.plugins.auth import AuthManager, authenticate_and_apply, configure_from_options
from wvs.profiles import ProfileManager

logger = logging.getLogger(__name__)


def serialize_vuln(v: Any) -> Dict[str, Any]:
    """漏洞 → SSE/导出 JSON 字典（含 evidence_chain）。"""
    severity = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
    vuln_type = v.type.value if hasattr(v.type, "value") else str(v.type)
    return {
        "severity": severity,
        "type": vuln_type,
        "title": v.title or "",
        "url": v.url or "",
        "method": v.method or "GET",
        "parameter": v.parameter or "",
        "parameter_type": v.parameter_type or "",
        "payload": v.payload or "",
        "evidence": v.evidence or "",
        "description": v.description or "",
        "recommendation": v.recommendation or "",
        "module": v.module or "",
        "evidence_chain": list(v.evidence_chain or []),
    }


class ScanSession:
    """单次扫描会话:worker 线程 + SSE 事件队列 + 结果暂存。"""

    def __init__(self):
        self.queue: queue.Queue = queue.Queue()
        self.scanning = False
        self._thread: Optional[threading.Thread] = None
        self._result: Optional[ScanResult] = None
        self._start_time: Optional[float] = None
        self._module_order: List[str] = []
        self._log_handlers: List[Any] = []
        self._orig_stdout: Any = None

    # ── 日志捕获 ──
    def _setup_log_capture(self) -> None:
        """劫持扫描器模块 logger，输出实时发到 SSE 队列。"""

        class QueueHandler(logging.Handler):
            def __init__(self, q):
                super().__init__()
                self.q = q
                self.setFormatter(logging.Formatter("%(message)s"))

            def emit(self, record):
                try:
                    msg = self.format(record)
                    msg = re.sub(r"\033\[[0-9;]*m", "", msg)
                    if msg.strip():
                        self.q.put(
                            (
                                "log",
                                {
                                    "level": record.levelname,
                                    "text": msg,
                                    "time": datetime.now().strftime("%H:%M:%S"),
                                },
                            )
                        )
                    m = re.search(r"Found\s+(\S+)\s+in\s+(\S+)", msg, re.I)
                    m2 = re.search(r"🔴\s+发现\s+\[(\w+)\]\s+(\S+)", msg)
                    m3 = re.search(r"injection|XSS|LFI|SSRF|RCE|CMDi|XXE|sensitive|WAF", msg, re.I)
                    if m or m2 or m3:
                        self.q.put(("found", {"text": msg}))
                except Exception:  # noqa: BLE001
                    pass

        self._log_handlers = []
        for name in ["wvs.core.scanner", "wvs.core.crawler", "wvs.modules", "wvs.core.session", "wvs"]:
            lg = logging.getLogger(name)
            lg.setLevel(logging.INFO)
            handler = QueueHandler(self.queue)
            lg.addHandler(handler)
            lg.propagate = False
            self._log_handlers.append((lg, handler))

    def _teardown_log_capture(self) -> None:
        for lg, handler in self._log_handlers:
            try:
                lg.removeHandler(handler)
            except Exception:  # noqa: BLE001
                pass
        self._log_handlers = []

    class _StdoutCapture:
        """劫持 print() 输出发到 SSE 队列 + 同时保持终端显示。"""

        def __init__(self, q, original_stdout):
            self.q = q
            self.orig = original_stdout
            self._buffer = ""

        def write(self, text):
            self.orig.write(text)
            self.orig.flush()
            self._buffer += text
            if "\n" in self._buffer or "\r" in self._buffer:
                lines = self._buffer.replace("\r\n", "\n").replace("\r", "\n").split("\n")
                for line in lines[:-1]:
                    clean = re.sub(r"\033\[[0-9;]*m", "", line).strip()
                    if clean:
                        self.q.put(
                            (
                                "log",
                                {"level": "INFO", "text": clean, "time": datetime.now().strftime("%H:%M:%S")},
                            )
                        )
                self._buffer = lines[-1]

        def flush(self):
            self.orig.flush()

    # ── 生命周期 ──
    def start(
        self,
        payload: Dict[str, Any],
        config: ConfigManager,
        modules: List[str],
        from_proxy_queue_path: Optional[Path] = None,
        on_finish: Optional[Callable[[Optional[ScanResult], float, Dict[str, Any]], None]] = None,
    ) -> None:
        self.scanning = True
        self._start_time = time.time()
        self._module_order = list(modules or [])
        self._setup_log_capture()
        self._orig_stdout = sys.stdout
        sys.stdout = self._StdoutCapture(self.queue, self._orig_stdout)
        self._thread = threading.Thread(
            target=self._worker,
            args=(payload, config, modules, from_proxy_queue_path, on_finish),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self.scanning = False

    def events(self):
        """SSE 事件生成器。"""
        while True:
            try:
                typ, data = self.queue.get(timeout=1)
                yield f"event: {typ}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
            except queue.Empty:
                if not self.scanning and self.queue.empty():
                    yield f"event: done\ndata: {json.dumps({'msg': 'scan finished'})}\n\n"
                    break
                yield ": keepalive\n\n"

    # ── 执行 ──
    def _worker(self, payload, config, modules, from_proxy_queue_path, on_finish) -> None:
        result: Optional[ScanResult] = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    self._run_scan(payload, config, modules, from_proxy_queue_path)
                )
            finally:
                loop.close()
        except Exception as e:  # noqa: BLE001
            self._log("ERROR", f"扫描异常: {e}")
            import traceback

            for line in traceback.format_exc().split("\n"):
                if line.strip():
                    self._log("ERROR", line)
        finally:
            elapsed = time.time() - (self._start_time or time.time())
            if on_finish:
                try:
                    on_finish(result, elapsed, payload)
                except Exception as e:  # noqa: BLE001
                    logger.warning("on_finish 回调失败: %s", e)
            self._teardown_log_capture()
            if self._orig_stdout is not None:
                sys.stdout = self._orig_stdout
            self.scanning = False
            self.queue.put(("done", {"msg": "扫描结束"}))

    async def _run_scan(
        self,
        payload: Dict[str, Any],
        config: ConfigManager,
        modules: List[str],
        from_proxy_queue_path: Optional[Path],
    ) -> Optional[ScanResult]:
        if self._start_time is None:
            self._start_time = time.time()
        url = str(payload.get("url") or "")
        session = HTTPPool(config)
        scanner = WAVScanner(config, session)
        scanner._progress_callback = self._progress_cb
        for mod in modules or []:
            scanner.load_module(mod)

        self._log("INFO", "=" * 50)
        self._log("INFO", f"▶ 目标: {url}")
        self._log("INFO", f"▶ 模块: {', '.join(modules) if modules else '默认'}")
        self._log("INFO", "=" * 50)
        self._progress(5)

        target = ScanTarget(url=url)
        result: Optional[ScanResult] = None
        try:
            auth_payload = payload.get("auth") or {}
            if auth_payload:
                auth_manager = AuthManager(config)
                ok, err = configure_from_options(auth_manager, auth_payload)
                if not ok:
                    self._log("ERROR", f"认证配置错误: {err}")
                    return None
                self._log("INFO", f"[AUTH] 正在执行认证 ({auth_manager.provider_name})...")
                ok, err = await authenticate_and_apply(auth_manager, target, session)
                if not ok:
                    self._log("ERROR", f"认证失败: {err}")
                    return None
                self._log("INFO", "认证成功，已启用登录态维持")

            if payload.get("from_proxy"):
                result = await self._run_from_proxy(scanner, session, target, config, from_proxy_queue_path)
            else:
                try:
                    result = await asyncio.wait_for(
                        scanner.scan(target), timeout=config.get("max_scan_time", 7200)
                    )
                except asyncio.TimeoutError:
                    self._log("ERROR", "扫描超时")
                    return None
        finally:
            await session.close()

        if result is None:
            return None

        elapsed = time.time() - (self._start_time or time.time())
        self._progress(100)
        self._log("INFO", f"✅ 完成！耗时 {elapsed:.0f}s")
        self._log(
            "INFO",
            f"   端点: {result.endpoints_found}  |  请求: {result.requests_made}  |  漏洞: {len(result.vulnerabilities)}",
        )
        severity_count: Dict[str, int] = {}
        for v in result.vulnerabilities:
            sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
            severity_count[sev] = severity_count.get(sev, 0) + 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_count:
                self._log("INFO", f"   [{sev.upper()}] {severity_count[sev]} 个")

        self.queue.put(
            (
                "result",
                {
                    "vulnerabilities": [serialize_vuln(v) for v in result.vulnerabilities],
                    "stats": {
                        "endpoints": result.endpoints_found,
                        "requests": result.requests_made,
                        "elapsed": round(elapsed, 1),
                    },
                },
            )
        )
        self._result = result
        return result

    async def _run_from_proxy(
        self,
        scanner: WAVScanner,
        session: HTTPPool,
        target: ScanTarget,
        config: ConfigManager,
        queue_path: Optional[Path],
    ) -> Optional[ScanResult]:
        if not queue_path or not Path(queue_path).exists():
            self._log("ERROR", "没有可用的被动捕获队列")
            return None
        try:
            capture_queue = ProxyCaptureQueue.load(Path(queue_path))
        except Exception as e:  # noqa: BLE001
            self._log("ERROR", f"队列文件解析失败: {e}")
            return None
        endpoints = capture_queue.filter_for_target(target.url)
        if not endpoints:
            self._log("ERROR", "队列中没有属于该目标域的端点")
            return None
        effective_rate = apply_gentle_rate_cap(config)
        self._log("INFO", f"被动队列定向扫描: {len(endpoints)} 端点, 速率上限 {effective_rate} req/s")
        queue_result = ScanResult(target=target)
        await scan_proxy_queue(
            scanner,
            session,
            endpoints,
            target.url,
            config.get("concurrent_endpoints", 10),
            queue_result,
        )
        return queue_result

    # ── 进度 / 日志 ──
    def _progress(self, pct: int) -> None:
        self.queue.put(("progress", {"pct": pct}))

    def _progress_cb(self, module_name, done, total, pct):
        if not self.scanning:
            return
        if module_name in set(m.lower() for m in self._module_order):
            total_m = len(self._module_order)
            try:
                idx = [m.lower() for m in self._module_order].index(module_name.lower())
            except ValueError:
                idx = 0
            base = 10 + (idx / max(total_m, 1)) * 75
            share = 75 / max(total_m, 1)
            val = int(base + (done / max(total, 1)) * share)
            self.queue.put(("progress", {"pct": min(val, 90)}))
            self.queue.put(
                (
                    "action",
                    {
                        "module": module_name,
                        "done": done,
                        "total": total,
                        "text": f"检测 {module_name.upper()}... ({done}/{total})",
                    },
                )
            )
        elif module_name == "crawl":
            self.queue.put(("progress", {"pct": min(3 + (done / max(total, 1)) * 7, 10)}))
            self.queue.put(("action", {"text": f"爬虫 {done}/{total} 页面"}))

    def _log(self, level: str, text: str) -> None:
        self.queue.put(
            ("log", {"level": level, "text": text, "time": datetime.now().strftime("%H:%M:%S")})
        )
```

注意：`ProfileManager` 在本任务中未直接使用；若 ruff F401 报未使用，则删除该 import（`_run_from_proxy` 的速率上限在 `queue_scan` 内部自行读取 gentle 预设）。

- [ ] **Step 4: 跑测试**

```powershell
python -m pytest tests/test_web_ui.py -q
ruff check --fix web_ui/sessions.py tests/test_web_ui.py
ruff format web_ui/sessions.py tests/test_web_ui.py
```

Expected: `9 passed`（TestPayloads 4 + TestScanSession 5）。

- [ ] **Step 5: 提交**

```powershell
git add web_ui/sessions.py tests/test_web_ui.py
git commit -m "feat(v2.3): web_ui.sessions.ScanSession — 认证/explain/from-proxy 会话（T3.5）"
```

---

### Task 5: web_ui/sessions.py — PassiveProxySession（TDD）

**Files:**
- Modify: `web_ui/sessions.py`（追加类）
- Modify: `tests/test_web_ui.py`（追加 TestPassiveSession）

- [ ] **Step 1: 写失败测试（追加到 `tests/test_web_ui.py`）**

```python
class _FakeProxy:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.result = SimpleNamespace(
            requests_captured=0,
            endpoints_discovered=0,
            queued_endpoints=0,
            requests_scanned=0,
            vulnerabilities=[],
            errors=[],
        )
        self.queue = []
        self._stop = None
        self.closed = False
        _FakeProxy.instances.append(self)

    async def start(self):
        self._stop = asyncio.Event()

    async def serve_forever(self):
        await self._stop.wait()
        raise asyncio.CancelledError()

    async def close(self):
        self.closed = True
        if self._stop is not None:
            self._stop.set()


class TestPassiveSession:
    def test_start_status_stop(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sessions, "PassiveProxy", _FakeProxy)
        ps = sessions.PassiveProxySession()
        ps.start(
            {
                "target": "http://example.com/app",
                "listen": "127.0.0.1",
                "port": 18081,
                "tls_intercept": False,
                "ca_dir": None,
                "queue_path": str(tmp_path / "q.json"),
            }
        )
        status = ps.status()
        assert status["running"] is True
        assert status["target_filter"] == "example.com"
        assert status["listen"] == "127.0.0.1:18081"
        assert status["queue_path"] == str(tmp_path / "q.json")

        proxy = _FakeProxy.instances[-1]
        assert proxy.kwargs["scan_callback"] is None
        assert proxy.kwargs["target_filter"] == "example.com"

        ps.stop()
        assert ps.status()["running"] is False
        assert proxy.closed is True

    def test_duplicate_start_rejected(self, monkeypatch, tmp_path):
        monkeypatch.setattr(sessions, "PassiveProxy", _FakeProxy)
        ps = sessions.PassiveProxySession()
        options = {"target": "http://t", "port": 18082, "queue_path": str(tmp_path / "q.json")}
        ps.start(options)
        try:
            with pytest.raises(RuntimeError):
                ps.start(options)
        finally:
            ps.stop()

    def test_start_failure_raises(self, monkeypatch, tmp_path):
        class _BoomProxy(_FakeProxy):
            async def start(self):
                raise OSError("port in use")

        monkeypatch.setattr(sessions, "PassiveProxy", _BoomProxy)
        ps = sessions.PassiveProxySession()
        with pytest.raises(RuntimeError, match="port in use"):
            ps.start({"target": "http://t", "port": 18083, "queue_path": str(tmp_path / "q.json")})
        assert ps.status()["running"] is False
```

- [ ] **Step 2: 跑测试确认失败**

```powershell
python -m pytest tests/test_web_ui.py::TestPassiveSession -q
```

Expected: FAIL — `AttributeError: module 'web_ui.sessions' has no attribute 'PassiveProxySession'`（或 `PassiveProxy` 不存在）。

- [ ] **Step 3: 在 `web_ui/sessions.py` 追加 PassiveProxySession**

导入区追加：

```python
from urllib.parse import urlparse

from wvs.core.passive import PassiveProxy
```

文件末尾追加：

```python
class PassiveProxySession:
    """被动代理会话:后台线程运行 asyncio 代理,只捕获不入检（--no-live-scan 语义）。"""

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._proxy: Any = None
        self._lock = threading.Lock()
        self._started = threading.Event()
        self.running = False
        self.last_error: Optional[str] = None
        self.target: Optional[str] = None
        self.target_filter: Optional[str] = None
        self.listen_host = "127.0.0.1"
        self.listen_port = 8081
        self.tls_intercept = False
        self.ca_dir: Optional[str] = None
        self.queue_path: Optional[Path] = None

    @staticmethod
    def _normalize_target(raw: str) -> str:
        """目标 URL → host 过滤值（与 CLI cmd_passive 同语义）。"""
        target = (raw or "").strip().rstrip("/")
        if target.startswith(("http://", "https://")):
            target = urlparse(target).netloc or target
        return target

    def start(self, options: Dict[str, Any]) -> None:
        with self._lock:
            if self.running:
                raise RuntimeError("被动代理已在运行")
            self.target = str(options.get("target") or "").strip()
            self.target_filter = self._normalize_target(self.target)
            self.listen_host = str(options.get("listen") or "127.0.0.1")
            self.listen_port = int(options.get("port") or 8081)
            self.tls_intercept = bool(options.get("tls_intercept"))
            self.ca_dir = options.get("ca_dir") or None
            self.queue_path = Path(options["queue_path"]) if options.get("queue_path") else None
            self.last_error = None
            self._started.clear()
            self.running = True
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        if not self._started.wait(timeout=10):
            self.running = False
            raise RuntimeError("代理启动超时")
        if self.last_error:
            self.running = False
            raise RuntimeError(self.last_error)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._proxy = PassiveProxy(
                scan_callback=None,
                target_filter=self.target_filter,
                listen_host=self.listen_host,
                listen_port=self.listen_port,
                tls_intercept=self.tls_intercept,
                ca_dir=self.ca_dir,
                queue_path=self.queue_path,
            )
            self._loop.run_until_complete(self._proxy.start())
            self._started.set()
            self._loop.run_until_complete(self._proxy.serve_forever())
        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001
            self.last_error = str(e)
            self._started.set()
        finally:
            self.running = False
            try:
                self._loop.close()
            except Exception:  # noqa: BLE001
                pass

    def stop(self) -> None:
        with self._lock:
            proxy = self._proxy
            loop = self._loop
            if not self.running or proxy is None or loop is None:
                self.running = False
                return
            future = asyncio.run_coroutine_threadsafe(proxy.close(), loop)
            try:
                future.result(timeout=5)
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)
        if self._thread:
            self._thread.join(timeout=5)
        self.running = False

    def status(self) -> Dict[str, Any]:
        proxy = self._proxy
        result = getattr(proxy, "result", None)
        queued = 0
        if proxy is not None:
            try:
                queued = len(proxy.queue)
            except Exception:  # noqa: BLE001
                queued = 0
        return {
            "running": bool(self.running),
            "listen": f"{self.listen_host}:{self.listen_port}",
            "target": self.target,
            "target_filter": self.target_filter,
            "tls_intercept": self.tls_intercept,
            "ca_dir": self.ca_dir,
            "queue_path": str(self.queue_path) if self.queue_path else None,
            "requests_captured": getattr(result, "requests_captured", 0) if result else 0,
            "endpoints_discovered": getattr(result, "endpoints_discovered", 0) if result else 0,
            "queued_endpoints": queued or (getattr(result, "queued_endpoints", 0) if result else 0),
            "errors": list(getattr(result, "errors", []) or []) if result else [],
        }
```

- [ ] **Step 4: 跑测试 + ruff**

```powershell
python -m pytest tests/test_web_ui.py -q
ruff check --fix web_ui/sessions.py tests/test_web_ui.py
ruff format web_ui/sessions.py tests/test_web_ui.py
```

Expected: `12 passed`。

- [ ] **Step 5: 提交**

```powershell
git add web_ui/sessions.py tests/test_web_ui.py
git commit -m "feat(v2.3): web_ui.sessions.PassiveProxySession — 代理线程与状态机（T3.5）"
```

---

### Task 6: web_ui/app.py 路由重构 + API 测试（TDD）

**Files:**
- Rewrite: `web_ui/app.py`
- Modify: `tests/test_web_ui.py`（追加 TestApi）

- [ ] **Step 1: 写失败测试（追加到 `tests/test_web_ui.py`）**

```python
class TestApi:
    @pytest.fixture()
    def app_client(self, monkeypatch):
        from web_ui import app as web_app

        web_app.app.config["TESTING"] = True
        monkeypatch.setattr(web_app, "scan_session", sessions.ScanSession())
        monkeypatch.setattr(web_app, "passive_session", sessions.PassiveProxySession())
        with web_app.app.test_client() as client:
            yield client, web_app

    def test_api_requires_auth(self, app_client):
        client, _ = app_client
        assert client.get("/api/modules").status_code == 401

    def test_api_token_allows_and_lists_modules(self, app_client):
        client, web_app = app_client
        response = client.get("/api/modules", headers={"X-Api-Token": web_app.API_TOKEN})
        assert response.status_code == 200
        modules = response.get_json()["modules"]
        assert {"sqli", "xss", "mcp"} <= {m["name"] for m in modules}

    def test_session_post_requires_csrf(self, app_client):
        client, web_app = app_client
        response = client.post("/login", data={"token": web_app.API_TOKEN})
        assert response.status_code in (302, 303)
        response = client.post("/api/scan", json={"url": "http://t", "modules": ["sqli"]})
        assert response.status_code == 403

    def test_profiles_list_save_and_detail(self, app_client, monkeypatch, tmp_path):
        client, web_app = app_client
        monkeypatch.setattr(web_app, "_profile_manager", ProfileManager(tmp_path))
        headers = {"X-Api-Token": web_app.API_TOKEN}

        names = {p["name"] for p in client.get("/api/profiles", headers=headers).get_json()["profiles"]}
        assert {"default", "gentle"} <= names

        response = client.post(
            "/api/profiles",
            headers=headers,
            json={"name": "custom1", "description": "d", "modules": {"enabled": ["sqli"]}, "params": {"rate": 5}},
        )
        assert response.status_code == 200
        assert (tmp_path / "custom1.yaml").exists()

        detail = client.get("/api/profiles/custom1", headers=headers).get_json()
        assert detail["params"]["rate"] == 5
        assert detail["builtin"] is False

        assert client.get("/api/profiles/nope", headers=headers).status_code == 404
        assert (
            client.post("/api/profiles", headers=headers, json={"name": "gentle", "params": {}}).status_code == 409
        )

    def test_scan_unknown_profile_400(self, app_client):
        client, web_app = app_client
        response = client.post(
            "/api/scan",
            headers={"X-Api-Token": web_app.API_TOKEN},
            json={"url": "http://t", "profile": "nope"},
        )
        assert response.status_code == 400

    def test_scan_bad_auth_400(self, app_client):
        client, web_app = app_client
        response = client.post(
            "/api/scan",
            headers={"X-Api-Token": web_app.API_TOKEN},
            json={"url": "http://t", "auth": {"type": "bearer"}},
        )
        assert response.status_code == 400

    def test_scan_from_proxy_without_queue_400(self, app_client):
        client, web_app = app_client
        response = client.post(
            "/api/scan",
            headers={"X-Api-Token": web_app.API_TOKEN},
            json={"url": "http://t", "from_proxy": True},
        )
        assert response.status_code == 400

    def test_scan_start_returns_started(self, app_client):
        client, web_app = app_client

        class _FakeScanSession:
            scanning = False

            def __init__(self):
                self.started = False

            def start(self, *args, **kwargs):
                self.started = True

        fake = _FakeScanSession()
        web_app.scan_session = fake
        response = client.post(
            "/api/scan",
            headers={"X-Api-Token": web_app.API_TOKEN},
            json={"url": "http://t", "modules": ["sqli"], "explain": True},
        )
        assert response.status_code == 200 and fake.started

    def test_export_json_includes_evidence_chain(self, app_client):
        client, web_app = app_client
        web_app.scan_session._result = ScanResult(
            target=ScanTarget(url="http://t"), vulnerabilities=[_stub_vuln()]
        )
        response = client.get("/api/export/json", headers={"X-Api-Token": web_app.API_TOKEN})
        assert response.status_code == 200
        vuln = response.get_json()["vulnerabilities"][0]
        assert vuln["evidence_chain"][0]["kind"] == "payload"
        assert vuln["recommendation"] == ""

    def test_passive_start_requires_target(self, app_client):
        client, web_app = app_client
        response = client.post(
            "/api/passive/start", headers={"X-Api-Token": web_app.API_TOKEN}, json={"port": 18091}
        )
        assert response.status_code == 400

    def test_passive_start_queue_path_restricted(self, app_client):
        client, web_app = app_client
        response = client.post(
            "/api/passive/start",
            headers={"X-Api-Token": web_app.API_TOKEN},
            json={"target": "http://t", "queue_out": "evil/outside.json"},
        )
        assert response.status_code == 400

    def test_passive_conflict_and_status(self, app_client):
        client, web_app = app_client
        web_app.passive_session.running = True
        headers = {"X-Api-Token": web_app.API_TOKEN}
        assert client.post("/api/passive/start", headers=headers, json={"target": "http://t"}).status_code == 409
        status = client.get("/api/passive/status", headers=headers).get_json()
        assert status["running"] is True
        assert "queue_path" in status
```

- [ ] **Step 2: 跑测试确认失败**

```powershell
python -m pytest tests/test_web_ui.py::TestApi -q
```

Expected: FAIL — 路由不存在（404/401 断言不符）。

- [ ] **Step 3: 重写 `web_ui/app.py`**

```python
"""
RayScan Web UI (Flask + SSE 实时日志) — v2.3 T3.5

HTTP 层:路由 / 鉴权 / CSRF / 序列化。
业务逻辑:web_ui.payloads(请求 → 配置)、web_ui.sessions(扫描/被动会话)。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secrets  # noqa: E402

import threading  # noqa: E402
from datetime import datetime  # noqa: E402
from pathlib import Path  # noqa: E402

from flask import (  # noqa: E402
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    session,
    stream_with_context,
)

from web_ui import payloads, sessions  # noqa: E402
from wvs import __version__  # noqa: E402
from wvs.config import ConfigManager  # noqa: E402
from wvs.plugins.auth import AuthManager, configure_from_options  # noqa: E402

app = Flask(__name__)

# ── 鉴权 + CSRF 配置 ──
# SECRET_KEY：必需（生产环境请用环境变量覆盖）。仅在缺失时给一个进程内随机值，
# 这意味着每次重启会让已有 session 失效 — 配合 CSRF 重新签发即可。
_app_secret = os.environ.get("RAYSCAN_WEB_SECRET")
if _app_secret:
    app.secret_key = _app_secret
else:
    app.secret_key = secrets.token_hex(32)
    print(
        "[WARN] 未设置 RAYSCAN_WEB_SECRET；Web UI 使用进程内随机 secret key。"
        "重启后所有 session/CSRF token 失效。生产请设置该环境变量。"
    )

# 简单的 API token（与登录 session 二选一）。默认生成一个并打印到终端，
# 用户可以 RAYSCAN_WEB_TOKEN=xxx 覆盖。
_DEFAULT_TOKEN = secrets.token_urlsafe(24)
API_TOKEN = os.environ.get("RAYSCAN_WEB_TOKEN") or _DEFAULT_TOKEN
print(f"[INFO] RayScan Web UI API token (header 'X-Api-Token'): {API_TOKEN}")
print("[INFO] 访问 /login 页面用此 token 登录；或 curl 调用时带 X-Api-Token。")

# 仓库根与 scan_reports 目录（queue_out 白名单）
REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = (REPO_ROOT / "scan_reports").resolve()

# 全局会话 + Profile 管理器（测试可 monkeypatch）
scan_session = sessions.ScanSession()
passive_session = sessions.PassiveProxySession()

from wvs.profiles import ProfileManager  # noqa: E402

_profile_manager = ProfileManager()

# 扫描历史存储
SCAN_HISTORY: list = []
_HISTORY_LOCK = threading.Lock()


def _is_authorized() -> bool:
    """校验当前请求是否已通过鉴权（session 或 API token 任一即可）"""
    if session.get("authenticated"):
        return True
    token = request.headers.get("X-Api-Token", "")
    if token and secrets.compare_digest(token, API_TOKEN):
        return True
    return False


def _get_or_create_csrf_token() -> str:
    """返回当前 session 的 CSRF token（缺失时生成）"""
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf_token"] = tok
    return tok


def _require_csrf():
    """校验 POST/PUT/DELETE 是否带有效 CSRF token（API token 用户不受限）"""
    if request.headers.get("X-Api-Token") and secrets.compare_digest(
        request.headers.get("X-Api-Token", ""), API_TOKEN
    ):
        return  # API token 用户已通过 _is_authorized，跳过 CSRF
    sent = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    if not expected or not sent or not secrets.compare_digest(sent, expected):
        abort(403, description="CSRF token missing or invalid")


def _resolve_queue_out(raw) -> Path:
    """校验 queue_out 位于 scan_reports/ 下（防任意文件写）。"""
    value = (str(raw).strip() if raw else "") or "scan_reports/proxy_queue.json"
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = (REPORTS_DIR / candidate) if candidate.parent == Path(".") else (REPO_ROOT / candidate)
    resolved = candidate.resolve()
    if resolved != REPORTS_DIR and REPORTS_DIR not in resolved.parents:
        raise ValueError("queue_out 必须是 scan_reports/ 下的路径")
    return resolved


# ── 路由 ──

@app.route("/")
def index():
    if not _is_authorized():
        return _redirect_to_login()
    return render_template("index.html", csrf_token=_get_or_create_csrf_token(), version=__version__)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        submitted = (request.form.get("token") or "").strip()
        if submitted and secrets.compare_digest(submitted, API_TOKEN):
            session["authenticated"] = True
            return _redirect_to_index()
        return render_template("login.html", error="Token 无效"), 401
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return _redirect_to_login()


def _redirect_to_login():
    from flask import redirect, url_for

    return redirect(url_for("login"))


def _redirect_to_index():
    from flask import redirect, url_for

    return redirect(url_for("index"))


@app.route("/api/modules")
def api_modules():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return jsonify({"modules": payloads.module_catalog()})


@app.route("/api/profiles", methods=["GET"])
def api_profiles():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return jsonify({"profiles": _profile_manager.list_profiles()})


@app.route("/api/profiles/<name>", methods=["GET"])
def api_profile_detail(name):
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    profile = _profile_manager.load_profile(name)
    if profile is None:
        return jsonify({"error": "profile 不存在"}), 404
    builtin = any(p["name"] == name and p.get("builtin") for p in _profile_manager.list_profiles())
    return jsonify(
        {
            "name": name,
            "description": profile.get("description", ""),
            "builtin": builtin,
            "modules": profile.get("modules", {}),
            "params": profile.get("params", {}),
        }
    )


@app.route("/api/profiles", methods=["POST"])
def api_profile_save():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "请输入 Profile 名称"}), 400
    builtin_names = {p["name"] for p in _profile_manager.list_profiles() if p.get("builtin")}
    if name in builtin_names:
        return jsonify({"error": f"'{name}' 是内置 Profile，请换一个名称"}), 409
    profile = {
        "name": name,
        "description": data.get("description", ""),
        "modules": data.get("modules") or {"enabled": [], "disabled": []},
        "params": data.get("params") or {},
    }
    try:
        path = _profile_manager.save_profile(name, profile)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"status": "saved", "path": str(path)})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    if scan_session.scanning:
        return jsonify({"error": "已有扫描正在运行"}), 400

    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "请输入 URL"}), 400

    try:
        config = ConfigManager()
        profile_name = payloads.apply_scan_config(config, data, _profile_manager)
        modules = payloads.resolve_scan_modules(data, profile_name, _profile_manager)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    auth_payload = data.get("auth") or {}
    if auth_payload:
        ok, err = configure_from_options(AuthManager(config), auth_payload)
        if not ok:
            return jsonify({"error": err}), 400

    from_proxy_path = None
    if data.get("from_proxy"):
        from_proxy_path = passive_session.queue_path
        if not from_proxy_path or not Path(from_proxy_path).exists():
            return jsonify({"error": "没有可用的被动捕获队列，请先在「被动捕获」启动代理"}), 400

    def _on_finish(result, elapsed, _payload):
        _record_scan(url, result.vulnerabilities if result else [], elapsed)

    scan_session.start(
        data,
        config,
        modules,
        from_proxy_queue_path=from_proxy_path,
        on_finish=_on_finish,
    )
    return jsonify({"status": "started"})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    scan_session.stop()
    return jsonify({"status": "stopped"})


@app.route("/api/stream")
def api_stream():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return Response(
        stream_with_context(scan_session.events()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/passive/start", methods=["POST"])
def api_passive_start():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    if passive_session.running:
        return jsonify({"error": "被动代理已在运行"}), 409

    data = request.get_json() or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "请输入目标域（未指定会捕获全量流量）"}), 400
    port = int(data.get("port") or 8081)
    if not (1 <= port <= 65535):
        return jsonify({"error": "端口非法"}), 400
    try:
        queue_path = _resolve_queue_out(data.get("queue_out"))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    try:
        passive_session.start(
            {
                "target": target,
                "listen": data.get("listen") or "127.0.0.1",
                "port": port,
                "tls_intercept": bool(data.get("tls_intercept")),
                "ca_dir": data.get("ca_dir") or None,
                "queue_path": str(queue_path),
            }
        )
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"status": "started", "queue_path": str(queue_path)})


@app.route("/api/passive/stop", methods=["POST"])
def api_passive_stop():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    _require_csrf()
    try:
        passive_session.stop()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"status": "stopped", "stats": passive_session.status()})


@app.route("/api/passive/status")
def api_passive_status():
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    return jsonify(passive_session.status())


@app.route("/api/export/<fmt>")
def api_export(fmt):
    if not _is_authorized():
        return jsonify({"error": "未授权"}), 401
    result = scan_session._result
    if result is None:
        return jsonify({"error": "没有结果"}), 400

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if fmt == "json":
        return jsonify(
            {
                "scan_time": ts,
                "total": len(result.vulnerabilities),
                "vulnerabilities": [sessions.serialize_vuln(v) for v in result.vulnerabilities],
            }
        )
    return jsonify({"error": "不支持格式"}), 400


@app.route("/api/history")
def api_scan_history():
    """获取扫描历史"""
    if not _is_authorized():
        abort(401)
    limit = request.args.get("limit", 50, type=int)
    with _HISTORY_LOCK:
        snapshot = list(SCAN_HISTORY)
    history = sorted(snapshot, key=lambda x: x.get("time", ""), reverse=True)[:limit]
    return jsonify(history)


@app.route("/api/stats")
def api_stats():
    """获取统计概览"""
    if not _is_authorized():
        abort(401)
    with _HISTORY_LOCK:
        snapshot = list(SCAN_HISTORY)
    total_scans = len(snapshot)
    total_vulns = sum(h.get("total_vulns", 0) for h in snapshot)
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for h in snapshot:
        for sev, count in h.get("severity_counts", {}).items():
            if sev in severity_totals:
                severity_totals[sev] += count
    return jsonify(
        {
            "total_scans": total_scans,
            "total_vulns": total_vulns,
            "severity_totals": severity_totals,
            "engines_available": {"nuclei": True, "sqlmap": True},
        }
    )


def _record_scan(target: str, vulns: list, duration: float) -> dict:
    """记录一次扫描到历史（worker 线程调用，需加锁）。"""
    severity_counts = {}
    for v in vulns:
        sev = v.severity.value if hasattr(v.severity, "value") else "info"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    record = {
        "id": len(SCAN_HISTORY) + 1,
        "target": target,
        "time": datetime.now().isoformat(),
        "duration": round(duration, 1),
        "total_vulns": len(vulns),
        "severity_counts": severity_counts,
    }
    with _HISTORY_LOCK:
        SCAN_HISTORY.append(record)
        if len(SCAN_HISTORY) > 200:
            SCAN_HISTORY[:] = SCAN_HISTORY[-200:]
    return record


if __name__ == "__main__":
    # ── 默认仅本机绑定，避免无认证状态下对外暴露 ──
    # 需要对外服务时：RAYSCAN_WEB_HOST=0.0.0.0 python app.py
    bind_host = os.environ.get("RAYSCAN_WEB_HOST", "127.0.0.1")
    bind_port = int(os.environ.get("RAYSCAN_WEB_PORT", "5000"))
    print("=" * 50)
    print(f"  RayScan {__version__} — Web UI")
    print(f"  http://{bind_host}:{bind_port}")
    if bind_host in ("0.0.0.0", "::"):
        print("  [WARN] 监听所有网卡 — 请确保已启用鉴权 (RAYSCAN_WEB_TOKEN)")
    print("=" * 50)
    app.run(debug=False, host=bind_host, port=bind_port, threaded=True)
```

- [ ] **Step 4: 跑测试**

```powershell
python -m pytest tests/test_web_ui.py -q
ruff check --fix web_ui/app.py tests/test_web_ui.py
ruff format web_ui/app.py tests/test_web_ui.py
```

Expected: `24 passed`（12 + TestApi 12）。

- [ ] **Step 5: 回归相邻模块**

```powershell
python -m pytest tests/test_smoke_cli.py tests/test_profiles tests/test_from_proxy.py -q
```

Expected: 全部 PASS。

- [ ] **Step 6: 提交**

```powershell
git add web_ui/app.py tests/test_web_ui.py
git commit -m "feat(v2.3): Web UI 路由重构 — 动态模块/profile/认证/被动捕获/证据链导出（T3.5）"
```

---

### Task 7: index.html 结构改造（Tab 导航 + 版本 + 动态模块）

**Files:**
- Modify: `web_ui/templates/index.html`

- [ ] **Step 1: 版本占位替换（3 处）**

```
<title>RayScan 2.2.0 — Web Vulnerability Scanner</title>
→ <title>RayScan {{ version }} — Web Vulnerability Scanner</title>

<small class="text-secondary ms-2" style="font-size:0.7rem;">2.2.0</small>
→ <small class="text-secondary ms-2" style="font-size:0.7rem;">{{ version }}</small>

<div class="stat-label">RayScan 2.2.0</div>
→ <div class="stat-label">RayScan {{ version }}</div>
```

- [ ] **Step 2: 导航栏加 Tab**

在 `<span class="navbar-brand mb-0 h1">...</span>` 之后插入：

```html
        <ul class="nav nav-pills ms-3" id="main-tabs" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" id="tab-scan-btn" data-bs-toggle="tab"
                        data-bs-target="#tab-scan" type="button" role="tab">扫描</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="tab-passive-btn" data-bs-toggle="tab"
                        data-bs-target="#tab-passive" type="button" role="tab">被动捕获</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" id="tab-history-btn" data-bs-toggle="tab"
                        data-bs-target="#tab-history" type="button" role="tab">历史</button>
            </li>
        </ul>
```

- [ ] **Step 3: 主体包进 tab-content（扫描 pane）**

替换：

```html
<div class="container-fluid px-3 py-3">
    <div class="row g-3">
```

为：

```html
<div class="container-fluid px-3 py-3">
  <div class="tab-content" id="main-tabs-content">
    <div class="tab-pane fade show active" id="tab-scan" role="tabpanel">
    <div class="row g-3">
```

- [ ] **Step 4: 历史/仪表盘移入独立 pane，被动 pane 占位**

把从 `        <!-- Dashboard Tab -->` 到文件末尾 `    </div>\n</div>` 之间的内容整体替换为：

```html
    </div> <!-- /#tab-scan row -->

    <!-- 被动捕获 Tab（Task 9 填充面板） -->
    <div class="tab-pane fade" id="tab-passive" role="tabpanel"></div>

    <!-- 历史 Tab（原 dashboard + history 标记，ID 不变） -->
    <div class="tab-pane fade" id="tab-history" role="tabpanel">
        <div class="row mt-3">
            <div class="col-md-3">
                <div class="card text-white bg-primary mb-3">
                    <div class="card-header">总扫描数</div>
                    <div class="card-body"><h3 id="dash-total-scans">0</h3></div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-white bg-danger mb-3">
                    <div class="card-header">总漏洞数</div>
                    <div class="card-body"><h3 id="dash-total-vulns">0</h3></div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card text-white bg-danger mb-3">
                    <div class="card-header">严重</div>
                    <div class="card-body"><h3 id="dash-critical">0</h3></div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card text-white bg-warning mb-3">
                    <div class="card-header">高危</div>
                    <div class="card-body"><h3 id="dash-high">0</h3></div>
                </div>
            </div>
            <div class="col-md-2">
                <div class="card text-white bg-info mb-3">
                    <div class="card-header">中危</div>
                    <div class="card-body"><h3 id="dash-medium">0</h3></div>
                </div>
            </div>
        </div>
        <div class="card mt-2">
            <div class="card-header">最近扫描</div>
            <div class="card-body" id="dash-recent" style="max-height:400px;overflow-y:auto">
                <p class="text-muted">暂无扫描记录</p>
            </div>
        </div>
        <div class="card mt-3">
            <div class="card-header d-flex justify-content-between">
                <span>扫描历史</span>
                <button class="btn btn-sm btn-outline-secondary" onclick="loadHistory()">刷新</button>
            </div>
            <div class="card-body" id="history-list" style="max-height:500px;overflow-y:auto">
                <p class="text-muted">暂无历史记录</p>
            </div>
        </div>
    </div>

  </div> <!-- /#main-tabs-content -->
</div>
```

- [ ] **Step 5: 模块列表动态化（替换硬编码 MODULES 与 initModules）**

删除：

```js
const MODULES = {
    "sqli": "SQL注入", "xss": "XSS", "cmdi": "命令注入",
    "lfi": "LFI", "rce": "RCE", "ssrf": "SSRF", "xxe": "XXE",
    "api": "API安全", "sensitive": "敏感信息", "waf": "WAF检测",
};
const MODULE_COLS = 2;

function initModules() {
    const container = document.getElementById('modules-container');
    let cols = [];
    const keys = Object.keys(MODULES);
    for (let i = 0; i < Math.min(MODULE_COLS, keys.length); i++) {
        cols[i] = document.createElement('div');
        cols[i].className = 'col-6';
    }
    keys.forEach((key, idx) => {
        const col = cols[idx % MODULE_COLS];
        const div = document.createElement('div');
        div.className = 'form-check';
        div.innerHTML = `<input class="form-check-input module-cb" type="checkbox" id="mod-${key}" checked>
                         <label class="form-check-label" for="mod-${key}">${MODULES[key]}</label>`;
        col.appendChild(div);
    });
    cols.forEach(c => container.appendChild(col));
}
initModules();
```

替换为：

```js
const MODULE_LABELS = {
    "sqli": "SQL注入", "xss": "XSS", "cmdi": "命令注入",
    "lfi": "LFI", "rce": "RCE", "ssrf": "SSRF", "xxe": "XXE",
    "api": "API安全", "sensitive": "敏感信息", "waf": "WAF检测",
};
const MODULE_COLS = 2;

async function loadModules() {
    try {
        const r = await fetch('/api/modules');
        const data = await r.json();
        renderModules(data.modules || []);
    } catch (e) {
        appendLog('--', 'ERROR', '模块列表加载失败: ' + e);
    }
}

function renderModules(list) {
    const container = document.getElementById('modules-container');
    container.innerHTML = '';
    const cols = [];
    for (let i = 0; i < MODULE_COLS; i++) {
        const c = document.createElement('div');
        c.className = 'col-6';
        cols.push(c);
    }
    list.forEach((m, idx) => {
        const div = document.createElement('div');
        div.className = 'form-check';
        const checked = m.default_enabled ? 'checked' : '';
        const label = MODULE_LABELS[m.name] || m.name.toUpperCase();
        div.innerHTML = `<input class="form-check-input module-cb" type="checkbox" id="mod-${m.name}" ${checked}>
                         <label class="form-check-label" for="mod-${m.name}"
                                title="${escapeHtml(m.description || '')}">${escapeHtml(label)}</label>`;
        cols[idx % MODULE_COLS].appendChild(div);
    });
    cols.forEach(c => container.appendChild(c));
}

function collectModules() {
    const out = [];
    document.querySelectorAll('.module-cb:checked').forEach(cb => out.push(cb.id.replace('mod-', '')));
    return out;
}

loadModules();
```

- [ ] **Step 6: 手动冒烟（静态检查）**

```powershell
python -m pytest tests/test_web_ui.py -q
python -c "import web_ui.app; print('import OK')"
```

Expected: 测试 PASS、import OK。

- [ ] **Step 7: 提交**

```powershell
git add web_ui/templates/index.html
git commit -m "feat(v2.3): Web UI 分 Tab 导航 + 动态模块列表 + 版本占位（T3.5）"
```

---

### Task 8: index.html 扫描增强（profile / 认证 / explain / from-proxy / 证据链）

**Files:**
- Modify: `web_ui/templates/index.html`

- [ ] **Step 1: 扫描配置卡片加入 Profile / explain / from-proxy**

在「扫描配置」卡片 `<div class="card-body py-2">` 的第一个 `<div class="mb-2">`（速率）之前插入：

```html
                    <div class="mb-2">
                        <label class="stat-label">Profile</label>
                        <div class="input-group input-group-sm">
                            <select class="form-select" id="profile-select"></select>
                            <button class="btn btn-outline-secondary" type="button" onclick="applyProfile()">应用</button>
                            <button class="btn btn-outline-secondary" type="button" onclick="saveProfile()">保存为</button>
                        </div>
                    </div>
```

在「跳过 SSL 验证」form-check 之后插入：

```html
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="cfg-explain" checked>
                        <label class="form-check-label" for="cfg-explain">证据链（--explain）</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="cfg-from-proxy">
                        <label class="form-check-label" for="cfg-from-proxy">被动队列定向扫描</label>
                    </div>
```

- [ ] **Step 2: 认证折叠面板**

在「扫描配置」卡片之后（左侧栏 `</div>` 前）插入：

```html
            <div class="card mb-3">
                <div class="card-header py-2">
                    <a class="text-decoration-none" data-bs-toggle="collapse" href="#auth-body">认证（可选）</a>
                </div>
                <div class="collapse" id="auth-body">
                    <div class="card-body py-2">
                        <select class="form-select form-select-sm mb-2" id="auth-type" onchange="toggleAuthFields()">
                            <option value="">无认证</option>
                            <option value="form">表单登录</option>
                            <option value="bearer">Bearer Token</option>
                            <option value="basic">Basic Auth</option>
                            <option value="apikey">API Key</option>
                            <option value="cookie">Cookie 注入</option>
                        </select>
                        <div class="auth-fields" data-type="form" style="display:none">
                            <input class="form-control form-control-sm mb-1" id="auth-login-url" placeholder="登录 URL">
                            <input class="form-control form-control-sm mb-1" id="auth-username" placeholder="用户名">
                            <input class="form-control form-control-sm" type="password" id="auth-password" placeholder="密码">
                        </div>
                        <div class="auth-fields" data-type="bearer" style="display:none">
                            <input class="form-control form-control-sm" id="auth-token" placeholder="Bearer Token">
                        </div>
                        <div class="auth-fields" data-type="basic" style="display:none">
                            <input class="form-control form-control-sm mb-1" id="auth-basic-user" placeholder="用户名">
                            <input class="form-control form-control-sm" type="password" id="auth-basic-pass" placeholder="密码">
                        </div>
                        <div class="auth-fields" data-type="apikey" style="display:none">
                            <input class="form-control form-control-sm mb-1" id="auth-apikey" placeholder="API Key">
                            <input class="form-control form-control-sm" id="auth-apikey-header"
                                   placeholder="Header 名称（默认 X-API-Key）" value="X-API-Key">
                        </div>
                        <div class="auth-fields" data-type="cookie" style="display:none">
                            <textarea class="form-control form-control-sm" id="auth-cookies" rows="2"
                                      placeholder="name=value; name2=value2"></textarea>
                        </div>
                    </div>
                </div>
            </div>
```

- [ ] **Step 3: profile / auth JS**

在 `loadModules();` 之后插入：

```js
async function loadProfiles() {
    try {
        const r = await fetch('/api/profiles');
        const data = await r.json();
        const sel = document.getElementById('profile-select');
        sel.innerHTML = '<option value="">（不使用）</option>' + (data.profiles || [])
            .map(p => `<option value="${escapeHtml(p.name)}">${escapeHtml(p.name)}${p.builtin ? '（内置）' : ''}</option>`)
            .join('');
    } catch (e) {}
}

async function applyProfile() {
    const name = document.getElementById('profile-select').value;
    if (!name) return;
    const r = await fetch(`/api/profiles/${encodeURIComponent(name)}`);
    if (!r.ok) { alert('Profile 加载失败'); return; }
    const p = await r.json();
    const params = p.params || {};
    if (params.rate !== undefined) document.getElementById('cfg-rate').value = params.rate;
    if (params.timeout !== undefined) document.getElementById('cfg-timeout').value = params.timeout;
    if (params.crawl_depth !== undefined) document.getElementById('cfg-depth').value = params.crawl_depth;
    if (params.crawl_max_urls !== undefined) document.getElementById('cfg-urls').value = params.crawl_max_urls;
    if (params.verify_ssl === false) document.getElementById('cfg-insecure').checked = true;
    const enabled = ((p.modules || {}).enabled) || [];
    if (enabled.length) {
        document.querySelectorAll('.module-cb').forEach(cb => {
            cb.checked = enabled.includes(cb.id.replace('mod-', ''));
        });
    }
}

async function saveProfile() {
    const name = prompt('Profile 名称（字母/数字/_/-）');
    if (!name) return;
    const params = {
        rate: parseInt(document.getElementById('cfg-rate').value) || 15,
        timeout: parseInt(document.getElementById('cfg-timeout').value) || 15,
        crawl_depth: parseInt(document.getElementById('cfg-depth').value) || 2,
        crawl_max_urls: parseInt(document.getElementById('cfg-urls').value) || 50,
    };
    const r = await fetch('/api/profiles', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': '{{ csrf_token }}'},
        body: JSON.stringify({
            name: name,
            description: 'Web UI 保存',
            modules: {enabled: collectModules(), disabled: []},
            params: params,
        }),
    });
    const d = await r.json();
    if (d.error) { alert(d.error); } else { alert('已保存'); loadProfiles(); }
}

function toggleAuthFields() {
    const t = document.getElementById('auth-type').value;
    document.querySelectorAll('.auth-fields').forEach(el => {
        el.style.display = (el.dataset.type === t) ? '' : 'none';
    });
}

function buildAuthPayload() {
    const t = document.getElementById('auth-type').value;
    if (!t) return null;
    const val = id => document.getElementById(id).value.trim();
    if (t === 'form') {
        return {type: 'form', login_url: val('auth-login-url'), username: val('auth-username'),
                password: document.getElementById('auth-password').value};
    }
    if (t === 'bearer') return {type: 'bearer', token: val('auth-token')};
    if (t === 'basic') {
        return {type: 'basic', username: val('auth-basic-user'),
                password: document.getElementById('auth-basic-pass').value};
    }
    if (t === 'apikey') {
        return {type: 'apikey', api_key: val('auth-apikey'),
                api_key_header: val('auth-apikey-header') || 'X-API-Key'};
    }
    if (t === 'cookie') return {type: 'cookie', cookies: document.getElementById('auth-cookies').value};
    return null;
}

loadProfiles();
```

- [ ] **Step 4: startScan 请求体扩展**

替换 `startScan()` 中「模块收集 + fetch body」两段。模块收集：

```js
    const modules = collectModules();
```

`fetch('/api/scan', {...})` 的 body 替换为：

```js
        body: JSON.stringify({
            url: url,
            modules: modules,
            profile: document.getElementById('profile-select').value || null,
            explain: document.getElementById('cfg-explain').checked,
            from_proxy: document.getElementById('cfg-from-proxy').checked,
            auth: buildAuthPayload(),
            rate: parseInt(document.getElementById('cfg-rate').value) || 15,
            timeout: parseInt(document.getElementById('cfg-timeout').value) || 15,
            crawl_depth: parseInt(document.getElementById('cfg-depth').value) || 2,
            crawl_max_urls: parseInt(document.getElementById('cfg-urls').value) || 50,
            concurrent_endpoints: parseInt(document.getElementById('cfg-concurrent').value) || 10,
            insecure: document.getElementById('cfg-insecure').checked,
        }),
```

- [ ] **Step 5: 证据链展开行**

替换 `addResultRow` 整个函数为：

```js
function addResultRow(v) {
    const tbody = document.getElementById('results-body');
    const sev = (v.severity || 'info').toLowerCase();
    const badgeCls = `badge-${sev}`;
    const tr = document.createElement('tr');
    tr.dataset.severity = sev;
    tr.style.cursor = 'pointer';
    tr._vulnData = v;
    const typeText = escapeHtml(v.type || '');
    const urlText = escapeHtml(v.url || '');
    tr.innerHTML = `
        <td><span class="severity-badge ${badgeCls}">${sev.toUpperCase()}</span></td>
        <td class="result-type">${typeText}</td>
        <td class="result-url" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${urlText}</td>
        <td>${escapeHtml(v.parameter || '')}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(v.evidence || '')}</td>
    `;
    tr.onclick = () => toggleDetailRow(tr);
    _allResults.push({sev, type: typeText, url: urlText, el: tr});
    tbody.appendChild(tr);

    updateStats();
    filterResults();
}

function toggleDetailRow(tr) {
    const next = tr.nextElementSibling;
    if (next && next.classList.contains('detail-row')) {
        next.style.display = next.style.display === 'none' ? '' : 'none';
        return;
    }
    const detail = document.createElement('tr');
    detail.className = 'detail-row';
    detail.innerHTML = `<td colspan="5" style="background:#0d1117;">${renderEvidenceChain(tr._vulnData || {})}</td>`;
    tr.insertAdjacentElement('afterend', detail);
}

function renderEvidenceChain(v) {
    let html = '';
    if (v.description) html += `<div class="mb-1"><strong>描述:</strong> ${escapeHtml(v.description)}</div>`;
    if (v.recommendation) html += `<div class="mb-1"><strong>修复建议:</strong> ${escapeHtml(v.recommendation)}</div>`;
    if (v.payload) html += `<div class="mb-1"><strong>载荷:</strong> <code>${escapeHtml(v.payload)}</code></div>`;
    const chain = v.evidence_chain || [];
    if (chain.length) {
        html += '<div><strong>证据链:</strong><ol class="mb-0 mt-1">';
        chain.forEach(ev => {
            html += `<li><span class="badge bg-secondary">${escapeHtml(ev.kind || '')}</span> ${escapeHtml(ev.detail || '')}`;
            if (ev.data && Object.keys(ev.data).length) {
                html += `<pre class="mb-0 mt-1" style="font-size:11px;white-space:pre-wrap;">${escapeHtml(JSON.stringify(ev.data, null, 2))}</pre>`;
            }
            html += '</li>';
        });
        html += '</ol></div>';
    }
    return html || '<span class="text-muted">（无证据链，未开启 explain 或无信号）</span>';
}
```

- [ ] **Step 6: 冒烟**

```powershell
python -c "import web_ui.app; print('import OK')"
```

Expected: `import OK`。

- [ ] **Step 7: 提交**

```powershell
git add web_ui/templates/index.html
git commit -m "feat(v2.3): Web UI 扫描面板 — profile/认证/explain/from-proxy/证据链展开（T3.5）"
```

---

### Task 9: index.html 被动捕获 Tab

**Files:**
- Modify: `web_ui/templates/index.html`

- [ ] **Step 1: 用面板替换占位 pane**

把 `<div class="tab-pane fade" id="tab-passive" role="tabpanel"></div>` 替换为：

```html
    <div class="tab-pane fade" id="tab-passive" role="tabpanel">
        <div class="row g-3 mt-1">
            <div class="col-12 col-md-5">
                <div class="card">
                    <div class="card-header py-2">被动捕获配置</div>
                    <div class="card-body py-2">
                        <div class="mb-2">
                            <label class="stat-label">目标域（必填，须有授权）</label>
                            <input class="form-control form-control-sm" id="passive-target" placeholder="http://授权目标">
                        </div>
                        <div class="row g-2 mb-2">
                            <div class="col-6">
                                <label class="stat-label">监听地址</label>
                                <input class="form-control form-control-sm" id="passive-listen" value="127.0.0.1">
                            </div>
                            <div class="col-6">
                                <label class="stat-label">端口</label>
                                <input class="form-control form-control-sm" id="passive-port" value="8081">
                            </div>
                        </div>
                        <div class="mb-2">
                            <label class="stat-label">队列文件（仅限 scan_reports/）</label>
                            <input class="form-control form-control-sm" id="passive-queue"
                                   value="scan_reports/proxy_queue.json">
                        </div>
                        <div class="form-check mb-2">
                            <input class="form-check-input" type="checkbox" id="passive-tls">
                            <label class="form-check-label" for="passive-tls">TLS 解密（需先信任 CA）</label>
                        </div>
                        <div class="mb-2" id="passive-ca-row" style="display:none">
                            <label class="stat-label">CA 目录（留空用默认 ~/.rayscan/ca）</label>
                            <input class="form-control form-control-sm" id="passive-ca-dir" placeholder="~/.rayscan/ca">
                        </div>
                        <button class="btn btn-primary btn-sm" id="btn-passive-start" onclick="startPassive()">▶ 启动代理</button>
                        <button class="btn btn-danger btn-sm" id="btn-passive-stop" onclick="stopPassive()" disabled>■ 停止</button>
                    </div>
                </div>
            </div>
            <div class="col-12 col-md-7">
                <div class="card">
                    <div class="card-header py-2 d-flex justify-content-between align-items-center">
                        <span>捕获状态（只捕获不入检）</span>
                        <button class="btn btn-sm btn-outline-secondary" onclick="toQueueScan()"
                                id="btn-queue-scan" disabled>去扫描队列</button>
                    </div>
                    <div class="card-body py-2">
                        <div class="row text-center mb-2">
                            <div class="col-3"><div class="stat-label">捕获请求</div><div class="stat-value" id="p-stat-requests">0</div></div>
                            <div class="col-3"><div class="stat-label">发现端点</div><div class="stat-value" id="p-stat-endpoints">0</div></div>
                            <div class="col-3"><div class="stat-label">已入队</div><div class="stat-value" id="p-stat-queued">0</div></div>
                            <div class="col-3"><div class="stat-label">状态</div><div class="stat-value" id="p-stat-state">未运行</div></div>
                        </div>
                        <div class="stat-label" id="p-hint">启动后将浏览器/工具代理指向提示地址，浏览目标站点即可捕获真实参数面。</div>
                        <div class="stat-label mt-1" id="p-queue-path" style="font-size:0.7rem;"></div>
                        <div class="log-error mt-1" id="p-errors" style="font-size:0.75rem;"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
```

- [ ] **Step 2: 被动 JS**

在 `loadProfiles();` 之后插入：

```js
let passiveTimer = null;

async function startPassive() {
    const target = document.getElementById('passive-target').value.trim();
    if (!target) { alert('请输入目标域（必须是你有授权的目标）'); return; }
    const body = {
        target: target,
        listen: document.getElementById('passive-listen').value.trim() || '127.0.0.1',
        port: parseInt(document.getElementById('passive-port').value) || 8081,
        tls_intercept: document.getElementById('passive-tls').checked,
        ca_dir: document.getElementById('passive-ca-dir').value.trim() || null,
        queue_out: document.getElementById('passive-queue').value.trim(),
    };
    const r = await fetch('/api/passive/start', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': '{{ csrf_token }}'},
        body: JSON.stringify(body),
    });
    const d = await r.json();
    if (d.error) { alert(d.error); return; }
    document.getElementById('btn-passive-start').disabled = true;
    document.getElementById('btn-passive-stop').disabled = false;
    document.getElementById('p-queue-path').textContent = '队列: ' + d.queue_path;
    if (passiveTimer) clearInterval(passiveTimer);
    passiveTimer = setInterval(refreshPassiveStatus, 2000);
    refreshPassiveStatus();
}

async function stopPassive() {
    const r = await fetch('/api/passive/stop', {
        method: 'POST',
        headers: {'X-CSRF-Token': '{{ csrf_token }}'},
    });
    const d = await r.json();
    if (d.error) { alert(d.error); return; }
    document.getElementById('btn-passive-start').disabled = false;
    document.getElementById('btn-passive-stop').disabled = true;
    if (passiveTimer) { clearInterval(passiveTimer); passiveTimer = null; }
    refreshPassiveStatus();
}

async function refreshPassiveStatus() {
    try {
        const r = await fetch('/api/passive/status');
        const s = await r.json();
        document.getElementById('p-stat-requests').textContent = s.requests_captured || 0;
        document.getElementById('p-stat-endpoints').textContent = s.endpoints_discovered || 0;
        document.getElementById('p-stat-queued').textContent = s.queued_endpoints || 0;
        document.getElementById('p-stat-state').textContent = s.running ? '运行中' : '已停止';
        document.getElementById('btn-queue-scan').disabled = !(s.queued_endpoints > 0);
        if (s.running) {
            const tlsHint = s.tls_intercept
                ? `HTTPS 解密已开，请先信任 ${s.ca_dir || '~/.rayscan/ca'} 下的 CA 证书。`
                : 'HTTPS 流量仅隧道转发（不解密）。';
            document.getElementById('p-hint').textContent =
                `浏览器/工具代理指向 ${s.listen}；目标域 ${s.target_filter || ''}。` + tlsHint;
        }
        document.getElementById('p-errors').textContent = (s.errors || []).join(' | ');
    } catch (e) {}
}

function toQueueScan() {
    const target = document.getElementById('passive-target').value.trim();
    document.getElementById('tab-scan-btn').click();
    if (target) document.getElementById('url-input').value = target;
    document.getElementById('cfg-from-proxy').checked = true;
    appendLog('--', 'INFO', '已切换到扫描页并启用「被动队列定向扫描」，点击开始扫描');
}

document.getElementById('passive-tls').addEventListener('change', e => {
    document.getElementById('passive-ca-row').style.display = e.target.checked ? '' : 'none';
});
```

- [ ] **Step 3: 冒烟**

```powershell
python -c "import web_ui.app; print('import OK')"
```

- [ ] **Step 4: 提交**

```powershell
git add web_ui/templates/index.html
git commit -m "feat(v2.3): Web UI 被动捕获 Tab — 代理启停/状态轮询/队列转扫描（T3.5）"
```

---

### Task 10: CI/ruff 覆盖 web_ui + 版本 2.3.0

**Files:**
- Modify: `.github/workflows/ci.yml:92,105`
- Modify: `pyproject.toml:7`、`wvs/__init__.py`、`README.md`、其余存量版本引用
- Modify: `web_ui/app.py`（已是动态版本）、`web_ui/templates/index.html`（已是 `{{ version }}`）

- [ ] **Step 1: CI ruff 命令加 `web_ui/`**

```yaml
        run: ruff check wvs/ tests/ web_ui/
```

```yaml
        run: ruff format --check wvs/ tests/ web_ui/
```

- [ ] **Step 2: 版本号 2.2.0 → 2.3.0**

`pyproject.toml`：

```toml
version = "2.3.0"
```

`wvs/__init__.py`：

```python
"""
RayScan 2.3.0 — Practical Web Vulnerability Scanner
(RayScan 2.3.0)
"""

# 版本单一事实源（SSOT）：与 pyproject.toml [project].version 保持一致
__version__ = "2.3.0"
```

存量引用同步（docstring / 协议标识）：

- `wvs/core/encoding_bypass.py:2` → `RayScan 2.3.0 — Encoding bypass payload generator`
- `wvs/exploit/engine.py:2` → `RayScan 2.3.0 Exploit Engine`
- `wvs/integrations/__init__.py:3` → `RayScan 2.3.0 — External Tool Integration Module`
- `wvs/core/session_manager.py:2` → `RayScan 2.3.0 — Session lifecycle manager`
- `wvs/modules/mcp/detector.py:77` → `"clientInfo": {"name": "rayscan", "version": "2.3.0"}`

README：

- 第 1 行 `# 🔬 RayScan 2.2.0` → `# 🔬 RayScan 2.3.0`
- 第 7 行徽章 `Version-2.2.0-blue` → `Version-2.3.0-blue`
- 第 22 行改为：
  `> 📈 **v2.3.0 新特性**：被动捕获→主动验证联动（passive --queue-out / scan --from-proxy）· 证据包导出（report --pack，含可复现 curl）· OA 规则外部化（rules/oa YAML）· Nuclei 模板策展 · Web UI 三能力入口（被动捕获 / Profile / 证据链）`
- 第 10/17 行测试数徽章：跑 `python -m pytest --collect-only tests/ | Select-String collected` 取实测数字（不要用 `-q`，pyproject addopts 已含 `-q`，再传 `-q` 会变 `-qq` 吞掉汇总行），把 376 更新为实测值。
- 第 163 行示例输出 `RayScan 2.2.0` → `RayScan 2.3.0`

- [ ] **Step 3: 验证版本一致性 + 全量测试**

```powershell
python -m pytest tests/test_smoke_cli.py -q
python -m pytest tests/ -q
```

Expected: 全量 PASS（版本一致性用例通过）。

- [ ] **Step 4: ruff 全绿**

```powershell
ruff check wvs/ tests/ web_ui/
ruff format --check wvs/ tests/ web_ui/
```

Expected: `All checks passed!` / 无 format 差异（有差异则先 `ruff format` 再提交）。

- [ ] **Step 5: 提交**

```powershell
git add .github/workflows/ci.yml pyproject.toml wvs/__init__.py README.md wvs/core/encoding_bypass.py wvs/exploit/engine.py wvs/integrations/__init__.py wvs/core/session_manager.py wvs/modules/mcp/detector.py
git commit -m "chore(v2.3): 版本升级 2.3.0 + CI ruff 覆盖 web_ui/"
```

---

### Task 11: 文档

**Files:**
- Modify: `CHANGELOG.md`（[Unreleased] 顶部新增 T3.5 段）
- Modify: `docs/rayscan-upgrade-roadmap-2026-09-07.md`（执行状态 T3.5 完成）
- Modify: `AGENTS.md`（Change Log 新条目）

- [ ] **Step 1: CHANGELOG**

在 `## [Unreleased]` 下、T3.2 条目前插入：

```markdown
### Added — v2.3 T3.5 Web UI 对齐 CLI（passive / explain / profile 三能力入口）

- **薄 app + 服务层**：`web_ui/app.py` 收敛为路由/鉴权/CSRF 层；新增 `web_ui/sessions.py`（`ScanSession` 线程+SSE+结果序列化、`PassiveProxySession` 代理线程状态机）与 `web_ui/payloads.py`（profile/参数/模块解析纯函数）
- **认证（五种）**：Web UI 支持 form/bearer/basic/apikey/cookie 认证扫描，扫描中自动启用登录态维持（T2.4）；认证装配/执行提取为 `wvs.plugins.auth.configure_from_options/authenticate_and_apply`（CLI cmd_scan 同步改用，行为不变）
- **证据链**：扫描默认开 explain，SSE 结果与 JSON 导出均含 `evidence_chain`；结果表行点击展开逐信号明细
- **Profile**：下拉应用（填充速率/深度/模块）+ 当前配置保存为新 Profile（内置名保护，名称白名单校验）
- **被动捕获闭环**：UI 启动/停止代理（TLS 解密可选、目标域必填、queue_out 限 scan_reports/）→ 2s 轮询捕获统计 → 「去扫描队列」预填并 `from_proxy` 定向主动验证（复用 `wvs/core/passive/queue_scan.py` 共享实现，gentle 限速）
- **死标签修复**：dashboard/history 接入 Tab 导航；`_record_scan` 首次被调用（历史/统计有数据，读写加锁）；模块列表从硬编码 10 个改为 `/api/modules` 动态获取（18 个）；版本号改由 `wvs.__version__` 渲染
- **共享提取**：`wvs/core/passive/queue_scan.py`（`apply_gentle_rate_cap`/`queue_endpoint_to_target`/`scan_proxy_queue` 自 cli.py 转正），CLI 与 UI 同一实现
- **测试**：`tests/test_web_ui.py`（payloads/ScanSession/PassiveProxySession/API 共 24 用例）、`tests/test_auth_assembly.py`（8 用例）；CI ruff 覆盖 `web_ui/`
```

- [ ] **Step 2: 路线图状态**

把「待办：⑪ v2.3 四件。」改为：

```markdown
> **⑪ 已完成（2026-09-12）**：v2.3 四件全部落地（T3.1 联动 / T3.2 证据包 / T3.3 规则外部化 / T3.4 模板策展），
> 另完成 **T3.5 Web UI 对齐 CLI**（passive 捕获队列闭环 / explain 证据链 / profile 应用保存 / 五类认证）。
> v2.3 收尾，版本升 2.3.0。
```

并把 v2.3 表格 T3.5 行「说明」前加 `✅ `。

- [ ] **Step 3: AGENTS.md Change Log**

在 `## Change Log` 下插入新条目（日期 2026-09-12），内容概括：T3.5 三能力入口、共享提取、测试/CI、版本 2.3.0，并列出影响文件。

- [ ] **Step 4: 提交**

```powershell
git add CHANGELOG.md docs/rayscan-upgrade-roadmap-2026-09-07.md AGENTS.md
git commit -m "docs(v2.3): T3.5 收尾 — CHANGELOG/路线图/变更日志"
```

---

### Task 12: 全量回归 + 手工验收

- [ ] **Step 1: 全量测试 + 覆盖率门禁（对齐 CI）**

```powershell
python -m pytest tests/ -q --cov=wvs --cov-report=term-missing
```

Expected: 全部 PASS，`fail_under=30` 通过（新增测试只会抬高覆盖率）。

- [ ] **Step 2: CLI 回归（共享提取后主链路）**

```powershell
python -m wvs list-modules
python -m wvs --help
python -m wvs scan --help
```

Expected: 无异常，模块数 18。

- [ ] **Step 3: Web UI 手工验收（curl 冒烟 + 浏览器）**

```powershell
$env:RAYSCAN_WEB_TOKEN="devtoken"
$p = Start-Process -FilePath python -ArgumentList "web_ui/app.py" -PassThru
Start-Sleep -Seconds 3
curl.exe -s -H "X-Api-Token: devtoken" http://127.0.0.1:5000/api/modules
curl.exe -s -H "X-Api-Token: devtoken" http://127.0.0.1:5000/api/profiles
curl.exe -s -H "X-Api-Token: devtoken" http://127.0.0.1:5000/api/passive/status
```

Expected: 三个端点 200 JSON；`/api/modules` 含 18 模块。

浏览器打开 `http://127.0.0.1:5000` → token 登录，逐项确认：

1. 三 Tab 可达；扫描 Tab 模块列表 18 个、Profile 下拉含内置 5 个
2. 对本地靶场发起一次 explain 扫描：结果行可展开证据链、历史 Tab 出现记录
3. 被动 Tab：填入本地靶场域 → 启动 → 浏览器代理指向提示地址访问靶场 → 计数增长 → 停止 → 「去扫描队列」→ 扫描页 `from_proxy` 已勾选 → 开始扫描，检出捕获面漏洞
4. 认证面板：选 form 类型填写本地靶场登录信息，扫描日志出现「认证成功」

验收完成后停止 Web UI 进程：

```powershell
Stop-Process -Id $p.Id
```

- [ ] **Step 4: 收尾提交（如有验收中出现的小修复）**

```powershell
git status
git add -A
git commit -m "fix(v2.3): T3.5 手工验收修复"
```

验收无问题则跳过本步。

---

## 自审记录

- **Spec 覆盖**：§4.1→Task 1；§4.2→Task 2；§5.1→Task 6/8；§5.2→Task 3/6/8；§5.3→Task 5/6/9；§5.4→Task 6；§6→Task 7/8/9；§7→Task 6；§8→Task 2-6；§9→Task 10/11；§10→Task 12
- **无占位符**：所有代码步骤含完整代码与预期输出
- **类型一致性**：`apply_scan_config/resolve_scan_modules/module_catalog`、`ScanSession.start(payload, config, modules, from_proxy_queue_path, on_finish)`、`PassiveProxySession.start/stop/status`、`configure_from_options/authenticate_and_apply/parse_cookies`、`apply_gentle_rate_cap/queue_endpoint_to_target/scan_proxy_queue` 在各 Task 间命名一致
