"""
认证插件
v18 痛点：认证扫描从未实现，导致需要登录的页面完全扫不了

支持三种认证方式：
1. Form Login（表单认证）— 提交登录表单获取 session cookie（v19: 自动提取 CSRF token）
2. Bearer Token — Authorization: Bearer <token>
3. Basic Auth — Authorization: Basic <base64>
4. API Key — 自定义 header（如 X-API-Key）
"""
import asyncio
import base64
import logging
import re
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx

from ..config import ConfigManager
from ..models import ScanTarget


logger = logging.getLogger("wvs.auth")


# ─────────────────────────────────────────────────────────────────
# Auth Provider 接口
# ─────────────────────────────────────────────────────────────────

class AuthProvider(ABC):
    """
    认证提供者基类

    子类必须实现：
    - authenticate(): 执行认证，返回 cookies/headers
    - is_authenticated(): 检查是否仍然有效
    """

    @abstractmethod
    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        """
        执行认证

        Args:
            session: httpx 客户端实例

        Returns:
            dict，包含：
            - cookies: Dict[str, str]
            - headers: Dict[str, str]
            - authenticated: bool
            - error: Optional[str]
        """
        ...

    async def is_authenticated(
        self,
        session: httpx.AsyncClient,
        check_url: str,
    ) -> bool:
        """
        检查认证是否仍然有效（子类可覆盖）

        默认：检查响应状态码，2xx = 有效
        """
        try:
            resp = await session.get(check_url, timeout=10)
            return resp.status_code < 400
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────
# 表单认证
# ─────────────────────────────────────────────────────────────────

class FormLoginAuth(AuthProvider):
    """
    表单登录认证（v19: 自动提取 CSRF token）

    流程：
    1. GET 登录页面 → 提取 CSRF token
    2. POST 登录表单 → 获取 session cookie

    配置参数：
    - login_url: 登录页面地址（同时作为 GET 和 POST 目标）
    - username_field: 用户名 input 的 name 属性（默认 username）
    - password_field: 密码 input 的 name 属性（默认 password）
    - extra_fields: 额外表单字段
    - csrf_fields: 自定义 CSRF 字段名列表（默认自动检测常见名称）
    - success_check: 登录成功判断字符串
    - fail_check: 登录失败判断字符串
    """

    # 自动检测的 CSRF token 字段名（按常见度排序）
    CSRF_FIELD_NAMES = [
        "user_token",        # DVWA
        "csrf_token",        # 通用
        "csrfmiddlewaretoken", # Django
        "authenticity_token",  # Rails
        "_token",            # Laravel
        "token",             # 通用
        "anti_forgery_token",  # ASP.NET
        "__requestverificationtoken",  # ASP.NET MVC
        "nonce",             # WordPress
        "_wpnonce",          # WordPress
    ]

    # 登录失败常见标识
    DEFAULT_FAIL_CHECKS = [
        "login failed",
        "Login failed",
        "Login Failed",
        "incorrect",
        "Invalid username or password",
        "Invalid Username or Password",
        "authentication failed",
        "Authentication failed",
        "wrong password",
        "Wrong password",
        "登录失败",
        "用户名或密码错误",
        "名或密码不正确",
    ]

    def __init__(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: Optional[Dict[str, str]] = None,
        csrf_fields: Optional[List[str]] = None,
        success_check: Optional[str] = None,
        fail_check: Optional[str] = None,
        method: str = "POST",
    ):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.extra_fields = extra_fields or {}
        self.csrf_fields = csrf_fields or self.CSRF_FIELD_NAMES
        self.success_check = success_check
        self.fail_check = fail_check
        self.method = method.upper()

    def _extract_csrf_tokens(self, html: str) -> Dict[str, str]:
        """
        从登录页面 HTML 中提取 CSRF token

        支持的 HTML 形式：
        - <input type="hidden" name="user_token" value="xxx">
        - <input name="csrf_token" type="hidden" value="xxx">
        - <meta name="csrf-token" content="xxx">

        Returns:
            dict: {field_name: token_value}
        """
        tokens: Dict[str, str] = {}

        # 优先检查用户指定的字段
        field_names = list(self.csrf_fields)

        for field_name in field_names:
            # 模式1: <input ... name="field_name" ... value="xxx">
            # 匹配 name 在 value 前面或后面的情况
            patterns = [
                # name="xxx" value="yyy"
                rf'<input[^>]*\bname\s*=\s*["\']?{re.escape(field_name)}["\']?[^>]*\bvalue\s*=\s*["\']([^"\']+)["\']',
                # value="yyy" name="xxx"
                rf'<input[^>]*\bvalue\s*=\s*["\']([^"\']+)["\'][^>]*\bname\s*=\s*["\']?{re.escape(field_name)}["\']?[^>]*',
                # <meta name="xxx" content="yyy">
                rf'<meta[^>]*\bname\s*=\s*["\']?{re.escape(field_name)}["\']?[^>]*\bcontent\s*=\s*["\']([^"\']+)["\']',
            ]
            for pattern in patterns:
                m = re.search(pattern, html, re.IGNORECASE)
                if m:
                    tokens[field_name] = m.group(1)
                    logger.debug(f"[Auth:FormLogin] 提取 CSRF token: {field_name}={m.group(1)[:8]}...")
                    break  # 找到一个就够

        return tokens

    def _extract_submit_buttons(self, html: str) -> Dict[str, str]:
        """
        从登录页面 HTML 中提取 submit 按钮

        许多登录表单需要提交按钮的 name=value 才能正常工作
        （如 DVWA 要求 Login=Login）

        Returns:
            dict: {button_name: button_value}
        """
        buttons: Dict[str, str] = {}

        # <input type="submit" name="Login" value="Login">
        patterns = [
            # <input type="submit" name="xxx" value="yyy">
            rf'<input[^>]*type\s*=\s*["\']?submit["\']?[^>]*\bname\s*=\s*["\']([^"\']+)["\']?[^>]*\bvalue\s*=\s*["\']([^"\']*)["\']',
            # <input type="submit" value="yyy" name="xxx">
            rf'<input[^>]*type\s*=\s*["\']?submit["\']?[^>]*\bvalue\s*=\s*["\']([^"\']*)["\']?[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
            # <button type="submit" name="xxx" value="yyy">
            rf'<button[^>]*type\s*=\s*["\']?submit["\']?[^>]*\bname\s*=\s*["\']([^"\']+)["\']?[^>]*\bvalue\s*=\s*["\']([^"\']*)["\']',
        ]

        for pattern in patterns:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                # 取 name 和 value（位置取决于模式）
                groups = m.groups()
                if len(groups) == 2:
                    # 第一个模式：name, value
                    name, value = groups[0], groups[1]
                    if name and value:
                        buttons[name] = value
                        logger.debug(f"[Auth:FormLogin] 发现 submit 按钮: {name}={value}")
                    elif name:
                        buttons[name] = ""
                        logger.debug(f"[Auth:FormLogin] 发现 submit 按钮: {name}=(empty)")
                break  # 只取第一个 submit 按钮

        return buttons

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        try:
            # ── Step 1: GET 登录页面，提取 CSRF token ──
            logger.info(f"[Auth:FormLogin] GET {self.login_url} (提取 CSRF token)")
            get_resp = await session.get(self.login_url, timeout=30, follow_redirects=True)

            csrf_tokens = {}
            submit_buttons = {}
            if get_resp.status_code == 200:
                csrf_tokens = self._extract_csrf_tokens(get_resp.text)
                submit_buttons = self._extract_submit_buttons(get_resp.text)
                if csrf_tokens:
                    logger.info(f"[Auth:FormLogin] 发现 {len(csrf_tokens)} 个 CSRF token: {list(csrf_tokens.keys())}")
                else:
                    logger.debug("[Auth:FormLogin] 未发现 CSRF token（可能不需要）")
                if submit_buttons:
                    logger.info(f"[Auth:FormLogin] 发现 {len(submit_buttons)} 个 submit 按钮: {list(submit_buttons.keys())}")
            else:
                logger.debug(f"[Auth:FormLogin] GET 返回 {get_resp.status_code}，跳过 CSRF 提取")

            # ── Step 2: 构建登录 POST data ──
            data = {
                self.username_field: self.username,
                self.password_field: self.password,
            }
            # Submit 按钮（很多表单需要，如 DVWA 的 Login=Login）
            data.update(submit_buttons)
            # CSRF token 优先级：extra_fields > 自动提取
            data.update(csrf_tokens)
            data.update(self.extra_fields)

            logger.info(f"[Auth:FormLogin] {self.method} {self.login_url}")
            logger.debug(f"[Auth:FormLogin] 字段: {list(data.keys())}")

            # ── Step 3: POST 登录表单 ──
            if self.method == "POST":
                resp = await session.post(self.login_url, data=data, timeout=30, follow_redirects=True)
            else:
                resp = await session.request(self.method, self.login_url, data=data, timeout=30, follow_redirects=True)

            # ── Step 4: 检查登录结果 ──

            # 4a. 最强信号：POST 后 URL 不再是登录页 → 登录成功
            login_path = self.login_url.rstrip("/").split("/")[-1]
            current_path = str(resp.url).rstrip("/")
            if login_path not in current_path.split("/")[-1]:
                cookies = dict(session.cookies)
                if cookies:
                    logger.info(f"[Auth:FormLogin] ✅ 登录成功（已跳转到 {resp.url}，{len(cookies)} cookie）")
                    return {"cookies": cookies, "headers": {}, "authenticated": True, "error": None}

            # 4b. 检查失败标识
            fail_checks = [self.fail_check] if self.fail_check else self.DEFAULT_FAIL_CHECKS
            for fc in fail_checks:
                if fc and fc in resp.text:
                    return {
                        "cookies": {},
                        "headers": {},
                        "authenticated": False,
                        "error": f"登录失败：响应包含失败标识 '{fc}'",
                    }

            # 4b. 检查是否还在登录页（说明没跳转成功）
            login_form_indicators = [
                f'name="{self.username_field}"',
                f'name="{self.password_field}"',
                f'name=\'{self.username_field}\'',
                f'name=\'{self.password_field}\'',
            ]
            still_on_login = any(ind in resp.text for ind in login_form_indicators)
            # 只有当 URL 仍然是登录页时才认为失败
            if still_on_login and self.login_url.rstrip("/") in resp.url.path:
                # 再确认：如果页面也有成功标识，那不算失败
                if not self.success_check or self.success_check not in resp.text:
                    return {
                        "cookies": {},
                        "headers": {},
                        "authenticated": False,
                        "error": "登录后仍停留在登录页面，可能用户名/密码错误或 CSRF token 无效",
                    }

            # 4c. 检查成功标识
            if self.success_check:
                if self.success_check in resp.text:
                    cookies = dict(session.cookies)
                    logger.info(f"[Auth:FormLogin] ✅ 登录成功，获取 {len(cookies)} 个 cookie")
                    return {"cookies": cookies, "headers": {}, "authenticated": True, "error": None}
                else:
                    # 没有成功标识，但也没有失败标识 → 尝试检查 cookie
                    cookies = dict(session.cookies)
                    if cookies:
                        logger.info(f"[Auth:FormLogin] ⚠ 无成功标识但有 {len(cookies)} cookie，视为登录成功")
                        return {"cookies": cookies, "headers": {}, "authenticated": True, "error": None}
                    return {
                        "cookies": {},
                        "headers": {},
                        "authenticated": False,
                        "error": f"登录成功标识 '{self.success_check}' 未在响应中找到",
                    }

            # 4d. 默认：有 cookie 就算成功
            if resp.status_code in (200, 302, 303):
                cookies = dict(session.cookies)
                if cookies:
                    logger.info(f"[Auth:FormLogin] ✅ 登录成功（{len(cookies)} cookie）")
                    return {"cookies": cookies, "headers": {}, "authenticated": True, "error": None}
                else:
                    return {
                        "cookies": {},
                        "headers": {},
                        "authenticated": False,
                        "error": "未获取到任何 cookie",
                    }

            return {
                "cookies": {},
                "headers": {},
                "authenticated": False,
                "error": f"HTTP {resp.status_code}",
            }

        except Exception as e:
            logger.error(f"[Auth:FormLogin] 异常: {e}")
            return {"cookies": {}, "headers": {}, "authenticated": False, "error": str(e)}


# ─────────────────────────────────────────────────────────────────
# Bearer Token
# ─────────────────────────────────────────────────────────────────

class BearerTokenAuth(AuthProvider):
    """
    Bearer Token 认证

    用于 JWT、OAuth2 access_token 等场景
    """

    def __init__(self, token: str, header_name: str = "Authorization"):
        self.token = token
        self.header_name = header_name

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        header_value = f"Bearer {self.token}" if not self.token.startswith("Bearer ") else self.token
        return {
            "cookies": {},
            "headers": {self.header_name: header_value},
            "authenticated": True,
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# Basic Auth
# ─────────────────────────────────────────────────────────────────

class BasicAuth(AuthProvider):
    """
    HTTP Basic 认证
    """

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        credentials = base64.b64encode(
            f"{self.username}:{self.password}".encode()
        ).decode()
        return {
            "cookies": {},
            "headers": {"Authorization": f"Basic {credentials}"},
            "authenticated": True,
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# API Key
# ─────────────────────────────────────────────────────────────────

class APIKeyAuth(AuthProvider):
    """
    API Key 认证（自定义 Header）
    """

    def __init__(self, key: str, header_name: str = "X-API-Key"):
        self.key = key
        self.header_name = header_name

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        return {
            "cookies": {},
            "headers": {self.header_name: self.key},
            "authenticated": True,
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# Cookie Auth（直接注入已有 cookie）
# ─────────────────────────────────────────────────────────────────

class CookieAuth(AuthProvider):
    """
    直接注入 Cookie（手动获取或从浏览器复制）
    """

    def __init__(self, cookies: Dict[str, str]):
        if isinstance(cookies, str):
            # 支持 "PHPSESSID=abc; user=admin" 格式的字符串
            self.cookie_dict = {}
            for part in cookies.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.cookie_dict[k.strip()] = v.strip()
        else:
            self.cookie_dict = cookies

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        # 直接设置 cookies 到 session
        for name, value in self.cookie_dict.items():
            session.cookies.set(name, value)
        return {
            "cookies": self.cookie_dict,
            "headers": {},
            "authenticated": True,
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# Auth Manager
# ─────────────────────────────────────────────────────────────────

class AuthManager:
    """
    认证管理器

    统一管理认证流程：
    1. 构建 AuthProvider
    2. 执行认证
    3. 将认证结果注入 ScanTarget
    4. 验证认证状态
    """

    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self._provider: Optional[AuthProvider] = None
        self._auth_result: Dict[str, Any] = {}

    def configure_form_login(
        self,
        login_url: str,
        username: str,
        password: str,
        **kwargs,
    ) -> "AuthManager":
        """配置表单登录"""
        self._provider = FormLoginAuth(
            login_url=login_url,
            username=username,
            password=password,
            **kwargs,
        )
        return self

    def configure_bearer(self, token: str, header_name: str = "Authorization") -> "AuthManager":
        self._provider = BearerTokenAuth(token=token, header_name=header_name)
        return self

    def configure_basic(self, username: str, password: str) -> "AuthManager":
        self._provider = BasicAuth(username=username, password=password)
        return self

    def configure_api_key(self, key: str, header_name: str = "X-API-Key") -> "AuthManager":
        self._provider = APIKeyAuth(key=key, header_name=header_name)
        return self

    def configure_cookies(self, cookies: Dict[str, str]) -> "AuthManager":
        self._provider = CookieAuth(cookies=cookies)
        return self

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        """
        执行认证，返回认证信息

        Returns:
            dict，同 AuthProvider.authenticate() 返回值
        """
        if not self._provider:
            logger.warning("[AuthManager] 未配置任何认证方式")
            return {"cookies": {}, "headers": {}, "authenticated": False, "error": "No auth configured"}

        self._auth_result = await self._provider.authenticate(session)
        return self._auth_result

    def apply_to_target(self, target: ScanTarget) -> ScanTarget:
        """
        将认证结果应用到 ScanTarget

        修改 target.cookies 和 target.headers
        """
        if not self._auth_result:
            logger.warning("[AuthManager] 尚未执行认证")
            return target

        if self._auth_result.get("cookies"):
            for k, v in self._auth_result["cookies"].items():
                target.cookies[k] = v
                logger.debug(f"[AuthManager] 应用 Cookie: {k}=...")

        if self._auth_result.get("headers"):
            target.headers.update(self._auth_result["headers"])
            logger.debug(f"[AuthManager] 应用 Header: {list(self._auth_result['headers'].keys())}")

        return target

    @property
    def is_authenticated(self) -> bool:
        return self._auth_result.get("authenticated", False)

    @property
    def auth_error(self) -> Optional[str]:
        return self._auth_result.get("error")

    @property
    def provider_name(self) -> str:
        return self._provider.__class__.__name__ if self._provider else "None"
