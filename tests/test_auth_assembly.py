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

    # 旧行为保留:用户名+密码但缺 login_url 时仍视为表单登录意图
    # （configure_from_options 会报错退出，不会静默跳过认证）
    missing_login_url = SimpleNamespace(**{**legacy.__dict__, "login_url": None})
    assert _auth_options_from_args(missing_login_url)["type"] == "form"
    ok, err = configure_from_options(AuthManager(), _auth_options_from_args(missing_login_url))
    assert not ok and "login_url" in err

    empty = SimpleNamespace(**{**legacy.__dict__, "login_url": None, "username": None, "password": None})
    assert _auth_options_from_args(empty) is None
