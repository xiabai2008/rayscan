"""Phase 1 亮点 C:业务逻辑检测模块单元测试。

覆盖:
- IDOR: 对象替换判定、公共路径排除、非数字参数跳过
- AuthBypass: 认证头移除重放判定、登录页排除
- 模块注册信息(category=lite, enabled_by_default=False)
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

from wvs.config import ConfigManager
from wvs.models import ScanTarget, Vulnerability


class _FakeSession:
    """模拟 HTTPPool:按 URL 返回配置的响应,并模拟 httpx 的 query 拼接。"""

    def __init__(self, responses: Dict[str, Dict[str, Any]]):
        self.responses = responses
        self.calls: List[Dict[str, Any]] = []

    @staticmethod
    def _with_query(url: str, params) -> str:
        if not params:
            return url
        from urllib.parse import urlencode

        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{urlencode(params)}"

    async def request(self, method: str, url: str, **kwargs) -> Any:
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        full_url = url
        # GET: httpx 将 params 拼接到 URL
        if method.upper() == "GET" and kwargs.get("params"):
            full_url = self._with_query(url, kwargs["params"])
        resp = self.responses.get(full_url, self.responses.get("__default__", {}))
        return _FakeResponse(resp.get("status_code", 404), resp.get("text", ""))


class _FakeResponse:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text
        self.headers: Dict[str, Any] = {}


# HTML 结构一致的"用户资料页"(模拟 IDOR); 长度需 >100 字符以通过防误报门槛
_USER_PAGE = (
    '<html><head><title>User Profile</title></head><body>'
    '<div id="profile"><h1>User Profile</h1><p>Name: Alice</p><p>Email: alice@example.com</p>'
    '<p>Phone: +86-13800000000</p><p>Address: Beijing</p></div>'
    '<div id="footer">copyright</div></body></html>'
)
_FORBIDDEN = '<html><head><title>403</title></head><body><h1>403 Forbidden</h1><p>Access Denied</p></body></html>'


def _make_idor() -> Any:
    from wvs.modules.idor.detector import IDORDetector

    config = ConfigManager()
    module = IDORDetector(config)
    module.enabled = True
    return module


def test_idor_get_info() -> None:
    from wvs.modules.idor.detector import IDORDetector

    info = IDORDetector.get_info()
    assert info.name == "idor"
    assert info.category == "lite"
    assert info.enabled_by_default is False


def test_idor_object_replacement_detected() -> None:
    """替换 ID 参数后两个不同值均返回 200 且结构一致 → 判定 IDOR。"""
    module = _make_idor()
    session = _FakeSession(
        {
            "http://app.test/profile.php": {"status_code": 200, "text": _USER_PAGE},
            "http://app.test/profile.php?id=1": {"status_code": 200, "text": _USER_PAGE},
            "http://app.test/profile.php?id=0": {"status_code": 200, "text": _USER_PAGE},
            "http://app.test/profile.php?id=101": {"status_code": 200, "text": _USER_PAGE},
        }
    )
    module._active_session = session
    target = ScanTarget(url="http://app.test/profile.php?id=1", params={"id": "1"})

    async def _run() -> List[Vulnerability]:
        return await module._scan_impl(target)

    vulns = asyncio.run(_run())
    assert len(vulns) >= 1
    assert vulns[0].type.value == "broken_access" or "idor" in vulns[0].title.lower()


def test_idor_skips_public_path() -> None:
    module = _make_idor()
    session = _FakeSession({})
    module._active_session = session
    target = ScanTarget(url="http://app.test/login?id=1", params={"id": "1"})

    async def _run() -> List[Vulnerability]:
        return await module._scan_impl(target)

    vulns = asyncio.run(_run())
    assert vulns == []


def test_idor_no_403_no_false_positive() -> None:
    """替换值返回 403 → 不应判定 IDOR。"""
    module = _make_idor()
    session = _FakeSession(
        {
            "http://app.test/item": {"status_code": 200, "text": _USER_PAGE},
            "http://app.test/item?id=2": {"status_code": 200, "text": _USER_PAGE},
            "http://app.test/item?id=1": {"status_code": 403, "text": _FORBIDDEN},
            "http://app.test/item?id=102": {"status_code": 403, "text": _FORBIDDEN},
        }
    )
    module._active_session = session
    target = ScanTarget(url="http://app.test/item?id=2", params={"id": "2"})

    async def _run() -> List[Vulnerability]:
        return await module._scan_impl(target)

    vulns = asyncio.run(_run())
    assert vulns == []


def test_authbypass_get_info() -> None:
    from wvs.modules.authbypass.detector import AuthBypassDetector

    info = AuthBypassDetector.get_info()
    assert info.name == "authbypass"
    assert info.category == "lite"
    assert info.enabled_by_default is False


def test_authbypass_header_removal_detected() -> None:
    """移除认证头后仍 200 且结构一致 → 判定认证绕过。"""
    from wvs.modules.authbypass.detector import AuthBypassDetector

    config = ConfigManager()
    module = AuthBypassDetector(config)
    module.enabled = True

    page = (
        '<html><head><title>Admin Dashboard</title></head><body>'
        '<div id="dash"><h1>Admin Dashboard</h1><table>'
        '<tr><th>User</th><th>Role</th></tr><tr><td>alice</td><td>admin</td></tr>'
        '<tr><td>bob</td><td>user</td></tr></table></div>'
        '<div id="footer">internal tool</div></body></html>'
    )
    session = _FakeSession({"http://app.test/dashboard": {"status_code": 200, "text": page}})
    module._active_session = session
    target = ScanTarget(
        url="http://app.test/dashboard",
        headers={"Authorization": "Bearer faketoken123"},
    )

    async def _run() -> List[Vulnerability]:
        return await module._scan_impl(target)

    vulns = asyncio.run(_run())
    assert len(vulns) >= 1
    assert "auth" in vulns[0].title.lower() or "bypass" in vulns[0].title.lower()


def test_authbypass_skips_login_redirect() -> None:
    """移除认证头后重定向到登录页 → 不应判定。"""
    from wvs.modules.authbypass.detector import AuthBypassDetector

    config = ConfigManager()
    module = AuthBypassDetector(config)
    module.enabled = True

    login_page = """<html><head><title>Login</title></head><body><form>username password</form></body></html>"""
    session = _FakeSession(
        {
            "http://app.test/dashboard": {"status_code": 200, "text": """<html><body>Dashboard</body></html>"""},
            "__default__": {"status_code": 200, "text": login_page},
        }
    )
    module._active_session = session
    target = ScanTarget(
        url="http://app.test/dashboard",
        headers={"Authorization": "Bearer faketoken123"},
    )

    async def _run() -> List[Vulnerability]:
        return await module._scan_impl(target)

    vulns = asyncio.run(_run())
    assert vulns == []


def test_module_registered_in_factory() -> None:
    """新模块应出现在 ModuleFactory 注册表中。"""
    import wvs.modules  # noqa: F401  # 触发注册
    from wvs.modules.base import ModuleFactory

    names = ModuleFactory.list_modules()
    assert "idor" in names
    assert "authbypass" in names
