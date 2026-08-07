"""Phase 1 亮点 B:被动扫描代理单元测试。

覆盖:
- Host 目标过滤(子域匹配/端口剥离)
- 端点构造(GET query / POST form / JSON body / cookie 参数)
- 代理生命周期(start/close)
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from wvs.core.passive.proxy import PassiveProxy


def _proxy(target_filter: str = None) -> PassiveProxy:
    return PassiveProxy(scan_callback=None, target_filter=target_filter)


def test_host_matches_exact() -> None:
    assert _proxy("example.com")._host_matches("example.com", "example.com") is True


def test_host_matches_subdomain() -> None:
    assert _proxy("example.com")._host_matches("api.example.com", "example.com") is True


def test_host_matches_port_stripped() -> None:
    assert _proxy("example.com")._host_matches("example.com:8080", "example.com") is True


def test_host_no_match() -> None:
    assert _proxy("example.com")._host_matches("evil.org", "example.com") is False


def test_build_endpoint_get_query() -> None:
    p = _proxy()
    parsed = urlparse("http://example.com/page.php?id=1&name=test")
    ep = p._build_endpoint("GET", "http://example.com/page.php?id=1&name=test", parsed, b"", {})
    assert ep.url == "http://example.com/page.php"
    assert ep.parameters == {"id": "1", "name": "test"}
    assert ep.param_types == {"id": "query", "name": "query"}


def test_build_endpoint_post_form() -> None:
    p = _proxy()
    parsed = urlparse("http://example.com/login")
    body = b"user=admin&pass=secret"
    headers = {"content-type": "application/x-www-form-urlencoded"}
    ep = p._build_endpoint("POST", "http://example.com/login", parsed, body, headers)
    assert ep.parameters == {"user": "admin", "pass": "secret"}
    assert ep.param_types == {"user": "body", "pass": "body"}


def test_build_endpoint_post_json() -> None:
    p = _proxy()
    parsed = urlparse("http://example.com/api/user")
    body = b'{"id": 1, "name": "alice", "admin": true}'
    headers = {"content-type": "application/json"}
    ep = p._build_endpoint("POST", "http://example.com/api/user", parsed, body, headers)
    assert ep.parameters.get("id") == "1"
    assert ep.parameters.get("name") == "alice"
    assert ep.param_types.get("name") == "body"


def test_build_endpoint_cookie() -> None:
    p = _proxy()
    parsed = urlparse("http://example.com/profile")
    headers = {"cookie": "session=abc123; theme=dark"}
    ep = p._build_endpoint("GET", "http://example.com/profile", parsed, b"", headers)
    assert ep.parameters.get("session") == "abc123"
    assert ep.parameters.get("theme") == "dark"
    assert ep.param_types.get("session") == "cookie"


def test_proxy_lifecycle() -> None:
    """代理应能启动与关闭。"""
    p = PassiveProxy(scan_callback=None, listen_host="127.0.0.1", listen_port=0)

    async def _run():
        await p.start()
        assert p._server is not None
        await p.close()
        assert p._server is None

    asyncio.run(_run())
