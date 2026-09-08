"""T3 GraphQL 检测测试 — 2026-08-08.

覆盖：GraphQL 特征识别/introspection 判定、端点探测（证据验证才报）、
--js-render 配置接线。原则：仅端点可达不报；无 GraphQL 特征一律不报。
"""

import json
from types import SimpleNamespace

import pytest

from wvs.models import ScanTarget, Severity


class FakeSession:
    """鸭子类型 HTTPPool：GET 返回预设，POST 按 body 路由。"""

    def __init__(self, responses):
        self.responses = responses  # {path: {"get": (status,text,headers), "typename": text|None, "schema": text|None, "batched": text|None}}

    async def request(self, method, url, **kwargs):
        path = url.split("://", 1)[1]
        path = path[path.index("/") :] if "/" in path else "/"
        route = self.responses.get(path, {})

        if method.upper() == "GET":
            entry = route.get("get")
            if entry is None:
                return SimpleNamespace(status_code=404, text="", headers={})
            status, text, headers = entry
            return SimpleNamespace(status_code=status, text=text, headers=headers)

        body = kwargs.get("data") or ""
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        body = str(body)

        text = None
        if body.lstrip().startswith("["):
            # batched 请求体是 JSON 数组（注意其 query 字段也含 __typename，需优先匹配）
            text = route.get("batched")
        elif "__schema" in body:
            text = route.get("schema")
        elif "__typename" in body:
            text = route.get("typename")

        if text is None:
            return SimpleNamespace(status_code=404, text="", headers={})
        return SimpleNamespace(status_code=200, text=text, headers={"content-type": "application/json"})


def _make_detector(session):
    from wvs.modules.graphql.detector import GraphQLDetector

    det = GraphQLDetector()
    det._active_session = session
    return det


_TYPENAME_OK = '{"data": {"__typename": "Query"}}'
_SCHEMA_OK = '{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}'
_BATCHED_OK = '[{"data": {"__typename": "Query"}}, {"data": {"__typename": "Query"}}]'


# =====================================================================
# 特征/判定辅助
# =====================================================================


class TestGraphQLHelpers:
    def test_looks_like_graphql(self):
        from wvs.modules.graphql.detector import _looks_like_graphql

        assert _looks_like_graphql('{"data": {"__typename": "Query"}}') is True
        assert _looks_like_graphql("<title>GraphQL Playground</title>") is True
        assert _looks_like_graphql("<html><body>Welcome</body></html>") is False
        assert _looks_like_graphql("") is False

    def test_is_introspection_response(self):
        from wvs.modules.graphql.detector import _is_introspection_response

        assert _is_introspection_response('{"data": {"__schema": {"types": [{"name": "Q"}]}}}') is True
        assert _is_introspection_response('{"data": {"__typename": "Q"}}') is False
        assert _is_introspection_response('{"errors": [{"message": "introspection disabled"}]}') is False


# =====================================================================
# GraphQLDetector 端点探测
# =====================================================================


class TestGraphQLDetector:
    @pytest.mark.asyncio
    async def test_normal_site_no_vuln(self):
        session = FakeSession({"/": {"get": (200, "<html>home</html>", {"content-type": "text/html"})}})
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert vulns == []

    @pytest.mark.asyncio
    async def test_404_no_vuln(self):
        det = _make_detector(FakeSession({}))
        vulns = await det.scan(ScanTarget(url="http://t/"), session=FakeSession({}))
        assert vulns == []

    @pytest.mark.asyncio
    async def test_introspection_enabled(self):
        session = FakeSession(
            {
                "/graphql": {
                    "get": (200, "<html>api</html>", {"content-type": "text/html"}),
                    "typename": _TYPENAME_OK,
                    "schema": _SCHEMA_OK,
                }
            }
        )
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert len(vulns) == 1
        v = vulns[0]
        assert v.severity == Severity.MEDIUM
        assert "introspection" in (v.payload or "")
        assert v.evidence and "__schema" in v.evidence

    @pytest.mark.asyncio
    async def test_graphql_but_introspection_disabled_no_vuln(self):
        """确认是 GraphQL 但 introspection 返回错误 → 不报（禁用了就是安全的）"""
        session = FakeSession(
            {
                "/graphql": {
                    "get": (200, "<html>api</html>", {"content-type": "text/html"}),
                    "typename": _TYPENAME_OK,
                    "schema": '{"errors": [{"message": "GraphQL introspection is not allowed"}]}',
                }
            }
        )
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert vulns == []

    @pytest.mark.asyncio
    async def test_batched_query_supported(self):
        session = FakeSession(
            {
                "/graphql": {
                    "get": (200, "<html>api</html>", {"content-type": "text/html"}),
                    "typename": _TYPENAME_OK,
                    "batched": _BATCHED_OK,
                }
            }
        )
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert len(vulns) == 1
        v = vulns[0]
        assert v.severity == Severity.LOW
        assert "batched" in (v.payload or "")

    @pytest.mark.asyncio
    async def test_introspection_and_batched_both(self):
        session = FakeSession(
            {
                "/graphql": {
                    "get": (200, "<html>api</html>", {"content-type": "text/html"}),
                    "typename": _TYPENAME_OK,
                    "schema": _SCHEMA_OK,
                    "batched": _BATCHED_OK,
                }
            }
        )
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert len(vulns) == 2

    @pytest.mark.asyncio
    async def test_playground_get_page_still_checks(self):
        """GET 已含 GraphQL 特征（playground 页）→ 继续做 POST 检查"""
        session = FakeSession(
            {
                "/graphiql": {
                    "get": (200, "<html><title>GraphiQL</title></html>", {"content-type": "text/html"}),
                    "typename": _TYPENAME_OK,
                    "schema": _SCHEMA_OK,
                }
            }
        )
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/graphiql"), session=session)
        assert len(vulns) == 1

    @pytest.mark.asyncio
    async def test_non_graphql_endpoint_skipped(self):
        """具体端点路径不含 graphql 特征词 → 不探测（避免重测无关端点/路径爆炸）"""
        session = FakeSession({"/api": {"get": (200, "<html>api</html>", {"content-type": "text/html"})}})
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/api"), session=session)
        assert vulns == []

    def test_get_info_registered(self):
        from wvs.modules.base import ModuleFactory
        from wvs.modules.graphql.detector import GraphQLDetector

        info = GraphQLDetector.get_info()
        assert info.name == "graphql"
        assert info.category == "lite"
        assert "graphql" in ModuleFactory.list_modules()


# =====================================================================
# T3.2 --js-render 配置接线
# =====================================================================


class TestJsRenderWiring:
    def test_default_off(self):
        from wvs.config import ConfigManager
        from wvs.core.scanner import WAVScanner

        scanner = WAVScanner(ConfigManager())
        assert scanner.crawler._js_render is False

    def test_config_on(self):
        from wvs.config import ConfigManager
        from wvs.core.scanner import WAVScanner

        config = ConfigManager()
        config.set("crawler.js_render", True)
        scanner = WAVScanner(config)
        assert scanner.crawler._js_render is True

    def test_cli_flag_registered(self):
        from wvs.cli import build_parser

        args = build_parser().parse_args(["scan", "http://t/", "--js-render"])
        assert args.js_render is True
