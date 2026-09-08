"""T2 MCP 测试 — 2026-08-08.

覆盖：MCP 特征识别/工具解析、MCPDetector 端点探测（证据验证才报）、
MCP Server 工具摘要/错误路径（无 mcp SDK 时跳过）、CLI mcp/update-pocs 子命令。
"""

import json
import sys
from types import SimpleNamespace

import pytest

from wvs.models import ScanResult, ScanTarget, Severity, Vulnerability, VulnerabilityType

# =====================================================================
# MCP 特征/工具解析
# =====================================================================


class TestMCPHelpers:
    def test_looks_like_mcp_jsonrpc(self):
        from wvs.modules.mcp.detector import _looks_like_mcp

        assert _looks_like_mcp('{"jsonrpc":"2.0","result":{}}', {}) is True

    def test_looks_like_mcp_server_info(self):
        from wvs.modules.mcp.detector import _looks_like_mcp

        assert _looks_like_mcp('{"serverInfo":{"name":"test"}}', {}) is True

    def test_looks_like_mcp_sse_header(self):
        from wvs.modules.mcp.detector import _looks_like_mcp

        assert _looks_like_mcp("event: message", {"content-type": "text/event-stream"}) is True

    def test_looks_like_mcp_case_insensitive(self):
        from wvs.modules.mcp.detector import _looks_like_mcp

        assert _looks_like_mcp("ServerInfo: X", {}) is True

    def test_normal_html_not_mcp(self):
        from wvs.modules.mcp.detector import _looks_like_mcp

        assert _looks_like_mcp("<html><body>Hello</body></html>", {"content-type": "text/html"}) is False

    def test_parse_tools(self):
        from wvs.modules.mcp.detector import _parse_tools

        payload = {"result": {"tools": [{"name": "get_weather"}, {"name": "run_shell"}, "not-a-dict"]}}
        assert _parse_tools(payload) == ["get_weather", "run_shell"]

    def test_parse_tools_empty(self):
        from wvs.modules.mcp.detector import _parse_tools

        assert _parse_tools({"result": {"tools": []}}) == []
        assert _parse_tools({"error": {"code": -32601}}) == []


# =====================================================================
# MCPDetector 端点探测
# =====================================================================


class FakeSession:
    """鸭子类型 HTTPPool：按 method/data 路由 GET/POST 响应。"""

    def __init__(self, responses):
        self.responses = (
            responses  # {path: {"get": (status, text, headers) | None, "tools": text | None, "init": text | None}}
        )

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

        # POST JSON-RPC
        data = kwargs.get("data") or ""
        try:
            body = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            body = {}
        rpc_method = body.get("method", "")

        text = None
        if rpc_method == "tools/list" and route.get("tools") is not None:
            text = route["tools"]
        elif rpc_method == "initialize" and route.get("init") is not None:
            text = route["init"]

        if text is None:
            return SimpleNamespace(status_code=404, text="", headers={})
        return SimpleNamespace(status_code=200, text=text, headers={"content-type": "application/json"})


def _make_detector(session):
    from wvs.modules.mcp.detector import MCPDetector

    det = MCPDetector()
    det._active_session = session
    return det


_TOOLS_RESP = json.dumps(
    {"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "get_weather"}, {"name": "run_shell"}]}}
)
_EMPTY_TOOLS_RESP = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}})
_INIT_RESP = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"protocolVersion": "2025-06-18", "serverInfo": {"name": "demo", "version": "1.0"}},
    }
)


class TestMCPDetector:
    @pytest.mark.asyncio
    async def test_normal_site_no_vuln(self):
        session = FakeSession({"/": {"get": (200, "<html><body>Welcome</body></html>", {"content-type": "text/html"})}})
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert vulns == []

    @pytest.mark.asyncio
    async def test_404_no_vuln(self):
        session = FakeSession({})
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert vulns == []

    @pytest.mark.asyncio
    async def test_tools_exposed_and_sensitive_tool(self):
        session = FakeSession(
            {
                "/mcp": {
                    "get": (200, "", {"content-type": "text/event-stream"}),
                    "tools": _TOOLS_RESP,
                    "init": _INIT_RESP,
                }
            }
        )
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert len(vulns) == 2
        # 工具列表泄露（MEDIUM）
        info_vuln = [v for v in vulns if "/tools/list" in (v.payload or "")]
        assert len(info_vuln) == 1
        assert info_vuln[0].severity == Severity.MEDIUM
        assert "run_shell" in (info_vuln[0].evidence or "")
        # 敏感工具未授权（HIGH）
        high_vuln = [v for v in vulns if "/tools/call" in (v.payload or "")]
        assert len(high_vuln) == 1
        assert high_vuln[0].severity == Severity.HIGH
        assert "run_shell" in (high_vuln[0].evidence or "")

    @pytest.mark.asyncio
    async def test_handshake_only_no_tools_no_vuln(self):
        """initialize 成功但 tools/list 无工具 → 不报（纯握手不是漏洞）"""
        session = FakeSession(
            {
                "/mcp": {
                    "get": (200, "", {"content-type": "text/event-stream"}),
                    "tools": _EMPTY_TOOLS_RESP,
                    "init": _INIT_RESP,
                }
            }
        )
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert vulns == []

    @pytest.mark.asyncio
    async def test_post_only_server_detected(self):
        """GET 普通页面，POST initialize 暴露 MCP 特征 + tools 泄露 → 检出"""
        session = FakeSession(
            {
                "/rpc": {
                    "get": (200, "<html>spa</html>", {"content-type": "text/html"}),
                    "tools": _TOOLS_RESP,
                    "init": _INIT_RESP,
                }
            }
        )
        det = _make_detector(session)
        vulns = await det.scan(ScanTarget(url="http://t/"), session=session)
        assert len(vulns) == 2

    def test_get_info_registered(self):
        from wvs.modules.base import ModuleFactory
        from wvs.modules.mcp.detector import MCPDetector

        info = MCPDetector.get_info()
        assert info.name == "mcp"
        assert info.category == "lite"
        assert "mcp" in ModuleFactory.list_modules()


# =====================================================================
# MCP Server（T2.1）
# =====================================================================


class TestMCPServer:
    def test_vuln_summary_truncates(self):
        from wvs.mcp_server import _vuln_summary

        v = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.HIGH,
            url="http://t/" + "x" * 500,
            parameter="id",
            evidence="e" * 1000,
        )
        result = ScanResult(target=ScanTarget(url="http://t"))
        result.vulnerabilities = [v]
        summary = _vuln_summary(result)
        assert len(summary) == 1
        assert len(summary[0]["url"]) <= 203
        assert len(summary[0]["evidence"]) <= 303

    @pytest.mark.asyncio
    async def test_run_scan_summary(self, monkeypatch):
        import wvs.mcp_server as mcp_mod

        class FakeScanner:
            _modules = {"sqli": object(), "xss": object()}
            _scan_max_time = 0

            def load_all_modules(self):
                return None

            def load_module(self, name):
                return True

            async def scan(self, target):
                result = ScanResult(target=target)
                result.vulnerabilities = [
                    Vulnerability(
                        type=VulnerabilityType.XSS, severity=Severity.MEDIUM, url=target.url, evidence="xss ev"
                    )
                ]
                result.duration = 2.5
                result.requests_made = 42
                result.endpoints_found = 7
                result.modules_run = 2
                return result

        class FakeSession:
            async def close(self):
                pass

        monkeypatch.setattr(mcp_mod, "_build_scanner", lambda: (None, FakeSession(), FakeScanner()))
        summary = await mcp_mod._run_scan("http://t/")
        assert summary["target"] == "http://t/"
        assert summary["duration_seconds"] == 2.5
        assert summary["requests_made"] == 42
        assert summary["modules_loaded"] == 2
        assert summary["vulnerability_count"]["cross_site_scripting"] == 1
        assert mcp_mod._LAST_RESULT is not None

    @pytest.mark.asyncio
    async def test_run_scan_error(self, monkeypatch):
        import wvs.mcp_server as mcp_mod

        class BoomScanner:
            _modules = {}

            async def scan(self, target):
                raise RuntimeError("boom")

        monkeypatch.setattr(mcp_mod, "_build_scanner", lambda: (None, SimpleNamespace(), BoomScanner()))
        summary = await mcp_mod._run_scan("http://t/")
        assert "error" in summary

    @pytest.mark.asyncio
    async def test_get_report_empty(self):
        pytest.importorskip("mcp")
        import wvs.mcp_server as mcp_mod

        mcp_mod._LAST_RESULT = None
        out = await mcp_mod.create_server().call_tool("get_report", {})
        text = out[0].text if isinstance(out, list) else str(out)
        assert "尚无扫描结果" in text

    def test_server_tools_registered(self):
        pytest.importorskip("mcp")
        from wvs.mcp_server import create_server

        server = create_server()
        tools = server._tool_manager._tools
        assert "scan" in tools
        assert "list_modules" in tools
        assert "get_report" in tools


# =====================================================================
# CLI 子命令
# =====================================================================


class TestMCPCLI:
    def test_cmd_mcp_missing_sdk_returns_1(self, monkeypatch):
        from wvs.cli import cmd_mcp

        monkeypatch.setitem(sys.modules, "wvs.mcp_server", None)
        assert cmd_mcp(SimpleNamespace(host="127.0.0.1", port=18000)) == 1

    def test_cmd_update_pocs_empty(self, monkeypatch):
        from wvs.cli import cmd_update_pocs

        class FakeManager:
            def __init__(self):
                self._templates = {}
                self._stats = {}

            def build_index(self, force=False):
                return 0

        monkeypatch.setattr("wvs.core.nuclei_template_manager.NucleiTemplateManager", FakeManager)
        assert cmd_update_pocs(SimpleNamespace(list_oa=False)) == 0
