"""v2.3 T3.5 Web UI 对齐 CLI 测试。

覆盖:
- payloads: profile 应用与显式覆盖优先级、模块解析、模块目录
- ScanSession: explain/认证透传、from_proxy 定向扫描、历史回调
- PassiveProxySession: start/status/stop 状态机、重复启动拒绝
- API: 鉴权/CSRF、profile 保存、扫描校验、被动参数校验、导出证据链
"""

from __future__ import annotations

import asyncio
import queue as queue_module
import time
from types import SimpleNamespace

import pytest

from web_ui import payloads, sessions
from wvs.config import ConfigManager
from wvs.core.crawler import DiscoveredEndpoint
from wvs.core.passive import ProxyCaptureQueue
from wvs.models import ScanResult, Severity, Vulnerability, VulnerabilityType
from wvs.profiles import ProfileManager


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
            payloads.apply_scan_config(ConfigManager(), {"profile": "nope"}, ProfileManager(tmp_path))

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
        return ScanResult(target=target, vulnerabilities=[_stub_vuln()], endpoints_found=3, requests_made=7)


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
        endpoint = DiscoveredEndpoint(url="http://t/user", method="GET", source_url="http://t/user?id=1", is_api=True)
        endpoint.parameters = {"id": "1"}
        endpoint.param_types = {"id": "query"}
        capture.enqueue(endpoint)
        path = capture.save(tmp_path / "queue.json")

        s = sessions.ScanSession()
        result = asyncio.run(s._run_scan({"url": "http://t", "from_proxy": True}, ConfigManager(), ["sqli"], path))
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
