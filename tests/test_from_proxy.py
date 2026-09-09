"""v2.3 T3.1 passive→active 联动测试。

覆盖:
- ProxyCaptureQueue 去重语义(参数值变化合并为同一参数面,参数名变化视为新端点)
- 队列落盘/恢复(schema 校验)
- filter_for_target 域名过滤(与代理 --target 同语义:子域匹配)
- PassiveProxy 捕获入队(目标域过滤延续、第三方域不入队)
- _scan_proxy_queue 定向主动验证(仅扫队列端点、来源标注、结果去重)
- _apply_gentle_rate_cap(gentle 预设上限,更低用户速率优先)
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import httpx
import pytest

from wvs.cli import _apply_gentle_rate_cap, _queue_endpoint_to_target, _scan_proxy_queue
from wvs.config import ConfigManager
from wvs.core.crawler import DiscoveredEndpoint
from wvs.core.passive import ProxyCaptureQueue
from wvs.core.passive.proxy import PassiveProxy
from wvs.models import ScanResult, ScanTarget, Severity, Vulnerability, VulnerabilityType


def _ep(url: str, method: str = "GET", params: dict = None, ptypes: dict = None) -> DiscoveredEndpoint:
    ep = DiscoveredEndpoint(url=url.split("?")[0], method=method, source_url=url, is_api=True)
    ep.parameters = dict(params or {})
    ep.param_types = dict(ptypes or {})
    return ep


# ─────────────────────────────────────────────────────────────────
# 队列去重 / 序列化 / 域名过滤
# ─────────────────────────────────────────────────────────────────


def test_queue_dedup_by_param_face() -> None:
    """同参数面的不同参数值合并(首见值保留);参数名变化视为新端点。"""
    q = ProxyCaptureQueue()
    assert q.enqueue(_ep("http://x/user", params={"id": "1"}, ptypes={"id": "query"})) is True
    assert q.enqueue(_ep("http://x/user", params={"id": "2"}, ptypes={"id": "query"})) is False
    assert len(q) == 1
    assert q.endpoints[0].parameters == {"id": "1"}  # 首见值作为基线
    assert q.hits(q.endpoints[0]) == 2

    assert q.enqueue(_ep("http://x/user", params={"name": "a"}, ptypes={"name": "query"})) is True
    assert len(q) == 2

    # 方法不同 = 不同端点
    assert q.enqueue(_ep("http://x/user", method="POST", params={"id": "1"}, ptypes={"id": "body"})) is True
    assert len(q) == 3


def test_queue_save_load_roundtrip(tmp_path) -> None:
    q = ProxyCaptureQueue(target_filter="example.com")
    q.enqueue(_ep("http://app.example.com/api/order", params={"uid": "7"}, ptypes={"uid": "query"}))
    q.enqueue(
        _ep(
            "http://app.example.com/login",
            method="POST",
            params={"u": "a", "p": "b"},
            ptypes={"u": "body", "p": "body"},
        )
    )
    path = q.save(tmp_path / "queue.json")

    loaded = ProxyCaptureQueue.load(path)
    assert len(loaded) == 2
    assert loaded.target_filter == "example.com"
    assert [e.url for e in loaded.endpoints] == [e.url for e in q.endpoints]
    assert loaded.endpoints[0].parameters == {"uid": "7"}
    assert loaded.endpoints[1].method == "POST"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "rayscan-proxy-queue-v1"
    assert data["count"] == 2


def test_queue_load_rejects_bad_schema(tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"endpoints": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        ProxyCaptureQueue.load(bad)


def test_filter_for_target_semantics() -> None:
    """联动扫描的域名过滤与代理 --target 同语义(主域+子域,排除第三方)。"""
    q = ProxyCaptureQueue()
    q.enqueue(_ep("http://app.example.com/a?id=1", params={"id": "1"}))
    q.enqueue(_ep("http://example.com/b?page=2", params={"page": "2"}))
    q.enqueue(_ep("http://evil.org/c", params={"x": "1"}))
    q.enqueue(_ep("http://192.168.1.5:8080/d", params={"y": "1"}))

    kept = q.filter_for_target("http://example.com")
    urls = [e.url for e in kept]
    assert any("app.example.com" in u for u in urls)
    assert any(u.startswith("http://example.com") for u in urls)
    assert not any("evil.org" in u for u in urls)
    assert not any("192.168.1.5" in u for u in urls)

    # IP 目标(本地靶场场景)
    kept_ip = q.filter_for_target("http://192.168.1.5:8080")
    assert [e.url for e in kept_ip] == ["http://192.168.1.5:8080/d"]


# ─────────────────────────────────────────────────────────────────
# 被动代理捕获入队
# ─────────────────────────────────────────────────────────────────


class _EchoTarget(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默
        pass

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_proxy_captures_into_queue() -> None:
    """代理捕获 → 入队去重;目标过滤延续(第三方域不入队)。"""
    target_srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoTarget)
    threading.Thread(target=target_srv.serve_forever, daemon=True).start()
    tport = target_srv.server_address[1]

    async def _run():
        proxy = PassiveProxy(target_filter="127.0.0.1")
        await proxy.start()
        try:
            proxy_port = proxy._server.sockets[0].getsockname()[1]
            base = f"http://127.0.0.1:{tport}"
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}", trust_env=False) as c:
                await c.get(f"{base}/user?id=1")
                await c.get(f"{base}/user?id=2")  # 同参数面 → 去重
                await c.get(f"{base}/search?q=abc")
                # 第三方:Host=localhost ≠ 127.0.0.1 → 目标过滤排除(不走外网)
                await c.get(f"http://localhost:{tport}/other")
            assert proxy.result.requests_captured == 4
            assert len(proxy.queue) == 2
            assert proxy.result.queued_endpoints == 2
            urls = [e.url for e in proxy.queue.endpoints]
            assert any(u.endswith("/user") for u in urls)
            assert not any("/other" in u for u in urls)  # 第三方域未入队
            # 透明转发仍然工作(浏览器拿到响应)
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}", trust_env=False) as c:
                r = await c.get(f"{base}/user?id=9")
                assert r.status_code == 200
        finally:
            await proxy.close()

    try:
        asyncio.run(_run())
    finally:
        target_srv.shutdown()


# ─────────────────────────────────────────────────────────────────
# 定向主动验证
# ─────────────────────────────────────────────────────────────────


class _StubModule:
    """桩模块:记录被扫描的目标,对标记端点返回固定漏洞。"""

    name = "stub"

    def __init__(self, vuln_urls: set):
        self.vuln_urls = vuln_urls
        self.scanned: list = []

    async def scan(self, target: ScanTarget):
        self.scanned.append(target.url)
        if any(target.url.startswith(u) for u in self.vuln_urls):
            return [
                Vulnerability(
                    type=VulnerabilityType.SQL_INJECTION,
                    title="stub finding",
                    url=target.url,
                    method="GET",
                    parameter="id",
                    parameter_type="query",
                    payload="' OR '1'='1",
                    evidence="stub evidence",
                    severity=Severity.HIGH,
                )
            ]
        return []


class _FakeSession:
    def get_stats(self):
        return {"total_requests": 42}


def test_scan_proxy_queue_only_scans_captured_endpoints() -> None:
    """联动验证只打队列端点(不爬取);漏洞来源标注 proxy_queue;同签名去重。"""
    mod = _StubModule(vuln_urls={"http://t/user"})
    scanner = SimpleNamespace(_modules={"stub": mod})
    q = ProxyCaptureQueue()
    q.enqueue(_ep("http://t/user", params={"id": "1"}))
    q.enqueue(_ep("http://t/user", params={"id": "2"}))  # 去重后不存在
    q.enqueue(_ep("http://t/search", params={"q": "x"}))

    queue_result = ScanResult(target=ScanTarget(url="http://t"))
    asyncio.run(_scan_proxy_queue(scanner, _FakeSession(), q.endpoints, "http://t", 4, queue_result))

    assert sorted(mod.scanned) == ["http://t/search", "http://t/user"]  # 去重后的参数面
    assert queue_result.endpoints_found == 2
    assert queue_result.modules_run == 1
    assert queue_result.requests_made == 42
    assert len(queue_result.vulnerabilities) == 1
    v = queue_result.vulnerabilities[0]
    assert v.module == "stub"
    assert v.context.get("source") == "proxy_queue"


def test_scan_proxy_queue_dedups_identical_findings() -> None:
    """两个端点产生相同(类型|URL|参数|载荷)签名时只保留一条。"""
    q = ProxyCaptureQueue()
    q.enqueue(_ep("http://t/a", params={"id": "1"}))
    q.enqueue(_ep("http://t/b", params={"id": "1"}))

    # 桩模块对不同 URL 生成不同 url 字段 → 两条都保留;改造桩让 url 固定为同一值来触发去重
    class _SameURLModule(_StubModule):
        async def scan(self, target: ScanTarget):
            vulns = await super().scan(target)
            for v in vulns:
                v.url = "http://t/a"
            return vulns

    same = _SameURLModule(vuln_urls={"http://t"})
    queue_result = ScanResult(target=ScanTarget(url="http://t"))
    asyncio.run(
        _scan_proxy_queue(
            SimpleNamespace(_modules={"stub": same}), _FakeSession(), q.endpoints, "http://t", 4, queue_result
        )
    )
    assert len(queue_result.vulnerabilities) == 1


def test_queue_endpoint_to_target_param_split() -> None:
    ep = _ep(
        "http://t/api",
        method="POST",
        params={"page": "1", "name": "n", "sid": "abc"},
        ptypes={"page": "query", "name": "json", "sid": "cookie"},
    )
    t = _queue_endpoint_to_target(ep)
    assert t.methods == ["POST"]
    assert t.params == {"page": "1"}
    assert t.data == {"name": "n"}
    assert t.cookies == {"sid": "abc"}
    assert t.param_types == {"page": "query", "name": "json", "sid": "cookie"}


def test_gentle_rate_cap_applies_and_respects_lower_rate(monkeypatch) -> None:
    """速率上限取 gentle 预设(3);用户更低速率优先;预设缺失回退当前上限。"""
    from wvs.profiles import ProfileManager

    real_load = ProfileManager.load_profile

    def fake_load(self, name):
        if name == "gentle":
            return {"params": {"rate": 3}}
        return real_load(self, name)

    monkeypatch.setattr(ProfileManager, "load_profile", fake_load)
    cfg = ConfigManager()
    cfg.set("rate", 10)
    assert _apply_gentle_rate_cap(cfg) == 3
    assert cfg.get("rate") == 3
    assert cfg.get("max_requests_per_second") == 3

    cfg = ConfigManager()
    cfg.set("rate", 1)  # 用户更低速率优先
    assert _apply_gentle_rate_cap(cfg) == 1

    def missing_load(self, name):
        return None

    monkeypatch.setattr(ProfileManager, "load_profile", missing_load)
    cfg = ConfigManager()
    cfg.set("rate", 10)
    assert _apply_gentle_rate_cap(cfg) == 10  # 回退当前默认上限
