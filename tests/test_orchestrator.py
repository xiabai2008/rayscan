"""Phase 2 P2-1:扫描编排器单元测试。

覆盖:
- ScanStage 抽象接口可实例化
- ScanContext 读写共享数据
- ScanOrchestrator 顺序执行 + 单 stage 失败不阻断
- WAVScanner 默认装配编排器(stages 非空)
"""

from __future__ import annotations

import asyncio

from wvs.config import ConfigManager
from wvs.core.orchestrator import ScanContext, ScanOrchestrator, ScanStage
from wvs.core.stages import DedupStage, WAFDetectionStage


class _NoopStage(ScanStage):
    name = "noop"

    async def run(self, ctx: ScanContext) -> None:
        ctx.set("noop_called", True)


class _FailStage(ScanStage):
    name = "fail"

    async def run(self, ctx: ScanContext) -> None:
        raise RuntimeError("stage failure")


class _SetStage(ScanStage):
    name = "set"

    async def run(self, ctx: ScanContext) -> None:
        ctx.set("value", 42)


def test_scan_context_read_write() -> None:
    scanner = _make_scanner()
    ctx = ScanContext(scanner)
    ctx.set("key", "value")
    assert ctx.get("key") == "value"
    assert ctx.get("missing", "default") == "default"


def _make_scanner():
    config = ConfigManager()
    from wvs.core.scanner import WAVScanner

    return WAVScanner(config, None)


def test_orchestrator_runs_in_order() -> None:
    scanner = _make_scanner()
    calls: list = []

    class _OrderStage(ScanStage):
        name = "order"

        async def run(self, ctx: ScanContext) -> None:
            calls.append(ctx.get("value"))

    orch = ScanOrchestrator(scanner, stages=[_SetStage(scanner), _OrderStage(scanner)])
    ctx = ScanContext(scanner)

    async def _run():
        await orch.run(ctx)

    asyncio.run(_run())
    assert calls == [42]


def test_orchestrator_continues_after_stage_failure() -> None:
    scanner = _make_scanner()
    orch = ScanOrchestrator(scanner, stages=[_FailStage(scanner), _NoopStage(scanner)])
    ctx = ScanContext(scanner)

    async def _run():
        await orch.run(ctx)

    asyncio.run(_run())  # 不应抛异常
    assert ctx.get("noop_called") is True


def test_scanner_has_default_orchestrator() -> None:
    scanner = _make_scanner()
    assert scanner._orchestrator is not None
    assert len(scanner._orchestrator.stages) >= 4  # WAF/Lab/OA/Dedup


def test_prebuilt_stages_importable() -> None:
    from wvs.core.stages import LabAuthStage, OADetectionStage, ResumeStage

    scanner = _make_scanner()
    assert WAFDetectionStage(scanner).name == "waf-detection"
    assert LabAuthStage(scanner).name == "lab-auth"
    assert OADetectionStage(scanner).name == "oa-detection"
    assert ResumeStage(scanner).name == "resume"
    assert DedupStage(scanner).name == "dedup"


def test_resume_stage_merges_checkpoint_vulns_and_skips_modules() -> None:
    """ResumeStage:checkpoint 漏洞并入 ctx.raw_vulns,已完成模块被跳过。"""
    from wvs.core.stages import ResumeStage

    scanner = _make_scanner()
    scanner.load_module("sqli")
    scanner.load_module("xss")
    scanner._resume_checkpoint = {
        "vulnerabilities": [
            {
                "type": "sql_injection",
                "url": "http://example.com/?id=1",
                "severity": "high",
                "title": "t",
                "description": "d",
            }
        ],
        "modules_done": ["sqli"],
    }
    ctx = ScanContext(scanner)

    async def _run():
        await ResumeStage(scanner).run(ctx)

    asyncio.run(_run())
    assert len(ctx.raw_vulns) == 1
    assert "sqli" not in scanner._modules
    assert "xss" in scanner._modules


def test_resume_stage_noop_without_checkpoint() -> None:
    from wvs.core.stages import ResumeStage

    scanner = _make_scanner()
    ctx = ScanContext(scanner)

    async def _run():
        await ResumeStage(scanner).run(ctx)

    asyncio.run(_run())
    assert ctx.raw_vulns == []


def _stub_crawler(scanner, crawl_eps):
    """替换 scanner.crawler 为无网络 stub。"""
    from types import SimpleNamespace

    async def fake_crawl(url, session):
        return list(crawl_eps)

    async def fake_discover(eps, session):
        return list(eps)

    scanner.crawler = SimpleNamespace(
        crawl=fake_crawl,
        discover_params_batch=fake_discover,
        get_stats=lambda: {"pages_crawled": 1, "forms_found": 0},
        max_urls_per_run=0,
        max_depth=0,
    )
    scanner._try_save_checkpoint = lambda *a, **k: None
    scanner._timeout_remaining = lambda: 100.0


def test_crawl_detect_stage_streams_findings_into_ctx() -> None:
    from wvs.core.crawler import DiscoveredEndpoint
    from wvs.core.stages import CrawlDetectStage
    from wvs.models import ScanTarget, Severity, Vulnerability, VulnerabilityType

    scanner = _make_scanner()
    ep = DiscoveredEndpoint(url="http://example.com/", method="GET", source_url="http://example.com/", source_depth=1)
    _stub_crawler(scanner, [ep])
    scanner.load_module("sqli")

    found = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url="http://example.com/?id=1",
        severity=Severity.HIGH,
        title="t",
        description="d",
    )

    async def fake_run_module(mod_name, target, batch, concurrency, global_sem):
        assert batch == [ep]
        return [found]

    scanner._run_module_concurrent = fake_run_module

    ctx = ScanContext(scanner)
    ctx.target = ScanTarget(url="http://example.com/")

    async def _run():
        await CrawlDetectStage(scanner).run(ctx)

    asyncio.run(_run())
    assert len(ctx.endpoints) == 1
    assert ctx.raw_vulns == [found]
    assert scanner._stats["endpoints_discovered"] == 1


def test_crawl_detect_stage_empty_crawl_seeds_fallback_endpoint() -> None:
    """T0 兜底:crawler 零端点时至少测目标本身,流式检测不被整体跳过。"""
    from wvs.core.stages import CrawlDetectStage
    from wvs.models import ScanTarget

    scanner = _make_scanner()
    _stub_crawler(scanner, [])

    ctx = ScanContext(scanner)
    ctx.target = ScanTarget(url="http://example.com/")

    async def _run():
        await CrawlDetectStage(scanner).run(ctx)

    asyncio.run(_run())
    assert len(ctx.endpoints) == 1
    assert ctx.endpoints[0].url == "http://example.com/"


def test_dedup_stage_empty() -> None:
    scanner = _make_scanner()
    stage = DedupStage(scanner)
    ctx = ScanContext(scanner)
    ctx.raw_vulns = []

    async def _run():
        await stage.run(ctx)

    asyncio.run(_run())
    assert ctx.unique_vulns == []
