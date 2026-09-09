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
    names = [s.name for s in scanner._orchestrator.stages]
    assert names == [
        "waf-detection",
        "lab-auth",
        "oa-detection",
        "resume",
        "crawl-detect",
        "dedup",
        "nuclei",
        "ai-verify",
        "checkpoint",
    ]


def test_prebuilt_stages_importable() -> None:
    from wvs.core.stages import AIVerifyStage, CheckpointStage, LabAuthStage, NucleiStage, OADetectionStage, ResumeStage

    scanner = _make_scanner()
    assert WAFDetectionStage(scanner).name == "waf-detection"
    assert LabAuthStage(scanner).name == "lab-auth"
    assert OADetectionStage(scanner).name == "oa-detection"
    assert ResumeStage(scanner).name == "resume"
    assert NucleiStage(scanner).name == "nuclei"
    assert AIVerifyStage(scanner).name == "ai-verify"
    assert CheckpointStage(scanner).name == "checkpoint"
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


def test_nuclei_stage_merges_findings_into_unique() -> None:
    """NucleiStage:外部引擎发现与主流程发现合并去重。"""
    from wvs.core.stages import NucleiStage
    from wvs.models import ScanTarget, Severity, Vulnerability, VulnerabilityType

    scanner = _make_scanner()
    main_v = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url="http://example.com/a?id=1",
        severity=Severity.HIGH,
        title="t1",
        description="d",
    )
    nuclei_v = Vulnerability(
        type=VulnerabilityType.INFO_DISCLOSURE,
        url="http://example.com/.git/config",
        severity=Severity.MEDIUM,
        title="t2",
        description="d",
    )

    async def fake_nuclei(target):
        return [nuclei_v]

    scanner._run_nuclei = fake_nuclei

    ctx = ScanContext(scanner)
    ctx.target = ScanTarget(url="http://example.com/")
    ctx.unique_vulns = [main_v]

    async def _run():
        await NucleiStage(scanner).run(ctx)

    asyncio.run(_run())
    assert {v.url for v in ctx.unique_vulns} == {"http://example.com/a?id=1", "http://example.com/.git/config"}


def test_nuclei_stage_skipped_when_disabled() -> None:
    from wvs.core.stages import NucleiStage
    from wvs.models import ScanTarget

    scanner = _make_scanner()
    scanner.config.set("nuclei.enabled", False)

    async def fake_nuclei(target):
        raise AssertionError("nuclei.enabled=False 时不应调用 _run_nuclei")

    scanner._run_nuclei = fake_nuclei

    ctx = ScanContext(scanner)
    ctx.target = ScanTarget(url="http://example.com/")

    async def _run():
        await NucleiStage(scanner).run(ctx)

    asyncio.run(_run())  # 不抛异常即通过


def test_ai_verify_stage_noop_when_disabled() -> None:
    """ai.verify 默认关:AIVerifyStage 不改写 unique_vulns。"""
    from wvs.core.stages import AIVerifyStage
    from wvs.models import ScanTarget, Severity, Vulnerability, VulnerabilityType

    scanner = _make_scanner()
    v = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url="http://example.com/?id=1",
        severity=Severity.HIGH,
        title="t",
        description="d",
    )
    ctx = ScanContext(scanner)
    ctx.target = ScanTarget(url="http://example.com/")
    ctx.unique_vulns = [v]

    async def _run():
        await AIVerifyStage(scanner).run(ctx)

    asyncio.run(_run())
    assert ctx.unique_vulns == [v]


def test_checkpoint_stage_saves_final_state() -> None:
    """CheckpointStage:最终 checkpoint 落盘(URL/去重后漏洞/定型端点表)。"""
    from wvs.core.stages import CheckpointStage
    from wvs.models import ScanTarget, Severity, Vulnerability, VulnerabilityType

    scanner = _make_scanner()
    v = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url="http://example.com/?id=1",
        severity=Severity.HIGH,
        title="t",
        description="d",
    )
    saved = {}

    def fake_save(url, vulns, endpoints):
        saved["url"] = url
        saved["vulns"] = list(vulns)
        saved["endpoints"] = list(endpoints)

    scanner._save_checkpoint = fake_save

    ctx = ScanContext(scanner)
    ctx.target = ScanTarget(url="http://example.com/")
    ctx.unique_vulns = [v]
    ep = ScanTarget(url="http://example.com/")  # 端点形态不限,透传即可
    ctx.endpoints = [ep]

    async def _run():
        await CheckpointStage(scanner).run(ctx)

    asyncio.run(_run())
    assert saved["url"] == "http://example.com/"
    assert saved["vulns"] == [v]
    assert saved["endpoints"] == [ep]


def test_scan_facade_runs_single_pipeline() -> None:
    """facade 端到端:scan() 单趟流水线 → 爬取+检测+Nuclei 合并+checkpoint 落盘+报告。"""
    from wvs.core.crawler import DiscoveredEndpoint
    from wvs.models import ScanTarget, Severity, Vulnerability, VulnerabilityType

    scanner = _make_scanner()
    ep = DiscoveredEndpoint(url="http://example.com/", method="GET", source_url="http://example.com/", source_depth=1)
    _stub_crawler(scanner, [ep])
    scanner.load_module("sqli")

    sqli_v = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url="http://example.com/a?id=1",
        severity=Severity.HIGH,
        title="t1",
        description="d",
    )

    async def fake_run_module(mod_name, target, batch, concurrency, global_sem):
        return [sqli_v]

    scanner._run_module_concurrent = fake_run_module

    nuclei_v = Vulnerability(
        type=VulnerabilityType.INFO_DISCLOSURE,
        url="http://example.com/.git/config",
        severity=Severity.HIGH,
        title="t2",
        description="d",
    )

    async def fake_nuclei(target):
        return [nuclei_v]

    scanner._run_nuclei = fake_nuclei

    saved = {}

    def fake_save(url, vulns, endpoints):
        saved["url"] = url
        saved["vulns"] = list(vulns)
        saved["endpoints"] = len(endpoints)

    scanner._save_checkpoint = fake_save

    result = asyncio.run(scanner.scan(ScanTarget(url="http://example.com/")))
    assert {v.url for v in result.vulnerabilities} == {
        "http://example.com/a?id=1",
        "http://example.com/.git/config",
    }
    assert result.endpoints_found == 1
    assert result.modules_run == 1
    assert saved["url"] == "http://example.com/"
    assert len(saved["vulns"]) == 2
    assert saved["endpoints"] == 1


def test_dedup_stage_empty() -> None:
    scanner = _make_scanner()
    stage = DedupStage(scanner)
    ctx = ScanContext(scanner)
    ctx.raw_vulns = []

    async def _run():
        await stage.run(ctx)

    asyncio.run(_run())
    assert ctx.unique_vulns == []
