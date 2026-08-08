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
    from wvs.core.stages import LabAuthStage, OADetectionStage

    scanner = _make_scanner()
    assert WAFDetectionStage(scanner).name == "waf-detection"
    assert LabAuthStage(scanner).name == "lab-auth"
    assert OADetectionStage(scanner).name == "oa-detection"
    assert DedupStage(scanner).name == "dedup"


def test_dedup_stage_empty() -> None:
    scanner = _make_scanner()
    stage = DedupStage(scanner)
    ctx = ScanContext(scanner)
    ctx.raw_vulns = []

    async def _run():
        await stage.run(ctx)

    asyncio.run(_run())
    assert ctx.unique_vulns == []
