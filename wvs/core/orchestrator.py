"""扫描编排层 (Phase 2: P2-1 拆 WAVScanner)。

将 WAVScanner 中的扫描流程阶段化为独立 Stage,每个 Stage 可独立实现/测试,
由 ScanOrchestrator 按顺序编排。WAVScanner.scan() 作为 facade 保持向后兼容。

Stage 划分(对齐扫描四阶段):
- WAFDetectionStage    : Step 0 WAF 检测并广播结果
- LabAuthStage         : Step 1.8 靶机识别与自动认证
- OADetectionStage     : Step 1.9 OA 系统指纹检测
- ResumeStage          : --resume 恢复(checkpoint 漏洞合并 + 已完成模块跳过)
- CrawlDetectStage     : Phase 1/2 爬取 + 流式检测(+ 端点定型 + JSPathfinder)
- DedupStage           : Phase 3 去重与置信度
- NucleiStage          : Phase 3.5 Nuclei 外部引擎扫描并合并
- AIVerifyStage        : Phase 3.6 AI 误报复核(默认关)
- CheckpointStage      : S2 最终 checkpoint 落盘

注:Stage 之间通过共享的 ScanContext(持有 config/session/scanner 引用)传递数据,
降低耦合;新增被动扫描 stage 只需实现 ScanStage 并注册。
报告统计/排序(result 填充)保留在 WAVScanner.scan() facade——该段异常需向上
传播(CLI 超时/异常抢救依赖),不走 stage 的失败不阻断语义。
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from .scanner import WAVScanner

logger = logging.getLogger(__name__)


class ScanStage(ABC):
    """扫描阶段抽象接口。"""

    name: str = "stage"

    def __init__(self, scanner: "WAVScanner"):
        self.scanner = scanner

    @abstractmethod
    async def run(self, ctx: "ScanContext") -> None:
        """执行本阶段。通过 ctx 读写共享状态。"""
        raise NotImplementedError


class ScanContext:
    """跨 Stage 的共享上下文。"""

    def __init__(self, scanner: "WAVScanner"):
        self.scanner = scanner
        self.config = scanner.config
        self.session = scanner.session
        self.target = None  # 当前扫描目标(ScanTarget)
        self.result = None  # 当前 ScanResult(NucleiStage 写入 template_selection 审计字段)
        self.endpoints: List[Any] = []  # 爬取发现的端点
        self.raw_vulns: List[Any] = []  # 去重前的原始漏洞
        self.unique_vulns: List[Any] = []  # 去重后的漏洞
        self.stage_failures: List[Dict[str, str]] = []  # 失败 stage 记录(可观测,见 ScanOrchestrator.run)
        self._data: Dict[str, Any] = {}  # 扩展数据

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value


class ScanOrchestrator:
    """按顺序执行一组 Stage。"""

    def __init__(self, scanner: "WAVScanner", stages: Optional[List[ScanStage]] = None):
        self.scanner = scanner
        self.stages: List[ScanStage] = stages or []

    def add_stage(self, stage: ScanStage) -> None:
        self.stages.append(stage)

    async def run(self, ctx: ScanContext) -> None:
        """顺序执行所有 stage;单个 stage 失败不阻断后续(告警 + 记录到 ctx.stage_failures)。"""
        for stage in self.stages:
            try:
                logger.debug("[Orchestrator] 执行 stage: %s", stage.name)
                await stage.run(ctx)
            except Exception as e:  # noqa: BLE001
                # 失败不阻断,但必须可观测:WARNING 带堆栈 + 结构化记录,
                # 由 facade 转入 result.errors / 统计,而非静默吞掉。
                logger.warning("[Orchestrator] stage %s 失败: %s", stage.name, e, exc_info=True)
                ctx.stage_failures.append({"stage": stage.name, "error": str(e)})

    def __repr__(self) -> str:
        return f"ScanOrchestrator(stages={[s.name for s in self.stages]})"
