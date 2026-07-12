"""
RayScan 多引擎结果合并器

合并 AWVS / Nessus / Nuclei / sqlmap / RayScan 自有模块的扫描结果，
进行去重、置信度投票、严重程度统一。

策略:
  1. 按 (type, url, parameter) 三元组去重
  2. 多引擎同时报告的漏洞提升置信度
  3. 取最高严重程度
  4. 保留各引擎的原始证据
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import Vulnerability, Severity, Confidence, VulnerabilityType

logger = logging.getLogger("wvs.result_merger")

# 严重程度排序
SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# 置信度排序
CONFIDENCE_ORDER = {
    Confidence.CERTAIN: 0,
    Confidence.HIGH: 1,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 3,
}

# ── 引擎优先级（用于选择主报告来源）───────────────────────────
ENGINE_PRIORITY = {
    "awvs": 0,
    "nessus": 1,
    "nuclei": 2,
    "rayscan_sqli": 3,
    "rayscan_xss": 4,
    "sqlmap": 5,
    "rayscan": 6,
    "ffuf": 7,
    "other": 8,
}


@dataclass
class MergedVulnerability:
    """合并后的漏洞信息"""
    vuln: Vulnerability
    engines: List[str] = field(default_factory=list)  # 报告此漏洞的引擎
    original_vulns: List[Vulnerability] = field(default_factory=list)  # 各引擎原始数据

    @property
    def engine_count(self) -> int:
        return len(self.engines)

    @property
    def is_multi_engine(self) -> bool:
        return self.engine_count >= 2


class ResultMerger:
    """多引擎扫描结果合并器"""

    def __init__(self):
        self._stats = {
            "total_input": 0,
            "total_output": 0,
            "merged_count": 0,
            "by_engine": {},
        }

    def merge(
        self,
        engine_results: Dict[str, List[Vulnerability]],
    ) -> List[Vulnerability]:
        """
        合并多引擎扫描结果

        Args:
            engine_results: {引擎名: [Vulnerability列表]}
                示例: {"awvs": [...], "nessus": [...], "nuclei": [...], "rayscan": [...]}

        Returns:
            去重合并后的 Vulnerability 列表
        """
        all_vulns: List[Vulnerability] = []
        for engine, vulns in engine_results.items():
            for v in vulns:
                v.module = v.module or engine  # 确保标记来源
                all_vulns.append(v)
                self._stats["by_engine"][engine] = self._stats["by_engine"].get(engine, 0) + 1

        self._stats["total_input"] = len(all_vulns)
        logger.info(f"[ResultMerger] 输入: {len(all_vulns)} 个漏洞 (来自 {len(engine_results)} 个引擎)")

        # Step 1: 按签名分组
        groups: Dict[str, List[Vulnerability]] = defaultdict(list)
        for v in all_vulns:
            sig = self._make_signature(v)
            groups[sig].append(v)

        # Step 2: 每组合并
        merged: List[Vulnerability] = []
        for sig, group in groups.items():
            merged_vuln = self._merge_group(group)
            merged.append(merged_vuln)

        # Step 3: 按严重程度排序
        merged.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))

        self._stats["total_output"] = len(merged)
        self._stats["merged_count"] = len(all_vulns) - len(merged)
        logger.info(f"[ResultMerger] 输出: {len(merged)} 个漏洞 (合并去重 {self._stats['merged_count']} 个)")
        return merged

    @staticmethod
    def _make_signature(v: Vulnerability) -> str:
        """
        生成漏洞签名用于去重

        策略：(漏洞类型, URL, 参数名) 三元组
        """
        url_part = (v.url or "").rstrip("/").split("?")[0].split("#")[0]
        param_part = v.parameter or ""
        type_part = v.type.value if v.type else "unknown"
        return f"{type_part}|{url_part}|{param_part}"

    def _merge_group(self, group: List[Vulnerability]) -> Vulnerability:
        """合并一组相同签名的漏洞"""
        # 选取最佳代表
        best = self._select_best(group)

        # 收集所有引擎名
        engines_found: Set[str] = set()
        for v in group:
            eng = v.module or "unknown"
            engines_found.add(eng)

        # 提升置信度（多引擎确认）
        if len(engines_found) >= 2:
            if best.confidence == Confidence.LOW:
                best.confidence = Confidence.MEDIUM
            elif best.confidence == Confidence.MEDIUM:
                best.confidence = Confidence.HIGH

        # 记录多引擎信息
        best.tags = list(set(best.tags or []) | {"multi-engine" if len(engines_found) >= 2 else "single-engine"})
        best.context = best.context or {}
        best.context["merged_from_engines"] = sorted(engines_found)
        best.context["merged_count"] = len(group)

        return best

    @staticmethod
    def _select_best(group: List[Vulnerability]) -> Vulnerability:
        """
        从一组漏洞中选择最佳代表

        策略:
        - 最高严重程度
        - 最高置信度
        - 最高引擎优先级 (AWVS > Nessus > Nuclei > RayScan)
        """
        best = group[0]

        for v in group[1:]:
            # 比较严重程度
            if SEVERITY_ORDER.get(v.severity, 99) < SEVERITY_ORDER.get(best.severity, 99):
                best = v
                continue
            elif SEVERITY_ORDER.get(v.severity, 99) > SEVERITY_ORDER.get(best.severity, 99):
                continue

            # 同严重程度：比较置信度
            if CONFIDENCE_ORDER.get(v.confidence, 99) < CONFIDENCE_ORDER.get(best.confidence, 99):
                best = v
                continue
            elif CONFIDENCE_ORDER.get(v.confidence, 99) > CONFIDENCE_ORDER.get(best.confidence, 99):
                continue

            # 同严重+置信度：比较引擎优先级
            best_engine = best.module or "other"
            v_engine = v.module or "other"
            if ENGINE_PRIORITY.get(v_engine, 99) < ENGINE_PRIORITY.get(best_engine, 99):
                best = v

        return best

    def get_stats(self) -> Dict[str, Any]:
        """获取合并统计"""
        return {
            **self._stats,
            "reduction_ratio": f"{(1 - self._stats['total_output'] / max(self._stats['total_input'], 1)) * 100:.1f}%",
        }

    def print_summary(self, merged: List[Vulnerability]) -> str:
        """打印合并结果摘要"""
        lines = []
        lines.append("📊 多引擎结果合并摘要")
        lines.append("=" * 50)
        lines.append(f"  输入漏洞:    {self._stats['total_input']}")
        lines.append(f"  去重合并:    {self._stats['merged_count']}")
        lines.append(f"  输出漏洞:    {self._stats['total_output']}")
        lines.append(f"  缩减率:      {self._stats.get('reduction_ratio', '0%')}")
        lines.append("")
        lines.append(f"  按引擎来源:")
        for engine, count in sorted(self._stats.get("by_engine", {}).items()):
            lines.append(f"    {engine}: {count}")

        severity_count = defaultdict(int)
        for v in merged:
            severity_count[v.severity.value] += 1
        lines.append(f"\n  按严重程度:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if severity_count[sev] > 0:
                lines.append(f"    [{sev.upper():<8}] {severity_count[sev]}")

        multi = sum(1 for v in merged if "multi-engine" in (v.tags or []))
        lines.append(f"\n  多引擎确认: {multi}")
        return "\n".join(lines)


def merge_and_display(
    engine_results: Dict[str, List[Vulnerability]],
) -> List[Vulnerability]:
    """便捷函数：合并并显示结果"""
    merger = ResultMerger()
    result = merger.merge(engine_results)
    print(merger.print_summary(result))
    return result
