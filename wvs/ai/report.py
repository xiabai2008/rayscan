"""
AI 报告生成（T1.3）— rayscan ai-report 子命令。

读取既有 JSON 扫描报告，调用 LLM 生成自然语言 markdown 摘要：
  概述 → 关键发现（按严重度）→ 修复建议。
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .client import LLMClient, truncate

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "你是一名资深 Web 安全工程师，负责把扫描报告转写成给客户/开发团队的清晰摘要。"
    "输出格式为 Markdown，需包含：\n"
    "1. ## 扫描概述（目标、扫描时间、漏洞总数、按严重度分布）\n"
    "2. ## 关键发现（按严重度从高到低逐条：漏洞类型、URL、参数、影响、证据要点）\n"
    "3. ## 修复建议（按漏洞类型分组，给出可落地的修复措施）\n"
    "要求：专业、简洁、不夸大严重性；未提供的信息不要臆造。"
)


def _extract_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    vulns = report.get("vulnerabilities") or []
    findings = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        findings.append(
            {
                "type": v.get("type", "unknown"),
                "severity": v.get("severity", "info"),
                "title": truncate(v.get("title") or "", 200),
                "url": truncate(v.get("url") or "", 200),
                "parameter": v.get("parameter") or "",
                "evidence": truncate(v.get("evidence") or "", 400),
            }
        )
    return findings


def _build_user_prompt(report: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
    meta = {
        "target": report.get("target", {}).get("url", "") if isinstance(report.get("target"), dict) else "",
        "scan_time": report.get("scan_time", ""),
        "duration": report.get("duration", 0),
        "requests_made": report.get("requests_made", 0),
        "endpoints_found": report.get("endpoints_found", 0),
        "vulnerability_count": report.get("vulnerability_count", {}),
        "severity_count": report.get("severity_count", {}),
    }
    return (
        "扫描元数据（JSON）：\n"
        + json.dumps(meta, ensure_ascii=False)
        + "\n\n漏洞列表（JSON）：\n"
        + json.dumps(findings, ensure_ascii=False)
    )


async def generate_ai_summary(report: Dict[str, Any], client: Optional[LLMClient] = None) -> Optional[str]:
    """
    生成 AI 报告摘要（markdown）。

    Returns:
        markdown 字符串；无 key / 无漏洞 / 请求失败时返回 None。
    """
    client = client or LLMClient()
    if not client.available:
        return None

    findings = _extract_findings(report)
    if not findings:
        logger.info("[AI] 报告中无漏洞条目，跳过摘要生成")
        return None

    return await client.chat(
        [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(report, findings)},
        ],
        temperature=0.3,
        max_tokens=1500,
    )
