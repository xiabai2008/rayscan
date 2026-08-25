"""
AI 误报验证器（T1.2）。

对扫描器产出的候选漏洞（medium 及以上）做 LLM 二次复核：
  - 把 type/url/parameter/payload/evidence/响应片段交给 LLM 判定是否真实漏洞
  - 确认（vulnerable=true 且 confidence>=0.8）→ tag ai_confirmed
  - 存疑（vulnerable=false 且 confidence<=0.3）→ 严重度降一级 + tag ai_disputed
  - 其余 → tag ai_reviewed（保持原状，不掩盖任何候选）

安全设计：
  - 无 key / 请求失败 / 输出不可解析 → 整批原样返回（宁可不复核，不误改结果）
  - 复核只降级不删除，避免 AI 误判掩盖真实漏洞
"""

import json
import logging
from typing import Any, Dict, List, Optional

from ..models import Confidence, Severity, Vulnerability
from .client import LLMClient, truncate

logger = logging.getLogger(__name__)

# 每批发送给 LLM 的漏洞数（控制 token 成本）
BATCH_SIZE = 5
# 发送字段截断上限
EVIDENCE_LIMIT = 500
RESPONSE_LIMIT = 800

_CONFIRM_TAG = "ai_confirmed"
_DISPUTED_TAG = "ai_disputed"
_REVIEWED_TAG = "ai_reviewed"

_CONFIRM_THRESHOLD = 0.8
_DISPUTE_THRESHOLD = 0.3

_SEVERITY_DOWNGRADE = {
    Severity.CRITICAL: Severity.HIGH,
    Severity.HIGH: Severity.MEDIUM,
    Severity.MEDIUM: Severity.LOW,
    Severity.LOW: Severity.INFO,
    Severity.INFO: Severity.INFO,
}


def _build_items(vulns: List[Vulnerability]) -> List[Dict[str, Any]]:
    """把漏洞转成发给 LLM 的紧凑条目。"""
    items = []
    for idx, v in enumerate(vulns):
        items.append(
            {
                "index": idx,
                "type": v.type.value if v.type else "unknown",
                "url": truncate(v.url, 200),
                "parameter": v.parameter or "",
                "payload": truncate(v.payload, 200),
                "evidence": truncate(v.evidence, EVIDENCE_LIMIT),
                "response_sample": truncate(v.http_response, RESPONSE_LIMIT),
            }
        )
    return items


_SYSTEM_PROMPT = (
    "你是一个严谨的 Web 漏洞扫描结果复核助手。"
    "下面是扫描器发现的候选漏洞及其证据，请逐条判断是否为真实可利用的漏洞。\n"
    "判定要点：\n"
    "1. 只依据给出的证据判断，不要臆测目标是否存在其他问题。\n"
    "2. 若证据显示 payload 在响应中被原样/半原样回显，且响应与业务正常页面明显不同（报错信息、堆栈、执行结果等），更可能是真实的。\n"
    "3. 若证据只是普通页面特征、固定文案、回显服务器（echo-server）、错误页模板或正常业务行为，判为 vulnerable=false。\n"
    "4. confidence 表示你对判定的把握程度（0~1）。\n"
    "输出必须严格是 JSON，不要包含其他文字：\n"
    '{"results":[{"index":0,"vulnerable":true,"confidence":0.9,"reason":"简短理由"}]}'
)


def _build_user_prompt(items: List[Dict[str, Any]]) -> str:
    return "候选漏洞列表（JSON）：\n" + json.dumps(items, ensure_ascii=False)


class AIVerifier:
    """候选漏洞 LLM 复核器。"""

    def __init__(self, config: Any = None, client: Optional[LLMClient] = None):
        self.config = config
        self.client = client or LLMClient(config)
        self.reviewed_count = 0
        self.confirmed_count = 0
        self.disputed_count = 0

    @property
    def available(self) -> bool:
        return self.client.available

    async def verify_batch(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """
        复核候选漏洞列表（medium 及以上），原地修改并返回。

        无 key / 无候选 / 请求失败 → 原样返回。
        """
        if not self.client.available or not vulns:
            return vulns

        candidates = [v for v in vulns if v.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        if not candidates:
            return vulns

        for start in range(0, len(candidates), BATCH_SIZE):
            batch = candidates[start : start + BATCH_SIZE]
            await self._verify_one_batch(batch)

        self.reviewed_count = sum(1 for v in vulns if _REVIEWED_TAG in (v.tags or []))
        return vulns

    async def _verify_one_batch(self, batch: List[Vulnerability]) -> None:
        """复核单批；任何异常都保持原状。"""
        items = _build_items(batch)
        try:
            parsed = await self.client.chat_json(
                [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": _build_user_prompt(items)},
                ],
                temperature=0.0,
            )
        except Exception as e:
            logger.debug(f"[AI] 复核批异常: {e}")
            return

        if not parsed:
            return
        results = parsed.get("results")
        if not isinstance(results, list):
            return

        by_index = {}
        for r in results:
            if isinstance(r, dict) and isinstance(r.get("index"), int):
                by_index[r["index"]] = r

        for pos, v in enumerate(batch):
            self._apply_verdict(v, by_index.get(pos))

    def _apply_verdict(self, v: Vulnerability, verdict: Optional[Dict[str, Any]]) -> None:
        """应用单条判定：确认/存疑/仅记录。verdict=None 视为"无法判定"。"""
        if not v.tags:
            v.tags = []
        if verdict is None:
            v.tags.append(_REVIEWED_TAG)
            self._record_context(v, None)
            return

        try:
            vulnerable = bool(verdict.get("vulnerable"))
            confidence = float(verdict.get("confidence") or 0.0)
        except (TypeError, ValueError):
            vulnerable = False
            confidence = 0.0

        if vulnerable and confidence >= _CONFIRM_THRESHOLD:
            v.tags.append(_CONFIRM_TAG)
            v.confidence = Confidence.HIGH if v.confidence == Confidence.LOW else v.confidence
            self.confirmed_count += 1
        elif not vulnerable and confidence <= _DISPUTE_THRESHOLD:
            v.tags.append(_DISPUTED_TAG)
            v.severity = _SEVERITY_DOWNGRADE.get(v.severity, v.severity)
            self.disputed_count += 1
        else:
            v.tags.append(_REVIEWED_TAG)

        self._record_context(v, verdict)

    @staticmethod
    def _record_context(v: Vulnerability, verdict: Optional[Dict[str, Any]]) -> None:
        ctx = dict(v.context or {})
        ctx["ai_reviewed"] = True
        if verdict is not None:
            ctx["ai_verdict"] = {
                "vulnerable": bool(verdict.get("vulnerable")),
                "confidence": verdict.get("confidence"),
                "reason": truncate(verdict.get("reason") or "", 300),
            }
        v.context = ctx
