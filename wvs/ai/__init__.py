"""
RayScan AI 辅助模块（可选，默认关闭）。

提供：
  - LLMClient  : OpenAI 兼容 chat/completions 客户端（官方 API，复用 httpx）
  - AIVerifier : 对扫描候选漏洞做 LLM 二次复核（误报治理）
  - AI 报告摘要 : rayscan ai-report 子命令（见 report.py）

合规约定：
  - 无 LLM_API_KEY / 配置关闭时静默跳过，零行为变化
  - 所有 AI 调用需显式开启（--ai-verify / --ai-report），并打印数据将发送给第三方的告警
"""

from .client import LLMClient, extract_json, truncate
from .verifier import AIVerifier

__all__ = [
    "LLMClient",
    "AIVerifier",
    "extract_json",
    "truncate",
]
