"""
RayScan Lite 模块 — 轻量辅助检测

这些模块不随 RayScan 核心加载，需要显式启用（--all-modules）。
可作为独立工具集成到破晓等工作流。

模块清单:
- cmdi        : 命令注入
- lfi         : 文件包含
- rce         : 远程代码执行
- ssrf        : 服务端请求伪造
- xxe         : XML 外部实体注入
- sensitive   : 敏感信息泄露
- api         : API 安全
- waf         : WAF 检测与绕过
- jspathfinder: JavaScript 端点发现
- js_analysis : JS 敏感信息分析
"""

import logging

logger = logging.getLogger(__name__)

from ..api import APIDetector
from ..cmdi import CMDInjectionDetector
from ..js_analysis import JSAnalysisDetector
from ..jspathfinder import JSPathfinderDetector
from ..lfi import LFIDetector
from ..rce import RCEDetector
from ..sensitive import SensitiveDetector
from ..ssrf import SSRFDetector
from ..waf import WAFDetector
from ..xxe import XXEDetector

__all__ = [
    "APIDetector",
    "CMDInjectionDetector",
    "JSAnalysisDetector",
    "JSPathfinderDetector",
    "LFIDetector",
    "RCEDetector",
    "SSRFDetector",
    "SensitiveDetector",
    "WAFDetector",
    "XXEDetector",
]


def register_lite_modules():
    """Ensure all Lite detection modules are registered with ModuleFactory.

    T2.1: the lite detectors live as flat subpackages under ``wvs.modules`` and are
    registered on import via ``@register_module``. Re-importing them here makes
    registration explicit and idempotent.
    """
    import importlib

    for name in (
        "api",
        "cmdi",
        "js_analysis",
        "jspathfinder",
        "lfi",
        "rce",
        "sensitive",
        "ssrf",
        "waf",
        "xxe",
    ):
        try:
            importlib.import_module(f"wvs.modules.{name}.detector")
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(f"[modules.lite] 注册模块失败: {name}: {exc}")
