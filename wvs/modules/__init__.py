"""
RayScan 检测模块

核心模块（专精深度检测）:
  - sqli : SQL 注入（error-based / union / boolean-blind / time-based / stacked / second-order）
  - xss  : 跨站脚本（reflected / stored / DOM-based / context-aware）

Lite 模块（轻量辅助，需 --all-modules 启用，category="lite"）为扁平子包:
  - cmdi / lfi / rce / ssrf / xxe / sensitive / api / waf / jspathfinder / js_analysis

模块加载（T2.1）: 每个 detector 文件在导入时通过 @register_module / register_module()
自动注册到 ModuleFactory；register_all_modules() 遍历导入全部 detector 触发注册，
使 ModuleFactory 注册表成为模块加载的唯一事实源。
"""

import logging

logger = logging.getLogger(__name__)

from .api import APIDetector
from .cmdi import CMDInjectionDetector
from .graphql import GraphQLDetector
from .js_analysis import JSAnalysisDetector
from .jspathfinder import JSPathfinderDetector
from .lfi import LFIDetector
from .mcp import MCPDetector
from .oa import OADetector
from .rce import RCEDetector
from .sensitive import SensitiveDetector
from .sqli import SQLiDetector
from .ssrf import SSRFDetector
from .subdomain import SubdomainDetector
from .waf import WAFDetector
from .weakpass import WeakPasswordDetector
from .webshell import WebShellDetector
from .xss import XSSDetector
from .xxe import XXEDetector

__all__ = [
    "APIDetector",
    "CMDInjectionDetector",
    "GraphQLDetector",
    "JSAnalysisDetector",
    "JSPathfinderDetector",
    "LFIDetector",
    "MCPDetector",
    "OADetector",
    "RCEDetector",
    "SQLiDetector",
    "SSRFDetector",
    "SensitiveDetector",
    "SubdomainDetector",
    "WAFDetector",
    "WeakPasswordDetector",
    "WebShellDetector",
    "XSSDetector",
    "XXEDetector",
]


# T2.1: every detector submodule. Importing this package already registers all
# of them (each detector file calls @register_module / register_module() at import
# time); the list below makes registration explicit and idempotent so that entry
# points can guarantee a fully populated ModuleFactory registry.
_ALL_DETECTOR_MODULES = [
    "api",
    "cmdi",
    "graphql",
    "js_analysis",
    "jspathfinder",
    "lfi",
    "mcp",
    "oa",
    "rce",
    "sensitive",
    "sqli",
    "ssrf",
    "subdomain",
    "waf",
    "weakpass",
    "webshell",
    "xss",
    "xxe",
]


def register_all_modules():
    """Ensure every detection module is registered with ModuleFactory.

    Importing ``wvs.modules`` already triggers registration of all detectors via
    their top-level ``@register_module`` decorator / ``register_module()`` call.
    This function re-imports each detector submodule to guarantee registration
    even if the package-level imports were later trimmed, making the
    ModuleFactory registry the single source of truth for module loading.
    """
    import importlib

    for name in _ALL_DETECTOR_MODULES:
        try:
            importlib.import_module(f"wvs.modules.{name}.detector")
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(f"[modules] 注册模块失败: {name}: {exc}")
