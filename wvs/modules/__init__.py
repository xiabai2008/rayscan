"""
RayScan 检测模块

核心模块（专精深度检测）:
  - sqli : SQL 注入（error-based / union / boolean-blind / time-based / stacked / second-order）
  - xss  : 跨站脚本（reflected / stored / DOM-based / context-aware）

Lite 模块（轻量辅助，需 --all-modules 启用）位于 wvs.modules.lite 子包:
  - cmdi / lfi / rce / ssrf / xxe / sensitive / api / waf / jspathfinder / js_analysis
"""

from .api import APIDetector
from .cmdi import CMDInjectionDetector
from .js_analysis import JSAnalysisDetector
from .jspathfinder import JSPathfinderDetector
from .lfi import LFIDetector
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
    "JSAnalysisDetector",
    "JSPathfinderDetector",
    "LFIDetector",
    "OADetector",
    "RCEDetector",
    "SensitiveDetector",
    "SQLiDetector",
    "SSRFDetector",
    "SubdomainDetector",
    "WAFDetector",
    "WeakPasswordDetector",
    "WebShellDetector",
    "XSSDetector",
    "XXEDetector",
]


def register_all_modules():
    """Ensure all modules are registered with ModuleFactory.

    Only sqli and xss load by default.
    Use --all-modules to load cmdi/lfi/rce/ssrf/xxe/sensitive/api/waf/jspathfinder.
    """
    pass
