"""
RayScan 检测模块

核心模块（专精深度检测）:
  - sqli : SQL 注入（error-based / union / boolean-blind / time-based / stacked / second-order）
  - xss  : 跨站脚本（reflected / stored / DOM-based / context-aware）

Lite 模块（轻量辅助，需 --all-modules 启用）位于 wvs.modules.lite 子包:
  - cmdi / lfi / rce / ssrf / xxe / sensitive / api / waf / jspathfinder / js_analysis
"""

from .oa import OADetector
from .sqli import SQLiDetector
from .subdomain import SubdomainDetector
from .weakpass import WeakPasswordDetector
from .webshell import WebShellDetector
from .xss import XSSDetector

__all__ = [
    "OADetector",
    "SQLiDetector",
    "SubdomainDetector",
    "WeakPasswordDetector",
    "WebShellDetector",
    "XSSDetector",
]


def register_all_modules():
    """Ensure all modules are registered with ModuleFactory.

    Only sqli and xss load by default.
    Use --all-modules to load cmdi/lfi/rce/ssrf/xxe/sensitive/api/waf/jspathfinder.
    """
    pass
