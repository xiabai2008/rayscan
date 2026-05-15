"""
RayScan Detection Modules

Registered modules:
- sqli      : SQL injection (error-based / union / boolean-blind / time-based)
- cmdi      : Command injection (echo / time-based / OOB)
- xss       : Cross-site scripting (reflected / stored / DOM-based)
- lfi       : Local file inclusion
- rce       : Remote code execution (code injection / deserialization)
- api       : API security (auth bypass / JWT / CORS)
- ssrf      : Server-side request forgery
- xxe       : XML external entity injection
- sensitive : Sensitive information disclosure (backup files / config / source code)
- waf       : WAF detection and bypass
- jspathfinder : JavaScript endpoint discovery
"""

from .sqli import SQLiDetector
from .cmdi import CMDInjectionDetector
from .xss import XSSDetector
from .lfi import LFIDetector
from .rce import RCEDetector
from .api import APIDetector
from .ssrf import SSRFDetector
from .xxe import XXEDetector
from .sensitive import SensitiveDetector
from .waf import WAFDetector
from .jspathfinder import JSPathfinderDetector

__all__ = [
    "SQLiDetector",
    "CMDInjectionDetector",
    "XSSDetector",
    "LFIDetector",
    "RCEDetector",
    "APIDetector",
    "SSRFDetector",
    "XXEDetector",
    "SensitiveDetector",
    "WAFDetector",
    "JSPathfinderDetector",
]


def register_all_modules():
    """Ensure all modules are registered with ModuleFactory.

    Modules register themselves via @register_module decorator at import time,
    so this function is a no-op — it exists for backward compatibility.
    """
    pass
