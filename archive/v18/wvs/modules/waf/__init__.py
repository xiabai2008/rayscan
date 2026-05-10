"""WAF 模块

检测和绕过 Web Application Firewall。
"""
from .waf_detector import WAFDetector, WAFResult, detect_waf
from .bypass_payloads import BYPASS_PAYLOADS, get_bypass_payloads, TAMPER_SCRIPTS

__all__ = [
    "WAFDetector",
    "WAFResult", 
    "detect_waf",
    "BYPASS_PAYLOADS",
    "get_bypass_payloads",
    "TAMPER_SCRIPTS"
]
