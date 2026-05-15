"""
WAF Detection Module
"""

from .detector import WAFDetector, WAFDetectionResult
from .bypass_payloads import BYPASS_PAYLOADS, get_bypass_payloads, TAMPER_SCRIPTS

__all__ = ["WAFDetector", "WAFDetectionResult", "BYPASS_PAYLOADS", "get_bypass_payloads", "TAMPER_SCRIPTS"]
