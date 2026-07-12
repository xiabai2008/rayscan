"""
JavaScript Analysis Module.
"""

from .analyzer import SENSITIVE_PATTERNS, extract_endpoints_from_js, extract_sensitive_info
from .detector import JSAnalysisDetector

__all__ = [
    "SENSITIVE_PATTERNS",
    "extract_endpoints_from_js",
    "extract_sensitive_info",
    "JSAnalysisDetector",
]
