"""WVS v16.0 漏洞检测模块"""
from .sqli_v16 import SQLiScannerV16, WAFBypassScanner
from .xss_v16 import XSSScannerV16, MutationXSSScanner
from .crawler_v16 import CrawlerV16, AuthKeeper
from .report_v16 import ReportGeneratorV16, Vulnerability

__all__ = [
    "SQLiScannerV16",
    "WAFBypassScanner",
    "XSSScannerV16",
    "MutationXSSScanner",
    "CrawlerV16",
    "AuthKeeper",
    "ReportGeneratorV16",
    "Vulnerability",
]
