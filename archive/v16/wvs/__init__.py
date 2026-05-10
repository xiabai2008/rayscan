"""WVS v16.0 - Web Vulnerability Scanner"""
__version__ = "16.0.0"
__author__ = "Security Team"
__release_date__ = "2026-04-17"

# v16.0 新特性
FEATURES_V16 = [
    "多阶段 SQL 注入验证（错误型 -> UNION -> 布尔盲注 -> 时间盲注）",
    "上下文感知 XSS 检测（自动选择最佳 payload）",
    "智能爬虫（表单识别、API 发现、SPA 支持）",
    "WAF 规避技术",
    "数据库指纹识别",
    "CSP 检测和绕过建议",
    "时间盲注优化（多次验证减少误报）",
    "突变 XSS（mXSS）检测",
    "认证态保持",
    "云元数据 SSRF 检测",
    "可视化报告（交互式 HTML、图表、多格式导出）",
    "增强 CLI（彩色输出、进度条、实时反馈）",
    "Web UI（FastAPI + WebSocket 实时推送）",
]

# 模块导出
from .vuln.sqli_v16 import SQLiScannerV16
from .vuln.xss_v16 import XSSScannerV16, MutationXSSScanner
from .vuln.crawler_v16 import CrawlerV16, AuthKeeper
from .vuln.report_v16 import ReportGeneratorV16, Vulnerability

__all__ = [
    "SQLiScannerV16",
    "XSSScannerV16",
    "MutationXSSScanner",
    "CrawlerV16",
    "AuthKeeper",
    "ReportGeneratorV16",
    "Vulnerability",
]
