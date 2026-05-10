"""WVS v18.0 - 集成模块

集成了多个安全工具：
- SQLMap: SQL 注入检测
- Nuclei: CVE 和配置漏洞扫描
- Playwright: JavaScript 渲染和 DOM XSS 检测
"""
from .sqlmap_integration import SQLMapIntegration, SQLMapVulnerability, quick_sqli_test
from .nuclei_integration import NucleiIntegration, NucleiVulnerability, quick_scan as nuclei_quick_scan
from .playwright_integration import (
    PlaywrightIntegration,
    EnhancedCrawlerWithJS,
    DOMXSSVulnerability,
    crawl_with_js,
    test_dom_xss
)

__all__ = [
    # SQLMap
    "SQLMapIntegration",
    "SQLMapVulnerability",
    "quick_sqli_test",
    
    # Nuclei
    "NucleiIntegration",
    "NucleiVulnerability",
    "nuclei_quick_scan",
    
    # Playwright
    "PlaywrightIntegration",
    "EnhancedCrawlerWithJS",
    "DOMXSSVulnerability",
    "crawl_with_js",
    "test_dom_xss",
]
