"""
WVS 检测模块

已注册模块：
- sqli      : SQL 注入检测（error-based / union / boolean-blind / time-based）
- cmdi     : 命令注入检测（echo 回显 / time-based / OOB）
- xss       : XSS 检测（reflected / stored / DOM-based）
- lfi       : 本地文件包含检测
- rce       : 远程代码执行检测（code injection / deserialization）
- api       : API 安全检测（auth bypass / JWT / CORS）
- ssrf      : 服务端请求伪造检测
- xxe       : XML 外部实体注入检测
- sensitive : 敏感信息泄露检测（备份文件 / 配置 / 源码）
- waf       : WAF 检测与绕过
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
    """确保所有模块被注册到 ModuleFactory（触发 @register_module 装饰器）"""
    _ = [
        SQLiDetector,
        CMDInjectionDetector,
        XSSDetector,
        LFIDetector,
        RCEDetector,
        APIDetector,
        SSRFDetector,
        XXEDetector,
        SensitiveDetector,
        WAFDetector,
        JSPathfinderDetector,
    ]
