#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WVS v19.2 — 外部工具集成模块

已集成工具：
- nuclei  : ProjectDiscovery 模板化漏洞扫描
- sqlmap  : 自动化 SQL 注入检测与利用
- ffuf    : 目录/文件爆破与模糊测试
- wappalyzer : 技术栈指纹识别
"""
from .nuclei_integration import NucleiIntegration
from .sqlmap_integration import SqlmapIntegration
from .ffuf_integration import FfufIntegration
from .wappalyzer_integration import WappalyzerIntegration

__all__ = [
    'NucleiIntegration',
    'SqlmapIntegration',
    'FfufIntegration',
    'WappalyzerIntegration',
]
