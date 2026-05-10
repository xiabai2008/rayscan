#!/usr/bin/env python3
"""
WVS v18.4 缓存系统使用示例

展示缓存系统的各种用法，包括：
1. 基本缓存操作
2. 目标指纹生成
3. 缓存管理器使用
4. 与并发扫描器集成
"""

import asyncio
import time
import json
from dataclasses import dataclass
from typing import List

# 导入缓存系统
from cache_system import (
    ScanCache, TargetFingerprinter, CacheManager,
    ScanResultSerializer, get_global_cache_manager,
    cache_scan, get_cached_scan
)

# 导入扫描结果类型
try:
    from wvs.vuln.scanner_v18 import ScanResult, Vulnerability, URLInfo
except ImportError:
    # 回退定义
    @dataclass
    class URLInfo:
        url: str
        method: str = "GET"
        params: dict = None
        form_data: dict = None
        headers: dict = None
        depth: int = 0
        parent: str = ""

    @dataclass
    class Vulnerability:
        type: str
        url: str
        parameter: str
        payload: str
        severity: str
        confidence: float
        evidence: str = ""
        poc: str = ""

    @dataclass
    class ScanResult:
        urls: List[URLInfo]
        forms: List[dict]
        vulnerabilities: List[Vulnerability]
        js_files: List[str]
        sensitive_paths: List[dict]
        duration: float
        total_requests: int


def example_basic_cache():
    """示例1: 基本缓存操作"""
    print("=" * 60)
    print("示例1: 基本缓存操作")
    print("=" * 60)

    # 创建缓存实例
    cache = ScanCache(max_size=100, default_ttl=60)  # 最大100条目，默认TTL 60秒

    # 创建模拟扫描结果
    vuln = Vulnerability(
        type="SQL Injection",
        url="http://example.com/test.php",
        parameter="id",
        payload="' OR 1=1 --",
        severity="critical",
        confidence=0.95
    )

    result = ScanResult(
        urls=[URLInfo(url="http://example.com/test.php?id=1")],
        forms=[],
        vulnerabilities=[vuln],
        js_files=[],
        sensitive_paths=[],
        duration=2.5,
        total_requests=10
    )

    # 设置缓存
    cache.set("example_target", result, ttl=30)
    print(f"缓存设置: example_target, TTL: 30秒")

    # 获取缓存
    cached_result = cache.get("example_target")
    if cached_result:
        print(f"缓存命中: 发现 {len(cached_result.vulnerabilities)} 个漏洞")
        print(f"第一个漏洞: {cached_result.vulnerabilities[0].type}")

    # 检查缓存是否存在
    if cache.has("example_target"):
        print("缓存键存在")

    # 获取统计信息
    stats = cache.stats()
    print(f"缓存统计: 大小={stats['size']}, 命中率={stats['hit_rate']:.2%}")

    # 清理过期条目
    cache.cleanup()
    print("已清理过期条目")

    # 清空缓存
    cache.clear()
    print("缓存已清空")


def example_target_fingerprinter():
    """示例2: 目标指纹生成"""
    print("\n" + "=" * 60)
    print("示例2: 目标指纹生成")
    print("=" * 60)

    # 创建指纹生成器
    fingerprinter = TargetFingerprinter(level="normal", include_method=False)

    # 测试不同URL
    test_urls = [
        "http://example.com/path?q=test&sort=desc",
        "http://example.com/path?sort=desc&q=test",  # 参数顺序不同
        "http://example.com/path?q=test&sort=desc#section",
        "http://example.com/path?q=test",
        "http://example.com/another/path",
    ]

    for url in test_urls:
        fingerprint = fingerprinter.fingerprint(url)
        print(f"URL: {url[:50]:<50} 指纹: {fingerprint}")

    # 测试不同级别
    print("\n不同指纹级别:")
    for level in ["strict", "normal", "relaxed", "domain"]:
        fingerprinter = TargetFingerprinter(level=level)
        url = "http://example.com/admin/login.php?user=admin&pass=test#dashboard"
        fingerprint = fingerprinter.fingerprint(url)
        print(f"级别 {level:<10}: {fingerprint}")

    # 批量生成指纹
    print("\n批量生成指纹:")
    fingerprints = fingerprinter.batch_fingerprint(test_urls)
    for url, fp in fingerprints.items():
        print(f"  {url[:30]:<30} -> {fp}")


def example_cache_manager():
    """示例3: 缓存管理器"""
    print("\n" + "=" * 60)
    print("示例3: 缓存管理器")
    print("=" * 60)

    # 创建缓存管理器（带持久化）
    manager = CacheManager(persist_path="./example_cache.json", default_max_size=500)

    # 获取或创建命名缓存
    vuln_cache = manager.get_cache("vuln_scan", max_size=200, ttl=1800)
    config_cache = manager.get_cache("config", max_size=50, ttl=86400)

    # 创建模拟扫描结果
    vuln = Vulnerability(
        type="XSS",
        url="http://test.com/search.php",
        parameter="query",
        payload="<script>alert(1)</script>",
        severity="high",
        confidence=0.9
    )

    result = ScanResult(
        urls=[URLInfo(url="http://test.com/search.php?query=test")],
        forms=[],
        vulnerabilities=[vuln],
        js_files=[],
        sensitive_paths=[],
        duration=1.2,
        total_requests=5
    )

    # 缓存扫描结果
    target = "http://test.com/search.php?query=test"
    fingerprint = manager.cache_scan_result(target, result, cache_name="vuln_scan", ttl=600)
    print(f"已缓存扫描结果: {target}")
    print(f"生成指纹: {fingerprint}")

    # 获取缓存的扫描结果
    cached_result = manager.get_cached_result(target, cache_name="vuln_scan")
    if cached_result:
        print(f"从缓存读取结果: {len(cached_result.vulnerabilities)} 个漏洞")

    # 检查是否有缓存
    has_cache = manager.has_cached_result(target, cache_name="vuln_scan")
    print(f"是否有缓存: {has_cache}")

    # 获取缓存统计
    stats = manager.stats_all()
    print(f"\n缓存统计:")
    for name, stat in stats.items():
        print(f"  {name}: 大小={stat['size']}, 命中率={stat['hit_rate']:.2%}")

    # 保存到磁盘
    manager.save_to_disk()
    print(f"\n缓存已保存到磁盘: ./example_cache.json")

    # 清理过期条目
    manager.cleanup_all()
    print("已清理所有过期条目")

    # 使用上下文管理器自动保存
    print("\n使用上下文管理器:")
    with CacheManager(persist_path="./temp_cache.json") as mgr:
        cache = mgr.get_cache("temp")
        cache.set("key1", result, ttl=10)
        print("在上下文中设置了缓存，退出时将自动保存")

    # 清理临时文件
    import os
    if os.path.exists("./example_cache.json"):
        os.remove("./example_cache.json")
    if os.path.exists("./temp_cache.json"):
        os.remove("./temp_cache.json")


def example_global_cache():
    """示例4: 全局缓存管理器（单例模式）"""
    print("\n" + "=" * 60)
    print("示例4: 全局缓存管理器")
    print("=" * 60)

    # 获取全局缓存管理器（首次调用可指定持久化路径）
    manager = get_global_cache_manager(persist_path="./global_cache.json")

    # 使用全局函数缓存扫描结果
    vuln = Vulnerability(
        type="Command Injection",
        url="http://target.com/exec.php",
        parameter="cmd",
        payload="; ls -la",
        severity="critical",
        confidence=0.85
    )

    result = ScanResult(
        urls=[URLInfo(url="http://target.com/exec.php?cmd=whoami")],
        forms=[],
        vulnerabilities=[vuln],
        js_files=[],
        sensitive_paths=[],
        duration=3.1,
        total_requests=8
    )

    target = "http://target.com/exec.php?cmd=whoami"
    fingerprint = cache_scan(target, result, ttl=7200)
    print(f"使用全局函数缓存: {target}")
    print(f"生成指纹: {fingerprint}")

    # 使用全局函数获取缓存
    cached = get_cached_scan(target)
    if cached:
        print(f"使用全局函数读取缓存: {cached.vulnerabilities[0].type}")

    # 获取缓存统计
    stats = manager.stats_all()
    print(f"全局缓存统计: {len(stats)} 个缓存实例")

    # 清理
    manager.clear_cache()
    if os.path.exists("./global_cache.json"):
        os.remove("./global_cache.json")


def example_concurrent_scanner_integration():
    """示例5: 与并发扫描器集成"""
    print("\n" + "=" * 60)
    print("示例5: 与并发扫描器集成")
    print("=" * 60)

    try:
        from concurrent_scanner import ConcurrentScanner
        print("成功导入 ConcurrentScanner")

        # 配置并发扫描器，启用缓存
        config = {
            'max_workers': 2,
            'timeout_per_target': 30,
            'enable_validation': True,
            'enable_cache': True,  # 启用缓存
            'cache_ttl': 1800,     # 30分钟
            'cache_persist_path': './scanner_cache.json'
        }

        scanner = ConcurrentScanner(config)
        print(f"创建并发扫描器，缓存已启用: {scanner.enable_cache}")

        # 模拟扫描目标
        test_targets = [
            "http://192.168.1.100/dvwa/",
            "http://192.168.1.100/mutillidae/",
            "http://192.168.1.100/dvwa/vulnerabilities/sqli/",
        ]

        print(f"配置扫描 {len(test_targets)} 个目标")
        print("注意: 此示例需要实际目标才能运行完整扫描")

        # 展示缓存配置
        if scanner.enable_cache and scanner.cache_manager:
            print(f"缓存管理器: {type(scanner.cache_manager).__name__}")
            print(f"缓存TTL: {scanner.cache_ttl}秒")
            print(f"持久化路径: {scanner.cache_persist_path}")

            # 获取缓存统计
            stats = scanner.cache_manager.stats_all()
            print(f"初始缓存统计: {len(stats)} 个缓存实例")

    except ImportError as e:
        print(f"导入 ConcurrentScanner 失败: {e}")
        print("请确保在正确的目录下运行此示例")


def example_serialization():
    """示例6: 序列化/反序列化"""
    print("\n" + "=" * 60)
    print("示例6: 序列化/反序列化")
    print("=" * 60)

    serializer = ScanResultSerializer()

    # 创建扫描结果
    vuln = Vulnerability(
        type="LFI",
        url="http://victim.com/view.php",
        parameter="file",
        payload="../../../etc/passwd",
        severity="critical",
        confidence=0.95,
        evidence="root:x:0:0:root:/root:/bin/bash",
        poc="http://victim.com/view.php?file=../../../etc/passwd"
    )

    result = ScanResult(
        urls=[URLInfo(url="http://victim.com/view.php?file=index.html")],
        forms=[{"url": "http://victim.com/login.php", "method": "POST", "inputs": {"user": "admin"}}],
        vulnerabilities=[vuln],
        js_files=["http://victim.com/js/main.js"],
        sensitive_paths=[{"url": "http://victim.com/.env", "type": "Environment File", "severity": "critical"}],
        duration=4.2,
        total_requests=15
    )

    # 转换为字典
    result_dict = serializer.to_dict(result)
    print(f"转换为字典: 包含 {len(result_dict)} 个字段")
    print(f"漏洞列表: {len(result_dict['vulnerabilities'])} 个漏洞")

    # 转换为JSON
    json_str = serializer.to_json(result, indent=2)
    print(f"\n转换为JSON: {len(json_str)} 字符")
    print(f"JSON片段: {json_str[:200]}...")

    # 从JSON还原
    restored_result = serializer.from_json(json_str)
    print(f"\n从JSON还原: {len(restored_result.vulnerabilities)} 个漏洞")
    print(f"第一个漏洞类型: {restored_result.vulnerabilities[0].type}")

    # 验证数据完整性
    assert len(result.vulnerabilities) == len(restored_result.vulnerabilities)
    assert result.vulnerabilities[0].type == restored_result.vulnerabilities[0].type
    print("数据完整性验证通过")


async def main():
    """运行所有示例"""
    print("WVS v18.4 缓存系统使用示例")
    print("=" * 60)

    # 示例1: 基本缓存操作
    example_basic_cache()

    # 示例2: 目标指纹生成
    example_target_fingerprinter()

    # 示例3: 缓存管理器
    example_cache_manager()

    # 示例4: 全局缓存管理器
    example_global_cache()

    # 示例5: 与并发扫描器集成
    example_concurrent_scanner_integration()

    # 示例6: 序列化/反序列化
    example_serialization()

    print("\n" + "=" * 60)
    print("所有示例完成!")
    print("=" * 60)


if __name__ == "__main__":
    # Windows兼容性
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # 运行主函数
    asyncio.run(main())