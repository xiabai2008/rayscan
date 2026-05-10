#!/usr/bin/env python3
"""
WVS v18.4 缓存系统功能测试

测试缓存系统的核心功能，确保与扫描器正确集成。
"""

import asyncio
import time
import json
import os
import sys
from dataclasses import dataclass
from typing import List

# 添加当前目录到路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 测试配置
TEST_TARGETS = [
    "http://test.example.com/path1",
    "http://test.example.com/path2?param=value",
    "http://test.example.com/path3#section",
    "http://test.example.com/path4?b=2&a=1",
]

def test_imports():
    """测试模块导入"""
    print("测试模块导入...")
    try:
        from cache_system import (
            ScanCache, TargetFingerprinter, CacheManager,
            ScanResultSerializer, get_global_cache_manager
        )
        print("[OK] 所有模块导入成功")
        return True
    except ImportError as e:
        print(f"[FAIL] 模块导入失败: {e}")
        return False

def test_scan_cache():
    """测试 ScanCache 类"""
    print("\n测试 ScanCache 类...")
    from cache_system import ScanCache, ScanResult, Vulnerability, URLInfo

    # 创建测试数据
    vuln = Vulnerability(
        type="SQL Injection",
        url="http://test.com/page.php",
        parameter="id",
        payload="' OR 1=1 --",
        severity="critical",
        confidence=0.95
    )

    result = ScanResult(
        urls=[URLInfo(url="http://test.com/page.php?id=1")],
        forms=[],
        vulnerabilities=[vuln],
        js_files=[],
        sensitive_paths=[],
        duration=1.5,
        total_requests=5
    )

    # 创建缓存
    cache = ScanCache(max_size=10, default_ttl=1)  # 1秒TTL

    # 测试设置和获取
    cache.set("test_key", result)
    cached = cache.get("test_key")
    assert cached is not None
    assert len(cached.vulnerabilities) == 1
    assert cached.vulnerabilities[0].type == "SQL Injection"
    print("[OK] 基本缓存设置/获取测试通过")

    # 测试TTL过期
    time.sleep(1.1)  # 等待过期
    expired = cache.get("test_key")
    assert expired is None
    print("[OK] TTL过期测试通过")

    # 测试LRU淘汰
    for i in range(15):  # 超过最大大小
        cache.set(f"key_{i}", result)

    assert len(cache) <= 10  # 不超过最大大小
    print("[OK] LRU淘汰测试通过")

    # 测试统计信息
    stats = cache.stats()
    assert 'size' in stats
    assert 'hit_rate' in stats
    print("[OK] 统计信息测试通过")

    cache.clear()
    print("[OK] ScanCache 所有测试通过")
    return True

def test_target_fingerprinter():
    """测试 TargetFingerprinter 类"""
    print("\n测试 TargetFingerprinter 类...")
    from cache_system import TargetFingerprinter

    fingerprinter = TargetFingerprinter(level="normal")

    # 测试相同URL不同参数顺序应产生相同指纹
    url1 = "http://example.com/path?a=1&b=2"
    url2 = "http://example.com/path?b=2&a=1"

    fp1 = fingerprinter.fingerprint(url1)
    fp2 = fingerprinter.fingerprint(url2)

    assert fp1 == fp2
    print("[OK] 查询参数顺序规范化测试通过")

    # 测试不同级别
    strict_fp = TargetFingerprinter(level="strict").fingerprint(url1)
    relaxed_fp = TargetFingerprinter(level="relaxed").fingerprint(url1)
    domain_fp = TargetFingerprinter(level="domain").fingerprint(url1)

    # 指纹应该不同
    assert strict_fp != relaxed_fp
    assert relaxed_fp != domain_fp
    print("[OK] 不同级别指纹测试通过")

    # 测试批量生成
    fingerprints = fingerprinter.batch_fingerprint(TEST_TARGETS)
    assert len(fingerprints) == len(TEST_TARGETS)
    print("[OK] 批量指纹生成测试通过")

    print("[OK] TargetFingerprinter 所有测试通过")
    return True

def test_cache_manager():
    """测试 CacheManager 类"""
    print("\n测试 CacheManager 类...")
    from cache_system import CacheManager, ScanResult, Vulnerability, URLInfo

    # 创建测试数据
    vuln = Vulnerability(
        type="XSS",
        url="http://test.com/search.php",
        parameter="q",
        payload="<script>alert(1)</script>",
        severity="high",
        confidence=0.9
    )

    result = ScanResult(
        urls=[URLInfo(url="http://test.com/search.php?q=test")],
        forms=[],
        vulnerabilities=[vuln],
        js_files=[],
        sensitive_paths=[],
        duration=2.0,
        total_requests=8
    )

    # 使用临时文件进行持久化测试
    temp_file = "./test_cache_temp.json"
    if os.path.exists(temp_file):
        os.remove(temp_file)

    # 创建管理器
    manager = CacheManager(persist_path=temp_file, default_max_size=50)

    # 测试获取缓存
    cache = manager.get_cache("test_cache")
    assert cache is not None
    print("[OK] 缓存获取测试通过")

    # 测试缓存扫描结果
    target = "http://test.com/search.php?q=test"
    fingerprint = manager.cache_scan_result(target, result, ttl=10)
    assert fingerprint is not None
    print("[OK] 扫描结果缓存测试通过")

    # 测试获取缓存的扫描结果
    cached = manager.get_cached_result(target)
    assert cached is not None
    assert len(cached.vulnerabilities) == 1
    print("[OK] 缓存结果获取测试通过")

    # 测试缓存命中检查
    has_cache = manager.has_cached_result(target)
    assert has_cache is True
    print("[OK] 缓存命中检查测试通过")

    # 测试持久化
    manager.save_to_disk()
    assert os.path.exists(temp_file)
    print("[OK] 持久化保存测试通过")

    # 测试从磁盘加载
    manager2 = CacheManager(persist_path=temp_file)
    cached2 = manager2.get_cached_result(target)
    assert cached2 is not None
    print("[OK] 持久化加载测试通过")

    # 测试统计信息
    stats = manager.stats_all()
    assert "test_cache" in stats
    print("[OK] 统计信息测试通过")

    # 清理
    manager.clear_cache()
    if os.path.exists(temp_file):
        os.remove(temp_file)

    print("[OK] CacheManager 所有测试通过")
    return True

def test_serialization():
    """测试序列化/反序列化"""
    print("\n测试序列化/反序列化...")
    from cache_system import ScanResultSerializer, ScanResult, Vulnerability, URLInfo

    serializer = ScanResultSerializer()

    # 创建测试数据
    vuln = Vulnerability(
        type="Command Injection",
        url="http://test.com/exec.php",
        parameter="cmd",
        payload="; ls -la",
        severity="critical",
        confidence=0.85,
        evidence="uid=0(root)",
        poc="http://test.com/exec.php?cmd=;ls -la"
    )

    result = ScanResult(
        urls=[
            URLInfo(
                url="http://test.com/exec.php?cmd=whoami",
                method="GET",
                params={"cmd": "whoami"},
                depth=0
            )
        ],
        forms=[{"url": "http://test.com/login.php", "method": "POST"}],
        vulnerabilities=[vuln],
        js_files=["http://test.com/js/main.js"],
        sensitive_paths=[{"url": "http://test.com/.env", "type": "Environment"}],
        duration=3.5,
        total_requests=12
    )

    # 测试字典转换
    result_dict = serializer.to_dict(result)
    assert isinstance(result_dict, dict)
    assert "vulnerabilities" in result_dict
    assert len(result_dict["vulnerabilities"]) == 1
    print("[OK] 字典转换测试通过")

    # 测试JSON转换
    json_str = serializer.to_json(result, indent=2)
    assert isinstance(json_str, str)
    assert "Command Injection" in json_str
    print("[OK] JSON转换测试通过")

    # 测试从JSON还原
    restored = serializer.from_json(json_str)
    assert len(restored.vulnerabilities) == 1
    assert restored.vulnerabilities[0].type == "Command Injection"
    print("[OK] JSON还原测试通过")

    # 测试数据完整性
    assert result.duration == restored.duration
    assert result.total_requests == restored.total_requests
    print("[OK] 数据完整性测试通过")

    print("[OK] 序列化/反序列化所有测试通过")
    return True

def test_concurrent_scanner_integration():
    """测试并发扫描器集成"""
    print("\n测试并发扫描器集成...")

    try:
        from concurrent_scanner import ConcurrentScanner

        # 测试配置
        config = {
            'max_workers': 2,
            'timeout_per_target': 10,
            'enable_validation': False,
            'enable_cache': True,
            'cache_ttl': 2,  # 2秒，便于测试
            'cache_persist_path': './test_scanner_cache.json'
        }

        scanner = ConcurrentScanner(config)

        # 验证缓存配置
        assert hasattr(scanner, 'enable_cache')
        assert scanner.enable_cache is True
        assert hasattr(scanner, 'cache_manager')
        assert scanner.cache_manager is not None
        print("[OK] 扫描器缓存配置测试通过")

        # 清理测试文件
        if os.path.exists('./test_scanner_cache.json'):
            os.remove('./test_scanner_cache.json')

        print("[OK] 并发扫描器集成测试通过")
        return True

    except ImportError as e:
        print(f"[FAIL] 无法导入 ConcurrentScanner: {e}")
        return False
    except Exception as e:
        print(f"[FAIL] 集成测试失败: {e}")
        return False

async def test_scan_with_cache():
    """测试带缓存的扫描流程"""
    print("\n测试带缓存的扫描流程...")

    try:
        from concurrent_scanner import ConcurrentScanner

        # 使用测试配置
        config = {
            'max_workers': 1,
            'timeout_per_target': 5,
            'enable_validation': False,
            'enable_cache': True,
            'cache_ttl': 5
        }

        scanner = ConcurrentScanner(config)

        # 模拟目标（不会真正扫描，因为使用模拟连接测试）
        test_targets = ["http://127.0.0.1:9999/test1", "http://127.0.0.1:9999/test2"]

        # 第一次扫描（应该缓存）
        print("  第一次扫描（应缓存结果）...")
        results1 = await scanner.scan_many(test_targets)
        assert len(results1) == 2
        print("  [OK] 第一次扫描完成")

        # 第二次扫描（应命中缓存）
        print("  第二次扫描（应命中缓存）...")
        scanner2 = ConcurrentScanner(config)  # 新实例，测试缓存持久性
        results2 = await scanner2.scan_many(test_targets)
        assert len(results2) == 2
        print("  [OK] 第二次扫描完成")

        # 注意：由于当前扫描器使用模拟连接测试，可能无法实际测试缓存命中
        # 但至少验证了集成不会导致错误

        print("[OK] 带缓存的扫描流程测试通过")
        return True

    except Exception as e:
        print(f"[FAIL] 扫描流程测试失败: {e}")
        return False

def cleanup():
    """清理测试文件"""
    test_files = [
        './test_cache_temp.json',
        './test_scanner_cache.json',
        './scan_cache.json',
        './global_cache.json',
        './example_cache.json',
        './temp_cache.json'
    ]

    for file in test_files:
        if os.path.exists(file):
            try:
                os.remove(file)
                print(f"清理文件: {file}")
            except:
                pass

async def run_all_tests():
    """运行所有测试"""
    print("=" * 60)
    print("WVS v18.4 缓存系统功能测试")
    print("=" * 60)

    all_passed = True

    # 运行测试
    if not test_imports():
        all_passed = False

    if not test_scan_cache():
        all_passed = False

    if not test_target_fingerprinter():
        all_passed = False

    if not test_cache_manager():
        all_passed = False

    if not test_serialization():
        all_passed = False

    if not test_concurrent_scanner_integration():
        all_passed = False

    # 注释掉实际扫描测试，避免网络依赖
    # if not await test_scan_with_cache():
    #     all_passed = False

    # 清理
    cleanup()

    print("\n" + "=" * 60)
    if all_passed:
        print("[OK] 所有测试通过!")
    else:
        print("[FAIL] 部分测试失败")
    print("=" * 60)

    return all_passed

if __name__ == "__main__":
    # Windows兼容性
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # 运行测试
    success = asyncio.run(run_all_tests())

    # 返回退出码
    sys.exit(0 if success else 1)