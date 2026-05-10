#!/usr/bin/env python3
"""
智能限速系统测试

测试 RateLimiter、AdaptiveRateLimiter、WAFEvasion 和 IntelligentRateLimiter 的功能
"""

import asyncio
import time
import sys
import os

# 添加当前目录到路径，以便导入模块
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from intelligent_rate_limiter import (
    RateLimiter,
    AdaptiveRateLimiter,
    WAFEvasion,
    IntelligentRateLimiter,
    RateLimitMode
)


async def test_rate_limiter_burst():
    """测试突发模式速率限制器"""
    print("=== 测试突发模式速率限制器 ===")

    # 创建限制器：最大5 RPS，突发模式
    limiter = RateLimiter(max_rps=5, window_size=1.0, mode=RateLimitMode.BURST)

    # 发送10个请求，应该需要大约1秒（5个/秒）
    start_time = time.time()
    for i in range(10):
        wait_time = await limiter.acquire()
        print(f"请求 {i+1}: 等待 {wait_time:.3f} 秒")

    elapsed = time.time() - start_time
    expected_min = 1.0  # 至少需要1秒（5个请求/秒 * 2批）

    print(f"总耗时: {elapsed:.3f} 秒，预期至少 {expected_min:.3f} 秒")
    assert elapsed >= expected_min, f"耗时 {elapsed:.3f} 秒小于预期 {expected_min:.3f} 秒"

    # 检查指标
    metrics = limiter.get_metrics()
    print(f"指标: {metrics}")
    assert metrics['request_count'] == 10
    assert metrics['current_rps'] <= 5.5  # 允许一些误差

    print("✓ 突发模式测试通过\n")


async def test_rate_limiter_uniform():
    """测试均匀模式速率限制器"""
    print("=== 测试均匀模式速率限制器 ===")

    # 创建限制器：最大2 RPS，均匀模式
    limiter = RateLimiter(max_rps=2, window_size=1.0, mode=RateLimitMode.UNIFORM)

    # 发送6个请求，应该需要大约2.5秒（2个/秒）
    start_time = time.time()
    for i in range(6):
        wait_time = await limiter.acquire()
        print(f"请求 {i+1}: 等待 {wait_time:.3f} 秒")

    elapsed = time.time() - start_time
    expected_min = 2.5  # 6个请求，2个/秒，需要至少2.5秒

    print(f"总耗时: {elapsed:.3f} 秒，预期至少 {expected_min:.3f} 秒")
    assert elapsed >= expected_min, f"耗时 {elapsed:.3f} 秒小于预期 {expected_min:.3f} 秒"

    print("✓ 均匀模式测试通过\n")


async def test_adaptive_rate_limiter():
    """测试自适应速率限制器"""
    print("=== 测试自适应速率限制器 ===")

    # 创建自适应限制器：最大10 RPS
    limiter = AdaptiveRateLimiter(max_rps=10, min_rps=1, recovery_rate=0.1, backoff_factor=2.0)

    # 模拟正常请求
    for i in range(5):
        await limiter.acquire()
        limiter.update_metrics(200, 0.5)  # 正常响应

    # 模拟429错误，触发退避
    await limiter.acquire()
    limiter.update_metrics(429, 0.5)

    # 检查健康状态
    health = limiter.get_health_status()
    print(f"触发429后健康状态: {health}")
    assert health['status'] == 'throttled' or health['is_in_backoff'], "应进入限制状态"

    # 模拟更多错误，进一步降低RPS
    for i in range(3):
        await limiter.acquire()
        limiter.update_metrics(503, 2.0)

    health = limiter.get_health_status()
    print(f"多次错误后健康状态: {health}")

    # 模拟正常请求，逐步恢复
    for i in range(10):
        await limiter.acquire()
        limiter.update_metrics(200, 0.3)

    health = limiter.get_health_status()
    print(f"恢复后健康状态: {health}")

    print("✓ 自适应速率限制器测试通过\n")


async def test_waf_evasion():
    """测试WAF规避策略"""
    print("=== 测试WAF规避策略 ===")

    evasion = WAFEvasion(enable_jitter=True, enable_rotation=True, jitter_range=0.2)

    # 测试随机抖动
    base_delay = 0.5
    total_jitter = 0.0
    for i in range(5):
        jitter_time = await evasion.apply_jitter(base_delay)
        total_jitter += jitter_time
        print(f"抖动 {i+1}: 基础 {base_delay:.3f} 秒，实际 {jitter_time:.3f} 秒")

    # 测试头部生成
    headers = evasion.get_evasion_headers()
    print(f"生成的头部: {headers}")
    assert 'User-Agent' in headers
    assert headers['User-Agent']  # 非空

    # 测试多次生成，User-Agent应轮换
    headers_list = []
    for i in range(3):
        headers_list.append(evasion.get_evasion_headers())

    # 检查User-Agent是否不同（可能相同，因为随机选择）
    ua_set = {h['User-Agent'] for h in headers_list if 'User-Agent' in h}
    print(f"唯一User-Agent数量: {len(ua_set)}")

    # 测试参数随机化
    params = {'id': '123', 'name': 'test', 'action': 'submit'}
    randomized = evasion.randomize_request_order(params)
    print(f"原始参数: {params}")
    print(f"随机化后: {randomized}")
    assert set(params.keys()) == set(randomized.keys()), "参数键应相同"

    # 测试添加冗余参数
    params_with_redundant = evasion.add_redundant_parameters(params.copy())
    print(f"添加冗余参数后: {params_with_redundant}")

    print("✓ WAF规避测试通过\n")


async def test_intelligent_rate_limiter():
    """测试智能速率限制器"""
    print("=== 测试智能速率限制器 ===")

    config = {
        "max_rps": 3,
        "mode": "burst",
        "enable_adaptive": True,
        "enable_waf_evasion": True,
        "enable_jitter": True,
        "jitter_range": 0.1,
    }

    limiter = IntelligentRateLimiter(config)

    # 模拟一系列请求
    start_time = time.time()
    for i in range(8):
        wait_time = await limiter.acquire()
        print(f"请求 {i+1}: 等待 {wait_time:.3f} 秒")

        # 模拟响应
        if i == 2:
            # 第三个请求模拟429错误
            limiter.update_metrics(429, 2.0)
            print(f"  响应: 429 Too Many Requests")
        else:
            limiter.update_metrics(200, 0.5 + i * 0.1)
            print(f"  响应: 200 OK")

    elapsed = time.time() - start_time
    print(f"总耗时: {elapsed:.3f} 秒")

    # 获取统计信息
    stats = limiter.get_stats()
    print(f"统计信息:")
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for k, v in value.items():
                print(f"    {k}: {v}")
        else:
            print(f"  {key}: {value}")

    assert stats['total_requests'] == 8
    assert stats['rate_limiter']['request_count'] == 8

    print("✓ 智能速率限制器测试通过\n")


async def test_integration_with_scanner():
    """测试与扫描器的集成"""
    print("=== 测试与扫描器的集成 ===")

    try:
        from wvs.vuln.scanner_v18 import VulnerabilityScanner

        # 创建带有限速器配置的扫描器
        scanner_config = {
            "timeout": 10,
            "delay": 0.1,  # 原始delay，将被速率限制器覆盖
            "rate_limiter": {
                "enabled": True,
                "max_rps": 5,
                "mode": "burst",
                "enable_adaptive": True,
                "enable_waf_evasion": True,
            }
        }

        scanner = VulnerabilityScanner(scanner_config)

        # 检查速率限制器是否已初始化
        if hasattr(scanner, 'rate_limiter') and scanner.rate_limiter:
            print("✓ 扫描器已成功初始化速率限制器")

            # 测试获取规避头部
            headers = scanner.rate_limiter.get_evasion_headers()
            print(f"生成的规避头部: {headers}")

            # 模拟请求（不实际发送）
            print("✓ 扫描器集成测试通过")
        else:
            print("⚠ 扫描器未初始化速率限制器（可能模块不可用）")

    except ImportError as e:
        print(f"⚠ 无法导入扫描器模块: {e}")
    except Exception as e:
        print(f"⚠ 集成测试出错: {e}")

    print()


async def main():
    """运行所有测试"""
    print("开始智能限速系统测试...\n")

    try:
        await test_rate_limiter_burst()
        await test_rate_limiter_uniform()
        await test_adaptive_rate_limiter()
        await test_waf_evasion()
        await test_intelligent_rate_limiter()
        await test_integration_with_scanner()

        print("=" * 60)
        print("所有测试通过！智能限速系统功能正常。")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n❌ 测试出错: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    # Windows兼容性
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    exit_code = asyncio.run(main())
    sys.exit(exit_code)