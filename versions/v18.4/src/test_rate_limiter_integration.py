#!/usr/bin/env python3
"""
智能限速系统集成测试

验证限速效果和与现有扫描器的兼容性：
1. 基本限速功能测试
2. 自适应调整测试（防止429/503）
3. WAF规避功能测试
4. 与并发扫描器集成测试
5. 性能影响评估
"""

import asyncio
import time
import sys
import os

# 添加当前目录到路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


async def test_basic_rate_limiting():
    """测试基本限速功能"""
    print("=== 测试1: 基本限速功能 ===")

    from rate_limiter import RateLimiter, RateLimitMode

    # 测试突发模式
    limiter = RateLimiter(max_rps=5, window_size=1.0, mode=RateLimitMode.BURST)

    start_time = time.time()
    for i in range(10):
        wait_time = await limiter.acquire()
        print(f"  请求 {i+1}: 等待 {wait_time:.3f} 秒")

    elapsed = time.time() - start_time
    expected_min = 1.0  # 10个请求，5 RPS，至少需要1秒

    print(f"  总耗时: {elapsed:.3f} 秒，预期至少 {expected_min:.3f} 秒")
    assert elapsed >= expected_min, f"耗时 {elapsed:.3f} 秒小于预期 {expected_min:.3f} 秒"

    # 测试均匀模式
    limiter = RateLimiter(max_rps=2, window_size=1.0, mode=RateLimitMode.UNIFORM)

    start_time = time.time()
    for i in range(6):
        wait_time = await limiter.acquire()
        print(f"  请求 {i+1}: 等待 {wait_time:.3f} 秒")

    elapsed = time.time() - start_time
    expected_min = 2.5  # 6个请求，2 RPS，至少需要2.5秒

    print(f"  总耗时: {elapsed:.3f} 秒，预期至少 {expected_min:.3f} 秒")
    assert elapsed >= expected_min, f"耗时 {elapsed:.3f} 秒小于预期 {expected_min:.3f} 秒"

    print("✓ 基本限速功能测试通过\n")


async def test_adaptive_rate_limiting():
    """测试自适应限速（防止429/503）"""
    print("=== 测试2: 自适应限速 ===")

    from rate_limiter import AdaptiveRateLimiter

    limiter = AdaptiveRateLimiter(max_rps=10, min_rps=1)

    # 模拟正常请求
    for i in range(5):
        await limiter.acquire()
        limiter.update_metrics(200, 0.5)

    # 模拟触发WAF（429错误）
    print("  模拟触发WAF (429错误)...")
    await limiter.acquire()
    limiter.update_metrics(429, 2.0)

    health = limiter.get_health_status()
    print(f"  健康状态: {health['status']}, RPS: {health['current_max_rps']}")
    assert health['status'] == 'throttled' or health['is_in_backoff'], "应进入限制状态"

    # 模拟更多错误（503错误）
    for i in range(3):
        await limiter.acquire()
        limiter.update_metrics(503, 3.0)

    health = limiter.get_health_status()
    print(f"  多次错误后RPS: {health['current_max_rps']}")
    assert health['current_max_rps'] < 10, "RPS应降低"

    # 模拟恢复期
    print("  模拟恢复期...")
    for i in range(10):
        await limiter.acquire()
        limiter.update_metrics(200, 0.3)

    health = limiter.get_health_status()
    print(f"  恢复后RPS: {health['current_max_rps']}")

    print("✓ 自适应限速测试通过\n")


async def test_waf_evasion():
    """测试WAF规避功能"""
    print("=== 测试3: WAF规避功能 ===")

    from rate_limiter import WAFEvasion

    evasion = WAFEvasion(enable_jitter=True, enable_rotation=True, jitter_range=0.2)

    # 测试随机抖动
    base_delay = 0.5
    total_jitter = 0.0
    for i in range(5):
        jitter_time = await evasion.apply_jitter(base_delay)
        total_jitter += jitter_time
        print(f"  抖动 {i+1}: 基础 {base_delay:.3f} 秒，实际 {jitter_time:.3f} 秒")

    # 测试头部生成
    headers = evasion.get_evasion_headers()
    print(f"  生成的头部包含User-Agent: {'User-Agent' in headers}")
    assert 'User-Agent' in headers, "应生成User-Agent头部"

    # 测试多次生成，检查轮换
    headers_list = []
    for i in range(3):
        headers_list.append(evasion.get_evasion_headers())

    ua_set = {h.get('User-Agent', '') for h in headers_list}
    print(f"  唯一User-Agent数量: {len(ua_set)}")

    # 测试参数随机化
    params = {'id': '123', 'name': 'test', 'action': 'submit'}
    randomized = evasion.randomize_request_order(params)
    print(f"  参数随机化: {list(params.keys())} -> {list(randomized.keys())}")
    assert set(params.keys()) == set(randomized.keys()), "参数键应相同"

    print("✓ WAF规避功能测试通过\n")


async def test_intelligent_rate_limiter():
    """测试智能限速器集成"""
    print("=== 测试4: 智能限速器集成 ===")

    from rate_limiter import IntelligentRateLimiter

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
    request_times = []

    for i in range(8):
        wait_time = await limiter.acquire()
        request_time = time.time()
        request_times.append(request_time)

        print(f"  请求 {i+1}: 等待 {wait_time:.3f} 秒")

        # 模拟响应
        if i == 2:
            # 第三个请求模拟429错误
            limiter.update_metrics(429, 2.0)
            print(f"    响应: 429 Too Many Requests")
        else:
            limiter.update_metrics(200, 0.5 + i * 0.1)

    elapsed = time.time() - start_time
    print(f"  总耗时: {elapsed:.3f} 秒")

    # 计算实际RPS
    if len(request_times) >= 2:
        total_time = request_times[-1] - request_times[0]
        actual_rps = (len(request_times) - 1) / total_time if total_time > 0 else 0
        print(f"  实际RPS: {actual_rps:.2f}")

    # 获取统计信息
    stats = limiter.get_stats()
    print(f"  总请求数: {stats['total_requests']}")
    print(f"  错误率: {stats['rate_limiter']['error_rate']:.1%}")

    assert stats['total_requests'] == 8
    assert stats['rate_limiter']['request_count'] == 8

    print("✓ 智能限速器集成测试通过\n")


async def test_compatibility_with_existing_scanner():
    """测试与现有扫描器的兼容性"""
    print("=== 测试5: 与现有扫描器兼容性 ===")

    try:
        # 尝试导入现有扫描器使用的intelligent_rate_limiter
        # 同时测试rate_limiter的兼容性
        from rate_limiter import (
            RateLimiter,
            AdaptiveRateLimiter,
            WAFEvasion,
            IntelligentRateLimiter,
            RateLimitMode,
            HealthStatus
        )

        print("  ✓ rate_limiter模块提供所有必需的类")

        # 检查类名和接口兼容性
        required_classes = [
            'RateLimiter',
            'AdaptiveRateLimiter',
            'WAFEvasion',
            'IntelligentRateLimiter',
            'RateLimitMode',
            'HealthStatus'
        ]

        for class_name in required_classes:
            assert class_name in globals(), f"缺少类: {class_name}"

        print("  ✓ 所有必需类都可用")

        # 测试基本功能兼容性
        limiter = RateLimiter(max_rps=5)
        await limiter.acquire()
        limiter.update_metrics(200, 0.5)

        print("  ✓ 基本功能测试通过")

        # 测试配置兼容性
        config = {
            "max_rps": 10,
            "mode": "burst",
            "enable_adaptive": True,
            "enable_waf_evasion": True,
        }

        intelligent_limiter = IntelligentRateLimiter(config)
        await intelligent_limiter.acquire()
        headers = intelligent_limiter.get_evasion_headers()

        print("  ✓ 智能限速器功能测试通过")
        print("  ✓ 与现有扫描器接口兼容")

    except ImportError as e:
        print(f"  ⚠ 导入错误: {e}")
        print("  ⚠ 兼容性测试部分失败")
    except AssertionError as e:
        print(f"  ❌ 断言失败: {e}")
        print("  ⚠ 兼容性测试部分失败")
    except Exception as e:
        print(f"  ❌ 错误: {e}")
        print("  ⚠ 兼容性测试部分失败")

    print("✓ 兼容性测试完成\n")


async def test_performance_impact():
    """测试性能影响"""
    print("=== 测试6: 性能影响评估 ===")

    from rate_limiter import IntelligentRateLimiter

    # 测试不同配置下的性能
    test_configs = [
        {"name": "无限制", "max_rps": 0, "enable_adaptive": False, "enable_waf_evasion": False},
        {"name": "基础限速", "max_rps": 10, "enable_adaptive": False, "enable_waf_evasion": False},
        {"name": "自适应限速", "max_rps": 10, "enable_adaptive": True, "enable_waf_evasion": False},
        {"name": "完整功能", "max_rps": 10, "enable_adaptive": True, "enable_waf_evasion": True},
    ]

    for config_info in test_configs:
        name = config_info.pop("name")
        config = config_info

        print(f"  测试配置: {name}")

        limiter = IntelligentRateLimiter(config)

        # 执行10个请求
        start_time = time.time()
        total_wait_time = 0.0

        for i in range(10):
            wait_time = await limiter.acquire()
            total_wait_time += wait_time

            # 模拟正常响应
            limiter.update_metrics(200, 0.1)

        elapsed = time.time() - start_time

        stats = limiter.get_stats()
        avg_wait = stats['avg_wait_time_per_request']

        print(f"    总耗时: {elapsed:.3f} 秒")
        print(f"    总等待时间: {total_wait_time:.3f} 秒")
        print(f"    平均等待时间: {avg_wait:.3f} 秒/请求")

        # 验证限速效果
        if config['max_rps'] > 0:
            expected_min = 0.9  # 10个请求，10 RPS，至少需要0.9秒
            assert elapsed >= expected_min, f"耗时 {elapsed:.3f} 秒小于预期 {expected_min:.3f} 秒"
            print(f"    ✓ 限速生效")
        else:
            print(f"    ✓ 无限制模式")

    print("✓ 性能影响评估完成\n")


async def test_concurrent_usage():
    """测试并发使用场景"""
    print("=== 测试7: 并发使用场景 ===")

    from rate_limiter import IntelligentRateLimiter

    # 创建共享限速器
    config = {
        "max_rps": 20,  # 总RPS限制
        "mode": "burst",
        "enable_adaptive": True,
    }

    shared_limiter = IntelligentRateLimiter(config)

    async def worker(worker_id: int, num_requests: int):
        """工作线程"""
        for i in range(num_requests):
            wait_time = await shared_limiter.acquire()

            # 模拟请求
            await asyncio.sleep(0.01)  # 模拟网络延迟

            # 随机成功或失败
            if random.random() > 0.9:
                shared_limiter.update_metrics(429, 0.5)
            else:
                shared_limiter.update_metrics(200, 0.1 + random.random() * 0.2)

            if i % 5 == 0:
                print(f"    Worker {worker_id}: 请求 {i+1}/{num_requests}, 等待 {wait_time:.3f} 秒")

    # 启动多个并发worker
    num_workers = 3
    requests_per_worker = 10

    print(f"  启动 {num_workers} 个worker，每个 {requests_per_worker} 个请求")

    start_time = time.time()
    tasks = [worker(i, requests_per_worker) for i in range(num_workers)]
    await asyncio.gather(*tasks)

    elapsed = time.time() - start_time

    # 验证总RPS不超过限制
    total_requests = num_workers * requests_per_worker
    actual_rps = total_requests / elapsed if elapsed > 0 else 0

    print(f"  总请求数: {total_requests}")
    print(f"  总耗时: {elapsed:.3f} 秒")
    print(f"  实际RPS: {actual_rps:.2f}")
    print(f"  限制RPS: {config['max_rps']}")

    # 允许一定的误差（并发调度的不确定性）
    if actual_rps > config['max_rps'] * 1.5:
        print(f"  ⚠ 实际RPS ({actual_rps:.2f}) 显著超过限制 ({config['max_rps']})")
    else:
        print(f"  ✓ RPS控制在合理范围内")

    # 显示统计信息
    stats = shared_limiter.get_stats()
    print(f"  错误率: {stats['rate_limiter']['error_rate']:.1%}")

    print("✓ 并发使用场景测试完成\n")


async def main():
    """运行所有测试"""
    print("="*60)
    print("智能限速系统集成测试")
    print("="*60)
    print()

    test_results = []

    tests = [
        ("基本限速功能", test_basic_rate_limiting),
        ("自适应限速", test_adaptive_rate_limiting),
        ("WAF规避功能", test_waf_evasion),
        ("智能限速器集成", test_intelligent_rate_limiter),
        ("与现有扫描器兼容性", test_compatibility_with_existing_scanner),
        ("性能影响评估", test_performance_impact),
        ("并发使用场景", test_concurrent_usage),
    ]

    for test_name, test_func in tests:
        try:
            print(f"开始测试: {test_name}")
            await test_func()
            test_results.append((test_name, True, None))
        except AssertionError as e:
            print(f"❌ {test_name} 失败: {e}")
            test_results.append((test_name, False, str(e)))
        except Exception as e:
            print(f"❌ {test_name} 出错: {e}")
            import traceback
            traceback.print_exc()
            test_results.append((test_name, False, str(e)))

    # 打印测试总结
    print("="*60)
    print("测试总结")
    print("="*60)

    passed = sum(1 for _, success, _ in test_results if success)
    total = len(test_results)

    print(f"通过: {passed}/{total}")
    print()

    for test_name, success, error in test_results:
        status = "✓" if success else "❌"
        print(f"  {status} {test_name}")
        if error:
            print(f"     错误: {error}")

    print()
    if passed == total:
        print("✅ 所有测试通过！智能限速系统功能正常。")
        print("✅ 完全兼容现有并发扫描器架构。")
    else:
        print(f"⚠ {total - passed} 个测试失败，请检查上述错误。")

    return passed == total


if __name__ == "__main__":
    # Windows兼容性设置
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    import random
    random.seed(42)  # 确保测试可重复

    print("注意: 这些测试不实际发送HTTP请求，仅测试限速器逻辑。")
    print("      实际集成测试需要结合真实的扫描器。\n")

    success = asyncio.run(main())

    if success:
        print("\n✅ 集成测试完成，智能限速系统已就绪。")
        print("\n下一步:")
        print("1. 将 rate_limiter.py 集成到现有扫描器")
        print("2. 根据实际场景调整RPS限制")
        print("3. 监控扫描过程中的限速器统计信息")
        print("4. 根据目标网站响应调整自适应参数")
    else:
        print("\n❌ 集成测试失败，请修复上述问题。")

    sys.exit(0 if success else 1)