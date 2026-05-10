#!/usr/bin/env python3
"""
智能限速系统使用示例

展示如何在各种场景下使用智能限速系统：
1. 独立使用智能限速器
2. 与漏洞扫描器集成
3. 与并发扫描器集成
4. 自定义配置和监控
"""

import asyncio
import time
import sys
import os

# 添加当前目录到路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


async def example_standalone_usage():
    """示例1: 独立使用智能限速器"""
    print("=== 示例1: 独立使用智能限速器 ===\n")

    from intelligent_rate_limiter import IntelligentRateLimiter

    # 创建配置
    config = {
        "max_rps": 3,                # 最大3个请求/秒
        "mode": "burst",             # 突发模式
        "enable_adaptive": True,     # 启用自适应调整
        "enable_waf_evasion": True,  # 启用WAF规避
        "enable_jitter": True,       # 启用随机抖动
        "jitter_range": 0.2,         # 抖动范围0.2秒
    }

    # 创建限速器
    rate_limiter = IntelligentRateLimiter(config)
    print("✓ 智能限速器已创建")

    # 模拟发送一系列请求
    print("\n模拟发送10个请求...")
    for i in range(10):
        # 等待直到可以发送请求
        wait_time = await rate_limiter.acquire()
        print(f"  请求 {i+1}: 等待 {wait_time:.3f} 秒")

        # 模拟请求（这里只是示例，实际应发送HTTP请求）
        # 获取WAF规避头部
        headers = rate_limiter.get_evasion_headers()
        print(f"    使用头部: User-Agent={headers.get('User-Agent', 'N/A')[:50]}...")

        # 模拟响应（成功或失败）
        if i == 3:
            # 模拟触发WAF（429错误）
            rate_limiter.update_metrics(429, 2.5)
            print(f"    响应: 429 Too Many Requests (触发WAF)")
        elif i == 7:
            # 模拟服务器过载（503错误）
            rate_limiter.update_metrics(503, 3.0)
            print(f"    响应: 503 Service Unavailable")
        else:
            # 模拟成功响应
            response_time = 0.5 + (i % 3) * 0.2
            rate_limiter.update_metrics(200, response_time)
            print(f"    响应: 200 OK (耗时 {response_time:.2f} 秒)")

    # 显示统计信息
    print("\n统计信息:")
    stats = rate_limiter.get_stats()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for k, v in value.items():
                if isinstance(v, dict):
                    print(f"    {k}:")
                    for k2, v2 in v.items():
                        print(f"      {k2}: {v2}")
                else:
                    print(f"    {k}: {v}")
        else:
            print(f"  {key}: {value}")

    print("\n✓ 示例1完成\n")


async def example_with_vulnerability_scanner():
    """示例2: 与漏洞扫描器集成"""
    print("=== 示例2: 与漏洞扫描器集成 ===\n")

    try:
        from wvs.vuln.scanner_v18 import VulnerabilityScanner

        # 配置扫描器，启用智能限速
        scanner_config = {
            "timeout": 30,
            "verify_ssl": False,
            "delay": 0.1,  # 原始delay，将被速率限制器覆盖

            # 智能限速配置
            "rate_limiter": {
                "enabled": True,
                "max_rps": 5,
                "mode": "burst",
                "enable_adaptive": True,
                "enable_waf_evasion": True,
                "enable_jitter": True,
                "jitter_range": 0.3,
            }
        }

        scanner = VulnerabilityScanner(scanner_config)
        print("✓ 漏洞扫描器已创建，智能限速已启用")

        # 检查速率限制器是否已初始化
        if hasattr(scanner, 'rate_limiter') and scanner.rate_limiter:
            print("✓ 速率限制器已成功初始化")

            # 显示配置信息
            print(f"  最大RPS: {scanner.config.get('rate_limiter', {}).get('max_rps', 'N/A')}")
            print(f"  模式: {scanner.config.get('rate_limiter', {}).get('mode', 'N/A')}")
            print(f"  自适应调整: {scanner.config.get('rate_limiter', {}).get('enable_adaptive', False)}")
            print(f"  WAF规避: {scanner.config.get('rate_limiter', {}).get('enable_waf_evasion', False)}")

            # 注意：实际扫描需要目标URL，这里只是展示配置
            print("\n⚠ 注意: 此示例仅展示配置，实际扫描需要目标URL")
        else:
            print("⚠ 速率限制器未初始化（可能intelligent_rate_limiter模块不可用）")

    except ImportError as e:
        print(f"⚠ 无法导入扫描器模块: {e}")
    except Exception as e:
        print(f"⚠ 出错: {e}")

    print("\n✓ 示例2完成\n")


async def example_with_concurrent_scanner():
    """示例3: 与并发扫描器集成"""
    print("=== 示例3: 与并发扫描器集成 ===\n")

    try:
        from concurrent_scanner import ConcurrentScanner

        # 配置并发扫描器，启用智能限速
        config = {
            "max_workers": 3,
            "timeout_per_target": 120,
            "scanner_timeout": 30,
            "scanner_delay": 0.1,
            "enable_validation": True,

            # 智能限速配置（将传递给每个扫描器实例）
            "rate_limiter": {
                "enabled": True,
                "max_rps": 10,  # 每个扫描器实例的RPS限制
                "mode": "burst",
                "enable_adaptive": True,
                "enable_waf_evasion": True,
            }
        }

        scanner = ConcurrentScanner(config)
        print("✓ 并发扫描器已创建，智能限速已启用")

        # 显示配置信息
        print(f"  最大工作线程: {scanner.max_workers}")
        print(f"  启用限速器: {scanner.enable_rate_limiter}")
        print(f"  限速器配置: {scanner.rate_limiter_config}")

        # 注意：实际并发扫描需要目标列表，这里只是展示配置
        print("\n⚠ 注意: 此示例仅展示配置，实际并发扫描需要目标列表")

        # 模拟创建扫描器实例
        print("\n模拟创建扫描器实例...")
        test_scanner = scanner.create_scanner_for_target("http://example.com")
        print(f"✓ 扫描器实例已创建")
        print(f"  扫描器配置包含限速器: {'rate_limiter' in test_scanner.config}")

    except ImportError as e:
        print(f"⚠ 无法导入并发扫描器模块: {e}")
    except Exception as e:
        print(f"⚠ 出错: {e}")

    print("\n✓ 示例3完成\n")


async def example_advanced_monitoring():
    """示例4: 高级监控和调整"""
    print("=== 示例4: 高级监控和调整 ===\n")

    from intelligent_rate_limiter import IntelligentRateLimiter

    # 创建自适应限速器
    config = {
        "max_rps": 8,
        "mode": "burst",
        "enable_adaptive": True,
        "min_rps": 1,
        "recovery_rate": 0.1,
        "backoff_factor": 2.0,
        "enable_waf_evasion": True,
    }

    rate_limiter = IntelligentRateLimiter(config)
    print("✓ 自适应限速器已创建")

    # 模拟监控循环
    print("\n模拟监控循环（5个周期）...")
    for cycle in range(5):
        print(f"\n--- 周期 {cycle + 1} ---")

        # 发送一些请求
        for i in range(3):
            await rate_limiter.acquire()

            # 模拟不同的响应
            if cycle == 1 and i == 1:
                # 周期1触发WAF
                rate_limiter.update_metrics(429, 2.0)
                print(f"  请求 {i+1}: 429 Too Many Requests (触发WAF)")
            elif cycle == 2:
                # 周期2服务器过载
                rate_limiter.update_metrics(503, 3.0)
                print(f"  请求 {i+1}: 503 Service Unavailable")
            else:
                # 正常响应，响应时间逐渐增加
                response_time = 0.5 + cycle * 0.3
                rate_limiter.update_metrics(200, response_time)
                print(f"  请求 {i+1}: 200 OK (耗时 {response_time:.2f} 秒)")

        # 获取当前状态
        stats = rate_limiter.get_stats()
        adaptive_status = stats.get('adaptive_status', {})

        print(f"  当前RPS限制: {adaptive_status.get('current_max_rps', 'N/A')}")
        print(f"  健康状态: {adaptive_status.get('status', 'N/A')}")
        print(f"  退避状态: {adaptive_status.get('is_in_backoff', False)}")

        # 等待下一个监控周期
        await asyncio.sleep(1.0)

    # 最终统计
    print("\n最终统计信息:")
    stats = rate_limiter.get_stats()
    print(f"  总请求数: {stats['total_requests']}")
    print(f"  总等待时间: {stats['total_wait_time']:.2f} 秒")
    print(f"  平均等待时间: {stats['avg_wait_time_per_request']:.3f} 秒/请求")
    print(f"  错误率: {stats['rate_limiter']['error_rate']:.2%}")

    print("\n✓ 示例4完成\n")


async def example_custom_configuration():
    """示例5: 自定义配置场景"""
    print("=== 示例5: 自定义配置场景 ===\n")

    from intelligent_rate_limiter import IntelligentRateLimiter

    scenarios = {
        "快速扫描": {
            "max_rps": 20,
            "mode": "burst",
            "enable_adaptive": False,
            "enable_waf_evasion": False,
        },
        "平衡模式": {
            "max_rps": 10,
            "mode": "burst",
            "enable_adaptive": True,
            "enable_waf_evasion": True,
            "enable_jitter": True,
            "jitter_range": 0.2,
        },
        "隐蔽模式": {
            "max_rps": 3,
            "mode": "uniform",
            "enable_adaptive": True,
            "min_rps": 1,
            "recovery_rate": 0.05,
            "backoff_factor": 3.0,
            "enable_waf_evasion": True,
            "enable_jitter": True,
            "jitter_range": 0.5,
            "enable_rotation": True,
        },
    }

    for scenario_name, config in scenarios.items():
        print(f"场景: {scenario_name}")
        print(f"配置: {config}")

        # 创建限速器
        rate_limiter = IntelligentRateLimiter(config)

        # 模拟发送几个请求
        for i in range(2):
            wait_time = await rate_limiter.acquire()
            rate_limiter.update_metrics(200, 0.5)
            print(f"  请求 {i+1}: 等待 {wait_time:.3f} 秒")

        # 获取WAF规避头部
        headers = rate_limiter.get_evasion_headers()
        print(f"  User-Agent示例: {headers.get('User-Agent', 'N/A')[:40]}...")

        print()

    print("✓ 示例5完成\n")


async def main():
    """运行所有示例"""
    print("=" * 60)
    print("智能限速系统使用示例")
    print("=" * 60)

    try:
        await example_standalone_usage()
        await example_with_vulnerability_scanner()
        await example_with_concurrent_scanner()
        await example_advanced_monitoring()
        await example_custom_configuration()

        print("=" * 60)
        print("所有示例完成！")
        print("=" * 60)
        print("\n总结:")
        print("1. 智能限速系统提供了完整的速率控制和WAF规避功能")
        print("2. 可以独立使用，也可以与现有扫描器无缝集成")
        print("3. 自适应调整能够根据响应状态码和响应时间动态调整速率")
        print("4. WAF规避策略包括随机抖动、User-Agent轮换、请求头变化等")
        print("5. 通过合理配置，可以在扫描速度和隐蔽性之间取得平衡")

    except Exception as e:
        print(f"\n❌ 示例执行出错: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    # Windows兼容性
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    print("注意: 这些示例仅展示配置和使用方法，不实际发送HTTP请求。")
    print("要实际测试，请提供真实的目标URL并修改示例代码。\n")

    exit_code = asyncio.run(main())
    sys.exit(exit_code)