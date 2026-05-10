#!/usr/bin/env python3
"""
WVS v18.4 智能限速系统 - 兼容性包装器

此文件为向后兼容性而存在，重新导出 rate_limiter.py 中的所有组件。
现有代码可以继续导入此模块，实际功能由 rate_limiter.py 提供。

注意: 为了保持完全兼容，此模块提供了与原有 intelligent_rate_limiter.py
完全相同的接口和功能。所有新开发应直接使用 rate_limiter.py。
"""

import sys
import os
import asyncio

# 添加当前目录到路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 从 rate_limiter 导入所有内容
try:
    from rate_limiter import (
        # 枚举类型
        RateLimitMode,
        HealthStatus,

        # 数据类
        RateLimitMetrics,

        # 主要类
        RateLimiter,
        AdaptiveRateLimiter,
        WAFEvasion,
        IntelligentRateLimiter,

        # 示例函数（如果需要）
        example_basic_usage,
        example_integration_with_scanner,
        example_concurrent_scanner_integration,
        example_adaptive_behavior,
        integration_guide,
        main as example_main,
    )

    # 设置模块导出
    __all__ = [
        'RateLimitMode',
        'HealthStatus',
        'RateLimitMetrics',
        'RateLimiter',
        'AdaptiveRateLimiter',
        'WAFEvasion',
        'IntelligentRateLimiter',
        'example_basic_usage',
        'example_integration_with_scanner',
        'example_concurrent_scanner_integration',
        'example_adaptive_behavior',
        'integration_guide',
        'example_main',
        'example_usage',  # 保持向后兼容
    ]

    # 打印兼容性提示
    if __name__ != "__main__":
        print("[智能限速] 使用兼容性包装器，实际功能来自 rate_limiter.py")
        print("[智能限速] 建议新代码直接导入 rate_limiter 模块")

except ImportError as e:
    print(f"[错误] 无法导入 rate_limiter.py: {e}")
    print("[错误] 请确保 rate_limiter.py 存在于当前目录")

    # 提供回退到备份（如果存在）
    try:
        from intelligent_rate_limiter_backup import *
        print("[智能限速] 已回退到备份模块")
    except ImportError:
        print("[错误] 备份模块也不可用，智能限速功能将不可用")
        raise


# 原有的示例函数（保持兼容性）
async def example_usage():
    """原有示例函数的兼容性版本"""
    print("[兼容性] 使用 rate_limiter.py 中的示例")
    from rate_limiter import example_basic_usage
    await example_basic_usage()


if __name__ == "__main__":
    # Windows兼容性设置
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # 运行示例
    print("=" * 60)
    print("智能限速系统兼容性包装器演示")
    print("=" * 60)
    print("此模块为向后兼容性而存在，实际功能来自 rate_limiter.py")
    print()

    asyncio.run(example_usage())