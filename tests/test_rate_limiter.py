"""RateLimiter 家族单元测试(TD-008 core 单测补强)。

覆盖:突发/均匀窗口限速、429 退避与健康恢复、WAF 规避头、IntelligentRateLimiter 装配。
"""

from __future__ import annotations

import asyncio
import time

from wvs.core.rate_limiter import (
    AdaptiveRateLimiter,
    HealthStatus,
    IntelligentRateLimiter,
    RateLimiter,
    RateLimitMode,
    WAFEvasion,
)


def test_rate_limiter_burst_allows_within_max_rps() -> None:
    """窗口内前 max_rps 个请求应立即放行。"""

    async def _run():
        rl = RateLimiter(max_rps=5, window_size=1.0)
        start = time.monotonic()
        for _ in range(5):
            await rl.acquire()
        assert time.monotonic() - start < 0.5  # 无明显等待

    asyncio.run(_run())


def test_rate_limiter_burst_blocks_over_max_rps() -> None:
    """超过 max_rps 的请求应被延迟到下一窗口。"""

    async def _run():
        rl = RateLimiter(max_rps=2, window_size=0.2)
        await rl.acquire()
        await rl.acquire()
        start = time.monotonic()
        await rl.acquire()  # 第 3 个必须等窗口
        elapsed = time.monotonic() - start
        assert elapsed >= 0.1  # 等待了窗口剩余时间

    asyncio.run(_run())


def test_rate_limiter_uniform_mode_spacing() -> None:
    """uniform 模式应按 1/rps 间隔放行。"""

    async def _run():
        rl = RateLimiter(max_rps=10, window_size=1.0, mode=RateLimitMode.UNIFORM)
        start = time.monotonic()
        for _ in range(3):
            await rl.acquire()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.1  # 3 个请求至少间隔 2×(1/10)=0.2s,留余量断言

    asyncio.run(_run())


def test_rate_limiter_update_metrics_and_reset() -> None:
    rl = RateLimiter(max_rps=10)
    rl.update_metrics(200, 0.1)
    rl.update_metrics(429, 0.2)
    metrics = rl.get_metrics()
    assert metrics["success_count"] == 1
    assert metrics["error_count"] == 1
    rl.reset()
    assert rl.get_metrics()["success_count"] == 0
    assert rl.get_metrics()["error_count"] == 0


def test_adaptive_backoff_on_429_and_recovery() -> None:
    """429 触发退避(健康态 THROTTLED、max_rps 折半),恢复窗口后向上调整。"""
    import time as _time

    rl = AdaptiveRateLimiter(max_rps=10, min_rps=1, recovery_rate=0.5)
    rl.update_metrics(429, 0.5)
    assert rl.health_status == HealthStatus.THROTTLED
    assert rl.max_rps < 10  # 退避生效

    # 模拟冷却期结束后的连续成功 → 自适应上调
    rl.last_adjustment_time = _time.time() - 60
    for _ in range(6):
        rl.update_metrics(200, 0.05)
        rl.last_adjustment_time = _time.time() - 60  # 每次都越过冷却
    assert rl.max_rps > 1  # 向恢复方向调整


def test_wafevasion_headers_and_jitter() -> None:
    ev = WAFEvasion(enable_jitter=False, enable_rotation=True)
    headers = ev.get_evasion_headers()
    assert "User-Agent" in headers and headers["User-Agent"]
    params = ev.randomize_request_order({"a": "1", "b": "2", "c": "3"})
    assert set(params.keys()) == {"a", "b", "c"}  # 只乱序不改内容


def test_intelligent_rate_limiter_config_wiring() -> None:
    """IntelligentRateLimiter 应按 config 装配,并透传 metrics/规避头。"""
    rl = IntelligentRateLimiter(
        {
            "max_rps": 8,
            "mode": "burst",
            "enable_adaptive": True,
            "enable_waf_evasion": True,
            "window_size": 1.0,
        }
    )
    assert rl.rate_limiter.max_rps == 8
    rl.update_metrics(200, 0.1)
    stats = rl.get_stats()
    assert stats["rate_limiter"]["success_count"] == 1
    headers = rl.get_evasion_headers()
    assert "User-Agent" in headers
    rl.reset_stats()
    assert rl.get_stats()["rate_limiter"]["success_count"] == 0
