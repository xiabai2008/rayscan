#!/usr/bin/env python3
"""
WVS v18.4 智能限速系统

提供完整的速率限制和WAF规避功能：
1. RateLimiter: 滑动窗口请求限制（最大RPS控制）
2. AdaptiveRateLimiter: 基于响应时间、状态码动态调整速率
3. WAFEvasion: 随机请求间隔、User-Agent轮换、请求模式变化
4. IntelligentRateLimiter: 集成以上所有功能的智能限速器

完全兼容现有并发扫描器架构。
"""

import asyncio
import time
import random
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Deque
from collections import deque
from enum import Enum
import secrets
import string


class RateLimitMode(Enum):
    """速率限制模式"""
    BURST = "burst"      # 突发模式：允许突发请求，只要在时间窗口内不超过限制
    UNIFORM = "uniform"  # 均匀模式：请求均匀分布


class HealthStatus(Enum):
    """健康状态"""
    HEALTHY = "healthy"      # 正常状态
    WARNING = "warning"      # 警告状态（响应时间增加或偶发错误）
    THROTTLED = "throttled"  # 限制状态（频繁错误或触发WAF）


@dataclass
class RateLimitMetrics:
    """速率限制指标"""
    request_count: int = 0
    success_count: int = 0
    error_count: int = 0
    total_response_time: float = 0.0
    last_status_code: int = 0
    last_response_time: float = 0.0
    window_start_time: float = 0.0

    def reset(self):
        """重置指标"""
        self.request_count = 0
        self.success_count = 0
        self.error_count = 0
        self.total_response_time = 0.0


class RateLimiter:
    """
    滑动窗口请求限制器

    实现基于时间窗口的RPS（每秒请求数）控制，支持突发和均匀两种模式。
    """

    def __init__(self, max_rps: int = 10, window_size: float = 1.0,
                 mode: RateLimitMode = RateLimitMode.BURST):
        """
        初始化速率限制器

        Args:
            max_rps: 最大每秒请求数
            window_size: 时间窗口大小（秒）
            mode: 限制模式（BURST或UNIFORM）
        """
        self.max_rps = max_rps
        self.window_size = window_size
        self.mode = mode

        # 请求时间戳队列
        self.request_timestamps: Deque[float] = deque()

        # 指标收集
        self.metrics = RateLimitMetrics()
        self.metrics.window_start_time = time.time()

        # 锁，确保线程安全
        self._lock = asyncio.Lock()

        # 最后请求时间（用于均匀模式）
        self._last_request_time = 0.0

    async def acquire(self, n: int = 1) -> float:
        """
        等待直到可以发送n个请求

        Args:
            n: 请求数量

        Returns:
            等待的时间（秒）
        """
        if self.max_rps <= 0:
            return 0.0

        async with self._lock:
            if self.mode == RateLimitMode.BURST:
                return await self._acquire_burst(n)
            else:
                return await self._acquire_uniform(n)

    async def _acquire_burst(self, n: int) -> float:
        """突发模式：允许突发请求，只要在时间窗口内不超过限制"""
        current_time = time.time()

        # 清理过期的请求时间戳
        cutoff_time = current_time - self.window_size
        while self.request_timestamps and self.request_timestamps[0] < cutoff_time:
            self.request_timestamps.popleft()

        # 计算需要等待的时间
        wait_time = 0.0

        if len(self.request_timestamps) + n > self.max_rps:
            # 需要等待，直到有足够的空间
            oldest_timestamp = self.request_timestamps[0]
            wait_time = max(0.0, oldest_timestamp + self.window_size - current_time)

            # 更新当前时间
            current_time += wait_time

            # 重新清理过期的请求时间戳
            cutoff_time = current_time - self.window_size
            while self.request_timestamps and self.request_timestamps[0] < cutoff_time:
                self.request_timestamps.popleft()

        # 添加新的请求时间戳
        for _ in range(n):
            self.request_timestamps.append(current_time)

        # 更新指标
        self.metrics.request_count += n

        # 如果需要等待，实际睡眠
        if wait_time > 0:
            await asyncio.sleep(wait_time)

        return wait_time

    async def _acquire_uniform(self, n: int) -> float:
        """均匀模式：请求均匀分布"""
        current_time = time.time()
        wait_time = 0.0

        if self._last_request_time > 0:
            # 计算最小请求间隔
            min_interval = 1.0 / self.max_rps

            # 计算需要等待的时间
            time_since_last = current_time - self._last_request_time
            if time_since_last < min_interval * n:
                wait_time = min_interval * n - time_since_last

        # 更新最后请求时间
        self._last_request_time = current_time + wait_time

        # 更新指标
        self.metrics.request_count += n

        # 如果需要等待，实际睡眠
        if wait_time > 0:
            await asyncio.sleep(wait_time)

        return wait_time

    def update_metrics(self, status_code: int, response_time: float):
        """
        更新请求指标

        Args:
            status_code: HTTP状态码
            response_time: 响应时间（秒）
        """
        self.metrics.last_status_code = status_code
        self.metrics.last_response_time = response_time
        self.metrics.total_response_time += response_time

        if 200 <= status_code < 400:
            self.metrics.success_count += 1
        else:
            self.metrics.error_count += 1

    def get_current_rps(self) -> float:
        """获取当前RPS"""
        current_time = time.time()
        cutoff_time = current_time - self.window_size

        # 清理过期的请求时间戳
        while self.request_timestamps and self.request_timestamps[0] < cutoff_time:
            self.request_timestamps.popleft()

        return len(self.request_timestamps) / self.window_size

    def get_metrics(self) -> Dict:
        """获取指标"""
        return {
            "max_rps": self.max_rps,
            "current_rps": self.get_current_rps(),
            "request_count": self.metrics.request_count,
            "success_count": self.metrics.success_count,
            "error_count": self.metrics.error_count,
            "avg_response_time": (self.metrics.total_response_time / self.metrics.request_count
                                 if self.metrics.request_count > 0 else 0.0),
            "error_rate": (self.metrics.error_count / self.metrics.request_count
                          if self.metrics.request_count > 0 else 0.0),
        }


class AdaptiveRateLimiter(RateLimiter):
    """
    自适应速率限制器

    基于响应指标动态调整RPS：
    1. 响应时间增加 => 降低速率
    2. 429/503状态码 => 指数退避
    3. 成功率下降 => 降低速率
    4. 一段时间无错误后逐渐恢复速率
    """

    def __init__(self, max_rps: int = 10, window_size: float = 1.0,
                 mode: RateLimitMode = RateLimitMode.BURST,
                 min_rps: int = 1, recovery_rate: float = 0.1,
                 backoff_factor: float = 2.0):
        """
        初始化自适应速率限制器

        Args:
            max_rps: 最大RPS
            window_size: 时间窗口大小
            mode: 限制模式
            min_rps: 最小RPS
            recovery_rate: 恢复速率（每次调整增加的比例）
            backoff_factor: 退避因子（遇到错误时RPS减少的倍数）
        """
        super().__init__(max_rps, window_size, mode)
        self.original_max_rps = max_rps
        self.min_rps = min_rps
        self.recovery_rate = recovery_rate
        self.backoff_factor = backoff_factor

        # 自适应状态
        self.health_status = HealthStatus.HEALTHY
        self.last_adjustment_time = time.time()
        self.adjustment_cooldown = 5.0  # 调整冷却时间（秒）

        # 历史指标
        self.response_time_history: List[float] = []
        self.status_code_history: List[int] = []
        self.history_size = 20

        # 退避状态
        self.is_in_backoff = False
        self.backoff_until = 0.0
        self.backoff_count = 0

    def update_metrics(self, status_code: int, response_time: float):
        """更新指标并可能触发自适应调整"""
        super().update_metrics(status_code, response_time)

        # 记录历史
        self.response_time_history.append(response_time)
        self.status_code_history.append(status_code)
        if len(self.response_time_history) > self.history_size:
            self.response_time_history.pop(0)
            self.status_code_history.pop(0)

        # 检查是否需要退避
        if status_code in [429, 503]:  # Too Many Requests, Service Unavailable
            self._trigger_backoff()

        # 自适应调整（冷却时间内不重复调整）
        current_time = time.time()
        if current_time - self.last_adjustment_time >= self.adjustment_cooldown:
            self._adaptive_adjust()
            self.last_adjustment_time = current_time

    def _trigger_backoff(self):
        """触发退避机制"""
        self.is_in_backoff = True
        self.backoff_count += 1

        # 计算退避时间：指数增长，最大60秒
        backoff_time = min(60.0, 5.0 * (self.backoff_factor ** self.backoff_count))
        self.backoff_until = time.time() + backoff_time

        # 降低RPS
        self.max_rps = max(self.min_rps, self.max_rps // self.backoff_factor)

        # 更新健康状态
        self.health_status = HealthStatus.THROTTLED

        print(f"[自适应限速] 触发退避，等待 {backoff_time:.1f} 秒，RPS降至 {self.max_rps}")

    def _adaptive_adjust(self):
        """自适应调整RPS"""
        # 如果处于退避状态，检查是否结束
        if self.is_in_backoff and time.time() >= self.backoff_until:
            self.is_in_backoff = False
            self.health_status = HealthStatus.HEALTHY
            print(f"[自适应限速] 退避结束，恢复调整")

        # 如果没有足够的历史数据，不调整
        if len(self.response_time_history) < 5:
            return

        # 计算指标
        avg_response_time = statistics.mean(self.response_time_history)
        error_rate = self.metrics.error_count / max(1, self.metrics.request_count)

        # 确定健康状态
        if error_rate > 0.3:
            new_status = HealthStatus.THROTTLED
        elif error_rate > 0.1 or avg_response_time > 2.0:
            new_status = HealthStatus.WARNING
        else:
            new_status = HealthStatus.HEALTHY

        # 状态变化时调整RPS
        if new_status != self.health_status:
            self.health_status = new_status

            if new_status == HealthStatus.HEALTHY:
                # 恢复：逐步增加RPS
                self.max_rps = min(self.original_max_rps,
                                  int(self.max_rps * (1.0 + self.recovery_rate)))
                print(f"[自适应限速] 状态恢复健康，RPS增至 {self.max_rps}")

            elif new_status == HealthStatus.WARNING:
                # 警告：适当降低RPS
                self.max_rps = max(self.min_rps, int(self.max_rps * 0.8))
                print(f"[自适应限速] 进入警告状态，RPS降至 {self.max_rps}")

            elif new_status == HealthStatus.THROTTLED:
                # 限制：大幅降低RPS
                self.max_rps = max(self.min_rps, int(self.max_rps * 0.5))
                print(f"[自适应限速] 进入限制状态，RPS降至 {self.max_rps}")

    async def acquire(self, n: int = 1) -> float:
        """重写acquire方法，在退避期间等待"""
        if self.is_in_backoff:
            current_time = time.time()
            if current_time < self.backoff_until:
                wait_time = self.backoff_until - current_time
                print(f"[自适应限速] 退避等待中，剩余 {wait_time:.1f} 秒")
                await asyncio.sleep(wait_time)

        return await super().acquire(n)

    def get_health_status(self) -> Dict:
        """获取健康状态"""
        return {
            "status": self.health_status.value,
            "is_in_backoff": self.is_in_backoff,
            "backoff_until": self.backoff_until,
            "backoff_count": self.backoff_count,
            "current_max_rps": self.max_rps,
            "original_max_rps": self.original_max_rps,
        }


class WAFEvasion:
    """
    WAF规避策略

    实现多种WAF规避技术：
    1. 随机请求间隔
    2. User-Agent轮换
    3. 请求头变化
    4. 请求模式变化
    """

    # 常用User-Agent列表
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    ]

    # 语言列表
    LANGUAGES = [
        "en-US,en;q=0.9",
        "zh-CN,zh;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8",
        "ko-KR,ko;q=0.9,en;q=0.8",
        "es-ES,es;q=0.9,en;q=0.8",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
    ]

    # 接受内容类型
    ACCEPT_TYPES = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    ]

    def __init__(self, enable_jitter: bool = True, enable_rotation: bool = True,
                 jitter_range: float = 0.3):
        """
        初始化WAF规避策略

        Args:
            enable_jitter: 启用随机抖动
            enable_rotation: 启用User-Agent轮换
            jitter_range: 抖动范围（秒）
        """
        self.enable_jitter = enable_jitter
        self.enable_rotation = enable_rotation
        self.jitter_range = jitter_range

        # 当前使用的User-Agent索引
        self.current_ua_index = 0

        # 请求计数器（用于定期轮换）
        self.request_counter = 0

    async def apply_jitter(self, base_delay: float = 0.0) -> float:
        """
        应用随机抖动

        Args:
            base_delay: 基础延迟

        Returns:
            实际延迟时间
        """
        if not self.enable_jitter or self.jitter_range <= 0:
            return base_delay

        # 在基础延迟上添加随机抖动
        jitter = random.uniform(-self.jitter_range, self.jitter_range)
        actual_delay = max(0.0, base_delay + jitter)

        if actual_delay > 0:
            await asyncio.sleep(actual_delay)

        return actual_delay

    def get_evasion_headers(self) -> Dict[str, str]:
        """
        获取WAF规避头部

        返回随机的User-Agent、Accept、Accept-Language等头部
        """
        headers = {}

        # User-Agent轮换
        if self.enable_rotation:
            self.current_ua_index = (self.current_ua_index + 1) % len(self.USER_AGENTS)
            headers["User-Agent"] = self.USER_AGENTS[self.current_ua_index]
        else:
            headers["User-Agent"] = random.choice(self.USER_AGENTS)

        # 其他随机头部
        if random.random() > 0.5:
            headers["Accept"] = random.choice(self.ACCEPT_TYPES)

        if random.random() > 0.5:
            headers["Accept-Language"] = random.choice(self.LANGUAGES)

        if random.random() > 0.7:
            headers["Accept-Encoding"] = random.choice(["gzip, deflate, br", "gzip, deflate"])

        if random.random() > 0.8:
            headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])

        # 添加一些随机头部以增加变化
        if random.random() > 0.9:
            headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

        self.request_counter += 1
        return headers

    def randomize_request_order(self, params: Dict) -> Dict:
        """
        随机化请求参数顺序

        Args:
            params: 原始参数字典

        Returns:
            随机化顺序后的参数字典
        """
        if not params:
            return params

        # 将字典转换为列表，随机排序后再转换回字典
        items = list(params.items())
        random.shuffle(items)
        return dict(items)

    def add_redundant_parameters(self, params: Dict) -> Dict:
        """
        添加冗余参数

        Args:
            params: 原始参数字典

        Returns:
            添加冗余参数后的字典
        """
        if random.random() > 0.7:
            # 添加一些常见但无害的参数
            redundant_params = {
                "timestamp": str(int(time.time())),
                "random": secrets.token_hex(4),
                "v": "1.0",
                "format": "json",
                "callback": "jQuery" + str(random.randint(1000000000, 9999999999)),
            }

            # 随机选择一些冗余参数添加
            num_to_add = random.randint(1, 3)
            selected_keys = random.sample(list(redundant_params.keys()), num_to_add)

            for key in selected_keys:
                if key not in params:
                    params[key] = redundant_params[key]

        return params


class IntelligentRateLimiter:
    """
    智能速率限制器

    集成速率限制、自适应调整和WAF规避的完整解决方案
    """

    def __init__(self, config: Dict = None):
        """
        初始化智能速率限制器

        Args:
            config: 配置字典
        """
        self.config = config or {}

        # 解析配置
        max_rps = self.config.get("max_rps", 10)
        mode_str = self.config.get("mode", "burst")
        mode = RateLimitMode.BURST if mode_str == "burst" else RateLimitMode.UNIFORM

        enable_adaptive = self.config.get("enable_adaptive", True)
        enable_waf_evasion = self.config.get("enable_waf_evasion", True)

        # 初始化组件
        if enable_adaptive:
            self.rate_limiter = AdaptiveRateLimiter(
                max_rps=max_rps,
                window_size=self.config.get("window_size", 1.0),
                mode=mode,
                min_rps=self.config.get("min_rps", 1),
                recovery_rate=self.config.get("recovery_rate", 0.1),
                backoff_factor=self.config.get("backoff_factor", 2.0)
            )
        else:
            self.rate_limiter = RateLimiter(
                max_rps=max_rps,
                window_size=self.config.get("window_size", 1.0),
                mode=mode
            )

        self.waf_evasion = WAFEvasion(
            enable_jitter=self.config.get("enable_jitter", True),
            enable_rotation=self.config.get("enable_rotation", True),
            jitter_range=self.config.get("jitter_range", 0.3)
        ) if enable_waf_evasion else None

        # 统计信息
        self.total_requests = 0
        self.total_wait_time = 0.0

    async def acquire(self, n: int = 1) -> float:
        """
        等待直到可以发送请求

        Args:
            n: 请求数量

        Returns:
            总等待时间（秒）
        """
        # 应用速率限制
        wait_time = await self.rate_limiter.acquire(n)
        self.total_wait_time += wait_time

        # 应用WAF规避抖动
        if self.waf_evasion:
            jitter_time = await self.waf_evasion.apply_jitter()
            self.total_wait_time += jitter_time
            wait_time += jitter_time

        self.total_requests += n
        return wait_time

    def update_metrics(self, status_code: int, response_time: float):
        """
        更新请求指标

        Args:
            status_code: HTTP状态码
            response_time: 响应时间（秒）
        """
        self.rate_limiter.update_metrics(status_code, response_time)

    def get_evasion_headers(self) -> Dict[str, str]:
        """
        获取WAF规避头部

        Returns:
            头部字典，如果未启用WAF规避则返回空字典
        """
        if self.waf_evasion:
            return self.waf_evasion.get_evasion_headers()
        return {}

    def randomize_request(self, params: Dict) -> Dict:
        """
        随机化请求参数

        Args:
            params: 原始参数字典

        Returns:
            随机化后的参数字典
        """
        if not self.waf_evasion:
            return params

        # 随机化参数顺序
        params = self.waf_evasion.randomize_request_order(params)

        # 添加冗余参数
        params = self.waf_evasion.add_redundant_parameters(params)

        return params

    def get_stats(self) -> Dict:
        """获取统计信息"""
        stats = {
            "total_requests": self.total_requests,
            "total_wait_time": self.total_wait_time,
            "avg_wait_time_per_request": (self.total_wait_time / self.total_requests
                                         if self.total_requests > 0 else 0.0),
            "rate_limiter": self.rate_limiter.get_metrics(),
        }

        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            stats["adaptive_status"] = self.rate_limiter.get_health_status()

        return stats

    def reset_stats(self):
        """重置统计信息"""
        self.total_requests = 0
        self.total_wait_time = 0.0


# 使用示例
async def example_usage():
    """使用示例"""
    print("=== 智能限速系统使用示例 ===")

    # 创建智能限速器
    config = {
        "max_rps": 5,                # 最大5个请求/秒
        "mode": "burst",             # 突发模式
        "enable_adaptive": True,     # 启用自适应调整
        "enable_waf_evasion": True,  # 启用WAF规避
        "enable_jitter": True,       # 启用随机抖动
        "jitter_range": 0.2,         # 抖动范围0.2秒
    }

    rate_limiter = IntelligentRateLimiter(config)

    # 模拟发送请求
    import aiohttp

    async with aiohttp.ClientSession() as session:
        for i in range(10):
            # 等待直到可以发送请求
            wait_time = await rate_limiter.acquire()
            print(f"请求 {i+1}: 等待 {wait_time:.3f} 秒")

            # 获取WAF规避头部
            headers = rate_limiter.get_evasion_headers()

            # 发送请求（这里只是示例，实际应发送真实请求）
            start_time = time.time()
            try:
                # 模拟请求
                await asyncio.sleep(0.1)  # 模拟网络延迟
                status_code = 200  # 模拟成功响应
                response_time = time.time() - start_time

                # 更新指标
                rate_limiter.update_metrics(status_code, response_time)

                print(f"  响应: 状态码 {status_code}, 耗时 {response_time:.3f} 秒")

            except Exception as e:
                # 模拟错误
                rate_limiter.update_metrics(500, time.time() - start_time)
                print(f"  错误: {e}")

    # 打印统计信息
    print("\n=== 统计信息 ===")
    stats = rate_limiter.get_stats()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"{key}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        else:
            print(f"{key}: {value}")


if __name__ == "__main__":
    # 运行示例
    asyncio.run(example_usage())