"""
RayScan intelligent rate limiting system.

Components:
- RateLimiter: Sliding window rate limiter (RPS control)
- AdaptiveRateLimiter: Dynamically adjusts rate based on response times and status codes
- WAFEvasion: Random intervals, UA rotation, request pattern variation
- IntelligentRateLimiter: Integrates all of the above

Thread-safe, async-compatible, with burst/uniform modes.
"""

import asyncio
import time
import random
import statistics
from dataclasses import dataclass
from typing import List, Dict, Deque
from collections import deque
from enum import Enum
import secrets


class RateLimitMode(Enum):
    """Rate limit mode enumeration"""

    BURST = "burst"
    UNIFORM = "uniform"


class HealthStatus(Enum):
    """Health status enumeration"""

    HEALTHY = "healthy"
    WARNING = "warning"
    THROTTLED = "throttled"


@dataclass
class RateLimitMetrics:
    """Rate limit metrics collector"""

    request_count: int = 0
    success_count: int = 0
    error_count: int = 0
    total_response_time: float = 0.0
    last_status_code: int = 0
    last_response_time: float = 0.0
    window_start_time: float = 0.0

    def reset(self):
        """Reset metrics"""
        self.request_count = 0
        self.success_count = 0
        self.error_count = 0
        self.total_response_time = 0.0


class RateLimiter:
    """
    Sliding window request limiter

    Implements RPS (requests per second) control based on time windows, supporting burst and uniform modes.
    """

    def __init__(self, max_rps: int = 10, window_size: float = 1.0, mode: RateLimitMode = RateLimitMode.BURST):
        self.max_rps = max_rps
        self.window_size = window_size
        self.mode = mode

        self.request_timestamps: Deque[float] = deque()
        self.metrics = RateLimitMetrics()
        self.metrics.window_start_time = time.time()
        self._lock = asyncio.Lock()
        self._last_request_time = 0.0

    async def acquire(self, n: int = 1) -> float:
        """Wait until n requests can be sent"""
        if self.max_rps <= 0:
            return 0.0

        async with self._lock:
            if self.mode == RateLimitMode.BURST:
                return await self._acquire_burst(n)
            else:
                return await self._acquire_uniform(n)

    async def _acquire_burst(self, n: int) -> float:
        """Burst mode: allows burst requests"""
        current_time = time.time()

        cutoff_time = current_time - self.window_size
        while self.request_timestamps and self.request_timestamps[0] < cutoff_time:
            self.request_timestamps.popleft()

        wait_time = 0.0

        if len(self.request_timestamps) + n > self.max_rps:
            oldest_timestamp = self.request_timestamps[0]
            wait_time = max(0.0, oldest_timestamp + self.window_size - current_time)

            current_time += wait_time

            cutoff_time = current_time - self.window_size
            while self.request_timestamps and self.request_timestamps[0] < cutoff_time:
                self.request_timestamps.popleft()

        for _ in range(n):
            self.request_timestamps.append(current_time)

        self.metrics.request_count += n

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        return wait_time

    async def _acquire_uniform(self, n: int) -> float:
        """Uniform mode: evenly distribute requests"""
        current_time = time.time()
        wait_time = 0.0

        if self._last_request_time > 0:
            min_interval = 1.0 / self.max_rps
            time_since_last = current_time - self._last_request_time
            if time_since_last < min_interval * n:
                wait_time = min_interval * n - time_since_last

        self._last_request_time = current_time + wait_time
        self.metrics.request_count += n

        if wait_time > 0:
            await asyncio.sleep(wait_time)

        return wait_time

    def update_metrics(self, status_code: int, response_time: float):
        """Update request metrics"""
        self.metrics.last_status_code = status_code
        self.metrics.last_response_time = response_time
        self.metrics.total_response_time += response_time

        if 200 <= status_code < 400:
            self.metrics.success_count += 1
        else:
            self.metrics.error_count += 1

    def get_current_rps(self) -> float:
        """Get current RPS (within sliding window)"""
        current_time = time.time()
        cutoff_time = current_time - self.window_size

        while self.request_timestamps and self.request_timestamps[0] < cutoff_time:
            self.request_timestamps.popleft()

        return len(self.request_timestamps) / self.window_size

    def get_metrics(self) -> Dict:
        """Get complete metrics information"""
        return {
            "max_rps": self.max_rps,
            "current_rps": self.get_current_rps(),
            "request_count": self.metrics.request_count,
            "success_count": self.metrics.success_count,
            "error_count": self.metrics.error_count,
            "avg_response_time": (self.metrics.total_response_time / self.metrics.request_count if self.metrics.request_count > 0 else 0.0),
            "error_rate": (self.metrics.error_count / self.metrics.request_count if self.metrics.request_count > 0 else 0.0),
            "window_size": self.window_size,
            "mode": self.mode.value,
        }

    def reset(self):
        """Reset limiter state"""
        self.request_timestamps.clear()
        self.metrics.reset()
        self.metrics.window_start_time = time.time()
        self._last_request_time = 0.0


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter

    Dynamically adjusts RPS based on response metrics:
    1. Response time increases => reduce rate
    2. 429/503 status codes => exponential backoff
    3. Success rate decreases => reduce rate
    4. Gradually recover rate after a period without errors
    """

    def __init__(
        self,
        max_rps: int = 10,
        window_size: float = 1.0,
        mode: RateLimitMode = RateLimitMode.BURST,
        min_rps: int = 1,
        recovery_rate: float = 0.1,
        backoff_factor: float = 2.0,
    ):
        super().__init__(max_rps, window_size, mode)
        self.original_max_rps = max_rps
        self.min_rps = min_rps
        self.recovery_rate = recovery_rate
        self.backoff_factor = backoff_factor

        self.health_status = HealthStatus.HEALTHY
        self.last_adjustment_time = time.time()
        self.adjustment_cooldown = 5.0

        self.response_time_history: List[float] = []
        self.status_code_history: List[int] = []
        self.history_size = 20

        self.is_in_backoff = False
        self.backoff_until = 0.0
        self.backoff_count = 0

    def update_metrics(self, status_code: int, response_time: float):
        """Update metrics and potentially trigger adaptive adjustment"""
        super().update_metrics(status_code, response_time)

        self.response_time_history.append(response_time)
        self.status_code_history.append(status_code)
        if len(self.response_time_history) > self.history_size:
            self.response_time_history.pop(0)
            self.status_code_history.pop(0)

        if status_code in [429, 503]:
            self._trigger_backoff()

        current_time = time.time()
        if current_time - self.last_adjustment_time >= self.adjustment_cooldown:
            self._adaptive_adjust()
            self.last_adjustment_time = current_time

    def _trigger_backoff(self):
        """Trigger backoff mechanism (exponential backoff)"""
        self.is_in_backoff = True
        self.backoff_count += 1

        backoff_time = min(60.0, 5.0 * (self.backoff_factor**self.backoff_count))
        self.backoff_until = time.time() + backoff_time

        self.max_rps = max(self.min_rps, int(self.max_rps // self.backoff_factor))

        self.health_status = HealthStatus.THROTTLED

    def _adaptive_adjust(self):
        """Perform adaptive adjustment based on historical data"""
        if self.is_in_backoff and time.time() >= self.backoff_until:
            self.is_in_backoff = False
            self.health_status = HealthStatus.HEALTHY

        if len(self.response_time_history) < 5:
            return

        avg_response_time = statistics.mean(self.response_time_history)
        error_rate = self.metrics.error_count / max(1, self.metrics.request_count)

        if error_rate > 0.3:
            new_status = HealthStatus.THROTTLED
        elif error_rate > 0.1 or avg_response_time > 2.0:
            new_status = HealthStatus.WARNING
        else:
            new_status = HealthStatus.HEALTHY

        if new_status != self.health_status:
            self.health_status = new_status

            if new_status == HealthStatus.HEALTHY:
                self.max_rps = min(self.original_max_rps, int(self.max_rps * (1.0 + self.recovery_rate)))
            elif new_status == HealthStatus.WARNING:
                self.max_rps = max(self.min_rps, int(self.max_rps * 0.8))
            elif new_status == HealthStatus.THROTTLED:
                self.max_rps = max(self.min_rps, int(self.max_rps * 0.5))

    async def acquire(self, n: int = 1) -> float:
        """Override acquire method, wait during backoff period"""
        if self.is_in_backoff:
            current_time = time.time()
            if current_time < self.backoff_until:
                wait_time = self.backoff_until - current_time
                await asyncio.sleep(wait_time)

        return await super().acquire(n)

    def get_health_status(self) -> Dict:
        """Get health status information"""
        return {
            "status": self.health_status.value,
            "is_in_backoff": self.is_in_backoff,
            "backoff_until": self.backoff_until,
            "backoff_count": self.backoff_count,
            "current_max_rps": self.max_rps,
            "original_max_rps": self.original_max_rps,
            "min_rps": self.min_rps,
            "recovery_rate": self.recovery_rate,
        }


class WAFEvasion:
    """
    WAF evasion strategies

    Implements various WAF evasion techniques:
    1. Random request intervals (jitter)
    2. User-Agent rotation
    3. Request header variation
    4. Request pattern variation
    """

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

    LANGUAGES = [
        "en-US,en;q=0.9",
        "zh-CN,zh;q=0.9,en;q=0.8",
        "ja-JP,ja;q=0.9,en;q=0.8",
        "ko-KR,ko;q=0.9,en;q=0.8",
        "es-ES,es;q=0.9,en;q=0.8",
        "fr-FR,fr;q=0.9,en;q=0.8",
        "de-DE,de;q=0.9,en;q=0.8",
    ]

    ACCEPT_TYPES = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    ]

    def __init__(self, enable_jitter: bool = True, enable_rotation: bool = True, jitter_range: float = 0.3):
        self.enable_jitter = enable_jitter
        self.enable_rotation = enable_rotation
        self.jitter_range = jitter_range
        self.current_ua_index = 0
        self.request_counter = 0

    async def apply_jitter(self, base_delay: float = 0.0) -> float:
        """Apply random jitter"""
        if not self.enable_jitter or self.jitter_range <= 0:
            return base_delay

        jitter = random.uniform(-self.jitter_range, self.jitter_range)
        actual_delay = max(0.0, base_delay + jitter)

        if actual_delay > 0:
            await asyncio.sleep(actual_delay)

        return actual_delay

    def get_evasion_headers(self) -> Dict[str, str]:
        """Get WAF evasion headers"""
        headers = {}

        if self.enable_rotation:
            self.current_ua_index = (self.current_ua_index + 1) % len(self.USER_AGENTS)
            headers["User-Agent"] = self.USER_AGENTS[self.current_ua_index]
        else:
            headers["User-Agent"] = random.choice(self.USER_AGENTS)

        if random.random() > 0.5:
            headers["Accept"] = random.choice(self.ACCEPT_TYPES)

        if random.random() > 0.5:
            headers["Accept-Language"] = random.choice(self.LANGUAGES)

        if random.random() > 0.7:
            headers["Accept-Encoding"] = random.choice(["gzip, deflate, br", "gzip, deflate"])

        if random.random() > 0.8:
            headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])

        if random.random() > 0.9:
            headers["X-Forwarded-For"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

        self.request_counter += 1
        return headers

    def randomize_request_order(self, params: Dict) -> Dict:
        """Randomize request parameter order"""
        if not params:
            return params

        items = list(params.items())
        random.shuffle(items)
        return dict(items)

    def add_redundant_parameters(self, params: Dict) -> Dict:
        """Add redundant parameters"""
        if random.random() > 0.7:
            redundant_params = {
                "timestamp": str(int(time.time())),
                "random": secrets.token_hex(4),
                "v": "1.0",
                "format": "json",
                "callback": "jQuery" + str(random.randint(1000000000, 9999999999)),
            }

            num_to_add = random.randint(1, 3)
            selected_keys = random.sample(list(redundant_params.keys()), num_to_add)

            for key in selected_keys:
                if key not in params:
                    params[key] = redundant_params[key]

        return params


class IntelligentRateLimiter:
    """
    Intelligent rate limiter

    Complete solution integrating rate limiting, adaptive adjustment, and WAF evasion.
    """

    def __init__(self, config: Dict = None):
        self.config = config or {}

        max_rps = self.config.get("max_rps", 10)
        mode_str = self.config.get("mode", "burst")
        mode = RateLimitMode.BURST if mode_str == "burst" else RateLimitMode.UNIFORM

        enable_adaptive = self.config.get("enable_adaptive", True)
        enable_waf_evasion = self.config.get("enable_waf_evasion", True)

        if enable_adaptive:
            self.rate_limiter = AdaptiveRateLimiter(
                max_rps=max_rps,
                window_size=self.config.get("window_size", 1.0),
                mode=mode,
                min_rps=self.config.get("min_rps", 1),
                recovery_rate=self.config.get("recovery_rate", 0.1),
                backoff_factor=self.config.get("backoff_factor", 2.0),
            )
        else:
            self.rate_limiter = RateLimiter(max_rps=max_rps, window_size=self.config.get("window_size", 1.0), mode=mode)

        self.waf_evasion = (
            WAFEvasion(
                enable_jitter=self.config.get("enable_jitter", True),
                enable_rotation=self.config.get("enable_rotation", True),
                jitter_range=self.config.get("jitter_range", 0.3),
            )
            if enable_waf_evasion
            else None
        )

        self.total_requests = 0
        self.total_wait_time = 0.0

    async def acquire(self, n: int = 1) -> float:
        """Wait until requests can be sent"""
        wait_time = await self.rate_limiter.acquire(n)
        self.total_wait_time += wait_time

        if self.waf_evasion:
            jitter_time = await self.waf_evasion.apply_jitter()
            self.total_wait_time += jitter_time
            wait_time += jitter_time

        self.total_requests += n
        return wait_time

    def update_metrics(self, status_code: int, response_time: float):
        """Update request metrics"""
        self.rate_limiter.update_metrics(status_code, response_time)

    def get_evasion_headers(self) -> Dict[str, str]:
        """Get WAF evasion headers"""
        if self.waf_evasion:
            return self.waf_evasion.get_evasion_headers()
        return {}

    def randomize_request(self, params: Dict) -> Dict:
        """Randomize request parameters"""
        if not self.waf_evasion:
            return params

        params = self.waf_evasion.randomize_request_order(params)
        params = self.waf_evasion.add_redundant_parameters(params)

        return params

    def get_stats(self) -> Dict:
        """Get complete statistics"""
        stats = {
            "total_requests": self.total_requests,
            "total_wait_time": self.total_wait_time,
            "avg_wait_time_per_request": (self.total_wait_time / self.total_requests if self.total_requests > 0 else 0.0),
            "rate_limiter": self.rate_limiter.get_metrics(),
        }

        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            stats["adaptive_status"] = self.rate_limiter.get_health_status()

        if self.waf_evasion:
            stats["waf_evasion"] = {
                "enabled": True,
                "request_counter": self.waf_evasion.request_counter,
                "jitter_enabled": self.waf_evasion.enable_jitter,
            }

        return stats

    def reset_stats(self):
        """Reset statistics"""
        self.total_requests = 0
        self.total_wait_time = 0.0
        if isinstance(self.rate_limiter, RateLimiter):
            self.rate_limiter.reset()
