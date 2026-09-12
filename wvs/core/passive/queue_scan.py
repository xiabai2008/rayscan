"""passive→active 联动共享实现（v2.3 T3.1 自 cli.py 转正）。

CLI（`rayscan scan --from-proxy`）与 Web UI（被动捕获队列定向扫描）共用:
- apply_gentle_rate_cap: 联动速率上限取 gentle 预设（用户更低速率优先）
- queue_endpoint_to_target: 队列端点 → ScanTarget（按参数类型分流）
- scan_proxy_queue: 定向主动验证（不爬取，复用已加载模块）
"""

from __future__ import annotations

import asyncio
import logging

from rich.console import Console

from ...config import ConfigManager
from ...models import ScanResult, ScanTarget

logger = logging.getLogger(__name__)
console = Console()


def apply_gentle_rate_cap(config: ConfigManager) -> int:
    """--from-proxy 联动扫描的速率上限取 gentle 预设（被动流量授权面,强制低速）。

    用户显式给出的更低速率先于上限生效(取 min);gentle 预设不可用时回退
    当前默认上限并告警。返回生效速率。
    """
    from ...profiles import ProfileManager

    gentle_rate = None
    try:
        profile = ProfileManager().load_profile("gentle")
        if profile:
            gentle_rate = (profile.get("params") or {}).get("rate")
    except Exception as e:  # noqa: BLE001
        logger.debug("gentle 预设读取失败: %s", e)
    try:
        gentle_rate = int(gentle_rate)
    except (TypeError, ValueError):
        gentle_rate = 0
    if gentle_rate <= 0:
        gentle_rate = int(config.get("max_requests_per_second", 10) or 10)
        console.print(f"[yellow][!] gentle 预设不可用,联动速率回退默认上限 {gentle_rate} req/s[/yellow]")
    current = int(config.get("rate", 10) or 10)
    effective = min(current, gentle_rate)
    config.set("rate", effective)
    config.set("max_requests_per_second", effective)
    return effective


def queue_endpoint_to_target(ep) -> ScanTarget:
    """队列端点 → ScanTarget（按参数类型分流：query→params、body/json→data、cookie→cookies）。"""
    params = {}
    data = {}
    cookies = {}
    ptypes = getattr(ep, "param_types", None) or {}
    for k, v in (getattr(ep, "parameters", None) or {}).items():
        t = ptypes.get(k, "query")
        if t == "cookie":
            cookies[k] = v
        elif t == "query":
            params[k] = v
        else:  # body / json
            data[k] = v
    method = (getattr(ep, "method", None) or "GET").upper()
    return ScanTarget(
        url=getattr(ep, "url", ""),
        methods=[method],
        params=params or None,
        data=data or None,
        cookies=cookies or None,
        param_types=dict(ptypes) or None,
    )


async def scan_proxy_queue(scanner, session, endpoints, target_url: str, concurrency: int, queue_result) -> ScanResult:
    """--from-proxy 定向主动验证：队列端点逐个交给已加载模块（不爬取,复用现有模块）。

    限速由 HTTPPool 内置 RateLimiter 统一执行（联动模式速率上限=gentle 预设）;
    端点间并发由 semaphore 控制（与主动扫描 concurrent_endpoints 同源）。
    发现随做随写入 queue_result（超时/中断可抢救）,返回前去重。
    """
    sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def verify_one(ep):
        async with sem:
            ep_target = queue_endpoint_to_target(ep)
            for mod_name, module in list(scanner._modules.items()):
                try:
                    vulns = await module.scan(ep_target)
                except Exception as e:  # noqa: BLE001
                    logger.debug("[FromProxy] 模块 %s 对 %s 检测失败: %s", mod_name, getattr(ep, "url", ep), e)
                    continue
                for v in vulns or []:
                    if not v.module:
                        v.module = mod_name
                    if isinstance(getattr(v, "context", None), dict):
                        v.context.setdefault("source", "proxy_queue")
                    queue_result.vulnerabilities.append(v)

    await asyncio.gather(*(verify_one(ep) for ep in endpoints))

    seen = set()
    unique = []
    for v in queue_result.vulnerabilities:
        sig = f"{v.type.value}|{v.url or ''}|{v.parameter or ''}|{v.payload or ''}".lower()
        if sig not in seen:
            seen.add(sig)
            unique.append(v)
    queue_result.vulnerabilities = unique
    queue_result.requests_made = session.get_stats().get("total_requests", 0)
    queue_result.modules_run = len(scanner._modules)
    queue_result.endpoints_found = len(endpoints)
    return queue_result
