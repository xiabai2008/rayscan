#!/usr/bin/env python
"""
WVS v19 快速使用示例

演示 programmatic API 用法，不依赖 CLI
"""
import asyncio
import sys
from pathlib import Path

# 添加 wvs 到 path
sys.path.insert(0, str(Path(__file__).parent.parent))

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget
from wvs.modules import register_all_modules
from wvs.plugins.auth import AuthManager
from wvs.reporting import ConsoleReporter


async def basic_scan(url: str):
    """最简扫描"""
    print(f"[*] 扫描 {url}")
    config = ConfigManager()
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    target = ScanTarget(url=url)
    result = await scanner.scan(target)
    await session.close()

    reporter = ConsoleReporter()
    reporter.report(result)


async def auth_scan(url: str, login_url: str, username: str, password: str):
    """带表单认证的扫描"""
    print(f"[*] 带认证扫描 {url}")

    config = ConfigManager()
    auth = AuthManager(config)

    # 配置表单认证
    auth.configure_form_login(
        login_url=login_url,
        username=username,
        password=password,
        # 可选：额外表单字段（如 CSRF token）
        # extra_fields={"csrf_token": "abc123"},
    )

    # 执行认证
    import httpx
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as tmp_client:
        result = await auth.authenticate(tmp_client)

    if not auth.is_authenticated:
        print(f"[✗] 认证失败: {auth.auth_error}")
        return

    # 构建带认证的扫描目标
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    target = ScanTarget(url=url)
    auth.apply_to_target(target)

    scan_result = await scanner.scan(target)
    await session.close()

    reporter = ConsoleReporter()
    reporter.report(scan_result)


async def selective_modules_scan(url: str, modules: list[str]):
    """只扫描指定模块"""
    print(f"[*] 扫描 {url}（模块: {', '.join(modules)}）")
    config = ConfigManager()
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)

    for mod in modules:
        scanner.load_module(mod)

    target = ScanTarget(url=url)
    result = await scanner.scan(target)
    await session.close()

    reporter = ConsoleReporter()
    reporter.report(result)


async def bearer_token_scan(url: str, token: str):
    """Bearer Token 认证扫描"""
    config = ConfigManager()
    auth = AuthManager(config)
    auth.configure_bearer(token=token)

    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    target = ScanTarget(url=url)
    auth.apply_to_target(target)

    result = await scanner.scan(target)
    await session.close()

    reporter = ConsoleReporter()
    reporter.report(result)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WVS v19 示例")
    parser.add_argument("url", help="目标 URL")
    parser.add_argument("--modules", nargs="+", help="指定模块")
    parser.add_argument("--auth-form", action="store_true", help="表单认证")
    parser.add_argument("--login-url", help="登录 URL")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--bearer", help="Bearer Token")

    args = parser.parse_args()

    if args.auth_form:
        asyncio.run(auth_scan(args.url, args.login_url, args.username, args.password))
    elif args.bearer:
        asyncio.run(bearer_token_scan(args.url, args.bearer))
    elif args.modules:
        asyncio.run(selective_modules_scan(args.url, args.modules))
    else:
        asyncio.run(basic_scan(args.url))
