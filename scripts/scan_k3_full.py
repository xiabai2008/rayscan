"""Kioptrix L3 — 三个改进验证"""
import asyncio
from wvs.core.scanner import WAVScanner
from wvs.config import ConfigManager
from wvs.models import ScanTarget

async def main():
    target = 'http://192.168.18.131'
    config = ConfigManager()
    scanner = WAVScanner(config)
    scanner.load_module('sqli')
    scanner.load_module('cmdi')
    scanner.load_module('xss')
    scanner.load_module('lfi')

    # target 不传 auth_config，不传 cookies → 走 DVWA auto-auth
    scan_target = ScanTarget(url=target)
    print(f'目标: {target} (无显式认证，将自动 DVWA 认证)\n')

    result = await scanner.scan(scan_target)
    print(f'\n{"="*60}')
    print(f'  耗时: {result.duration:.1f}s  请求: {result.total_requests}  漏洞: {len(result.vulnerabilities)}')
    for v in result.vulnerabilities:
        print(f'  [{v.severity.value:5s}] {v.type.value:30s} {v.url}')
    await scanner.session.close()

asyncio.run(main())
