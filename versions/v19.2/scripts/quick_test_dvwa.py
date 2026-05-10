#!/usr/bin/env python3
"""
WVS v19 快速实战测试 - 单靶机
"""
import asyncio
import sys
import time

sys.path.insert(0, r'C:\Users\HZR\.openclaw\workspace\wvs-v19')

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.cmdi.detector import CMDInjectionDetector
from wvs.modules.xss.detector import XSSDetector
from wvs.modules.lfi.detector import LFIDetector

async def test_dvwa():
    """测试 DVWA 核心漏洞"""
    print("="*60)
    print("WVS v19 快速测试 - DVWA")
    print("="*60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    # DVWA 认证
    print("\n[1] DVWA 认证...")
    from wvs.core.scanner import WAVScanner
    scanner = WAVScanner(config)
    scanner.session = session
    
    # 手动设置 DVWA cookies
    await session.request("GET", "http://47.95.192.41:8081/login.php")
    login_resp = await session.request(
        "POST", "http://47.95.192.41:8081/login.php",
        data={"username": "admin", "password": "password", "Login": "Login"}
    )
    
    # 设置安全等级
    await session.request(
        "GET", "http://47.95.192.41:8081/security.php",
        params={"security": "low", "seclev_submit": "Submit"}
    )
    
    print("    [OK] 认证完成")
    
    # 测试 SQLi
    print("\n[2] SQLi 检测...")
    sqli = SQLiDetector(config=config, session=session)
    target = ScanTarget(
        url="http://47.95.192.41:8081/vulnerabilities/sqli/",
        params={"id": "1"}
    )
    start = time.time()
    vulns = await asyncio.wait_for(sqli.scan(target), timeout=30)
    print(f"    [OK] 发现 {len(vulns)} 个 SQLi ({time.time()-start:.1f}s)")
    for v in vulns:
        print(f"        - {v.type.value} [{v.severity.value}] {v.parameter}")
    
    # 测试 CMDi
    print("\n[3] CMDi 检测...")
    cmdi = CMDInjectionDetector(config=config, session=session)
    target = ScanTarget(
        url="http://47.95.192.41:8081/vulnerabilities/exec/",
        data={"ip": "127.0.0.1", "Submit": "Submit"}
    )
    start = time.time()
    vulns = await asyncio.wait_for(cmdi.scan(target), timeout=30)
    print(f"    [OK] 发现 {len(vulns)} 个 CMDi ({time.time()-start:.1f}s)")
    for v in vulns:
        print(f"        - {v.type.value} [{v.severity.value}] {v.parameter}")
    
    # 测试 XSS
    print("\n[4] XSS 检测...")
    xss = XSSDetector(config=config, session=session)
    target = ScanTarget(
        url="http://47.95.192.41:8081/vulnerabilities/xss_r/",
        params={"name": "test"}
    )
    start = time.time()
    vulns = await asyncio.wait_for(xss.scan(target), timeout=30)
    print(f"    [OK] 发现 {len(vulns)} 个 XSS ({time.time()-start:.1f}s)")
    for v in vulns:
        print(f"        - {v.type.value} [{v.severity.value}] {v.parameter}")
    
    # 测试 LFI
    print("\n[5] LFI 检测...")
    lfi = LFIDetector(config=config, session=session)
    target = ScanTarget(
        url="http://47.95.192.41:8081/vulnerabilities/fi/",
        params={"page": "include.php"}
    )
    start = time.time()
    vulns = await asyncio.wait_for(lfi.scan(target), timeout=30)
    print(f"    [OK] 发现 {len(vulns)} 个 LFI ({time.time()-start:.1f}s)")
    for v in vulns:
        print(f"        - {v.type.value} [{v.severity.value}] {v.parameter}")
    
    await session.close()
    
    print("\n" + "="*60)
    print("测试完成")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(test_dvwa())
