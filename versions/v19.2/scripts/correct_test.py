#!/usr/bin/env python3
"""WVS v19 正确测试"""
import asyncio
import sys
import time

sys.path.insert(0, r'C:\Users\HZR\.openclaw\workspace\wvs-v19')

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.cmdi.detector import CMDInjectionDetector

DVWA = "http://47.95.192.41:8081"

async def main():
    print("="*60)
    print("WVS v19 Test")
    print("="*60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    # DVWA auth
    print("\n[1] DVWA auth...")
    await session.request("GET", f"{DVWA}/login.php")
    await session.request("POST", f"{DVWA}/login.php", 
        data={"username": "admin", "password": "password", "Login": "Login"})
    await session.request("GET", f"{DVWA}/security.php",
        params={"security": "low", "seclev_submit": "Submit"})
    print("    Done")
    
    # SQLi test - 使用 scan() 方法
    print("\n[2] SQLi test...")
    det = SQLiDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/sqli/", params={"id": "1"})
    
    start = time.time()
    vulns = await det.scan(target)  # 正确调用
    elapsed = time.time() - start
    
    print(f"    Found: {len(vulns)} vulns ({elapsed:.1f}s)")
    for v in vulns:
        print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter}")
    
    # CMDi test
    print("\n[3] CMDi test...")
    det2 = CMDInjectionDetector(config=config, session=session)
    target2 = ScanTarget(url=f"{DVWA}/vulnerabilities/exec/", data={"ip": "127.0.0.1", "Submit": "Submit"})
    
    start = time.time()
    vulns2 = await det2.scan(target2)
    elapsed = time.time() - start
    
    print(f"    Found: {len(vulns2)} vulns ({elapsed:.1f}s)")
    for v in vulns2:
        print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter} evidence={v.evidence[:30] if v.evidence else ''}")
    
    await session.close()
    print("\n" + "="*60)
    print("Done")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
