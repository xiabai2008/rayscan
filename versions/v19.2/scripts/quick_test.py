#!/usr/bin/env python3
"""WVS v19 快速测试"""
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

DVWA = "http://47.95.192.41:8081"

async def dvwa_auth(session):
    """DVWA login"""
    await session.request("GET", f"{DVWA}/login.php")
    await session.request("POST", f"{DVWA}/login.php", 
        data={"username": "admin", "password": "password", "Login": "Login"})
    await session.request("GET", f"{DVWA}/security.php",
        params={"security": "low", "seclev_submit": "Submit"})
    print("[+] DVWA auth done")

async def test_sqli(session, config):
    print("\n[SQLi] Testing...")
    start = time.time()
    det = SQLiDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/sqli/", params={"id": "1"})
    vulns = await asyncio.wait_for(det.scan(target), timeout=60)
    print(f"    Found: {len(vulns)} vulns ({time.time()-start:.1f}s)")
    for v in vulns:
        print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter} payload={v.payload[:30] if v.payload else ''}")

async def test_cmdi(session, config):
    print("\n[CMDi] Testing...")
    start = time.time()
    det = CMDInjectionDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/exec/", data={"ip": "127.0.0.1", "Submit": "Submit"})
    vulns = await asyncio.wait_for(det.scan(target), timeout=60)
    print(f"    Found: {len(vulns)} vulns ({time.time()-start:.1f}s)")
    for v in vulns:
        print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter} evidence={v.evidence[:30] if v.evidence else ''}")

async def test_xss(session, config):
    print("\n[XSS] Testing...")
    start = time.time()
    det = XSSDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/xss_r/", params={"name": "test"})
    vulns = await asyncio.wait_for(det.scan(target), timeout=60)
    print(f"    Found: {len(vulns)} vulns ({time.time()-start:.1f}s)")
    for v in vulns:
        print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter}")

async def test_lfi(session, config):
    print("\n[LFI] Testing...")
    start = time.time()
    det = LFIDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/fi/", params={"page": "include.php"})
    vulns = await asyncio.wait_for(det.scan(target), timeout=60)
    print(f"    Found: {len(vulns)} vulns ({time.time()-start:.1f}s)")
    for v in vulns:
        print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter}")

async def main():
    print("="*60)
    print("WVS v19 Quick Test - DVWA")
    print("="*60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    try:
        await dvwa_auth(session)
        await test_sqli(session, config)
        await test_cmdi(session, config)
        await test_xss(session, config)
        await test_lfi(session, config)
    finally:
        await session.close()
    
    print("\n" + "="*60)
    print("Done")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
