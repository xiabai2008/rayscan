#!/usr/bin/env python3
"""WVS v19 简单测试 - 单模块"""
import asyncio
import sys
import time
import logging

# 设置日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(name)s %(levelname)s %(message)s')

sys.path.insert(0, r'C:\Users\HZR\.openclaw\workspace\wvs-v19')

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector

DVWA = "http://47.95.192.41:8081"

async def main():
    print("Starting...")
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    # DVWA auth
    print("Authenticating...")
    await session.request("GET", f"{DVWA}/login.php")
    await session.request("POST", f"{DVWA}/login.php", 
        data={"username": "admin", "password": "password", "Login": "Login"})
    await session.request("GET", f"{DVWA}/security.php",
        params={"security": "low", "seclev_submit": "Submit"})
    print("Auth done")
    
    # SQLi test - single param, error-based only
    print("\nTesting SQLi error-based only...")
    det = SQLiDetector(config=config, session=session)
    
    # 设置短的测试
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/sqli/", params={"id": "1"})
    
    start = time.time()
    try:
        # 只测 error-based
        await det._test_error_based(
            f"{DVWA}/vulnerabilities/sqli/", 
            {"id": "1"}, 
            "id", "1", 
            "GET", "query", 
            {"status_code": 200, "text": "normal"}
        )
    except Exception as e:
        print(f"Error: {e}")
    
    elapsed = time.time() - start
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Found vulns: {len(det._found_vulns)}")
    
    await session.close()

if __name__ == "__main__":
    asyncio.run(main())
