"""正确的 DVWA 测试 - 使用 set_cookie 注入 cookies"""
import asyncio
import sys
import re
sys.stdout.reconfigure(encoding='utf-8')

import httpx
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.xss.detector import XSSDetector
from wvs.modules.cmdi.detector import CMDInjectionDetector
from wvs.modules.lfi.detector import LFIDetector

DVWA = "http://192.168.18.131/dvwa"

async def main():
    print("=" * 60)
    print("WVS v19 - DVWA 正确测试")
    print("=" * 60)
    
    # 步骤 1: 登录并设置 security
    print("\n[1] 登录 DVWA...")
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        await c.get(f"{DVWA}/login.php")
        await c.post(f"{DVWA}/login.php", data={"username": "admin", "password": "password", "Login": "Login"})
        
        r = await c.get(f"{DVWA}/security.php")
        m = re.search(r"user_token'\s*value\s*=\s*'([^']+)'", r.text)
        token = m.group(1) if m else ""
        await c.post(f"{DVWA}/security.php", data={"security": "low", "seclev_submit": "Submit", "user_token": token})
        
        cookies = dict(c.cookies)
        print(f"    Cookies: {cookies}")
    
    # 步骤 2: 创建 HTTPPool 并注入 cookies
    print("\n[2] 创建 session 并注入 cookies...")
    config = ConfigManager()
    session = HTTPPool(config)
    
    # 关键：使用 set_cookie 方法
    for name, value in cookies.items():
        session.set_cookie(DVWA, name, value)
        print(f"    注入 cookie: {name}={value}")
    
    # 步骤 3: 测试 SQLi
    print("\n[3] 测试 SQLi...")
    detector = SQLiDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"})
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"    发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"      - {v.type.value} [{v.parameter}] {v.payload[:40]}")
    except asyncio.TimeoutError:
        print("    [ERROR] 超时")
    except Exception as e:
        print(f"    [ERROR] {e}")
    
    # 步骤 4: 测试 XSS
    print("\n[4] 测试 XSS...")
    detector = XSSDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/xss_r/", params={"name": "test"})
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"    发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"      - {v.type.value} [{v.parameter}]")
    except asyncio.TimeoutError:
        print("    [ERROR] 超时")
    except Exception as e:
        print(f"    [ERROR] {e}")
    
    # 步骤 5: 测试 CMDi (POST)
    print("\n[5] 测试 CMDi (POST)...")
    detector = CMDInjectionDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/exec/", data={"ip": "127.0.0.1", "submit": "submit"})
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"    发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"      - {v.type.value} [{v.parameter}] {v.payload[:40]}")
    except asyncio.TimeoutError:
        print("    [ERROR] 超时")
    except Exception as e:
        print(f"    [ERROR] {e}")
    
    # 步骤 6: 测试 LFI
    print("\n[6] 测试 LFI...")
    detector = LFIDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/fi/", params={"page": "include.php"})
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"    发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"      - {v.type.value} [{v.parameter}]")
    except asyncio.TimeoutError:
        print("    [ERROR] 超时")
    except Exception as e:
        print(f"    [ERROR] {e}")
    
    await session.close()
    print("\n" + "=" * 60)
    print("[OK] 测试完成")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
