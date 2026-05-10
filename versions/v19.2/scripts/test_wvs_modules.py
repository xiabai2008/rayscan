"""WVS v19 检测模块测试 - DVWA"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import requests
import re

from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.xss.detector import XSSDetector
from wvs.modules.cmdi.detector import CMDInjectionDetector
from wvs.modules.lfi.detector import LFIDetector

DVWA = "http://47.95.192.41:8081"

async def login_dvwa(session: HTTPPool) -> bool:
    """登录 DVWA"""
    print("[*] 登录 DVWA...")
    
    # 获取 CSRF token
    r = await session.get(f"{DVWA}/login.php")
    token_match = re.search(r"name='user_token' value='([^']+)'", r.text)
    token = token_match.group(1) if token_match else None
    
    # 登录
    data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }
    r = await session.post(f"{DVWA}/login.php", data=data, follow_redirects=True)
    
    if "index.php" in str(r.url) or "Vulnerability" in r.text:
        print("    [OK] 登录成功")
        return True
    else:
        print("    [FAIL] 登录失败")
        return False

async def test_module(module_name: str, detector_class, url: str, params: dict = None, data: dict = None):
    """测试单个检测模块"""
    print(f"\n[{module_name}] 测试...")
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    # 登录
    await login_dvwa(session)
    
    # 创建检测器
    detector = detector_class(config=config, session=session)
    
    # 创建目标
    target = ScanTarget(url=url, params=params, data=data)
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"    发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"      - {v.type.value} [{v.severity.value}] param={v.parameter}")
            if v.payload:
                print(f"        payload: {v.payload[:60]}")
        return len(vulns)
    except asyncio.TimeoutError:
        print("    [TIMEOUT]")
        return 0
    except Exception as e:
        print(f"    [ERROR] {e}")
        return 0
    finally:
        await session.close()

async def main():
    print("="*60)
    print("WVS v19 - DVWA 检测模块验证")
    print("="*60)
    
    results = {}
    
    # 1. SQLi 检测
    results['sqli'] = await test_module(
        "SQLi",
        SQLiDetector,
        f"{DVWA}/vulnerabilities/sqli/",
        params={"id": "1", "Submit": "Submit"}
    )
    
    # 2. XSS 检测
    results['xss'] = await test_module(
        "XSS",
        XSSDetector,
        f"{DVWA}/vulnerabilities/xss_r/",
        params={"name": "test"}
    )
    
    # 3. CMDi 检测
    results['cmdi'] = await test_module(
        "CMDi",
        CMDInjectionDetector,
        f"{DVWA}/vulnerabilities/exec/",
        params={"ip": "127.0.0.1", "Submit": "Submit"}
    )
    
    # 4. LFI 检测
    results['lfi'] = await test_module(
        "LFI",
        LFIDetector,
        f"{DVWA}/vulnerabilities/fi/",
        params={"page": "include.php"}
    )
    
    # 汇总
    print("\n" + "="*60)
    print("检测结果汇总")
    print("="*60)
    total = 0
    for name, count in results.items():
        status = "✓" if count > 0 else "✗"
        print(f"  [{status}] {name.upper()}: {count} 个漏洞")
        total += count
    print(f"\n总计: {total} 个漏洞")
    
    if total >= 2:
        print("\n[OK] WVS v19 检测模块验证通过!")
    else:
        print("\n[WARN] 检测模块可能需要优化")

if __name__ == "__main__":
    asyncio.run(main())
