"""测试优化后的 CMDi 和 LFI 检测"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import requests
import re

from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.modules.cmdi.detector import CMDInjectionDetector
from wvs.modules.lfi.detector import LFIDetector

DVWA = "http://47.95.192.41:8081"

async def login(session: HTTPPool):
    """登录 DVWA"""
    r = await session.get(f"{DVWA}/login.php")
    token = re.search(r"name='user_token' value='([^']+)'", r.text)
    if token:
        await session.post(
            f"{DVWA}/login.php",
            data={"username": "admin", "password": "password", "Login": "Login", "user_token": token.group(1)},
            follow_redirects=True
        )
        print("[OK] 登录成功")

async def test_cmdi():
    """测试 CMDi 检测"""
    print("\n" + "="*60)
    print("[CMDi] 测试优化后的检测器")
    print("="*60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    await login(session)
    
    detector = CMDInjectionDetector(config=config, session=session)
    
    # DVWA CMDi 页面 - 需要测试 POST
    target = ScanTarget(
        url=f"{DVWA}/vulnerabilities/exec/",
        params={"ip": "127.0.0.1", "Submit": "Submit"}
    )
    
    print(f"\n[*] 扫描: {target.url}")
    print(f"    参数: {target.params}")
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"\n[结果] 发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter}")
            if v.payload:
                print(f"      payload: {v.payload[:50]}")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        await session.close()

async def test_lfi():
    """测试 LFI 检测"""
    print("\n" + "="*60)
    print("[LFI] 测试优化后的检测器")
    print("="*60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    await login(session)
    
    detector = LFIDetector(config=config, session=session)
    
    # DVWA LFI 页面
    target = ScanTarget(
        url=f"{DVWA}/vulnerabilities/fi/",
        params={"page": "include.php"}
    )
    
    print(f"\n[*] 扫描: {target.url}")
    print(f"    参数: {target.params}")
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"\n[结果] 发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter}")
            if v.payload:
                print(f"      payload: {v.payload[:50]}")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        await session.close()

async def main():
    print("="*60)
    print("WVS v19 - CMDi/LFI 检测优化验证")
    print("="*60)
    
    await test_cmdi()
    await test_lfi()
    
    print("\n" + "="*60)
    print("测试完成")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
