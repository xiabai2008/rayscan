"""测试 CMDi 模块 - 使用 POST 请求"""
import asyncio
import sys
import re
sys.stdout.reconfigure(encoding='utf-8')

import httpx
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.modules.cmdi.detector import CMDInjectionDetector

DVWA = "http://192.168.18.131/dvwa"

async def main():
    print("=" * 60)
    print("CMDi 模块测试 - POST 请求")
    print("=" * 60)
    
    # 登录并设置 security
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        await c.get(f"{DVWA}/login.php")
        await c.post(f"{DVWA}/login.php", data={"username": "admin", "password": "password", "Login": "Login"})
        r = await c.get(f"{DVWA}/security.php")
        m = re.search(r"user_token'\s*value\s*=\s*'([^']+)'", r.text)
        token = m.group(1) if m else ""
        await c.post(f"{DVWA}/security.php", data={"security": "low", "seclev_submit": "Submit", "user_token": token})
        cookies = dict(c.cookies)
        print(f"[OK] DVWA ready (security=low)")
    
    # 创建 session
    config = ConfigManager()
    session = HTTPPool(config)
    for name, value in cookies.items():
        session.set_cookie(DVWA, name, value)
    
    # 测试 CMDi - 使用 data 参数（POST 请求）
    print("\n[1] 测试 CMDi 模块 (POST)...")
    detector = CMDInjectionDetector(config=config, session=session)
    
    # 使用 data 参数，这样会触发 POST 检测
    target = ScanTarget(
        url=f"{DVWA}/vulnerabilities/exec/",
        data={"ip": "127.0.0.1", "submit": "submit"}  # POST 参数
    )
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"  发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"    - {v.type.value} [{v.parameter}] {v.payload[:40]}")
    except asyncio.TimeoutError:
        print("  [ERROR] 超时")
    except Exception as e:
        print(f"  [ERROR] {e}")
        import traceback
        traceback.print_exc()
    
    # 测试 GET 请求（应该不工作）
    print("\n[2] 测试 CMDi 模块 (GET)...")
    target = ScanTarget(
        url=f"{DVWA}/vulnerabilities/exec/",
        params={"ip": "127.0.0.1", "Submit": "Submit"}  # GET 参数
    )
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"  发现 {len(vulns)} 个漏洞")
    except Exception as e:
        print(f"  [ERROR] {e}")
    
    await session.close()
    print("\n[OK] 测试完成")

if __name__ == "__main__":
    asyncio.run(main())
