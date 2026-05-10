"""单独测试 SQLi 模块"""
import asyncio
import sys
import re
sys.stdout.reconfigure(encoding='utf-8')

import httpx
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector

DVWA = "http://192.168.18.131/dvwa"

async def main():
    print("=" * 60)
    print("SQLi 模块测试")
    print("=" * 60)
    
    # 设置 DVWA
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        await c.get(f"{DVWA}/login.php")
        await c.post(f"{DVWA}/login.php", data={"username": "admin", "password": "password", "Login": "Login"})
        r = await c.get(f"{DVWA}/security.php")
        m = re.search(r"user_token'\s*value\s*=\s*'([^']+)'", r.text)
        token = m.group(1) if m else ""
        await c.post(f"{DVWA}/security.php", data={"security": "low", "seclev_submit": "Submit", "user_token": token})
        cookies = dict(c.cookies)
        print(f"[OK] DVWA ready, cookies: {list(cookies.keys())}")
    
    # 创建 session
    config = ConfigManager()
    session = HTTPPool(config)
    session._cookie_jar["192.168.18.131"] = cookies
    
    # 测试 SQLi
    print("\n[*] 测试 SQLi 模块...")
    detector = SQLiDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"})
    
    try:
        vulns = await detector.scan(target)
        print(f"\n[结果] 发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"  - {v.type.value} ({v.severity.value}) [{v.parameter}]")
            print(f"    Payload: {v.payload[:60]}")
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
    
    await session.close()
    print("\n[OK] 完成")

if __name__ == "__main__":
    asyncio.run(main())
