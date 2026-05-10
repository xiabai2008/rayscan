"""测试多个靶机"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import httpx
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.xss.detector import XSSDetector
from wvs.modules.lfi.detector import LFIDetector

# 靶机列表
TARGETS = [
    {
        "name": "Metasploitable2 DVWA",
        "url": "http://192.168.18.131/dvwa",
        "auth": {"login": "/login.php", "user": "admin", "pass": "password"},
    },
    {
        "name": "Metasploitable2 Mutillidae",
        "url": "http://192.168.18.131/mutillidae",
        "auth": None,  # 无需登录
    },
    {
        "name": "Metasploitable2 WebDAV",
        "url": "http://192.168.18.131/dav",
        "auth": None,
    },
]

async def test_target(target):
    """测试单个靶机"""
    print(f"\n{'=' * 60}")
    print(f"[*] 测试: {target['name']}")
    print(f"    URL: {target['url']}")
    print('=' * 60)
    
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        # 检查是否在线
        try:
            r = await c.get(target['url'])
            print(f"[OK] 在线 - 状态: {r.status_code}")
        except Exception as e:
            print(f"[X] 离线 - {e}")
            return
        
        # 查找测试点
        print(f"\n[1] 查找测试点...")
        
        # 常见漏洞页面
        test_paths = [
            "/?id=1",
            "/index.php?id=1",
            "/page.php?id=1",
            "/vulnerabilities/",
            "/admin/",
        ]
        
        found_pages = []
        for path in test_paths:
            try:
                url = target['url'].rstrip('/') + path
                r = await c.get(url)
                if r.status_code == 200 and len(r.text) > 100:
                    found_pages.append((url, len(r.text)))
                    print(f"    发现: {url} ({len(r.text)} bytes)")
            except:
                pass
        
        if not found_pages:
            print("    未找到测试页面")
            return
        
        # 测试 SQLi
        print(f"\n[2] 测试 SQLi...")
        config = ConfigManager()
        session = HTTPPool(config)
        
        for url, _ in found_pages[:3]:
            if '?' in url:
                try:
                    # 解析参数
                    from urllib.parse import urlparse, parse_qs
                    parsed = urlparse(url)
                    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                    
                    if not params:
                        continue
                    
                    target_obj = ScanTarget(url=url.split('?')[0], params=params)
                    detector = SQLiDetector(config=config, session=session)
                    
                    vulns = await asyncio.wait_for(detector.scan(target_obj), timeout=30)
                    if vulns:
                        print(f"    [!] {url}: 发现 {len(vulns)} 个 SQLi")
                        for v in vulns:
                            print(f"        - {v.parameter}: {v.payload[:30]}")
                        break
                except asyncio.TimeoutError:
                    print(f"    [TIMEOUT] {url}")
                except Exception as e:
                    pass
        
        await session.close()

async def main():
    print("=" * 60)
    print("WVS v19 - 多靶机测试")
    print("=" * 60)
    
    for target in TARGETS:
        await test_target(target)
    
    print("\n" + "=" * 60)
    print("[OK] 测试完成")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
