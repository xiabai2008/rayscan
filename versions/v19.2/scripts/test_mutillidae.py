"""测试 Mutillidae 靶机漏洞"""
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

MUTILLIDAE = "http://192.168.18.131/mutillidae"

# Mutillidae 已知漏洞页面
VULN_PAGES = [
    # SQLi
    ("/index.php?page=user-info.php", {"username": "admin", "password": "test", "user-info-php-submit-button": "View Account Details"}, "POST", "sqli"),
    # XSS
    ("/index.php?page=dns-lookup.php", {"target-host": "127.0.0.1", "dns-lookup-php-submit-button": "Lookup DNS"}, "POST", "xss"),
    # LFI
    ("/index.php?page=pen-test-tool-lookup.php", ["page"], "GET", "lfi"),
]

async def test_sqli(session, config):
    """测试 SQLi"""
    print("\n[1] 测试 SQLi...")
    
    url = f"{MUTILLIDAE}/index.php?page=user-info.php"
    data = {"username": "admin", "password": "test", "user-info-php-submit-button": "View Account Details"}
    
    detector = SQLiDetector(config=config, session=session)
    target = ScanTarget(url=url, data=data)
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"  发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"    - {v.type.value} [{v.parameter}] {v.payload[:40]}")
    except asyncio.TimeoutError:
        print("  [TIMEOUT]")
    except Exception as e:
        print(f"  [ERROR] {e}")

async def test_xss(session, config):
    """测试 XSS"""
    print("\n[2] 测试 XSS...")
    
    url = f"{MUTILLIDAE}/index.php?page=dns-lookup.php"
    data = {"target-host": "127.0.0.1", "dns-lookup-php-submit-button": "Lookup DNS"}
    
    detector = XSSDetector(config=config, session=session)
    target = ScanTarget(url=url, data=data)
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"  发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"    - {v.type.value} [{v.parameter}]")
    except asyncio.TimeoutError:
        print("  [TIMEOUT]")
    except Exception as e:
        print(f"  [ERROR] {e}")

async def test_lfi(session, config):
    """测试 LFI"""
    print("\n[3] 测试 LFI...")
    
    url = f"{MUTILLIDAE}/index.php"
    params = {"page": "pen-test-tool-lookup.php"}
    
    detector = LFIDetector(config=config, session=session)
    target = ScanTarget(url=url, params=params)
    
    try:
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"  发现 {len(vulns)} 个漏洞")
        for v in vulns:
            print(f"    - {v.type.value} [{v.parameter}]")
    except asyncio.TimeoutError:
        print("  [TIMEOUT]")
    except Exception as e:
        print(f"  [ERROR] {e}")

async def test_manual():
    """手动测试"""
    print("\n[4] 手动测试...")
    
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        # 测试 SQLi
        print("  [a] SQLi 手动测试...")
        data = {"username": "admin'", "password": "test", "user-info-php-submit-button": "View Account Details"}
        r = await c.post(f"{MUTILLIDAE}/index.php?page=user-info.php", data=data)
        
        if "error" in r.text.lower() or "sql" in r.text.lower():
            print("    [!] SQL 错误检测到")
        elif "admin" in r.text:
            print("    [!] 可能存在 SQLi")
        else:
            print("    未检测到")
        
        # 测试 XSS
        print("  [b] XSS 手动测试...")
        data = {"target-host": "<script>alert(1)</script>", "dns-lookup-php-submit-button": "Lookup DNS"}
        r = await c.post(f"{MUTILLIDAE}/index.php?page=dns-lookup.php", data=data)
        
        if "<script>alert(1)</script>" in r.text:
            print("    [!] XSS 反射成功")
        else:
            print("    未检测到")
        
        # 测试 LFI
        print("  [c] LFI 手动测试...")
        r = await c.get(f"{MUTILLIDAE}/index.php?page=../../../../etc/passwd")
        
        if "root:" in r.text:
            print("    [!] LFI 成功")
            # 提取
            import re
            match = re.search(r'root:[^:]+:\d+:\d+', r.text)
            if match:
                print(f"    输出: {match.group()}")
        else:
            print("    未检测到")

async def main():
    print("=" * 60)
    print("WVS v19 - Mutillidae 测试")
    print("=" * 60)
    
    # 检查靶机在线
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        try:
            r = await c.get(MUTILLIDAE)
            print(f"[OK] Mutillidae 在线 - 状态: {r.status_code}")
        except Exception as e:
            print(f"[X] Mutillidae 离线 - {e}")
            return
    
    # 创建 session
    config = ConfigManager()
    session = HTTPPool(config)
    
    # 测试各模块
    await test_sqli(session, config)
    await test_xss(session, config)
    await test_lfi(session, config)
    
    await session.close()
    
    # 手动测试
    await test_manual()
    
    print("\n" + "=" * 60)
    print("[OK] 测试完成")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
