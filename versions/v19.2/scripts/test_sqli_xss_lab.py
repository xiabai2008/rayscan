"""测试 SQLi-Lab 和 XSS-Lab"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import httpx
import re

from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.xss.detector import XSSDetector

SQLI_LAB = "http://47.95.192.41:8083"
XSS_LAB = "http://47.95.192.41:8085"

async def test_sqli_lab():
    """测试 SQLi-Lab"""
    print("\n" + "="*60)
    print("SQLi-Lab 测试")
    print("="*60)
    
    async with httpx.AsyncClient(timeout=10) as client:
        # 检查首页
        r = await client.get(SQLI_LAB)
        print(f"\n首页: {r.status_code}, 长度: {len(r.text)}")
        
        # 测试 Less-1
        print("\n[Less-1] GET - Error based - Single quotes:")
        try:
            # 正常请求
            r = await client.get(f"{SQLI_LAB}/Less-1/?id=1")
            print(f"  正常: {r.status_code}, 长度: {len(r.text)}")
            
            # 单引号注入
            r = await client.get(f"{SQLI_LAB}/Less-1/?id=1'")
            if "error" in r.text.lower() or "syntax" in r.text.lower() or "mysql" in r.text.lower():
                print(f"  [!] 单引号报错 - SQLi 存在")
                # 提取错误信息
                err = re.search(r"(syntax[^<]+|error[^<]+|mysql[^<]+)", r.text, re.I)
                if err:
                    print(f"      错误: {err.group()[:80]}")
            else:
                print(f"  单引号: 无明显报错")
                
        except Exception as e:
            print(f"  ERROR: {e}")
    
    # 用 WVS 检测器测试
    print("\n[WVS SQLi 检测器]:")
    config = ConfigManager()
    session = HTTPPool(config)
    
    try:
        detector = SQLiDetector(config=config, session=session)
        target = ScanTarget(url=f"{SQLI_LAB}/Less-1/", params={"id": "1"})
        
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"  发现 {len(vulns)} 个漏洞")
        for v in vulns[:3]:
            print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter}")
            if v.payload:
                print(f"      payload: {v.payload[:50]}")
    except Exception as e:
        print(f"  ERROR: {e}")
    finally:
        await session.close()

async def test_xss_lab():
    """测试 XSS-Lab"""
    print("\n" + "="*60)
    print("XSS-Lab 测试")
    print("="*60)
    
    async with httpx.AsyncClient(timeout=10) as client:
        # 检查首页
        r = await client.get(XSS_LAB)
        print(f"\n首页: {r.status_code}, 长度: {len(r.text)}")
        
        # 查找 level 页面
        print("\n探测关卡:")
        for level in ["level1.php", "level2.php", "level1.php"]:
            try:
                r = await client.get(f"{XSS_LAB}/{level}")
                if r.status_code == 200:
                    # 检查参数
                    r2 = await client.get(f"{XSS_LAB}/{level}?name=test")
                    if "test" in r2.text:
                        print(f"  {level}?name= - 参数回显")
                        
                        # 测试 XSS
                        r3 = await client.get(f"{XSS_LAB}/{level}?name=<script>alert(1)</script>")
                        if "<script>alert(1)</script>" in r3.text:
                            print(f"    [!] XSS 存在")
                        break
            except:
                pass
    
    # 用 WVS 检测器测试
    print("\n[WVS XSS 检测器]:")
    config = ConfigManager()
    session = HTTPPool(config)
    
    try:
        detector = XSSDetector(config=config, session=session)
        target = ScanTarget(url=f"{XSS_LAB}/level1.php", params={"name": "test"})
        
        vulns = await asyncio.wait_for(detector.scan(target), timeout=60)
        print(f"  发现 {len(vulns)} 个漏洞")
        for v in vulns[:3]:
            print(f"    - {v.type.value} [{v.severity.value}] param={v.parameter}")
            if v.payload:
                print(f"      payload: {v.payload[:50]}")
    except Exception as e:
        print(f"  ERROR: {e}")
    finally:
        await session.close()

async def main():
    print("="*60)
    print("SQLi-Lab / XSS-Lab 测试")
    print("="*60)
    
    await test_sqli_lab()
    await test_xss_lab()
    
    print("\n" + "="*60)
    print("测试完成")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
