"""批量测试服务器靶场"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import httpx
import re

TARGETS = {
    "DVWA": "http://47.95.192.41:8081",
    "Pikachu": "http://47.95.192.41:8082",
    "SQLi-Lab": "http://47.95.192.41:8083",
    "XSS-Lab": "http://47.95.192.41:8085",
}

async def check_target(name: str, url: str):
    """检查靶场是否可访问"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            
            # 检查页面特征
            features = []
            if "DVWA" in r.text:
                features.append("DVWA")
            if "pikachu" in r.text.lower():
                features.append("Pikachu")
            if "sqli" in r.text.lower() or "SQL" in r.text:
                features.append("SQLi-Lab")
            if "xss" in r.text.lower():
                features.append("XSS-Lab")
            if "upload" in r.text.lower():
                features.append("Upload-Lab")
            
            # 检查登录页面
            login_paths = ["/login.php", "/login.html", "/index.php", "/"]
            login_found = []
            for path in login_paths:
                try:
                    r2 = await client.get(f"{url}{path}")
                    if r2.status_code == 200:
                        if "login" in r2.text.lower() or "password" in r2.text.lower():
                            login_found.append(path)
                except:
                    pass
            
            return {
                "status": "OK",
                "code": r.status_code,
                "len": len(r.text),
                "features": features,
                "login_pages": login_found[:3]
            }
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}

async def explore_pikachu():
    """探索 Pikachu 靶场结构"""
    print("\n" + "="*60)
    print("Pikachu 靶场探索")
    print("="*60)
    
    base = TARGETS["Pikachu"]
    
    async with httpx.AsyncClient(timeout=10) as client:
        # 首页
        r = await client.get(base)
        print(f"\n首页: {r.status_code}, 长度: {len(r.text)}")
        
        # 查找漏洞模块链接
        links = re.findall(r'href="([^"]*vul[^"]*)"', r.text, re.I)
        if links:
            print(f"\n发现漏洞模块: {len(links)} 个")
            for link in links[:10]:
                print(f"  - {link}")
        
        # 检查常见漏洞页面
        vuln_paths = [
            "/vul/sqli/sqli_str.php",
            "/vul/xss/xss_reflected.php",
            "/vul/rce/rce.php",
            "/vul/fileinclude/fi_local.php",
        ]
        
        print("\n检测漏洞页面:")
        for path in vuln_paths:
            try:
                r = await client.get(f"{base}{path}")
                if r.status_code == 200:
                    # 检查是否有表单
                    has_form = "form" in r.text.lower()
                    has_input = "input" in r.text.lower()
                    print(f"  [OK] {path} (form={has_form}, input={has_input})")
            except:
                pass

async def explore_sqli_lab():
    """探索 SQLi-Lab 靶场"""
    print("\n" + "="*60)
    print("SQLi-Lab 靶场探索")
    print("="*60)
    
    base = TARGETS["SQLi-Lab"]
    
    async with httpx.AsyncClient(timeout=10) as client:
        # 首页
        r = await client.get(base)
        print(f"\n首页: {r.status_code}, 长度: {len(r.text)}")
        
        # SQLi-Lab 通常是 Less-1 到 Less-65
        # 测试 Less-1 (GET - Error based - Single quotes)
        print("\n测试 Less-1:")
        try:
            r = await client.get(f"{base}/Less-1/?id=1")
            print(f"  Less-1/?id=1: {r.status_code}, 长度: {len(r.text)}")
            
            # 测试注入
            r = await client.get(f"{base}/Less-1/?id=1'")
            if "error" in r.text.lower() or "syntax" in r.text.lower():
                print(f"  [!] SQLi 可能存在 (单引号报错)")
        except Exception as e:
            print(f"  ERROR: {e}")

async def explore_xss_lab():
    """探索 XSS-Lab 靶场"""
    print("\n" + "="*60)
    print("XSS-Lab 靶场探索")
    print("="*60)
    
    base = TARGETS["XSS-Lab"]
    
    async with httpx.AsyncClient(timeout=10) as client:
        # 首页
        r = await client.get(base)
        print(f"\n首页: {r.status_code}, 长度: {len(r.text)}")
        
        # 查找 level 链接
        levels = re.findall(r'level([0-9]+)', r.text)
        if levels:
            print(f"\n发现关卡: {sorted(set(levels))[:10]}")
        
        # 测试 Level 1
        print("\n测试 Level 1:")
        try:
            r = await client.get(f"{base}/level1.php?name=test")
            if "test" in r.text:
                print(f"  Level 1 可访问, 参数 name 回显")
                # 测试 XSS
                r = await client.get(f"{base}/level1.php?name=<script>alert(1)</script>")
                if "<script>alert(1)</script>" in r.text:
                    print(f"  [!] XSS 可能存在")
        except Exception as e:
            print(f"  ERROR: {e}")

async def main():
    print("="*60)
    print("服务器靶场批量检测")
    print("="*60)
    
    # 1. 检查所有靶场可用性
    print("\n[1] 靶场可用性检查:")
    for name, url in TARGETS.items():
        result = await check_target(name, url)
        if result["status"] == "OK":
            print(f"  [{name}] ✅ {result['code']} | {result['len']} bytes | {result['features'][:2]}")
        else:
            print(f"  [{name}] ❌ {result['error']}")
    
    # 2. 探索每个靶场
    await explore_pikachu()
    await explore_sqli_lab()
    await explore_xss_lab()
    
    print("\n" + "="*60)
    print("检测完成")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
