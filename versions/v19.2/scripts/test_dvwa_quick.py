"""快速测试 DVWA SQLi"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import httpx

DVWA = "http://47.95.192.41:8081"

async def main():
    async with httpx.AsyncClient(timeout=10) as client:
        # 1. 访问首页
        print("[1] 访问 DVWA...")
        try:
            r = await client.get(f"{DVWA}/")
            print(f"    状态: {r.status_code}")
        except Exception as e:
            print(f"    错误: {e}")
            return
        
        # 2. 登录
        print("[2] 登录...")
        try:
            r = await client.get(f"{DVWA}/login.php")
            r = await client.post(
                f"{DVWA}/login.php",
                data={"username": "admin", "password": "password", "Login": "Login"},
                follow_redirects=True
            )
            print(f"    状态: {r.status_code}")
            print(f"    Cookie: {dict(client.cookies)}")
        except Exception as e:
            print(f"    错误: {e}")
            return
        
        # 3. 测试 SQLi 页面
        print("[3] 测试 SQLi 页面...")
        sqli_url = f"{DVWA}/vulnerabilities/sqli/"
        
        # 正常请求
        r1 = await client.get(f"{sqli_url}?id=1&Submit=Submit")
        len1 = len(r1.text)
        print(f"    正常: status={r1.status_code}, len={len1}")
        
        # 注入请求
        r2 = await client.get(f"{sqli_url}?id=1'&Submit=Submit")
        len2 = len(r2.text)
        has_error = "error" in r2.text.lower() or "syntax" in r2.text.lower()
        print(f"    注入: status={r2.status_code}, len={len2}, error={'是' if has_error else '否'}")
        
        # 4. 测试 XSS 页面
        print("[4] 测试 XSS 页面...")
        xss_url = f"{DVWA}/vulnerabilities/xss_r/"
        r = await client.get(f"{xss_url}?name=<script>alert(1)</script>")
        reflected = "<script>alert(1)</script>" in r.text
        print(f"    状态: {r.status_code}")
        print(f"    反射: {'是' if reflected else '否'}")
        
        # 5. 测试 CMDi 页面
        print("[5] 测试 CMDi 页面...")
        cmdi_url = f"{DVWA}/vulnerabilities/exec/"
        r = await client.get(f"{cmdi_url}?ip=127.0.0.1")
        print(f"    状态: {r.status_code}")
        print(f"    长度: {len(r.text)}")
        
        print("\n[OK] DVWA 可访问，存在漏洞页面")

asyncio.run(main())
