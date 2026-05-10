import httpx
import re

# 测试 Pikachu SQLi
url = "http://47.95.192.41:8082/vul/sqli/sqli_str.php"
r = httpx.get(url, params={"name": "1'"}, timeout=10)
print(f"Status: {r.status_code}")
print(f"Length: {len(r.text)}")

# 检查错误信息
error_keywords = ['error', 'syntax', 'warning', 'mysql', 'sql']
found = [k for k in error_keywords if k in r.text.lower()]
print(f"Found keywords: {found}")

# 提取页面主要内容
# 检查是否有查询结果
if 'uid' in r.text or 'root' in r.text or 'admin' in r.text:
    print("Found database content!")

# 检查是否有 You have an error
if 'you have an error' in r.text.lower():
    print("SQL Error detected!")
    match = re.search(r'(you have an error[^<]{0,300})', r.text, re.IGNORECASE)
    if match:
        print(f"Error: {match.group(1)}")

# 打印部分响应内容查找关键信息
start = r.text.find('<body')
if start > 0:
    body = r.text[start:start+2000]
    # 查找 form 或 input
    if 'form' in body:
        print("Form found")
