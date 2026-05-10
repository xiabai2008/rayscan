"""DVWA 完整认证诊断"""
import asyncio
import aiohttp
import re

async def test():
    async with aiohttp.ClientSession() as s:
        # Step 1: Check setup.php - does DVWA need DB init?
        r = await s.get('http://192.168.18.131/dvwa/setup.php',
                        timeout=aiohttp.ClientTimeout(total=5))
        cookies_init = {k: v.value for k, v in s.cookie_jar.filter_cookies('http://192.168.18.131').items()}
        print(f"[setup.php] status={r.status} cookies={list(cookies_init.keys())}")
        setup_text = await r.text()
        print(f"  len={len(setup_text)}")
        if 'create' in setup_text.lower() or 'reset' in setup_text.lower():
            print("  Database not initialized - need to create")
            # POST to create database
            hiddens = {}
            for m in re.finditer(r'<input[^>]+type=["\']?hidden["\']?[^>]+name=["\']?([\w\-]+)["\']?[^>]+value=["\']?([^"\']*)["\']?', setup_text, re.I):
                hiddens[m.group(1)] = m.group(2)
            r2 = await s.post('http://192.168.18.131/dvwa/setup.php', data=hiddens,
                             timeout=aiohttp.ClientTimeout(total=5))
            after_setup = await r2.text()
            print(f"  setup POST status={r2.status} len={len(after_setup)}")
            if 'success' in after_setup.lower() or 'created' in after_setup.lower():
                print("  Database created!")
        else:
            print("  DB already initialized")

        # Step 2: GET login.php with session cookie
        r3 = await s.get('http://192.168.18.131/dvwa/login.php',
                         timeout=aiohttp.ClientTimeout(total=5))
        cookies_pre = {k: v.value for k, v in s.cookie_jar.filter_cookies('http://192.168.18.131').items()}
        print(f"\n[login.php] cookies={list(cookies_pre.keys())}")
        page = await r3.text()

        # Extract user_token
        token_m = re.search(r"user_token[^>]+value=['\"]([a-f0-9]{32})['\"]", page, re.I)
        token = token_m.group(1) if token_m else ''
        # Extract login button value
        login_m = re.search(r"name=['\"]login['\"]\s+value=['\"]([^'\"]+)['\"]", page, re.I)
        login_val = login_m.group(1) if login_m else 'Login'
        print(f"  user_token={token[:10] if token else 'NONE'}... login={login_val}")

        # Step 3: POST login
        post_data = {'username': 'admin', 'password': 'password',
                     'user_token': token, 'login': login_val}
        r4 = await s.post('http://192.168.18.131/dvwa/login.php', data=post_data,
                          timeout=aiohttp.ClientTimeout(total=5))
        print(f"\n[POST login] status={r4.status} url={r4.url}")
        cookies_post = {k: v.value for k, v in s.cookie_jar.filter_cookies('http://192.168.18.131').items()}
        print(f"  cookies={list(cookies_post.keys())}")

        # Step 4: Access vulnerability pages
        for path in ['/dvwa/vulnerabilities/sqli/', '/dvwa/vulnerabilities/xss_r/']:
            r5 = await s.get(f'http://192.168.18.131{path}',
                             timeout=aiohttp.ClientTimeout(total=5))
            text = await r5.text()
            on_login = '<form' in text[:600] and 'password' in text[:600]
            print(f"\n{path}")
            print(f"  status={r5.status} url={r5.url} len={len(text)}")
            print(f"  on_login={on_login}")
            if not on_login:
                inputs = re.findall(r'name=["\']([^"\']+)["\']', text[:2000])
                print(f"  params: {inputs[:10]}")

asyncio.run(test())
