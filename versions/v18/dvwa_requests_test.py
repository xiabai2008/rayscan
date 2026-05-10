"""DVWA auth with manual cookie management"""
import asyncio
import aiohttp
import re

async def test():
    # Try with manual cookie management
    async with aiohttp.ClientSession() as s:
        # GET setup first
        r = await s.get('http://192.168.18.131/dvwa/setup.php',
                        timeout=aiohttp.ClientTimeout(total=5))
        print(f"setup.php: status={r.status}")
        setup_text = await r.text()
        # POST to create DB
        hiddens = {}
        for m in re.finditer(r'<input[^>]+type=["\']?hidden["\']?[^>]+name=["\']?([\w\-]+)["\']?[^>]+value=["\']?([^"\']*)["\']?', setup_text, re.I):
            hiddens[m.group(1)] = m.group(2)
        print(f"  hiddens={list(hiddens.keys())}")
        r2 = await s.post('http://192.168.18.131/dvwa/setup.php', data=hiddens,
                         timeout=aiohttp.ClientTimeout(total=5))
        # Check Set-Cookie header
        print(f"  POST Set-Cookie: {r2.headers.get('Set-Cookie', 'NONE')}")

    # Check: maybe aiohttp isn't setting cookies. Try requests instead
    print("\n--- Using requests library ---")
    import requests
    sess = requests.Session()
    r = sess.get('http://192.168.18.131/dvwa/setup.php', timeout=5)
    print(f"setup.php cookies: {dict(sess.cookies)}")
    r2 = sess.post('http://192.168.18.131/dvwa/setup.php', data={}, timeout=5)
    print(f"setup POST cookies: {dict(sess.cookies)}")
    r3 = sess.get('http://192.168.18.131/dvwa/login.php', timeout=5)
    print(f"login GET cookies: {dict(sess.cookies)}")
    page = r3.text
    token_m = re.search(r"user_token[^>]+value=['\"]([a-f0-9]{32})['\"]", page, re.I)
    token = token_m.group(1) if token_m else ''
    login_m = re.search(r"name=['\"]login['\"]\s+value=['\"]([^'\"]+)['\"]", page, re.I)
    login_val = login_m.group(1) if login_m else 'Login'
    print(f"  user_token={token[:10] if token else 'NONE'}")
    r4 = sess.post('http://192.168.18.131/dvwa/login.php',
                   data={'username': 'admin', 'password': 'password',
                         'user_token': token, 'login': login_val}, timeout=5)
    print(f"login POST url={r4.url} cookies={dict(sess.cookies)}")
    r5 = sess.get('http://192.168.18.131/dvwa/vulnerabilities/sqli/?id=1', timeout=5)
    print(f"sqli page: {r5.url} len={len(r5.text)}")
    print(f"  on_login={'<form' in r5.text[:500] and 'password' in r5.text[:500]}")

asyncio.run(test())
