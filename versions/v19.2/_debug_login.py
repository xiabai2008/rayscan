import httpx, asyncio

async def main():
    c = httpx.AsyncClient(timeout=10, verify=False)
    
    # Login
    r = await c.get('http://47.95.192.41:8081/login.php')
    tok = None
    for p in r.text.split('user_token'):
        if "value='" in p:
            tok = p.split("value='")[1].split("'")[0]; break
    r = await c.post('http://47.95.192.41:8081/login.php',
        data={'username': 'gordonb', 'password': 'abc123', 'Login': 'Login', 'user_token': tok},
        follow_redirects=True)
    tok2 = None
    for p in r.text.split('user_token'):
        if "value='" in p:
            tok2 = p.split("value='")[1].split("'")[0]; break
    if tok2:
        await c.post('http://47.95.192.41:8081/security.php',
            data={'security': 'low', 'seclev_submit': 'Submit', 'user_token': tok2})
    
    # Probe all common DVWA endpoints
    paths = [
        '/vulnerabilities/exec/',
        '/vulnerabilities/csrf/',
        '/vulnerabilities/brute/',
        '/vulnerabilities/csp/',
        '/vulnerabilities/javascript/',
        '/vulnerabilities/weak_id/',
        '/vulnerabilities/sqli/',
        '/vulnerabilities/sqli_blind/',
        '/vulnerabilities/xss_r/',
        '/vulnerabilities/xss_s/',
        '/vulnerabilities/xss_d/',
        '/vulnerabilities/cmdi/',
        '/vulnerabilities/fi/',
        '/vulnerabilities/fi/?page=include.php',
        '/vulnerabilities/upload/',
        '/instructions.php',
    ]
    for p in paths:
        r = await c.get(f'http://47.95.192.41:8081{p}')
        tag = 'OK' if r.status_code == 200 else f'{r.status_code}'
        if r.status_code == 302:
            tag += f' -> {r.headers.get("location","?")}'
        if r.status_code == 200:
            tag += f' ({len(r.text)}b)'
        print(f'{p:45s} {tag}')
    
    await c.aclose()

asyncio.run(main())
