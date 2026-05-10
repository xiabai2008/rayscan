"""逐帧调试 cookie 注入"""
import httpx
import asyncio

async def main():
    from wvs.core.session import HTTPPool
    from wvs.config import ConfigManager

    # Step 1: auth
    async with httpx.AsyncClient(follow_redirects=True, timeout=15, verify=False) as client:
        r = await client.post(
            'http://192.168.18.131/dvwa/login.php',
            data={'username': 'admin', 'password': 'password', 'Login': 'Login'}
        )
        print('Auth final URL:', r.url)
        cookies = dict(client.cookies)
        print('Auth cookies:', cookies)

    # Step 2: HTTPPool + cookie injection
    config = ConfigManager()
    session = HTTPPool(config)

    sc = session._get_httpx_client()
    for name, value in cookies.items():
        sc.cookies.set(name, value, domain='192.168.18.131', path='/')

    print('\nCookies in jar after injection:')
    print('  dict:', dict(sc.cookies))

    # Step 3: 请求 /dvwa/ 但不过 follow redirect
    print('\nGET /dvwa/ (no redirect):')
    r1 = await session.get('http://192.168.18.131/dvwa/', timeout=15, follow_redirects=False)
    print('  Status:', r1.status_code, 'URL:', r1.url)
    print('  Set-Cookie header:', r1.headers.get('set-cookie'))
    print('  Response URL:', r1.url)

    # Step 4: 检查 /dvwa/ 的实际响应内容
    if r1.status_code == 200:
        print('  Title:', r1.text[r1.text.find('<title>')+7:r1.text.find('</title>')][:60] if '<title>' in r1.text else 'N/A')
        if 'login' in r1.text.lower():
            print('  [NEED LOGIN] DVWA 需要登录')
        else:
            print('  [OK] 似乎已登录')

    # Step 5: 检查请求是否真的带了 cookie
    # 用调试方式看请求 header
    print('\n手动构造请求检查 cookie:')
    test_client = httpx.AsyncClient(follow_redirects=False, verify=False)
    req = test_client.build_request('GET', 'http://192.168.18.131/dvwa/')
    print('  Request headers (cookie part):', dict(req.headers).get('cookie', 'NONE'))

    # 用 HTTPPool 的 client 检查
    print('\nHTTPPool client cookie jar:')
    jar = sc.cookies
    print('  Type:', type(jar))
    print('  Content:', jar)

    await session.close()
    await test_client.aclose()

asyncio.run(main())
