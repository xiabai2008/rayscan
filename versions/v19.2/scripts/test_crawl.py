"""模拟 scanner.scan() 的爬虫阶段，验证 cookie 注入后能爬到 DVWA 内容"""
import asyncio
from wvs.core.session import HTTPPool
from wvs.core.crawler import WebCrawler
from wvs.config import ConfigManager

async def main():
    config = ConfigManager()
    session = HTTPPool(config)

    # Step 1: auth，获取 cookies
    import httpx
    async with httpx.AsyncClient(follow_redirects=True, timeout=15, verify=False) as auth_client:
        r = await auth_client.post(
            'http://192.168.18.131/dvwa/login.php',
            data={'username': 'admin', 'password': 'password', 'Login': 'Login'}
        )
        cookies = dict(auth_client.cookies)
        print(f'[+] Auth got cookies: {cookies}')

    # Step 2: 注入 cookie 到 HTTPPool（跟 CLI 同样的方式）
    for name, value in cookies.items():
        session.set_cookie('http://192.168.18.131/dvwa', name, value)
    print(f'[+] Injected {len(cookies)} cookies into HTTPPool')

    # 验证一下 HTTPPool 能否访问 DVWA
    test = await session.get('http://192.168.18.131/dvwa/', timeout=15, follow_redirects=False)
    print(f'[+] Test GET /dvwa/ → {test.status_code}, title: {test.text[test.text.find("<title>")+7:test.text.find("</title>")][:50] if "<title>" in test.text else "N/A"}')

    # Step 3: 启动爬虫
    crawler = WebCrawler(max_depth=2, max_urls_per_run=50)
    endpoints = await crawler.crawl('http://192.168.18.131/dvwa/', session)
    print(f'\n[+] Crawl complete: {len(endpoints)} endpoints')
    for ep in endpoints[:10]:
        print(f'  - {ep.method} {ep.url}')

    await session.close()

asyncio.run(main())
