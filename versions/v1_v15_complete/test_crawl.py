import asyncio
import sys
sys.path.insert(0, '.')

import aiohttp

async def test_crawl():
    url = 'http://47.95.192.41:8082'
    print(f"Testing crawl: {url}")
    
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=False) as resp:
                print(f"Status: {resp.status}")
                print(f"Content-Type: {resp.headers.get('Content-Type')}")
                if resp.status == 200:
                    html = await resp.text()
                    print(f"HTML length: {len(html)}")
                    print(f"First 500 chars: {html[:500]}")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

asyncio.run(test_crawl())
