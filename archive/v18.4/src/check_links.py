"""检查 httpbin.org 首页链接"""
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

async def check_links():
    url = "https://httpbin.org/"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            content = await resp.text()
    
    soup = BeautifulSoup(content, 'lxml')
    
    print(f"Page: {url}")
    print(f"Content length: {len(content)}")
    print(f"\nLinks found: {len(soup.find_all('a', href=True))}")
    
    base_domain = urlparse(url).netloc
    
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(url, href)
        parsed = urlparse(full_url)
        
        same_domain = parsed.netloc == base_domain
        is_static = any(parsed.path.lower().endswith(ext) for ext in 
                       ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg'])
        
        print(f"  - {href}")
        print(f"    Full: {full_url}")
        print(f"    Same domain: {same_domain}, Static: {is_static}")
        print()

asyncio.run(check_links())
