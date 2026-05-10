"""Test crawler enhancement"""
import asyncio, sys, warnings
sys.path.insert(0, '.')
from bs4 import XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

from wvs.vuln.scanner_v18 import EnhancedCrawler

async def main():
    c = EnhancedCrawler({'max_depth': 2, 'max_urls': 80, 'timeout': 5, 'delay': 0.05})
    print('[*] Crawling driftingblues9...')
    result = await c.crawl('http://192.168.18.133')
    print(f'URLs found: {len(result.urls)}')
    for u in result.urls:
        print(f'  {u.url}')
    print(f'Forms: {len(result.forms)}')
    for f in result.forms:
        print(f'  [{f["method"]}] {f["url"]}')
    print(f'Sensitive paths: {len(result.sensitive_paths)}')

asyncio.run(main())
