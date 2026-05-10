"""简单测试"""
import asyncio
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

async def test():
    from wvs.vuln.scanner_v18 import EnhancedCrawler
    
    print("Testing crawler...")
    crawler = EnhancedCrawler({"max_depth": 1, "max_urls": 10})
    result = await crawler.crawl("https://example.com/")
    
    print(f"URLs: {len(result.urls)}")
    print(f"Forms: {len(result.forms)}")
    print(f"Duration: {result.duration:.2f}s")
    
    for u in result.urls:
        print(f"  - {u.url}")

asyncio.run(test())
