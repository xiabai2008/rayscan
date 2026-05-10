"""WVS v18 - Debug scan"""
import asyncio, sys, time
sys.path.insert(0, '.')
from wvs.vuln.full_scanner import FullScanner

async def main():
    scanner = FullScanner({
        'enable_basic': True, 'enable_nuclei': True,
        'enable_sqlmap': False, 'enable_playwright': False,
        'max_urls': 20, 'max_depth': 2, 'timeout': 6,
    })
    print("[1] Scanner init done")
    
    # Phase 1: crawl only
    t = time.time()
    crawl_r = await scanner.crawler.crawl('http://192.168.18.131')
    print(f"[2] Crawl done: {len(crawl_r.urls)} urls ({time.time()-t:.1f}s)")
    
    # Phase 2: basic scan only
    t = time.time()
    basic_vulns = await scanner._scan_basic('http://192.168.18.131', crawl_r, ['sqli'])
    print(f"[3] _scan_basic done: {len(basic_vulns)} vulns ({time.time()-t:.1f}s)")
    
    # Phase 3: nuclei
    t = time.time()
    nuclei_vulns = await scanner._scan_nuclei('http://192.168.18.131', [u.url for u in crawl_r.urls])
    print(f"[4] _scan_nuclei done: {len(nuclei_vulns)} vulns ({time.time()-t:.1f}s)")

if __name__ == '__main__':
    asyncio.run(main())
