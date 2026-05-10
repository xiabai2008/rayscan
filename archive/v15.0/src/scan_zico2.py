import sys
sys.path.insert(0, r'C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18')
from wvs.vuln.crawler_v18 import CrawlerV18
from wvs.vuln.scanner_v18 import VulnerabilityScanner
import asyncio, aiohttp, json, time, os

TARGET = 'http://192.168.18.132'

async def scan():
    results = {'urls': [], 'vulns': [], 'start': time.strftime('%Y-%m-%d %H:%M:%S')}
    
    # Crawl
    print('[1] Crawling zico2...')
    crawler = CrawlerV18({'max_depth': 3, 'max_urls': 100, 'timeout': 10})
    crawl_result = await crawler.crawl(TARGET)
    urls = crawl_result.urls
    print(f'Found {len(urls)} URLs')
    
    # Scan
    print('[2] Scanning for vulns...')
    scanner = VulnerabilityScanner({'timeout': 15})
    
    async with aiohttp.ClientSession() as session:
        for ui in urls[:30]:
            url = ui.url if hasattr(ui, 'url') else str(ui)
            params = ui.params if hasattr(ui, 'params') else {}
            
            for p in params:
                try:
                    for v in await scanner.test_sqli(session, url, p, 'GET') or []:
                        print(f'  [SQLi] {url[:60]} param={p}')
                        results['vulns'].append({'type': 'SQLi', 'url': url, 'param': p, 'conf': v.confidence})
                except: pass
                try:
                    for v in await scanner.test_xss(session, url, p) or []:
                        print(f'  [XSS] {url[:60]} param={p}')
                        results['vulns'].append({'type': 'XSS', 'url': url, 'param': p, 'conf': v.confidence})
                except: pass
    
    results['total'] = len(results['vulns'])
    results['end'] = time.strftime('%Y-%m-%d %H:%M:%S')
    os.makedirs('C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18/reports', exist_ok=True)
    with open('C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18/reports/zico2_scan.json', 'w') as f:
        json.dump(results, f, indent=2)
    print('Complete. Total vulns:', len(results['vulns']))

asyncio.run(scan())
