import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")
from wvs.vuln.crawler_v18 import CrawlerV18
from wvs.vuln.scanner_v18 import VulnerabilityScanner
import asyncio, aiohttp, json, time, os

TARGET = "http://192.168.18.132"

async def scan():
    results = {"urls": [], "vulns": [], "start": time.strftime("%Y-%m-%d %H:%M:%S")}
    
    # 1. Crawl
    print("[1] Crawling zico2...")
    crawler = CrawlerV18({"max_depth": 3, "max_urls": 50, "timeout": 10})
    crawl_result = await crawler.crawl(TARGET)
    urls = crawl_result.urls
    print(f"    Found {len(urls)} URLs")
    results["urls"] = [u.url for u in urls]
    
    # 2. Scan
    print("[2] Scanning for vulnerabilities...")
    scanner = VulnerabilityScanner({"timeout": 15, "delay": 0.1})
    
    async with aiohttp.ClientSession() as session:
        for ui in urls[:30]:
            url = ui.url
            params = ui.params if hasattr(ui, "params") else {}
            
            # SQLi
            for p in params:
                try:
                    for v in await scanner.test_sqli(session, url, p, "GET") or []:
                        print(f"  [SQLi] {url[:50]}")
                        results["vulns"].append({"type": "SQLi", "url": url, "param": p})
                except: pass
            
            # XSS
            for p in params:
                try:
                    for v in await scanner.test_xss(session, url, p) or []:
                        print(f"  [XSS] {url[:50]}")
                        results["vulns"].append({"type": "XSS", "url": url, "param": p})
                except: pass
            
            # CMDi
            for p in params:
                try:
                    for v in await scanner.test_cmdi(session, url, p) or []:
                        print(f"  [CMDi] {url[:50]}")
                        results["vulns"].append({"type": "CMDi", "url": url, "param": p})
                except: pass
            
            # LFI
            for p in params:
                try:
                    for v in await scanner.test_lfi(session, url, p) or []:
                        print(f"  [LFI] {url[:50]}")
                        results["vulns"].append({"type": "LFI", "url": url, "param": p, "evidence": v.evidence})
                except: pass
    
    results["total"] = len(results["vulns"])
    results["end"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    os.makedirs("C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18/reports", exist_ok=True)
    with open("C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18/reports/zico2_v2.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"Complete. Total: {len(results['vulns'])} vulns")

asyncio.run(scan())
