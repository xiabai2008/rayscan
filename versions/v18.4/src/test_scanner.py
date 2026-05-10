"""WVS v18.0 实战测试"""

import asyncio
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

from wvs.vuln.scanner_v18 import FullScanner, EnhancedCrawler, VulnerabilityScanner
from datetime import datetime


async def test_crawler():
    """测试爬虫"""
    print("=" * 70)
    print("WVS v18.0 - Enhanced Crawler Test")
    print("=" * 70)
    
    crawler = EnhancedCrawler({
        "max_depth": 2,
        "max_urls": 100,
        "timeout": 10,
        "delay": 0.05
    })
    
    targets = [
        ("HTTPBin", "https://httpbin.org/"),
        ("Example", "https://example.com/"),
    ]
    
    for name, url in targets:
        print(f"\n[*] Crawling {name}: {url}")
        start = datetime.now()
        result = await crawler.crawl(url)
        duration = (datetime.now() - start).total_seconds()
        
        print(f"    URLs: {len(result.urls)}")
        print(f"    Forms: {len(result.forms)}")
        print(f"    JS Files: {len(result.js_files)}")
        print(f"    Sensitive: {len(result.sensitive_paths)}")
        print(f"    Requests: {result.total_requests}")
        print(f"    Duration: {duration:.2f}s")
        
        if result.urls:
            print(f"    Sample URLs:")
            for u in result.urls[:10]:
                print(f"      - {u.url}")
        
        if result.forms:
            print(f"    Forms found:")
            for f in result.forms[:5]:
                print(f"      - [{f['method']}] {f['url']} ({len(f['inputs'])} inputs)")


async def test_sqli_detection():
    """测试 SQL 注入检测"""
    print("\n" + "=" * 70)
    print("WVS v18.0 - SQLi Detection Test")
    print("=" * 70)
    
    scanner = VulnerabilityScanner({"timeout": 15, "delay": 0.1})
    
    # 使用 httpbin 的测试端点
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        # 测试一个可能存在注入的 URL
        test_url = "https://httpbin.org/get"
        param = "id"
        
        print(f"\n[*] Testing {test_url}?{param}=<payload>")
        
        # 发送正常请求作为基线
        status, content, duration = await scanner._send_request(session, test_url, "GET", {param: "1"})
        print(f"    Baseline: status={status}, time={duration:.2f}s")
        
        # 测试 SQL 注入 payloads
        print(f"\n    Testing payloads...")
        vulns = await scanner.test_sqli(session, test_url, param, "GET", content)
        
        if vulns:
            print(f"    Vulnerabilities found: {len(vulns)}")
            for v in vulns:
                print(f"      - [{v.severity.upper()}] {v.type}")
                print(f"        Parameter: {v.parameter}")
                print(f"        Payload: {v.payload[:50]}")
                print(f"        Confidence: {v.confidence:.2f}")
        else:
            print(f"    No vulnerabilities detected (expected for httpbin.org)")


async def test_full_scan():
    """测试完整扫描"""
    print("\n" + "=" * 70)
    print("WVS v18.0 - Full Scan Test")
    print("=" * 70)
    
    scanner = FullScanner({
        "max_depth": 2,
        "max_urls": 50,
        "timeout": 10,
        "delay": 0.05
    })
    
    url = "https://httpbin.org/"
    print(f"\n[*] Full scanning: {url}")
    
    start = datetime.now()
    result = await scanner.scan(url, modules=["sqli", "xss"])
    duration = (datetime.now() - start).total_seconds()
    
    print(f"\n    Duration: {duration:.2f}s")
    print(f"    URLs crawled: {len(result.urls)}")
    print(f"    Forms found: {len(result.forms)}")
    print(f"    Vulnerabilities: {len(result.vulnerabilities)}")
    print(f"    Sensitive paths: {len(result.sensitive_paths)}")
    
    if result.vulnerabilities:
        print(f"\n    [!] Vulnerabilities:")
        for v in result.vulnerabilities:
            print(f"      - [{v.severity.upper()}] {v.type} at {v.url}")
            print(f"        Parameter: {v.parameter}")
            print(f"        Payload: {v.payload[:40]}...")
    
    if result.sensitive_paths:
        print(f"\n    [!] Sensitive paths:")
        for s in result.sensitive_paths:
            print(f"      - [{s['severity'].upper()}] {s['url']} ({s['type']})")


async def main():
    """主测试"""
    print("WVS v18.0 - Vulnerability Scanner Test Suite")
    print("=" * 70)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    await test_crawler()
    await test_sqli_detection()
    await test_full_scan()
    
    print("\n" + "=" * 70)
    print("Test Complete!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
