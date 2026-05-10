"""WVS v18.0 测试 - 使用可达目标"""

import asyncio
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

from wvs.vuln.crawler_v18 import CrawlerV18
from wvs.vuln.report_v18 import ReportGeneratorV18
from datetime import datetime


async def test_crawler():
    """测试爬虫"""
    print("=" * 60)
    print("WVS v18.0 Crawler Test")
    print("=" * 60)
    
    # 使用可达的目标
    targets = [
        ("HTTPBin", "https://httpbin.org/"),
        ("Example", "https://example.com/"),
    ]
    
    results = []
    
    for name, url in targets:
        print(f"\n[+] Scanning {name}: {url}")
        
        crawler = CrawlerV18({
            "max_depth": 2,
            "max_urls": 30,
            "timeout": 10,
            "verify_ssl": True
        })
        
        start = datetime.now()
        result = await crawler.crawl(url)
        duration = (datetime.now() - start).total_seconds()
        
        print(f"  - URLs: {len(result.urls)}")
        print(f"  - Forms: {len(result.forms)}")
        print(f"  - JS Files: {len(result.js_files)}")
        print(f"  - Sensitive Paths: {len(result.sensitive_paths)}")
        print(f"  - Total Requests: {result.total_requests}")
        print(f"  - Duration: {duration:.2f}s")
        
        if result.urls:
            print(f"  - Sample URLs:")
            for u in result.urls[:5]:
                print(f"    * {u.url}")
        
        if result.sensitive_paths:
            print(f"  - Sensitive Paths Found:")
            for p in result.sensitive_paths[:5]:
                print(f"    * [{p['severity']}] {p['url']} - {p['type']}")
        
        results.append({
            "name": name,
            "url": url,
            "urls": len(result.urls),
            "forms": len(result.forms),
            "sensitive": len(result.sensitive_paths),
            "duration": duration
        })
    
    # 生成报告
    print("\n" + "=" * 60)
    print("Generating Reports...")
    
    report_gen = ReportGeneratorV18({
        "output_dir": "C:\\Users\\HZR\\.qclaw\\workspace-agent-b7ed571b\\wvs-v18\\reports"
    })
    
    # 创建测试发现
    test_findings = [
        {
            "type": "Sensitive File Exposure",
            "url": "https://example.com/.git/config",
            "severity": "high",
            "parameter": "N/A",
            "payload": "N/A",
            "confidence": 0.95
        },
        {
            "type": "XSS",
            "url": "https://httpbin.org/get?q=test",
            "severity": "medium",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "confidence": 0.8
        }
    ]
    
    for fmt in ["html", "json", "md"]:
        path = report_gen.save_report(test_findings, format=fmt)
        print(f"  - {fmt.upper()} Report: {path}")
    
    print("\n[+] Test Complete!")
    
    return results


if __name__ == "__main__":
    results = asyncio.run(test_crawler())
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"{'Target':<15} {'URLs':<10} {'Forms':<10} {'Sensitive':<10} {'Duration':<10}")
    print("-" * 60)
    for r in results:
        print(f"{r['name']:<15} {r['urls']:<10} {r['forms']:<10} {r['sensitive']:<10} {r['duration']:.2f}s")
