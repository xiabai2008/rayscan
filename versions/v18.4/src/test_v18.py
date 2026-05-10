"""WVS v18.0 测试脚本"""

import asyncio
import sys
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")

from wvs.vuln.crawler_v18 import CrawlerV18
from wvs.vuln.report_v18 import ReportGeneratorV18
from datetime import datetime


async def test_crawler():
    """测试爬虫"""
    print("=" * 60)
    print("WVS v18.0 爬虫测试")
    print("=" * 60)
    
    # 测试目标
    targets = [
        ("SQLi-Labs", "http://47.95.192.41:8083/"),
        ("Pikachu", "http://47.95.192.41:8082/"),
        ("DVWA", "http://47.95.192.41:8081/"),
    ]
    
    results = []
    
    for name, url in targets:
        print(f"\n[+] 扫描 {name}: {url}")
        
        crawler = CrawlerV18({
            "max_depth": 2,
            "max_urls": 50,
            "timeout": 5
        })
        
        start = datetime.now()
        result = await crawler.crawl(url)
        duration = (datetime.now() - start).total_seconds()
        
        print(f"  - URL 数量: {len(result.urls)}")
        print(f"  - 表单数量: {len(result.forms)}")
        print(f"  - JS 文件: {len(result.js_files)}")
        print(f"  - 敏感路径: {len(result.sensitive_paths)}")
        print(f"  - 总请求数: {result.total_requests}")
        print(f"  - 耗时: {duration:.2f}s")
        
        if result.sensitive_paths:
            print(f"  - 敏感路径发现:")
            for p in result.sensitive_paths[:5]:
                print(f"    • [{p['severity']}] {p['url']} - {p['type']}")
        
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
    print("生成报告...")
    
    report_gen = ReportGeneratorV18({
        "output_dir": "C:\\Users\\HZR\\.qclaw\\workspace-agent-b7ed571b\\wvs-v18\\reports"
    })
    
    # 收集所有敏感路径
    all_sensitive = []
    for r in results:
        # 这里需要实际数据
        pass
    
    # 测试报告格式
    test_findings = [
        {
            "type": "敏感文件泄露",
            "url": "http://47.95.192.41:8083/.git/HEAD",
            "severity": "high",
            "parameter": "N/A",
            "payload": "N/A",
            "confidence": 0.9
        }
    ]
    
    for fmt in ["html", "json", "md"]:
        path = report_gen.save_report(test_findings, format=fmt)
        print(f"  - {fmt.upper()} 报告: {path}")
    
    print("\n[+] 测试完成!")
    
    return results


if __name__ == "__main__":
    results = asyncio.run(test_crawler())
    
    # 打印汇总表格
    print("\n" + "=" * 60)
    print("测试结果汇总")
    print("=" * 60)
    print(f"{'目标':<15} {'URLs':<10} {'表单':<10} {'敏感路径':<10} {'耗时':<10}")
    print("-" * 60)
    for r in results:
        print(f"{r['name']:<15} {r['urls']:<10} {r['forms']:<10} {r['sensitive']:<10} {r['duration']:.2f}s")
