#!/usr/bin/env python3
"""
WVS v19 实战性能测试 - 5 靶机批量扫描
靶机：DVWA / Pikachu / SQLi-Lab / Upload / XSS-Lab
"""
import asyncio
import sys
import time
from datetime import datetime

sys.path.insert(0, r'C:\Users\HZR\.openclaw\workspace\wvs-v19')

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.core.scanner import WAVScanner
from wvs.models import ScanTarget
from wvs.reporting import ConsoleReporter, HTMLReporter, JSONReporter

# 靶机配置
TARGETS = [
    {"name": "DVWA", "url": "http://47.95.192.41:8081/", "auth": True},
    {"name": "Pikachu", "url": "http://47.95.192.41:8082/", "auth": False},
    {"name": "SQLi-Lab", "url": "http://47.95.192.41:8083/", "auth": False},
    {"name": "Upload-Lab", "url": "http://47.95.192.41:8084/", "auth": False},
    {"name": "XSS-Lab", "url": "http://47.95.192.41:8085/", "auth": False},
]

async def scan_target(target_info: dict, config: ConfigManager) -> dict:
    """扫描单个靶机"""
    name = target_info["name"]
    url = target_info["url"]
    
    print(f"\n{'='*60}")
    print(f"[+] 开始扫描: {name}")
    print(f"    URL: {url}")
    print(f"{'='*60}")
    
    start_time = time.time()
    
    try:
        scanner = WAVScanner(config)
        
        # DVWA 需要认证
        if target_info.get("auth"):
            print("    [~] DVWA 自动认证中...")
            # WAVScanner 内置 DVWA 自动认证
        
        target = ScanTarget(url=url)
        results = await asyncio.wait_for(
            scanner.scan(target),
            timeout=120  # 2分钟超时
        )
        
        duration = time.time() - start_time
        
        # 统计结果
        vuln_count = len(results.get("vulnerabilities", []))
        by_severity = {}
        by_type = {}
        
        for v in results.get("vulnerabilities", []):
            sev = v.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            vtype = v.type.value if hasattr(v.type, 'value') else str(v.type)
            by_type[vtype] = by_type.get(vtype, 0) + 1
        
        print(f"    [✓] 完成 - {vuln_count} 个漏洞 ({duration:.1f}s)")
        for sev, count in sorted(by_severity.items(), key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}.get(x[0],4)):
            print(f"        - {sev.upper()}: {count}")
        
        return {
            "name": name,
            "url": url,
            "success": True,
            "duration": duration,
            "vuln_count": vuln_count,
            "by_severity": by_severity,
            "by_type": by_type,
            "vulnerabilities": results.get("vulnerabilities", []),
        }
        
    except asyncio.TimeoutError:
        print(f"    [FAIL] 超时 (>120s)")
        return {"name": name, "url": url, "success": False, "error": "timeout"}
    except Exception as e:
        print(f"    [FAIL] 错误: {e}")
        return {"name": name, "url": url, "success": False, "error": str(e)}

async def main():
    print("="*60)
    print("WVS v19 实战性能测试")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    config = ConfigManager()
    
    # 批量扫描
    results = []
    for target_info in TARGETS:
        result = await scan_target(target_info, config)
        results.append(result)
    
    # 汇总报告
    print(f"\n{'='*60}")
    print("扫描汇总")
    print(f"{'='*60}")
    
    total_vulns = 0
    total_time = 0
    success_count = 0
    
    for r in results:
        if r["success"]:
            success_count += 1
            total_vulns += r["vuln_count"]
            total_time += r["duration"]
            print(f"{r['name']:12} | {r['vuln_count']:2} vulns | {r['duration']:5.1f}s | ✓")
        else:
            print(f"{r['name']:12} | FAIL | {r.get('error', 'unknown')}")
    
    print(f"{'='*60}")
    print(f"总计: {success_count}/{len(TARGETS)} 成功, {total_vulns} 漏洞, {total_time:.1f}s")
    print(f"="*60)
    
    # 生成报告
    print("\n[+] 生成报告...")
    
    # 合并所有漏洞
    all_vulns = []
    for r in results:
        if r["success"]:
            all_vulns.extend(r.get("vulnerabilities", []))
    
    # HTML 报告
    html_reporter = HTMLReporter()
    html_report = html_reporter.generate({
        "target": {"url": "批量扫描 (5 targets)"},
        "scan_info": {
            "start_time": datetime.now().isoformat(),
            "duration_seconds": total_time,
            "requests_made": 0,
        },
        "vulnerabilities": all_vulns,
        "statistics": {
            "total_vulnerabilities": total_vulns,
            "by_severity": {},
        }
    })
    
    report_file = r"C:\Users\HZR\.openclaw\workspace\wvs-v19\reports\batch_scan_5targets.html"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html_report)
    
    print(f"    [✓] HTML 报告: {report_file}")
    
    return results

if __name__ == "__main__":
    asyncio.run(main())
