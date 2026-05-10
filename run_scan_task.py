#!/usr/bin/env python3
"""
WVS v19 定时扫描脚本
扫描 Metasploitable2 靶机生成报告
"""
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Fix Windows console encoding for Chinese output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget


def _resolve_vuln_type(v):
    """安全获取漏洞类型字符串，避免 NameError"""
    if hasattr(v.type, 'value'):
        return v.type.value
    return str(v.type)


def run_scan():
    """执行 WVS 扫描"""
    config = ConfigManager()
    config.set("verify_ssl", False)
    config.set("crawl_depth", 4)
    config.set("crawl_max_urls", 500)
    config.set("max_time", 10800)  # 3小时超时
    config.set("concurrent_endpoints", 12)

    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    target = ScanTarget(url="http://47.95.192.41:8081/dvwa")

    print(f"\n{'='*60}")
    print(f"WVS v19.0 - Metasploitable2 扫描")
    print(f"目标: http://172.17.43.128")
    print(f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"模块: {list(scanner._modules.keys())}")
    print(f"{'='*60}\n")

    max_time = config.get("max_time", 0)
    if max_time > 0:
        print(f"[*] 扫描超时限制: {max_time}秒")
        result = asyncio.run(asyncio.wait_for(scanner.scan(target), timeout=max_time))
    else:
        result = asyncio.run(scanner.scan(target))

    # 生成报告
    report = generate_report(result)

    # 报告保存到文件
    report_path = Path(__file__).parent / "scan_reports" / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_path.parent.mkdir(exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\n报告已保存: {report_path}")
    return report


def generate_report(result):
    """生成结构化报告"""
    vuln_by_type = {}
    vuln_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for v in result.vulnerabilities:
        vtype = v.type.value if hasattr(v.type, 'value') else str(v.type)
        vuln_by_type[vtype] = vuln_by_type.get(vtype, 0) + 1

        sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        vuln_by_severity[sev] = vuln_by_severity.get(sev, 0) + 1

    report = {
        "scan_time": datetime.now().isoformat(),
        "target": "http://172.17.43.128",
        "duration_seconds": result.duration,
        "endpoints_found": result.endpoints_found,
        "requests_made": result.requests_made,
        "total_vulnerabilities": len(result.vulnerabilities),
        "vulnerabilities_by_type": vuln_by_type,
        "vulnerabilities_by_severity": vuln_by_severity,
        "vulnerabilities": [
            {
                "type": _resolve_vuln_type(v),
                "severity": v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
                "url": v.url,
                "parameter": v.parameter,
                "parameter_type": v.parameter_type,
                "payload": v.payload[:200] if v.payload else None,
                "evidence": (v.evidence[:300] if len(v.evidence) > 300 else v.evidence) if v.evidence else None,
                "module": getattr(v, 'module', None),
                "confidence": v.confidence.value if hasattr(v.confidence, 'value') else str(v.confidence),
            }
            for v in result.vulnerabilities
        ]
    }

    return report


if __name__ == "__main__":
    try:
        report = run_scan()
        print("\n" + "="*60)
        print("扫描完成！")
        print(f"总漏洞数: {report['total_vulnerabilities']}")
        print(f"端点数: {report['endpoints_found']}")
        print(f"请求总数: {report['requests_made']}")
        print("="*60)
    except Exception as e:
        print(f"扫描失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)