"""全量扫描 172.17.43.128"""
import asyncio, json, sys, time, os
from datetime import datetime
from pathlib import Path

sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19')

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget


def resolve_type(v):
    if hasattr(v.type, 'value'):
        return v.type.value
    return str(v.type)


async def main():
    config = ConfigManager()
    config.set("verify_ssl", False)
    config.set("crawl_depth", 3)
    config.set("crawl_max_urls", 500)
    config.set("concurrent_endpoints", 12)

    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    target = ScanTarget(url="http://172.17.43.128/mutillidae/")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] 扫描开始")
    print(f"  目标: {target.url}")
    print(f"  模块: {list(scanner._modules.keys())}")

    t0 = time.time()
    try:
        result = await asyncio.wait_for(scanner.scan(target), timeout=10800)
    except asyncio.TimeoutError:
        elapsed = time.time() - t0
        print(f"[!] 超时 ({elapsed:.0f}s)")
        return None

    elapsed = time.time() - t0

    vuln_by_type = {}
    for v in result.vulnerabilities:
        vt = resolve_type(v)
        vuln_by_type[vt] = vuln_by_type.get(vt, 0) + 1

    report = {
        "scan_time": datetime.now().isoformat(),
        "target": str(target.url),
        "duration_seconds": elapsed,
        "endpoints_found": result.endpoints_found,
        "requests_made": result.requests_made,
        "total_vulnerabilities": len(result.vulnerabilities),
        "vulnerabilities_by_type": vuln_by_type,
        "vulnerabilities": [
            {
                "type": resolve_type(v),
                "severity": v.severity.value,
                "url": v.url[:120],
                "parameter": v.parameter,
                "evidence": (v.evidence[:300] if len(v.evidence) > 300 else v.evidence) if v.evidence else None,
                "module": getattr(v, 'module', None),
            }
            for v in result.vulnerabilities
        ]
    }

    Path("scan_reports").mkdir(exist_ok=True)
    fp = Path(f"scan_reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    fp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n{'='*50}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 扫描完成 ({elapsed:.0f}s)")
    print(f"  端点数: {result.endpoints_found}")
    print(f"  请求数: {result.requests_made}")
    print(f"  漏洞数: {len(result.vulnerabilities)}")
    for t, c in sorted(vuln_by_type.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c}")
    print(f"  报告: {fp}")
    print(f"{'='*50}")
    return report

if __name__ == "__main__":
    import asyncio
    result = asyncio.run(main())
    if not result:
        sys.exit(1)
