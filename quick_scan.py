"""快速扫描 172.17.43.128 — P13 优化版 (并发 cmdi + 本地延迟)"""
import asyncio, json, sys, time, os
from datetime import datetime
from pathlib import Path

# P13: 禁用 stdout 缓冲，进度条实时刷新
os.environ["PYTHONUNBUFFERED"] = "1"

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
    config.set("crawl_depth", 2)
    config.set("crawl_max_urls", 25)  # ~300 endpoints, <1800s scan time
    config.set("concurrent_endpoints", 15)  # P14: reduced from 20 — less server pressure
    config.set("param_discovery_samples", 2)
    config.set("retry_count", 0)
    config.set("timeout", 15)  # P14: 15s — slow servers spike under load

    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    # 保留全部模块（cmdi 已优化为并发 time-based）
    modules = list(scanner._modules.keys())
    target = ScanTarget(url="http://172.17.43.128/mutillidae/")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] P13 快速扫描开始")
    print(f"  目标: {target.url}")
    print(f"  模块: {modules}")
    print(f"  cmdi优化: 并发time-based + 本地延迟(1/2s)")

    t0 = time.time()
    try:
        result = await asyncio.wait_for(scanner.scan(target), timeout=1800)
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
        "duration_seconds": round(elapsed, 1),
        "endpoints_found": result.endpoints_found,
        "requests_made": result.requests_made,
        "total_vulnerabilities": len(result.vulnerabilities),
        "vulnerabilities_by_type": vuln_by_type,
        "vulnerabilities": [
            {
                "type": resolve_type(v),
                "severity": v.severity.value,
                "url": v.url[:150],
                "parameter": v.parameter,
                "module": getattr(v, 'module', None),
                "evidence": (v.evidence[:300] if len(v.evidence or '') > 300 else v.evidence) if v.evidence else None,
            }
            for v in result.vulnerabilities
        ]
    }

    Path("scan_reports").mkdir(exist_ok=True)
    fp = Path(f"scan_reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    fp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n{'='*50}")
    print(f"  耗时: {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"  端点: {result.endpoints_found}")
    print(f"  请求: {result.requests_made}")
    print(f"  漏洞: {len(result.vulnerabilities)}")
    for t, c in sorted(vuln_by_type.items(), key=lambda x: -x[1]):
        print(f"    {t}: {c}")
    print(f"  报告: {fp}")
    print(f"{'='*50}")
    return report

if __name__ == "__main__":
    try:
        result = asyncio.run(main())
    except Exception as e:
        print(f"[!] 扫描异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    if not result:
        print("[!] 扫描未返回结果")
        sys.exit(1)
    sys.exit(0)
