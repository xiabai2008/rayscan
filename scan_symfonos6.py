"""Symfonos6v2 scan"""
import asyncio, sys, time, json
from datetime import datetime; from pathlib import Path

sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19')
os = __import__('os')
os.environ["PYTHONUNBUFFERED"] = "1"

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.core.scanner import WAVScanner
from wvs.models import ScanTarget

TARGETS = [
    "http://172.17.43.132:3000",  # Gitea
    "http://172.17.43.132/",      # Apache
]

async def scan_one(config, url):
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()
    
    print(f"\n{'='*50}")
    print(f"Scanning: {url}")
    
    target = ScanTarget(url=url, methods=["GET", "POST"])
    result = await scanner.scan(target)
    
    stats = scanner.get_stats()
    print(f"  Endpoints: {stats.get('endpoints', '?')}")
    print(f"  Requests: {stats.get('requests', '?')}")
    print(f"  Findings: {len(result.vulnerabilities) if result else 0}")
    
    return result

async def main():
    config = ConfigManager()
    for k, v in {
        "timeout": 10, "retry_count": 1, "verify_ssl": False,
        "crawl_depth": 1, "crawl_max_urls": 30,
        "concurrent_endpoints": 5,
    }.items():
        config.set(k, v)

    all_findings = []
    for url in TARGETS:
        try:
            result = await scan_one(config, url)
            if result and result.vulnerabilities:
                all_findings.extend(result.vulnerabilities)
        except Exception as e:
            print(f"  Error: {e}")

    print(f"\n{'='*50}")
    print(f"Total findings: {len(all_findings)}")
    
    # Save
    report_dir = Path(r"C:\Users\HZR\Desktop\wvs-v19\scan_reports")
    report_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"report_symfonos6v2_{ts}.json"
    
    report = {
        "targets": TARGETS,
        "timestamp": datetime.now().isoformat(),
        "findings": len(all_findings),
        "results": [],
    }
    
    for v in all_findings:
        try:
            report["results"].append({
                "module": getattr(v, 'module', '?'),
                "severity": getattr(v, 'severity', 'info'),
                "url": getattr(v, 'url', '?'),
                "title": getattr(v, 'title', '?'),
                "description": getattr(v, 'description', '')[:200],
            })
        except:
            pass
    
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    print(f"Report: {report_path}")
    
    # Summary
    by_sev = {}
    for v in all_findings:
        s = getattr(v, 'severity', 'info')
        by_sev[s] = by_sev.get(s, 0) + 1
    print("\nBy severity:")
    for s, c in sorted(by_sev.items()):
        print(f"  {s}: {c}")

if __name__ == "__main__":
    asyncio.run(main())
