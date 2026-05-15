"""
RayScan Quick Test — Metasploitable2 targeted scan
"""
import asyncio, sys, json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget


TARGET = "http://192.168.18.131"


def _severity_value(vuln):
    sev = getattr(vuln, 'severity', None)
    if sev:
        return getattr(sev, 'value', str(sev))
    return 'unknown'


async def scan_url(url: str, label: str):
    config = ConfigManager()
    config.set("verify_ssl", False)
    config.set("crawl_depth", 1)
    config.set("crawl_max_urls", 30)
    config.set("crawl_max_urls_per_prefix", 15)
    config.set("timeout", 10)
    config.set("concurrent_endpoints", 5)
    config.set("retry_count", 0)

    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()

    target = ScanTarget(url=url)
    print(f"\n{'='*55}")
    print(f"  Scanning: {label}")
    print(f"  URL: {url}")
    print(f"{'='*55}")

    try:
        result = await asyncio.wait_for(scanner.scan(target), timeout=120)
    except asyncio.TimeoutError:
        print(f"  [!] Timeout (>120s)")
        return label, 0, []

    vulns = result.vulnerabilities
    for v in vulns:
        sev = _severity_value(v)
        vtype = getattr(v.type, 'value', str(v.type)) if v.type else 'N/A'
        print(f"  [{sev.upper():<8}] {vtype:<25} {getattr(v, 'url', '')[:60]}")
        if getattr(v, 'parameter', None):
            print(f"          param={v.parameter}  payload={str(getattr(v, 'payload', ''))[:60]}")

    return label, len(vulns), vulns


async def main():
    targets = [
        ("http://192.168.18.131/dvwa/login.php", "DVWA Login"),
        ("http://192.168.18.131/mutillidae/index.php?page=login.php", "Mutillidae"),
        ("http://192.168.18.131/phpMyAdmin/", "phpMyAdmin"),
    ]

    total_vulns = 0
    all_results = []

    for url, label in targets:
        name, count, vulns = await scan_url(url, label)
        total_vulns += count
        all_results.append((name, count, vulns))

    print(f"\n{'='*55}")
    print(f"  QUICK SCAN COMPLETE")
    print(f"  Total vulnerabilities found: {total_vulns}")
    print(f"{'='*55}")
    for name, count, vulns in all_results:
        print(f"  {name}: {count} vulnerabilities")

    return all_results


if __name__ == "__main__":
    asyncio.run(main())
