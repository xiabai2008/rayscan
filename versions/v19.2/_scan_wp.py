"""WVS v19.2 — 最快路径测试: SQLi + XSS + LFI + JSPathfinder + Wappalyzer"""
import asyncio, time, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
TARGET = 'http://172.17.43.131/wordpress/'

async def main():
    from wvs.core.scanner import WAVScanner
    from wvs.models import ScanTarget
    from wvs.config import ConfigManager

    cfg = ConfigManager()
    cfg.set("crawl_depth", 1)
    cfg.set("crawl_max_urls", 20)
    cfg.set("concurrent_endpoints", 4)
    cfg.set("max_time", 300)
    cfg.set("enable_waf_detection", True)

    # 只开最稳定的模块
    for m in ['sqli','xss','lfi','jspathfinder','waf']:
        cfg.set(f"modules.{m}.enabled", True)
    for m in ['cmdi','rce','ssrf','xxe','api','sensitive']:
        cfg.set(f"modules.{m}.enabled", False)

    cfg.set("integrations.enabled", True)
    cfg.set("integrations.wappalyzer.enabled", True)
    cfg.set("integrations.ffuf.enabled", False)
    cfg.set("integrations.sqlmap.enabled", False)
    cfg.set("integrations.nuclei.enabled", False)

    scanner = WAVScanner(config=cfg)
    target = ScanTarget(url=TARGET)

    t0 = time.time()
    result = await scanner.scan(target)
    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"  WordPress 快速扫描")
    print(f"{'='*60}")
    print(f"  Duration:    {elapsed:.1f}s")
    print(f"  Requests:    {result.requests_made}")
    print(f"  Endpoints:   {result.endpoints_found}")
    print(f"  Vulns:       {len(result.vulnerabilities)}")
    print(f"  Modules:     {result.modules_run}")

    by_sev, by_type = {}, {}
    for v in result.vulnerabilities:
        sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        by_sev[sev] = by_sev.get(sev, 0) + 1
        vt = v.type.value if hasattr(v.type, 'value') else str(v.type)
        by_type[vt] = by_type.get(vt, 0) + 1

    print(f"\n  By Severity:")
    for s in ['critical','high','medium','low','info']:
        if s in by_sev: print(f"    {s:10s}: {by_sev[s]}")
    print(f"\n  All Findings:")
    for i, v in enumerate(result.vulnerabilities):
        sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
        src = getattr(v, 'source', '?')
        print(f"  {i+1:2d}. [{sev:8s}] [{src:12s}] {v.title[:95]}")
    print(f"{'='*60}")

if __name__ == '__main__':
    import urllib3; urllib3.disable_warnings()
    asyncio.run(main())
