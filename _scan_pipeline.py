"""v19.2 Full pipeline test — crawl → scan, rate-limited for cloud DVWA

Runs the REAL scanner pipeline (not direct endpoint injection).
Tests: merge logic fix, rate limiting, Wappalyzer, P18 lock.
"""
import asyncio, sys, time, json, re, os
# P19: line-buffered stdout for background process logs
sys.stdout.reconfigure(line_buffering=True) if hasattr(sys.stdout, 'reconfigure') else None
os.environ['PYTHONUNBUFFERED'] = '1'
from datetime import datetime
from pathlib import Path

# Import from project root (pip install -e . first)
import urllib3; urllib3.disable_warnings()
import requests
from wvs.config import ConfigManager
from wvs.core.scanner import WAVScanner, ScanTarget

CLOUD_URL = "http://47.95.192.41:8081"

# ── Login as gordonb ──
def login():
    s = requests.Session(); s.verify = False
    for _ in range(5):
        try: r = s.get(f"{CLOUD_URL}/login.php", timeout=10); break
        except: time.sleep(2)

    tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
    s.post(f"{CLOUD_URL}/login.php",
           data={"username": "admin", "password": "password",
                 "Login": "Login", "user_token": tok},
           timeout=15, allow_redirects=True)

    r = s.get(f"{CLOUD_URL}/security.php", timeout=10)
    tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    tk2 = tk_m.group(1) if tk_m else ""
    s.post(f"{CLOUD_URL}/security.php",
           data={"security": "low", "seclev_submit": "Submit", "user_token": tk2},
           timeout=15)

    print(f"[init] security={s.cookies.get('security','none')}", flush=True)
    print(f"[init] PHPSESSID={s.cookies.get('PHPSESSID','')}", flush=True)
    return s.cookies.get_dict()

async def main():
    cookies = login()

    config = ConfigManager()
    # ── P19: Conservative rate limits for fragile cloud targets ──
    config.set("max_connections", 8)           # httpx pool limit
    config.set("max_concurrent_requests", 99)   # P19: unbounded — let RPS+pool+delay control rate
    config.set("concurrent_endpoints", 3)       # per-module concurrency
    config.set("request_delay_ms", 200)         # 200ms gap between requests
    config.set("max_requests_per_second", 5)    # RPS limit
    config.set("timeout", 15)
    config.set("retry_count", 1)
    config.set("verify_ssl", False)
    config.set("crawl_depth", 2)
    config.set("crawl_max_urls", 50)
    config.set("max_time", 1800)  # 30min max

    # Disable heavy integrations for this test
    config.set("integrations.enabled", False)
    config.set("enable_waf_detection", False)

    target = ScanTarget(url=CLOUD_URL, cookies=cookies)

    scanner = WAVScanner(config=config)
    scanner.load_all_modules()
    print(f"[modules] {scanner._loaded_module_names}", flush=True)
    print("[scan] starting...", flush=True)

    t0 = time.time()
    result = await scanner.scan(target)
    elapsed = time.time() - t0

    # ── Summary ──
    print(f"\n{'='*60}")
    print(f"  Pipeline Test Complete")
    print(f"  Duration : {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"  Requests : {result.requests_made}")
    print(f"  Found    : {len(result.vulnerabilities)}")
    print()

    by_type = {}
    for v in result.vulnerabilities:
        t = v.type.value if hasattr(v.type, "value") else str(v.type)
        by_type[t] = by_type.get(t, 0) + 1

    for tc, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {tc}: {c}")
    print()

    for v in result.vulnerabilities:
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        mod = getattr(v, "module", "?")
        ev = (getattr(v, "evidence", "") or "")[:100]
        print(f"    [{sev:8}] {v.url[:60]:30} | {(v.parameter or '-'):10} | {(mod or '?'):8} | {ev}")
    print(f"{'='*60}")

    # Save report
    report_dir = Path(r"C:\Users\HZR\Desktop\wvs-v19.2\scan_reports")
    report_dir.mkdir(exist_ok=True)
    dt = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = report_dir / f"report_cloud_pipeline_v19.2_{dt}.json"

    vuln_list = []
    for v in result.vulnerabilities:
        try:
            vuln_list.append({
                "type": v.type.value if hasattr(v.type, "value") else str(v.type),
                "url": v.url,
                "parameter": v.parameter,
                "module": getattr(v, "module", ""),
                "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                "evidence": (getattr(v, "evidence", "") or "")[:200],
                "payload": (getattr(v, "payload", "") or "")[:200],
            })
        except: pass

    report_path.write_text(json.dumps({
        "tool": "WVS v19.2",
        "target": CLOUD_URL,
        "scan_time": datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 1),
        "requests": result.requests_made,
        "total_vulnerabilities": len(result.vulnerabilities),
        "vulnerabilities_by_type": by_type,
        "vulnerabilities": vuln_list,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[report] {report_path}")

    await scanner.session.close()

asyncio.run(main())
