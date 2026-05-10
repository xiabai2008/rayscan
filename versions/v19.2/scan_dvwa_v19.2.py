"""v19.2 DVWA scan — full pipeline with pre-login cookies"""
import asyncio, sys, time, os, re, json
from datetime import datetime; from pathlib import Path

DVWA_URL = "http://172.17.43.129:8888/dvwa"
SCAN_DIR = Path(r"C:\Users\HZR\Desktop\wvs-v19.2")
sys.path.insert(0, str(SCAN_DIR))

import urllib3; urllib3.disable_warnings()
import requests
from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.core.scanner import WAVScanner
from wvs.models import ScanTarget

def init_dvwa():
    """Initialize DVWA: setup DB, login, set security=low. Returns cookies dict."""
    s = requests.Session(); s.verify = False
    
    # Setup database
    r = loop_get(s, f"{DVWA_URL}/setup.php")
    if "Create / Reset Database" in r.text:
        tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
        s.post(f"{DVWA_URL}/setup.php",
               data={"create_db": "Create / Reset Database", "user_token": tk},
               timeout=15)
        print("[init] database reset")
    
    # Login
    r = s.get(f"{DVWA_URL}/login.php", timeout=15)
    tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
    r2 = s.post(f"{DVWA_URL}/login.php",
                data={"username": "admin", "password": "password", "Login": "Login", "user_token": tk},
                timeout=15, allow_redirects=True)
    ok = "Welcome" in r2.text
    print(f"[init] login {'OK' if ok else 'FAIL'}")
    
    # Security level
    r = s.get(f"{DVWA_URL}/security.php", timeout=15)
    tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    tk2 = tk_m.group(1) if tk_m else ""
    s.post(f"{DVWA_URL}/security.php",
           data={"security": "low", "seclev_submit": "Submit", "user_token": tk2},
           timeout=15)
    print(f"[init] security={s.cookies.get('security', 'none')}")
    
    return s.cookies.get_dict()

def loop_get(session, url, max_retries=10):
    for _ in range(max_retries):
        try:
            return session.get(url, timeout=10)
        except Exception:
            time.sleep(2)
    raise RuntimeError(f"Cannot reach {url}")

async def main():
    cookies = init_dvwa()
    print(f"[init] cookies: {list(cookies.keys())}")
    
    # Config
    config = ConfigManager()
    config.set("timeout", 15)
    config.set("retry_count", 0)
    config.set("verify_ssl", False)
    config.set("max_time", 900)  # 15 min
    config.set("rate_limit", 15)
    config.set("max_urls", 15)  # only crawl a few pages, rely on lab endpoints
    # Speed up: disable time-blind SQLi (Boolean-blind is enough for DVWA)
    config.set("modules.sqli.custom_params.test_time_based", False)
    
    # Build session with pre-set cookies
    session = HTTPPool(config)
    for name, value in cookies.items():
        session.set_cookie(DVWA_URL, name, value, domain="172.17.43.129")
    
    # Verify auth works
    r = await session.get(f"{DVWA_URL}/vulnerabilities/sqli/", timeout=15)
    has_form = "name=\"id\"" in r.text
    print(f"[verify] sqli page: {r.status_code}, has_form={has_form}")
    
    if not has_form:
        print("[!] Auth may have failed — proceeding anyway")
    
    # Create scanner with our session
    scanner = WAVScanner(config=config, session=session)
    scanner.load_all_modules()
    print(f"[scanner] loaded {len(scanner._modules)} modules: {list(scanner._modules.keys())}")
    
    # Create target with cookies (this skips lab auth)
    target = ScanTarget(url=DVWA_URL, cookies=cookies)
    
    # Run full scan
    t0 = time.time()
    result = await scanner.scan(target)
    elapsed = time.time() - t0
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"  Scan Complete — {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"  Endpoints: {result.endpoints_found}")
    print(f"  Requests: {result.requests_made}")
    print(f"  Modules: {result.modules_run}")
    print(f"  Vulnerabilities: {len(result.vulnerabilities)}")
    
    by_type = {}
    for v in result.vulnerabilities:
        t = v.type.value if hasattr(v.type, "value") else str(v.type)
        by_type[t] = by_type.get(t, 0) + 1
    
    for tc, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {tc}: {c}")
    
    # Top findings
    for v in result.vulnerabilities[:15]:
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        mod = getattr(v, "module", "?")
        ev = (getattr(v, "evidence", "") or "")[:100]
        print(f"    [{sev}] {v.url}|{v.parameter}|{mod}|{ev}")
    
    print(f"{'='*60}")
    
    # Save report
    report_dir = SCAN_DIR / "scan_reports"
    report_dir.mkdir(exist_ok=True)
    report_path = report_dir / f"report_dvwa_v19.2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
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
        except Exception:
            pass
    
    report_path.write_text(json.dumps({
        "tool": "WVS v19.2",
        "target": DVWA_URL,
        "scan_time": datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 1),
        "requests_made": result.requests_made,
        "endpoints_found": result.endpoints_found,
        "total_vulnerabilities": len(result.vulnerabilities),
        "vulnerabilities_by_type": by_type,
        "vulnerabilities": vuln_list,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    
    print(f"[report] {report_path}")

asyncio.run(main())
