"""v19.2 Cloud DVWA scan — rate-limited, gordonb auth, no crawler"""
import asyncio, sys, time, gc, json, re
from datetime import datetime; from pathlib import Path

# ⚠ CLOUD SERVER — conservative settings
CLOUD_URL = "http://47.95.192.41:8081"
CONCURRENT = 2           # mild concurrency (safe for ECS)
REQUEST_DELAY = 0.3       # 300ms between requests
TASK_TIMEOUT = 90          # per-endpoint timeout

sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19.2')

import urllib3; urllib3.disable_warnings()
import requests
from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.modules.base import DetectionModule, ScanTarget

# ── Init: login as gordonb, set security=low ──
def init():
    s = requests.Session(); s.verify = False
    for _ in range(5):
        try:
            r = s.get(f"{CLOUD_URL}/login.php", timeout=10)
            break
        except:
            time.sleep(2)
    
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
    
    print(f"[init] cookies={s.cookies.get_dict()}")
    return s.cookies.get_dict()

# ── Cloud DVWA endpoints (no /dvwa/ prefix, /exec/ for CMDi) ──
ENDPOINTS = [
    ("sqli",        "GET",  "/vulnerabilities/sqli/",        {"id": "1", "Submit": "Submit"}),
    ("sqli_blind",  "GET",  "/vulnerabilities/sqli_blind/",  {"id": "1", "Submit": "Submit"}),
    ("xss_r",       "GET",  "/vulnerabilities/xss_r/",       {"name": "test"}),
    ("xss_s",       "POST", "/vulnerabilities/xss_s/",       {"txtName": "test", "mtxMessage": "test", "btnSign": "Sign"}),
    ("xss_d",       "GET",  "/vulnerabilities/xss_d/",       {"default": "English"}),
    ("fi",          "GET",  "/vulnerabilities/fi/",          {"page": "include.php"}),
    ("exec",        "POST", "/vulnerabilities/exec/",        {"ip": "127.0.0.1", "Submit": "Submit"}),
    ("brute",       "GET",  "/vulnerabilities/brute/",       {"username": "admin", "password": "password", "Login": "Login"}),
    ("csrf",        "GET",  "/vulnerabilities/csrf/",        {"password_new": "test", "password_conf": "test", "Change": "Change"}),
    ("upload",      "POST", "/vulnerabilities/upload/",      {}),
    ("csp",         "POST", "/vulnerabilities/csp/",         {"include": "test"}),
    ("javascript",  "POST", "/vulnerabilities/javascript/",  {"token": "test", "phrase": "test", "send": "Submit"}),
]

async def main():
    cookies = init()
    
    config = ConfigManager()
    config.set("timeout", 15)
    config.set("retry_count", 0)
    config.set("verify_ssl", False)
    
    session = HTTPPool(config)
    for n, v in cookies.items():
        session.set_cookie(CLOUD_URL, n, v, domain="47.95.192.41")
    
    # Build ScanTargets
    targets = []
    for name, method, path, params in ENDPOINTS:
        t = ScanTarget(
            url=f"{CLOUD_URL}{path}",
            methods=[method],
            params=params if method == "GET" else None,
            data=params if method == "POST" else None,
            cookies=cookies
        )
        targets.append((name, t))
    
    print(f"[endpoints] {len(targets)}")
    
    # Load detector modules
    import importlib
    mods = {}
    wvs_dir = Path(r"C:\Users\HZR\Desktop\wvs-v19.2\wvs")
    for pkg in sorted((wvs_dir / "modules").iterdir()):
        name = pkg.name
        if not pkg.is_dir() or not (pkg / "detector.py").exists():
            continue
        try:
            mod = importlib.import_module(f"wvs.modules.{name}.detector")
            for attr in dir(mod):
                obj = getattr(mod, attr)
                if isinstance(obj, type) and issubclass(obj, DetectionModule) and obj is not DetectionModule:
                    mods[name] = obj(config, session)
                    break
        except Exception as e:
            print(f"  [skip] {name}: {e}")
    
    print(f"[modules] {len(mods)}: {list(mods.keys())}")
    
    sem = asyncio.Semaphore(CONCURRENT)
    total = len(targets) * len(mods)
    done = [0]
    
    async def run_one(tname, t, mn, m):
        async with sem:
            await asyncio.sleep(REQUEST_DELAY)  # inter-request gap
            try:
                res = await asyncio.wait_for(m.scan(t), timeout=TASK_TIMEOUT)
                return res or []
            except asyncio.TimeoutError:
                print(f"\n  [TIMEOUT] {mn} on {tname}")
                return []
            except Exception as e:
                print(f"\n  [ERR] {mn} on {tname}: {e}")
                return []
            finally:
                done[0] += 1
                if done[0] % 12 == 0 or done[0] == total:
                    gc.collect()
                    print(f"\r  [{done[0]}/{total} {done[0]/total*100:.0f}%]", end="", flush=True)
    
    t0 = time.time()
    tasks = [run_one(tn, t, mn, m) for tn, t in targets for mn, m in mods.items()]
    results = await asyncio.gather(*tasks)
    print()
    
    all_vulns = [v for r in results if r for v in r]
    elapsed = time.time() - t0
    
    # Dedup & classify
    by_type = {}
    seen = set()
    unique = []
    for v in all_vulns:
        key = (v.url, v.parameter, str(v.type))
        if key in seen:
            continue
        seen.add(key)
        unique.append(v)
        t = v.type.value if hasattr(v.type, "value") else str(v.type)
        by_type[t] = by_type.get(t, 0) + 1
    
    print(f"\n{'='*60}")
    print(f"  Cloud DVWA Scan — {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"  Endpoints: {len(targets)}  Modules: {len(mods)}  Vulns: {len(unique)}")
    for tc, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {tc}: {c}")
    
    for v in unique:
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        mod = getattr(v, "module", "?")
        ev = (getattr(v, "evidence", "") or "")[:100]
        param = v.parameter or "-"
        name = v.url.split("/")[-2] if v.url.endswith("/") else v.url.split("/")[-1]
        print(f"    [{sev:8}] {name:12} | {param:12} | {(mod or '?'):8} | {ev}")
    print(f"{'='*60}")
    
    # Save report
    report_dir = Path(r"C:\Users\HZR\Desktop\wvs-v19.2\scan_reports")
    report_dir.mkdir(exist_ok=True)
    dt = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_path = report_dir / f"report_cloud_dvwa_v19.2_{dt}.json"
    
    import os as _os
    vuln_list = []
    for v in unique:
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
        "total_vulnerabilities": len(unique),
        "vulnerabilities_by_type": by_type,
        "vulnerabilities": vuln_list,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[report] {report_path}")

asyncio.run(main())
