"""v19.2 DVWA direct scan — lab endpoints only, no crawler"""
import asyncio, sys, time, os, re, json
from datetime import datetime; from pathlib import Path

DVWA_URL = "http://172.17.43.129:8888/dvwa"
sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19.2')

import urllib3; urllib3.disable_warnings()
import requests
from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.core.lab_profiles import DVWA_PROFILE, get_lab_endpoints
from wvs.modules.base import DetectionModule, ScanTarget

def init():
    s = requests.Session(); s.verify = False
    for _ in range(5):
        try: r = s.get(f"{DVWA_URL}/setup.php", timeout=10); break
        except: time.sleep(2)
    if "Create / Reset Database" in r.text:
        tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
        s.post(f"{DVWA_URL}/setup.php", data={"create_db":"Create / Reset Database","user_token":tk}, timeout=15)
    r = s.get(f"{DVWA_URL}/login.php", timeout=10)
    tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
    s.post(f"{DVWA_URL}/login.php", data={"username":"admin","password":"password","Login":"Login","user_token":tk}, timeout=15, allow_redirects=True)
    r = s.get(f"{DVWA_URL}/security.php", timeout=10)
    tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    tk2 = tk_m.group(1) if tk_m else ""
    s.post(f"{DVWA_URL}/security.php", data={"security":"low","seclev_submit":"Submit","user_token":tk2}, timeout=15)
    print(f"[init] security={s.cookies.get('security','none')}")
    return s.cookies.get_dict()

async def main():
    cookies = init()
    config = ConfigManager()
    config.set("timeout", 15)
    config.set("retry_count", 0)
    config.set("verify_ssl", False)
    
    session = HTTPPool(config)
    for n, v in cookies.items():
        session.set_cookie(DVWA_URL, n, v, domain="172.17.43.129")
    
    # Load only lab endpoints (correct params, correct methods)
    lab_eps = get_lab_endpoints(DVWA_PROFILE, DVWA_URL)
    print(f"[lab] {len(lab_eps)} endpoints")
    for e in lab_eps:
        print(f"  {e.url} [{e.method}] params={list(e.parameters.keys())[:4]}")
    
    # Build ScanTargets
    targets = []
    for ep in lab_eps:
        t = ScanTarget(
            url=ep.url, methods=[ep.method],
            params=ep.parameters if ep.method == "GET" else None,
            data=ep.parameters if ep.method == "POST" else None,
            cookies=cookies
        )
        name = ep.url.split("/")[-2] if ep.url.endswith("/") else ep.url.split("/")[-1]
        targets.append((name, t))
    
    # Load all detector modules
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
    
    print(f"[mods] {len(mods)} modules: {list(mods.keys())}")
    
    # Run all modules on all targets with concurrency control
    import gc
    sem = asyncio.Semaphore(2)
    total = len(targets) * len(mods)
    done = [0]
    
    # P18: per-module locks prevent concurrent scan() on same instance
    #      _scan_impl uses self._found_vulns as accumulator → concurrency unsafe
    mod_locks = {mn: asyncio.Lock() for mn in mods}
    
    async def run_one(tname, t, mn, m):
        async with mod_locks[mn]:  # serialize same-module, different-target scans
            async with sem:
                await asyncio.sleep(0.1)  # P16: inter-task gap prevents burst
                try:
                    res = await asyncio.wait_for(m.scan(t), timeout=60)
                    return res or []
                except asyncio.TimeoutError:
                    return []
                except Exception as e:
                    return []
                finally:
                    done[0] += 1
                    if done[0] % 24 == 0 or done[0] == total:
                        gc.collect()
                        print(f"\r  [{done[0]}/{total} {done[0]/total*100:.0f}%]", end="", flush=True)
    
    t0 = time.time()
    tasks = [run_one(tn, t, mn, m) for tn, t in targets for mn, m in mods.items()]
    results = await asyncio.gather(*tasks)
    print()
    
    all_vulns = [v for r in results if r for v in r]
    elapsed = time.time() - t0
    
    # Dedup & summarize
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
    print(f"  DVWA Full Scan — {elapsed:.0f}s ({elapsed/60:.1f}min)")
    print(f"  Endpoints: {len(targets)}  Modules: {len(mods)}  Vulns: {len(unique)}")
    for tc, c in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"    {tc}: {c}")
    
    for v in unique[:25]:
        sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
        mod = getattr(v, "module", "?")
        ev = (getattr(v, "evidence", "") or "")[:80]
        print(f"    [{sev:8}] {v.url.split('/')[-2]:12} | {(v.parameter or '-'):10} | {(mod or '?'):8} | {ev}")
    print(f"{'='*60}")
    
    # Save report
    report_dir = Path(r"C:\Users\HZR\Desktop\wvs-v19.2\scan_reports")
    report_dir.mkdir(exist_ok=True)
    report_path = report_dir / f"report_dvwa_v19.2_direct_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
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
        "target": DVWA_URL,
        "scan_time": datetime.now().isoformat(),
        "duration_seconds": round(elapsed, 1),
        "total_vulnerabilities": len(unique),
        "vulnerabilities_by_type": by_type,
        "vulnerabilities": vuln_list,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[report] {report_path}")

asyncio.run(main())
