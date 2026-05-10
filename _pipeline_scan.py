"""WVS v19.2 full pipeline scan — DVWA (crawler + scanner)"""
import sys, time, re, os, asyncio, json, logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, r"C:\Users\HZR\Desktop\wvs-v19.2")
os.chdir(r"C:\Users\HZR\Desktop\wvs-v19.2")

import urllib3; urllib3.disable_warnings()
import requests
from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.core.scanner import WAVScanner
from wvs.models import ScanTarget

logging.basicConfig(level=logging.WARNING, format="%(levelname)-7s %(message)s")
logger = logging.getLogger("wvs")
logger.setLevel(logging.WARNING)

DVWA_URL = "http://172.17.43.129:8888/dvwa"

# ── Step 1: Initialize DVWA ──
print("[1/4] Initializing DVWA...")
s = requests.Session(); s.verify = False
for _ in range(5):
    try: r = s.get(f"{DVWA_URL}/setup.php", timeout=10); break
    except: time.sleep(2)

if "Create / Reset Database" in r.text:
    tk = re.search(r"user_token' value='([^']+)'", r.text).group(1)
    s.post(f"{DVWA_URL}/setup.php", data={"create_db":"Create / Reset Database","user_token":tk}, timeout=15)
    print("  [setup] Database initialized")

# Login
r = s.get(f"{DVWA_URL}/login.php", timeout=10)
tk = re.search(r"user_token' value='([^']+)'", r.text).group(1)
s.post(f"{DVWA_URL}/login.php", data={"username":"admin","password":"password","Login":"Login","user_token":tk}, timeout=15, allow_redirects=True)

# Set security to low
r = s.get(f"{DVWA_URL}/security.php", timeout=10)
tk = re.search(r"user_token' value='([^']+)'", r.text).group(1)
s.post(f"{DVWA_URL}/security.php", data={"security":"low","seclev_submit":"Submit","user_token":tk}, timeout=15)
cookies = s.cookies.get_dict()

r = s.get(f"{DVWA_URL}/index.php", timeout=10)
print(f"  [auth] security={cookies.get('security')} | logged in: {'DVWA' in r.text and 'Logout' in r.text} | {len(r.text)}B")

# ── Step 2: Set up WVS scanner with auth cookies ──
print("[2/4] Setting up WVS...")
config = ConfigManager()
config.set("timeout", 15)
config.set("retry_count", 1)
config.set("verify_ssl", False)
config.set("max_depth", 2)
config.set("max_pages", 80)
config.set("rate", 5)
config.set("delay", 0.2)
config.set("threads", 2)

session = HTTPPool(config)
scanner = WAVScanner(config, session)

# Inject cookies into HTTPPool
for name, value in cookies.items():
    session.set_cookie(DVWA_URL, name, value)
print(f"  Cookies injected: {list(cookies.keys())}")

# Load all modules
scanner.load_all_modules()
print(f"  Modules: {list(scanner._modules.keys())}")

# ── Step 3: Run full crawl + scan ──
print("[3/4] Starting full pipeline (crawler + scanner)...")
target = ScanTarget(url=DVWA_URL + "/")

t0 = time.time()
async def run():
    return await scanner.scan(target)
result = asyncio.run(run())
elapsed = time.time() - t0

# ── Step 4: Report ──
print(f"\n[4/4] Done in {elapsed:.0f}s ({elapsed/60:.1f}min)")
print(f"  Requests: {result.requests_made}")
print(f"  Endpoints: {result.endpoints_found}")
print(f"  Vulnerabilities: {len(result.vulnerabilities)}")

by_type = {}
sev_count = {}
for v in result.vulnerabilities:
    t = v.type.value if hasattr(v.type, "value") else str(v.type)
    by_type[t] = by_type.get(t, 0) + 1
    s = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
    sev_count[s] = sev_count.get(s, 0) + 1

print(f"\n  By type:")
for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
    print(f"    {t}: {c}")
print(f"  By severity: {sev_count}")

print(f"\n  Details:")
for v in result.vulnerabilities:
    sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
    mod = getattr(v, "module", "?")
    url_part = v.url.split("/")[-2] if "/" in (v.url or "") else v.url
    param = v.parameter or "-"
    ev = str(getattr(v, "evidence", "") or "")[:80]
    print(f"    [{sev:6}] {mod:6} | {url_part:12} | {param:10} | {ev}")

# Save report
report_dir = Path(r"C:\Users\HZR\Desktop\wvs-v19.2\scan_reports")
report_dir.mkdir(exist_ok=True)
report_path = report_dir / f"report_pipeline_dvwa_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
vuln_list = []
for v in result.vulnerabilities:
    vuln_list.append({
        "type": v.type.value if hasattr(v.type, "value") else str(v.type),
        "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
        "url": v.url, "parameter": v.parameter, "module": getattr(v, "module", "?"),
        "evidence": getattr(v, "evidence", ""),
    })
data = {
    "scan_time": datetime.now().isoformat(),
    "duration": elapsed,
    "requests": result.requests_made,
    "endpoints": result.endpoints_found,
    "total_vulnerabilities": len(result.vulnerabilities),
    "vulnerabilities_by_type": by_type,
    "vulnerabilities": vuln_list,
}
report_path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
print(f"\n  Report: {report_path}")
