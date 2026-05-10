"""P20 verification: compare time-based SQLi performance before/after.
Runs SQli module only on cloud DVWA, measures time-based phase duration.
"""
import sys, time, asyncio, re
sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19.2')
import urllib3; urllib3.disable_warnings()
import requests
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.modules.sqli.detector import SQLiDetector
from wvs.models import ScanTarget

CLOUD = "http://47.95.192.41:8081"

def login():
    s = requests.Session(); s.verify = False
    r = s.get(f"{CLOUD}/login.php", timeout=10)
    tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
    s.post(f"{CLOUD}/login.php",
           data={"username": "admin", "password": "password",
                 "Login": "Login", "user_token": tok},
           allow_redirects=True, timeout=15)
    r = s.get(f"{CLOUD}/security.php", timeout=10)
    tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    if tk_m:
        s.post(f"{CLOUD}/security.php",
               data={"security": "low", "seclev_submit": "Submit", "user_token": tk_m.group(1)})
    return s.cookies.get_dict()

async def main():
    cookies = login()
    print(f"Logged in, security={cookies.get('security')}", flush=True)

    config = ConfigManager()
    config.set("timeout", 15)
    config.set("retry_count", 1)
    config.set("verify_ssl", False)

    session = HTTPPool(config)
    for n, v in cookies.items():
        session.set_cookie(CLOUD, n, v, domain="47.95.192.41")

    sqli = SQLiDetector(config, session)

    # Test all 12 DVWA endpoints
    endpoints = [
        (f"{CLOUD}/vulnerabilities/sqli/", {"id": "1", "Submit": "Submit"}, "GET"),
        (f"{CLOUD}/vulnerabilities/sqli_blind/", {"id": "1", "Submit": "Submit"}, "GET"),
        (f"{CLOUD}/vulnerabilities/xss_r/", {"name": "test"}, "GET"),
        (f"{CLOUD}/vulnerabilities/xss_s/", {"txtName": "test", "mtxMessage": "test"}, "GET"),
        (f"{CLOUD}/vulnerabilities/xss_d/", {}, "GET"),
        (f"{CLOUD}/vulnerabilities/fi/", {"page": "include.php"}, "GET"),
        (f"{CLOUD}/vulnerabilities/exec/", {"ip": "127.0.0.1"}, "POST"),
        (f"{CLOUD}/vulnerabilities/brute/", {"username": "admin", "password": "test"}, "GET"),
        (f"{CLOUD}/vulnerabilities/csrf/", {}, "GET"),
        (f"{CLOUD}/vulnerabilities/upload/", {}, "GET"),
        (f"{CLOUD}/vulnerabilities/csp/", {"include": "test"}, "GET"),
        (f"{CLOUD}/vulnerabilities/javascript/", {}, "GET"),
    ]

    for url, params, method in endpoints:
        t = ScanTarget(url=url, methods=[method], params=params if method=="GET" else None,
                       data=params if method=="POST" else None,
                       cookies=cookies)

        t0 = time.time()
        vulns = await sqli.scan(t)
        elapsed = time.time() - t0

        vuln_types = set()
        for v in vulns:
            vt = v.type.value if hasattr(v.type, 'value') else str(v.type)
            vuln_types.add(vt)
        status = "+".join(sorted(vuln_types)) if vuln_types else "-"
        print(f"  {elapsed:5.1f}s | {url.split('/')[-2]:12s} | {status}", flush=True)

    await session.close()
    print("Done", flush=True)

asyncio.run(main())
