"""Direct module test against DVWA"""
import asyncio, sys, time, os, re
sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19.2')
import urllib3; urllib3.disable_warnings()
import requests

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.xss.detector import XSSDetector
from wvs.modules.cmdi.detector import CMDInjectionDetector
from wvs.modules.lfi.detector import LFIDetector
from wvs.modules.ssrf.detector import SSRFDetector
from wvs.modules.rce.detector import RCEDetector

DVWA = "http://172.17.43.129:8888/dvwa"

def init():
    s = requests.Session(); s.verify = False
    for i in range(10):
        try: r = s.get(f"{DVWA}/setup.php", timeout=10); break
        except: time.sleep(2)
    if "Create / Reset Database" in r.text:
        tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
        s.post(f"{DVWA}/setup.php", data={"create_db":"Create / Reset Database","user_token":tk}, timeout=15)
    r = s.get(f"{DVWA}/login.php", timeout=10)
    tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
    s.post(f"{DVWA}/login.php", data={"username":"admin","password":"password","Login":"Login","user_token":tk}, timeout=15, allow_redirects=True)
    r = s.get(f"{DVWA}/security.php", timeout=10)
    tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    tk2 = tk_m.group(1) if tk_m else ""
    s.post(f"{DVWA}/security.php", data={"security":"low","seclev_submit":"Submit","user_token":tk2}, timeout=15)
    return s.cookies.get_dict()

async def test_module(name, cls, target):
    """Test one module"""
    try:
        cfg = ConfigManager()
        cfg.set("timeout", 15)
        cfg.set("retry_count", 0)
        session = HTTPPool(cfg)
        cookies = init()
        for n, v in cookies.items():
            session.set_cookie(DVWA, n, v, domain="172.17.43.129")
        mod = cls(config=cfg, session=session)
        results = await asyncio.wait_for(mod.scan(target), timeout=120)
        if results:
            for v in results[:3]:
                sev = v.severity.value if hasattr(v.severity, "value") else str(v.severity)
                ev = (getattr(v, "evidence", "") or "")[:80]
                print(f"  [{sev}] {v.parameter}: {ev}")
        return len(results) if results else 0
    except asyncio.TimeoutError:
        print(f"  TIMEOUT")
        return -1
    except Exception as e:
        print(f"  ERROR: {e}")
        return -2

async def main():
    tests = [
        ("SQLi", SQLiDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/sqli/", methods=["GET"],
            params={"id": "1", "Submit": "Submit"})),
        ("SQLi_Blind", SQLiDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/sqli_blind/", methods=["GET"],
            params={"id": "1", "Submit": "Submit"})),
        ("XSS_Reflected", XSSDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/xss_r/", methods=["GET"],
            params={"name": "test"})),
        ("XSS_Stored", XSSDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/xss_s/", methods=["POST"],
            data={"txtName": "test", "mtxMessage": "test", "btnSign": "Sign"})),
        ("XSS_DOM", XSSDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/xss_d/", methods=["GET"],
            params={"default": "English"})),
        ("CMDi", CMDInjectionDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/exec/", methods=["POST"],
            data={"ip": "127.0.0.1", "Submit": "Submit"})),
        ("LFI", LFIDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/fi/", methods=["GET"],
            params={"page": "include.php"})),
        ("SSRF", SSRFDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/fi/", methods=["GET"],
            params={"page": "include.php"})),
        ("RCE", RCEDetector, ScanTarget(
            url=f"{DVWA}/vulnerabilities/exec/", methods=["POST"],
            data={"ip": "127.0.0.1", "Submit": "Submit"})),
    ]
    
    print("Module-by-module DVWA test (low security)")
    print("=" * 50)
    for name, cls, target in tests:
        count = await test_module(name, cls, target)
        print(f"{name}: {count} vuln(s)")
    
asyncio.run(main())
