"""DVWA scan — skip crawler, direct endpoints"""
import asyncio, sys, time, os, re, json, importlib
import requests; from datetime import datetime; from pathlib import Path

DVWA_URL="http://172.17.43.129:8888/dvwa"
os.environ["PYTHONUNBUFFERED"]="1"
sys.path.insert(0,r'C:\Users\HZR\Desktop\wvs-v19')
import urllib3;urllib3.disable_warnings()
from wvs.config import ConfigManager; from wvs.core import HTTPPool
from wvs.modules.base import DetectionModule, ScanTarget

def init():
    s=requests.Session();s.verify=False
    for _ in range(10):
        try:r=s.get(f"{DVWA_URL}/setup.php",timeout=10);break
        except:time.sleep(2)
    if "Create / Reset Database" in r.text:
        tk=re.search(r"name='user_token'\s+value='([^']+)'",r.text).group(1)
        s.post(f"{DVWA_URL}/setup.php",data={"create_db":"Create / Reset Database","user_token":tk},timeout=15)
    r=s.get(f"{DVWA_URL}/login.php",timeout=15)
    tk=re.search(r"name='user_token'\s+value='([^']+)'",r.text).group(1)
    s.post(f"{DVWA_URL}/login.php",data={"username":"admin","password":"password","Login":"Login","user_token":tk},timeout=15,allow_redirects=True)
    r=s.get(f"{DVWA_URL}/security.php",timeout=15)
    tk=re.search(r"name='user_token'\s+value='([^']+)'",r.text)
    tk=tk.group(1) if tk else ""
    s.post(f"{DVWA_URL}/security.php",data={"security":"low","seclev_submit":"Submit","user_token":tk},timeout=15)
    print(f"[init] security={'low' if 'low' in s.cookies.get('security','') else 'FAIL:'+s.cookies.get('security','none')}")
    return s.cookies.get_dict()

MANUAL_ENDPOINTS = [
    (["GET"],  "/vulnerabilities/sqli/",      None, {"id":""}),
    (["GET"],  "/vulnerabilities/sqli_blind/", None, {"id":""}),
    (["GET"],  "/vulnerabilities/xss_r/",      None, {"name":""}),
    (["POST"], "/vulnerabilities/xss_s/",      {"txtName":"","mtxMessage":"","btnSign":"Sign Guestbook"}, None),
    (["POST"], "/vulnerabilities/exec/",       {"ip":"","Submit":"Submit"}, None),
    (["GET"],  "/vulnerabilities/fi/",         None, {"page":"include.php"}),
    (["POST"], "/vulnerabilities/upload/",     {"MAX_FILE_SIZE":"100000","Upload":"Upload"}, None),
    (["GET"],  "/vulnerabilities/csrf/",       None, {"password_new":"","password_conf":"","Change":"Change"}),
    (["GET"],  "/vulnerabilities/brute/",      None, {"username":"","password":"","Login":"Login"}),
    (["POST"], "/vulnerabilities/captcha/",    {"step":"1","password_new":"","password_conf":"","Change":"Change"}, None),
    (["GET"],  "/vulnerabilities/xss_d/",      None, {"default":"English"}),
    (["POST"], "/vulnerabilities/csp/",        {"include":""}, None),
    (["POST"], "/vulnerabilities/javascript/", {"token":"","phrase":"","send":"Submit"}, None),
]

async def main():
    cookies=init()
    print(f"[init] {list(cookies.keys())}")

    config=ConfigManager()
    for k,v in {"timeout":15,"retry_count":0,"verify_ssl":False}.items():config.set(k,v)
    session=HTTPPool(config)
    for n,v in cookies.items():session.set_cookie(DVWA_URL,n,v,domain="172.17.43.129")

    # Verify
    r=await session.get(f"{DVWA_URL}/vulnerabilities/sqli/",timeout=15)
    print(f"[verify] sqli: {r.status_code} {len(r.text)}B form={'Y' if 'name=\"id\"' in r.text else 'N'}")

    # Build ScanTargets directly from manual endpoints
    targets=[]
    for methods,path,data,params in MANUAL_ENDPOINTS:
        full_url=DVWA_URL+path
        name=path.split("/")[2]
        t=ScanTarget(url=full_url,methods=methods,params=params,data=data,cookies=cookies)
        targets.append((name,t))
    print(f"[targets] {len(targets)} manual targets")

    # Relogin (just in case)
    cookies=init();session=HTTPPool(config)
    for n,v in cookies.items():session.set_cookie(DVWA_URL,n,v,domain="172.17.43.129")

    t0=time.time()
    mods={}
    wvs_dir=Path(r"C:\Users\HZR\Desktop\wvs-v19\wvs")
    for pkg in sorted((wvs_dir/"modules").iterdir()):
        name=pkg.name
        if not pkg.is_dir() or name=="waf" or not (pkg/"detector.py").exists():continue
        try:
            mod=importlib.import_module(f"wvs.modules.{name}.detector")
            for attr in dir(mod):
                obj=getattr(mod,attr)
                if isinstance(obj,type) and issubclass(obj,DetectionModule) and obj is not DetectionModule:
                    mods[name]=obj(config,session);break
        except:pass

    print(f"[detect] {len(mods)} mods x {len(targets)} targets")
    sem=asyncio.Semaphore(3);total=len(targets)*len(mods);done=[0]
    async def run(tname,target,mn,mod):
        async with sem:
            try:return await asyncio.wait_for(mod.scan(target) or [],timeout=120)
            except asyncio.TimeoutError:
                print(f"\n[TIMEOUT] {mn} on {tname}",flush=True)
                return []
            except:return []
            finally:
                done[0]+=1
                if done[0]%30==0 or done[0]==total:print(f"\r  [{done[0]}/{total} {done[0]/total*100:.0f}%]",end="",flush=True)
    tasks=[run(tname,t,mn,mod) for tname,t in targets for mn,mod in mods.items()]
    results=await asyncio.gather(*tasks);print()
    all_vulns=[v for r in results if r for v in r]

    elapsed=time.time()-t0;by_type={}
    for v in all_vulns:
        t=v.type.value if hasattr(v.type,"value") else str(v.type)
        by_type[t]=by_type.get(t,0)+1
    print(f"\n{'='*50}")
    print(f"  Time:{elapsed:.0f}s ({elapsed/60:.1f}min) Targets:{len(targets)} Vulns:{len(all_vulns)}")
    for tc,c in sorted(by_type.items(),key=lambda x:-x[1]):print(f"    {tc}: {c}")
    for v in all_vulns[:20]:
        sev=v.severity.value if hasattr(v.severity,"value") else str(v.severity)
        print(f"    [{sev}] {v.url}|{v.parameter}|{getattr(v,'module','')}|{(getattr(v,'evidence','') or '')[:80]}")
    print(f"{'='*50}")
    Path("scan_reports").mkdir(exist_ok=True)
    try:
        report_dir=Path(r"C:\Users\HZR\Desktop\wvs-v19\scan_reports")
        report_dir.mkdir(exist_ok=True)
        report_path=report_dir/f"report_dvwa_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        vuln_list=[]
        for v in all_vulns:
            try:
                vuln_list.append({
                    "type":v.type.value if hasattr(v.type,"value") else str(v.type),
                    "url":v.url,"parameter":v.parameter,"module":getattr(v,"module",""),
                    "severity":v.severity.value if hasattr(v.severity,"value") else str(v.severity),
                    "evidence":(getattr(v,"evidence","") or "")[:200],
                    "payload":(getattr(v,"payload","") or "")[:200]
                })
            except:pass
        report_path.write_text(json.dumps({
            "scan_time":datetime.now().isoformat(),"target":DVWA_URL,
            "duration_seconds":round(elapsed,1),
            "total_vulnerabilities":len(all_vulns),
            "vulnerabilities_by_type":by_type,
            "vulnerabilities":vuln_list
        },indent=2,ensure_ascii=False),encoding="utf-8")
        print(f"[report] {report_path}")
    except Exception as e:
        print(f"[report] FAILED: {e}")

asyncio.run(main())
