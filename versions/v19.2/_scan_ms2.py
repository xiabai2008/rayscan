"""MS2保守扫描 — CONC=1, DELAY=800ms, 仅6个核心端点"""
import sys, asyncio, time, gc, importlib, re
from pathlib import Path
sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19.2')
import urllib3; urllib3.disable_warnings()
from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.models import ScanTarget

CONC = 1
DELAY = 800

config = ConfigManager()
config.set('timeout', 15); config.set('retry_count', 1); config.set('verify_ssl', False)
config.set('max_concurrent_requests', 1); config.set('request_delay_ms', DELAY)
config.set('concurrent_endpoints', CONC)

pool = HTTPPool(config)

# Load modules
wvs_dir = Path(r'C:\Users\HZR\Desktop\wvs-v19.2\wvs\modules')
mods = {}; mod_names = []
for pkg in sorted(wvs_dir.iterdir()):
    if not pkg.is_dir() or pkg.name.startswith('_') or pkg.name.startswith('.'): continue
    n = pkg.name
    try:
        m = importlib.import_module(f'wvs.modules.{n}.detector')
        from wvs.modules.base import DetectionModule
        for attr in dir(m):
            obj = getattr(m, attr)
            if isinstance(obj, type) and issubclass(obj, DetectionModule) and obj is not DetectionModule and attr != 'ModuleInfo':
                mods[n] = obj(config, pool); mod_names.append(n); break
    except Exception as e:
        print(f'  skip {n}: {e}', flush=True)

print(f'Modules: {mod_names}', flush=True)

# MS2 core endpoints
endpoints = [
    ('dvwa_login', 'http://172.17.43.128/dvwa/login.php', 'GET', {}),
    ('dvwa_setup', 'http://172.17.43.128/dvwa/setup.php', 'GET', {}),
    ('dvwa_index', 'http://172.17.43.128/dvwa/index.php', 'GET', {}),
    ('dvwa_sec', 'http://172.17.43.128/dvwa/security.php', 'GET', {}),
    ('muti', 'http://172.17.43.128/mutillidae/index.php', 'GET', {'page': 'add-to-your-blog.php'}),
    ('twiki', 'http://172.17.43.128/twiki/bin/view/Main/WebHome', 'GET', {}),
]
print(f'Endpoints: {len(endpoints)}', flush=True)

found_vulns = []
sem = asyncio.Semaphore(CONC)
lock = asyncio.Lock()

async def run_mod(name, mod, ep_url, ep_method, ep_params):
    t = ScanTarget(url=ep_url, methods=[ep_method], params=ep_params)
    async with sem:
        try:
            vs = await mod.scan(t)
            async with lock:
                for v in vs:
                    v.module = v.module or name
                    found_vulns.append(v)
        except Exception as e:
            pass

async def run_all():
    tasks = []
    for mod_name, mod in mods.items():
        for ep_name, ep_url, ep_method, ep_params in endpoints:
            await asyncio.sleep(DELAY / 1000)
            tasks.append(run_mod(mod_name, mod, ep_url, ep_method, ep_params))
    await asyncio.gather(*tasks, return_exceptions=True)

t0 = time.time()
asyncio.run(run_all())
elapsed = time.time() - t0

# Dedup
seen = set(); deduped = []
for v in found_vulns:
    key = (v.url or '', v.parameter or '', str(v.type))
    if key not in seen:
        seen.add(key); deduped.append(v)

print(f'\nDone: {elapsed:.0f}s, {len(found_vulns)} raw, {len(deduped)} deduped', flush=True)
for v in deduped:
    vt = str(v.type)
    if hasattr(v.type, 'value'): vt = v.type.value
    ev = (v.evidence or '')[:80].replace('\n', ' ')
    url_short = (v.url or '?')[-50:]
    print(f'  [{vt:25s}] {url_short:50s} {v.parameter or "-"}  {ev}', flush=True)

asyncio.run(pool.close())
