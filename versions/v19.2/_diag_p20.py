import sys, asyncio, re, requests, urllib3
urllib3.disable_warnings()
sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19.2')

from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget

BASE = 'http://47.95.192.41:8081'

async def main():
    # 1. Login with requests (known working)
    s = requests.Session(); s.verify = False
    # Reset DB first (safety)
    r = s.get(f'{BASE}/setup.php', timeout=10)
    tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    if tok:
        s.post(f'{BASE}/setup.php',
            data={'create_db': 'Create / Reset Database', 'user_token': tok.group(1)})
    # Login
    r = s.get(f'{BASE}/login.php', timeout=10)
    tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
    r = s.post(f'{BASE}/login.php',
        data={'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': tok},
        allow_redirects=True, timeout=15)
    # Set security
    tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    if tk_m:
        s.post(f'{BASE}/security.php',
            data={'security': 'low', 'seclev_submit': 'Submit', 'user_token': tk_m.group(1)})
    cookies = s.cookies.get_dict()
    print(f'requests OK: PHPSESSID={cookies["PHPSESSID"][:12]} security={cookies["security"]}', flush=True)

    # 2. Transfer cookies to HTTPPool via set_cookie()
    config = ConfigManager(); config.set('verify_ssl', False)
    pool = HTTPPool(config)
    for n, v in cookies.items():
        pool.set_cookie(BASE, n, v, domain='47.95.192.41')

    # 3. Test direct access via HTTPPool
    r = await pool.get(f'{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit')
    is_login = 'login' in r.text[:500].lower()
    has_form = '<form' in r.text.lower()
    print(f'HTTPPool GET sqli: {r.status_code} {len(r.text)}b is_login={is_login} has_form={has_form}', flush=True)

    # 4. Test SQLi detection
    from wvs.modules.sqli.detector import SQLiDetector
    sqli = SQLiDetector(config, pool)
    t = ScanTarget(url=f'{BASE}/vulnerabilities/sqli/', methods=['GET'],
                   params={'id': '1', 'Submit': 'Submit'}, cookies=cookies)
    import time
    t0 = time.time()
    vulns = await sqli.scan(t)
    td = time.time() - t0
    print(f'SQLiDetector scan: {td:.1f}s, {len(vulns)} vulns', flush=True)
    for v in vulns:
        vt = v.type.value if hasattr(v.type, 'value') else str(v.type)
        print(f'  [{vt}] {v.parameter}: {(v.evidence or "")[:100]}', flush=True)

    await pool.close()

asyncio.run(main())
