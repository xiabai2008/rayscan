import sys, time, re
sys.path.insert(0, r'C:\Users\HZR\Desktop\wvs-v19.2')
import urllib3; urllib3.disable_warnings()
import requests

BASE = 'http://47.95.192.41:8081'
s = requests.Session(); s.verify = False

print("1. login page...", flush=True)
r = s.get(f'{BASE}/login.php', timeout=10)
print(f'   status={r.status_code} len={len(r.text)}', flush=True)

tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
print(f'   token={tok[:15]}', flush=True)

r = s.post(f'{BASE}/login.php',
           data={'username': 'gordonb', 'password': 'abc123',
                 'Login': 'Login', 'user_token': tok},
           timeout=15, allow_redirects=True)
print(f'2. login: status={r.status_code} welcome={"Welcome" in r.text}', flush=True)

r = s.get(f'{BASE}/security.php', timeout=10)
tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
tk2 = tk_m.group(1) if tk_m else ''
s.post(f'{BASE}/security.php',
       data={'security': 'low', 'seclev_submit': 'Submit', 'user_token': tk2},
       timeout=15)
print(f'3. security={s.cookies.get("security")}', flush=True)
print(f'4. PHPSESSID={s.cookies.get("PHPSESSID")}', flush=True)

# Quick crawl test
print(f'5. crawl page...', flush=True)
r = s.get(f'{BASE}/index.php', timeout=10)
print(f'   status={r.status_code} len={len(r.text)}', flush=True)

# Try loading scanner
from wvs.config import ConfigManager
from wvs.core.scanner import WAVScanner, ScanTarget
print('6. imports OK', flush=True)

config = ConfigManager()
config.set("max_connections", 8)
config.set("max_concurrent_requests", 5)
config.set("concurrent_endpoints", 3)
config.set("request_delay_ms", 200)
config.set("max_requests_per_second", 5)
config.set("timeout", 15)
config.set("retry_count", 1)
config.set("verify_ssl", False)
config.set("crawl_depth", 2)
config.set("crawl_max_urls", 50)
config.set("max_time", 1800)
config.set("integrations.enabled", False)
config.set("enable_waf_detection", False)

target = ScanTarget(url=BASE, cookies=s.cookies.get_dict())
scanner = WAVScanner(config=config)
scanner.load_all_modules()
print(f'7. modules={scanner._loaded_module_names}', flush=True)
print('ALL OK', flush=True)
