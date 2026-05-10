import requests, re, urllib3
urllib3.disable_warnings()
BASE = 'http://47.95.192.41:8081'
s = requests.Session(); s.verify = False

# Reset DB
r = s.get(f'{BASE}/setup.php', timeout=10)
tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
if tok:
    r = s.post(f'{BASE}/setup.php',
        data={'create_db': 'Create / Reset Database', 'user_token': tok.group(1)})
    ok = 'Database has been' in r.text or 'database has been created' in r.text.lower()
    print(f'DB reset: {r.status_code} ok={ok}')

# Login
r = s.get(f'{BASE}/login.php', timeout=10)
tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
if tok:
    r = s.post(f'{BASE}/login.php',
        data={'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': tok.group(1)},
        allow_redirects=True, timeout=15)
    ok = 'Welcome' in r.text or 'Logout' in r.text
    print(f'Login: ok={ok}')
    if not ok:
        # Try to find error message
        for m in re.finditer(r'<div[^>]*class="message"[^>]*>(.*?)</div>', r.text, re.DOTALL):
            print(f'  Message: {m.group(1).strip()[:200]}')

# If logged in, set security and test
if ok:
    r = s.get(f'{BASE}/security.php', timeout=10)
    tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    if tk_m:
        s.post(f'{BASE}/security.php',
            data={'security': 'low', 'seclev_submit': 'Submit', 'user_token': tk_m.group(1)})
    r = s.get(f'{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit', timeout=10)
    print(f'sqli page: {r.status_code} {len(r.text)}b has_form={"<form" in r.text}')
    print(f'COOKIE_STRING: PHPSESSID={s.cookies.get("PHPSESSID","?")}; security={s.cookies.get("security","?")}')
