import requests, re

BASE = 'http://47.95.192.41:8081'
s = requests.Session(); s.verify = False

# Reset DB
r = s.get(f'{BASE}/setup.php', timeout=10)
print(f'setup page: {r.status_code} len={len(r.text)}')

tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
if tok:
    r = s.post(f'{BASE}/setup.php',
        data={'create_db': 'Create / Reset Database', 'user_token': tok.group(1)},
        timeout=15)
    print(f'reset DB: status={r.status_code}')
    if 'Database has been' in r.text or 'database has been created' in r.text.lower():
        print('DB CREATED SUCCESSFULLY')
    elif 'Could not connect' in r.text:
        print('DB CONNECTION FAILED')
    else:
        print('Result unclear, checking...')

# Login admin
r = s.get(f'{BASE}/login.php', timeout=10)
tok = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
if tok:
    r = s.post(f'{BASE}/login.php',
        data={'username': 'admin', 'password': 'password', 'Login': 'Login', 'user_token': tok.group(1)},
        allow_redirects=True, timeout=15)
    ok = 'Welcome' in r.text or 'Logout' in r.text
    print(f'admin login: status={r.status_code} ok={ok}')

# Test endpoint
if ok:
    tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
    if tk_m:
        s.post(f'{BASE}/security.php',
            data={'security': 'low', 'seclev_submit': 'Submit', 'user_token': tk_m.group(1)})
    r = s.get(f'{BASE}/vulnerabilities/sqli/?id=1&Submit=Submit', timeout=10)
    print(f'sqli page: {r.status_code} len={len(r.text)} has_form={"<form" in r.text}')
