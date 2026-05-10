import requests, re, time
s = requests.Session(); s.verify = False
DVWA = 'http://172.17.43.129:8888/dvwa'

# Setup
r = s.get(f'{DVWA}/setup.php', timeout=10)
if 'Create / Reset Database' in r.text:
    tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
    s.post(f'{DVWA}/setup.php', data={'create_db':'Create / Reset Database','user_token':tk}, timeout=15)
    print('setup done')

# Login
r = s.get(f'{DVWA}/login.php', timeout=10)
tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
r2 = s.post(f'{DVWA}/login.php', data={'username':'admin','password':'password','Login':'Login','user_token':tk}, timeout=15, allow_redirects=True)
print(f'login: status={r2.status_code} welcome={"Welcome" in r2.text} PHPSESSID={s.cookies.get("PHPSESSID","none")[:10]}...')

# Security
r = s.get(f'{DVWA}/security.php', timeout=10)
tk_m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
tk2 = tk_m.group(1) if tk_m else ''
s.post(f'{DVWA}/security.php', data={'security':'low','seclev_submit':'Submit','user_token':tk2}, timeout=15)
print(f'security: {s.cookies.get("security","none")}')

# Check each vuln page
print('\n--- Forms on vuln pages ---')
for path in ['/vulnerabilities/sqli/','/vulnerabilities/sqli_blind/','/vulnerabilities/xss_r/',
             '/vulnerabilities/xss_s/','/vulnerabilities/xss_d/','/vulnerabilities/exec/',
             '/vulnerabilities/fi/','/vulnerabilities/upload/','/vulnerabilities/csrf/','/vulnerabilities/brute/',
             '/vulnerabilities/csp/','/vulnerabilities/javascript/']:
    r = s.get(f'{DVWA}{path}', timeout=10)
    login_page = 'Username' in r.text and 'Login' in r.text
    forms = re.findall(r'<(?:input|select|textarea)\s[^>]*name=[\"\'](\w+)[\"\'][^>]*>', r.text)
    method_m = re.search(r'<form[^>]*method=[\"\'](\w+)[\"\']', r.text)
    method = method_m.group(1).upper() if method_m else 'GET'
    status = 'LOGIN_PAGE' if login_page else 'OK'
    print(f'{path} [{method}] {status}: {forms[:6]}')
