#!/usr/bin/env python3
"""zico2 - Enumerate web root /var/www/"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 10
BASE = 'http://192.168.18.132'

# Try to access various files in web root
print('=== /var/www/ enumeration ===')
files = [
    '/index.php', '/index.html', '/view.php', '/dbadmin/', '/style.css',
    '/.htaccess', '/robots.txt', '/README',
    # Subdirectories
    '/wordpress/', '/wp/', '/blog/', '/test/', '/upload/', '/uploads/',
    '/images/', '/img/', '/js/', '/css/', '/includes/', '/inc/',
    '/assets/', '/files/', '/downloads/', '/admin/', '/backup/',
    # Other common web apps
    '/phpmyadmin/', '/pma/', '/phpinfo.php', '/info.php',
    '/cgi-bin/test.cgi', '/cgi-bin/',
    # zico2 specific
    '/utility_scripts/', '/tarballs/', '/archive/',
]

for f in files:
    try:
        r = s.get(f'{BASE}{f}', timeout=5)
        if r.status_code == 200:
            title = re.search(r'<title>([^<]*)</title>', r.text)
            t = title.group(1)[:50] if title else ''
            print(f'  [200] {f} ({len(r.text)}B) {t}')
        elif r.status_code == 301 or r.status_code == 302:
            loc = r.headers.get('Location', '')
            print(f'  [{r.status_code}] {f} -> {loc[:80]}')
        elif r.status_code == 403:
            print(f'  [403] {f}')
    except:
        pass

# Also check /var/www/ via LFI - try to read directory listing
print('\n=== Reading /var/www/ contents via various methods ===')

# Try to read a file that might list directory contents
# On Apache with autoindex, we might get a listing at specific paths
index_paths = ['/', '/dbadmin/', '/icons/']
for p in index_paths:
    r = s.get(f'{BASE}{p}', timeout=5)
    if 'Index of' in r.text or 'Parent Directory' in r.text:
        print(f'  [+] Directory listing at {p}!')
        links = re.findall(r'href="([^"]*)"', r.text)
        for link in links:
            print(f'      {link}')

# Try to read view.php source via LFI by guessing the include base path
# view.php might be in /var/www/ and includes files from there
# The LFI works with ../../ so view.php is likely 2 levels deep from /var/www/
# That means view.php might be at /var/www/something/view.php or similar
# But we already know it's at /var/www/view.php (accessible via http)
# The LFI ../../ works because the include base might be different

# Let's check the actual web root structure
print('\n=== Reading Apache document root config ===')
# We already know DocumentRoot is /var/www from the config
# But view.php is directly accessible at /view.php
# And dbadmin/ is at /dbadmin/

# Let's check if there's a zico-specific tool or utility
for path in ['/view.php?page=tools.html', '/tools.html']:
    r = s.get(f'{BASE}{path}', timeout=5)
    if r.status_code == 200 and len(r.text) > 50:
        print(f'  {path}: {r.status_code} ({len(r.text)}B)')
        links = re.findall(r'href=["\']([^"\']*)["\']', r.text)
        print(f'  Links: {links[:10]}')
