#!/usr/bin/env python3
"""Find the exact database path in phpLiteAdmin"""
import requests
import re
from bs4 import BeautifulSoup

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
PHPLITE = 'http://192.168.18.132/dbadmin/test_db.php'

s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})
r = s.get(PHPLITE, timeout=15)

# Find "Path to database" context
soup = BeautifulSoup(r.text, 'lxml')
for elem in soup.find_all(string=re.compile(r'Path to database', re.I)):
    parent = elem.parent
    for i in range(5):
        if parent:
            print(f'Level {i}: <{parent.name}> class={parent.get("class")} id={parent.get("id")}')
            if parent.name == 'div' or parent.name == 'p':
                print(f'  Full text: {parent.get_text(strip=True)[:200]}')
                print(f'  Full HTML: {str(parent)[:500]}')
            parent = parent.parent
    print('---')

# Also look for any span/div with the path value
print('\n=== Looking for path value near "Path to database" ===')
# Get the section containing "Path to database"
idx = r.text.find('Path to database')
if idx >= 0:
    context = r.text[max(0,idx-100):idx+300]
    print(context)
