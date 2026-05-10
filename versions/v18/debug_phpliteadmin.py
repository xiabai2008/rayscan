#!/usr/bin/env python3
"""Read phpLiteAdmin page structure and find correct directory change method"""
import requests
import re
from bs4 import BeautifulSoup

s = requests.Session()
s.headers['User-Agent'] = 'Mozilla/5.0'
s.timeout = 15
BASE = 'http://192.168.18.132'
PHPLITE = f'{BASE}/dbadmin/test_db.php'

# Login
s.post(PHPLITE, data={'password': 'admin', 'remember': 'on', 'login': 'Login', 'proc_login': 'true'})

# Get page after login
r = s.get(PHPLITE, timeout=15)
soup = BeautifulSoup(r.text, 'lxml')

# Find ALL forms
print('=== ALL FORMS ===')
for i, form in enumerate(soup.find_all('form')):
    action = form.get('action', '')
    method = form.get('method', 'GET')
    print(f'\nForm {i}: {method} {action}')
    
    # All hidden inputs
    hiddens = form.find_all('input', {'type': 'hidden'})
    for h in hiddens:
        print(f'  HIDDEN: {h.get("name")} = {h.get("value")}')
    
    # All inputs
    all_inputs = form.find_all('input')
    for inp in all_inputs:
        if inp.get('type') != 'hidden':
            print(f'  INPUT: type={inp.get("type")} name={inp.get("name")} value={inp.get("value", "")}')

# Find text containing "directory" or "path"
print('\n=== DIRECTORY REFS ===')
for elem in soup.find_all(string=re.compile(r'directory|path|dir', re.I)):
    print(f'  Text: "{elem.strip()[:100]}"')
    parent = elem.find_parent(['input', 'select', 'span', 'div', 'p'])
    if parent:
        print(f'  Parent tag: {parent.name}')

# Check select elements (for directory selection)
print('\n=== SELECT ELEMENTS ===')
for sel in soup.find_all('select'):
    name = sel.get('name', '')
    print(f'\nSelect: {name}')
    for opt in sel.find_all('option'):
        val = opt.get('value', '')
        text = opt.get_text(strip=True)
        print(f'  Option: value="{val}" text="{text}"')

# Check the actual form submission format
print('\n=== RAW FORM HTML (first 2000 chars of forms) ===')
for form in soup.find_all('form')[:3]:
    print(str(form)[:500])
    print('---')
