"""Test SQL noise stripping on DVWA responses"""
import re, sys
import urllib3; urllib3.disable_warnings()
import requests

s = requests.Session(); s.verify = False
DVWA = "http://172.17.43.129:8888/dvwa"

# Login first
r = s.get(f"{DVWA}/login.php", timeout=10)
tk = re.search(r"name='user_token'\s+value='([^']+)'", r.text).group(1)
s.post(f"{DVWA}/login.php", data={"username":"admin","password":"password","Login":"Login","user_token":tk}, timeout=15, allow_redirects=True)
r = s.get(f"{DVWA}/security.php", timeout=10)
tk2 = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
if tk2: s.post(f"{DVWA}/security.php", data={"security":"low","seclev_submit":"Submit","user_token":tk2.group(1)}, timeout=15)
print(f"Logged in, security={s.cookies.get('security','?')}")

def strip_noise(t):
    t = re.sub(r'<[^>]+>', '', t)
    t = re.sub(r"'[^']*'", '', t)
    t = re.sub(r'"[^"]*"', '', t)
    t = re.sub(r'\b(?:AND|OR|NOT|SELECT|UNION|NULL|WHERE|FROM|ORDER|BY|SLEEP|HAVING|LIKE)\b', '', t, flags=re.IGNORECASE)
    t = re.sub(r'\b\d+\b', 'N', t)
    t = re.sub(r'[=\<\>\!\+\-\*/%]', ' ', t)
    t = re.sub(r'--|#', ' ', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t

# Test 1: xss_r (should be FP → stripped texts identical)
print("\n=== Test 1: xss_r (should be identical after stripping) ===")
for p in ["' AND 1=1--", "' AND 1=2--"]:
    r = s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": p}, timeout=10)
    cleaned = strip_noise(r.text)
    print(f"  {p:25s} → len={len(cleaned):4d}  ...{cleaned[-80:]}")

# Test 2: sqli (should be DIFFERENT after stripping)
print("\n=== Test 2: sqli (should differ after stripping) ===")
r1 = s.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"}, timeout=10)
r2 = s.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "' AND 1=1--", "Submit": "Submit"}, timeout=10)
r3 = s.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "' AND 1=2--", "Submit": "Submit"}, timeout=10)
c1 = strip_noise(r1.text)
c2 = strip_noise(r2.text)
c3 = strip_noise(r3.text)
print(f"  baseline (id=1)      → len={len(c1):4d}")
print(f"  true (id=' AND 1=1--) → len={len(c2):4d}  same_as_baseline={c1==c2}")
print(f"  false (id=' AND 1=2--)→ len={len(c3):4d}  same_as_true={c2==c3}")

print("\n=== Comparison ===")
x1 = strip_noise(s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": "' AND 1=1--"}, timeout=10).text)
x2 = strip_noise(s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": "' AND 1=2--"}, timeout=10).text)
print(f"  xss_r true==false: {x1 == x2}")
print(f"  sqli  true==false: {c2 == c3}")
