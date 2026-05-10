import re, time, urllib3, requests
urllib3.disable_warnings()

DVWA_URL = "http://172.17.43.129:8888/dvwa"

s = requests.Session(); s.verify = False

# Setup database
for _ in range(5):
    try: r = s.get(f"{DVWA_URL}/setup.php", timeout=10); break
    except: time.sleep(2)
if "Create / Reset Database" in r.text:
    tk = re.search(r"user_token' value='([^']+)'", r.text).group(1)
    r = s.post(f"{DVWA_URL}/setup.php", data={
        "create_db":"Create / Reset Database","user_token":tk
    }, timeout=15)
    print(f"[setup] done, {len(r.text)} bytes")

# Login
r = s.get(f"{DVWA_URL}/login.php", timeout=10)
tk = re.search(r"user_token' value='([^']+)'", r.text).group(1)
r = s.post(f"{DVWA_URL}/login.php", data={
    "username":"admin","password":"password","Login":"Login","user_token":tk
}, timeout=15, allow_redirects=True)
print(f"[login] status={r.status_code} url part={r.url.split('/')[-2]} has DVWA: {'DVWA' in r.text}")

# Set security to low
r = s.get(f"{DVWA_URL}/security.php", timeout=10)
tk = re.search(r"user_token' value='([^']+)'", r.text).group(1)
r = s.post(f"{DVWA_URL}/security.php", data={
    "security":"low","seclev_submit":"Submit","user_token":tk
}, timeout=15)
r = s.get(f"{DVWA_URL}/security.php", timeout=10)
m = re.search(r"value='(low|medium|high|impossible)'\s+selected", r.text)
print(f"[security] current={m.group(1) if m else '?'} cookie={s.cookies.get('security')}")

cookies = s.cookies.get_dict()
print(f"[cookie] {'; '.join(f'{k}={v}' for k,v in cookies.items())}")
