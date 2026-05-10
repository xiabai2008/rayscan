"""Test HTML tag comparison on DVWA xss_r boolean-blind responses"""
import re, sys
import urllib3; urllib3.disable_warnings()
import requests

URL = "http://172.17.43.129:8888/dvwa/vulnerabilities/xss_r/"
s = requests.Session(); s.verify = False

for name_val in ["' AND 1=1--", "' AND 1=2--", "test"]:
    r = s.get(URL, params={"name": name_val}, timeout=10)
    text = r.text[:10000]
    tags = re.findall(r'</?(\w+)', text)
    tag_types = tuple(tags)
    print(f"payload={name_val:25s}  status={r.status_code}  tags={len(tags):3d}  types={len(set(tag_types)):2d}")
    # Show first 5 and last 5 tags
    print(f"  first 10 tags: {list(tag_types[:10])}")
    print(f"  last 10 tags:  {list(tag_types[-10:])}")
    print()

# Compare the two boolean payloads
r1 = s.get(URL, params={"name": "' AND 1=1--"}, timeout=10)
r2 = s.get(URL, params={"name": "' AND 1=2--"}, timeout=10)
t1 = tuple(re.findall(r'</?(\w+)', r1.text[:10000]))
t2 = tuple(re.findall(r'</?(\w+)', r2.text[:10000]))
print(f"\nCOMPARISON: tags1={len(t1)} tags2={len(t2)} same={t1==t2}")
if t1 != t2:
    for i, (a, b) in enumerate(zip(t1, t2)):
        if a != b:
            print(f"  FIRST DIFF at index {i}: {a} != {b}")
            break
    print(f"  Later tags around diff: {list(t1[max(0,i-3):i+3])}")
    print(f"                           {list(t2[max(0,i-3):i+3])}")
