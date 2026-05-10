"""Test each boolean-blind payload pair against xss_r"""
import re, urllib3, requests, sys
urllib3.disable_warnings()

DVWA = "http://172.17.43.129:8888/dvwa"
s = requests.Session(); s.verify = False

def strip_noise(t):
    t = re.sub(r'<[^>]+>', '', t)
    t = re.sub(r"'[^']*'", '', t)
    t = re.sub(r'"[^"]*"', '', t)
    t = re.sub(r'\b(?:AND|OR|NOT|SELECT|UNION|NULL|WHERE|FROM|ORDER|BY|SLEEP|HAVING|LIKE)\b', '', t, flags=re.IGNORECASE)
    t = re.sub(r'\b\d+\b', 'N', t)
    t = re.sub(r'[=\<\>\!\+\-\*/%]', ' ', t)
    t = re.sub(r'--|#', ' ', t)
    t = re.sub(r'\b\w\b', '', t)
    t = re.sub(r'\s+', ' ', t).strip()
    return t

PAIRS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' AND 'a'='a", "' AND 'a'='b"),
    ("') AND 1=1--", "') AND 1=2--"),
    ("' AND 2>1--", "' AND 2<1--"),
    ("' OR '1'='1", "' OR '1'='2"),
    (" AND 1=1--", " AND 1=2--"),
    (" AND 1=1", " AND 1=2"),
    (" AND 5=5--", " AND 5=6--"),
    (" OR 1=1--", " OR 1=2--"),
    (" AND 99=99", " AND 99=0"),
    ('" AND 1=1--', '" AND 1=2--'),
    ('") AND 1=1--', '") AND 1=2--'),
    ("' AND 1=1;--", "' AND 1=2;--"),
    ("' AND (SELECT 1)=1--", "' AND (SELECT 1)=2--"),
]

print(f"Testing {len(PAIRS)} payload pairs on xss_r (no auth needed)...")
fps = 0
for i, (tp, fp) in enumerate(PAIRS):
    try:
        r1 = s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": tp}, timeout=10)
        r2 = s.get(f"{DVWA}/vulnerabilities/xss_r/", params={"name": fp}, timeout=10)
    except Exception as e:
        print(f"  [{i}] ERROR: {e}")
        continue
    c1 = strip_noise(r1.text[:10000])
    c2 = strip_noise(r2.text[:10000])
    same = c1 == c2
    if not same:
        fps += 1
        print(f"  [{i}] FP! {tp} | {fp} -> len: {len(c1)} vs {len(c2)} same={same}")
        for j, (a, b) in enumerate(zip(c1, c2)):
            if a != b:
                print(f"       diff@{j}: [{c1[max(0,j-25):j+25]}] vs [{c2[max(0,j-25):j+25]}]")
                break
    else:
        print(f"  [{i}] OK  {tp} block")
    sys.stdout.flush()

print(f"\nResult: {fps}/{len(PAIRS)} FP pairs (should be 0)")
