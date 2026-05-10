"""WVS v18 - 带 DVWA 低安全级别认证的扫描"""
import asyncio, json, sys, time
sys.path.insert(0, '.')
from wvs.vuln.full_scanner import FullScanner

# Step 1: 用 requests 登录 DVWA 并设为 low 安全级别
import requests

sess = requests.Session()
sess.get('http://192.168.18.131/dvwa/setup.php', timeout=5)
sess.post('http://192.168.18.131/dvwa/login.php',
          data={'username': 'admin', 'password': 'password', 'Login': 'Login'}, timeout=5)
# 改 security=low
r = sess.get('http://192.168.18.131/dvwa/security.php', timeout=5)
import re
m = re.search(r'<option[^>]*value=["\']([^"\']+)["\'][^>]*>\s*low', r.text, re.I)
if m:
    sess.post('http://192.168.18.131/dvwa/security.php',
              data={'security': m.group(1), 'seclev_submit': 'Submit'}, timeout=5)

auth_cookies = dict(sess.cookies)
print(f"Auth cookies: {auth_cookies}")
print(f"DVWA security: {auth_cookies.get('security', 'unknown')}")

# Step 2: 用带认证的 cookie 跑完整扫描
async def main():
    t0 = time.time()
    scanner = FullScanner({
        'enable_basic': True,
        'enable_nuclei': True,
        'enable_sqlmap': False,
        'enable_playwright': False,
        'max_urls': 30,
        'max_depth': 2,
        'timeout': 8,
    })
    # 预置认证 cookie
    scanner.set_auth(auth_cookies, None)
    scanner.crawler.set_auth(auth_cookies, None)

    print("[*] Scan with DVWA auth (security=low)")
    result = await scanner.scan(
        'http://192.168.18.131',
        modules=['sqli', 'xss', 'cmdi', 'lfi', 'nuclei']
    )
    elapsed = time.time() - t0

    by_sev = {}
    for v in result.vulnerabilities:
        by_sev.setdefault(v.severity, []).append(v)

    lines = []
    lines.append(f"URLs: {len(result.urls)}  Forms: {len(result.forms)}  Elapsed: {elapsed:.1f}s")
    lines.append(f"Sources: {result.sources}")
    for sev in ['critical', 'high', 'medium', 'info']:
        if by_sev.get(sev):
            lines.append(f"--- {sev.upper()} ({len(by_sev[sev])}) ---")
            for v in by_sev[sev]:
                lines.append(f"  [{v.source:10s}] {v.type} -- {v.url[:80]}")
                if v.evidence:
                    lines.append(f"                 evidence: {v.evidence[:80]}")
    lines.append(f"\nTotal: {len(result.vulnerabilities)} vulns")

    with open('scan_result.json', 'w', encoding='utf-8') as f:
        json.dump({
            'target': result.target, 'urls': len(result.urls),
            'forms': len(result.forms), 'duration': result.duration,
            'sources': result.sources,
            'vulns': [{'type': v.type, 'severity': v.severity, 'url': v.url,
                       'source': v.source, 'confidence': v.confidence,
                       'evidence': v.evidence[:100] if v.evidence else ''}
                      for v in result.vulnerabilities]
        }, f, indent=2, ensure_ascii=False)

    with open('scan_output.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print('\n'.join(lines))
    print("\nSaved: scan_result.json  scan_output.txt")

asyncio.run(main())
