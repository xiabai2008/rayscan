"""WVS v18 - 完整扫描 driftingblues9"""
import asyncio, sys, warnings
sys.path.insert(0, '.')
# 静默 XMLParsedAsHTMLWarning
from bs4 import XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

from wvs.vuln.full_scanner import FullScanner

async def main():
    s = FullScanner({
        'enable_basic': True,
        'enable_nuclei': True,
        'enable_sqlmap': False,
        'enable_playwright': False,
        'max_urls': 60,
        'max_depth': 3,
        'timeout': 8,
    })
    print('[*] Full scan driftingblues9 (login_sqli module enabled)...')
    r = await s.scan(
        'http://192.168.18.133',
        modules=['sqli', 'xss', 'cmdi', 'lfi', 'nuclei']
    )

    from collections import defaultdict
    by_sev = defaultdict(list)
    for v in r.vulnerabilities:
        by_sev[v.severity].append(v)

    print(f'\nURLs={len(r.urls)} Forms={len(r.forms)} Sources={r.sources}')
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        for v in by_sev.get(sev, []):
            print(f'  [{sev:8s}] [{v.source:12s}] {v.type}')
            print(f'              {v.url[:90]}')
            if v.evidence:
                print(f'              ev: {v.evidence[:80]}')
    print(f'\nTotal: {len(r.vulnerabilities)} vulns')

    import json
    with open('drifting_v18_result.json', 'w', encoding='utf-8') as f:
        json.dump({
            'target': r.target, 'urls': len(r.urls),
            'forms': len(r.forms), 'sources': r.sources,
            'vulns': [
                {'type': v.type, 'sev': v.severity, 'url': v.url,
                 'src': v.source, 'conf': v.confidence,
                 'ev': v.evidence[:100] if v.evidence else ''}
                for v in r.vulnerabilities
            ]
        }, f, indent=2, ensure_ascii=False)
    print('Saved drifting_v18_result.json')

asyncio.run(main())
