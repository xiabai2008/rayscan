"""WVS v18 - Metasploitable2 完整扫描"""
import asyncio, json, sys, time
sys.path.insert(0, '.')
from wvs.vuln.full_scanner import FullScanner

async def main():
    t0 = time.time()
    scanner = FullScanner({
        'enable_basic': True,
        'enable_nuclei': True,
        'enable_sqlmap': False,
        'enable_playwright': False,
        'max_urls': 80,
        'max_depth': 3,
        'timeout': 10,
    })
    print("[*] Scan start: http://192.168.18.131")
    result = await scanner.scan(
        'http://192.168.18.131',
        modules=['sqli', 'xss', 'cmdi', 'lfi', 'nuclei']
    )
    elapsed = time.time() - t0
    print()
    print(f"URLs: {len(result.urls)}  Forms: {len(result.forms)}  Elapsed: {elapsed:.1f}s")
    print(f"Sources: {result.sources}")
    print()
    by_sev = {}
    for v in result.vulnerabilities:
        by_sev.setdefault(v.severity, []).append(v)
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        if by_sev.get(sev):
            print(f"--- {sev.upper()} ({len(by_sev[sev])}) ---")
            for v in by_sev[sev]:
                print(f"  [{v.source:10s}] {v.type}")
                print(f"    URL: {v.url[:80]}")
    with open('scan_result.json', 'w', encoding='utf-8') as f:
        json.dump({
            'target': result.target,
            'urls': len(result.urls),
            'forms': len(result.forms),
            'duration': result.duration,
            'sources': result.sources,
            'vulns': [{'type': v.type, 'severity': v.severity, 'url': v.url,
                       'source': v.source, 'confidence': v.confidence,
                       'evidence': v.evidence[:100] if v.evidence else ''}
                      for v in result.vulnerabilities]
        }, f, indent=2, ensure_ascii=False)
    print(f"\nTotal: {len(result.vulnerabilities)} vulns -> scan_result.json")

if __name__ == '__main__':
    asyncio.run(main())
