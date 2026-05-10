# -*- coding: utf-8 -*-
import json
import sys

report_file = 'scan_reports/report_20260504_115439.json'
try:
    with open(report_file, 'r', encoding='utf-8') as f:
        d = json.load(f)
except:
    # try latest
    import glob, os
    files = sorted(glob.glob('scan_reports/report_*.json'), key=os.path.getmtime, reverse=True)
    if files:
        with open(files[0], 'r', encoding='utf-8') as f:
            d = json.load(f)
        print(f"Using latest: {files[0]}")
    else:
        print("No reports found")
        sys.exit(0)

vulns = d.get('vulnerabilities', [])
print(f"Total vulnerabilities: {len(vulns)}")

severity_stats = {}
for v in vulns:
    sev = v.get('severity', 'unknown')
    severity_stats[sev] = severity_stats.get(sev, 0) + 1

print("\nSeverity breakdown:")
for sev, cnt in sorted(severity_stats.items()):
    print(f"  {sev}: {cnt}")

print("\nVulnerability details:")
for v in vulns:
    print(f"  [{v.get('severity','?')}] {v.get('name','?')} @ {v.get('url','?')}")
    if v.get('evidence'):
        print(f"    Evidence: {str(v.get('evidence'))[:200]}")

# Metadata
meta = d.get('metadata', {})
print(f"\nScan metadata:")
print(f"  Target: {meta.get('target', 'N/A')}")
print(f"  Duration: {meta.get('duration', 'N/A')}s")
print(f"  Modules: {meta.get('modules', [])}")
print(f"  Crawled URLs: {meta.get('crawled_count', 0)}")
print(f"  Requests sent: {meta.get('request_count', 0)}")
print(f"  Errors: {meta.get('errors', 0)}")
