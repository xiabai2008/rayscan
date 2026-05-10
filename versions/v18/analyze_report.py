"""分析扫描报告"""
import json

with open(r'C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18\reports\report_20260417_225838.json', encoding='utf-8') as f:
    data = json.load(f)

print('Total:', data['summary']['total'])
print()
print('By severity:')
for sev, count in data['summary']['by_severity'].items():
    if count > 0:
        print(f'  {sev}: {count}')
print()
print('By type:')
for vtype, count in sorted(data['summary']['by_type'].items(), key=lambda x: -x[1])[:15]:
    print(f'  {vtype}: {count}')
print()
print('High severity:')
for v in data['vulnerabilities']:
    if v.get('severity') == 'high':
        print(f'  [{v["severity"]}] {v["type"]} @ {v["url"]}')
        print(f'    Payload: {v.get("payload", "N/A")[:80]}')
        print(f'    Conf: {v["confidence"]:.0%}')
        print()
print('Medium severity:')
for v in data['vulnerabilities']:
    if v.get('severity') == 'medium':
        print(f'  [{v["severity"]}] {v["type"]} @ {v["url"]}')
        print(f'    Payload: {v.get("payload", "N/A")[:80]}')
        print()
