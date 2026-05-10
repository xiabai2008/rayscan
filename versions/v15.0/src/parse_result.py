import json
with open(r'C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18\drifting_v18_result.json', encoding='utf-8') as f:
    d = json.load(f)

from collections import Counter
src_cnt = Counter(v['src'] for v in d['vulns'])
sev_cnt = Counter(v['sev'] for v in d['vulns'])

print('Sources:', dict(src_cnt))
print('Severity:', dict(sev_cnt))
print('Total:', len(d['vulns']))

# Unique vuln types
types = {}
for v in d['vulns']:
    t = v['type']
    if t not in types:
        types[t] = v

print('\nUnique vulnerabilities:')
for t, v in types.items():
    print(f'  [{v["sev"]:8s}] [{v["src"]:12s}] {v["type"]}')
    print(f'              {v["url"][:80]}')
