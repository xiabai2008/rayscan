f = open(r'C:/Users/HZR/.openclaw/workspace/wvs-v19/wvs/core/crawler.py', 'r', encoding='utf-8')
c = f.read()
f.close()

old = '        return urllib.parse.urljoin(base, path)'
new = "        result = urllib.parse.urljoin(base, path)\n        print(f'[_join_url] base={base!r} + path={path!r} => {result!r}')\n        return result"

if old in c:
    c = c.replace(old, new, 1)
    open(r'C:/Users/HZR/.openclaw/workspace/wvs-v19/wvs/core/crawler.py', 'w', encoding='utf-8').write(c)
    print('Fixed f-string debug print')
else:
    print('Pattern not found')
    idx = c.find('urljoin')
    if idx >= 0:
        print('Found urljoin at:', repr(c[max(0,idx-30):idx+80]))
