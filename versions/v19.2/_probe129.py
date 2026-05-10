import urllib.request, re
base = 'http://172.17.43.129:8888'
paths = [
    '/login','/admin','/api','/index','/home','/app','/dashboard',
    '/setup','/install','/config','/dvwa','/mutillidae',
    '/vulnerabilities','/bodgeit','/webgoat','/juice-shop',
    '/status','/health','/info','/console','/manager','/test',
    '/wp-admin','/user','/users','/upload','/files','/docs',
    '/swagger','/graphql','/api/v1','/rest','/soap',
    '/phpmyadmin','/pma','/mysql','/db','/database',
    '/shell','/cmd','/exec','/debug','/trace',
    '/security','/login.php','/index.php','/admin.php',
]
for p in paths:
    try:
        req = urllib.request.Request(f'{base}{p}', headers={'User-Agent':'Mozilla/5.0'})
        r = urllib.request.urlopen(req, timeout=3)
        body = r.read().decode('utf-8','ignore')[:300]
        title = re.search(r'<title>(.*?)</title>', body, re.I)
        ttl = title.group(1).strip() if title else '-'
        ct = r.headers.get('Content-Type','')[:45]
        print(f'  [200] {p:25s} | {ct:45s}| {ttl[:60]}')
    except urllib.error.HTTPError as e:
        if e.code not in (404,):
            print(f'  [{e.code}] {p}')
    except Exception as e:
        pass
print('Done')
