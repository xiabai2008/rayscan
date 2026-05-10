import httpx, asyncio

BASE = 'http://47.95.192.41:8081'

async def main():
    c = httpx.AsyncClient(timeout=10, verify=False)
    
    # Step 1: check login page / db init
    r = await c.get(f'{BASE}/login.php')
    print(f'login page: {r.status_code} ({len(r.text)}b)')
    
    if 'Create / Reset Database' in r.text:
        r = await c.post(f'{BASE}/setup.php', data={'create_db': 'Create / Reset Database'}, follow_redirects=True)
        ok = 'Database has been' in r.text
        print(f'setup: {r.status_code} db_created={ok}')
    
    # Step 2: get user_token
    r = await c.get(f'{BASE}/login.php')
    tok = None
    for part in r.text.split('user_token'):
        if "value='" in part:
            tok = part.split("value='")[1].split("'")[0]
            break
    print(f'user_token: {tok[:20] if tok else "NOT FOUND"}')
    
    if not tok:
        await c.aclose()
        return
    
    # Step 3: login
    r = await c.post(f'{BASE}/login.php', data={
        'username': 'admin', 'password': 'password',
        'Login': 'Login', 'user_token': tok
    })
    welcome = 'Welcome' in r.text
    print(f'login: {"OK" if welcome else "FAIL"}')
    
    if not welcome:
        await c.aclose()
        return
    
    print(f'PHPSESSID: {c.cookies.get("PHPSESSID", "")[:10]}...')
    
    # Step 4: set security=low
    tok2 = None
    for part in r.text.split('user_token'):
        if "value='" in part:
            tok2 = part.split("value='")[1].split("'")[0]
            break
    
    if tok2:
        r = await c.post(f'{BASE}/security.php', data={
            'security': 'low', 'seclev_submit': 'Submit', 'user_token': tok2
        })
        print(f'security set: {r.status_code}')
        
        # verify
        r = await c.get(f'{BASE}/security.php')
        is_low = 'value="low"' in r.text and 'selected' in r.text.split('value="low"')[1][:20]
        print(f'verify low: {is_low}')
    
    await c.aclose()

asyncio.run(main())
