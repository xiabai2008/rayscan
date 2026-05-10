"""测试 DVWA auth cookie 是否生效"""
import asyncio, httpx
from wvs.plugins.auth import FormLoginAuth
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager

async def test():
    config = ConfigManager()
    session = HTTPPool(config)
    
    # Step 1: 探测 DVWA
    r = await session.get('http://192.168.18.131/dvwa/login.php', timeout=10)
    print(f'DVWA login.php: {r.status_code}, DVWA in text: {"DVWA" in r.text}')
    
    # Step 2: FormLoginAuth
    provider = FormLoginAuth(
        login_url='http://192.168.18.131/dvwa/login.php',
        username='admin',
        password='password',
        extra_fields={'Login': 'Login'},
    )
    client = session._get_httpx_client()
    print(f'client cookies before: {dict(client.cookies)}')
    auth_result = await provider.authenticate(client)
    print(f'auth result: authenticated={auth_result.get("authenticated")}, cookies={auth_result.get("cookies")}')
    print(f'client cookies after auth: {dict(client.cookies)}')
    
    # Step 3: set_cookie
    for name, value in auth_result.get('cookies', {}).items():
        session.set_cookie('http://192.168.18.131/dvwa', name, value)
    session.set_cookie('http://192.168.18.131/dvwa', 'security', 'low')
    
    # Step 4: crawl test
    r2 = await session.get('http://192.168.18.131/dvwa/', timeout=10)
    print(f'DVWA after auth: {r2.status_code}, DVWA in text: {"DVWA" in r2.text}')
    
    await session.close()

asyncio.run(test())
