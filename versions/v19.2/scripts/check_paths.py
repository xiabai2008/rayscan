import httpx
import asyncio

async def test():
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        # 检查根路径
        r = await client.get('http://47.95.192.41:8081/')
        print(f'Root: {r.status_code}, Location: {r.headers.get("location", "N/A")}')
        
        # 检查 dvwa 路径
        r = await client.get('http://47.95.192.41:8081/dvwa/')
        print(f'DVWA: {r.status_code}, Location: {r.headers.get("location", "N/A")}')
        
        # 检查 vulnerabilities 路径
        r = await client.get('http://47.95.192.41:8081/vulnerabilities/sqli/')
        print(f'SQLi: {r.status_code}, Location: {r.headers.get("location", "N/A")}')
        
        # 登录
        r = await client.post('http://47.95.192.41:8081/login.php', 
            data={'username': 'admin', 'password': 'password', 'Login': 'Login'})
        print(f'Login: {r.status_code}, cookies={dict(client.cookies)}')
        
        # 设置安全等级
        r = await client.get('http://47.95.192.41:8081/security.php?security=low&seclev_submit=Submit')
        print(f'Security: {r.status_code}')
        
        # 现在 SQLi
        r = await client.get('http://47.95.192.41:8081/vulnerabilities/sqli/?id=1', follow_redirects=False)
        print(f'SQLi after login: {r.status_code}, Location: {r.headers.get("location", "N/A")}')

asyncio.run(test())
