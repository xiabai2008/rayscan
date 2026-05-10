"""切换 DVWA 到 low security 模式并扫描"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import httpx
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget, Vulnerability, VulnerabilityType, Severity, Confidence
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.xss.detector import XSSDetector
from wvs.modules.lfi.detector import LFIDetector
from wvs.modules.cmdi.detector import CMDInjectionDetector

DVWA_BASE = "http://192.168.18.131/dvwa"

async def set_dvwa_security(session: HTTPPool, level: str = "low"):
    """设置 DVWA security 级别"""
    print(f"[*] 设置 DVWA security = {level}")
    
    # 访问 security 页面
    security_url = f"{DVWA_BASE}/security.php"
    resp = await session.get(security_url)
    
    # 提取 user_token (CSRF)
    import re
    token_match = re.search(r"user_token'\s*value\s*=\s*'([^']+)'", resp.text)
    user_token = token_match.group(1) if token_match else ""
    
    # 提交表单
    data = {
        "security": level,
        "seclev_submit": "Submit",
        "user_token": user_token
    }
    
    resp = await session.post(security_url, data=data, follow_redirects=True)
    
    # 验证
    resp = await session.get(security_url)
    if f"Security level is currently: {level}" in resp.text or f"Security level set to {level}" in resp.text.lower():
        print(f"[OK] Security 已设置为: {level}")
        return True
    else:
        print(f"[WARN] 可能未成功设置，继续尝试...")
        return False

async def login_and_set_security(session: HTTPPool):
    """登录并设置 security"""
    print("[*] 登录 DVWA...")
    
    # 获取登录页面
    await session.get(f"{DVWA_BASE}/login.php")
    
    # 登录
    result = await session.post(
        f"{DVWA_BASE}/login.php",
        data={"username": "admin", "password": "password", "Login": "Login"},
        follow_redirects=True
    )
    
    print(f"[OK] 登录成功")
    
    # 设置 security
    await set_dvwa_security(session, "low")

async def scan_vulnerabilities(session: HTTPPool):
    """扫描漏洞"""
    print("\n" + "=" * 60)
    print("开始扫描 (security=low)")
    print("=" * 60)
    
    all_vulns = []
    
    # 测试页面配置
    test_pages = [
        {
            "name": "SQL Injection",
            "url": f"{DVWA_BASE}/vulnerabilities/sqli/",
            "params": {"id": "1", "Submit": "Submit"},
            "modules": ["sqli"]
        },
        {
            "name": "SQL Injection Blind",
            "url": f"{DVWA_BASE}/vulnerabilities/sqli_blind/",
            "params": {"id": "1", "Submit": "Submit"},
            "modules": ["sqli"]
        },
        {
            "name": "XSS Reflected",
            "url": f"{DVWA_BASE}/vulnerabilities/xss_r/",
            "params": {"name": "test"},
            "modules": ["xss"]
        },
        {
            "name": "XSS Stored",
            "url": f"{DVWA_BASE}/vulnerabilities/xss_s/",
            "params": {"txtName": "test", "mtxMessage": "test", "btnSign": "Sign Guestbook"},
            "modules": ["xss"]
        },
        {
            "name": "Command Injection",
            "url": f"{DVWA_BASE}/vulnerabilities/exec/",
            "params": {"ip": "127.0.0.1", "Submit": "Submit"},
            "modules": ["cmdi"]
        },
        {
            "name": "File Inclusion",
            "url": f"{DVWA_BASE}/vulnerabilities/fi/",
            "params": {"page": "include.php"},
            "modules": ["lfi"]
        },
    ]
    
    config = ConfigManager()
    
    for page in test_pages:
        print(f"\n[*] 测试: {page['name']}")
        print(f"    URL: {page['url']}")
        
        target = ScanTarget(url=page['url'], params=page['params'])
        
        for module_name in page['modules']:
            if module_name == "sqli":
                detector = SQLiDetector(config=config, session=session)
            elif module_name == "xss":
                detector = XSSDetector(config=config, session=session)
            elif module_name == "cmdi":
                detector = CMDInjectionDetector(config=config, session=session)
            elif module_name == "lfi":
                detector = LFIDetector(config=config, session=session)
            else:
                continue
            
            try:
                vulns = await detector.scan(target)
                if vulns:
                    all_vulns.extend(vulns)
                    print(f"    [{module_name}] [OK] 发现 {len(vulns)} 个漏洞")
                    for v in vulns:
                        print(f"        - {v.type.value} ({v.severity.value})")
                else:
                    print(f"    [{module_name}] 未发现漏洞")
            except Exception as e:
                print(f"    [{module_name}] 错误: {e}")
    
    return all_vulns

async def main():
    print("=" * 60)
    print("WVS v19 - DVWA Low Security 扫描")
    print("=" * 60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    try:
        # 登录并设置 security
        await login_and_set_security(session)
        
        # 扫描
        vulns = await scan_vulnerabilities(session)
        
        # 输出结果
        print("\n" + "=" * 60)
        print("扫描结果")
        print("=" * 60)
        
        if vulns:
            print(f"\n[!] 共发现 {len(vulns)} 个漏洞:")
            for i, v in enumerate(vulns, 1):
                print(f"\n--- 漏洞 #{i} ---")
                print(f"类型: {v.type.value}")
                print(f"严重: {v.severity.value}")
                print(f"URL: {v.url}")
                print(f"参数: {v.parameter}")
                payload = v.payload[:100] if len(v.payload) > 100 else v.payload
                print(f"Payload: {payload}")
                print(f"置信度: {v.confidence.value}")
        else:
            print("\n[INFO] 未发现漏洞")
        
    finally:
        await session.close()
    
    print("\n[OK] 扫描完成!")

if __name__ == "__main__":
    asyncio.run(main())
