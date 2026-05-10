"""公网靶场测试 - 验证 WVS v19 检测能力"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

from wvs.core.scanner import WAVScanner
from wvs.config import ConfigManager
from wvs.models import ScanTarget

# 公网靶场
TARGETS = {
    "DVWA": {
        "base": "http://47.95.192.41:8081",
        "login": "/login.php",
        "username": "admin",
        "password": "password",
        "vuln_pages": [
            "/vulnerabilities/sqli/?id=1&Submit=Submit",
            "/vulnerabilities/sqli_blind/?id=1&Submit=Submit", 
            "/vulnerabilities/xss_r/?name=test",
            "/vulnerabilities/xss_s/?name=test",
            "/vulnerabilities/exec/?ip=127.0.0.1",
            "/vulnerabilities/fi/?page=include.php",
        ]
    },
    "Pikachu": {
        "base": "http://47.95.192.41:8082",
        "vuln_pages": [
            "/vul/sqli/sqli_str.php?id=1",
            "/vul/sqli/sqli_i.php?id=1",
            "/vul/xss/xss_reflected_get.php?message=test",
            "/vul/xss/xss_stored.php",
            "/vul/rce/rce_ping.php?ip=127.0.0.1",
        ]
    },
    "SQLi-Lab": {
        "base": "http://47.95.192.41:8083",
        "vuln_pages": [
            "/?id=1",
        ]
    },
    "XSS-Lab": {
        "base": "http://47.95.192.41:8085",
        "vuln_pages": [
            "/level1.php?name=test",
            "/level2.php?keyword=test",
        ]
    }
}


async def scan_target(name: str, config: dict):
    """扫描单个靶场"""
    print(f"\n{'='*60}")
    print(f"[{name}] {config['base']}")
    print('='*60)
    
    scanner = WAVScanner(ConfigManager())
    scanner.load_module('sqli')
    scanner.load_module('cmdi') 
    scanner.load_module('xss')
    scanner.load_module('lfi')
    
    # 登录 (DVWA)
    if 'login' in config:
        print("[*] 登录中...")
        login_url = config['base'] + config['login']
        login_data = {
            "username": config['username'],
            "password": config['password'],
            "Login": "Login"
        }
        try:
            await scanner.session.get(login_url)
            result = await scanner.session.post(login_url, data=login_data, follow_redirects=True)
            if "index" in result.text.lower() or result.status_code == 200:
                print("[OK] 登录成功")
        except Exception as e:
            print(f"[WARN] 登录失败: {e}")
    
    # 扫描漏洞页面
    all_vulns = []
    for page in config['vuln_pages']:
        url = config['base'] + page
        print(f"\n[*] {page}")
        
        target = ScanTarget(url=url)
        
        for mod_name, module in scanner._modules.items():
            try:
                vulns = await asyncio.wait_for(module.scan(target), timeout=30)
                if vulns:
                    all_vulns.extend(vulns)
                    for v in vulns:
                        print(f"    [FOUND] {v.type.value} | {v.parameter} | {v.severity.value}")
            except asyncio.TimeoutError:
                print(f"    [{mod_name}] TIMEOUT")
            except Exception as e:
                pass  # 静默处理错误
    
    await scanner.session.close()
    
    print(f"\n[结果] 发现 {len(all_vulns)} 个漏洞")
    return all_vulns


async def main():
    print("="*60)
    print("WVS v19 - 公网靶场检测验证")
    print("="*60)
    
    results = {}
    
    # 测试 DVWA 和 Pikachu
    for name in ["DVWA", "Pikachu", "SQLi-Lab", "XSS-Lab"]:
        try:
            vulns = await scan_target(name, TARGETS[name])
            results[name] = len(vulns)
        except Exception as e:
            print(f"\n[{name}] 错误: {e}")
            results[name] = 0
    
    # 汇总
    print("\n" + "="*60)
    print("检测汇总")
    print("="*60)
    total = 0
    for name, count in results.items():
        print(f"  {name}: {count} 个漏洞")
        total += count
    print(f"\n总计: {total} 个漏洞")


if __name__ == "__main__":
    asyncio.run(main())
