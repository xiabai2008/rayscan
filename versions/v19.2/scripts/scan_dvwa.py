"""DVWA 实战扫描测试"""
import asyncio
import json
import sys
from pathlib import Path

# 设置 UTF-8 编码
sys.stdout.reconfigure(encoding='utf-8')

from wvs.core.scanner import WAVScanner
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.plugins.auth import FormLoginAuth

async def main():
    print("=" * 60)
    print("WVS v19 - DVWA 实战扫描测试")
    print("=" * 60)
    
    # 目标配置
    target_url = "http://192.168.18.131/dvwa/"
    login_url = "http://192.168.18.131/dvwa/login.php"
    username = "admin"
    password = "password"
    
    # 创建扫描器
    config = ConfigManager()
    scanner = WAVScanner(config)
    
    # 加载模块
    scanner.load_module('sqli')
    scanner.load_module('cmdi')
    scanner.load_module('xss')
    scanner.load_module('lfi')
    
    print(f"\n[+] 目标: {target_url}")
    print(f"[+] 模块: sqli, cmdi, xss, lfi")
    
    # 扫描 DVWA 已知漏洞端点
    vuln_pages = [
        f"{target_url}vulnerabilities/sqli/?id=1&Submit=Submit",
        f"{target_url}vulnerabilities/sqli_blind/?id=1&Submit=Submit",
        f"{target_url}vulnerabilities/xss_r/?name=test",
        f"{target_url}vulnerabilities/xss_s/?name=test",
        f"{target_url}vulnerabilities/exec/?ip=127.0.0.1",
        f"{target_url}vulnerabilities/fi/?page=include.php",
    ]
    
    # 设置认证 cookies (DVWA default)
    # 先登录获取 session
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login"
    }
    
    print("[*] 正在登录 DVWA...")
    try:
        # 获取登录页面
        login_resp = await scanner.session.get(login_url)
        
        # 登录
        login_result = await scanner.session.post(
            login_url,
            data=login_data,
            follow_redirects=True
        )
        
        if "index.php" in str(login_result.url) or "Welcome" in login_result.text:
            print("[OK] 登录成功!")
        else:
            print("[WARN] 登录可能失败，继续尝试...")
    except Exception as e:
        print(f"[WARN] 登录异常: {e}")
    
    # 创建扫描目标
    target = ScanTarget(url=target_url)
    
    # 开始扫描
    print("\n[*] 开始扫描...")
    
    all_vulns = []
    
    for page_url in vuln_pages:
        print(f"\n[*] 扫描: {page_url}")
        try:
            target = ScanTarget(url=page_url)
            for module_name, module in scanner._modules.items():
                try:
                    vulns = await module.scan(target)
                    if vulns:
                        all_vulns.extend(vulns)
                        print(f"    [{module_name}] 发现 {len(vulns)} 个漏洞")
                except Exception as e:
                    print(f"    [{module_name}] 错误: {e}")
        except Exception as e:
            print(f"    错误: {e}")
    
    result = {
        "vulnerabilities": all_vulns,
        "total": len(all_vulns)
    }
    
    # 输出结果
    print("\n" + "=" * 60)
    print("扫描结果")
    print("=" * 60)
    
    vulns = result["vulnerabilities"]
    if vulns:
        print(f"\n[!] 发现 {len(vulns)} 个漏洞:")
        for i, vuln in enumerate(vulns, 1):
            print(f"\n--- 漏洞 #{i} ---")
            print(f"类型: {vuln.type.value}")
            print(f"严重: {vuln.severity.value}")
            print(f"URL: {vuln.url}")
            print(f"参数: {vuln.parameter}")
            print(f"Payload: {vuln.payload[:80]}..." if len(vuln.payload) > 80 else f"Payload: {vuln.payload}")
            print(f"置信度: {vuln.confidence.value}")
    else:
        print("\n[INFO] 未发现漏洞")
    
    # 保存结果
    output_file = Path("dvwa_scan_result.json")
    vuln_dicts = [v.to_dict() for v in vulns]
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({"vulnerabilities": vuln_dicts}, f, indent=2, ensure_ascii=False)
    print(f"\n[+] 结果已保存到: {output_file}")
    
    # 关闭 session
    await scanner.session.close()
    
    print("\n[OK] 扫描完成!")

if __name__ == "__main__":
    asyncio.run(main())
