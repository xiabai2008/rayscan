"""检测模块诊断脚本 - 找出为什么 DVWA 漏洞没有被检测到"""
import asyncio
import sys
sys.stdout.reconfigure(encoding='utf-8')

import httpx
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget
from wvs.modules.sqli.detector import SQLiDetector
from wvs.modules.xss.detector import XSSDetector
from wvs.modules.lfi.detector import LFIDetector

# DVWA 配置
DVWA_BASE = "http://192.168.18.131/dvwa"
LOGIN_URL = f"{DVWA_BASE}/login.php"

async def login(session: HTTPPool):
    """登录 DVWA"""
    print("[*] 登录 DVWA...")
    
    # 获取登录页面
    await session.get(LOGIN_URL)
    
    # 登录
    result = await session.post(
        LOGIN_URL,
        data={"username": "admin", "password": "password", "Login": "Login"},
        follow_redirects=True
    )
    
    print(f"[OK] 登录成功: {result.status_code}")
    return result

async def test_sqli_direct():
    """直接测试 SQLi 检测"""
    print("\n" + "=" * 60)
    print("SQLi 检测诊断")
    print("=" * 60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    # 登录
    await login(session)
    
    # 测试 SQLi 页面
    sqli_url = f"{DVWA_BASE}/vulnerabilities/sqli/"
    
    print(f"\n[*] 测试: {sqli_url}")
    
    # 手动测试 payload
    test_payloads = [
        ("id=1", "Normal request"),
        ("id=1'", "Single quote"),
        ("id=1' OR '1'='1", "OR injection"),
        ("id=1 UNION SELECT 1,2,3--", "UNION"),
        ("id=1 AND 1=1", "Boolean true"),
        ("id=1 AND 1=2", "Boolean false"),
    ]
    
    for payload, desc in test_payloads:
        url = f"{sqli_url}?{payload}&Submit=Submit"
        try:
            resp = await session.get(url)
            text = resp.text[:200]
            
            # 检查是否有 SQL 错误
            error_indicators = [
                "SQL syntax", "mysql_fetch", "mysql_num_rows",
                "Warning", "Error", "syntax error",
                "Unknown column", "mysql_query"
            ]
            has_error = any(e.lower() in text.lower() for e in error_indicators)
            
            print(f"\n  Payload: {payload}")
            print(f"  描述: {desc}")
            print(f"  状态: {resp.status_code}")
            print(f"  长度: {len(resp.text)}")
            print(f"  错误: {'是' if has_error else '否'}")
            
            if has_error:
                # 提取错误信息
                for e in error_indicators:
                    if e.lower() in text.lower():
                        print(f"  发现错误: {e}")
                        break
        except Exception as e:
            print(f"  错误: {e}")
    
    await session.close()

async def test_xss_direct():
    """直接测试 XSS 检测"""
    print("\n" + "=" * 60)
    print("XSS 检测诊断")
    print("=" * 60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    # 登录
    await login(session)
    
    # 测试 XSS 页面
    xss_url = f"{DVWA_BASE}/vulnerabilities/xss_r/"
    
    print(f"\n[*] 测试: {xss_url}")
    
    # 测试 payload
    test_payloads = [
        ("name=test", "Normal"),
        ("name=<script>alert(1)</script>", "Script tag"),
        ("name=<img src=x onerror=alert(1)>", "Img onerror"),
        ("name=<svg onload=alert(1)>", "SVG onload"),
        ("name=\\x3cscript\\x3ealert(1)\\x3c/script\\x3e", "Hex encoded"),
    ]
    
    for payload, desc in test_payloads:
        url = f"{xss_url}?{payload}"
        try:
            resp = await session.get(url)
            text = resp.text
            
            # 检查是否反射
            payload_key = payload.split("=")[1]
            is_reflected = payload_key in text
            
            print(f"\n  Payload: {payload}")
            print(f"  描述: {desc}")
            print(f"  状态: {resp.status_code}")
            print(f"  反射: {'是' if is_reflected else '否'}")
            
            if is_reflected:
                # 检查是否被转义
                escaped = "&lt;script&gt;" in text or "\\x3c" in text
                print(f"  转义: {'是' if escaped else '否'}")
        except Exception as e:
            print(f"  错误: {e}")
    
    await session.close()

async def test_lfi_direct():
    """直接测试 LFI 检测"""
    print("\n" + "=" * 60)
    print("LFI 检测诊断")
    print("=" * 60)
    
    config = ConfigManager()
    session = HTTPPool(config)
    
    # 登录
    await login(session)
    
    # 测试 LFI 页面
    lfi_url = f"{DVWA_BASE}/vulnerabilities/fi/"
    
    print(f"\n[*] 测试: {lfi_url}")
    
    # 测试 payload
    test_payloads = [
        ("page=include.php", "Normal"),
        ("page=../../../etc/passwd", "Path traversal"),
        ("page=....//....//....//etc/passwd", "Double dot"),
        ("page=/etc/passwd", "Absolute path"),
        ("page=php://filter/convert.base64-encode/resource=index.php", "PHP wrapper"),
    ]
    
    for payload, desc in test_payloads:
        url = f"{lfi_url}?{payload}"
        try:
            resp = await session.get(url)
            text = resp.text[:500]
            
            # 检查文件内容特征
            indicators = ["root:", "nobody:", "daemon:", "<?php", "include", "require"]
            found = [i for i in indicators if i in text]
            
            print(f"\n  Payload: {payload}")
            print(f"  描述: {desc}")
            print(f"  状态: {resp.status_code}")
            print(f"  长度: {len(resp.text)}")
            print(f"  特征: {found if found else '无'}")
        except Exception as e:
            print(f"  错误: {e}")
    
    await session.close()

async def main():
    print("=" * 60)
    print("WVS v19 检测模块诊断")
    print("=" * 60)
    
    # 测试连接
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(DVWA_BASE)
            print(f"\n[OK] DVWA 可访问: {r.status_code}")
    except Exception as e:
        print(f"\n[ERROR] DVWA 不可访问: {e}")
        return
    
    # 运行诊断
    await test_sqli_direct()
    await test_xss_direct()
    await test_lfi_direct()
    
    print("\n" + "=" * 60)
    print("诊断完成")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
