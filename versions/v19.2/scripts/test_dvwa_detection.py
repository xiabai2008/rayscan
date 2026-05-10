#!/usr/bin/env python3
"""
DVWA 检测测试脚本

测试 WVS v19 检测模块对 DVWA 的检测效果
"""
import asyncio
import logging
import sys
import os

# 添加项目根目录到 Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.core.scanner import WAVScanner
from wvs.models import ScanTarget


# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("test_dvwa")


# DVWA 目标配置
DVWA_BASE_URL = "http://192.168.1.100:8080/DVWA"  # 修改为你的 DVWA 地址
DVWA_USERNAME = "admin"
DVWA_PASSWORD = "password"


async def test_sqli(scanner: WAVScanner):
    """测试 SQLi 检测"""
    print("\n" + "=" * 60)
    print("测试 SQLi 检测")
    print("=" * 60)

    # DVWA SQLi 页面
    target = ScanTarget(
        url=f"{DVWA_BASE_URL}/vulnerabilities/sqli/",
        params={"id": "1"},
        cookies={"security": "low", "PHPSESSID": "test"}
    )

    # 加载 SQLi 模块
    scanner.load_module("sqli")

    # 执行扫描
    from wvs.modules.sqli.detector import SQLiDetector
    detector = SQLiDetector(scanner.config, session=scanner.session)
    vulns = await detector.scan(target)

    print(f"\n发现 {len(vulns)} 个 SQLi 漏洞:")
    for v in vulns:
        print(f"  - [{v.severity.value}] {v.title}")
        print(f"    URL: {v.url}")
        print(f"    参数: {v.parameter}")
        print(f"    Payload: {v.payload}")
        print(f"    证据: {v.evidence[:100] if v.evidence else 'N/A'}")

    return vulns


async def test_xss(scanner: WAVScanner):
    """测试 XSS 检测"""
    print("\n" + "=" * 60)
    print("测试 XSS 检测")
    print("=" * 60)

    # DVWA XSS Reflected 页面
    target = ScanTarget(
        url=f"{DVWA_BASE_URL}/vulnerabilities/xss_r/",
        params={"name": "test"},
        cookies={"security": "low", "PHPSESSID": "test"}
    )

    # 加载 XSS 模块
    scanner.load_module("xss")

    # 执行扫描
    from wvs.modules.xss.detector import XSSDetector
    detector = XSSDetector(scanner.config, session=scanner.session)
    vulns = await detector.scan(target)

    print(f"\n发现 {len(vulns)} 个 XSS 漏洞:")
    for v in vulns:
        print(f"  - [{v.severity.value}] {v.title}")
        print(f"    URL: {v.url}")
        print(f"    参数: {v.parameter}")
        print(f"    Payload: {v.payload}")

    return vulns


async def test_lfi(scanner: WAVScanner):
    """测试 LFI 检测"""
    print("\n" + "=" * 60)
    print("测试 LFI 检测")
    print("=" * 60)

    # DVWA File Inclusion 页面
    target = ScanTarget(
        url=f"{DVWA_BASE_URL}/vulnerabilities/fi/",
        params={"page": "include.php"},
        cookies={"security": "low", "PHPSESSID": "test"}
    )

    # 加载 LFI 模块
    scanner.load_module("lfi")

    # 执行扫描
    from wvs.modules.lfi.detector import LFIDetector
    detector = LFIDetector(scanner.config, session=scanner.session)
    vulns = await detector.scan(target)

    print(f"\n发现 {len(vulns)} 个 LFI 漏洞:")
    for v in vulns:
        print(f"  - [{v.severity.value}] {v.title}")
        print(f"    URL: {v.url}")
        print(f"    参数: {v.parameter}")
        print(f"    Payload: {v.payload}")

    return vulns


async def test_direct_request():
    """直接测试 DVWA 页面响应"""
    print("\n" + "=" * 60)
    print("直接测试 DVWA 页面响应")
    print("=" * 60)

    config = ConfigManager()
    session = HTTPPool(config)

    # 测试 SQLi 页面
    print("\n1. 测试 SQLi 页面...")
    try:
        # 先登录获取 cookie
        login_resp = await session.request(
            "POST",
            f"{DVWA_BASE_URL}/login.php",
            data={"username": DVWA_USERNAME, "password": DVWA_PASSWORD, "Login": "Login"},
            follow_redirects=True
        )
        print(f"   登录状态: {login_resp.status_code}")

        # 获取 cookies
        cookies = {}
        for cookie in session._get_httpx_client().cookies.jar:
            cookies[cookie.name] = cookie.value
        print(f"   Cookies: {cookies}")

        # 测试 SQLi
        sqli_url = f"{DVWA_BASE_URL}/vulnerabilities/sqli/"
        resp = await session.request("GET", sqli_url, params={"id": "1"}, cookies=cookies)
        print(f"   SQLi 页面状态: {resp.status_code}")
        print(f"   SQLi 页面长度: {len(resp.text)}")

        # 测试注入
        sqli_test_url = f"{DVWA_BASE_URL}/vulnerabilities/sqli/"
        resp2 = await session.request("GET", sqli_test_url, params={"id": "1'"}, cookies=cookies)
        print(f"   SQLi 注入测试状态: {resp2.status_code}")
        print(f"   SQLi 注入测试长度: {len(resp2.text)}")

        # 检查是否有 SQL 错误
        if "error" in resp2.text.lower() or "syntax" in resp2.text.lower():
            print("   >>> 发现 SQL 错误特征!")

        # 测试 XSS 页面
        print("\n2. 测试 XSS 页面...")
        xss_url = f"{DVWA_BASE_URL}/vulnerabilities/xss_r/"
        resp3 = await session.request("GET", xss_url, params={"name": "<script>alert(1)</script>"}, cookies=cookies)
        print(f"   XSS 页面状态: {resp3.status_code}")
        print(f"   XSS 页面长度: {len(resp3.text)}")

        # 检查是否有 XSS 反射
        if "<script>alert(1)</script>" in resp3.text:
            print("   >>> 发现 XSS 反射!")
        elif "<script>" in resp3.text.lower():
            print("   >>> 发现部分 XSS 反射!")

        # 测试 LFI 页面
        print("\n3. 测试 LFI 页面...")
        lfi_url = f"{DVWA_BASE_URL}/vulnerabilities/fi/"
        resp4 = await session.request("GET", lfi_url, params={"page": "include.php"}, cookies=cookies)
        print(f"   LFI 页面状态: {resp4.status_code}")
        print(f"   LFI 页面长度: {len(resp4.text)}")

        # 测试路径遍历
        resp5 = await session.request("GET", lfi_url, params={"page": "../../../etc/passwd"}, cookies=cookies)
        print(f"   LFI 路径遍历测试状态: {resp5.status_code}")
        print(f"   LFI 路径遍历测试长度: {len(resp5.text)}")

        # 检查是否有文件内容
        if "root:" in resp5.text or "passwd" in resp5.text:
            print("   >>> 发现 LFI 文件读取!")

    except Exception as e:
        print(f"   错误: {e}")
        import traceback
        traceback.print_exc()

    await session.close()


async def main():
    """主测试函数"""
    print("=" * 60)
    print("WVS v19 DVWA 检测测试")
    print("=" * 60)
    print(f"DVWA 地址: {DVWA_BASE_URL}")

    # 先测试直接请求
    await test_direct_request()

    # 创建扫描器
    config = ConfigManager()
    scanner = WAVScanner(config)

    all_vulns = []

    # 测试各模块
    try:
        vulns = await test_sqli(scanner)
        all_vulns.extend(vulns)
    except Exception as e:
        print(f"SQLi 测试失败: {e}")

    try:
        vulns = await test_xss(scanner)
        all_vulns.extend(vulns)
    except Exception as e:
        print(f"XSS 测试失败: {e}")

    try:
        vulns = await test_lfi(scanner)
        all_vulns.extend(vulns)
    except Exception as e:
        print(f"LFI 测试失败: {e}")

    # 汇总
    print("\n" + "=" * 60)
    print("测试汇总")
    print("=" * 60)
    print(f"总计发现 {len(all_vulns)} 个漏洞")

    # 按类型统计
    from collections import Counter
    types = Counter(v.type.value for v in all_vulns)
    for t, count in types.items():
        print(f"  - {t}: {count}")

    # 关闭 session
    await scanner.session.close()


if __name__ == "__main__":
    asyncio.run(main())
