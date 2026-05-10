#!/usr/bin/env python3
"""初始化 DVWA 并执行扫描"""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import httpx
from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanTarget


async def init_dvwa(session: httpx.AsyncClient) -> bool:
    """初始化 DVWA 数据库"""
    base = "http://47.95.192.41:8081"
    
    # 1. 访问 setup.php 创建数据库
    r = await session.get(f"{base}/setup.php")
    print(f"setup.php: {r.status_code}")
    
    # 2. 执行数据库创建/重置
    r = await session.get(f"{base}/setup.php?create=1")
    print(f"create=1: {r.status_code}")
    
    # 3. 登录获取 session
    r = await session.post(
        f"{base}/login.php",
        data={"username": "admin", "password": "password", "Login": "Login"},
        follow_redirects=True
    )
    logged_in = "login" not in str(r.url)
    print(f"Login: {r.status_code} -> {r.url} (logged_in={logged_in})")
    
    return logged_in


async def run_scan():
    config = ConfigManager()
    config.set("verify_ssl", False)
    config.set("crawl_depth", 3)
    config.set("crawl_max_urls", 200)
    config.set("max_time", 3600)  # 1小时超时测试
    config.set("concurrent_endpoints", 8)
    
    # 先创建带认证的 session
    session = HTTPPool(config)
    
    # 初始化 DVWA
    print("\n[*] 初始化 DVWA...")
    http_session = session._get_httpx_client()  # 获取底层 httpx client
    ok = await init_dvwa(http_session)
    if not ok:
        print("[!] DVWA 登录失败")
        return None
    
    # 将认证 session 传入扫描器
    scanner = WAVScanner(config, session)
    scanner.load_all_modules()
    
    target = ScanTarget(url="http://47.95.192.41:8081/")
    print(f"[*] 扫描目标: {target.url}")
    print(f"[*] 模块: {list(scanner._modules.keys())}")
    
    try:
        result = await asyncio.wait_for(scanner.scan(target), timeout=3600)
        return result
    except asyncio.TimeoutError:
        print("[!] 扫描超时")
        return None


if __name__ == "__main__":
    import json
    from datetime import datetime
    
    result = asyncio.run(run_scan())
    
    if result:
        report = {
            "scan_time": datetime.now().isoformat(),
            "target": str(result.target),
            "duration_seconds": result.duration,
            "endpoints_found": result.endpoints_found,
            "requests_made": result.requests_made,
            "total_vulnerabilities": len(result.vulnerabilities),
            "vulnerabilities": [
                {
                    "type": v.type.value if hasattr(v.type, 'value') else str(v.type),
                    "severity": v.severity.value,
                    "url": v.url,
                    "parameter": v.parameter,
                    "evidence": v.evidence[:200] if v.evidence else None,
                }
                for v in result.vulnerabilities
            ]
        }
        
        Path("scan_reports").mkdir(exist_ok=True)
        fp = Path(f"scan_reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        fp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[+] 报告已保存: {fp}")
        print(f"    漏洞数: {report['total_vulnerabilities']}")
        print(f"    端点数: {report['endpoints_found']}")
    else:
        print("\n[!] 扫描失败")