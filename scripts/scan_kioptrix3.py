"""Kioptrix Level 3 带 DVWA 认证的完整扫描"""
import asyncio, httpx
from wvs.core.scanner import WAVScanner
from wvs.core.session import HTTPPool
from wvs.config import ConfigManager
from wvs.models import ScanTarget

async def main():
    target = 'http://192.168.18.131'

    # ── 1. DVWA 认证 ──
    print('=== DVWA 认证 ===')
    async with httpx.AsyncClient(follow_redirects=True, timeout=15, verify=False) as c:
        r = await c.post(f'{target}/dvwa/login.php', data={
            'username': 'admin', 'password': 'password', 'Login': 'Login'
        })
        print(f'  登录: {r.status_code}')
        # 设为 low 安全等级
        await c.get(f'{target}/dvwa/security.php', params={'seclev': 'low'}, cookies=dict(c.cookies))
        cookies = dict(c.cookies)
        cookies['security'] = 'low'
        print(f'  Cookies: {cookies}')

    # ── 2. 初始化 scanner 并注入 cookies ──
    config = ConfigManager()
    session = HTTPPool(config)

    # 清空默认 cookies，注入 DVWA auth
    sc = session._get_httpx_client()
    sc.cookies.clear()

    for name, value in cookies.items():
        session.set_cookie(f'{target}/dvwa', name, value)

    print(f'\n验证 session jar: {dict(sc.cookies)}')

    # 验证 DVWA 认证
    r = await session.get(f'{target}/dvwa/', timeout=5)
    print(f'  DVWA 首页 (auth): {r.status_code}, 含 DVWA: {"DVWA" in r.text}')

    # ── 3. 扫描 DVWA SQLi ──
    print('\n=== 扫描 DVWA SQLi ===')
    sqli_det = session._module_sqli if hasattr(session, '_module_sqli') else None

    from wvs.modules.sqli.detector import SQLiDetector
    sqli_det = SQLiDetector(session=session)
    t = ScanTarget(
        url=f'{target}/dvwa/vulnerabilities/sqli/',
        params={'id': '1', 'Submit': 'Submit'},
    )
    print(f'  测试: {t.url} params={t.params}')
    vulns = await sqli_det.scan(t)
    print(f'  发现: {len(vulns)} 个漏洞')
    for v in vulns:
        print(f'    [{v.severity.value}] {v.type.value} | payload: {str(v.payload)[:60]}')

    # ── 4. 扫描 mutillidae XSS ──
    print('\n=== 扫描 Mutillidae XSS ===')
    from wvs.modules.xss.detector import XSSDetector
    xss_det = XSSDetector(session=session)
    t2 = ScanTarget(url=f'{target}/mutillidae/index.php', params={'page': 'text-file-viewer.php'})
    vulns2 = await xss_det.scan(t2)
    print(f'  发现: {len(vulns2)} 个漏洞')
    for v in vulns2:
        print(f'    [{v.severity.value}] {v.type.value}')

    await session.close()

asyncio.run(main())
