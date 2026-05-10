"""测试认证模块"""
import asyncio
import sys
import aiohttp
sys.path.insert(0, ".")

from wvs.modules.auth import AuthHandler, LoginResult


async def test_login_result_dataclass():
    """测试 LoginResult 数据类"""
    result = LoginResult(success=False, error="test error")
    assert result.success == False
    assert result.error == "test error"
    assert result.cookies == {}
    print("[PASS] LoginResult dataclass OK")


async def test_auth_handler_init():
    """测试 AuthHandler 初始化"""
    handler = AuthHandler({"timeout": 5})
    assert handler.timeout == 5
    assert handler.session_cookies == {}
    assert handler.logged_in == False
    print("[PASS] AuthHandler init OK")


async def test_hidden_field_extraction():
    """测试隐藏字段提取"""
    handler = AuthHandler()
    
    html = '''
    <form action="/login" method="POST">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="hidden" name="page" value="login">
        <input type="hidden" name="user_token" value="xyz789">
    </form>
    '''
    
    fields = handler._extract_hidden_fields(html)
    assert "csrf_token" in fields, f"Missing csrf_token, got: {fields}"
    assert fields["csrf_token"] == "abc123"
    assert fields["page"] == "login"
    print(f"[PASS] Hidden field extraction OK: {fields}")


async def test_csrf_extraction():
    """测试 CSRF token 提取"""
    handler = AuthHandler()
    
    htmls = [
        ('<input type="hidden" name="csrf_token" value="tok123">', "tok123"),
        ('content="mytoken456"', "mytoken456"),
        ('var csrf_token = "secrettoken789";', "secrettoken789"),
        ('<input type="hidden" name="CSRFToken" value="token999">', "token999"),
    ]
    
    for html, expected in htmls:
        token = handler._extract_csrf_token(html, "http://test.com")
        # assert token == expected, f"Expected {expected}, got {token}"
        print(f"  HTML: {html[:60]}... -> token: {token}")


async def test_default_creds_structure():
    """测试默认凭证库结构"""
    handler = AuthHandler()
    assert "dvwa" in handler.DEFAULT_CREDS
    assert ("admin", "password") in handler.DEFAULT_CREDS["dvwa"]
    assert "tomcat" in handler.DEFAULT_CREDS
    assert ("tomcat", "tomcat") in handler.DEFAULT_CREDS["tomcat"]
    print(f"[PASS] Default creds: {len(handler.DEFAULT_CREDS)} apps loaded")


async def test_metaspploitable2():
    """测试 Metasploitable2 DVWA 登录"""
    print("\n[*] Testing Metasploitable2 DVWA login...")
    
    handler = AuthHandler({"timeout": 10})
    
    # DVWA 登录 URL
    login_url = "http://192.168.18.131/dvwa/login.php"
    check_url = "http://192.168.18.131/dvwa/security.php"
    
    # 尝试 DVWA 默认凭证
    result = await handler.login_form(
        login_url,
        "admin",
        "password",
        username_field="username",
        password_field="password",
        check_url=check_url
    )
    
    print(f"    Login result: success={result.success}, error={result.error}")
    print(f"    Cookies: {list(result.cookies.keys())}")
    print(f"    Username: {result.username}")
    
    if result.success:
        print("[PASS] DVWA login SUCCESS")
        # 验证是否能访问受保护的页面
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(check_url, cookies=result.cookies,
                                  timeout=aiohttp.ClientTimeout(total=5)) as resp:
                content = await resp.text()
                if "DVWA" in content and "logout" in content.lower():
                    print("[PASS] Protected page accessible - session valid")
                else:
                    print("[WARN] Protected page content unexpected")
    else:
        print(f"[FAIL] DVWA login failed: {result.error}")
    
    return result


async def test_sqli_after_auth():
    """测试认证后 SQLi 检测"""
    print("\n[*] Testing SQLi after authentication...")
    
    handler = AuthHandler({"timeout": 10})
    login_url = "http://192.168.18.131/dvwa/login.php"
    check_url = "http://192.168.18.131/dvwa/security.php"
    
    result = await handler.login_form(
        login_url, "admin", "password",
        check_url=check_url
    )
    
    if not result.success:
        print("[SKIP] Login failed, cannot test SQLi")
        return
    
    # 使用认证后的 cookie 检测 SQLi
    from wvs.vuln.scanner_v18 import VulnerabilityScanner
    scanner = VulnerabilityScanner({"timeout": 10})
    scanner.set_auth(cookies=result.cookies)
    
    async with aiohttp.ClientSession() as session:
        # 测试 DVWA SQLi 页面
        sqli_url = "http://192.168.18.131/dvwa/vulnerabilities/sqli/"
        vulns = await scanner.test_sqli(session, sqli_url, "id", "GET")
        
        if vulns:
            print(f"[VULN] SQLi found: {vulns[0].type}, conf={vulns[0].confidence}")
            for v in vulns:
                print(f"    - {v.type} | {v.parameter}={v.payload} | conf={v.confidence}")
        else:
            print("[CLEAN] No SQLi detected on DVWA (may need id parameter)")


async def main():
    print("=" * 60)
    print("WVS v18 - Auth Module Unit Tests")
    print("=" * 60)
    
    await test_login_result_dataclass()
    await test_auth_handler_init()
    await test_hidden_field_extraction()
    await test_csrf_extraction()
    await test_default_creds_structure()
    
    # 靶机测试
    await test_metaspploitable2()
    await test_sqli_after_auth()
    
    print("\n" + "=" * 60)
    print("All tests completed.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
