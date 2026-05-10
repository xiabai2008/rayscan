"""WVS v18 - phpLiteAdmin Scanner Test"""
import asyncio
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, "C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18")

from wvs.modules.lfi.phpliteadmin_scanner import PHPLiteAdminScanner, PHPLiteAdminResult, scan_phpliteadmin


def test_scanner_init():
    scanner = PHPLiteAdminScanner()
    assert scanner is not None
    assert len(scanner.PATHS) >= 10
    assert len(scanner.DEFAULT_PASSWORDS) >= 3
    print("[PASS] Scanner init")


def test_is_phpliteadmin():
    scanner = PHPLiteAdminScanner()
    phplite_html = """
    <html><head><title>phpLiteAdmin</title></head>
    <body><h1>Database browser</h1>
    <a href="?database=test">test</a>
    <p>Create New Database</p>
    <p>SQLite version: 3.31.1</p>
    </body></html>
    """
    assert scanner._is_phpliteadmin(phplite_html) == True
    generic_html = "<html><body><h1>Welcome</h1></body></html>"
    assert scanner._is_phpliteadmin(generic_html) == False
    print("[PASS] phpLiteAdmin detection")


def test_version_extraction():
    scanner = PHPLiteAdminScanner()
    test_cases = [
        ("<title>phpLiteAdmin 1.9.3</title>", "1.9.3"),
        ("phpLiteAdmin v1.9.4", "1.9.4"),
        ("version = '1.9.5'", "1.9.5"),
    ]
    import re
    for html, expected in test_cases:
        found = False
        for pattern, conf in scanner.VERSION_PATTERNS:
            m = re.search(pattern, html, re.I)
            if m:
                version = m.group(1).strip()
                assert version == expected
                found = True
                break
        assert found
    print("[PASS] Version extraction")


def test_rce_vulnerability_check():
    scanner = PHPLiteAdminScanner()
    assert scanner._is_rce_vulnerable("1.9.3") == True
    assert scanner._is_rce_vulnerable("1.9.4") == True
    assert scanner._is_rce_vulnerable("1.9.8") == False
    assert scanner._is_rce_vulnerable("2.0.0") == False
    assert scanner._is_rce_vulnerable("unknown") == False
    print("[PASS] RCE vulnerability check")


def test_rce_info():
    scanner = PHPLiteAdminScanner()
    info = scanner._get_rce_info("1.9.3")
    assert "CVE-2012-5209" in info
    info = scanner._get_rce_info("1.9.5")
    assert "RCE" in info
    print("[PASS] RCE info generation")


def test_format_result():
    scanner = PHPLiteAdminScanner()
    result = PHPLiteAdminResult(found=False)
    formatted = scanner.format_result(result)
    assert "not found" in formatted.lower()

    result = PHPLiteAdminResult(found=True, url="http://test/dbadmin/", version="1.9.3", version_confidence=0.9)
    formatted = scanner.format_result(result)
    assert "found" in formatted.lower()
    assert "1.9.3" in formatted

    result = PHPLiteAdminResult(
        found=True, url="http://test/dbadmin/", version="1.9.3",
        version_confidence=0.9, login_success=True,
        credentials_used="admin:", databases=[{"name": "test.db"}],
    )
    formatted = scanner.format_result(result)
    assert "Login SUCCESS" in formatted
    assert "test.db" in formatted
    print("[PASS] Result formatting")


async def test_scan_zico2():
    target = "http://192.168.18.132/"
    print(f"\n[*] Scanning zico2 phpLiteAdmin: {target}")
    scanner = PHPLiteAdminScanner()
    result = await scanner.scan(target)
    print(scanner.format_result(result))
    assert result.found == True, "Should find phpLiteAdmin"
    assert result.version == "1.9.3", f"Version should be 1.9.3, got {result.version}"
    assert result.login_success == True, "admin: should login successfully"
    if result.databases:
        print(f"    Databases: {result.databases}")
    if result.credentials_leaked:
        print(f"    Credentials: {result.credentials_leaked}")
    print("[PASS] zico2 phpLiteAdmin scan")


async def main():
    print("=" * 50)
    print("phpLiteAdmin Scanner Tests")
    print("=" * 50)
    test_scanner_init()
    test_is_phpliteadmin()
    test_version_extraction()
    test_rce_vulnerability_check()
    test_rce_info()
    test_format_result()
    await test_scan_zico2()
    print("\n" + "=" * 50)
    print("ALL TESTS PASSED")
    print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
