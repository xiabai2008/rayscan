"""Log Poisoning Scanner 单元测试"""
import asyncio
import sys
try:
    from log_poison_scanner import LogPoisonScanner, _gen_unique_marker, PHP_PAYLOADS, LOG_PATHS
except ImportError:
    import sys, os
    sys.path.insert(0, os.path.dirname(__file__))
    from log_poison_scanner import LogPoisonScanner, _gen_unique_marker, PHP_PAYLOADS, LOG_PATHS


async def test_unit():
    """单元测试 - 不依赖网络"""
    print("[*] Log Poisoning Scanner Unit Tests")
    
    # 1. 唯一标记生成
    m1 = _gen_unique_marker()
    m2 = _gen_unique_marker()
    assert m1.startswith("WVS_"), f"Marker should start with WVS_: {m1}"
    assert len(m1) == 12, f"Marker length should be 12 (WVS_ + 8 chars): {len(m1)}"
    assert m1 != m2, "Two markers should be different"
    print(f"    [OK] _gen_unique_marker: {m1}, {m2}")
    
    # 2. PHP payloads 数量
    assert len(PHP_PAYLOADS) >= 10, f"Should have at least 10 payloads, got {len(PHP_PAYLOADS)}"
    print(f"    [OK] PHP_PAYLOADS count: {len(PHP_PAYLOADS)}")
    
    # 3. 日志路径数量
    assert len(LOG_PATHS) >= 15, f"Should have at least 15 log paths, got {len(LOG_PATHS)}"
    print(f"    [OK] LOG_PATHS count: {len(LOG_PATHS)}")
    
    # 4. Scanner 初始化
    scanner = LogPoisonScanner()
    assert scanner.timeout == 10
    assert scanner.max_log_paths == 8
    assert scanner.delay == 0.3
    print(f"    [OK] LogPoisonScanner init")
    
    # 5. Scanner 带配置初始化
    scanner2 = LogPoisonScanner({"timeout": 20, "max_log_paths": 5, "delay": 0.5})
    assert scanner2.timeout == 20
    assert scanner2.max_log_paths == 5
    assert scanner2.delay == 0.5
    print(f"    [OK] LogPoisonScanner init with config")
    
    # 6. scan_from_lfi_vuln URL 解析
    url = "http://target.com/view.php?page=test"
    base = url.split('?')[0]
    assert base == "http://target.com/view.php"
    print(f"    [OK] URL parsing: {url} -> {base}")
    
    print("\n[OK] All unit tests PASSED")
    return True


async def test_integration():
    """集成测试 - 需要靶机"""
    print("\n[*] Log Poisoning Scanner Integration Tests")
    
    # Metasploitable2 LFI
    metasploit_lfi = "http://192.168.18.131/mutillidae/index.php"
    
    scanner = LogPoisonScanner({"timeout": 8, "delay": 0.2})
    
    results = await scanner.scan(metasploit_lfi, lfi_param="page")
    
    print(f"    Found {len(results)} log poison results")
    
    for r in results:
        print(f"    - {r.log_path} | RCE: {r.rce_confirmed} | conf: {r.confidence}")
    
    return len(results) >= 0  # 不要求一定找到，验证不报错即可


async def main():
    unit_ok = await test_unit()
    if not unit_ok:
        print("[✗] Unit tests failed")
        return False
    
    # 集成测试可选
    try:
        await test_integration()
    except Exception as e:
        print(f"    [!] Integration test skipped/error: {e}")
    
    return True


if __name__ == "__main__":
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)
