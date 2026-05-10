#!/usr/bin/env python3
"""
WVS v19 模块加载测试
验证所有检测模块能正常加载和初始化
"""
import sys
import asyncio
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.core.scanner import WAVScanner


def test_module_loading():
    """测试模块加载"""
    print("=" * 60)
    print("  WVS v19 模块加载测试")
    print("=" * 60)
    
    config = ConfigManager()
    scanner = WAVScanner(config)
    
    # 加载所有模块
    scanner.load_all_modules()
    
    print(f"\n[*] 已加载模块数量: {len(scanner._modules)}")
    print(f"[*] 模块列表:")
    
    for name, module in scanner._modules.items():
        info = module.get_info()
        print(f"    - {name}: {info.description}")
        print(f"      版本: {info.version}, 标签: {', '.join(info.tags)}")
    
    # 统计
    total = len(scanner._modules)
    expected_modules = ["sqli", "cmdi", "xss", "lfi", "rce", "api", "sensitive"]
    loaded = [m for m in expected_modules if m in scanner._modules]
    
    print(f"\n[*] 预期模块: {expected_modules}")
    print(f"[*] 实际加载: {loaded}")
    print(f"[*] 加载率: {len(loaded)}/{len(expected_modules)} ({len(loaded)/len(expected_modules)*100:.0f}%)")
    
    if len(loaded) == len(expected_modules):
        print("\n[+] ✓ 所有模块加载成功!")
        return True
    else:
        missing = set(expected_modules) - set(loaded)
        print(f"\n[-] ✗ 缺失模块: {missing}")
        return False


def test_model_fields():
    """测试ScanResult字段完整性"""
    print("\n" + "=" * 60)
    print("  ScanResult 字段测试")
    print("=" * 60)
    
    from wvs.models import ScanResult, ScanTarget
    
    target = ScanTarget(url="http://example.com")
    result = ScanResult(target=target)
    
    # 检查字段
    fields = ["target", "vulnerabilities", "scan_time", "duration", 
              "requests_made", "endpoints_found", "modules_run", "errors"]
    
    print(f"\n[*] ScanResult 字段:")
    for field in fields:
        value = getattr(result, field, "MISSING")
        status = "✓" if value != "MISSING" else "✗"
        print(f"    {status} {field}: {type(value).__name__}")
    
    # 测试to_dict
    try:
        data = result.to_dict()
        print(f"\n[+] ✓ to_dict() 序列化成功")
        print(f"    字段数量: {len(data)}")
    except Exception as e:
        print(f"\n[-] ✗ to_dict() 失败: {e}")


def test_dvwa_auth_logic():
    """测试DVWA认证逻辑（代码层面检查）"""
    print("\n" + "=" * 60)
    print("  DVWA 认证逻辑检查")
    print("=" * 60)
    
    import inspect
    from wvs.core.scanner import WAVScanner
    
    # 获取scan方法源码
    source = inspect.getsource(WAVScanner.scan)
    
    # 检查是否有多处认证逻辑
    auth_count = source.count("DVWA 自动认证")
    
    print(f"\n[*] 'DVWA 自动认证' 出现次数: {auth_count}")
    
    if auth_count == 1:
        print("[+] ✓ DVWA认证逻辑已统一（只出现1次）")
        return True
    else:
        print(f"[-] ✗ DVWA认证可能重复（出现{auth_count}次）")
        return False


def main():
    """主测试函数"""
    print("\n")
    print("╔" + "═" * 58 + "╗")
    print("║" + " " * 10 + "WVS v19 完善测试套件" + " " * 26 + "║")
    print("╚" + "═" * 58 + "╝")
    
    results = []
    
    # 测试1: 模块加载
    results.append(("模块加载", test_module_loading()))
    
    # 测试2: ScanResult字段
    test_model_fields()
    
    # 测试3: DVWA认证逻辑
    results.append(("DVWA认证", test_dvwa_auth_logic()))
    
    # 总结
    print("\n" + "=" * 60)
    print("  测试总结")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    print(f"\n[*] 通过: {passed}/{total}")
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"    [{status}] {name}")
    
    if passed == total:
        print("\n[+] 所有测试通过!")
    else:
        print("\n[-] 部分测试失败，请检查")


if __name__ == "__main__":
    main()
