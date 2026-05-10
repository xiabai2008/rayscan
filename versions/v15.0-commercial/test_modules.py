"""模块直接测试 - 绕过CLI编码问题"""
import sys
import os
sys.path.insert(0, r'C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs')
os.chdir(r'C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs')

print("=== 测试1: 插件市场 ===")
try:
    from wvs.marketplace.marketplace import PluginMarketplace
    mp = PluginMarketplace()
    print(f"[OK] PluginMarketplace 初始化成功")
    print(f"     订阅计划: {list(mp.get_subscription_plans().keys())}")
    plugins = mp.browse_plugins()
    print(f"     插件数量: {len(plugins)}")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试2: 移动安全扫描器 ===")
try:
    from wvs.plugins.mobile import MobileSecurityScanner
    scanner = MobileSecurityScanner()
    caps = scanner.get_capabilities()
    print(f"[OK] MobileSecurityScanner 初始化成功")
    print(f"     支持平台: {[k for k,v in caps['platforms'].items() if v]}")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试3: 数据合规扫描器 ===")
try:
    from wvs.plugins.compliance.scanner import DataComplianceScanner
    scanner = DataComplianceScanner()
    print(f"[OK] DataComplianceScanner 初始化成功")
    print(f"     合规框架: {list(scanner.frameworks.keys())}")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试4: AI引擎 ===")
try:
    from wvs.core.ai.llm_engine import AIEnhancedScanner
    scanner = AIEnhancedScanner()
    print(f"[OK] AIEnhancedScanner 初始化成功")
    print(f"     LLM提供商: {list(scanner.llm_engine.llm_client.clients.keys())}")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试5: 插件SDK ===")
try:
    from wvs.marketplace.sdk import PluginSDK
    sdk = PluginSDK()
    templates = sdk.create_plugin_template("My Test Plugin", "scanner",
                                          description="Test plugin",
                                          author="Test Author")
    print(f"[OK] PluginSDK 初始化成功")
    print(f"     生成模板文件: {list(templates.keys())}")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试6: 主扫描器 ===")
try:
    from wvs.core.scanner import WVSScanner
    print(f"[OK] WVSScanner 导入成功")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试7: Android扫描器 ===")
try:
    from wvs.plugins.mobile.android_scanner import MobileSecurityScanner as AndroidScanner
    scanner = AndroidScanner()
    print(f"[OK] AndroidSecurityScanner 初始化成功")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试8: iOS扫描器 ===")
try:
    from wvs.plugins.mobile.ios_scanner import IOSSecurityScanner
    scanner = IOSSecurityScanner()
    print(f"[OK] IOSSecurityScanner 初始化成功")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试9: Compliance PII检测 ===")
try:
    from wvs.plugins.compliance.scanner import PIIPatterns
    patterns = PIIPatterns()
    test_text = "contact: user@example.com, phone: 13812345678"
    findings = patterns.detect_all(test_text)
    print(f"[OK] PIIPatterns 检测成功")
    print(f"     检测到: {[f.pii_type for f in findings]}")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试10: 工作流引擎 ===")
try:
    from wvs.core.workflow import RemediationWorkflow
    print(f"[OK] RemediationWorkflow 导入成功")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试11: 调度器 ===")
try:
    from wvs.core.scheduler import ScanScheduler
    print(f"[OK] ScanScheduler 导入成功")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n=== 测试12: 数据库 ===")
try:
    from wvs.core.database import Database
    print(f"[OK] Database 导入成功")
except Exception as e:
    print(f"[FAIL] {e}")

print("\n" + "="*60)
print("模块测试完成!")
