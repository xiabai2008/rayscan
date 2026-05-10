"""End-to-end功能测试"""
import sys, os
sys.path.insert(0, '.')
os.chdir('.')

print('=== 测试1: 实际扫描 + 合规检查 ===')
from wvs.plugins.compliance.scanner import DataComplianceScanner

scanner = DataComplianceScanner()
target = 'http://47.95.192.41:8082'
print(f'Target: {target}')

pii_results = scanner.scan_for_pii([target], scan_depth='standard')
print(f'PII发现: {pii_results.get("pii_summary", {}).get("total_findings", 0)}')

report = scanner.generate_compliance_report(pii_results, 'gdpr')
print(f'GDPR评分: {report["compliance_score"]}/100')
print(f'合规状态: {"PASS" if report["is_compliant"] else "FAIL"}')
print(f'检查项: {report["passed_checks"]}/{report["total_checks"]}')
print(f'违规项: {len(report["violations"])}')

print('\n=== 测试2: Web扫描 + 结果保存 ===')
from wvs.core.scanner import WVSScanner
from wvs.core.config import ScanConfig
import asyncio

config = ScanConfig(
    target='http://47.95.192.41:8082',
    port_range='8082',
    max_depth=2,
    max_urls=10,
    concurrency=5,
    timeout=5.0,
    output_dir='reports',
    check_xss=True,
    check_sqli=True,
    check_csrf=True,
    check_info=True,
    check_traversal=True,
)

async def run_scan():
    scan = WVSScanner(config)
    return await scan.scan()

result = asyncio.run(run_scan())

print(f'扫描ID: {result["scan_id"]}')
print(f'耗时: {result["duration"]:.2f}s')
print(f'漏洞: {result["vulnerabilities"]}')
print(f'报告: HTML={result["report_paths"]["html"]}')
print(f'      JSON={result["report_paths"]["json"]}')

print('\n=== 测试3: PluginSDK创建插件 ===')
from wvs.marketplace.sdk import PluginSDK
sdk = PluginSDK()

# 生成SQL注入扫描插件模板
templates = sdk.create_plugin_template(
    'Advanced SQLi Scanner',
    'scanner',
    description='Advanced SQL injection scanner with time-based blind detection',
    author='WVS Team'
)

# 验证模板内容
print(f'模板文件数: {len(templates)}')
plugin_code = templates['plugin.py']
# 检查关键方法是否存在
checks = [
    ('class AdvancedSqliScanner' in plugin_code),
    ('def scan' in plugin_code),
    ('WVSPlugin' in plugin_code),
    ('def name(self)' in plugin_code),
    ('def version(self)' in plugin_code),
]
print(f'代码检查: {"PASS" if all(checks) else "FAIL"}')
print(f'  - 类定义: {"OK" if checks[0] else "FAIL"}')
print(f'  - scan方法: {"OK" if checks[1] else "FAIL"}')
print(f'  - 基类继承: {"OK" if checks[2] else "FAIL"}')

print('\n=== 测试4: 订阅计划 + 插件安装 ===')
from wvs.marketplace.marketplace import PluginMarketplace

mp = PluginMarketplace()
plans = mp.get_subscription_plans()
print(f'订阅计划数: {len(plans)}')
for name, plan in plans.items():
    features_count = len(plan['features'])
    limits = plan['limits']
    print(f'  {name}: {features_count}功能, {limits["concurrent_scans"]}并发')

# 测试安装流程
print('\n注册一个测试插件...')
from wvs.marketplace.marketplace import PluginMetadata
meta = PluginMetadata(
    id='test-scanner',
    name='Test Scanner',
    version='1.0.0',
    description='Test plugin',
    author='Test',
    license_type='free',
    price=0,
    category='scanner',
    tags=['test'],
    dependencies=[],
    min_wvs_version='1.0.0',
    download_count=1,
)
result = mp.plugin_registry.register_plugin(meta)
print(f'注册结果: {"OK" if result else "FAIL"}')

# 尝试安装
install_result = mp.install_plugin('test-scanner')
print(f'安装结果: {"OK" if install_result["success"] else "FAIL"}')
print(f'消息: {install_result.get("message", install_result.get("error", ""))}')

print('\n=== 测试5: Compliance多框架扫描 ===')
all_reports = scanner.scan_all_frameworks(pii_results)
print(f'框架扫描数: {len(all_reports)}')
for fw_name, fw_report in all_reports.items():
    status = "PASS" if fw_report.get('is_compliant') else "FAIL"
    print(f'  {fw_name}: {fw_report["compliance_score"]}/100 [{status}]')

print('\n所有E2E测试完成!')
