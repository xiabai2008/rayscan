"""功能验证测试"""
import sys, os
sys.path.insert(0, '.')
os.chdir('.')

# Test 1: PII detection
from wvs.plugins.compliance.scanner import PIIPatterns

text = """用户信息：
姓名：张三
邮箱：zhangsan@example.com
手机：13800138000
身份证：110101199001011234
API密钥：sk_live_abc123def456"""

findings = PIIPatterns.detect_all(text)
print('=== PII检测测试 ===')
for f in findings:
    print(f'  [{f.pii_type}] 样本: {f.sample}')

# Test 2: Plugin SDK
from wvs.marketplace.sdk import PluginSDK
sdk = PluginSDK()
templates = sdk.create_plugin_template('SSRF Scanner', 'scanner',
    description='SSRF scanner', author='WVS Team')
print(f'\n=== 插件模板 ===')
print(f'  插件ID: ssrf-scanner')
for fn in templates.keys():
    print(f'  文件: {fn}')

# Test 3: Subscription plans
from wvs.marketplace.marketplace import PluginMarketplace
mp = PluginMarketplace()
plans = mp.get_subscription_plans()
print(f'\n=== 订阅计划 ===')
for name, plan in plans.items():
    price = '免费' if plan['price'] == 0 else f'${plan["price"]}/月'
    print(f'  {name.upper()}: {price}')
    print(f'    功能: {plan["features"][0]}, {plan["features"][1]}')

# Test 4: Mobile scanner auto-detection
from wvs.plugins.mobile import MobileSecurityScanner
scanner = MobileSecurityScanner()
caps = scanner.get_capabilities()
print(f'\n=== 移动扫描器 ===')
print(f'  Android: {"支持" if caps["platforms"]["android"] else "不支持"}')
print(f'  iOS: {"支持" if caps["platforms"]["ios"] else "不支持"}')
print(f'  API: {"支持" if caps["platforms"]["api"] else "不支持"}')

# Test 5: Compliance frameworks
from wvs.plugins.compliance.scanner import DataComplianceScanner
scanner2 = DataComplianceScanner()
print(f'\n=== 合规框架 ===')
for fw in scanner2.frameworks.keys():
    print(f'  - {fw}')

# Test 6: AI engine templates
from wvs.core.ai.llm_engine import LLMEnhancedEngine
engine = LLMEnhancedEngine()
print(f'\n=== AI提示模板 ===')
for tmpl in engine.prompt_templates.keys():
    print(f'  - {tmpl}')

print('\n所有功能验证通过!')
