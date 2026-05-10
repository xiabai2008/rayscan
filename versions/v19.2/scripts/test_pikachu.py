#!/usr/bin/env python3
"""测试 Pikachu 靶场扫描"""
import sys
sys.path.insert(0, 'C:/Users/HZR/.openclaw/workspace/wvs-v19')

from wvs.core.scanner import WAVScanner

# Pikachu 靶场
target = "http://47.95.192.41:8082/"

# 创建扫描器
scanner = WAVScanner(
    target_url=target,
    modules=["sqli", "xss", "cmdi", "lfi"]
)

# 运行扫描
result = scanner.scan()

# 输出结果
print(f"\n{'='*50}")
print(f"扫描完成！")
print(f"目标: {target}")
print(f"耗时: {result.duration:.1f}s")
print(f"请求数: {result.requests_made}")
print(f"漏洞数: {result.vulnerability_count}")
print(f"{'='*50}\n")

# 漏洞统计
from collections import Counter
types = Counter(v.type for v in result.vulnerabilities)
for vuln_type, count in types.items():
    print(f"  {vuln_type}: {count}")

# 显示前 5 个漏洞
print(f"\n前 5 个漏洞:")
for v in result.vulnerabilities[:5]:
    print(f"  [{v.severity}] {v.type} - {v.url}")
