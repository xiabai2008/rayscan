"""详细分析 HTML 报告"""
import re

with open(r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18\reports\report_20260417_225838.html", encoding="utf-8") as f:
    content = f.read()

# 提取所有 bar 数据
bars = re.findall(r'bar-label">(.*?)</div>', content)
values = re.findall(r'bar-value">(.*?)</div>', content)

print("=" * 60)
print("VULNERABILITY BREAKDOWN")
print("=" * 60)
total = 0
for i, label in enumerate(bars):
    val = values[i] if i < len(values) else "0"
    try:
        int_val = int(val)
        if int_val > 0:
            print(f"  {int_val:>6} x {label}")
            total += int_val
    except:
        pass
print(f"\nTotal: {total}")

# 提取唯一 URL
url_pattern = r'192\.168\.18\.131[^\s<"]+'
all_urls = re.findall(url_pattern, content)
unique_urls = list(dict.fromkeys(all_urls))  # preserve order
print(f"\nCrawled URLs ({len(unique_urls)}):")
for u in unique_urls:
    print(f"  {u}")

# 从 HTML 找详细漏洞信息
print("\n" + "=" * 60)
print("DETAILED VULNERABILITIES")
print("=" * 60)

# 找所有 vuln-item 或类似结构
# 通常格式: type | url | severity | confidence
# 尝试找 pre 或 code 区块
code_blocks = re.findall(r'<pre[^>]*>(.*?)</pre>', content, re.DOTALL)
print(f"\nCode blocks (potential payloads): {len(code_blocks)}")

# 找高置信度的
for block in code_blocks[:5]:
    clean = re.sub(r'<[^>]+>', '', block).strip()
    if clean and len(clean) < 200:
        print(f"  Payload: {clean[:100]}")

# 提取 JSON 漏洞数据（可能在 script 标签中）
scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL)
for i, script in enumerate(scripts):
    if 'vulnerability' in script.lower() and len(script) > 100:
        print(f"\nScript {i} contains vulnerability data ({len(script)} chars)")
        # 尝试找 JSON
        json_match = re.search(r'\[.*?\]', script, re.DOTALL)
        if json_match:
            print(f"  JSON found: {json_match.group(0)[:200]}")
