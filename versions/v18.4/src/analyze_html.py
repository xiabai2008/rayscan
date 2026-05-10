"""分析 HTML 报告"""
with open(r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18\reports\report_20260417_225838.html", encoding="utf-8") as f:
    content = f.read()

print("Size:", len(content))

# 找包含漏洞信息的区块
import re

# 找所有 vulnerability 区块
vuln_blocks = re.findall(r'<div class="vuln-card[^"]*"[^>]*>(.*?)</div>\s*</div>', content, re.DOTALL)
print("Vuln card blocks:", len(vuln_blocks))

# 尝试提取 severity
sev_counts = {}
for sev in ["critical", "high", "medium", "low", "info"]:
    count = content.lower().count(f'class="severity {sev}"')
    sev_counts[sev] = count
print("\nBy severity:", sev_counts)

# 找漏洞类型
vtypes = re.findall(r'<span class="vuln-type">(.*?)</span>', content)
print("\nVulnerability types found:", len(set(vtypes)))
for t in set(vtypes):
    print(f"  {t}: {vtypes.count(t)}")

# 找 URL
urls = re.findall(r'<code class="vuln-url">(.*?)</code>', content)
print("\nUnique URLs:", len(set(urls)))
for u in set(urls)[:10]:
    print(f"  {u}")
