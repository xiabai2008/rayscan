"""WVS v18.0 改进后实战扫描 - Metasploitable2"""
import sys, json, time
sys.path.insert(0, r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18")
from wvs.vuln.scanner_v18 import VulnerabilityScanner

TARGET = "http://192.168.18.131"

print("[*] WVS v18.0 Improved Scan - Metasploitable2")
print("[*] Target:", TARGET)
print("[*] Start:", time.strftime("%H:%M:%S"))
sys.stdout.flush()

scanner = VulnerabilityScanner()
results = scanner.scan(TARGET, max_urls=50, max_depth=2)

# Stats
vulns = results.get("vulnerabilities", [])
total = len(vulns)
sev_counts = {}
xss_high = xss_med = xss_low = xss_total = 0
sqli_total = cmdi_total = nuclei_total = info_total = 0

for v in vulns:
    sev = v.get("severity", "info")
    sev_counts[sev] = sev_counts.get(sev, 0) + 1
    name = v.get("name", "")
    source = v.get("source", "")
    if "XSS" in name:
        xss_total += 1
        conf = v.get("confidence", 0)
        if conf >= 0.9:
            xss_high += 1
        elif conf >= 0.5:
            xss_med += 1
        else:
            xss_low += 1
    elif "SQL" in name or "sqli" in name.lower():
        sqli_total += 1
    elif "CMD" in name or "Command" in name:
        cmdi_total += 1
    if "nuclei" in source.lower() or "template" in name.lower():
        nuclei_total += 1
    if sev == "info":
        info_total += 1

elapsed = results.get("scan_time", "?")
urls = results.get("urls_found", 0)

print("\n" + "=" * 60)
print("SCAN RESULTS")
print("=" * 60)
print(f"Total vulnerabilities: {total}")
print(f"URLs crawled: {urls}")
print(f"Scan time: {elapsed}")
print()
print(f"By severity:")
for s in ["critical", "high", "medium", "low", "info"]:
    c = sev_counts.get(s, 0)
    if c > 0:
        print(f"  {s:12s}: {c}")
print()
print(f"XSS:       {xss_total:3d} (high conf: {xss_high}, med: {xss_med}, low: {xss_low})")
print(f"SQLi:      {sqli_total:3d}")
print(f"CMDi:      {cmdi_total:3d}")
print(f"Nuclei:    {nuclei_total:3d}")
print(f"Info/tech: {info_total:3d}")

# High confidence vulns
print("\n--- HIGH CONFIDENCE / CRITICAL / HIGH ---")
for v in vulns:
    conf = v.get("confidence", 0)
    sev = v.get("severity", "info")
    if conf >= 0.9 or sev in ["critical", "high"]:
        print(f"  [{sev:8s}] conf={conf:.2f} {v.get('name', '?')}")
        print(f"           URL: {v.get('url', '?')}")
        print(f"           Evidence: {str(v.get('evidence', ''))[:80]}")

# Nuclei findings
print("\n--- NUCLEI TEMPLATE FINDINGS ---")
nuclei_vulns = [v for v in vulns if "nuclei" in v.get("source", "").lower()]
for v in nuclei_vulns[:20]:
    print(f"  [{v.get('severity', '?'):8s}] {v.get('name', '?')}")
if len(nuclei_vulns) > 20:
    print(f"  ... and {len(nuclei_vulns) - 20} more")

# Save
import os
os.makedirs("reports", exist_ok=True)
outfile = "reports/metasploitable_v18_improved.json"
with open(outfile, "w", encoding="utf-8") as f:
    json.dump(results, f, ensure_ascii=False, indent=2, default=str)
print(f"\nFull report: {outfile}")
print(f"Finished: {time.strftime('%H:%M:%S')}")
