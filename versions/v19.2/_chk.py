import json, pathlib

reports = sorted(pathlib.Path(r"C:\Users\HZR\Desktop\wvs-v19.2\scan_reports").glob("report_*.json"))
if not reports:
    print("No reports found")
    exit()

rpt = max(reports, key=lambda p: p.stat().st_mtime)
data = json.loads(rpt.read_text(encoding="utf-8"))

print(f"Report: {rpt.name}")
print(f"Total: {data.get('total_vulnerabilities')}")
print(f"By type: {data.get('vulnerabilities_by_type')}")
print()

for i, v in enumerate(data.get("vulnerabilities", [])):
    t = v.get("type") or "?" 
    p = v.get("parameter") or "-"
    u = v.get("url", "").split("/")[-2] if "/" in v.get("url", "") else v.get("url", "")
    e = str(v.get("evidence") or "")[:80]
    m = v.get("module") or "?"
    print(f"  [{i:2d}] {t:24s} | {p:10s} | {u:14s} | {e}")
