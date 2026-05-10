"""修复 markdown_report.py"""
content = open('C:/Users/HZR/.openclaw/workspace/wvs-v19/wvs/reporting/markdown_report.py', 'r', encoding='utf-8').read()
content = content.replace('result.started_at or datetime.now().isoformat()', "result.scan_time.strftime('%Y-%m-%d %H:%M:%S') if result.scan_time else datetime.now().strftime('%Y-%m-%d %H:%M:%S')")
open('C:/Users/HZR/.openclaw/workspace/wvs-v19/wvs/reporting/markdown_report.py', 'w', encoding='utf-8').write(content)
print('Fixed!')
