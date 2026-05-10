import os
os.chdir(r'C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs')

files = [
    'wvs/plugins/mobile/android_scanner.py',
    'wvs/core/workflow.py',
    'wvs/core/database.py',
]

for f in files:
    print(f"\n=== {f} ===")
    try:
        with open(f, 'r', encoding='utf-8', errors='replace') as fp:
            for i, line in enumerate(fp, 1):
                if 'class ' in line and not line.strip().startswith('#'):
                    print(f"  {i}: {line.strip()}")
    except Exception as e:
        print(f"  Error: {e}")
