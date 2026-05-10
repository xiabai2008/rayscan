"""CLI测试脚本"""
import subprocess
import sys
import os

os.environ['PYTHONIOENCODING'] = 'utf-8'

commands = [
    ['python', '-m', 'wvs.cli', 'scan', '--help'],
    ['python', '-m', 'wvs.cli', 'scan-mobile', '--help'],
    ['python', '-m', 'wvs.cli', 'compliance', '--help'],
    ['python', '-m', 'wvs.cli', 'marketplace', '--help'],
    ['python', '-m', 'wvs.cli', 'subscription', '--help'],
    ['python', '-m', 'wvs.cli', 'ai-report', '--help'],
    ['python', '-m', 'wvs.cli', 'create-plugin', '--help'],
]

os.chdir(r'C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs')

for cmd in commands:
    print(f"\n{'='*60}")
    print(f"命令: {' '.join(cmd)}")
    print('='*60)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=15
        )
        print(result.stdout)
        if result.stderr:
            print(f"STDERR: {result.stderr[:200]}")
    except Exception as e:
        print(f"错误: {e}")
