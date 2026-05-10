import os
import time

path = r"C:\Users\HZR\.qclaw\workspace-agent-b7ed571b\wvs-v18"

files = os.listdir(path)
print(f"目录: {path}")
print(f"文件总数: {len(files)}")
print()

# 查找Claude Code可能创建的文件
claude_patterns = ["zero_day", "logic_vulnerability", "auth_bypass", "api_security", "rate_limiter", "cache_system", "concurrent"]

found_files = []
for file in files:
    for pattern in claude_patterns:
        if pattern in file.lower():
            found_files.append(file)
            break

print("找到的Claude Code生成文件:")
if found_files:
    for f in found_files:
        full_path = os.path.join(path, f)
        mtime = os.path.getmtime(full_path)
        size = os.path.getsize(full_path)
        print(f"  {f} ({size:,} 字节, 修改时间: {time.strftime('%H:%M:%S', time.localtime(mtime))})")
else:
    print("  未找到相关文件")

print()

# 显示最新文件
print("最新的10个文件:")
file_times = [(f, os.path.getmtime(os.path.join(path, f))) for f in files]
file_times.sort(key=lambda x: x[1], reverse=True)

for f, mtime in file_times[:10]:
    print(f"  {f} ({time.strftime('%H:%M:%S', time.localtime(mtime))})")