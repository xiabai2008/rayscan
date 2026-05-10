"""下载 Nuclei 二进制"""
import urllib.request
import os
import sys

# URL
url = "https://github.com/projectdiscovery/nuclei/releases/download/v3.7.1/nuclei_3.7.1_windows_amd64.zip"
output = os.path.join(os.environ["TEMP"], "nuclei.zip")

print(f"Downloading Nuclei from: {url}")
print(f"Output: {output}")

try:
    # 设置请求头
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
    )
    
    # 下载
    with urllib.request.urlopen(req, timeout=120) as response:
        with open(output, 'wb') as f:
            total = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            chunk_size = 8192
            
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                downloaded += len(chunk)
                f.write(chunk)
                
                if total > 0:
                    pct = (downloaded / total) * 100
                    print(f"\rProgress: {pct:.1f}% ({downloaded}/{total} bytes)", end="")
    
    print(f"\n\nDownload complete: {output}")
    print(f"Size: {os.path.getsize(output) / 1024 / 1024:.2f} MB")
    
    # 解压
    print("\nExtracting...")
    import zipfile
    extract_dir = os.path.join(os.environ["TEMP"], "nuclei_extract")
    os.makedirs(extract_dir, exist_ok=True)
    
    with zipfile.ZipFile(output, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    
    # 移动到用户目录
    user_bin = os.path.join(os.environ["USERPROFILE"], ".local", "bin")
    os.makedirs(user_bin, exist_ok=True)
    
    nuclei_exe = os.path.join(extract_dir, "nuclei.exe")
    if os.path.exists(nuclei_exe):
        dest = os.path.join(user_bin, "nuclei.exe")
        import shutil
        shutil.copy(nuclei_exe, dest)
        print(f"\nInstalled to: {dest}")
        
        # 验证
        import subprocess
        result = subprocess.run([dest, "--version"], capture_output=True, text=True)
        print(f"\nVersion check:")
        print(result.stdout)
    else:
        print(f"\nError: nuclei.exe not found in extracted files")
        print(f"Files: {os.listdir(extract_dir)}")
        
except Exception as e:
    print(f"\n\nError: {e}")
    import traceback
    traceback.print_exc()
