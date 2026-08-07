"""认证绕过检测模块 (Phase 1: 业务逻辑检测亮点 C)。

检测思路:
1. 认证头移除重放:已认证请求 vs 无认证头请求,若都返回 200 且内容一致 → 认证未生效。
2. JWT 增强: none 算法 / 弱密钥 HS256(常见弱密钥列表)。
3. 默认凭据尝试(轻量,复用常见默认口令表)。

复用 API 模块的认证绕过判定经验,但更聚焦"认证头"路径。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Dict, List

from ...models import Confidence, ScanTarget, Severity, Vulnerability
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.authbypass")

# 常见默认凭据(仅用于检测,不自动登录);module-level tuple 避免 RUF012 可变类级默认值
_DEFAULT_CREDS = (
    ("admin", "admin"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "admin888"),
    ("root", "root"),
    ("admin", "1234"),
    ("admin", "000000"),
    ("test", "test"),
)


@register_module
class AuthBypassDetector(DetectionModule):
    """认证绕过检测。"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="authbypass",
            description="认证绕过检测 (认证头移除/JWT none与弱密钥/默认凭据)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=False,  # lite 模块
            tags=["auth", "bypass", "jwt", "business-logic"],
            category="lite",
            priority=50,
        )

    @staticmethod
    def _is_public_path(url: str) -> bool:
        public_patterns = [
            "/login", "/logout", "/register", "/signup", "/signin",
            "/forgot-password", "/reset-password", "/assets/", "/static/",
            "/public/", "/css/", "/js/", "/images/", "/img/", "/favicon",
            "/robots.txt", "/sitemap.xml", "/.well-known/", "/health",
            "/healthz", "/ping", "/status", "/version",
        ]
        url_lower = url.lower()
        return any(p in url_lower for p in public_patterns)

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if self._is_public_path(target.url):
            return vulns

        headers = dict(target.headers or {})

        # 1. 认证头移除重放
        auth_vulns = await self._detect_auth_header_removal(target, headers)
        vulns.extend(auth_vulns)

        # 2. JWT 检测(若存在 token)
        jwt_vulns = await self._detect_jwt_issues(target, headers)
        vulns.extend(jwt_vulns)

        # 3. 默认凭据尝试(仅对登录端点,且需配置开启,避免请求过多)
        if self.config.get("modules.authbypass.weak_creds", False) and any(
            kw in target.url.lower() for kw in ("login", "signin", "auth", "admin")
        ):
            cred_vulns = await self._detect_default_creds(target)
            vulns.extend(cred_vulns)

        return vulns

    async def _detect_default_creds(self, target: ScanTarget) -> List[Vulnerability]:
        """默认凭据尝试:对登录表单 POST 常见默认口令组合。

        仅做验证性探测(响应与失败对比),不自动登录;开启需显式配置
        modules.authbypass.weak_creds=true(合规考量)。
        """
        vulns: List[Vulnerability] = []
        base_url = target.url.split("?")[0]

        # 先探测一次失败登录,建立失败响应基线
        probe_params = {"username": "rayxscan_probe", "password": "invalid_probe_123"}
        fail_resp = await self._send_request("POST", base_url, probe_params, "body")
        if fail_resp is None or fail_resp.get("status_code") not in (200, 401, 403):
            return vulns
        fail_len = len(fail_resp.get("text", "") or "")

        for user, pwd in _DEFAULT_CREDS:
            self._explain("baseline", f"尝试默认凭据: {user}:{pwd}")
            test_params = {"username": user, "password": pwd}
            resp = await self._send_request("POST", base_url, test_params, "body")
            if resp is None:
                continue
            status = resp.get("status_code", 0)
            text = (resp.get("text", "") or "")[:3000]
            # 成功特征:状态码不同(200 vs 403/401)、内容与失败响应显著不同、含登录成功标识
            success = False
            success = (status in (200, 302) and fail_resp.get("status_code") in (401, 403)) or (
                len(text) > 0
                and fail_len > 0
                and abs(len(text) - fail_len) / max(fail_len, 1) > 0.3
                and not any(m in text.lower() for m in ("invalid", "error", "incorrect", "wrong password"))
            )
            if success:
                self._explain("signal", f"默认凭据有效: {user}:{pwd}", {"status": status})
                vulns.append(
                    self._create_vuln(
                        url=base_url,
                        param="",
                        param_type="body",
                        method="POST",
                        payload=f"username={user}&password={pwd}",
                        vuln_type="default-credentials",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence=f"Default credentials {user}:{pwd} accepted on login endpoint",
                        description="Login endpoint accepts well-known default credentials",
                        recommendation=(
                            "Force password change on first login and enforce a strong password policy."
                        ),
                        context={"username": user},
                    )
                )
                break  # 发现一组即可,避免继续试探

        return vulns

    async def _detect_auth_header_removal(self, target: ScanTarget, headers: Dict[str, str]) -> List[Vulnerability]:
        """移除认证头后重放,若仍 200 且内容一致 → 认证绕过。"""
        vulns: List[Vulnerability] = []
        auth_header_keys = ["authorization", "x-api-key", "x-auth-token", "api-key", "token"]
        has_auth = any(k.lower() in auth_header_keys for k in headers) or target.cookies
        if not has_auth:
            return vulns

        self._explain("baseline", "携带认证信息请求")

        # 带认证请求
        resp_auth = await self._send_request("GET", target.url, dict(target.params or {}), "query", headers=headers)
        if resp_auth is None or resp_auth.get("status_code") not in (200, 201, 302):
            return vulns

        # 移除认证头
        no_auth_headers = {k: v for k, v in headers.items() if k.lower() not in auth_header_keys}
        resp_noauth = await self._send_request(
            "GET", target.url, dict(target.params or {}), "query", headers=no_auth_headers or None
        )
        if resp_noauth is None:
            return vulns

        # 判定:移除认证后仍 200,且内容几乎一致(非重定向到登录页)
        status_noauth = resp_noauth.get("status_code", 0)
        if status_noauth not in (200, 201):
            return vulns

        text_auth = resp_auth.get("text", "") or ""
        text_noauth = resp_noauth.get("text", "") or ""

        # 排除重定向到登录页
        if any(m in text_noauth[:800].lower() for m in ("login", "sign in", "unauthorized", "forbidden", "403")):
            return vulns

        # 内容相似度:长度相近 + 标签骨架一致
        len_diff = abs(len(text_auth) - len(text_noauth)) / max(len(text_auth), 1)
        if len(text_auth) > 200 and len_diff < 0.2:
            import re

            tags_auth = tuple(re.findall(r"</?(\w+)", text_auth))[:40]
            tags_noauth = tuple(re.findall(r"</?(\w+)", text_noauth))[:40]
            if tags_auth == tags_noauth and len(tags_auth) > 5:
                self._explain(
                    "signal",
                    "移除认证头后仍返回 200 且页面结构一致",
                    {"auth_len": len(text_auth), "noauth_len": len(text_noauth), "len_diff": round(len_diff, 3)},
                )
                self._explain("decision", "认证头未生效 — 疑似认证绕过(需人工复核)")
                vulns.append(
                    self._create_vuln(
                        url=target.url,
                        param="",
                        param_type="header",
                        method="GET",
                        payload="remove auth headers",
                        vuln_type="auth-bypass",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence=f"Request without auth headers returned 200 with identical page structure (len_diff={len_diff:.2f})",
                        description="Endpoint remains accessible after removing authentication headers",
                        recommendation=(
                            "Enforce authentication middleware on the endpoint; do not rely on client-side checks."
                        ),
                        context={"auth_len": len(text_auth), "noauth_len": len(text_noauth)},
                    )
                )
        return vulns

    async def _detect_jwt_issues(self, target: ScanTarget, headers: Dict[str, str]) -> List[Vulnerability]:
        """JWT none 算法 + 弱密钥检测。"""
        vulns: List[Vulnerability] = []
        auth_header = ""
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth_header = v
                break
        token = auth_header.replace("Bearer", "").strip() if auth_header.startswith("Bearer") else ""
        if not token and "=" in auth_header:
            token = auth_header.split("=")[-1].strip()
        if not token or token.count(".") != 2:
            return vulns

        try:
            header_b64 = token.split(".")[0]
            header_padded = header_b64 + "=" * (-len(header_b64) % 4)
            header_json = json.loads(base64.urlsafe_b64decode(header_padded).decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            return vulns

        self._explain("baseline", f"发现 JWT, alg={header_json.get('alg', 'unknown')}")

        # 1. alg=none
        if header_json.get("alg", "").lower() == "none":
            self._explain("signal", "JWT 使用 alg=none — 签名可被省略绕过")
            vulns.append(
                self._create_vuln(
                    url=target.url,
                    param="",
                    param_type="header",
                    method="GET",
                    payload="JWT alg=none",
                    vuln_type="jwt-alg-none",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence="JWT header declares alg=none — signature verification bypass possible",
                    description="JWT uses the 'none' algorithm, allowing unsigned token forgery",
                    recommendation="Reject 'none' algorithm; enforce a whitelist of HMAC/RSA algorithms.",
                    context={"alg": header_json.get("alg")},
                )
            )
            return vulns

        # 2. HS256 弱密钥
        if header_json.get("alg", "").upper() in ("HS256", "HS384", "HS512"):
            signing_input = token.rsplit(".", 1)[0]
            weak_keys = ["secret", "password", "123456", "secretkey", "changeme", "admin", "test", "jwt_secret"]
            for key in weak_keys:
                try:
                    sig = base64.urlsafe_b64encode(
                        hmac.new(key.encode(), signing_input.encode(), hashlib.sha256).digest()
                    ).rstrip(b"=")
                    if sig.decode() == token.split(".")[2]:
                        self._explain("signal", f"JWT HS256 弱密钥破解成功: key={key!r}")
                        vulns.append(
                            self._create_vuln(
                                url=target.url,
                                param="",
                                param_type="header",
                                method="GET",
                                payload=f"JWT weak key: {key}",
                                vuln_type="jwt-weak-secret",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                evidence=f"JWT HS256 signed with weak secret '{key}' — tokens can be forged",
                                description="JWT uses a weak HMAC secret, allowing token forgery",
                                recommendation="Use a strong random secret (>=256 bits) and rotate it.",
                                context={"weak_key": key},
                            )
                        )
                        break
                except Exception:  # noqa: BLE001
                    continue

        return vulns
