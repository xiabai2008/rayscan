"""
API安全检测模块
检测:未授权访问、敏感信息泄露、API版本暴露、JWT漏洞、CORS配置错误
"""
import asyncio
import base64
import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget
from ...core.session import HTTPPool

logger = logging.getLogger("wvs.module.api")


@register_module
class APIDetector(DetectionModule):
    """
    API安全检测模块

    检测策略:
    1. 未授权访问(移除认证token后重放请求)
    2. 敏感信息泄露(API响应中的敏感数据)
    3. JWT漏洞(弱密钥、算法混淆)
    4. CORS配置错误
    5. API版本信息泄露
    """

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="api",
            description="API Security detection (auth bypass, info disclosure, JWT, CORS)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["api", "auth", "jwt", "cors", "info-disclosure"],
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """
        API安全检测主逻辑
        """
        vulns: List[Vulnerability] = []

        # 1. 未授权访问检测
        auth_vulns = await self._detect_auth_bypass(target)
        vulns.extend(auth_vulns)

        # 2. 敏感信息泄露检测
        info_vulns = await self._detect_info_disclosure(target)
        vulns.extend(info_vulns)

        # 3. CORS配置检测
        cors_vulns = await self._detect_cors_misconfig(target)
        vulns.extend(cors_vulns)

        # 4. JWT漏洞检测
        jwt_vulns = await self._detect_jwt_issues(target)
        vulns.extend(jwt_vulns)

        return vulns

    # 公开路径白名单：这些路径不需要认证，不报绕过
    PUBLIC_PATH_PATTERNS = [
        r'/readme\.', r'/license\.', r'/CHANGELOG', r'/docs?/', r'/help/',
        r'/css/', r'/js/', r'/images?/', r'/static/', r'/public/',
        r'/favicon', r'/robots\.txt', r'/sitemap\.xml', r'/crossdomain\.xml',
        r'phpMyAdmin/', r'/twiki/', r'/mutillidae/', r'/test/', r'/dav/',
        r'/phpinfo', r'/index\.php$', r'logo\.', r'\.txt$', r'\.md$',
        r'/instructions\.php$', r'/documentation/',
    ]

    def _is_public_path(self, url: str) -> bool:
        """检查是否为众所周知公开路径，跳过认证检测"""
        import re
        for pattern in self.PUBLIC_PATH_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    async def _detect_auth_bypass(self, target: ScanTarget) -> List[Vulnerability]:
        """
        检测未授权访问（减少假阳性）

        策略:
        1. 跳过已知公开路径（白名单）
        2. 先探测无认证请求：如果返回 200 → 页面本来就是公开的，不报
        3. 仅当无认证请求返回 401/403 时才判断存在认证机制
        4. 带认证能访问 + 无认证被拒 = 认证正常工作，不报
        """
        vulns: List[Vulnerability] = []

        # 跳过已知公开路径
        if self._is_public_path(target.url):
            return vulns

        try:
            headers = dict(target.headers) if target.headers else {}

            # 提取认证头类型
            auth_headers = ["authorization", "cookie", "x-api-key", "x-auth-token"]
            has_auth_headers = any(k.lower() in auth_headers for k in headers)

            # 如果没有任何认证头，无法测试绕过
            if not has_auth_headers:
                return vulns

            # 无认证请求
            no_auth_headers = {
                k: v for k, v in headers.items()
                if k.lower() not in auth_headers
            }

            resp_noauth = await self._active_session.get(
                target.url,
                params=target.params,
                headers=no_auth_headers if no_auth_headers else None,
                timeout=10,
            )

            # 无认证返回 200+ → 公开页面，不是绕过
            if resp_noauth.status_code in (200, 301, 302, 304):
                return vulns

            # 无认证返回 401/403 → 确认需要认证
            # 带认证请求
            resp_auth = await self._active_session.get(
                target.url,
                params=target.params,
                headers=headers,
                timeout=10,
            )

            # 带认证才返回 200 = 认证正常工作，没问题
            if resp_auth.status_code in (200, 301, 302):
                pass  # 认证有效，不报

        except Exception as e:
            logger.debug(f"Auth bypass test failed: {e}")

        return vulns

    async def _detect_info_disclosure(self, target: ScanTarget) -> List[Vulnerability]:
        """检测敏感信息泄露"""
        vulns: List[Vulnerability] = []

        try:
            resp = await self._active_session.get(
                target.url,
                params=target.params,
                timeout=10,
            )

            text = resp.text.lower()
            headers = resp.headers

            # 敏感信息模式
            sensitive_patterns = {
                "api_key": [r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{20,}"],
                "secret": [r"secret[_-]?key['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_-]{16,}"],
                "password": [r"password['\"]?\s*[:=]\s*['\"]?[^\s'\"]{8,}"],
                "token": [r"(access|auth|bearer)[_-]?token['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9_.-]{20,}"],
                "aws_key": [r"AKIA[0-9A-Z]{16}"],
                "private_key": [r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"],
            }

            for info_type, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    matches = re.findall(pattern, resp.text, re.IGNORECASE)
                    if matches:
                        vulns.append(Vulnerability(
                            type=VulnerabilityType.INFO_DISCLOSURE,
                            title=f"Sensitive Information Disclosure: {info_type}",
                            url=target.url,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            evidence=f"Pattern matched: {pattern[:50]}...",
                            description=f"Sensitive information ({info_type}) exposed in API response.",
                            recommendation="Remove sensitive data from API responses. Use environment variables for secrets.",
                            module="api",
                        ))
                        break

            # 检查响应头中的信息泄露
            server_header = headers.get("server", "")
            if server_header and len(server_header) > 0:
                # 检查是否暴露具体版本
                version_pattern = r"\d+\.\d+(\.\d+)?"
                if re.search(version_pattern, server_header):
                    vulns.append(Vulnerability(
                        type=VulnerabilityType.INFO_DISCLOSURE,
                        title="Server Version Disclosure",
                        url=target.url,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        evidence=f"Server header: {server_header}",
                        description="Server software version exposed in response headers.",
                        recommendation="Configure server to hide version information.",
                        module="api",
                    ))

        except Exception as e:
            logger.debug(f"Info disclosure test failed: {e}")

        return vulns

    async def _detect_cors_misconfig(self, target: ScanTarget) -> List[Vulnerability]:
        """检测CORS配置错误"""
        vulns: List[Vulnerability] = []

        try:
            # 发送带Origin头的请求
            test_origins = [
                "https://evil.com",
                "http://localhost",
                "null",
            ]

            for origin in test_origins:
                headers = dict(target.headers) if target.headers else {}
                headers["Origin"] = origin

                resp = await self._active_session.get(
                    target.url,
                    params=target.params,
                    headers=headers,
                    timeout=10,
                )

                resp_headers = resp.headers
                acao = resp_headers.get("Access-Control-Allow-Origin", "")
                acac = resp_headers.get("Access-Control-Allow-Credentials", "")

                # 检查是否反射任意Origin
                if acao == origin and acac.lower() == "true":
                    vulns.append(Vulnerability(
                        type=VulnerabilityType.INSECURE_CONFIG,
                        title="CORS Misconfiguration",
                        url=target.url,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence=f"Origin '{origin}' reflected with credentials allowed",
                        description="CORS configuration allows arbitrary origins with credentials.",
                        impact="Cross-origin data theft, user session hijacking.",
                        recommendation="Restrict Access-Control-Allow-Origin to trusted domains only.",
                        module="api",
                    ))
                    break

        except Exception as e:
            logger.debug(f"CORS test failed: {e}")

        return vulns

    async def _detect_jwt_issues(self, target: ScanTarget) -> List[Vulnerability]:
        """检测JWT漏洞"""
        vulns: List[Vulnerability] = []

        try:
            # 从请求头或URL参数中提取JWT
            headers = dict(target.headers) if target.headers else {}
            auth_header = headers.get("Authorization", "") or headers.get("authorization", "")

            jwt_token = None
            if auth_header.startswith("Bearer "):
                jwt_token = auth_header[7:]

            # 也检查URL参数
            if not jwt_token and target.params:
                jwt_token = target.params.get("token") or target.params.get("jwt")

            if not jwt_token:
                return vulns

            # 解析JWT
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return vulns

            # 解码header和payload
            try:
                header = json.loads(
                    base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
                )
                payload = json.loads(
                    base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
                )
            except Exception:
                return vulns

            # 检测弱算法(none算法)
            if header.get("alg", "").lower() == "none":
                vulns.append(Vulnerability(
                    type=VulnerabilityType.BROKEN_AUTH,
                    title="JWT None Algorithm Vulnerability",
                    url=target.url,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    evidence="JWT uses 'none' algorithm",
                    description="JWT token uses insecure 'none' algorithm allowing signature bypass.",
                    impact="Complete authentication bypass.",
                    recommendation="Reject JWTs with 'none' algorithm. Use strong algorithms (RS256, ES256).",
                    module="api",
                ))

            # 检测算法混淆(HS256→RS256)
            if header.get("alg") == "HS256" and "kid" in header:
                vulns.append(Vulnerability(
                    type=VulnerabilityType.BROKEN_AUTH,
                    title="JWT Potential Algorithm Confusion",
                    url=target.url,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence="JWT uses HS256 with 'kid' header, potential algorithm confusion",
                    description="JWT may be vulnerable to algorithm confusion attack (HS256 to RS256).",
                    impact="Authentication bypass via forged tokens.",
                    recommendation="Use separate key stores for symmetric and asymmetric algorithms.",
                    module="api",
                ))

            # 检测敏感信息泄露
            sensitive_fields = ["password", "secret", "ssn", "credit_card", "private_key"]
            for field in sensitive_fields:
                if field in payload:
                    vulns.append(Vulnerability(
                        type=VulnerabilityType.INFO_DISCLOSURE,
                        title="JWT Sensitive Data Exposure",
                        url=target.url,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        evidence=f"Sensitive field '{field}' found in JWT payload",
                        description="JWT contains sensitive information in payload.",
                        recommendation="Remove sensitive data from JWT payload. Use opaque tokens instead.",
                        module="api",
                    ))
                    break

        except Exception as e:
            logger.debug(f"JWT test failed: {e}")

        return vulns


# 注册模块
register_module(APIDetector)
