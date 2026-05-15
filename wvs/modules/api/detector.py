"""
API Security Detection Module
Detects: unauthorized access, sensitive information disclosure, API version exposure, JWT vulnerabilities, CORS misconfiguration
"""

import base64
import json
import logging
import re
from typing import List

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget

logger = logging.getLogger("wvs.module.api")


@register_module
class APIDetector(DetectionModule):
    """
    API Security Detection Module

    Detection strategies:
    1. Unauthorized access (replay request after removing auth token)
    2. Sensitive information disclosure (sensitive data in API responses)
    3. JWT vulnerabilities (weak keys, algorithm confusion)
    4. CORS misconfiguration
    5. API version information disclosure
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
        Main API security detection logic
        """
        vulns: List[Vulnerability] = []

        # 1. Unauthorized access detection
        auth_vulns = await self._detect_auth_bypass(target)
        vulns.extend(auth_vulns)

        # 2. Sensitive information disclosure detection
        info_vulns = await self._detect_info_disclosure(target)
        vulns.extend(info_vulns)

        # 3. CORS configuration detection
        cors_vulns = await self._detect_cors_misconfig(target)
        vulns.extend(cors_vulns)

        # 4. JWT vulnerability detection
        jwt_vulns = await self._detect_jwt_issues(target)
        vulns.extend(jwt_vulns)

        return vulns

    async def _detect_auth_bypass(self, target: ScanTarget) -> List[Vulnerability]:
        """Detect unauthorized access — P11: Multi-dimensional verification, distinguish public pages from authenticated pages"""
        vulns: List[Vulnerability] = []

        # 跳过已知公开路径
        if self._is_public_path(target.url):
            return vulns

        try:
            headers = dict(target.headers) if target.headers else {}

            # P7: Only perform bypass detection when authentication info is present
            auth_headers = ["authorization", "cookie", "x-api-key", "x-auth-token"]
            has_auth_headers = any(k.lower() in auth_headers for k in headers)

            # 如果没有任何认证头，无法测试绕过
            if not has_auth_headers:
                return vulns

            # Normal request (with authentication)
            resp_auth = await self._active_session.get(
                target.url,
                params=target.params,
                headers=headers,
                timeout=10,
            )

            # Replay after removing auth headers
            no_auth_headers = {k: v for k, v in headers.items() if k.lower() not in auth_headers}

            resp_noauth = await self._active_session.get(
                target.url,
                params=target.params,
                headers=no_auth_headers if no_auth_headers else None,
                timeout=10,
            )

            # P11: Multi-dimensional judgment of actual privilege escalation
            if not (resp_auth.status_code == 200 and resp_noauth.status_code == 200):
                return vulns

            # 无认证返回 401/403 → 确认需要认证
            # 带认证请求
            resp_auth = await self._active_session.get(
                target.url,
                params=target.params,
                headers=headers,
                timeout=10,
            )

            # P11-1: Exclude public login pages — pages with login forms are not auth defects
            login_indicators = [
                "<form",
                "login",
                "Login",
                "sign in",
                "Sign In",
                "username",
                "password",
                "passwd",
                "remember me",
                "forgot password",
                'type="password"',
                "type='password'",
            ]
            login_score = sum(1 for ind in login_indicators if ind in noauth_text[:2000])
            if login_score >= 3:
                logger.debug(f"[API] Skipping auth bypass — page looks like a login form (score={login_score})")
                return vulns

            # P11-2: Exclude static/public pages — response content lacks sensitive data markers
            sensitive_content_indicators = [
                '"id"',
                '"userId"',
                '"username"',
                '"email"',
                '"role"',
                '"data"',
                '"result"',
                '"users"',
                '"accounts"',
                '"profile"',
                '"admin"',
                '"settings"',
                '"config"',
                "dashboard",
                "Dashboard",
                "admin panel",
                "control panel",
            ]
            has_sensitive = any(ind in noauth_text[:3000] for ind in sensitive_content_indicators)
            if not has_sensitive:
                logger.debug("[API] Skipping auth bypass — no sensitive content indicators in response")
                return vulns

            # P11-3: Confirm both responses have substantially the same content (not just similar length)
            len_diff = abs(len(auth_text) - len(noauth_text))
            if len_diff >= 500:
                return vulns  # Large length difference indicates different responses

            # P11-4: Key content comparison — extract core page content (strip dynamic tokens/timestamps etc.)
            import re as _re

            def _normalize_text(t: str) -> str:
                # Remove CSRF token, timestamp, nonce, UUID and other dynamic fields
                t = _re.sub(r'<input[^>]*name=["\']_(csrf|token|nonce)["\'][^>]*>', "", t, flags=_re.IGNORECASE)
                t = _re.sub(r'name=["\']csrf[_]?token["\'][^>]*value=["\'][^"\']*["\']', "", t, flags=_re.IGNORECASE)
                t = _re.sub(r"\b[a-f0-9]{32,64}\b", "", t)  # MD5/SHA hashes
                t = _re.sub(r"\b\d{10,13}\b", "", t)  # timestamps
                t = _re.sub(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "", t)  # UUIDs
                return t

            norm_noauth = _normalize_text(noauth_text[:5000])
            norm_auth = _normalize_text(auth_text[:5000])
            content_similarity = abs(len(norm_noauth) - len(norm_auth)) / max(len(norm_noauth), 1)

            if content_similarity > 0.2:
                return vulns  # After normalization, content is actually different

            vulns.append(
                Vulnerability(
                    type=VulnerabilityType.BROKEN_AUTH,
                    title="API Authentication Bypass",
                    url=target.url,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence="API accessible without authentication — sensitive data exposed",
                    description="API endpoint returns sensitive data without requiring authentication.",
                    impact="Unauthorized access to sensitive data or functionality.",
                    recommendation="Implement proper authentication checks on all API endpoints.",
                    module="api",
                )
            )

        except Exception as e:
            logger.debug(f"Auth bypass test failed: {e}")

        return vulns

    async def _detect_info_disclosure(self, target: ScanTarget) -> List[Vulnerability]:
        """Detect sensitive information disclosure"""
        vulns: List[Vulnerability] = []

        try:
            resp = await self._active_session.get(
                target.url,
                params=target.params,
                timeout=10,
            )

            headers = resp.headers

            # Sensitive information patterns
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
                        vulns.append(
                            Vulnerability(
                                type=VulnerabilityType.INFO_DISCLOSURE,
                                title=f"Sensitive Information Disclosure: {info_type}",
                                url=target.url,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.HIGH,
                                evidence=f"Pattern matched: {pattern[:50]}...",
                                description=f"Sensitive information ({info_type}) exposed in API response.",
                                recommendation="Remove sensitive data from API responses. Use environment variables for secrets.",
                                module="api",
                            )
                        )
                        break

            # Check response headers for information disclosure
            server_header = headers.get("server", "")
            if server_header and len(server_header) > 0:
                # Check if specific version is exposed
                version_pattern = r"\d+\.\d+(\.\d+)?"
                if re.search(version_pattern, server_header):
                    vulns.append(
                        Vulnerability(
                            type=VulnerabilityType.INFO_DISCLOSURE,
                            title="Server Version Disclosure",
                            url=target.url,
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            evidence=f"Server header: {server_header}",
                            description="Server software version exposed in response headers.",
                            recommendation="Configure server to hide version information.",
                            module="api",
                        )
                    )

        except Exception as e:
            logger.debug(f"Info disclosure test failed: {e}")

        return vulns

    async def _detect_cors_misconfig(self, target: ScanTarget) -> List[Vulnerability]:
        """Detect CORS misconfiguration"""
        vulns: List[Vulnerability] = []

        try:
            # Send requests with Origin headers
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

                # Check if arbitrary Origin is reflected
                if acao == origin and acac.lower() == "true":
                    vulns.append(
                        Vulnerability(
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
                        )
                    )
                    break

        except Exception as e:
            logger.debug(f"CORS test failed: {e}")

        return vulns

    async def _detect_jwt_issues(self, target: ScanTarget) -> List[Vulnerability]:
        """Detect JWT vulnerabilities"""
        vulns: List[Vulnerability] = []

        try:
            # Extract JWT from request headers or URL parameters
            headers = dict(target.headers) if target.headers else {}
            auth_header = headers.get("Authorization", "") or headers.get("authorization", "")

            jwt_token = None
            if auth_header.startswith("Bearer "):
                jwt_token = auth_header[7:]

            # Also check URL parameters
            if not jwt_token and target.params:
                jwt_token = target.params.get("token") or target.params.get("jwt")

            if not jwt_token:
                return vulns

            # Parse JWT
            parts = jwt_token.split(".")
            if len(parts) != 3:
                return vulns

            # Decode header and payload
            try:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8"))
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8"))
            except Exception:
                return vulns

            # Detect weak algorithm (none algorithm)
            if header.get("alg", "").lower() == "none":
                vulns.append(
                    Vulnerability(
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
                    )
                )

            # Detect algorithm confusion (HS256 to RS256)
            if header.get("alg") == "HS256" and "kid" in header:
                vulns.append(
                    Vulnerability(
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
                    )
                )

            # Detect sensitive information disclosure
            sensitive_fields = ["password", "secret", "ssn", "credit_card", "private_key"]
            for field in sensitive_fields:
                if field in payload:
                    vulns.append(
                        Vulnerability(
                            type=VulnerabilityType.INFO_DISCLOSURE,
                            title="JWT Sensitive Data Exposure",
                            url=target.url,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            evidence=f"Sensitive field '{field}' found in JWT payload",
                            description="JWT contains sensitive information in payload.",
                            recommendation="Remove sensitive data from JWT payload. Use opaque tokens instead.",
                            module="api",
                        )
                    )
                    break

        except Exception as e:
            logger.debug(f"JWT test failed: {e}")

        return vulns


# Register module
register_module(APIDetector)
