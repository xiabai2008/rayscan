"""
API安全检测模块
检测：未授权访问、敏感信息泄露、API版本暴露、JWT漏洞、CORS配置错误
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
    
    检测策略：
    1. 未授权访问（移除认证token后重放请求）
    2. 敏感信息泄露（API响应中的敏感数据）
    3. JWT漏洞（弱密钥、算法混淆）
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
    
    async def _detect_auth_bypass(self, target: ScanTarget) -> List[Vulnerability]:
        """检测未授权访问 — P11: 增加多维度验证，区分公开页面与需鉴权页面"""
        vulns: List[Vulnerability] = []

        try:
            headers = dict(target.headers) if target.headers else {}

            # P7: 只在有认证信息时才做bypass检测
            auth_headers = ["authorization", "cookie", "x-api-key", "x-auth-token"]
            has_auth = any(k.lower() in auth_headers for k in headers)
            if not has_auth:
                return vulns

            # 正常请求（带认证）
            resp_auth = await self._active_session.get(
                target.url,
                params=target.params,
                headers=headers,
                timeout=10,
            )

            # 移除认证头后重放
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

            # P11: 多维度判断是否真的存在越权访问
            if not (resp_auth.status_code == 200 and resp_noauth.status_code == 200):
                return vulns

            auth_text = resp_auth.text
            noauth_text = resp_noauth.text

            # P11-1: 排除公开登录页 — 包含登录表单的不是鉴权缺陷
            login_indicators = [
                '<form', 'login', 'Login', 'sign in', 'Sign In',
                'username', 'password', 'passwd',
                'remember me', 'forgot password',
                'type="password"', "type='password'",
            ]
            login_score = sum(1 for ind in login_indicators if ind in noauth_text[:2000])
            if login_score >= 3:
                logger.debug(f"[API] Skipping auth bypass — page looks like a login form (score={login_score})")
                return vulns

            # P11-2: 排除静态/公开页面 — 响应内容不含敏感数据特征
            sensitive_content_indicators = [
                '"id"', '"userId"', '"username"', '"email"', '"role"',
                '"data"', '"result"', '"users"', '"accounts"', '"profile"',
                '"admin"', '"settings"', '"config"',
                'dashboard', 'Dashboard',
                'admin panel', 'control panel',
            ]
            has_sensitive = any(ind in noauth_text[:3000] for ind in sensitive_content_indicators)
            if not has_sensitive:
                logger.debug(f"[API] Skipping auth bypass — no sensitive content indicators in response")
                return vulns

            # P11-3: 确认两个响应的内容实质性相同（不只是长度相近）
            len_diff = abs(len(auth_text) - len(noauth_text))
            if len_diff >= 500:
                return vulns  # 长度差异大，说明非认证页面确实有不同响应

            # P11-4: 关键内容比较 — 提取页面核心内容（去掉动态token/时间等）
            import re as _re
            def _normalize_text(t: str) -> str:
                # 移除CSRF token, timestamp, nonce, UUID等动态字段
                t = _re.sub(r'<input[^>]*name=["\']_(csrf|token|nonce)["\'][^>]*>', '', t, flags=_re.IGNORECASE)
                t = _re.sub(r'name=["\']csrf[_]?token["\'][^>]*value=["\'][^"\']*["\']', '', t, flags=_re.IGNORECASE)
                t = _re.sub(r'\b[a-f0-9]{32,64}\b', '', t)  # MD5/SHA hashes
                t = _re.sub(r'\b\d{10,13}\b', '', t)  # timestamps
                t = _re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '', t)  # UUIDs
                return t

            norm_noauth = _normalize_text(noauth_text[:5000])
            norm_auth = _normalize_text(auth_text[:5000])
            content_similarity = abs(len(norm_noauth) - len(norm_auth)) / max(len(norm_noauth), 1)

            if content_similarity > 0.2:
                return vulns  # After normalization, content is actually different

            vulns.append(Vulnerability(
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
            ))

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
            
            # 检测弱算法（none算法）
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
            
            # 检测算法混淆（HS256→RS256）
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
