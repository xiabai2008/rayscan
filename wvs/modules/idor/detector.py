"""IDOR / 越权访问检测模块 (Phase 1: 业务逻辑检测亮点 C)。

检测思路(SRC 场景最大赏金来源之一,传统扫描器覆盖不到、WAF 拦不住):
1. 对象替换:对 URL/body 中的数字/ID 参数替换(±1、相同结构不同值),
   对比响应差异(状态码/内容/长度),识别水平越权读。
2. 批量接口探测:分页/批量参数(page/size/all/export)是否泄露其他用户数据。
3. 管理端点探测:直接访问常见管理路径,检测垂直越权。

降误报设计:
- 两次不同替换值(±1 与 +100)均返回 200 且内容结构一致 → 才判定
- 排除公开路径与登录/静态资源
- 判定结果 confidence=MEDIUM(提示人工复核)
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List

from ...models import Confidence, ScanTarget, Severity, Vulnerability
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.idor")


@register_module
class IDORDetector(DetectionModule):
    """IDOR (Insecure Direct Object Reference) / 越权访问检测。"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="idor",
            description="IDOR/越权访问检测 (对象替换/批量接口/管理端点)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=False,  # lite 模块, --all-modules 启用
            tags=["idor", "broken-access", "business-logic"],
            category="lite",
            priority=50,
        )

    # 对象 ID 参数名特征
    _ID_PARAM_RE = re.compile(
        r"(?i)(^|_)(id|uid|user_id|userid|account|profile|order|invoice|ticket|post|article"
        r"|product|item|record|document|file|attachment|payment|card|member|customer)(_|$)"
    )

    # 常见管理端点(垂直越权探测);module-level tuple 避免 RUF012 可变类级默认值
    _ADMIN_PATHS = (
        "/admin", "/administrator", "/manage", "/management", "/admin.php",
        "/admin/index.php", "/admin/users", "/admin/user", "/admin/list",
        "/admin/config", "/api/admin", "/api/users", "/api/admin/users",
        "/console", "/backend", "/sys", "/system/admin",
    )

    # 批量/导出参数名
    _BULK_PARAMS = ("page", "size", "limit", "offset", "all", "export", "download", "batch")

    @staticmethod
    def _is_public_path(url: str) -> bool:
        """排除公开路径与静态资源,降低误报。"""
        public_patterns = [
            "/login", "/logout", "/register", "/signup", "/signin",
            "/forgot-password", "/reset-password", "/assets/", "/static/",
            "/public/", "/css/", "/js/", "/images/", "/img/", "/favicon",
            "/robots.txt", "/sitemap.xml", "/.well-known/", "/health",
            "/healthz", "/ping", "/status", "/version",
        ]
        url_lower = url.lower()
        return any(p in url_lower for p in public_patterns)

    @staticmethod
    def _find_id_params(params: Dict[str, str]) -> List[str]:
        """找出疑似对象 ID 参数。"""
        id_params = []
        for name, value in params.items():
            if IDORDetector._ID_PARAM_RE.search(name):
                id_params.append(name)
            elif value and value.isdigit() and len(value) <= 10:
                # 数字值参数也可能是对象 ID
                id_params.append(name)
        return id_params

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        url = target.url

        if self._is_public_path(url):
            return vulns

        # 1. 对象替换检测
        idor_vulns = await self._detect_object_replacement(target)
        vulns.extend(idor_vulns)

        # 2. 批量接口探测
        bulk_vulns = await self._detect_bulk_params(target)
        vulns.extend(bulk_vulns)

        # 3. 管理端点垂直越权
        admin_vulns = await self._detect_admin_endpoints(target)
        vulns.extend(admin_vulns)

        return vulns

    async def _detect_object_replacement(self, target: ScanTarget) -> List[Vulnerability]:
        """对象替换检测:替换 ID 参数观察响应差异。"""
        vulns: List[Vulnerability] = []
        # 统一取参数:优先 target.params(GET),回退 target.data(POST)
        params = dict(target.params or {})
        if not params and target.data:
            params = dict(target.data)
        if not params:
            return vulns

        id_params = self._find_id_params(params)
        if not id_params:
            return vulns

        # 请求 URL 去掉已有 query,避免 _send_request 二次拼接导致参数重复
        base_url = target.url.split("?")[0]
        method = "GET" if target.params else "POST"
        param_type = "query" if target.params else "body"

        for param_name in id_params:
            orig_value = params[param_name]
            # 需要数字 ID 才能做 ±1 替换
            if not orig_value or not str(orig_value).isdigit():
                continue
            orig_value = str(orig_value)
            try:
                alt1 = str(int(orig_value) - 1)
                alt2 = str(int(orig_value) + 100)
            except ValueError:
                continue

            self._explain("baseline", f"原始请求: {param_name}={orig_value}")

            # 原始请求
            orig_resp = await self._send_request(method, base_url, params, param_type)
            if orig_resp is None:
                continue

            # 替换为 alt1
            p1 = params.copy()
            p1[param_name] = alt1
            resp1 = await self._send_request(method, base_url, p1, param_type)

            # 替换为 alt2(不同偏移,降低巧合)
            p2 = params.copy()
            p2[param_name] = alt2
            resp2 = await self._send_request(method, base_url, p2, param_type)

            if resp1 is None or resp2 is None:
                continue

            # 判定:两个不同替换值都返回 200,且响应结构一致(同类型资源),而非 403/404/空
            s1, s2, s0 = resp1.get("status_code"), resp2.get("status_code"), orig_resp.get("status_code")
            if not (s1 == 200 and s2 == 200 and s0 in (200, 302, 301)):
                continue

            text1 = resp1.get("text", "") or ""
            text2 = resp2.get("text", "") or ""
            text0 = orig_resp.get("text", "") or ""

            # 排除空响应/纯错误页
            if len(text1) < 100 or len(text2) < 100:
                continue
            # 排除 404 页面特征
            if any(m in text1[:500].lower() for m in ("404 not found", "page not found", "access denied", "forbidden")):
                continue

            # 结构一致:提取标签骨架比较
            tags1 = tuple(re.findall(r"</?(\w+)", text1))[:50]
            tags2 = tuple(re.findall(r"</?(\w+)", text2))[:50]
            if tags1 == tags2 and len(tags1) > 5:
                self._explain(
                    "signal",
                    f"对象替换 {param_name}: {orig_value}→{alt1}/{alt2} 均返回 200 且 HTML 结构一致",
                    {"alt1_len": len(text1), "alt2_len": len(text2), "orig_len": len(text0)},
                )
                self._explain(
                    "decision",
                    "两个不同偏移的替换值返回相同结构资源 — 疑似水平越权(需人工复核确认数据归属)",
                )
                vuln = self._create_vuln(
                    url=target.url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=f"{param_name}={orig_value} → {alt1}/{alt2}",
                    vuln_type="idor-object-replacement",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence=(
                        f"Replacing {param_name} from {orig_value} to {alt1}/{alt2} "
                        f"both returned 200 with identical HTML structure — possible IDOR"
                    ),
                    description="Replaceable object ID may allow unauthorized access to other users' resources",
                    recommendation=(
                        "Enforce server-side authorization checks: verify the current user owns the requested "
                        "object (not only that they are authenticated). Use UUIDs/opaque tokens where possible."
                    ),
                    context={"original_value": orig_value, "replacement_values": [alt1, alt2]},
                )
                vulns.append(vuln)
                break  # 每个参数只报一个

        return vulns

    async def _detect_bulk_params(self, target: ScanTarget) -> List[Vulnerability]:
        """批量/导出接口探测。"""
        vulns: List[Vulnerability] = []
        url = target.url.split("?")[0]
        # 只对含 API/batch/list/export 特征路径做批量探测
        if not any(kw in url.lower() for kw in ("api", "list", "export", "batch", "users", "orders", "reports")):
            return vulns

        for param_name in self._BULK_PARAMS:
            test_params = {param_name: "all"}
            resp = await self._send_request("GET", url, test_params, "query")
            if resp is None:
                continue
            status = resp.get("status_code", 0)
            text = resp.get("text", "") or ""
            if status != 200 or len(text) < 200:
                continue
            # 大量数据/敏感字段特征
            sensitive_hits = sum(
                1
                for m in ("email", '"email"', '"phone"', '"id_card"', '"password"', '"token"', '"salary"', '"secret"')
                if m in text[:5000]
            )
            if sensitive_hits >= 2:
                self._explain("signal", f"批量参数 {param_name}=all 返回含敏感字段的批量数据", {"hits": sensitive_hits})
                vulns.append(
                    self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type="query",
                        method="GET",
                        payload=f"{param_name}=all",
                        vuln_type="idor-bulk-data",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        evidence=f"Bulk parameter {param_name}=all returned sensitive data fields",
                        description="Bulk/export endpoint may expose all records without ownership checks",
                        recommendation="Paginate and scope bulk endpoints to the current user's data.",
                        context={"sensitive_hits": sensitive_hits},
                    )
                )
                break

        return vulns

    async def _detect_admin_endpoints(self, target: ScanTarget) -> List[Vulnerability]:
        """管理端点垂直越权探测(轻量,默认跳过以免产生过多请求)。"""
        vulns: List[Vulnerability] = []
        # 默认关闭——管理端点探测请求量大、误报高,仅在配置开启时执行
        if not self.config.get("modules.idor.admin_probe", False):
            return vulns

        from urllib.parse import urlparse

        parsed = urlparse(target.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self._ADMIN_PATHS:
            resp = await self._send_request("GET", base + path, {}, "query")
            if resp is None:
                continue
            status = resp.get("status_code", 0)
            text = resp.get("text", "") or ""
            if status in (200, 302, 301) and len(text) > 200 and "login" not in text.lower()[:1000]:
                self._explain("signal", f"管理端点可达: {path}", {"status_code": status})
                vulns.append(
                    self._create_vuln(
                        url=base + path,
                        param="",
                        param_type="query",
                        method="GET",
                        payload=path,
                        vuln_type="idor-admin-access",
                        severity=Severity.HIGH,
                        confidence=Confidence.LOW,  # 需人工确认是否未授权
                        evidence=f"Admin endpoint {path} reachable without obvious login redirect",
                        description="Possible vertical privilege escalation to admin area",
                        recommendation="Verify admin endpoints enforce authentication/authorization.",
                        context={"path": path},
                    )
                )
        return vulns
