"""
GraphQL 检测模块（T3.1，lite）

功能：
  1. 端点发现：常见 GraphQL 路径探测
  2. 端点确认：POST 简单 query（`{__typename}`）响应含 GraphQL 特征才算
  3. 检查项（全部基于响应证据验证，S1 误报治理原则）：
     - introspection 开启（INFO_DISCLOSURE / medium）：`{__schema{types{name}}}` 返回 schema 数据
     - 批量查询（batched query）支持（API_SECURITY / low）：JSON 数组请求被接受
  4. 仅"端点可达"不算漏洞；无 GraphQL 特征一律不报
"""

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from ...models import Confidence, ScanTarget, Severity, Vulnerability, VulnerabilityType
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.graphql")

# ── 常见 GraphQL 端点路径 ──────────────────────────────────────
GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/console",
    "/gql",
    "/graph",
    "/v1/graphql",
    "/v2/graphql",
    "/graphiql",
]

# ── 指纹特征（GET/POST 响应命中即视为 GraphQL） ────────────────
GRAPHQL_FINGERPRINTS = [
    "__typename",
    '"__schema"',
    "GraphQL",
    "graphiql",
    "apollo",
]

# ── 探测 query ─────────────────────────────────────────────────
_QUERY_TYPENAME = '{"query": "{ __typename }"}'
_QUERY_INTROSPECTION = '{"query": "{ __schema { types { name } } }"}'
_QUERY_BATCHED = '[{"query": "{ __typename }"}, {"query": "{ __typename }"}]'


def _looks_like_graphql(text: str) -> bool:
    """基于响应内容判断是否 GraphQL 服务（大小写不敏感）。"""
    if not text:
        return False
    low = text.lower()
    return any(fp.lower() in low for fp in GRAPHQL_FINGERPRINTS)


def _is_introspection_response(text: str) -> bool:
    """响应确含 introspection 数据（__schema 结构 + types 列表）。"""
    return '"__schema"' in text and '"types"' in text


@register_module
class GraphQLDetector(DetectionModule):
    """GraphQL 端点识别与暴露面检测"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="graphql",
            description="GraphQL 端点识别 / introspection 开启 / 批量查询检测",
            category="lite",
            priority=50,
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        base = target.url.rstrip("/")
        parsed = urlparse(base)

        # 根端点（/）→ 标准路径全集探测
        if parsed.path in ("", "/"):
            probe_urls = [urljoin(base + "/", p.lstrip("/")) for p in GRAPHQL_PATHS]
        elif any(kw in parsed.path.lower() for kw in ("graphql", "gql", "graphiql", "__graphql")):
            # 具体端点：仅当路径含 GraphQL 特征词才自身探测（避免重测无关端点）
            probe_urls = [base]
        else:
            return vulns

        for url in probe_urls:
            found = await self._probe_endpoint(url)
            vulns.extend(found)

        return vulns

    async def _probe_endpoint(self, url: str) -> List[Vulnerability]:
        """探测单个端点；返回发现的漏洞（证据验证通过才报）。"""
        vulns: List[Vulnerability] = []

        # GET 探测（响应特征命中直接进入深测；404/403 跳过）
        assert self._active_session is not None, "session required"
        try:
            get_resp = await self._active_session.request(
                "GET", url, timeout=self.module_config.timeout, follow_redirects=False
            )
        except Exception as e:
            logger.debug(f"[GraphQL] GET 探测失败 {url}: {e}")
            return vulns

        if get_resp.status_code in (404, 403, 405):
            return vulns
        get_text = get_resp.text or ""

        if not _looks_like_graphql(get_text):
            # GET 无特征 —— 用 POST 简单 query 确认
            confirm = await self._post_query(url, _QUERY_TYPENAME)
            if not confirm or not _looks_like_graphql(confirm.get("text", "")):
                return vulns

        # ── 检查项 1: introspection 开启 ──
        intro_resp = await self._post_query(url, _QUERY_INTROSPECTION)
        if intro_resp and _is_introspection_response(intro_resp.get("text", "")):
            vulns.append(
                self._create_vuln(
                    url=url,
                    param="",
                    param_type="body",
                    method="POST",
                    payload="introspection query",
                    vuln_type="graphql-introspection-enabled",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    explicit_vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                    evidence="GraphQL introspection 未禁用：__schema 查询返回了完整 types 列表",
                    description="GraphQL 服务未禁用 introspection，攻击者可枚举全部类型/字段/指令，辅助构造注入与敏感数据查询。",
                    recommendation="生产环境禁用 introspection（如 Apollo Server 设置 introspection: false）；配合查询深度/复杂度限制。",
                    context={"graphql_endpoint": url},
                )
            )

        # ── 检查项 2: 批量查询（batched query）支持 ──
        batch_resp = await self._post_query(url, _QUERY_BATCHED)
        if batch_resp:
            batch_text = batch_resp.get("text", "").lstrip()
            if batch_text.startswith("[") and '"data"' in batch_text:
                vulns.append(
                    self._create_vuln(
                        url=url,
                        param="",
                        param_type="body",
                        method="POST",
                        payload="batched query",
                        vuln_type="graphql-batched-query",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        explicit_vuln_type=VulnerabilityType.API_SECURITY,
                        evidence="GraphQL 接受 JSON 数组批量查询（单请求多 query）",
                        description="GraphQL 服务支持批量（batched）查询，可能被用于单请求放大攻击面或绕过速率限制。",
                        recommendation="按业务需要禁用批量查询或限制批次数；引入查询复杂度分析与速率限制。",
                        context={"graphql_endpoint": url},
                    )
                )

        return vulns

    async def _post_query(self, url: str, body: str) -> Optional[Dict[str, Any]]:
        """发送 GraphQL POST（application/json）；返回 {"text", "status_code"} 或 None。"""
        assert self._active_session is not None, "session required"
        try:
            resp = await self._active_session.request(
                "POST",
                url,
                data=body,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=self.module_config.timeout,
                follow_redirects=False,
            )
            return {"status_code": resp.status_code, "text": resp.text or ""}
        except Exception as e:
            logger.debug(f"[GraphQL] POST 失败 {url}: {e}")
            return None
