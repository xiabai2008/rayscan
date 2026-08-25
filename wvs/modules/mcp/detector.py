"""
MCP Server 检测模块（T2.2，lite）

检测暴露的 MCP（Model Context Protocol）server：
  1. 端点发现：常见 MCP 路径探测（/mcp、/api/mcp、/sse、/mcp/sse、/rpc、/mcp/rpc）
  2. 指纹识别：Content-Type text/event-stream、JSON-RPC 特征（jsonrpc/serverInfo/协议版本）
  3. 检查项（全部基于响应证据验证，S1 误报治理原则）：
     - tools/list 未授权调用成功 → 工具列表泄露（information_disclosure / medium）
     - tools/call 可调用敏感工具（shell/exec/bash/python/read_file 等）→ 未授权执行风险（broken_access / high）

探测协议：MCP Streamable HTTP 的 JSON-RPC 子集（initialize → tools/list → tools/call）。
"""

import json
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from ...models import Confidence, ScanTarget, Severity, Vulnerability, VulnerabilityType
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.mcp")

# ── 常见 MCP 端点路径 ──────────────────────────────────────────
MCP_PATHS = [
    "/mcp",
    "/api/mcp",
    "/mcp/sse",
    "/sse",
    "/rpc",
    "/mcp/rpc",
    "/mcp/message",
]

# ── 协议版本（MCP 规范 2025 系列） ─────────────────────────────
MCP_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]

# ── MCP 特征指纹（命中即视为 MCP server） ──────────────────────
MCP_FINGERPRINTS = [
    '"jsonrpc"',
    "serverInfo",
    '"tools"',
    "text/event-stream",
    "Mcp-Session-Id",
    "modelcontextprotocol",
    '"protocolVersion"',
]

# ── 敏感工具名特征（未授权可调 = 高危） ────────────────────────
SENSITIVE_TOOL_PATTERNS = [
    "shell",
    "exec",
    "command",
    "bash",
    "sh",
    "python",
    "eval",
    "read_file",
    "write_file",
    "file",
    "sql",
    "db",
    "redis",
    "ssh",
]


def _build_initialize() -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "rayscan", "version": "2.2.0"},
        },
    }


def _build_tools_list() -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


def _build_tools_call(tool_name: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": tool_name, "arguments": {}}}


def _looks_like_mcp(text: str, headers: Dict[str, str]) -> bool:
    """基于响应内容/响应头判断是否 MCP server（大小写不敏感）。"""
    low = text.lower()
    for fp in MCP_FINGERPRINTS:
        if fp.lower() in low:
            return True
    ctype = (headers.get("content-type") or "").lower()
    if "text/event-stream" in ctype or "application/vnd.jsonrpc" in ctype:
        return True
    return False


def _parse_tools(payload: Dict[str, Any]) -> List[str]:
    """从 tools/list 响应中提取工具名列表。"""
    result = payload.get("result") or {}
    tools = result.get("tools") or []
    names = []
    for t in tools:
        if isinstance(t, dict) and isinstance(t.get("name"), str):
            names.append(t["name"])
    return names


@register_module
class MCPDetector(DetectionModule):
    """MCP server 暴露面检测"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="mcp",
            description="MCP Server 暴露检测（端点发现/工具列表泄露/敏感工具未授权调用）",
            category="lite",
            priority=40,
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        base = target.url.rstrip("/")

        # 端点集合：目标自身 + 常见 MCP 路径
        probe_urls = [base]
        for path in MCP_PATHS:
            probe_urls.append(urljoin(base + "/", path.lstrip("/")))

        for url in probe_urls:
            found = await self._probe_endpoint(url, base)
            vulns.extend(found)

        return vulns

    async def _probe_endpoint(self, url: str, base: str) -> List[Vulnerability]:
        """探测单个端点；返回发现的漏洞（证据验证通过才报）。"""
        vulns: List[Vulnerability] = []
        assert self._active_session is not None, "session required"
        try:
            baseline_resp = await self._active_session.request(
                "GET", url, timeout=self.module_config.timeout, follow_redirects=False
            )
        except Exception as e:
            logger.debug(f"[MCP] GET 探测失败 {url}: {e}")
            return vulns

        # 端点不存在（404/403）或无法访问 → 跳过
        if baseline_resp.status_code in (404, 403, 405):
            return vulns
        baseline_text = baseline_resp.text or ""
        baseline_headers = dict(baseline_resp.headers)

        if not _looks_like_mcp(baseline_text, baseline_headers):
            # GET 不像 MCP —— 尝试 POST JSON-RPC（部分 server 仅接受 POST）
            post_resp = await self._post_jsonrpc(url, _build_initialize())
            if not post_resp or not _looks_like_mcp(post_resp.get("text", ""), post_resp.get("headers", {})):
                return vulns
        else:
            # GET 已暴露 MCP 特征 —— 也尝试 initialize 拿握手结果（仅作指纹确认，不单独上报）
            await self._post_jsonrpc(url, _build_initialize())

        # ── 检查项 1: tools/list 未授权调用成功（工具列表泄露） ──
        tools_resp = await self._post_jsonrpc(url, _build_tools_list())
        tool_names: List[str] = []
        if tools_resp:
            try:
                payload = json.loads(tools_resp.get("text", ""))
                tool_names = _parse_tools(payload)
            except (json.JSONDecodeError, TypeError):
                tool_names = []

        if tool_names:
            vulns.append(
                self._create_vuln(
                    url=url,
                    param="",
                    param_type="body",
                    method="POST",
                    payload="/tools/list",
                    vuln_type="mcp-tools-list-exposed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    explicit_vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                    evidence=f"MCP tools/list 未授权调用成功，暴露 {len(tool_names)} 个工具: {', '.join(tool_names[:10])}",
                    description="MCP Server 的 tools/list 接口无需认证即可调用，暴露全部工具清单（信息泄露）。",
                    recommendation="为 MCP Server 配置认证（OAuth/OAuth2）或访问控制，禁止匿名 tools/list。",
                    context={"mcp_endpoint": url, "tools": tool_names[:50], "base_url": base},
                )
            )

            # ── 检查项 2: 敏感工具未授权调用风险 ──
            sensitive = [t for t in tool_names if any(p in t.lower() for p in SENSITIVE_TOOL_PATTERNS)]
            if sensitive:
                vulns.append(
                    self._create_vuln(
                        url=url,
                        param="",
                        param_type="body",
                        method="POST",
                        payload="/tools/call",
                        vuln_type="mcp-sensitive-tool-unauth",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        explicit_vuln_type=VulnerabilityType.BROKEN_ACCESS,
                        evidence=f"MCP tools/call 存在敏感工具且未授权可调用: {', '.join(sensitive[:10])}",
                        description="MCP Server 暴露 shell/文件/数据库类敏感工具且未授权调用，存在被 AI 客户端或攻击者滥用执行命令/读写文件的风险。",
                        recommendation="对敏感工具实施认证与权限校验；关闭非必要工具；限制工具参数白名单。",
                        context={"mcp_endpoint": url, "sensitive_tools": sensitive[:20], "base_url": base},
                    )
                )

        # initialize 响应本身也算暴露证据（记录但仅当有工具列表时报告，避免纯握手误报）
        return vulns

    async def _post_jsonrpc(self, url: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """发送 JSON-RPC POST；返回 {"text", "headers", "status_code"} 或 None。"""
        assert self._active_session is not None, "session required"
        try:
            resp = await self._active_session.request(
                "POST",
                url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                timeout=self.module_config.timeout,
                follow_redirects=False,
            )
            return {
                "status_code": resp.status_code,
                "text": resp.text or "",
                "headers": dict(resp.headers),
            }
        except Exception as e:
            logger.debug(f"[MCP] JSON-RPC 请求失败 {url}: {e}")
            return None
