"""
RayScan MCP Server（T2.1）— 把扫描能力暴露给 AI 客户端（Claude Desktop / ChatGPT 等）。

- 基于官方 mcp SDK（可选依赖：`pip install "rayscan[mcp]"`；Python >= 3.10）
- 启动：`python -m wvs mcp [--host 127.0.0.1] [--port 18000]`
- 默认仅绑定本机回环地址；工具执行的是完整扫描（爬取→检测→Nuclei→报告），
  由 AI 客户端经 MCP 协议发起，等价于 CLI 一条扫描命令。

暴露工具：
  - scan(url, modules, all_modules, max_time) : 执行一次扫描并返回摘要 JSON
  - list_modules()                            : 列出全部检测模块
  - get_report()                              : 最近一次扫描的详细结果 JSON
"""

import asyncio
import json
import logging
from typing import Optional

logger = logging.getLogger("wvs.mcp_server")

# 最近一次扫描结果（进程内缓存，供 get_report 使用）
_LAST_RESULT: Optional[dict] = None


def _vuln_summary(result) -> list:
    """把 ScanResult.vulnerabilities 压成紧凑条目（截断 evidence 控制上下文）。"""
    out = []
    for v in result.vulnerabilities:
        out.append(
            {
                "type": v.type.value if v.type else "unknown",
                "severity": v.severity.value if v.severity else "info",
                "confidence": v.confidence.value if v.confidence else "unknown",
                "url": (v.url or "")[:200],
                "parameter": v.parameter or "",
                "evidence": (v.evidence or "")[:300],
            }
        )
    return out


def _build_scanner():
    """构造扫描器（与 CLI 一致的配置链）。"""
    from .config import ConfigManager
    from .core import HTTPPool, WAVScanner

    config = ConfigManager()
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    return config, session, scanner


def _load_modules(scanner, modules: str, all_modules: bool) -> int:
    """按参数加载模块；返回加载数量。"""
    if all_modules:
        scanner._load_all_modules = True
        scanner.load_all_modules()
    elif modules:
        for name in [m.strip() for m in modules.split(",") if m.strip()]:
            scanner.load_module(name)
    else:
        scanner.load_all_modules()
    return len(scanner._modules)


def _scan_summary(result) -> dict:
    return {
        "target": result.target.url,
        "duration_seconds": round(result.duration, 1),
        "requests_made": result.requests_made,
        "endpoints_found": result.endpoints_found,
        "modules_run": result.modules_run,
        "vulnerability_count": result.vulnerability_count,
        "severity_count": result.severity_count,
        "vulnerabilities": _vuln_summary(result),
    }


async def _run_scan(url: str, modules: str = "", all_modules: bool = False, max_time: int = 1200) -> dict:
    """执行扫描并返回摘要 dict（任何失败返回 {error: ...}）。"""
    global _LAST_RESULT

    from .models import ScanTarget

    try:
        config, session, scanner = _build_scanner()
        loaded = _load_modules(scanner, modules, all_modules)

        target = ScanTarget(url=url)
        scanner._scan_max_time = max_time

        coro = scanner.scan(target)
        if max_time and max_time > 0:
            result = await asyncio.wait_for(coro, timeout=max_time)
        else:
            result = await coro
        await session.close()

        summary = _scan_summary(result)
        summary["modules_loaded"] = loaded
        _LAST_RESULT = result.to_dict()
        return summary
    except asyncio.TimeoutError:
        return {"error": f"扫描超时（>{max_time}s），可增大 max_time 参数后重试"}
    except Exception as e:
        logger.exception("[MCP] scan failed")
        return {"error": f"扫描失败: {e}"}


def create_server(host: str = "127.0.0.1", port: int = 18000):
    """创建 FastMCP 服务器实例（测试可复用；host/port 供 run 时绑定）。"""
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("rayscan", host=host, port=port)

    @server.tool(
        description="对目标 URL 执行一次 RayScan 全流程扫描（爬取→检测→Nuclei→去重→报告），返回漏洞摘要。"
        "仅可用于你拥有明确授权的目标。"
    )
    async def scan(url: str, modules: str = "", all_modules: bool = False, max_time: int = 1200) -> str:
        """
        扫描单个目标 URL。

        Args:
            url: 目标 URL（http/https）。
            modules: 逗号分隔的模块名（如 "sqli,xss"）；空 = 默认 core 模块。
            all_modules: 是否加载全部模块（含 lite：OA/WebShell/弱口令等）。
            max_time: 全局扫描超时（秒），0 表示不限制。
        """
        summary = await _run_scan(url, modules, all_modules, max_time)
        return json.dumps(summary, ensure_ascii=False, indent=2)

    @server.tool(description="列出 RayScan 全部可用的检测模块（名称/描述/类别）。")
    async def list_modules() -> str:
        from .modules import register_all_modules
        from .modules.base import ModuleFactory

        register_all_modules()
        rows = []
        for name in ModuleFactory.list_modules():
            info = ModuleFactory.get_module_info(name)
            rows.append(
                {
                    "name": name,
                    "description": info.description if info else "",
                    "category": info.category if info else "lite",
                }
            )
        return json.dumps(rows, ensure_ascii=False, indent=2)

    @server.tool(description="返回最近一次 scan 工具调用的完整扫描结果（含全部漏洞详情）。")
    async def get_report() -> str:
        if _LAST_RESULT is None:
            return json.dumps({"error": "尚无扫描结果，请先调用 scan"}, ensure_ascii=False)
        return json.dumps(_LAST_RESULT, ensure_ascii=False, indent=2, default=str)

    return server


def run_server(host: str = "127.0.0.1", port: int = 18000) -> None:
    """启动 MCP Server（streamable-http transport）。"""
    server = create_server(host=host, port=port)
    logger.warning(f"[MCP] RayScan MCP Server 启动: http://{host}:{port}/mcp（仅供本机/AI 客户端调用）")
    server.run(transport="streamable-http")
