"""MCP Server 暴露检测模块（lite）。"""

from .detector import MCPDetector, _looks_like_mcp, _parse_tools

__all__ = ["MCPDetector", "_looks_like_mcp", "_parse_tools"]
