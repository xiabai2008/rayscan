"""Web UI 请求参数 → 扫描配置（纯函数，可脱离 Flask 单测）。

职责边界:不发起网络请求、不创建会话;只做 profile/参数/模块解析。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from wvs.config import ConfigManager
from wvs.profiles import ProfileManager

# 请求字段 → ConfigManager 键（显式值覆盖 profile）
_OVERRIDE_FIELDS = {
    "rate": "rate",
    "timeout": "timeout",
    "crawl_depth": "crawl_depth",
    "crawl_max_urls": "crawl_max_urls",
    "concurrent_endpoints": "concurrent_endpoints",
}


def apply_scan_config(
    config: ConfigManager, payload: Dict[str, Any], profile_manager: Optional[ProfileManager] = None
) -> Optional[str]:
    """应用 profile 与请求覆盖（profile 先、显式字段后），返回生效 profile 名。

    未知 profile / 非法数值抛 ValueError（调用方转 400）。
    """
    name = str(payload.get("profile") or "").strip()
    if name:
        manager = profile_manager or ProfileManager()
        if not manager.apply_to_config(config, name):
            raise ValueError(f"profile 不存在: {name}")
    for src, dst in _OVERRIDE_FIELDS.items():
        value = payload.get(src)
        if value is None or value == "":
            continue
        try:
            config.set(dst, int(value))
        except (TypeError, ValueError):
            raise ValueError(f"参数 {src} 非法: {value!r}") from None
    if payload.get("insecure"):
        config.set("verify_ssl", False)
    if payload.get("explain"):
        config.set("explain", True)
    return name or None


def resolve_scan_modules(
    payload: Dict[str, Any], profile_name: Optional[str], profile_manager: Optional[ProfileManager] = None
) -> List[str]:
    """模块解析：显式 modules > profile modules.enabled > []（scanner 默认 core）。"""
    explicit = payload.get("modules") or []
    if explicit:
        return [str(m) for m in explicit]
    if profile_name:
        manager = profile_manager or ProfileManager()
        enabled, _disabled = manager.get_profile_modules(profile_name)
        if enabled:
            return [str(m) for m in enabled]
    return []


def module_catalog() -> List[Dict[str, Any]]:
    """全部注册模块目录（core 在前），供前端动态渲染。"""
    from wvs.modules import register_all_modules
    from wvs.modules.base import ModuleFactory

    register_all_modules()
    catalog: List[Dict[str, Any]] = []
    for name in ModuleFactory.list_modules():
        info = ModuleFactory.get_module_info(name)
        if not info:
            continue
        catalog.append(
            {
                "name": name,
                "description": info.description,
                "category": info.category,
                "default_enabled": info.category == "core",
            }
        )
    catalog.sort(key=lambda item: (item["category"] != "core", item["name"]))
    return catalog
