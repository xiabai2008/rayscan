"""v2.3 T3.5 Web UI 对齐 CLI 测试。

覆盖:
- payloads: profile 应用与显式覆盖优先级、模块解析、模块目录
- ScanSession: explain/认证透传、from_proxy 定向扫描、历史回调
- PassiveProxySession: start/status/stop 状态机、重复启动拒绝
- API: 鉴权/CSRF、profile 保存、扫描校验、被动参数校验、导出证据链
"""

from __future__ import annotations

import pytest

from web_ui import payloads
from wvs.config import ConfigManager
from wvs.profiles import ProfileManager


class TestPayloads:
    def test_profile_then_explicit_override(self, tmp_path):
        manager = ProfileManager(tmp_path)
        manager.save_profile("quick", {"name": "quick", "params": {"rate": 5, "crawl_depth": 1}})
        cfg = ConfigManager()
        name = payloads.apply_scan_config(cfg, {"profile": "quick", "rate": 20, "explain": True}, manager)
        assert name == "quick"
        assert cfg.get("rate") == 20  # 显式覆盖 profile
        assert cfg.get("crawl_depth") == 1  # profile 保留
        assert cfg.get("explain") is True

    def test_unknown_profile_raises(self, tmp_path):
        with pytest.raises(ValueError):
            payloads.apply_scan_config(ConfigManager(), {"profile": "nope"}, ProfileManager(tmp_path))

    def test_resolve_scan_modules_precedence(self, tmp_path):
        manager = ProfileManager(tmp_path)
        manager.save_profile("only-xss", {"name": "only-xss", "modules": {"enabled": ["xss"], "disabled": []}})
        assert payloads.resolve_scan_modules({"modules": ["sqli"]}, "only-xss", manager) == ["sqli"]
        assert payloads.resolve_scan_modules({}, "only-xss", manager) == ["xss"]
        assert payloads.resolve_scan_modules({}, None, manager) == []  # 空 = 交给 scanner 默认

    def test_module_catalog_core_and_lite(self):
        catalog = payloads.module_catalog()
        names = {m["name"] for m in catalog}
        assert {"sqli", "xss", "mcp", "graphql"} <= names
        assert len(catalog) >= 18
        assert all(isinstance(m["default_enabled"], bool) for m in catalog)
        first_lite = min((i for i, m in enumerate(catalog) if m["category"] != "core"), default=len(catalog))
        assert all(m["category"] == "core" for m in catalog[:first_lite])
