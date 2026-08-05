"""S2 回归测试 — nuclei 接入主流程 + checkpoint/--resume 复活 (2026-08-05)."""

import asyncio
from types import SimpleNamespace

from wvs.config import ConfigManager
from wvs.core.scanner import WAVScanner
from wvs.models import ScanTarget, Severity, Vulnerability, VulnerabilityType


def _bare_scanner() -> WAVScanner:
    """构造不触发完整初始化的 scanner（绕过 __init__ 的 HTTPPool 等）"""
    scanner = WAVScanner.__new__(WAVScanner)
    scanner.config = ConfigManager()
    scanner._modules_done = ["sqli", "xss"]
    scanner._last_checkpoint_time = 0.0
    scanner._checkpoint_interval = 30.0
    scanner.session = SimpleNamespace(get_stats=lambda: {"total_requests": 42})
    return scanner


# =====================================================================
# Checkpoint 保存/加载往返
# =====================================================================


class TestCheckpointRoundtrip:
    def test_save_load_roundtrip(self, tmp_path, monkeypatch):
        scanner = _bare_scanner()
        monkeypatch.setattr(scanner, "_checkpoint_file", lambda url: tmp_path / "cp.json")

        v = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            url="http://example.com/?id=1",
            severity=Severity.HIGH,
            title="t",
            description="d",
            parameter="id",
        )
        scanner._save_checkpoint("http://example.com", [v], [])

        data = scanner.load_checkpoint("http://example.com")
        assert data is not None
        assert data["target"] == "http://example.com"
        assert data["modules_done"] == ["sqli", "xss"]
        assert data["requests_made"] == 42
        assert len(data["vulnerabilities"]) == 1

    def test_try_save_interval_control(self, tmp_path, monkeypatch):
        """首次（从未保存）立即落盘；间隔内不重复写；间隔到点写盘"""
        scanner = _bare_scanner()
        monkeypatch.setattr(scanner, "_checkpoint_file", lambda url: tmp_path / "cp.json")

        # 首次保存：last_checkpoint_time=0 → 立即落盘
        scanner._try_save_checkpoint(ScanTarget(url="http://example.com"), [], [])
        assert (tmp_path / "cp.json").exists()

        # 间隔内（interval=1000s，刚保存过）→ 不重复写
        cp = tmp_path / "cp.json"
        cp.unlink()
        scanner._checkpoint_interval = 1000.0
        scanner._try_save_checkpoint(ScanTarget(url="http://example.com"), [], [])
        assert not cp.exists()

        # 间隔到点（interval=0 恒触发）→ 写盘
        scanner._last_checkpoint_time = 0.0
        scanner._checkpoint_interval = 0.0
        scanner._try_save_checkpoint(ScanTarget(url="http://example.com"), [], [])
        assert cp.exists()

    def test_vuln_serialization_roundtrip(self):
        """resume 反序列化所需：Vulnerability to_dict/from_dict 往返"""
        v = Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            url="http://example.com/?id=1",
            severity=Severity.HIGH,
            title="t",
            description="d",
            parameter="id",
            payload="1' AND 1=1--",
        )
        restored = Vulnerability.from_dict(v.to_dict())
        assert restored.type == v.type
        assert restored.url == v.url
        assert restored.severity == v.severity
        assert restored.parameter == v.parameter
        assert restored.payload == v.payload

    def test_resume_checkpoint_fields(self, tmp_path, monkeypatch):
        """checkpoint 载荷结构完整：含 modules_done 与 vulnerabilities（cli 展示依赖）"""
        scanner = _bare_scanner()
        monkeypatch.setattr(scanner, "_checkpoint_file", lambda url: tmp_path / "cp.json")
        scanner._save_checkpoint("http://example.com", [], [])
        data = scanner.load_checkpoint("http://example.com")
        assert isinstance(data.get("modules_done", None), list)
        assert isinstance(data.get("vulnerabilities", None), list)


# =====================================================================
# Nuclei 接入主流程
# =====================================================================


class TestNucleiIntegration:
    def test_run_nuclei_lazy_instantiate_and_call(self, monkeypatch):
        """_run_nuclei 懒实例化集成并调用 scan()（CLI 可用路径）"""
        import wvs.integrations.nuclei_integration as ni_mod

        calls = []

        class FakeNuclei:
            def __init__(self, *a, **kw):
                calls.append("init")
                self.is_available = True

            async def scan(self, url, cookies=None, severities=None):
                calls.append("scan")
                return []

        monkeypatch.setattr(ni_mod, "NucleiIntegration", FakeNuclei)

        scanner = _bare_scanner()
        scanner._nuclei_integration = None
        target = ScanTarget(url="http://example.com")
        asyncio.run(scanner._run_nuclei(target))

        assert calls == ["init", "scan"]

    def test_run_nuclei_reuses_instance(self, monkeypatch):
        """第二次调用复用已实例化的集成（懒加载单例）"""
        import wvs.integrations.nuclei_integration as ni_mod

        calls = []

        class FakeNuclei:
            def __init__(self, *a, **kw):
                calls.append("init")
                self.is_available = True

            async def scan(self, url, cookies=None, severities=None):
                calls.append("scan")
                return []

        monkeypatch.setattr(ni_mod, "NucleiIntegration", FakeNuclei)

        scanner = _bare_scanner()
        scanner._nuclei_integration = None
        target = ScanTarget(url="http://example.com")
        asyncio.run(scanner._run_nuclei(target))
        asyncio.run(scanner._run_nuclei(target))

        assert calls == ["init", "scan", "scan"]

    def test_nuclei_enabled_default_and_override(self):
        """config nuclei.enabled 默认开；--no-nuclei 可关闭（cli 接线）"""
        cfg = ConfigManager()
        assert cfg.get("nuclei.enabled", True) is True
        cfg.set("nuclei.enabled", False)
        assert cfg.get("nuclei.enabled", True) is False

    def test_scanner_init_nuclei_fields(self):
        """WAVScanner 完整初始化包含 S2 字段（防 AttributeError 回归）"""
        from wvs.core.scanner import WAVScanner
        from wvs.core.session import HTTPPool

        cfg = ConfigManager()
        scanner = WAVScanner(cfg, HTTPPool(cfg))
        assert scanner._modules_done == []
        assert scanner._last_checkpoint_time == 0.0
        assert scanner._resume_checkpoint is None
        assert scanner._nuclei_integration is None
