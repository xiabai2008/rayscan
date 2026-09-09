"""T3.4 Nuclei 模板策展测试 — 按 OA 指纹挑选模板，淘汰泛匹配。

验收:
- 同一 OA 靶标上策展模式模板数量下降且 tech 匹配模板不丢失（检出不丢失）;
- 模板选择结果随报告输出（可审计字段 template_selection）。
"""

import asyncio
import json
from pathlib import Path

import pytest
import yaml

from wvs.config import ConfigManager
from wvs.core.nuclei_template_manager import NucleiTemplateManager
from wvs.core.scanner import WAVScanner
from wvs.integrations.nuclei_integration import NucleiIntegration
from wvs.models import ScanResult, ScanTarget
from wvs.modules.oa.detector import oa_tech_stack_for
from wvs.reporting.json_reporter import JSONReporter

# ─────────────────────────────────────────────────────────────
# 合成模板索引
# ─────────────────────────────────────────────────────────────


def _template_yaml(tid: str, name: str, severity: str, tags: list, cve: str = None) -> str:
    info = {"name": name, "severity": severity, "tags": tags}
    if cve:
        info["classification"] = {"cve-id": [cve]}
    return yaml.safe_dump({"id": tid, "info": info, "http": [{"path": "{{BaseURL}}"}]})


def _build_manager(tmp_path: Path) -> NucleiTemplateManager:
    """3 个 nacos 模板 + 1 个 wordpress 模板 + 2 个通用 misconfig 模板。"""
    tdir = tmp_path / "templates"
    tdir.mkdir()
    templates = {
        "nacos-unauth-users.yaml": _template_yaml(
            "nacos-unauth-users", "Nacos Unauthorized User List", "critical", ["nacos", "cve"], "CVE-2021-29441"
        ),
        "nacos-configs.yaml": _template_yaml("nacos-configs", "Nacos Configs Unauth", "high", ["nacos"]),
        "nacos-derby.yaml": _template_yaml("nacos-derby", "Nacos Derby RCE", "critical", ["nacos", "rce"]),
        "wp-plugin-xss.yaml": _template_yaml(
            "wp-plugin-xss", "WordPress Plugin XSS", "critical", ["wordpress", "wp-plugin", "cve"], "CVE-2019-9999"
        ),
        "misconfig-backup.yaml": _template_yaml(
            "misconfig-backup", "Backup Archive Exposed", "high", ["misconfig", "exposure"]
        ),
        "misconfig-git.yaml": _template_yaml("misconfig-git", "Git Directory Exposed", "medium", ["misconfig"]),
    }
    for fname, content in templates.items():
        (tdir / fname).write_text(content, encoding="utf-8")
    mgr = NucleiTemplateManager(template_dirs=[str(tdir)], cache_db=str(tmp_path / "cache.db"))
    mgr.build_index(force=True)
    return mgr


@pytest.fixture()
def tm(tmp_path):
    return _build_manager(tmp_path)


# ─────────────────────────────────────────────────────────────
# 策展选择（模板管理器）
# ─────────────────────────────────────────────────────────────


class TestCuratedSelection:
    def test_curated_only_tech_templates(self, tm):
        selected = tm.get_templates_for_target(tech_stack=["nacos"], curated=True)
        ids = {Path(p).stem for p in selected}
        assert ids == {"nacos-unauth-users", "nacos-configs", "nacos-derby"}

    def test_curated_reduces_count_and_keeps_tech(self, tm):
        """验收硬线：模板数量下降且检出不丢失（tech 匹配模板全量保留）。"""
        generic = tm.get_templates_for_target(tech_stack=["nacos"], max_templates=500)
        curated = tm.get_templates_for_target(tech_stack=["nacos"], max_templates=200, curated=True)
        assert len(curated) < len(generic)
        # 检出不丢失：策展结果包含全部 tech 匹配模板（泛匹配被淘汰，tech 命中一个不少）
        generic_ids = {Path(p).stem for p in generic}
        curated_ids = {Path(p).stem for p in curated}
        assert curated_ids <= generic_ids  # 策展 ⊆ 通用
        assert all("nacos" in i for i in curated_ids)  # 无泛匹配混入

    def test_curated_no_tech_match_returns_empty(self, tm):
        assert tm.get_templates_for_target(tech_stack=["haproxy-unknown"], curated=True) == []

    def test_generic_mode_unchanged(self, tm):
        """未命中指纹（curated=False）保持通用选择：泛匹配步骤仍然生效。"""
        selected = tm.get_templates_for_target(tech_stack=["nacos"], max_templates=500)
        ids = {Path(p).stem for p in selected}
        assert "misconfig-backup" in ids  # 泛匹配补充仍在
        assert "wp-plugin-xss" in ids  # 其他 tech 的 cve 类仍在（通用模式）

    def test_audit_recorded(self, tm):
        tm.get_templates_for_target(tech_stack=["nacos"], curated=True)
        audit = tm.last_selection
        assert audit["mode"] == "curated"
        assert audit["tech_stack"] == ["nacos"]
        assert audit["selected"] == 3
        assert set(audit["templates"]) >= {"nacos-unauth-users"}
        assert audit["truncated"] is False

    def test_audit_generic_mode_marked(self, tm):
        tm.get_templates_for_target(tech_stack=None, max_templates=500)
        assert tm.last_selection["mode"] == "generic"


# ─────────────────────────────────────────────────────────────
# NucleiIntegration 透传与审计
# ─────────────────────────────────────────────────────────────


class TestNucleiIntegrationWiring:
    def test_scan_passes_tech_stack_through(self):
        integration = NucleiIntegration(use_template_manager=False)
        captured = {}

        async def fake_cli(url, cookies, headers, severities, tech_stack=None):
            captured["tech_stack"] = tech_stack
            return []

        integration._cli_scan_async = fake_cli
        integration.nuclei_exe = "nuclei"  # 走 CLI 分支
        asyncio.run(integration.scan("http://x", tech_stack=["nacos"]))
        assert captured["tech_stack"] == ["nacos"]

    def test_fallback_records_builtin_fallback_mode(self):
        integration = NucleiIntegration(use_template_manager=False)
        integration.nuclei_exe = None  # CLI 不可用
        asyncio.run(integration.scan("http://x"))
        assert integration.last_selection["mode"] == "builtin-fallback"

    def test_cli_scan_curated_records_audit(self, tmp_path):
        """策展模式的审计从 template manager 透传到 integration。"""
        integration = NucleiIntegration(use_template_manager=False)
        tm = _build_manager(tmp_path)
        integration.template_manager = tm
        integration.use_template_manager = True
        integration.nuclei_exe = None  # 不真正执行 CLI

        cmd_holder = {}

        def fake_exec(*cmd, **kwargs):
            cmd_holder["cmd"] = cmd
            raise FileNotFoundError("no nuclei in test")

        # FileNotFoundError → 走 fallback，但模板选择已先行完成并记录
        integration._spawn = fake_exec
        try:
            asyncio.run(integration._cli_scan_async("http://x", None, None, ["critical"], ["nacos"]))
        except Exception:  # noqa: BLE001
            pass
        assert integration.last_selection["mode"] == "curated"
        assert integration.last_selection["tech_stack"] == ["nacos"]


# ─────────────────────────────────────────────────────────────
# scanner 接线
# ─────────────────────────────────────────────────────────────


class TestScannerWiring:
    def _scanner_with_oa(self, oa_name):
        scanner = WAVScanner(ConfigManager())
        import types

        scanner._modules["oa"] = types.SimpleNamespace(_detected_oa=oa_name)
        return scanner

    def test_oa_tech_hints(self):
        assert self._scanner_with_oa("Nacos")._oa_tech_hints() == ["nacos"]
        # scanner Step 1.9 注入的是短名（OA_FINGERPRINTS 键）
        assert self._scanner_with_oa("泛微")._oa_tech_hints() == ["weaver"]

    def test_oa_tech_hints_no_oa_module(self):
        scanner = WAVScanner(ConfigManager())
        assert scanner._oa_tech_hints() == []

    def test_oa_tech_hints_unknown_name(self):
        assert self._scanner_with_oa("未知OA")._oa_tech_hints() == []
        assert oa_tech_stack_for(None) == []

    def test_run_nuclei_passes_oa_tech(self, monkeypatch):
        """OA 指纹命中 → _run_nuclei 给 NucleiIntegration.scan 传策展 tech_stack。"""
        captured = {}

        class FakeIntegration:
            def __init__(self, config=None, use_template_manager=True):
                self.is_available = True
                self.last_selection = {"mode": "curated", "tech_stack": ["nacos"]}

            async def scan(self, url, cookies=None, severities=None, tech_stack=None):
                captured["tech_stack"] = tech_stack
                return []

        monkeypatch.setattr("wvs.integrations.nuclei_integration.NucleiIntegration", FakeIntegration)
        scanner = self._scanner_with_oa("Nacos")
        vulns = asyncio.run(scanner._run_nuclei(ScanTarget(url="http://x")))
        assert vulns == []
        assert captured["tech_stack"] == ["nacos"]

    def test_run_nuclei_generic_when_no_oa(self, monkeypatch):
        captured = {}

        class FakeIntegration:
            def __init__(self, config=None, use_template_manager=True):
                self.is_available = True
                self.last_selection = {"mode": "generic"}

            async def scan(self, url, cookies=None, severities=None, tech_stack=None):
                captured["tech_stack"] = tech_stack
                return []

        monkeypatch.setattr("wvs.integrations.nuclei_integration.NucleiIntegration", FakeIntegration)
        scanner = WAVScanner(ConfigManager())
        asyncio.run(scanner._run_nuclei(ScanTarget(url="http://x")))
        assert captured["tech_stack"] is None  # 无指纹 → 通用选择


# ─────────────────────────────────────────────────────────────
# 报告审计字段
# ─────────────────────────────────────────────────────────────


class TestReportAuditField:
    def test_report_contains_template_selection(self, tmp_path):
        result = ScanResult(target=ScanTarget(url="http://x"))
        result.template_selection = {
            "mode": "curated",
            "tech_stack": ["nacos"],
            "selected": 3,
            "templates": ["nacos-unauth-users"],
        }
        out = tmp_path / "report.json"
        JSONReporter().generate(result, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["template_selection"]["mode"] == "curated"
        assert data["template_selection"]["tech_stack"] == ["nacos"]

    def test_report_omits_field_when_none(self, tmp_path):
        result = ScanResult(target=ScanTarget(url="http://x"))
        out = tmp_path / "report.json"
        JSONReporter().generate(result, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "template_selection" not in data

    def test_to_dict_includes_template_selection(self):
        result = ScanResult(target=ScanTarget(url="http://x"))
        result.template_selection = {"mode": "generic"}
        assert result.to_dict()["template_selection"] == {"mode": "generic"}
