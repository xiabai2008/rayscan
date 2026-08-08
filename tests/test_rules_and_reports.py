"""Phase 3:规则管理与报告升级测试。

覆盖:
- RuleUpdater.status / init / update(非 git 降级)
- rules CLI 子命令已注册
- JSON/SARIF 报告包含 evidence_chain
- gentle 预设 profile 存在且参数合规
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from wvs.core.rule_updater import BUILTIN_RULES_DIR, RuleUpdater
from wvs.models import ScanResult, ScanTarget, Vulnerability, VulnerabilityType


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_rules_cli_registered() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "wvs", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(_project_root()),
    )
    assert "rules" in proc.stdout


def test_rules_status_command() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "wvs", "rules", "status"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(_project_root()),
    )
    assert proc.returncode == 0
    assert "nuclei" in proc.stdout


def test_rules_init_creates_dir(tmp_path) -> None:
    updater = RuleUpdater(rayscan_dir=str(tmp_path / ".rayscan"))
    created = updater.init()
    assert any("rules" in p for p in created)
    assert (tmp_path / ".rayscan" / "rules" / "README.md").exists()


def test_rules_update_non_git_graceful(tmp_path) -> None:
    """非 git 来源应优雅降级,不抛异常。"""
    updater = RuleUpdater(rayscan_dir=str(tmp_path / ".rayscan"))
    results = updater.update(sources=["nuclei", "xray"])
    assert len(results) == 2
    for r in results:
        assert r.is_git is False
        assert r.message  # 有说明信息
    # 无 .git 目录,不执行 git pull


def test_builtin_rules_dir_exists() -> None:
    assert BUILTIN_RULES_DIR.exists()
    assert (BUILTIN_RULES_DIR / "README.md").exists()


def test_gentle_profile_exists_and_compliant() -> None:
    import yaml

    gentle = _project_root() / "profiles" / "gentle.yaml"
    assert gentle.exists()
    data = yaml.safe_load(gentle.read_text(encoding="utf-8"))
    assert data["name"] == "gentle"
    assert data["params"]["rate"] <= 5  # 低速率
    assert data["params"]["crawl_depth"] <= 2  # 浅爬取
    assert data["compliance"]["exploit_enabled"] is False
    assert data["compliance"]["ssrf_metadata_block"] is True


def _make_vuln() -> Vulnerability:
    return Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        title="SQL Injection (error)",
        url="http://example.com/?id=1",
        method="GET",
        parameter="id",
        parameter_type="query",
        payload="' AND 1=1--",
        evidence="DB Error",
        module="sqli",
        evidence_chain=[
            {"kind": "signal", "detail": "SQL 错误签名命中: mysql DB"},
            {"kind": "decision", "detail": "二次验证通过"},
        ],
    )


def test_json_report_includes_evidence_chain(tmp_path) -> None:
    from wvs.reporting import JSONReporter

    result = ScanResult(target=ScanTarget(url="http://example.com/"))
    result.vulnerabilities = [_make_vuln()]
    out = tmp_path / "report.json"
    JSONReporter().generate(result, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "evidence_chain" in data["vulnerabilities"][0]
    assert data["vulnerabilities"][0]["evidence_chain"][0]["kind"] == "signal"


def test_sarif_report_includes_evidence_chain(tmp_path) -> None:
    from wvs.reporting import JSONReporter

    result = ScanResult(target=ScanTarget(url="http://example.com/"))
    result.vulnerabilities = [_make_vuln()]
    out = tmp_path / "report.sarif"
    JSONReporter().generate_sarif(result, out)
    data = json.loads(out.read_text(encoding="utf-8"))
    props = data["runs"][0]["results"][0]["properties"]
    assert "evidence_chain" in props
    assert len(props["evidence_chain"]) == 2
