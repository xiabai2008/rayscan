"""v2.3 T3.2 证据包导出测试。

覆盖:
- build_curl_command 各参数类型的重建形态(shell 引用安全)
- 两种报告 schema 还原(JSONReporter 落盘 / ScanResult.to_dict 部分保存)
- EvidencePackBuilder 目录结构(README/manifest/SARIF/vulns/*)
- 验收核心:真实检测器产出漏洞 → 打包 → replay.sh 的 curl **实际执行**,
  响应中再次出现该漏洞记录的证据特征(与扫描时同一响应签名)
"""

from __future__ import annotations

import asyncio
import json
import shlex
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from wvs.config import ConfigManager
from wvs.core import HTTPPool, WAVScanner
from wvs.models import ScanResult, ScanTarget, Severity, Vulnerability, VulnerabilityType
from wvs.reporting import EvidencePackBuilder, JSONReporter
from wvs.reporting.evidence_pack import (
    build_curl_command,
    find_response_feature,
    load_report_as_scan_result,
    shell_quote,
)

CURL = shutil.which("curl")
requires_curl = pytest.mark.skipif(CURL is None, reason="curl 不可用")


# ─────────────────────────────────────────────────────────────────
# mini 靶场(与 benchmark_lab 同响应形态)
# ─────────────────────────────────────────────────────────────────


class _Lab(BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静默
        pass

    def _respond(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        if parsed.path == "/sqli/error":
            v = qs.get("id", "")
            if "'" in v or "or" in v.lower():
                self._respond(
                    f"<html><body>SQLSTATE[42000]: Syntax error or access violation: 1064 "
                    f"You have an error in your SQL syntax near '{v[:40]}' at line 1</body></html>".encode()
                )
            else:
                self._respond(f"<html><body>user id={v} not found</body></html>".encode())
        elif parsed.path == "/sqli/blind":
            v = qs.get("id", "")
            if "1=1" in v or "1'='1" in v or "'a'='a" in v:
                self._respond(b"<html><body>Hello admin</body></html>")
            else:
                self._respond(b"<html><body>Hello guest</body></html>")
        elif parsed.path == "/xss/reflected":
            self._respond(f"<html><body>hello {qs.get('q', '')}</body></html>".encode())
        else:
            self._respond(b"<html><body>index</body></html>")


@pytest.fixture(scope="module")
def lab_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Lab)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _scan_lab(base: str) -> ScanResult:
    """用真实 sqli/xss 检测器扫描 mini 靶场,产出与真实管线一致的漏洞。"""
    config = ConfigManager()
    config.set("rate", 50)  # 测试提速
    config.set("explain", True)  # 产出 evidence_chain
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    scanner.load_module("sqli")
    scanner.load_module("xss")

    async def run():
        result = ScanResult(target=ScanTarget(url=base + "/"))
        for target, mod in [
            (ScanTarget(url=base + "/sqli/error", params={"id": "1"}), "sqli"),
            (ScanTarget(url=base + "/xss/reflected", params={"q": "hi"}), "xss"),
        ]:
            vulns = await scanner._modules[mod].scan(target)
            result.vulnerabilities.extend(vulns)
        await session.close()
        return result

    return asyncio.run(run())


# ─────────────────────────────────────────────────────────────────
# curl 重建
# ─────────────────────────────────────────────────────────────────


def test_shell_quote_escapes_single_quotes() -> None:
    assert shell_quote("it's") == "'it'\\''s'"
    assert shell_quote("plain") == "'plain'"


def test_curl_builder_query_param() -> None:
    v = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url="http://t/sqli/error",
        method="GET",
        parameter="id",
        parameter_type="query",
        payload="' OR '1'='1",
    )
    cmd = build_curl_command(v)
    assert cmd.startswith("curl -sk --max-time 30 ")
    assert "http://t/sqli/error?id=%27%20OR%20%271%27%3D%271" in cmd  # 百分号编码内嵌
    assert "-X" not in cmd  # GET 不带 -X


def test_curl_builder_body_and_json_and_cookie() -> None:
    v_post = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url="http://t/login",
        method="POST",
        parameter="u",
        parameter_type="body",
        payload="admin'--",
    )
    cmd = build_curl_command(v_post)
    assert "-X POST" in cmd and "--data-urlencode 'u=admin'\\''--'" in cmd  # 单引号安全转义

    v_json = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        url="http://t/api",
        method="POST",
        parameter="q",
        parameter_type="json",
        payload="' OR '1'='1",
    )
    cmd = build_curl_command(v_json)
    assert "Content-Type: application/json" in cmd and "--data-raw" in cmd and '"q"' in cmd

    v_cookie = Vulnerability(
        type=VulnerabilityType.BROKEN_ACCESS,
        url="http://t/api",
        method="GET",
        parameter="sid",
        parameter_type="cookie",
        payload="admin-session",
    )
    assert "Cookie: sid=admin-session" in build_curl_command(v_cookie)

    v_header = Vulnerability(
        type=VulnerabilityType.BROKEN_ACCESS,
        url="http://t/api",
        method="GET",
        parameter="X-Debug",
        parameter_type="header",
        payload="1",
    )
    assert "X-Debug: 1" in build_curl_command(v_header)

    # 无载荷 → 纯请求
    v_plain = Vulnerability(type=VulnerabilityType.INFO_DISCLOSURE, url="http://t/.env")
    assert build_curl_command(v_plain) == "curl -sk --max-time 30 'http://t/.env'"


# ─────────────────────────────────────────────────────────────────
# schema 还原
# ─────────────────────────────────────────────────────────────────


def test_load_report_supports_both_schemas(lab_url, tmp_path) -> None:
    result = _scan_lab(lab_url)
    # JSONReporter 落盘格式(wvs-report-v1)
    reporter = JSONReporter()
    data = reporter._build_standard(result)
    r1 = load_report_as_scan_result(data)
    assert r1.target.url == result.target.url
    assert len(r1.vulnerabilities) == len(result.vulnerabilities)

    # ScanResult.to_dict 格式(部分保存/兜底)
    r2 = load_report_as_scan_result(result.to_dict())
    assert len(r2.vulnerabilities) == len(result.vulnerabilities)
    assert r2.vulnerabilities[0].severity == result.vulnerabilities[0].severity


# ─────────────────────────────────────────────────────────────────
# 证据包目录 + curl 实际重放(验收)
# ─────────────────────────────────────────────────────────────────


@requires_curl
def test_pack_and_curl_replay_reproduces_evidence(lab_url, tmp_path) -> None:
    result = _scan_lab(lab_url)
    assert result.vulnerabilities, "mini 靶场应产出漏洞(sqli/xss)"

    report_path = tmp_path / "report.json"
    JSONReporter().generate(result, report_path)

    builder = EvidencePackBuilder(report_path, output_dir=tmp_path / "pack")
    manifest = builder.build()

    # 目录结构
    pack = tmp_path / "pack"
    assert (pack / "README.md").exists()
    assert (pack / "report.json").exists()
    assert (pack / "report.sarif").exists()
    assert (pack / "manifest.json").exists()
    sarif = json.loads((pack / "report.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == len(result.vulnerabilities)
    assert len(manifest["vulnerabilities"]) == len(result.vulnerabilities)

    # 验收:每条漏洞的 curl 实际重放,响应含同一证据特征
    replayed = 0
    for entry in manifest["vulnerabilities"]:
        vdir = pack / entry["dir"]
        assert (vdir / "finding.md").exists()
        assert (vdir / "evidence.json").exists()
        replay_sh = (vdir / "replay.sh").read_text(encoding="utf-8")
        curl_line = [ln for ln in replay_sh.splitlines() if ln.startswith("curl ")][0]
        argv = shlex.split(curl_line)
        assert argv[0] == "curl"
        proc = subprocess.run([CURL, *argv[1:]], capture_output=True, text=True, timeout=60)
        body = proc.stdout
        vuln = next(v for v in result.vulnerabilities if v.id == entry["id"])
        if find_response_feature(vuln, body) is None:
            pytest.fail(f"重放未复现证据特征: evidence={vuln.evidence[:80]!r} body={body[:200]!r}")
        replayed += 1
    assert replayed == len(result.vulnerabilities)


def _replay_cmd(curl_cmd: str) -> str:
    argv = shlex.split(curl_cmd)
    assert argv[0] == "curl"
    proc = subprocess.run([CURL, *argv[1:]], capture_output=True, text=True, timeout=60)
    return proc.stdout


@requires_curl
def test_pack_replay_differential_pair(lab_url, tmp_path) -> None:
    """布尔盲注(payload 记录 True/False 对):两条重放命令响应应有差异(差异即证据)。"""
    vuln = Vulnerability(
        type=VulnerabilityType.SQL_INJECTION,
        title="SQLI boolean-blind",
        url=f"{lab_url}/sqli/blind",
        method="GET",
        parameter="id",
        parameter_type="query",
        payload="' AND 1=1-- / ' AND 1=2--",
        evidence="Boolean condition: True/False responses differ",
        severity=Severity.HIGH,
        module="sqli",
    )
    result = ScanResult(target=ScanTarget(url=lab_url + "/"), vulnerabilities=[vuln])
    report_path = tmp_path / "report.json"
    JSONReporter().generate(result, report_path)
    manifest = EvidencePackBuilder(report_path, output_dir=tmp_path / "pack").build()

    entry = manifest["vulnerabilities"][0]
    ev = json.loads((tmp_path / "pack" / entry["evidence_json"]).read_text(encoding="utf-8"))
    assert ev["request"]["differential"] is True
    variants = ev["request"]["replay_variants"]
    assert len(variants) == 1

    true_body = _replay_cmd(ev["request"]["curl"])
    false_body = _replay_cmd(variants[0]["curl"])
    assert "Hello admin" in true_body and "Hello guest" in false_body
    assert true_body != false_body  # 差分特征复现
    replay_sh = (tmp_path / "pack" / entry["replay_sh"]).read_text(encoding="utf-8")
    assert "FALSE(对比)" in replay_sh
    assert "差分型漏洞" in (tmp_path / "pack" / entry["finding_md"]).read_text(encoding="utf-8")


@requires_curl
def test_find_response_feature_truncated_echo(lab_url) -> None:
    """服务端截断回显(如 SQL 报错页只回显载荷前 40 字符):最长前缀命中判定。"""
    vuln = Vulnerability(
        type=VulnerabilityType.XSS,
        title="XSS on error page",
        url=f"{lab_url}/sqli/error",
        method="GET",
        parameter="id",
        parameter_type="query",
        payload="<svg><style></style><img src=x onerror=alert(1)>",
        evidence="New <img onerror> tag in response",
        severity=Severity.HIGH,
    )
    body = _replay_cmd(build_curl_command(vuln))
    feature = find_response_feature(vuln, body)
    assert feature is not None
    assert feature.startswith("<svg>")  # 截断回显的最长前缀
    assert len(feature) < len(vuln.payload)  # 确为截断


def test_pack_finding_md_contains_chain_and_curl(lab_url, tmp_path) -> None:
    result = _scan_lab(lab_url)
    report_path = tmp_path / "report.json"
    JSONReporter().generate(result, report_path)
    manifest = EvidencePackBuilder(report_path, output_dir=tmp_path / "pack").build()

    entry = manifest["vulnerabilities"][0]
    md = (tmp_path / "pack" / entry["finding_md"]).read_text(encoding="utf-8")
    assert "证据链" in md and "curl -sk" in md and "修复建议" in md
    ev = json.loads((tmp_path / "pack" / entry["evidence_json"]).read_text(encoding="utf-8"))
    assert ev["request"]["curl"].startswith("curl")
    assert "evidence_chain" in ev
