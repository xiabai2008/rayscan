"""证据包导出 (v2.3 T3.2: 从"扫出漏洞"到"交付报告")。

`rayscan report --pack <report.json>` 把一次扫描的 JSON 报告展开为
可直接提交(SRC/渗透报告)的证据包目录:

    <outdir>/
    ├── README.md          # 概览 + 漏洞索引 + 重放说明
    ├── report.json        # 原始报告副本(单一事实源)
    ├── report.sarif       # SARIF 2.1.0(全量,GitHub Code Scanning 兼容)
    ├── manifest.json      # 机器可读索引
    └── vulns/
        └── 001-sql_injection-<id8>/
            ├── finding.md     # 漏洞详情(含 --explain 证据链)
            ├── replay.sh      # 可复现 curl 重放命令
            └── evidence.json  # 结构化证据(重建请求 + 证据链)

curl 命令由漏洞记录的 method/参数类型/载荷重建:
- query 参数  → curl -G --data-urlencode(与 httpx 同为发送前编码,服务端解码后一致)
- form body   → --data-urlencode
- json body   → -H 'Content-Type: application/json' --data-raw
- cookie/header → -H
验收口径:每条漏洞的 curl 实际重放,响应中应再次出现该漏洞记录的证据特征
(依赖会话的漏洞需按 README 提示补充凭据,已在 evidence.json 标注)。
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from .. import __version__
from ..models import ScanResult, ScanTarget, Severity, Vulnerability
from .json_reporter import JSONReporter

PACK_SCHEMA = "rayscan-evidence-pack-v1"


def _write_text(path: Path, text: str) -> None:
    """统一 LF 写入(Windows 默认会把 \\n 翻译成 \\r\n,replay.sh 的 URL 会带上 \\r 导致 curl 静默失败)。"""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def load_report_as_scan_result(data: Dict[str, Any]) -> ScanResult:
    """把报告 JSON 还原为 ScanResult(兼容 JSONReporter 与 ScanResult.to_dict 两种落盘格式)。"""
    vulns_raw = data.get("vulnerabilities") or []
    vulnerabilities = [Vulnerability.from_dict(v) for v in vulns_raw if isinstance(v, dict)]
    target_raw = data.get("target") or {}
    if isinstance(target_raw, dict) and target_raw.get("url"):
        try:
            target = ScanTarget(**{k: v for k, v in target_raw.items() if k in ScanTarget.__dataclass_fields__})
        except TypeError:
            target = ScanTarget(url=str(target_raw.get("url")))
    else:
        target = ScanTarget(url=str(data.get("scan_info", {}).get("url") or ""))
    return ScanResult(target=target, vulnerabilities=vulnerabilities)


def shell_quote(value: str) -> str:
    """POSIX 单引号安全引用(Windows 上由 Git Bash/WSL 执行 replay.sh)。"""
    return "'" + str(value).replace("'", "'\\''") + "'"


def build_curl_command(vuln: Vulnerability) -> str:
    """由漏洞记录重建可复现 curl 命令(含 method/headers/params/payload)。

    query 参数在 Python 侧百分号编码后内嵌 URL(与 httpx 发送前编码一致,
    服务端解码结果相同),避免 curl -G 改写请求方法。
    """
    method = (getattr(vuln, "method", None) or "GET").upper()
    url = getattr(vuln, "url", None) or "/"
    param = getattr(vuln, "parameter", None)
    ptype = (getattr(vuln, "parameter_type", None) or "query").lower()
    payload = getattr(vuln, "payload", None)

    argv = ["curl", "-sk", "--max-time", "30"]

    if payload is None or param is None:
        argv += (["-X", method] if method != "GET" else []) + [shell_quote(url)]
        return " ".join(argv)

    if ptype == "query":
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{quote(str(param), safe='')}={quote(str(payload), safe='')}"
        argv += (["-X", method] if method != "GET" else []) + [shell_quote(target)]
    elif ptype in ("body", "form"):
        argv += (["-X", method] if method != "GET" else []) + [
            shell_quote(url),
            "--data-urlencode",
            shell_quote(f"{param}={payload}"),
        ]
    elif ptype == "json":
        body = json.dumps({param: payload}, ensure_ascii=False)
        argv += (["-X", method] if method != "GET" else []) + [
            shell_quote(url),
            "-H",
            shell_quote("Content-Type: application/json"),
            "--data-raw",
            shell_quote(body),
        ]
    elif ptype == "cookie":
        argv += (["-X", method] if method != "GET" else []) + [
            shell_quote(url),
            "-H",
            shell_quote(f"Cookie: {param}={payload}"),
        ]
    elif ptype == "header":
        argv += (["-X", method] if method != "GET" else []) + [
            shell_quote(url),
            "-H",
            shell_quote(f"{param}: {payload}"),
        ]
    else:
        # 未知参数类型:退化为 query 注入(最常见形态)
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{quote(str(param), safe='')}={quote(str(payload), safe='')}"
        argv += (["-X", method] if method != "GET" else []) + [shell_quote(target)]

    return " ".join(argv)


def build_finding_markdown(vuln: Vulnerability, curl_cmd: str, extra_cmds: Optional[List] = None) -> str:
    """单漏洞 markdown 详情(表格 + 证据链 + 复现命令 + 修复建议)。

    extra_cmds: 差分型漏洞(布尔盲注等)的对比重放命令 [(label, cmd), ...]。
    """
    chain = getattr(vuln, "evidence_chain", None) or []
    chain_lines = []
    for i, ev in enumerate(chain, 1):
        kind = ev.get("kind", "") if isinstance(ev, dict) else ""
        detail = str(ev.get("detail", "")) if isinstance(ev, dict) else str(ev)
        chain_lines.append(f"{i}. **{kind}**: {detail}")
    chain_block = "\n".join(chain_lines) if chain_lines else "_(未启用 --explain,无逐信号证据链;下方证据为命中特征)_"

    references = "\n".join(f"- {r}" for r in (vuln.references or [])) or "_(无)_"
    payload_block = f"`{vuln.payload}`" if vuln.payload else "_(无)_"
    evidence_block = f"```text\n{vuln.evidence}\n```" if vuln.evidence else "_(无)_"

    cmd_blocks = [f"```bash\n{curl_cmd}\n```"]
    for label, cmd in extra_cmds or []:
        cmd_blocks.append(f"**{label}:**\n\n```bash\n{cmd}\n```")
    cmd_section = "\n\n".join(cmd_blocks)
    differential_note = (
        "\n> ⚠ 差分型漏洞(布尔盲注等):请**分别执行** TRUE/FALSE 两条命令并对比响应差异"
        "(差异本身即证据,单条响应无法自证)。\n"
        if extra_cmds
        else ""
    )

    return f"""# {vuln.title or vuln.type.value}

| 字段 | 值 |
|---|---|
| 严重程度 | **{vuln.severity.value.upper()}** |
| 置信度 | {vuln.confidence.value} |
| 漏洞类型 | {vuln.type.value} |
| 检测模块 | {vuln.module or "-"} |
| URL | {vuln.url} |
| 方法 | {vuln.method or "GET"} |
| 参数 | {vuln.parameter or "-"} ({vuln.parameter_type or "-"}) |
| 载荷 | {payload_block} |
| CWE | {f"CWE-{vuln.cwe_id}" if vuln.cwe_id else "-"} |

## 漏洞描述

{vuln.description or "_(无)_"}

## 危害

{vuln.impact or "_(未评估)_"}

## 证据特征

{evidence_block}

## 证据链(--explain 逐信号)

{chain_block}

## 复现

{cmd_section}
{differential_note}
> 重放说明:命令由漏洞记录的 method/参数/载荷重建(发送前编码与服务端解码一致)。
> 响应中应再次出现上方"证据特征"。若漏洞依赖登录态/CSRF,请补充对应 Cookie 或头
> (详见 evidence.json 的 session_required 提示)。

## 修复建议

{vuln.recommendation or "_(无)_"}

## 参考

{references}
"""


def split_differential_payload(payload: Optional[str]) -> Optional[Tuple[str, str]]:
    """布尔盲注检测器把 True/False 载荷对以 " / " 拼接记录在 payload 字段(sqli 惯例)。

    拆出 (true_payload, false_payload) 供差分重放;非对形态返回 None。
    """
    if not payload or " / " not in payload:
        return None
    parts = payload.split(" / ")
    if len(parts) == 2 and all(p.strip() for p in parts):
        return parts[0].strip(), parts[1].strip()
    return None


def is_differential_vuln(vuln: Vulnerability) -> bool:
    """布尔型差分漏洞(payload 记录 True/False 对 + 证据描述响应差异)。"""
    pair = split_differential_payload(getattr(vuln, "payload", None))
    if pair is None:
        return False
    text = (getattr(vuln, "evidence", "") or "").lower()
    return any(k in text for k in ("differ", "true/false", "boolean"))


def build_curl_commands(vuln: Vulnerability) -> Tuple[str, List]:
    """重建重放命令。返回 (主命令, 差分对比命令 [(label, cmd), ...])。

    差分型漏洞的主命令用 TRUE 载荷,FALSE 载荷作为对比命令一并输出。
    """
    if is_differential_vuln(vuln):
        true_payload, false_payload = split_differential_payload(vuln.payload)
        vuln_t = _clone_vuln_with_payload(vuln, true_payload)
        vuln_f = _clone_vuln_with_payload(vuln, false_payload)
        main = build_curl_command(vuln_t)
        extra = [("FALSE(对比)", build_curl_command(vuln_f))]
        return main, extra
    return build_curl_command(vuln), []


def _clone_vuln_with_payload(vuln: Vulnerability, payload: str) -> Vulnerability:
    clone = Vulnerability.from_dict(vuln.to_dict())
    clone.payload = payload
    return clone


def find_response_feature(vuln: Vulnerability, body: str) -> Optional[str]:
    """在重放响应中定位证据特征,返回命中的特征串(未命中 None)。

    匹配顺序:完整证据 → 剥离检测器注释前缀("DB Error (mysql): " 等)后的响应摘录
    → 记录载荷(反射/注入类证据由载荷回显构成)→ 载荷被服务端截断回显时的最长命中前缀。
    供验收测试与证据消费方共用。
    """
    ev = (getattr(vuln, "evidence", "") or "").strip()
    candidates: List[str] = []
    m = re.match(r"^[A-Za-z][A-Za-z /-]*?(\([^)]*\))?:\s+", ev)
    if m:
        candidates.append(ev[m.end() :])
    if ev:
        candidates.append(ev)
    payload = str(getattr(vuln, "payload", "") or "")
    if payload:
        candidates.append(payload)
    for c in candidates:
        c = c.strip()
        if len(c) >= 4 and c[:200] in body:
            return c[:200]
    if payload:
        for k in range(min(len(payload), 200), 11, -1):
            if payload[:k] in body:
                return payload[:k]
    return None


def build_evidence_json(vuln: Vulnerability) -> Dict[str, Any]:
    """结构化证据(重建请求 + 证据链),供机器消费。"""
    session_dependent_ptypes = {"cookie", "header"}
    main_cmd, extra_cmds = build_curl_commands(vuln)
    request = {
        "method": (vuln.method or "GET").upper(),
        "url": vuln.url,
        "parameter": vuln.parameter,
        "parameter_type": vuln.parameter_type,
        "payload": vuln.payload,
        "curl": main_cmd,
    }
    if extra_cmds:
        request["replay_variants"] = [{"label": label, "curl": cmd} for label, cmd in extra_cmds]
        request["differential"] = True
    return {
        "id": vuln.id,
        "type": vuln.type.value,
        "title": vuln.title,
        "severity": vuln.severity.value,
        "confidence": vuln.confidence.value,
        "module": vuln.module,
        "request": request,
        "evidence": vuln.evidence,
        "evidence_chain": getattr(vuln, "evidence_chain", None) or [],
        "context": getattr(vuln, "context", None) or {},
        "session_required": (vuln.parameter_type or "").lower() in session_dependent_ptypes,
        "tags": vuln.tags,
        "references": vuln.references,
        "timestamp": vuln.timestamp.isoformat() if vuln.timestamp else None,
    }


class EvidencePackBuilder:
    """把一份 JSON 扫描报告展开为可提交证据包目录。"""

    def __init__(self, report_path: Path, output_dir: Optional[Path] = None):
        self.report_path = Path(report_path)
        if output_dir is None:
            output_dir = self.report_path.parent / f"{self.report_path.stem}_pack"
        self.output_dir = Path(output_dir)
        self._json_reporter = JSONReporter()

    def build(self) -> Dict[str, Any]:
        """执行导出,返回 manifest(dict)。"""
        data = json.loads(self.report_path.read_text(encoding="utf-8"))
        result = load_report_as_scan_result(data)

        vulns_dir = self.output_dir / "vulns"
        vulns_dir.mkdir(parents=True, exist_ok=True)

        # 原始报告副本 + 全量 SARIF
        shutil.copy2(self.report_path, self.output_dir / "report.json")
        self._json_reporter.generate_sarif(result, self.output_dir / "report.sarif")

        manifest: Dict[str, Any] = {
            "schema": PACK_SCHEMA,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "scanner_version": __version__,
            "source_report": str(self.report_path.resolve()),
            "target": result.target.url,
            "vulnerability_count": len(result.vulnerabilities),
            "severity_count": result.severity_count,
            "vulnerabilities": [],
        }

        severity_rank = {
            s.value: i
            for i, s in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])
        }
        ordered = sorted(
            enumerate(result.vulnerabilities),
            key=lambda t: (severity_rank.get(t[1].severity.value, 99), t[0]),
        )

        for seq, (orig_idx, vuln) in enumerate(ordered, 1):
            vuln_id8 = re.sub(r"[^a-f0-9]", "", str(vuln.id))[:8] or f"{orig_idx:03d}"
            dir_name = f"{seq:03d}-{vuln.type.value}-{vuln_id8}"
            vdir = vulns_dir / dir_name
            vdir.mkdir(exist_ok=True)

            main_cmd, extra_cmds = build_curl_commands(vuln)
            _write_text(vdir / "finding.md", build_finding_markdown(vuln, main_cmd, extra_cmds))
            lines = [
                "#!/usr/bin/env bash",
                "# RayScan 证据包重放命令 — 每条漏洞可一键复现",
                "# 响应中应再次出现 finding.md 所载证据特征",
                "",
                main_cmd,
            ]
            for label, cmd in extra_cmds:
                lines += ["", f"# {label}", cmd]
            lines.append("")
            _write_text(vdir / "replay.sh", "\n".join(lines))
            evidence = build_evidence_json(vuln)
            _write_text(vdir / "evidence.json", json.dumps(evidence, indent=2, ensure_ascii=False))

            manifest["vulnerabilities"].append(
                {
                    "seq": seq,
                    "id": vuln.id,
                    "title": vuln.title,
                    "type": vuln.type.value,
                    "severity": vuln.severity.value,
                    "url": vuln.url,
                    "module": vuln.module,
                    "dir": f"vulns/{dir_name}",
                    "finding_md": f"vulns/{dir_name}/finding.md",
                    "replay_sh": f"vulns/{dir_name}/replay.sh",
                    "evidence_json": f"vulns/{dir_name}/evidence.json",
                }
            )

        manifest_path = self.output_dir / "manifest.json"
        _write_text(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False))
        _write_text(self.output_dir / "README.md", self._build_readme(manifest))
        return manifest

    @staticmethod
    def _build_readme(manifest: Dict[str, Any]) -> str:
        rows = []
        for v in manifest["vulnerabilities"]:
            rows.append(
                f"| {v['seq']:03d} | {v['severity'].upper()} | {v['type']} | {v['url']} | "
                f"[finding.md]({v['finding_md']}) / [replay.sh]({v['replay_sh']}) |"
            )
        table = "\n".join(rows) if rows else "_(本报告未发现漏洞)_"
        return f"""# RayScan 证据包

> 由 `rayscan report --pack` 生成 | 扫描器版本 {manifest["scanner_version"]} | 生成时间 {manifest["generated_at"]}
> 源报告: `{manifest["source_report"]}`

## 目标

`{manifest["target"]}`

## 漏洞索引({manifest["vulnerability_count"]} 项)

| # | 严重度 | 类型 | URL | 详情 |
|---|---|---|---|---|
{table}

## 重放说明

1. 每个漏洞目录内的 `replay.sh` 为可复现 curl 命令(含 method/headers/params/payload)。
2. 执行 `bash vulns/<目录>/replay.sh`,响应中应再次出现该漏洞 `finding.md` 记录的证据特征。
3. `session_required: true` 的漏洞(cookie/header 型参数)需补充会话凭据后重放。
4. `-k` 已默认关闭证书校验(内网/自签名场景);对外网有效证书目标可移除。

## 包内文件

- `report.json` — 原始扫描报告(单一事实源)
- `report.sarif` — SARIF 2.1.0(可导入 GitHub Code Scanning)
- `manifest.json` — 机器可读索引
- `vulns/` — 每漏洞一个目录:`finding.md` + `replay.sh` + `evidence.json`
"""
