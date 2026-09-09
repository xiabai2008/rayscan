"""OA 检测规则加载器（T3.3 规则外部化）。

OA 检测矩阵的单一事实源是 ``rules/oa/*.yaml`` 规则包，detector.py 只负责执行。

目录优先级（同名 OA 条目后者整体覆盖前者）:
  1. 仓库内置包  ``<repo>/rules/oa/``        — 随版本分发
  2. 用户覆盖包  ``~/.rayscan/rules/oa/``    — 用户/外部 git 仓库（``rayscan rules update``）

行为保证:
  - 两个目录都不存在/没有 YAML 时，完全回退 detector 的内置硬编码（行为与外部化前一致）；
  - 单个文件解析失败或校验不通过 → 告警并跳过该文件（不污染其他 OA）；
  - 检查项校验失败（缺 path/type/severity、未知字段笔误）→ 丢弃该检查项（宁可漏报，不降级验证语义）；
  - 新增一种 OA 只需放一个 YAML 文件，无需改代码。

YAML 每文件一个 OA，顶层键: ``name``（必填，OA 标识）、``paths``/``keywords``（URL 识别通道）、
``fingerprints``（内容指纹通道）、``checks``（检测项，含 path/method/params/param_type/type/
severity/evidence/min_version/max_version/status_codes 元数据）。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from ...models import Severity, VulnerabilityType

logger = logging.getLogger("wvs.module.oa.rules")

# ── 词表（与 detector 执行语义绑定；detector 由此 re-export） ──
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

VULN_TYPE_MAP = {
    "sqli": VulnerabilityType.SQL_INJECTION,
    "rce": VulnerabilityType.REMOTE_CODE_EXECUTION,
    "lfi": VulnerabilityType.LFI,
    "file_read": VulnerabilityType.LFI,
    "file_upload": VulnerabilityType.REMOTE_CODE_EXECUTION,
    "auth_bypass": VulnerabilityType.BROKEN_AUTH,
    "unauth": VulnerabilityType.BROKEN_AUTH,
    "info_disclosure": VulnerabilityType.INFO_DISCLOSURE,
    "info": VulnerabilityType.INFO_DISCLOSURE,
}

# 检查项字段白名单 — 未列出的键一律视为笔误（如 evidince），
# 丢弃整个检查项而不是静默忽略字段：丢字段会退化为弱验证（误报风险），丢检查项只是漏报。
_CHECK_KEYS = {
    "path",
    "method",
    "params",
    "param_type",
    "type",
    "severity",
    "evidence",
    "min_version",
    "max_version",
    "status_codes",
}
_KNOWN_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}
_KNOWN_PARAM_TYPES = {"query", "body", "json"}

# 内容指纹 match 通道（与 detector._match_content_fingerprint 的执行语义绑定）
_FINGERPRINT_MATCHES = {"html", "title", "header", "cookie"}


@dataclass
class OARulePack:
    """加载完成的 OA 规则包。"""

    rules: Dict[str, dict]  # OA 名 → {paths, keywords, checks}
    fingerprints: Dict[str, List[dict]]  # OA 名 → 内容指纹条目
    sources: Dict[str, str]  # OA 名 → 规则来源（yaml 路径或 "builtin"，审计用）


def builtin_rules_dir() -> Path:
    """仓库内置规则包目录。"""
    return Path(__file__).resolve().parents[3] / "rules" / "oa"


def user_rules_dir() -> Path:
    """用户规则包目录（可被 rules update 的 git 仓库管理）。"""
    return Path.home() / ".rayscan" / "rules" / "oa"


def default_rule_dirs() -> List[Path]:
    """默认加载顺序：内置在前，用户覆盖在后。"""
    return [builtin_rules_dir(), user_rules_dir()]


# ── 校验 ──────────────────────────────────────────────────────


def _coerce_str(value: Any) -> Optional[str]:
    """数字形字符串字段兜底（YAML 未加引号时 evidence: 54289 会解析成 int）。"""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    logger.warning("[OARules] 字段期望字符串，已自动转为 str: %r", value)
    return str(value)


def _validate_check(raw: Any, where: str) -> Optional[dict]:
    """校验单条检查项；不合法返回 None（丢弃，宁漏报）。"""
    if not isinstance(raw, dict):
        logger.warning("[OARules] %s: 检查项不是映射，已丢弃: %r", where, raw)
        return None

    unknown = set(raw) - _CHECK_KEYS
    if unknown:
        logger.warning("[OARules] %s: 未知字段 %s（笔误？），丢弃该检查项", where, sorted(unknown))
        return None

    path = raw.get("path")
    if not isinstance(path, str) or not path.startswith("/"):
        logger.warning("[OARules] %s: path 缺失或不是以 / 开头的字符串，丢弃: %r", where, path)
        return None

    vtype = raw.get("type")
    if vtype not in VULN_TYPE_MAP:
        logger.warning("[OARules] %s: 未知漏洞类型 %r（可选: %s），丢弃", where, vtype, sorted(VULN_TYPE_MAP))
        return None

    severity = raw.get("severity")
    if severity not in SEVERITY_MAP:
        logger.warning("[OARules] %s: 未知严重程度 %r（可选: %s），丢弃", where, severity, sorted(SEVERITY_MAP))
        return None

    check: dict = {"path": path, "type": vtype, "severity": severity}

    method = raw.get("method")
    if method is not None:
        method_u = str(method).upper()
        if method_u not in _KNOWN_METHODS:
            logger.warning("[OARules] %s: 未知 HTTP 方法 %r，丢弃该检查项", where, method)
            return None
        check["method"] = method_u

    param_type = raw.get("param_type")
    if param_type is not None:
        if param_type not in _KNOWN_PARAM_TYPES:
            logger.warning("[OARules] %s: 未知参数位置 %r，丢弃该检查项", where, param_type)
            return None
        check["param_type"] = param_type

    params = raw.get("params")
    if params is not None:
        if not isinstance(params, dict) or not all(isinstance(k, str) for k in params):
            logger.warning("[OARules] %s: params 必须是字符串键的映射，丢弃该检查项", where)
            return None
        check["params"] = {k: v if isinstance(v, str) else str(v) for k, v in params.items()}

    evidence = _coerce_str(raw.get("evidence"))
    if evidence:
        check["evidence"] = evidence
    min_version = _coerce_str(raw.get("min_version"))
    if min_version:
        check["min_version"] = min_version
    max_version = _coerce_str(raw.get("max_version"))
    if max_version:
        check["max_version"] = max_version

    status_codes = raw.get("status_codes")
    if status_codes is not None:
        if isinstance(status_codes, int):
            status_codes = [status_codes]
        if not isinstance(status_codes, list) or not all(isinstance(s, int) and 100 <= s < 600 for s in status_codes):
            logger.warning("[OARules] %s: status_codes 必须是合法状态码列表，丢弃该检查项", where)
            return None
        check["status_codes"] = status_codes

    return check


def _validate_fingerprint(raw: Any, where: str) -> Optional[dict]:
    """校验单条内容指纹；不合法返回 None。"""
    if not isinstance(raw, dict):
        logger.warning("[OARules] %s: 指纹条目不是映射，已丢弃: %r", where, raw)
        return None

    match = raw.get("match")
    if match not in _FINGERPRINT_MATCHES:
        logger.warning("[OARules] %s: 未知指纹通道 %r（可选: %s），丢弃", where, match, sorted(_FINGERPRINT_MATCHES))
        return None

    fp: Dict[str, Any] = {"match": match}
    if match == "header":
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            logger.warning("[OARules] %s: header 指纹缺少 name，丢弃", where)
            return None
        fp["name"] = name
        # value 为 None 表示"头存在即命中"——键必须显式存在（detector 匹配逻辑读 rule["value"]）
        value = raw.get("value")
        fp["value"] = str(value) if value is not None else None
    else:
        value = _coerce_str(raw.get("value"))
        if not value:
            logger.warning("[OARules] %s: %s 指纹缺少 value，丢弃", where, match)
            return None
        fp["value"] = value
    return fp


def _load_file(fpath: Path) -> Optional[Tuple[str, dict, Optional[List[dict]]]]:
    """解析单个规则文件 → (name, rule, fingerprints or None)。失败返回 None。"""
    try:
        data = yaml.safe_load(fpath.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        logger.warning("[OARules] 规则文件解析失败 %s: %s", fpath, e)
        return None
    if not isinstance(data, dict):
        logger.warning("[OARules] 规则文件顶层不是映射，跳过: %s", fpath)
        return None

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        logger.warning("[OARules] 规则文件缺少 name 字段，跳过: %s", fpath)
        return None
    where = f"{fpath.name} ({name.strip()})"
    name = name.strip()

    paths = data.get("paths", [])
    keywords = data.get("keywords", [])
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        logger.warning("[OARules] %s: paths 必须是字符串列表，已按空处理", where)
        paths = []
    if not isinstance(keywords, list) or not all(isinstance(k, str) for k in keywords):
        logger.warning("[OARules] %s: keywords 必须是字符串列表，已按空处理", where)
        keywords = []

    checks_raw = data.get("checks", [])
    if not isinstance(checks_raw, list):
        logger.warning("[OARules] %s: checks 必须是列表，已按空处理", where)
        checks_raw = []
    checks = [c for c in (_validate_check(raw, where) for raw in checks_raw) if c is not None]
    dropped = len(checks_raw) - len(checks)
    if dropped:
        logger.warning("[OARules] %s: %d/%d 条检查项校验失败被丢弃", where, dropped, len(checks_raw))

    fingerprints: Optional[List[dict]] = None
    if "fingerprints" in data:
        fps_raw = data.get("fingerprints") or []
        if isinstance(fps_raw, list):
            fingerprints = [f for f in (_validate_fingerprint(raw, where) for raw in fps_raw) if f is not None]
        else:
            logger.warning("[OARules] %s: fingerprints 必须是列表，已忽略", where)
            fingerprints = []

    rule = {"paths": paths, "keywords": keywords, "checks": checks}
    return name, rule, fingerprints


# ── 加载入口 ──────────────────────────────────────────────────


def load_oa_pack(
    fallback_rules: Dict[str, dict],
    fallback_fingerprints: Dict[str, List[dict]],
    directories: Optional[List[Path]] = None,
) -> OARulePack:
    """加载 OA 规则包：YAML 优先，硬编码兜底。

    合并语义：以内置硬编码为底座，YAML 定义的同名 OA 条目**整体替换**底座条目；
    仅出现在 YAML 中的新 OA 直接追加（新增 OA 不需要改代码）。
    """
    dirs = directories if directories is not None else default_rule_dirs()

    yaml_rules: Dict[str, dict] = {}
    yaml_fingerprints: Dict[str, List[dict]] = {}
    yaml_sources: Dict[str, str] = {}

    for d in dirs:
        d = Path(d)
        if not d.is_dir():
            continue
        for fpath in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml"))):
            parsed = _load_file(fpath)
            if parsed is None:
                continue
            name, rule, fingerprints = parsed
            if name in yaml_sources:
                logger.info("[OARules] OA %r 被更高优先级目录覆盖: %s", name, fpath)
            yaml_rules[name] = rule
            if fingerprints is not None:
                yaml_fingerprints[name] = fingerprints
            else:
                yaml_fingerprints.pop(name, None)  # YAML 未定义指纹 → 该 OA 不继承内置指纹
            yaml_sources[name] = str(fpath)

    if not yaml_rules:
        # YAML 包缺失 → 行为与外部化前完全一致
        logger.debug("[OARules] 未发现 YAML 规则，使用内置硬编码规则（%d 种 OA）", len(fallback_rules))
        return OARulePack(
            rules=dict(fallback_rules),
            fingerprints={k: list(v) for k, v in fallback_fingerprints.items()},
            sources={name: "builtin" for name in fallback_rules},
        )

    rules = dict(fallback_rules)
    fingerprints = {k: list(v) for k, v in fallback_fingerprints.items()}
    sources = {name: "builtin" for name in fallback_rules}

    for name, rule in yaml_rules.items():
        rules[name] = rule
        sources[name] = yaml_sources[name]
        if name in yaml_fingerprints:
            fingerprints[name] = yaml_fingerprints[name]
        else:
            fingerprints.pop(name, None)

    logger.info(
        "[OARules] 已加载 OA 规则包: %d 种（YAML %d + 内置兜底 %d）",
        len(rules),
        len(yaml_rules),
        len(rules) - len(yaml_rules),
    )
    return OARulePack(rules=rules, fingerprints=fingerprints, sources=sources)
