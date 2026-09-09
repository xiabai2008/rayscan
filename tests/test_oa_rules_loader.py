"""T3.3 OA 规则外部化测试 — rules/oa/*.yaml 加载器。

验收硬线:
- YAML 规则包与内置硬编码逐字段一致（黄金矩阵 oa_vuln/oa_fixed 20/20 不变的前提）;
- YAML 目录缺失时完全回退内置硬编码（行为不变）;
- 新增 OA 只需加 YAML 文件，不改代码。
"""

from pathlib import Path

import yaml

from wvs.modules.oa.detector import (
    BUILTIN_OA_CONTENT_FINGERPRINTS,
    BUILTIN_OA_RULES,
    OA_CONTENT_FINGERPRINTS,
    OA_RULE_SOURCES,
    OA_RULES,
)
from wvs.modules.oa.rules_loader import load_oa_pack

# ─────────────────────────────────────────────────────────────
# 内置包对齐（黄金矩阵 oa 靶标 20/20 不变的等价性保证）
# ─────────────────────────────────────────────────────────────


class TestBuiltinPackParity:
    def test_yaml_pack_matches_builtin_rules(self):
        """仓库 rules/oa/*.yaml 必须与内置硬编码逐字段一致。"""
        assert OA_RULES == BUILTIN_OA_RULES

    def test_yaml_pack_matches_builtin_fingerprints(self):
        assert OA_CONTENT_FINGERPRINTS == BUILTIN_OA_CONTENT_FINGERPRINTS

    def test_all_builtin_oas_have_yaml_source(self):
        """12 种 OA 全部由 YAML 驱动（sources 指向真实文件）。"""
        assert set(OA_RULE_SOURCES) == set(BUILTIN_OA_RULES)
        for name, source in OA_RULE_SOURCES.items():
            assert source.endswith(".yaml"), f"{name} 仍由硬编码驱动: {source}"
            assert Path(source).exists(), f"规则文件不存在: {source}"

    def test_nacos_version_filter_metadata_preserved(self):
        """黄金矩阵 oa_vuln/oa_fixed 的关键路径：Nacos 版本过滤元数据无损迁移。"""
        check = next(c for c in OA_RULES["Nacos"]["checks"] if "auth/users" in c["path"])
        assert check["evidence"] == "pageItems"
        assert check["max_version"] == "1.4.1"  # 必须是字符串（YAML 数字形标量防解析陷阱）
        assert isinstance(check["max_version"], str)


# ─────────────────────────────────────────────────────────────
# 回退与合并语义
# ─────────────────────────────────────────────────────────────


class TestFallbackAndMerge:
    def test_fallback_when_no_yaml_dirs(self, tmp_path):
        """两个规则目录都不存在 → 完全回退内置硬编码，来源标记 builtin。"""
        missing = tmp_path / "does-not-exist"
        pack = load_oa_pack(
            fallback_rules=BUILTIN_OA_RULES,
            fallback_fingerprints=BUILTIN_OA_CONTENT_FINGERPRINTS,
            directories=[missing],
        )
        assert pack.rules == BUILTIN_OA_RULES
        assert pack.fingerprints == BUILTIN_OA_CONTENT_FINGERPRINTS
        assert set(pack.sources.values()) == {"builtin"}

    def test_new_oa_added_by_yaml_only(self, tmp_path):
        """验收标准：新增 OA 只需加 YAML 文件，不改代码。"""
        new_oa = tmp_path / "rules-oa"
        new_oa.mkdir()
        (new_oa / "fresh-oa.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": "海潮-Hichao",
                    "paths": ["/hichao/"],
                    "keywords": ["hichao"],
                    "fingerprints": [{"match": "html", "value": "hichao"}],
                    "checks": [
                        {
                            "path": "/hichao/portal/file",
                            "type": "file_read",
                            "severity": "high",
                            "evidence": "<web-app",
                        }
                    ],
                },
                allow_unicode=True,
            ),
            encoding="utf-8",
        )
        pack = load_oa_pack(
            fallback_rules=BUILTIN_OA_RULES,
            fallback_fingerprints=BUILTIN_OA_CONTENT_FINGERPRINTS,
            directories=[new_oa],
        )
        assert "海潮-Hichao" in pack.rules
        assert pack.sources["海潮-Hichao"].endswith("fresh-oa.yaml")
        assert pack.fingerprints["海潮-Hichao"] == [{"match": "html", "value": "hichao"}]
        # 内置 OA 不受影响
        assert pack.rules["Nacos"] == BUILTIN_OA_RULES["Nacos"]

    def test_yaml_overrides_same_name_oa(self, tmp_path):
        """YAML 定义的内置同名 OA 条目整体替换内置条目（用户可修规则不改代码）。"""
        override_dir = tmp_path / "rules-oa"
        override_dir.mkdir()
        (override_dir / "nacos.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": "Nacos",
                    "paths": ["/nacos/"],
                    "keywords": ["nacos"],
                    "fingerprints": [{"match": "html", "value": "nacos"}],
                    "checks": [{"path": "/nacos/v1/auth/users", "type": "unauth", "severity": "critical"}],
                }
            ),
            encoding="utf-8",
        )
        pack = load_oa_pack(
            fallback_rules=BUILTIN_OA_RULES,
            fallback_fingerprints=BUILTIN_OA_CONTENT_FINGERPRINTS,
            directories=[override_dir],
        )
        assert len(pack.rules["Nacos"]["checks"]) == 1  # 整体替换，非合并
        assert pack.sources["Nacos"].endswith("nacos.yaml")

    def test_later_dir_wins_on_duplicate_name(self, tmp_path):
        d1 = tmp_path / "d1"
        d2 = tmp_path / "d2"
        d1.mkdir()
        d2.mkdir()
        for d, mark in ((d1, "first"), (d2, "second")):
            (d / "x.yaml").write_text(yaml.safe_dump({"name": "X", "keywords": [mark], "checks": []}), encoding="utf-8")
        pack = load_oa_pack(
            fallback_rules=BUILTIN_OA_RULES,
            fallback_fingerprints=BUILTIN_OA_CONTENT_FINGERPRINTS,
            directories=[d1, d2],
        )
        assert pack.rules["X"]["keywords"] == ["second"]

    def test_invalid_yaml_file_skipped(self, tmp_path):
        """单个文件损坏 → 跳过该文件，其余正常加载。"""
        d = tmp_path / "rules-oa"
        d.mkdir()
        (d / "broken.yaml").write_text("name: [unclosed", encoding="utf-8")
        (d / "good.yaml").write_text(
            yaml.safe_dump({"name": "Good", "keywords": ["good"], "checks": []}), encoding="utf-8"
        )
        pack = load_oa_pack(
            fallback_rules=BUILTIN_OA_RULES,
            fallback_fingerprints=BUILTIN_OA_CONTENT_FINGERPRINTS,
            directories=[d],
        )
        assert "Good" in pack.rules
        assert "broken" not in {p.split("/")[-1] for p in pack.sources.values()}


# ─────────────────────────────────────────────────────────────
# 检查项/指纹校验
# ─────────────────────────────────────────────────────────────


class TestValidation:
    def _load_checks(self, tmp_path, checks):
        d = tmp_path / "rules-oa"
        d.mkdir(exist_ok=True)
        (d / "t.yaml").write_text(
            yaml.safe_dump({"name": "T", "keywords": [], "checks": checks}, allow_unicode=True),
            encoding="utf-8",
        )
        pack = load_oa_pack(
            fallback_rules=BUILTIN_OA_RULES,
            fallback_fingerprints=BUILTIN_OA_CONTENT_FINGERPRINTS,
            directories=[d],
        )
        return pack.rules["T"]["checks"]

    def test_unknown_field_drops_check(self, tmp_path):
        """笔误字段（如 evidince）→ 丢弃整条检查项，不做弱化验证。"""
        checks = self._load_checks(tmp_path, [{"path": "/a", "type": "sqli", "severity": "high", "evidince": "x"}])
        assert checks == []

    def test_missing_required_fields_dropped(self, tmp_path):
        checks = self._load_checks(tmp_path, [{"type": "sqli", "severity": "high"}, {"path": "/b", "type": "sqli"}])
        assert checks == []

    def test_unknown_type_or_severity_dropped(self, tmp_path):
        checks = self._load_checks(
            tmp_path,
            [
                {"path": "/a", "type": "not_a_type", "severity": "high"},
                {"path": "/b", "type": "rce", "severity": "extreme"},
            ],
        )
        assert checks == []

    def test_numeric_evidence_coerced_to_str(self, tmp_path):
        """YAML 未加引号的数字形 evidence → 自动转 str（不炸 .lower()）。"""
        checks = self._load_checks(tmp_path, [{"path": "/a", "type": "rce", "severity": "critical", "evidence": 54289}])
        assert checks[0]["evidence"] == "54289"
        assert isinstance(checks[0]["evidence"], str)

    def test_valid_check_fields_roundtrip(self, tmp_path):
        checks = self._load_checks(
            tmp_path,
            [
                {
                    "path": "/up",
                    "method": "POST",
                    "param_type": "body",
                    "params": {"uid": "1"},
                    "type": "file_upload",
                    "severity": "high",
                    "evidence": '"code":"08441',
                    "status_codes": [500],
                    "min_version": "11",
                    "max_version": "11.5.200417",
                }
            ],
        )
        assert len(checks) == 1
        c = checks[0]
        assert c["method"] == "POST" and c["param_type"] == "body"
        assert c["params"] == {"uid": "1"}
        assert c["status_codes"] == [500]
        assert c["max_version"] == "11.5.200417"

    def test_header_fingerprint_value_none_preserved(self, tmp_path):
        """Jenkins 型 header 指纹：value: null 必须显式保留（匹配逻辑读 rule["value"]）。"""
        d = tmp_path / "rules-oa"
        d.mkdir()
        (d / "h.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": "H",
                    "keywords": [],
                    "checks": [],
                    "fingerprints": [{"match": "header", "name": "x-h", "value": None}],
                }
            ),
            encoding="utf-8",
        )
        pack = load_oa_pack(
            fallback_rules=BUILTIN_OA_RULES,
            fallback_fingerprints=BUILTIN_OA_CONTENT_FINGERPRINTS,
            directories=[d],
        )
        assert pack.fingerprints["H"] == [{"match": "header", "name": "x-h", "value": None}]

    def test_invalid_fingerprint_entries_dropped(self, tmp_path):
        d = tmp_path / "rules-oa"
        d.mkdir()
        (d / "h.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": "H",
                    "keywords": [],
                    "checks": [],
                    "fingerprints": [
                        {"match": "telepathy", "value": "x"},  # 未知通道
                        {"match": "header", "value": "y"},  # header 缺 name
                        {"match": "html", "value": "ok"},  # 合法
                    ],
                }
            ),
            encoding="utf-8",
        )
        pack = load_oa_pack(
            fallback_rules=BUILTIN_OA_RULES,
            fallback_fingerprints=BUILTIN_OA_CONTENT_FINGERPRINTS,
            directories=[d],
        )
        assert pack.fingerprints["H"] == [{"match": "html", "value": "ok"}]
