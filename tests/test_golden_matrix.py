"""黄金矩阵配置自检:manifest schema 一致性(不起靶场)。

保证 scripts/golden_matrix.yaml 的结构有效——期望条目对应的靶标/模块必须存在,
字段类型正确。矩阵本身的 FP/FN 断言由 run_golden_matrix.py(CI 手动 job)执行。
"""

from pathlib import Path

import yaml

MANIFEST = Path(__file__).resolve().parent.parent / "scripts" / "golden_matrix.yaml"


def _load():
    return yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_version_and_targets():
    m = _load()
    assert m["version"] == 1
    assert m["targets"], "至少需要一个靶标"
    for target, cfg in m["targets"].items():
        assert isinstance(cfg["modules"], list) and cfg["modules"], target


def test_expectations_reference_existing_targets():
    """expectations 中的靶标/模块必须在 targets 中存在(防清单漂移)。"""
    m = _load()
    for target, modules in m.get("expectations", {}).items():
        assert target in m["targets"], f"expectations 引用了不存在的靶标: {target}"
        for module in modules:
            assert module in m["targets"][target]["modules"], f"expectations 引用了 {target} 下不存在的模块: {module}"


def test_expectation_fields_valid():
    m = _load()
    for target, modules in m.get("expectations", {}).items():
        for module, exp in modules.items():
            assert set(exp.keys()) <= {"must_detect", "must_not_flag"}, (target, module)
            for field in ("must_detect", "must_not_flag"):
                assert isinstance(exp.get(field, []), list), (target, module, field)
                assert all(isinstance(e, str) and e.startswith("/") for e in exp.get(field, [])), (
                    f"{target}/{module}/{field} 条目必须是 / 开头的路径子串"
                )


def test_fp_guard_endpoints_present_in_lab():
    """误报护栏端点必须在靶场中真实存在(防护栏被误删后矩阵静默失去防线)。"""
    lab_src = (Path(__file__).resolve().parent.parent / "scripts" / "benchmark_lab.py").read_text(encoding="utf-8")
    for guard in ("/api/secure-invoice", "/safe/api", "/xss/reflected"):
        assert f'"{guard}"' in lab_src, f"误报护栏端点 {guard} 不在靶场路由中"
