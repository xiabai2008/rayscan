"""
P2-T2.1 回归测试：模块加载统一（ModuleFactory 注册表为唯一事实源）。

补充 tests/test_other_detectors.py::TestModuleRegistryT2_1 未覆盖的关键路径：

1. ModuleFactory 注册机制（@register_module 装饰器 / register）能从所有 detector 收集模块。
2. scanner.load_module(name) 按名从注册表取实例 —— 验证删除原 __import__ 动态兜底后
   仍能正确加载（无 ImportError，未知模块被优雅拒绝而非崩溃）。
3. lite 模式（--all-modules / _load_all_modules）仍正常工作。
4. CLI 模块加载行为向后兼容（--modules 按名 / --all-modules / --no-modules 禁用）。
"""

import inspect

import pytest

from wvs.config import ConfigManager
from wvs.core import WAVScanner
from wvs.core.session import HTTPPool
from wvs.modules import register_all_modules
from wvs.modules.base import (
    DetectionModule,
    ModuleFactory,
    ModuleInfo,
    register_module,
)

# 核对现有注册列表：sqli/xss/cmdi/lfi/rce/ssrf/xxe/waf/api/sensitive/jspathfinder 等
EXPECTED_CORE = {"sqli", "xss"}
EXPECTED_LITE = {
    "sensitive",
    "waf",
    "cmdi",
    "lfi",
    "ssrf",
    "xxe",
    "rce",
    "api",
    "js_analysis",
    "oa",
    "webshell",
    "weakpass",
    "subdomain",
}
EXPECTED_OPTIONAL = {"jspathfinder"}
EXPECTED_ALL = EXPECTED_CORE | EXPECTED_LITE | EXPECTED_OPTIONAL


@pytest.fixture
def registered():
    """确保注册表已填充（幂等）并返回模块名列表。"""
    register_all_modules()
    return ModuleFactory.list_modules()


@pytest.fixture
def scanner():
    return WAVScanner(ConfigManager(), HTTPPool(ConfigManager()))


class TestModuleFactoryRegistry:
    def test_registry_collects_all_detectors(self, registered):
        registered_set = set(registered)
        missing = EXPECTED_ALL - registered_set
        assert not missing, f"未注册的预期模块: {missing}"

    def test_registry_contains_teamlead_checklist(self, registered):
        for name in (
            "sqli",
            "xss",
            "cmdi",
            "lfi",
            "rce",
            "ssrf",
            "xxe",
            "waf",
            "api",
            "sensitive",
            "jspathfinder",
        ):
            assert name in registered, name

    def test_register_module_decorator_registers(self):
        """@register_module 装饰器机制：定义新模块应立即可见。"""
        before = set(ModuleFactory.list_modules())

        @register_module
        class _ProbeModule(DetectionModule):
            @classmethod
            def get_info(cls):
                return ModuleInfo(name="qa_probe", description="T2.1 probe", category="optional")

            async def _scan_impl(self, target):
                return []

        try:
            assert "qa_probe" in ModuleFactory.list_modules()
            assert "qa_probe" not in before
            assert ModuleFactory.get_module_info("qa_probe").name == "qa_probe"
        finally:
            ModuleFactory._modules.pop("qa_probe", None)

    def test_register_rejects_non_module(self):
        with pytest.raises(TypeError):
            ModuleFactory.register(int)  # int 不是 DetectionModule 子类

    def test_create_returns_instances(self, registered):
        for name in sorted(EXPECTED_ALL):
            inst = ModuleFactory.create(name)
            assert isinstance(inst, DetectionModule)
            assert inst.get_info().name == name


class TestScannerLoadByRegistry:
    """验证删 __import__ 兜底后，scanner.load_module 仍按名从注册表加载（无 ImportError）。"""

    def test_load_module_by_name(self, scanner):
        for name in sorted(EXPECTED_ALL):
            assert scanner.load_module(name) is True
            assert name in scanner._modules
            assert isinstance(scanner._modules[name], DetectionModule)

    def test_load_module_unknown_returns_false(self, scanner):
        # 删除 __import__ 兜底后，未知模块应被 KeyError 捕获并返回 False（不抛 ImportError）。
        assert scanner.load_module("does_not_exist_xyz") is False
        assert "does_not_exist_xyz" not in scanner._modules

    def test_load_module_idempotent(self, scanner):
        assert scanner.load_module("sqli") is True
        assert scanner.load_module("sqli") is True
        assert scanner._loaded_module_names.count("sqli") == 1

    def test_load_module_raises_no_import_error(self, scanner):
        # 回归重点：真实模块不得抛 ImportError（原实现依赖 __import__ 动态兜底）。
        for name in sorted(EXPECTED_ALL):
            try:
                ok = scanner.load_module(name)
            except ImportError as exc:  # pragma: no cover
                pytest.fail(f"load_module('{name}') 抛 ImportError: {exc}")
            assert ok is True, name

    def test_load_module_uses_registry_not_import_fallback(self):
        # 直接断言源码级回归：load_module 必须走注册表，不再有 __import__ 动态兜底。
        src = inspect.getsource(WAVScanner.load_module)
        assert "ModuleFactory.create" in src
        assert "register_all_modules" in src
        # 原动态兜底逻辑应已删除（注释中出现 '__import__' 字样不算实际调用）。
        assert "importlib.import_module" not in src
        assert "__import__(" not in src


class TestLiteMode:
    def test_all_modules_resolves_to_core_plus_lite(self):
        scanner = WAVScanner(ConfigManager(), HTTPPool(ConfigManager()))
        scanner._load_all_modules = True
        enabled = scanner._resolve_enabled_modules()
        for name in EXPECTED_LITE:
            assert name in enabled, name
        # optional 模块从不自动加载
        assert "jspathfinder" not in enabled

    def test_scanner_loads_lite_end_to_end(self):
        # 模拟 scan() 的真实流程：先按 _load_all_modules 重新 _resolve_enabled_modules 再 load_all_modules。
        scanner = WAVScanner(ConfigManager(), HTTPPool(ConfigManager()))
        scanner._load_all_modules = True
        scanner._enabled_modules = scanner._resolve_enabled_modules()
        scanner.load_all_modules()
        for name in EXPECTED_LITE:
            assert name in scanner._modules, name
            assert isinstance(scanner._modules[name], DetectionModule)


class TestCLIBackwardCompat:
    """CLI 模块加载行为向后兼容（对应 wvs/cli.py 的 --modules / --all-modules / --no-modules）。"""

    def test_modules_arg_loads_by_names(self, scanner):
        # 对应 CLI: --modules sqli,xss,cmdi
        for m in ["sqli", "xss", "cmdi"]:
            scanner.load_module(m)
        assert set(scanner._modules.keys()) == {"sqli", "xss", "cmdi"}

    def test_disabled_modules_filter(self, scanner):
        # 对应 CLI: --all-modules 后再 --no-modules cmdi,waf（从已加载集合中剔除）。
        scanner._load_all_modules = True
        scanner._enabled_modules = scanner._resolve_enabled_modules()
        scanner.load_all_modules()

        disable_set = {"cmdi", "waf"}
        for mod_name in list(scanner._modules.keys()):
            if mod_name in disable_set:
                del scanner._modules[mod_name]

        assert "cmdi" not in scanner._modules
        assert "waf" not in scanner._modules
        assert "sqli" in scanner._modules

    def test_profile_modules_load_by_name(self, scanner):
        # 对应 CLI: profile 指定模块时按名加载（不再依赖路径解析）。
        for mod in ["ssrf", "xxe"]:
            scanner.load_module(mod)
        assert {"ssrf", "xxe"} <= set(scanner._modules.keys())
