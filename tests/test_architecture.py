"""Architecture gates for RayScan.

These tests encode the invariants from ADR-0002 so that drift is caught in CI
instead of during the next audit:

- the kernel (``wvs/core``) must not import optional layers;
- modules deleted as legacy stay deleted;
- the CLI does not grow without bound;
- every registered detector has valid metadata;
- ``--all-modules`` loads core + lite (not just core).

They are intentionally cheap: AST/import checks only, no network.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORE_DIR = ROOT / "wvs" / "core"

# Files removed in the v2.3.1 legacy cleanup. Re-introducing one means the
# "no feature without a caller" rule was violated again.
REMOVED_FILES = [
    "wvs/core/scheduler.py",
    "wvs/core/session_manager.py",
    "wvs/core/cache.py",
    "wvs/core/encoding_bypass.py",
    "wvs/modules/waf/bypass_payloads.py",
    "wvs/modules/lite/__init__.py",
    "wvs/integrations/msf_integration.py",
]

REMOVED_MODULES = [
    "wvs.core.scheduler",
    "wvs.core.session_manager",
    "wvs.core.cache",
    "wvs.core.encoding_bypass",
    "wvs.modules.lite",
    "wvs.integrations.msf_integration",
]

REMOVED_EXPORTS = [
    "TaskScheduler",
    "TaskPriority",
    "PrioritizedTask",
    "SessionManager",
    "SessionState",
    "ScanCache",
    "CacheManager",
    "TargetFingerprinter",
    "cache_scan",
    "get_cached_scan",
    "PoCGenerator",
    "PoC",
]

# The Nuclei adapter is the single integration the main pipeline is allowed to
# call directly. Everything else must go through an application service.
ALLOWED_CORE_INTEGRATIONS = {"integrations.nuclei_integration"}

# Optional runtimes must never be hard dependencies of the kernel.
FORBIDDEN_CORE_IMPORT_ROOTS = {"flask", "playwright", "mcp"}

# Interim budget: current CLI is ~1.7k lines. Ratchet this down (target 600)
# as command bodies move into wvs/app/. The gate exists to stop growth now.
MAX_CLI_LINES = 1800


class _ImportCollector(ast.NodeVisitor):
    """Collect ``(function_depth, level, module)`` for every import.

    Optional layers may be imported lazily inside a function (guarded by
    config/try-except); a module-level import creates a hard dependency.
    """

    def __init__(self) -> None:
        self.depth = 0
        self.imports: list[tuple[int, int, str]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append((self.depth, 0, alias.name))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.imports.append((self.depth, node.level, node.module or ""))


def _iter_imports(path: Path):
    collector = _ImportCollector()
    collector.visit(ast.parse(path.read_text(encoding="utf-8")))
    return collector.imports


@pytest.mark.parametrize("rel_path", REMOVED_FILES)
def test_legacy_file_stays_removed(rel_path: str) -> None:
    assert not (ROOT / rel_path).exists(), f"{rel_path} was reintroduced"


@pytest.mark.parametrize("module_name", REMOVED_MODULES)
def test_legacy_module_is_not_importable(module_name: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module_name)


def test_core_does_not_export_removed_legacy_symbols() -> None:
    import wvs.core as core

    for name in REMOVED_EXPORTS:
        assert not hasattr(core, name), f"wvs.core still exports {name}"


def test_core_does_not_hard_import_optional_layers() -> None:
    violations: list[str] = []
    for path in CORE_DIR.glob("*.py"):
        for depth, level, module in _iter_imports(path):
            if depth > 0 or not module:
                continue  # lazy imports are allowed (guarded by config/try-except)
            if level > 0:
                # Relative import inside wvs.core: `from ..integrations...`
                # has level=2 + module="integrations...".
                if module.startswith("integrations") and module not in ALLOWED_CORE_INTEGRATIONS:
                    violations.append(f"{path.name}: from {'.' * level}{module}")
                if module.split(".")[0] in {"web_ui", "ai", "mcp_server", "exploit"}:
                    violations.append(f"{path.name}: from {'.' * level}{module}")
            else:
                root = module.split(".")[0]
                if root in FORBIDDEN_CORE_IMPORT_ROOTS:
                    violations.append(f"{path.name}: import {module}")
                if module.startswith("wvs."):
                    tail = module[4:]
                    if tail.split(".")[0] in {"web_ui", "ai", "mcp_server", "exploit"}:
                        violations.append(f"{path.name}: import {module}")
    assert violations == [], "optional layers became hard deps of wvs/core:\n" + "\n".join(violations)


def test_cli_size_budget() -> None:
    # Count non-blank lines (the audit's baseline: 1743). Target is 600 after
    # command bodies move into wvs/app/; the interim budget stops growth.
    lines = (ROOT / "wvs" / "cli.py").read_text(encoding="utf-8").splitlines()
    line_count = sum(1 for line in lines if line.strip())
    assert line_count <= MAX_CLI_LINES, f"wvs/cli.py grew to {line_count} non-blank lines (budget {MAX_CLI_LINES})"


def test_registered_modules_have_valid_metadata() -> None:
    from wvs.modules import register_all_modules
    from wvs.modules.base import ModuleFactory

    register_all_modules()
    names = ModuleFactory.list_modules()
    assert names, "module registry is empty"
    assert len(names) == len(set(names)), "duplicate module names"
    for name in names:
        info = ModuleFactory.get_module_info(name)
        assert info is not None, f"missing ModuleInfo for {name}"
        assert info.category in {"core", "lite", "optional"}, f"{name}: bad category {info.category}"


def test_all_modules_helper_loads_core_plus_lite() -> None:
    from wvs.config import ConfigManager
    from wvs.core import HTTPPool, WAVScanner

    scanner = WAVScanner(ConfigManager(), HTTPPool(ConfigManager()))
    scanner.enable_all_modules()
    assert {"sqli", "xss"} <= set(scanner._modules)
    assert {"oa", "cmdi", "graphql", "mcp", "domxss"} <= set(scanner._modules)
