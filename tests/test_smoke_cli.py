"""P0 冒烟测试:CLI 命令可达性 + 版本一致性。

覆盖升级改造 Phase 0 的验收标准:
- multi 子命令已注册且 main() 可分发给 cmd_multi
- exploit 授权标志在 cmd_scan 中初始化/设置正确
- pyproject.toml 与 wvs.__init__ 版本一致
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from wvs import __version__


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_cli_help_contains_multi() -> None:
    """multi 子命令必须出现在 CLI 帮助中。"""
    proc = subprocess.run(
        [sys.executable, "-m", "wvs", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(_project_root()),
    )
    assert proc.returncode == 0, proc.stderr
    assert "multi" in proc.stdout


def test_version_consistency() -> None:
    """pyproject.toml 与 wvs.__init__ 的版本号保持一致。"""
    try:
        import tomllib
    except ImportError:  # py<3.11：tomli 兜底（dev extras 已声明）
        import tomli as tomllib

    pyproject = tomllib.loads((_project_root() / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__


def test_multi_dispatch_registered() -> None:
    """main() 中必须有 multi 分发分支。"""
    import wvs.cli as cli

    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert 'args.command == "multi"' in source
    # cmd_multi 应只定义一次（修复重复定义回归）
    assert source.count("def cmd_multi(args):") == 1


def test_exploit_flag_initialized() -> None:
    """cmd_scan 中 exploit_enabled 必须默认 False,授权后置 True。"""
    import wvs.cli as cli

    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert "exploit_enabled = False" in source
    assert "exploit_enabled = True" in source
