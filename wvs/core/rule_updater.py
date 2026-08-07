"""RayScan 规则更新器 (Phase 3: P3-1 规则外部化)。

支持:
- `rayscan rules status` : 查看内置/外部规则仓库状态
- `rayscan rules init`   : 初始化 ~/.rayscan/rules 目录与示例规则
- `rayscan rules update` : 对可更新的规则仓库执行 git pull 增量更新
  (nuclei-templates / xray-pocs 等,若目录是 git 仓库且配置允许)

设计:与 config/poc_sources.yaml 对齐;不强制联网,仓库不存在或非 git 时优雅降级。
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .poc_source_manager import DEFAULT_POC_CONFIG, PoCSourceManager

logger = logging.getLogger("wvs.rule_updater")

# 内置规则目录(随仓库分发,作为外部规则的兜底)
BUILTIN_RULES_DIR = Path(__file__).resolve().parents[2] / "rules"


@dataclass
class RuleUpdateResult:
    """单来源更新结果。"""

    name: str
    path: str
    is_git: bool = False
    updated: bool = False
    templates_before: int = 0
    templates_after: int = 0
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "is_git": self.is_git,
            "updated": self.updated,
            "templates_before": self.templates_before,
            "templates_after": self.templates_after,
            "message": self.message,
        }


class RuleUpdater:
    """规则仓库管理与增量更新。"""

    def __init__(self, rayscan_dir: Optional[str] = None):
        self.manager = PoCSourceManager(rayscan_dir)
        self.rayscan_dir = Path(self.manager.rayscan_dir)

    # ─────────────────────────────────────────────
    # 状态
    # ─────────────────────────────────────────────

    def status(self) -> List[dict]:
        """列出所有规则来源的状态。"""
        rows = []
        for name, cfg in DEFAULT_POC_CONFIG.items():
            source = self.manager.get_source(name)
            base = Path(source.base_path) if source and source.base_path else self.rayscan_dir / cfg["dir"]
            is_git = (base / ".git").exists()
            rows.append(
                {
                    "name": name,
                    "label": cfg["label"],
                    "enabled": bool(source and source.enabled),
                    "path": str(base),
                    "exists": base.exists(),
                    "is_git": is_git,
                    "templates": source.template_count if source else 0,
                }
            )
        return rows

    # ─────────────────────────────────────────────
    # 初始化
    # ─────────────────────────────────────────────

    def init(self) -> Dict[str, str]:
        """初始化规则目录:创建目录骨架 + 内置示例规则。"""
        created: Dict[str, str] = {}
        rules_dir = self.rayscan_dir / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        created[str(rules_dir)] = "目录已就绪"

        example = rules_dir / "README.md"
        if not example.exists():
            example.write_text(
                "# RayScan 自定义规则\n\n"
                "将自定义检测规则(如 OA 指纹、敏感路径、默认口令字典)放入本目录。\n"
                "规则采用 YAML 格式,格式见 docs/rules-format.md。\n",
                encoding="utf-8",
            )
            created[str(example)] = "示例 README 已创建"

        # 创建各来源目录骨架
        for cfg in DEFAULT_POC_CONFIG.values():
            base = self.rayscan_dir / cfg["dir"]
            base.mkdir(parents=True, exist_ok=True)
            created[str(base)] = "来源目录已就绪"

        # 内置规则目录(仓库内 rules/)
        if BUILTIN_RULES_DIR.exists():
            created[str(BUILTIN_RULES_DIR)] = "内置规则目录(仓库内)"

        return created

    # ─────────────────────────────────────────────
    # 更新
    # ─────────────────────────────────────────────

    def update(self, sources: Optional[List[str]] = None, timeout: int = 120) -> List[RuleUpdateResult]:
        """对指定(或全部)来源执行 git pull 增量更新。"""
        results: List[RuleUpdateResult] = []
        names = [n for n in (sources or DEFAULT_POC_CONFIG.keys()) if n in DEFAULT_POC_CONFIG]

        for name in names:
            cfg = DEFAULT_POC_CONFIG[name]
            base = self.rayscan_dir / cfg["dir"]
            result = RuleUpdateResult(name=name, path=str(base))

            if not base.exists():
                result.message = "目录不存在,跳过(可先用 `rayscan rules init` 初始化)"
                results.append(result)
                continue

            # 模板数统计
            ext = cfg["ext"]

            def count(base=base, ext=ext) -> int:
                return len(list(base.rglob(f"*{ext}")))

            result.templates_before = count()

            if not (base / ".git").exists():
                result.message = "非 git 仓库,无法增量更新(使用 `rules init` 或手动放置规则)"
                result.templates_after = result.templates_before
                results.append(result)
                continue

            result.is_git = True
            try:
                proc = subprocess.run(
                    ["git", "pull", "--ff-only"],
                    cwd=str(base),
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    encoding="utf-8",
                    errors="replace",
                )
                if proc.returncode == 0:
                    result.updated = True
                    result.templates_after = count()
                    result.message = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "已更新"
                else:
                    result.message = f"git pull 失败: {proc.stderr.strip()[:300]}"
                    result.templates_after = result.templates_before
            except subprocess.TimeoutExpired:
                result.message = "git pull 超时"
            except FileNotFoundError:
                result.message = "未找到 git 命令"

            results.append(result)

        return results

    # ─────────────────────────────────────────────
    # 便捷入口
    # ─────────────────────────────────────────────

    @staticmethod
    def builtin_rules_available() -> bool:
        """仓库内是否有内置规则目录。"""
        return BUILTIN_RULES_DIR.exists() and any(BUILTIN_RULES_DIR.rglob("*.yaml"))
