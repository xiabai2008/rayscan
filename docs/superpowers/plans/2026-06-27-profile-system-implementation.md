# Profile System Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Profile system to RayScan — a preset mechanism for module switches and performance parameters.

**Architecture:** Profile = YAML file in `profiles/` directory. CLI adds `profile` subcommand for management and `use <profile>` to load profiles. Profile settings override ConfigManager defaults during scan.

**Tech Stack:** Python, YAML, argparse (existing CLI)

---

## File Structure

```
RayScan/
├── profiles/                           # NEW: Profile storage
│   ├── default.yaml                    # Built-in default profile
│   ├── src-quick.yaml                  # Built-in SRC quick scan
│   ├── pentest-full.yaml               # Built-in penetration test
│   └── sqli-only.yaml                  # Built-in SQL injection only
├── wvs/
│   ├── cli.py                          # MODIFY: add profile/use subcommands
│   ├── config.py                       # MODIFY: add from_profile() method
│   └── profiles/                       # NEW: Profile loader module
│       ├── __init__.py
│       ├── loader.py                   # ProfileManager class
│       └── builtin.py                  # Built-in profile definitions
└── tests/
    └── test_profiles/                   # NEW: Profile tests
        ├── test_loader.py
        └── test_cli.py
```

---

## Task 1: Create Profile Loader Module

**Files:**
- Create: `wvs/profiles/__init__.py`
- Create: `wvs/profiles/loader.py`
- Create: `wvs/profiles/builtin.py`
- Create: `tests/test_profiles/test_loader.py`

- [ ] **Step 1: Create builtin profile definitions**

```python
# wvs/profiles/builtin.py

BUILTIN_PROFILES = {
    "default": {
        "name": "default",
        "description": "均衡模式，全模块",
        "modules": {"enabled": [], "disabled": []},  # empty = all enabled
        "params": {
            "rate": 10,
            "threads": 5,
            "timeout": 30,
            "crawl_depth": 3,
            "crawl_max_urls": 100,
            "verify_ssl": True,
        },
    },
    "src-quick": {
        "name": "src-quick",
        "description": "SRC快瞄 — 高灵敏度，快速出结果",
        "modules": {"enabled": ["sqli", "xss", "cmdi", "lfi"], "disabled": []},
        "params": {
            "rate": 20,
            "threads": 10,
            "timeout": 15,
            "crawl_depth": 2,
            "crawl_max_urls": 50,
            "verify_ssl": False,
        },
    },
    "pentest-full": {
        "name": "pentest-full",
        "description": "渗透测试，深度爬，全模块",
        "modules": {"enabled": [], "disabled": []},
        "params": {
            "rate": 5,
            "threads": 3,
            "timeout": 45,
            "crawl_depth": 4,
            "crawl_max_urls": 500,
            "verify_ssl": False,
        },
    },
    "sqli-only": {
        "name": "sqli-only",
        "description": "只扫SQL注入",
        "modules": {"enabled": ["sqli"], "disabled": []},
        "params": {
            "rate": 20,
            "threads": 10,
            "timeout": 30,
            "crawl_depth": 2,
            "crawl_max_urls": 100,
            "verify_ssl": False,
        },
    },
}
```

- [ ] **Step 2: Create ProfileManager class**

```python
# wvs/profiles/__init__.py
from .loader import ProfileManager

__all__ = ["ProfileManager"]
```

```python
# wvs/profiles/loader.py
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

from .builtin import BUILTIN_PROFILES


class ProfileManager:
    """Manages scan profiles — loading, creating, listing, deleting."""

    def __init__(self, profiles_dir: Optional[Path] = None):
        if profiles_dir is None:
            self.profiles_dir = Path(__file__).parent.parent.parent / "profiles"
        else:
            self.profiles_dir = Path(profiles_dir)
        self.profiles_dir.mkdir(exist_ok=True)

    def list_profiles(self) -> List[Dict[str, Any]]:
        """List all available profiles (builtin + custom)."""
        profiles = []

        # Built-in profiles
        for name, data in BUILTIN_PROFILES.items():
            profiles.append({
                "name": name,
                "description": data["description"],
                "builtin": True,
                "path": None,
            })

        # Custom profiles from disk
        for path in self.profiles_dir.glob("*.yaml"):
            name = path.stem
            if name not in BUILTIN_PROFILES:
                try:
                    data = yaml.safe_load(path.read_text(encoding="utf-8"))
                    profiles.append({
                        "name": data.get("name", name),
                        "description": data.get("description", ""),
                        "builtin": False,
                        "path": str(path),
                    })
                except Exception:
                    pass

        return profiles

    def load_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Load a profile by name (builtin or custom)."""
        # Check builtin first
        if name in BUILTIN_PROFILES:
            return BUILTIN_PROFILES[name].copy()

        # Check custom profiles
        profile_path = self.profiles_dir / f"{name}.yaml"
        if profile_path.exists():
            try:
                data = yaml.safe_load(profile_path.read_text(encoding="utf-8"))
                return data
            except Exception:
                return None

        return None

    def save_profile(self, name: str, data: Dict[str, Any]) -> Path:
        """Save a custom profile to disk."""
        profile_path = self.profiles_dir / f"{name}.yaml"
        profile_path.parent.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True), encoding="utf-8")
        return profile_path

    def delete_profile(self, name: str) -> bool:
        """Delete a custom profile. Returns True if deleted, False if not found or builtin."""
        if name in BUILTIN_PROFILES:
            return False
        profile_path = self.profiles_dir / f"{name}.yaml"
        if profile_path.exists():
            profile_path.unlink()
            return True
        return False

    def apply_to_config(self, config_manager, profile_name: str) -> bool:
        """Apply a profile's settings to a ConfigManager instance."""
        profile = self.load_profile(profile_name)
        if profile is None:
            return False

        # Apply params
        params = profile.get("params", {})
        for key, value in params.items():
            config_manager.set(key, value)

        # Return True to indicate profile modules should be applied separately
        return True

    def get_profile_modules(self, profile_name: str) -> tuple:
        """Get enabled and disabled modules from a profile. Returns (enabled_list, disabled_list)."""
        profile = self.load_profile(profile_name)
        if profile is None:
            return ([], [])

        modules = profile.get("modules", {})
        enabled = modules.get("enabled", [])
        disabled = modules.get("disabled", [])
        return (enabled, disabled)
```

- [ ] **Step 3: Create test for ProfileManager**

```python
# tests/test_profiles/test_loader.py
import pytest
from pathlib import Path
from wvs.profiles import ProfileManager


def test_list_profiles():
    manager = ProfileManager()
    profiles = manager.list_profiles()
    names = [p["name"] for p in profiles]
    assert "default" in names
    assert "src-quick" in names
    assert "pentest-full" in names
    assert "sqli-only" in names


def test_load_builtin_profile():
    manager = ProfileManager()
    profile = manager.load_profile("src-quick")
    assert profile is not None
    assert profile["name"] == "src-quick"
    assert "sqli" in profile["modules"]["enabled"]


def test_load_nonexistent_profile():
    manager = ProfileManager()
    profile = manager.load_profile("nonexistent")
    assert profile is None


def test_save_and_load_custom_profile(tmp_path):
    manager = ProfileManager(profiles_dir=tmp_path)
    data = {
        "name": "test-profile",
        "description": "Test profile",
        "modules": {"enabled": ["sqli"], "disabled": []},
        "params": {"rate": 15, "threads": 5},
    }
    path = manager.save_profile("test-profile", data)
    assert path.exists()

    loaded = manager.load_profile("test-profile")
    assert loaded is not None
    assert loaded["name"] == "test-profile"
    assert loaded["params"]["rate"] == 15


def test_delete_custom_profile(tmp_path):
    manager = ProfileManager(profiles_dir=tmp_path)
    data = {"name": "to-delete", "description": "", "modules": {}, "params": {}}
    manager.save_profile("to-delete", data)

    assert manager.delete_profile("to-delete") is True
    assert manager.load_profile("to-delete") is None


def test_delete_builtin_profile():
    manager = ProfileManager()
    assert manager.delete_profile("default") is False
```

- [ ] **Step 4: Run tests to verify**

```
pytest tests/test_profiles/test_loader.py -v
```

Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add wvs/profiles/ tests/test_profiles/
git commit -m "feat: add ProfileManager for scan profile management"
```

---

## Task 2: Add profile CLI subcommand

**Files:**
- Modify: `wvs/cli.py` (add profile subparser and cmd_profile function)

- [ ] **Step 1: Add profile subparser to build_parser()**

In `build_parser()`, after the `version` parser:

```python
# profile 命令
profile_parser = sub.add_parser("profile", help="Profile 管理")
profile_sub = profile_parser.add_subparsers(dest="profile_action", required=True)

# profile list
profile_list = profile_sub.add_parser("list", help="列出所有 Profile")
profile_list.add_argument("--format", choices=["table", "json"], default="table", help="输出格式")

# profile create
profile_create = profile_sub.add_parser("create", help="创建新 Profile")
profile_create.add_argument("name", help="Profile 名称")
profile_create.add_argument("--description", default="", help="Profile 描述")
profile_create.add_argument("--modules", help="启用的模块（逗号分隔，如 sqli,xss）")
profile_create.add_argument("--disabled-modules", dest="disabled_modules", help="禁用的模块（逗号分隔）")
profile_create.add_argument("--rate", type=int, help="每秒请求数")
profile_create.add_argument("--threads", type=int, help="并发线程数")
profile_create.add_argument("--timeout", type=int, help="请求超时（秒）")
profile_create.add_argument("--crawl-depth", type=int, dest="crawl_depth", help="爬取深度")
profile_create.add_argument("--crawl-max-urls", type=int, dest="crawl_max_urls", help="最大爬取URL数")
profile_create.add_argument("--insecure", action="store_true", help="禁用 SSL 验证")

# profile delete
profile_delete = profile_sub.add_parser("delete", help="删除 Profile")
profile_delete.add_argument("name", help="Profile 名称")
profile_delete.add_argument("--force", action="store_true", help="强制删除，不确认")

# profile export
profile_export = profile_sub.add_parser("export", help="导出 Profile")
profile_export.add_argument("name", help="Profile 名称")
profile_export.add_argument("-o", "--output", required=True, help="输出目录")

# profile import
profile_import = profile_sub.add_parser("import", help="导入 Profile")
profile_import.add_argument("path", help="Profile 文件或目录路径")
```

- [ ] **Step 2: Add cmd_profile function**

```python
def cmd_profile(args):
    """Profile 管理命令"""
    from .profiles import ProfileManager

    manager = ProfileManager()

    if args.profile_action == "list":
        profiles = manager.list_profiles()
        if args.format == "table":
            table = Table(title="RayScan Profiles")
            table.add_column("名称", style="cyan")
            table.add_column("描述")
            table.add_column("类型", justify="center")
            for p in profiles:
                ptype = "[bold]内置[/bold]" if p["builtin"] else "自定义"
                table.add_row(p["name"], p["description"], ptype)
            console.print(table)
        else:
            console.print_json(data=profiles)
        return 0

    elif args.profile_action == "create":
        # Build profile data
        data = {
            "name": args.name,
            "description": args.description,
            "modules": {
                "enabled": args.modules.split(",") if args.modules else [],
                "disabled": args.disabled_modules.split(",") if args.disabled_modules else [],
            },
            "params": {},
        }

        if args.rate is not None:
            data["params"]["rate"] = args.rate
        if args.threads is not None:
            data["params"]["threads"] = args.threads
        if args.timeout is not None:
            data["params"]["timeout"] = args.timeout
        if args.crawl_depth is not None:
            data["params"]["crawl_depth"] = args.crawl_depth
        if args.crawl_max_urls is not None:
            data["params"]["crawl_max_urls"] = args.crawl_max_urls
        if args.insecure:
            data["params"]["verify_ssl"] = False

        path = manager.save_profile(args.name, data)
        console.print(f"[green]Profile 已创建: {path}[/green]")
        return 0

    elif args.profile_action == "delete":
        if args.name in ["default", "src-quick", "pentest-full", "sqli-only"]:
            console.print("[red]错误：无法删除内置 Profile[/red]")
            return 1

        if not args.force:
            confirm = console.input(f"[bold yellow]确认删除 Profile '{args.name}'？(y/N): [/bold yellow]")
            if confirm.lower() != "y":
                console.print("[yellow]已取消[/yellow]")
                return 0

        if manager.delete_profile(args.name):
            console.print(f"[green]Profile '{args.name}' 已删除[/green]")
        else:
            console.print(f"[red]Profile '{args.name}' 不存在[/red]")
        return 0

    elif args.profile_action == "export":
        profile = manager.load_profile(args.name)
        if profile is None:
            console.print(f"[red]Profile '{args.name}' 不存在[/red]")
            return 1

        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"{args.name}.yaml"
        import yaml
        output_file.write_text(yaml.dump(profile, default_flow_style=False, allow_unicode=True), encoding="utf-8")
        console.print(f"[green]Profile 已导出: {output_file}[/green]")
        return 0

    elif args.profile_action == "import":
        src_path = Path(args.path)
        if src_path.is_dir():
            # Import all YAML files in directory
            count = 0
            for yaml_file in src_path.glob("*.yaml"):
                try:
                    data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                    name = data.get("name", yaml_file.stem)
                    manager.save_profile(name, data)
                    count += 1
                except Exception as e:
                    console.print(f"[yellow]跳过 {yaml_file}: {e}[/yellow]")
            console.print(f"[green]已导入 {count} 个 Profile[/green]")
        else:
            data = yaml.safe_load(src_path.read_text(encoding="utf-8"))
            name = data.get("name", src_path.stem)
            manager.save_profile(name, data)
            console.print(f"[green]已导入 Profile: {name}[/green]")
        return 0

    return 0
```

- [ ] **Step 3: Wire up profile command in main()**

In `main()`:

```python
elif args.command == "profile":
    return cmd_profile(args)
```

- [ ] **Step 4: Test CLI**

```bash
python -m wvs profile list
python -m wvs profile list --format json
python -m wvs profile create test --modules sqli,xss --rate 15
python -m wvs profile list
python -m wvs profile delete test
```

- [ ] **Step 5: Commit**

```bash
git add wvs/cli.py
git commit -m "feat(cli): add profile management subcommands

- rayscan profile list [--format table|json]
- rayscan profile create <name> [--modules sqli,xss] [--rate 15] ...
- rayscan profile delete <name>
- rayscan profile export <name> -o <dir>
- rayscan profile import <path>"
```

---

## Task 3: Add `use` command for profile-based scanning

**Files:**
- Modify: `wvs/cli.py` (add use subparser, modify cmd_scan to accept profile)

- [ ] **Step 1: Add `use` subparser**

In `build_parser()`:

```python
# use 命令：加载 Profile 并执行扫描
use_parser = sub.add_parser("use", help="使用 Profile 扫描目标")
use_parser.add_argument("profile", help="Profile 名称")
use_parser.add_argument("-u", "--url", required=True, help="目标 URL")
use_parser.add_argument("-o", "--output", help="输出报告文件路径")
use_parser.add_argument("-f", "--format", choices=["json", "html", "markdown", "sarif", "csv"], default="json", help="报告格式")
use_parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
use_parser.add_argument("--auth", help="认证文件路径（JSON）")
use_parser.add_argument("--max-time", type=int, default=7200, help="扫描超时（秒）")
use_parser.add_argument("--insecure", action="store_true", help="禁用 SSL 证书验证")
use_parser.add_argument("--modules", nargs="+", help="额外启用的模块")
use_parser.add_argument("--no-modules", nargs="+", dest="disabled_modules", help="额外禁用的模块")
```

- [ ] **Step 2: Add cmd_use function**

```python
def cmd_use(args):
    """使用 Profile 扫描目标"""
    from .profiles import ProfileManager

    manager = ProfileManager()

    # Load profile
    profile = manager.load_profile(args.profile)
    if profile is None:
        console.print(f"[red]错误：Profile '{args.profile}' 不存在[/red]")
        console.print("[dim]使用 'rayscan profile list' 查看可用 Profile[/dim]")
        return 1

    # Initialize config from profile
    config = ConfigManager()
    manager.apply_to_config(config, args.profile)

    # Override with CLI args
    if args.verbose:
        config.set("verbose", True)
    if args.insecure:
        config.set("verify_ssl", False)
    if hasattr(args, "max_time") and args.max_time:
        config.set("max_time", args.max_time)

    # Set up scanner
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)

    # Apply profile modules
    enabled_modules, disabled_modules = manager.get_profile_modules(args.profile)

    if enabled_modules:
        # Profile specifies exact modules
        for mod in enabled_modules:
            scanner.load_module(mod)
    else:
        # Load all default modules
        scanner.load_all_modules()

    # Apply CLI module overrides
    if hasattr(args, "disabled_modules") and args.disabled_modules:
        for mod_name in list(scanner._modules.keys()):
            if mod_name in args.disabled_modules:
                del scanner._modules[mod_name]

    # Load auth if specified
    target = ScanTarget(url=args.url)
    if args.auth:
        auth_path = Path(args.auth)
        if auth_path.exists():
            try:
                import json
                auth_data = json.loads(auth_path.read_text(encoding="utf-8"))
                auth_manager = AuthManager(config)

                if "cookie" in auth_data:
                    auth_manager.configure_cookies(cookies=auth_data["cookie"])
                if "bearer" in auth_data:
                    auth_manager.configure_bearer(token=auth_data["bearer"])
                if "basic" in auth_data:
                    auth_manager.configure_basic(**auth_data["basic"])
                if "headers" in auth_data:
                    for k, v in auth_data["headers"].items():
                        target.headers[k] = v

                # Apply auth
                import httpx
                async def _do_auth():
                    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as tmp_client:
                        return await auth_manager.authenticate(tmp_client)
                asyncio.run(_do_auth())
                auth_manager.apply_to_target(target)

                # Sync cookies
                for name, value in target.cookies.items():
                    session.set_cookie(args.url, name, value)
            except Exception as e:
                console.print(f"[yellow]认证加载失败: {e}，继续扫描[/yellow]")

    # Print banner
    console.print(
        Panel.fit(
            f"[bold cyan]RayScan 1.1.0[/bold cyan] Profile: [bold]{args.profile}[/bold]\n"
            f"扫描目标: [bold]{args.url}[/bold]\n"
            f"模块: {', '.join(scanner._loaded_module_names) or '全部'}\n"
            f"速率: {config.get('rate', 10)} req/s",
            border_style="cyan",
        )
    )

    # Execute scan
    start = time.perf_counter()

    async def run_scan():
        try:
            result = await scanner.scan(target)
            return result
        finally:
            await session.close()

    try:
        result = asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]扫描被中断[/yellow]")
        return 130
    except Exception as e:
        console.print(f"\n[red]扫描异常: {e}[/red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()[:500]}[/dim]")
        return 1

    elapsed = time.perf_counter() - start

    # Display results
    display_result(result, elapsed, args)
    return 0
```

- [ ] **Step 3: Wire up use command in main()**

```python
elif args.command == "use":
    setup_logging(args.verbose)
    return cmd_use(args)
```

- [ ] **Step 4: Create built-in profile files on first run**

Add to ProfileManager.__init__ or add a method to ensure built-in profiles exist:

```python
def ensure_builtin_profiles(self):
    """Ensure built-in profile YAML files exist."""
    for name, data in BUILTIN_PROFILES.items():
        path = self.profiles_dir / f"{name}.yaml"
        if not path.exists():
            path.write_text(yaml.dump(data, default_flow_style=False, allow_unicode=True), encoding="utf-8")
```

Call this in cmd_profile list or in ProfileManager init.

- [ ] **Step 5: Test use command**

```bash
python -m wvs use src-quick -u https://example.com --insecure -v
```

- [ ] **Step 6: Commit**

```bash
git add wvs/cli.py
git commit -m "feat(cli): add 'use' command for profile-based scanning

- rayscan use <profile> -u <url> [--auth <file>] [--modules ...]
- Loads profile settings and applies to ConfigManager
- Supports JSON auth files for cookie/bearer/basic auth"
```

---

## Task 4: Write comprehensive CLI tests

**Files:**
- Modify: `tests/test_profiles/test_cli.py` (create)

- [ ] **Step 1: Test profile CLI commands**

```python
# tests/test_profiles/test_cli.py
import pytest
from click.testing import CliRunner
from wvs.cli import build_parser


def test_profile_list():
    parser = build_parser()
    args = parser.parse_args(["profile", "list"])
    assert args.profile_action == "list"


def test_profile_create():
    parser = build_parser()
    args = parser.parse_args([
        "profile", "create", "test-profile",
        "--modules", "sqli,xss",
        "--rate", "15"
    ])
    assert args.profile_action == "create"
    assert args.name == "test-profile"
    assert args.modules == "sqli,xss"
    assert args.rate == 15


def test_use_command():
    parser = build_parser()
    args = parser.parse_args([
        "use", "src-quick",
        "-u", "https://example.com",
        "--insecure"
    ])
    assert args.command == "use"
    assert args.profile == "src-quick"
    assert args.url == "https://example.com"
    assert args.insecure is True
```

- [ ] **Step 2: Run tests**

```bash
pytest tests/test_profiles/ -v
```

---

## Task 5: Create built-in profile YAML files

**Files:**
- Create: `profiles/default.yaml`
- Create: `profiles/src-quick.yaml`
- Create: `profiles/pentest-full.yaml`
- Create: `profiles/sqli-only.yaml`

- [ ] **Step 1: Create profile YAML files**

```yaml
# profiles/default.yaml
name: default
description: 均衡模式，全模块
modules:
  enabled: []
  disabled: []
params:
  rate: 10
  threads: 5
  timeout: 30
  crawl_depth: 3
  crawl_max_urls: 100
  verify_ssl: true
```

```yaml
# profiles/src-quick.yaml
name: src-quick
description: SRC快瞄 — 高灵敏度，快速出结果
modules:
  enabled:
    - sqli
    - xss
    - cmdi
    - lfi
  disabled: []
params:
  rate: 20
  threads: 10
  timeout: 15
  crawl_depth: 2
  crawl_max_urls: 50
  verify_ssl: false
```

```yaml
# profiles/pentest-full.yaml
name: pentest-full
description: 渗透测试，深度爬，全模块
modules:
  enabled: []
  disabled: []
params:
  rate: 5
  threads: 3
  timeout: 45
  crawl_depth: 4
  crawl_max_urls: 500
  verify_ssl: false
```

```yaml
# profiles/sqli-only.yaml
name: sqli-only
description: 只扫SQL注入
modules:
  enabled:
    - sqli
  disabled: []
params:
  rate: 20
  threads: 10
  timeout: 30
  crawl_depth: 2
  crawl_max_urls: 100
  verify_ssl: false
```

- [ ] **Step 2: Commit**

```bash
git add profiles/
git commit -m "feat: add built-in profile YAML files"
```

---

## Implementation Order

1. **Task 1**: Profile Loader Module (foundation)
2. **Task 2**: profile CLI subcommand (list/create/delete/export/import)
3. **Task 3**: `use` command (profile-based scanning)
4. **Task 4**: CLI tests
5. **Task 5**: Built-in profile YAML files

---

## Verification

After implementation:

```bash
# List profiles
rayscan profile list

# Create custom profile
rayscan profile create my-src --modules sqli,xss --rate 25 --insecure

# Export profile
rayscan profile export src-quick -o ./my-profiles/

# Scan with profile
rayscan use src-quick -u https://target.com --insecure -v

# Scan with profile + auth
rayscan use src-quick -u https://target.com --auth auth.json -v
```

---

## Self-Review Checklist

- [ ] Spec coverage: All Profile system requirements from design doc are implemented
- [ ] Placeholder scan: No TBD/TODO in plan steps
- [ ] Type consistency: Profile data structure is consistent across loader, CLI, and YAML files
- [ ] File paths: All paths are relative to project root
- [ ] Tests: Each component has corresponding tests
