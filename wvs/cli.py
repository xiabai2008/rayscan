"""
RayScan CLI entry point.

Usage:
    python -m wvs scan http://target.com
    python -m wvs batch targets.txt
    python -m wvs --list-modules
"""

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Windows GBK console fix ────────────────────────────────────
# rich library crashes on Windows GBK terminals when outputting Unicode
# characters (e.g. ⚠ U+26A0). Force UTF-8 on all text streams.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: S110
        pass  # not available on older Windows or already reconfigured

logger = logging.getLogger(__name__)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import ConfigManager
from .core import HTTPPool, WAVScanner
from .models import ScanResult, ScanTarget, Severity
from .modules.base import ModuleFactory
from .plugins.auth import AuthManager
from .reporting import ConsoleReporter, HTMLReporter, MarkdownReporter

console = Console()


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ─────────────────────────────────────────────────────────────────
# 全局异常保护辅助函数
# ─────────────────────────────────────────────────────────────────


def _collect_partial_vulns(scanner) -> list:
    """从所有已加载模块收集部分发现的漏洞"""
    partial_vulns = []
    for mod_name, mod_instance in scanner._modules.items():
        if hasattr(mod_instance, "_found_vulns"):
            partial_vulns.extend(mod_instance._found_vulns)
        elif hasattr(mod_instance, "vulnerabilities"):
            partial_vulns.extend(mod_instance.vulnerabilities)
    return partial_vulns


def _save_partial_results(
    partial_vulns: list,
    target_url: str,
    max_time: int,
    session,
    scanner,
    args,
):
    """去重并保存部分扫描结果"""
    if not partial_vulns:
        return
    import json
    import re
    from datetime import datetime
    from pathlib import Path

    from .models import ScanResult, ScanTarget

    seen = set()
    unique = []
    for v in partial_vulns:
        sig = f"{v.type.value}|{v.url or ''}|{v.parameter or ''}|{v.payload or ''}".lower()
        if sig not in seen:
            seen.add(sig)
            unique.append(v)

    partial_result = ScanResult(target=ScanTarget(url=target_url))
    partial_result.vulnerabilities = unique
    partial_result.duration = max_time or 0
    partial_result.requests_made = session.get_stats().get("total_requests", 0)
    partial_result.endpoints_found = 0
    partial_result.modules_run = len(scanner._modules)

    # 兜底保存 JSON
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^\w\-.]", "_", target_url.split("//")[-1].rstrip("/"))
    reports_dir = Path("scan_reports")
    reports_dir.mkdir(exist_ok=True)
    output_file = reports_dir / f"report_{safe_name}_{timestamp}.json"
    output_file.write_text(
        json.dumps(partial_result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    from rich.console import Console

    console = Console()
    console.print(f"[green]📄 部分结果报告已保存: {output_file.resolve()}[/green]")
    console.print(f"[yellow]共 {len(unique)} 个漏洞 (去重后)[/yellow]")


# ─────────────────────────────────────────────────────────────────
# CLI 命令
# ─────────────────────────────────────────────────────────────────


def cmd_scan(args):
    """执行单目标扫描"""
    target_url = args.url

    # 初始化配置
    if args.config:
        config = ConfigManager(config_file=args.config)
    else:
        config = ConfigManager()

    # 应用 CLI 参数覆盖
    if args.threads:
        config.set("threads", args.threads)
    if args.timeout:
        config.set("timeout", args.timeout)
    if args.verbose:
        config.set("verbose", True)
    if args.rate:
        config.set("rate", args.rate)
        config.set("max_requests_per_second", args.rate)
    if args.delay:
        config.set("delay", args.delay)
    if args.rate_mode:
        config.set("rate_mode", args.rate_mode)

    # 处理 --insecure 参数（禁用 SSL 验证）
    if hasattr(args, "insecure") and args.insecure:
        config.set("verify_ssl", False)
        console.print("[yellow][!] 警告: SSL 证书验证已禁用，存在 MITM 攻击风险[/yellow]")

    session = HTTPPool(config)
    scanner = WAVScanner(config, session)

    # 设置全局扫描超时（默认 7200s = 2h）
    max_time = args.max_time if hasattr(args, "max_time") else 7200
    if max_time <= 0:
        max_time = 0  # 0 = unlimited

    # 若启用 --resume，则加载上次 checkpoint
    if hasattr(args, "resume") and args.resume:
        checkpoint = scanner.load_checkpoint(target_url)
        if checkpoint:
            console.print(
                f"[cyan][*] 从 checkpoint 恢复: {len(checkpoint.get('vulnerabilities', []))} 个已有漏洞, "
                f"{len(checkpoint.get('modules_done', []))} 个已完成模块[/cyan]"
            )

    # 初始化 OOB 管理器（如果指定了 OOB 服务器）
    oob_manager = None
    if hasattr(args, "oob_server") and args.oob_server:
        from .core.oob import OOBManager

        oob_manager = OOBManager(server_url=args.oob_server)
        console.print(f"[cyan][OOB] 使用 OOB 服务器: {args.oob_server}[/cyan]")

    # 加载指定模块
    if hasattr(args, "all_modules") and args.all_modules:
        scanner._load_all_modules = True
        scanner.load_all_modules()
        console.print(f"[cyan][*] 加载全部模块（含 lite）: {len(scanner._modules)} 个[/cyan]")
    elif args.modules:
        for mod in args.modules:
            scanner.load_module(mod)
    else:
        scanner.load_all_modules()

    # 过滤禁用的模块（--no-modules）
    if hasattr(args, "disabled_modules") and args.disabled_modules:
        disable_set = set(args.disabled_modules)
        for mod_name in list(scanner._modules.keys()):
            if mod_name in disable_set:
                del scanner._modules[mod_name]
                scanner._loaded_module_names = [m for m in scanner._loaded_module_names if m != mod_name]
                console.print(f"[yellow]  禁用模块: {mod_name}[/yellow]")
        console.print(f"[yellow]  已禁用 {len(disable_set)} 个模块: {', '.join(sorted(disable_set))}[/yellow]")

    # 为检测模块设置 OOB 管理器
    if oob_manager:
        for mod_name, mod_instance in scanner._modules.items():
            mod_instance.set_oob_manager(oob_manager)

    # 认证处理
    target = ScanTarget(url=target_url)
    auth_manager = AuthManager(config)

    if args.auth_type == "form":
        if not args.login_url:
            console.print("[red]错误：--auth-type form 需要 --login-url[/red]")
            return 1
        if not (args.username and args.password):
            console.print("[red]错误：--auth-type form 需要 --username 和 --password[/red]")
            return 1
        extra = {}
        if args.login_extra:
            for pair in args.login_extra:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    extra[k] = v
        form_kwargs = {"extra_fields": extra}
        if hasattr(args, "csrf_fields") and args.csrf_fields:
            form_kwargs["csrf_fields"] = args.csrf_fields
        if hasattr(args, "success_check") and args.success_check:
            form_kwargs["success_check"] = args.success_check
        if hasattr(args, "fail_check") and args.fail_check:
            form_kwargs["fail_check"] = args.fail_check
        auth_manager.configure_form_login(
            login_url=args.login_url,
            username=args.username,
            password=args.password,
            **form_kwargs,
        )
    elif args.auth_type == "bearer":
        if not args.token:
            console.print("[red]错误：--auth-type bearer 需要 --token[/red]")
            return 1
        auth_manager.configure_bearer(token=args.token)
    elif args.auth_type == "basic":
        if not (args.username and args.password):
            console.print("[red]错误：--auth-type basic 需要 --username 和 --password[/red]")
            return 1
        auth_manager.configure_basic(username=args.username, password=args.password)
    elif args.auth_type == "apikey":
        if not args.api_key:
            console.print("[red]错误：--auth-type apikey 需要 --api-key[/red]")
            return 1
        auth_manager.configure_api_key(key=args.api_key, header_name=args.api_key_header)
    elif args.auth_type == "cookie":
        if not args.cookies:
            console.print("[red]错误：--auth-type cookie 需要 --cookies[/red]")
            return 1
        auth_manager.configure_cookies(cookies=args.cookies)
    else:
        # 兼容旧参数
        if args.auth_type is None and args.username and args.password and args.login_url:
            auth_manager.configure_form_login(
                login_url=args.login_url,
                username=args.username,
                password=args.password,
            )

    # 执行认证
    if args.auth_type or (args.username and args.password):
        console.print(f"[cyan][AUTH] 正在执行认证 ({auth_manager.provider_name})...[/cyan]")
        import httpx

        async def _do_auth():
            async with httpx.AsyncClient(follow_redirects=True, timeout=30) as tmp_client:
                return await auth_manager.authenticate(tmp_client)

        asyncio.run(_do_auth())

        if not auth_manager.is_authenticated:
            console.print(f"[red][X] 认证失败: {auth_manager.auth_error}[/red]")
            return 1

        console.print("[green][OK] 认证成功[/green]")
        auth_manager.apply_to_target(target)

        # 关键：把 auth cookies 同步进 scanner 的 HTTPPool
        # CLI 的 auth 用的是独立 httpx client，scanner 的 HTTPPool 是另一个 client
        for name, value in target.cookies.items():
            session.set_cookie(target_url, name, value)
        console.print(f"[cyan]  已同步 {len(target.cookies)} 个 cookie 到扫描 session[/cyan]")

    # ── 利用引擎开关校验（默认禁用） ──
    if hasattr(args, "i_have_permission") and args.i_have_permission:
        if os.environ.get("RAYSCAN_ENABLE_EXPLOIT") != "1":
            console.print(
                "[red][X] --i-have-permission 已设置，但环境变量 RAYSCAN_ENABLE_EXPLOIT != 1。利用模块拒绝加载。[/red]"
            )
            return 1
        console.print(
            Panel.fit(
                "[bold yellow]⚠  LEGAL WARNING ⚠[/bold yellow]\n"
                "你已确认对目标拥有书面授权。\n"
                "本次扫描将加载 wvs.exploit 自动利用模块，\n"
                "包括 SQLMap 链式利用、反弹 Shell、SSRF 元数据外发等。\n"
                "未授权扫描属违法行为，使用者自负法律责任。",
                border_style="yellow",
            )
        )
        try:
            confirm = console.input("[bold red]请输入 YES 确认继续（任意其他输入取消）：[/bold red]")
        except (EOFError, KeyboardInterrupt):
            confirm = ""
        if confirm.strip() != "YES":
            console.print("[yellow]已取消。[/yellow]")
            return 0
        logger.warning("[EXPLOIT] 用户已确认授权 — 启用自动利用模块，目标: %s", target_url)

    # 执行扫描
    console.print(
        Panel.fit(
            f"[bold cyan]RayScan 1.1.0[/bold cyan] 扫描目标: [bold]{target_url}[/bold]\n"
            f"模块: {', '.join(scanner._loaded_module_names) or '全部'}\n"
            f"速率: {config.get('rate', 10)} req/s",
            border_style="cyan",
        )
    )

    start = time.perf_counter()

    async def run_scan():
        # 初始化 OOB 管理器
        if oob_manager:
            await oob_manager.initialize()

        try:
            # 支持全局超时
            # 保存 max_time 到 scanner（超时抢救用）
            scanner._scan_max_time = max_time
            if max_time and max_time > 0:
                result = await asyncio.wait_for(scanner.scan(target), timeout=max_time)
            else:
                result = await scanner.scan(target)
            return result
        finally:
            # 关闭 OOB 管理器
            if oob_manager:
                await oob_manager.close()

    try:
        result = asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print("\n[yellow]扫描被中断[/yellow]")
        return 130
    except asyncio.TimeoutError:
        console.print(f"\n[yellow]扫描超时（>{max_time}秒），正在保存部分结果...[/yellow]")
        partial_vulns = _collect_partial_vulns(scanner)
        _save_partial_results(partial_vulns, target_url, max_time, session, scanner, args)
        return 124
    except Exception as e:
        console.print(f"\n[red]扫描异常: {e}[/red]")
        import traceback

        console.print(f"[dim]{traceback.format_exc()[:500]}[/dim]")
        partial_vulns = _collect_partial_vulns(scanner)
        if partial_vulns:
            console.print(f"[yellow]异常前已发现 {len(partial_vulns)} 个漏洞，尝试保存...[/yellow]")
            _save_partial_results(partial_vulns, target_url, None, session, scanner, args)
        else:
            completed = getattr(scanner, "_modules_completed", [])
            if completed:
                console.print(f"[yellow]异常，{len(completed)} 个模块已完成扫描但未发现漏洞[/yellow]")
            else:
                console.print("[yellow]异常，扫描未完成任何模块[/yellow]")
        return 1

    elapsed = time.perf_counter() - start

    # 输出结果
    try:
        display_result(result, elapsed, args)
    except Exception as e:
        console.print(f"\n[red]报告生成失败: {e}[/red]")
        # 兜底：手动保存 JSON
        try:
            from datetime import datetime
            from pathlib import Path

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = re.sub(r"[^\w\-.]", "_", target_url.split("//")[-1].rstrip("/"))
            fallback_path = Path("scan_reports") / f"report_{safe_name}_{timestamp}.json"
            fallback_path.parent.mkdir(exist_ok=True)
            fallback_path.write_text(
                json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            console.print(f"[green]📄 报告已兜底保存: {fallback_path.resolve()}[/green]")
        except Exception as e2:
            console.print(f"[red]报告兜底保存也失败: {e2}[/red]")
    return 0


def cmd_batch(args):
    """批量扫描"""
    target_file = Path(args.file)
    if not target_file.exists():
        console.print(f"[red]错误：找不到目标文件 {target_file}[/red]")
        return 1

    targets = [
        line.strip()
        for line in target_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not targets:
        console.print("[yellow]警告：目标文件为空[/yellow]")
        return 1

    console.print(
        Panel.fit(
            f"[bold cyan]RayScan 1.1.0 批量扫描[/bold cyan]\n目标数量: [bold]{len(targets)}[/bold]",
            border_style="cyan",
        )
    )

    config = ConfigManager()
    session = HTTPPool(config)
    scanner = WAVScanner(config, session)
    if hasattr(args, "all_modules") and args.all_modules:
        scanner._load_all_modules = True
        scanner.load_all_modules()
        console.print(f"[cyan][*] 批量加载全部模块（含 lite）: {len(scanner._modules)} 个[/cyan]")
    else:
        scanner.load_all_modules()

    batch_size = args.threads or 3

    async def scan_one(url: str) -> tuple:
        t = ScanTarget(url=url)
        try:
            r = await scanner.scan(t)
            return url, r, None
        except Exception as e:
            return url, None, str(e)

    async def run_batch():
        semaphore = asyncio.Semaphore(batch_size)

        async def sem_scan(url):
            async with semaphore:
                return await scan_one(url)

        return await asyncio.gather(*[sem_scan(u) for u in targets])

    start = time.perf_counter()
    raw_results = asyncio.run(run_batch())
    asyncio.run(session.close())
    elapsed = time.perf_counter() - start

    # 汇总
    table = Table(title="批量扫描结果")
    table.add_column("目标", style="cyan")
    table.add_column("漏洞数", justify="right")
    table.add_column("高危", justify="right", style="red")
    table.add_column("中危", justify="right", style="yellow")
    table.add_column("低危", justify="right", style="blue")
    table.add_column("耗时", justify="right")

    for url, result, error in raw_results:
        if error:
            table.add_row(url, "[red]错误[/red]", "-", "-", "-", "-")
        elif result:
            vulns = result.vulnerabilities
            high = len([v for v in vulns if v.severity == Severity.HIGH])
            med = len([v for v in vulns if v.severity == Severity.MEDIUM])
            low = len([v for v in vulns if v.severity in (Severity.LOW, Severity.INFO)])
            table.add_row(url, str(len(vulns)), str(high), str(med), str(low), f"{result.duration:.1f}s")
        else:
            table.add_row(url, "0", "0", "0", "0", "-")

    console.print(table)
    console.print(f"\n总耗时: {elapsed:.1f}s")

    # 保存批量报告
    if args.output:
        report = []
        for url, result, error in raw_results:
            if result:
                report.append(result.to_dict())
        Path(args.output).write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[green]报告已保存: {args.output}[/green]")

    return 0


def cmd_list_modules(args):
    """列出所有检测模块"""
    # 注册所有模块
    from .modules import register_all_modules

    register_all_modules()

    modules = ModuleFactory.list_modules()
    table = Table(title="RayScan 检测模块")
    table.add_column("名称", style="cyan")
    table.add_column("描述")
    table.add_column("默认", justify="center")
    table.add_column("层级")

    core_modules = {"sqli", "xss"}
    for name in modules:
        info = ModuleFactory.get_module_info(name)
        if info:
            tier = "[bold]核心[/bold]" if name in core_modules else "lite"
            table.add_row(
                name,
                info.description,
                "[OK]" if name in core_modules else "[X]",
                tier,
            )

    console.print(table)
    console.print(f"\n共 {len(modules)} 个模块（核心: sqli+xss, lite: {len(modules) - 2} 个）")
    console.print("[dim]提示: 使用 --all-modules 加载全部 lite 模块[/dim]")
    return 0


def cmd_version(args):
    """显示版本信息"""
    console.print(
        Panel.fit(
            "[bold cyan]RayScan 1.1.0[/bold cyan]\nSQLi + XSS 专精扫描器\nby xiabai2004",
            border_style="cyan",
        )
    )
    return 0


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
            import json

            console.print(json.dumps(profiles, indent=2, ensure_ascii=False))
        return 0

    elif args.profile_action == "create":
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
        builtin = ["default", "src-quick", "pentest-full", "sqli-only"]
        if args.name in builtin:
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

        output_file.write_text(
            yaml.dump(profile, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
        console.print(f"[green]Profile 已导出: {output_file}[/green]")
        return 0

    elif args.profile_action == "import":
        src_path = Path(args.path)
        import yaml

        if src_path.is_dir():
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
    if args.max_time:
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


# ─────────────────────────────────────────────────────────────────
# 结果展示
# ─────────────────────────────────────────────────────────────────


def display_result(result: ScanResult, elapsed: float, args):
    """
    使用真实 Reporter 输出扫描结果

    未指定 --output 时自动保存到 scan_reports/ 目录。
    """
    # 确保 result.duration 和其他字段与实际耗时一致
    result.duration = elapsed

    reporter = ConsoleReporter(verbose=args.verbose)
    html_reporter = HTMLReporter()
    md_reporter = MarkdownReporter()

    # 控制台报告
    reporter.report(result)

    # 确定输出路径和格式
    if args.output:
        output_file = Path(args.output)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        fmt = args.format or (
            "html" if output_file.suffix == ".html" else "json" if output_file.suffix == ".json" else "json"
        )
    else:
        # 未指定 -o：自动生成路径
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        fmt = args.format or "json"
        reports_dir = Path("scan_reports")
        reports_dir.mkdir(exist_ok=True)
        safe_name = re.sub(r"[^\w\-.]", "_", result.target.url.split("//")[-1].rstrip("/"))
        output_file = reports_dir / f"report_{safe_name}_{timestamp}.{fmt}"

    # 保存文件报告
    if fmt == "html":
        html_reporter.generate(result, output_file)
    elif fmt == "json":
        html_reporter.generate_json(result, output_file)
    elif fmt == "markdown":
        md_reporter.generate(result, output_file)

    console.print(f"[green]📄 {fmt.upper()} 报告已保存: {output_file.resolve()}[/green]")


# ─────────────────────────────────────────────────────────────────
# 主入口
# ─────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rayscan",
        description="RayScan 1.1.0 — SQLi + XSS 专精扫描器 | 二阶注入/宽字节/OOB/Polyglot/mXSS/SSTI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # scan 命令
    scan_parser = sub.add_parser("scan", help="扫描单个目标")
    scan_parser.add_argument("url", help="目标 URL（支持 http/https）")
    scan_parser.add_argument("-o", "--output", help="输出报告文件路径")
    scan_parser.add_argument(
        "-f",
        "--format",
        choices=["json", "html", "markdown", "sarif", "csv"],
        default="json",
        help="报告格式（默认 json）",
    )
    scan_parser.add_argument("-t", "--threads", type=int, help="并发线程数")
    scan_parser.add_argument("--timeout", type=int, help="请求超时（秒）")
    scan_parser.add_argument(
        "--all-modules", action="store_true", help="加载全部模块（含 lite 辅助模块，默认只加载 sqli+xss）"
    )
    scan_parser.add_argument("--modules", nargs="+", help="指定启用的模块（如 sqli xss）")
    scan_parser.add_argument("--no-modules", nargs="+", dest="disabled_modules", help="禁用的模块")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")

    # 扫描控制选项
    control_group = scan_parser.add_argument_group("扫描控制")
    control_group.add_argument(
        "--max-time", type=int, default=7200, help="全局扫描超时（秒），默认 7200（2小时），0 表示无限制"
    )
    control_group.add_argument("--resume", action="store_true", help="从上次 checkpoint 恢复扫描")
    control_group.add_argument("--rate", type=int, default=10, help="每秒最大请求数（默认 10）")
    control_group.add_argument(
        "--rate-mode", choices=["burst", "uniform"], default="burst", help="速率限制模式：burst(突发) / uniform(均匀)"
    )
    control_group.add_argument("--delay", type=float, default=0.0, help="请求间延迟（秒）")
    control_group.add_argument("-c", "--config", type=str, help="配置文件路径（YAML/JSON）")
    control_group.add_argument("--insecure", action="store_true", help="禁用 SSL 证书验证（不推荐，存在安全风险）")

    # 利用引擎选项（默认关闭）
    exploit_group = scan_parser.add_argument_group("利用引擎（默认禁用）")
    exploit_group.add_argument(
        "--i-have-permission",
        action="store_true",
        dest="i_have_permission",
        help=(
            "确认你拥有对目标系统的明确书面授权。"
            "启用 wvs.exploit 自动利用模块（默认禁用）。"
            "同时需要环境变量 RAYSCAN_ENABLE_EXPLOIT=1。"
        ),
    )

    # OOB 检测选项
    oob_group = scan_parser.add_argument_group("OOB 检测")
    oob_group.add_argument("--oob-server", type=str, help="OOB 回调服务器地址（如 https://interactsh.com）")
    oob_group.add_argument("--oob-timeout", type=int, default=30, help="OOB 回调等待超时（秒，默认 30）")

    # 认证选项
    auth_group = scan_parser.add_argument_group("认证选项")
    auth_group.add_argument(
        "--auth-type", choices=["form", "bearer", "basic", "apikey", "cookie"], help="认证类型（默认自动检测）"
    )
    auth_group.add_argument("--login-url", help="表单登录 URL（auth-type=form 时必填）")
    auth_group.add_argument("--username", help="认证用户名")
    auth_group.add_argument("--password", help="认证密码")
    auth_group.add_argument("--token", help="Bearer Token / API Token")
    auth_group.add_argument("--cookies", help="直接注入 Cookie（格式：name=value; name2=value2）")
    auth_group.add_argument("--api-key", help="API Key")
    auth_group.add_argument("--api-key-header", default="X-API-Key", help="API Key Header 名称（默认 X-API-Key）")
    auth_group.add_argument(
        "--login-extra", nargs="*", dest="login_extra", help="额外表单字段（格式：fieldname=value）"
    )
    auth_group.add_argument(
        "--csrf-fields",
        nargs="*",
        dest="csrf_fields",
        help="CSRF token 字段名（默认自动检测，如 user_token csrf_token）",
    )
    auth_group.add_argument("--success-check", dest="success_check", help="登录成功标识（响应中包含的字符串）")
    auth_group.add_argument("--fail-check", dest="fail_check", help="登录失败标识（响应中包含的字符串）")

    # batch 命令
    batch_parser = sub.add_parser("batch", help="批量扫描")
    batch_parser.add_argument("file", help="目标列表文件（每行一个 URL）")
    batch_parser.add_argument("-o", "--output", help="汇总报告输出路径")
    batch_parser.add_argument("--all-modules", action="store_true", help="加载全部模块（含 lite 辅助模块）")
    batch_parser.add_argument("-t", "--threads", type=int, default=3, help="并发数（默认 3）")
    batch_parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")

    # list-modules 命令
    sub.add_parser("list-modules", help="列出所有可用检测模块")

    # version 命令
    sub.add_parser("version", help="显示版本信息")

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

    # use 命令：加载 Profile 并执行扫描
    use_parser = sub.add_parser("use", help="使用 Profile 扫描目标")
    use_parser.add_argument("profile", help="Profile 名称")
    use_parser.add_argument("-u", "--url", required=True, help="目标 URL")
    use_parser.add_argument("-o", "--output", help="输出报告文件路径")
    use_parser.add_argument(
        "-f", "--format", choices=["json", "html", "markdown", "sarif", "csv"], default="json", help="报告格式"
    )
    use_parser.add_argument("-v", "--verbose", action="store_true", help="详细输出")
    use_parser.add_argument("--auth", help="认证文件路径（JSON）")
    use_parser.add_argument("--max-time", type=int, default=7200, help="扫描超时（秒）")
    use_parser.add_argument("--insecure", action="store_true", help="禁用 SSL 证书验证")
    use_parser.add_argument("--modules", nargs="+", help="额外启用的模块")
    use_parser.add_argument("--no-modules", nargs="+", dest="disabled_modules", help="额外禁用的模块")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        setup_logging(args.verbose)
        return cmd_scan(args)
    elif args.command == "batch":
        setup_logging(args.verbose)
        return cmd_batch(args)
    elif args.command == "list-modules":
        return cmd_list_modules(args)
    elif args.command == "version":
        return cmd_version(args)
    elif args.command == "profile":
        return cmd_profile(args)
    elif args.command == "use":
        setup_logging(args.verbose)
        return cmd_use(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
