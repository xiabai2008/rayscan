"""
黄金靶场矩阵 runner — docs/BASELINES.md 的数据来源与 CI 门禁。

与 run_benchmark.py 的区别:
- run_benchmark: 逐模块"至少 N 检出"粗粒度断言（历史兼容）
- golden matrix: 机器可读期望清单(scripts/golden_matrix.yaml)，
  must_detect 精确到 URL 子串、must_not_flag 为误报防线(命中即 FAIL)，
  未列入清单的发现仅告警并打印（新增检出需人工确认后更新清单）

流程: 起主靶场 + OA 漏洞版/修复版两个靶标 → 逐模块扫描 → 对照清单断言 → 矩阵汇总。

用法:
    python scripts/run_golden_matrix.py                # 全矩阵(CI 门禁)
    python scripts/run_golden_matrix.py --only sqli    # 调试单模块
    python scripts/run_golden_matrix.py --record       # 记录模式: 打印观察 URL,辅助更新清单

退出码: 0 = 全部断言通过; 1 = 有断言失败(must_detect 缺失 或 must_not_flag 命中)。
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_benchmark import EXCLUDE_LFI_ON_WINDOWS, wait_ready  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "scripts" / "golden_matrix.yaml"
LAB_SCRIPT = ROOT / "scripts" / "benchmark_lab.py"


def _start_lab(extra_args, ready_url):
    proc = subprocess.Popen(
        [sys.executable, str(LAB_SCRIPT), *extra_args],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not wait_ready(ready_url, timeout=30):
        proc.terminate()
        raise RuntimeError(f"靶场启动失败: {ready_url}")
    return proc


def _match(entry: str, findings: list) -> list:
    """期望条目与检出 URL 的子串匹配(条目可带 path 或 path?param 前缀)。"""
    return [url for url in findings if entry in url]


def scan_batch(port: int, modules: list, timeout: int = 2400) -> dict:
    """单次批量扫描多模块,按报告中的 module 字段归属发现。"""
    out = ROOT / f"bench_golden_{port}.json"
    cmd = [
        sys.executable,
        "-m",
        "wvs",
        "scan",
        f"http://127.0.0.1:{port}/",
        "--modules",
        *modules,
        "--no-nuclei",
        "--allow-loopback",
        "--rate",
        "20",
        "--max-time",
        str(timeout - 240),
        "-o",
        str(out),
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if not out.exists():
        raise RuntimeError(f"扫描未产出报告(端口 {port}): {proc.stdout[-500:] if proc.stdout else proc.stderr[-500:]}")
    data = json.loads(out.read_text(encoding="utf-8"))
    out.unlink(missing_ok=True)
    by_module: dict = {m: [] for m in modules}
    for v in data.get("vulnerabilities", []):
        mod = v.get("module") or "unknown"
        by_module.setdefault(mod, []).append(v.get("url", ""))
    return by_module


def run_matrix(only=None, record=False) -> int:
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    targets_cfg = manifest["targets"]
    expectations = manifest.get("expectations", {})

    main_port = 18101
    oa_vuln_port = 18102
    oa_fixed_port = 18103

    procs = []
    try:
        procs.append(_start_lab(["--port", str(main_port)], f"http://127.0.0.1:{main_port}/"))
        procs.append(
            _start_lab(
                ["--oa-port", str(oa_vuln_port), "--oa-version", "1.3.2"],
                f"http://127.0.0.1:{oa_vuln_port}/",
            )
        )
        procs.append(
            _start_lab(
                ["--oa-port", str(oa_fixed_port), "--oa-version", "1.5.0"],
                f"http://127.0.0.1:{oa_fixed_port}/",
            )
        )
        port_of = {"main": main_port, "oa_vuln": oa_vuln_port, "oa_fixed": oa_fixed_port}

        results = {}  # (target, module) -> [urls]
        scan_failed = False
        print("===== 黄金靶场矩阵扫描(分批) =====")
        for target, cfg in targets_cfg.items():
            modules_all = list(cfg["modules"])
            groups = [list(g) for g in (cfg.get("scan_groups") or [modules_all])]
            if only:
                groups = [[m for m in g if m in only] for g in groups]
            groups = [g for g in groups if g]
            if not groups:
                continue

            by_module: dict = {}
            target_failed = False
            for gi, group in enumerate(groups, 1):
                skipped = [m for m in group if m == "lfi" and EXCLUDE_LFI_ON_WINDOWS]
                scan_modules = [m for m in group if m not in skipped]
                for m in skipped:
                    print(f"  [SKIP] {target}/{m}（Windows 无 /etc/passwd，CI Linux 复测）")
                    results[(target, m)] = []
                if not scan_modules:
                    continue
                print(f"  [{target} 批次 {gi}/{len(groups)}]: {', '.join(scan_modules)}")
                try:
                    part = scan_batch(port_of[target], scan_modules)
                except RuntimeError as e:
                    print(f"  [FAIL] {target}: {e}")
                    scan_failed = True
                    target_failed = True
                    break
                for m, urls in part.items():
                    by_module.setdefault(m, []).extend(urls)
            if target_failed:
                break

            for m in modules_all:
                if (target, m) in results:
                    continue  # lfi-skip 已记录
                urls = by_module.get(m, [])
                results[(target, m)] = urls
                print(f"  [{target}/{m}] {len(urls)} 个检出")

        if record:
            print("\n===== 记录模式：观察到的检出 URL =====")
            for (target, module), urls in sorted(results.items()):
                print(f"\n# {target}/{module}")
                for u in sorted(urls):
                    print(f"  {u}")
            return 0

        if scan_failed:
            print("\n[RESULT] 扫描执行失败，矩阵无效")
            return 1

        print("\n===== 黄金矩阵断言 =====")
        failed = 0
        rows = []
        for target, cfg in targets_cfg.items():
            for module in cfg["modules"]:
                if only and module not in only:
                    continue
                if module == "lfi" and EXCLUDE_LFI_ON_WINDOWS:
                    continue
                key = (target, module)
                findings = results.get(key, [])
                exp = expectations.get(target, {}).get(module, {})
                must_detect = exp.get("must_detect", [])
                must_not = exp.get("must_not_flag", [])

                missed = [e for e in must_detect if not _match(e, findings)]
                fps = sorted({url for e in must_not for url in _match(e, findings)})
                known = set(must_detect) | set(must_not)
                extras = sorted(u for u in findings if not any(k in u for k in known))

                ok = not missed and not fps
                if not ok:
                    failed += 1
                rows.append((target, module, len(findings), missed, fps, extras, ok))

                status = "PASS" if ok else "FAIL"
                print(f"  [{status}] {target}/{module}: 检出 {len(findings)} 缺失 {len(missed)} 误报 {len(fps)}")
                for m in missed:
                    print(f"      缺失 must_detect: {m}")
                for f in fps:
                    print(f"      误报 must_not_flag 命中: {f}")
                for e in extras:
                    print(f"      [WARN] 清单外发现(人工确认后更新清单): {e}")

        print("\n===== 矩阵汇总 =====")
        print(f"{'靶标':<10} {'模块':<12} {'检出':>4} {'缺失':>4} {'误报':>4} {'清单外':>6}  结果")
        for target, module, n, missed, fps, extras, ok in rows:
            print(
                f"{target:<10} {module:<12} {n:>4} {len(missed):>4} {len(fps):>4} {len(extras):>6}  "
                f"{'✅' if ok else '❌'}"
            )
        if failed:
            print(f"\n[RESULT] {failed} 项断言失败 — 检测能力回归，禁止合并")
            return 1
        print("\n[RESULT] 黄金矩阵全部通过")
        return 0
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()


def main() -> int:
    parser = argparse.ArgumentParser(description="RayScan 黄金靶场矩阵")
    parser.add_argument("--only", default=None, help="仅扫描指定模块(逗号分隔,调试用)")
    parser.add_argument("--record", action="store_true", help="记录模式:打印观察 URL 不做断言")
    args = parser.parse_args()
    only = {m.strip() for m in args.only.split(",")} if args.only else None
    try:
        return run_matrix(only=only, record=args.record)
    except RuntimeError as e:
        print(f"[FAIL] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
