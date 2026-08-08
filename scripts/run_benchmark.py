"""
RayScan 基准回归脚本 — 发版前/CI 手动触发用。

流程：起本地靶场 → 逐模块扫描 → 断言各模块预期检出（对照 docs/BENCHMARK.md）→ 汇总。

用法：
    python scripts/run_benchmark.py            # 默认端口 18099
    python scripts/run_benchmark.py --port 18100 --keep

退出码：0 = 全部断言通过；1 = 有断言失败（CI 门禁）。
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB_SCRIPT = ROOT / "scripts" / "benchmark_lab.py"

# 模块 → (预期 ≥ 检出数, 说明)。Windows 下 lfi 无 /etc/passwd 跳过断言。
EXPECTATIONS = {
    "sqli": (4, "/sqli/error 四型注入"),
    "xss": (1, "/xss/reflected 反射 XSS"),
    "cmdi": (1, "/rce 命令注入 token echo"),
    "rce": (1, "/cmdi time-based 盲测或 /rce"),
    "xxe": (1, "/xxe_get 实体展开文件读取"),
    "ssrf": (1, "/ssrf cloud metadata 回显"),
    "sensitive": (1, "/.env 或 /backup/backup.sql"),
    "lfi": (1, "/lfi 文件读取（Linux 专属）"),
}

EXCLUDE_LFI_ON_WINDOWS = os.name == "nt"


def wait_ready(url: str, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=3)
            return True
        except Exception:
            time.sleep(1)
    return False


def scan_module(port: int, module: str, timeout: int = 900) -> dict:
    """扫描单模块并返回漏洞 URL 列表。"""
    out = ROOT / f"bench_{module}.json"
    cmd = [
        sys.executable,
        "-m",
        "wvs",
        "scan",
        f"http://127.0.0.1:{port}/",
        "--modules",
        module,
        "--no-nuclei",
        "--allow-loopback",
        "--rate",
        "20",
        "-o",
        str(out),
    ]
    subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=timeout)
    if not out.exists():
        return []
    data = json.loads(out.read_text(encoding="utf-8"))
    out.unlink(missing_ok=True)
    return [v.get("url", "") for v in data.get("vulnerabilities", [])]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18099)
    parser.add_argument("--keep", action="store_true", help="结束后保留靶场进程")
    args = parser.parse_args()

    lab = subprocess.Popen(
        [sys.executable, str(LAB_SCRIPT), "--port", str(args.port)],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        base = f"http://127.0.0.1:{args.port}/"
        if not wait_ready(base):
            print("[FAIL] 靶场启动失败")
            return 1

        results = {}
        for module in EXPECTATIONS:
            urls = scan_module(args.port, module)
            results[module] = urls
            print(f"  [{module}] {len(urls)} 个检出")

        print("\n===== 基准断言 =====")
        failed = 0
        for module, (minimum, desc) in EXPECTATIONS.items():
            if module == "lfi" and EXCLUDE_LFI_ON_WINDOWS:
                print("  [SKIP] lfi（Windows 无 /etc/passwd，需 Linux）")
                continue
            count = len(results[module])
            ok = count >= minimum
            status = "PASS" if ok else "FAIL"
            if not ok:
                failed += 1
            print(f"  [{status}] {module}: {count}/{minimum} — {desc}")

        if failed:
            print(f"\n[RESULT] {failed} 项断言失败")
            return 1
        print("\n[RESULT] 全部断言通过")
        return 0
    finally:
        if not args.keep:
            lab.terminate()
            try:
                lab.wait(timeout=5)
            except Exception:
                lab.kill()


if __name__ == "__main__":
    sys.exit(main())
