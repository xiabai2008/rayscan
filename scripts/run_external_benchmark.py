"""
RayScan 外部基准（Juice Shop）— CI 专用（workflow_dispatch 手动触发）。

本机网络受限（Docker Hub 阻断）时无法运行；GitHub Actions 环境可跑。
流程：docker run juice-shop → 扫描 → 断言核心模块检出 → 汇总。

用法：python scripts/run_external_benchmark.py [--port 3000]
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def wait_ready(url: str, timeout: int = 180) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = urllib.request.urlopen(url, timeout=5)
            if r.status == 200:
                return True
        except Exception:
            time.sleep(3)
    return False


def scan(port: int, modules: str, out_name: str, timeout: int = 1200) -> list:
    out = ROOT / f"{out_name}.json"
    cmd = [
        sys.executable,
        "-m",
        "wvs",
        "scan",
        f"http://127.0.0.1:{port}/",
        "--modules",
        modules,
        "--no-nuclei",
        "--allow-loopback",
        "--rate",
        "15",
        "--max-time",
        "1500",  # 大型 SPA 目标限时，防 CI 超时
        "-o",
        str(out),
    ]
    subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=timeout)
    if not out.exists():
        return []
    data = json.loads(out.read_text(encoding="utf-8"))
    out.unlink(missing_ok=True)
    return [(v.get("type"), v.get("severity"), v.get("url")) for v in data.get("vulnerabilities", [])]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--image", default="bkimminich/juice-shop")
    args = parser.parse_args()

    print("[*] 启动 Juice Shop 容器...")
    subprocess.run(["docker", "rm", "-f", "rayscan-juiceshop"], capture_output=True)
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            "rayscan-juiceshop",
            "-p",
            f"{args.port}:3000",
            args.image,
        ],
        capture_output=True,
    )
    try:
        base = f"http://127.0.0.1:{args.port}/"
        if not wait_ready(base):
            print("[FAIL] Juice Shop 未就绪")
            return 1

        print("[*] 扫描核心模块（sqli/xss/api/sensitive）...")
        vulns = scan(args.port, "sqli xss api sensitive", "bench_juice_core")
        print(f"  检出 {len(vulns)} 个漏洞")

        sqli = [v for v in vulns if v[0] == "sql_injection"]
        xss = [v for v in vulns if v[0] == "cross_site_scripting"]
        print(f"  sqli: {len(sqli)} | xss: {len(xss)} | 其他: {len(vulns) - len(sqli) - len(xss)}")

        failed = 0
        for name, hits, desc in [
            ("sqli（login 注入）", sqli, "SQLi 检出 ≥1"),
            ("xss（search 反射）", xss, "XSS 检出 ≥1"),
        ]:
            ok = len(hits) >= 1
            if not ok:
                failed += 1
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {len(hits)} — {desc}")

        for v in vulns[:15]:
            print(f"    - {v[0]}/{v[1]} @ {v[2][:80]}")

        if failed:
            print("[RESULT] 外部基准失败")
            return 1
        print("[RESULT] 外部基准通过")
        return 0
    finally:
        subprocess.run(["docker", "rm", "-f", "rayscan-juiceshop"], capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
