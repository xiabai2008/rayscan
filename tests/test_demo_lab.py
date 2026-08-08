"""Phase 4 P4-1:内置演示靶场测试。

覆盖:
- demo CLI 子命令已注册
- DemoLab 可启动且 health 可达
- SQLi 端点对异常输入返回错误特征
- XSS 端点反射 name 参数
"""

from __future__ import annotations

import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

from wvs.demo_lab import DemoLab


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_demo_cli_registered() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "wvs", "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(_project_root()),
    )
    assert "demo" in proc.stdout


@pytest.mark.skipif(sys.version_info < (3, 9), reason="Flask 最新版要求 Python 3.9+")
def test_demo_lab_start_and_health() -> None:
    lab = DemoLab(host="127.0.0.1", port=0)
    try:
        base = lab.start()
        assert base.startswith("http://127.0.0.1")
        with urllib.request.urlopen(base + "/health", timeout=3) as resp:
            assert resp.status == 200
    finally:
        lab.stop()


def test_demo_lab_sqli_endpoint_error_feature() -> None:
    """注入引号应产生 SQL 错误特征。"""
    lab = DemoLab(host="127.0.0.1", port=0)
    try:
        base = lab.start()
        with urllib.request.urlopen(base + "/user?id=1'", timeout=3) as resp:
            body = resp.read().decode("utf-8")
            assert resp.status == 200
            assert "SQL syntax error" in body or "SQL executed" in body
    finally:
        lab.stop()


def test_demo_lab_xss_reflection() -> None:
    lab = DemoLab(host="127.0.0.1", port=0)
    try:
        base = lab.start()
        from urllib.parse import quote

        payload = quote("<script>alert(1)</script>")
        with urllib.request.urlopen(base + f"/?name={payload}", timeout=3) as resp:
            body = resp.read().decode("utf-8")
            assert "alert(1)" in body
    finally:
        lab.stop()
