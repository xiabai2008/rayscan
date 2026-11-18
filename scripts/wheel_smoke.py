#!/usr/bin/env python3
"""Build the wheel, install it into a fresh venv and run a CLI smoke test.

This catches packaging regressions that the source tree masks:
- missing ``web_ui/templates`` (package-data);
- broken entry points;
- import-time failures in a clean environment.

Usage::

    python scripts/wheel_smoke.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_WHEEL_FILES = {
    "web_ui/templates/index.html",
    "web_ui/templates/login.html",
    "wvs/__init__.py",
}


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(str(c) for c in cmd))
    env = kwargs.pop("env", None) or os.environ.copy()
    # Windows consoles default to GBK; rich emits UTF-8. Force a stable codec
    # for captured output so the smoke test does not fail on decoding.
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        cmd,
        cwd=ROOT,
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        **kwargs,
    )


def _expected_version() -> str:
    text = (ROOT / "wvs" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if not match:
        raise SystemExit("cannot parse __version__ from wvs/__init__.py")
    return match.group(1)


def _venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def main() -> int:
    expected = _expected_version()
    with tempfile.TemporaryDirectory(prefix="rayscan-wheel-smoke-") as tmp:
        tmp_path = Path(tmp)
        dist_dir = tmp_path / "dist"
        dist_dir.mkdir()

        _run([sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir)])
        wheels = sorted(dist_dir.glob("rayscan-*.whl"))
        if len(wheels) != 1:
            raise SystemExit(f"expected exactly one wheel, found: {wheels}")
        wheel = wheels[0]
        print(f"[smoke] wheel: {wheel.name}")

        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            missing = REQUIRED_WHEEL_FILES - names
            if missing:
                raise SystemExit(f"wheel is missing runtime assets: {sorted(missing)}")
            if not any(name.endswith(".dist-info/entry_points.txt") for name in names):
                raise SystemExit("wheel is missing dist-info/entry_points.txt")

        venv_dir = tmp_path / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        python = _venv_python(venv_dir)
        _run([str(python), "-m", "pip", "install", "--disable-pip-version-check", str(wheel)])

        result = _run([str(python), "-m", "wvs", "version"], capture_output=True)
        output = (result.stdout or "") + (result.stderr or "")
        if expected not in output:
            raise SystemExit(f"version mismatch: expected {expected!r} in output:\n{output}")

        _run([str(python), "-c", "import wvs, web_ui; print('imports ok')"])

    print(f"[smoke] OK — wheel builds, installs, and reports {expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
