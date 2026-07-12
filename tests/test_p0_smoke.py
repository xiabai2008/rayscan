"""
P0 止血 (hotfix) regression smoke tests.

These tests lock in the four P0 fixes so they cannot silently regress:

1. ``pyproject.toml`` pins ``httpx`` (>=0.27,<0.29) and ``flask`` (>=3).
2. ``wvs/core/session.py`` uses the new httpx ``proxy=`` parameter
   (the legacy ``proxies=`` parameter was removed in httpx 0.28).
3. ``SQLiDetector`` forwards the injected session up to its base class
   via ``super().__init__(config, session)``.
4. Core modules import cleanly after the dependency bump (httpx 0.28 / flask 3).
"""

import re
from pathlib import Path
from unittest.mock import MagicMock

try:
    import tomllib
except ImportError:  # Python < 3.11 has no builtin tomllib, fall back to tomli
    import tomli as tomllib

from wvs.core.scanner import WAVScanner
from wvs.core.session import HTTPPool
from wvs.modules.sqli.detector import SQLiDetector

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_import_wav_scanner():
    """Core scanner class must import cleanly after the dependency bump."""
    assert WAVScanner is not None
    # Confirm it is a real class, not a stray None placeholder.
    assert isinstance(WAVScanner, type)


def test_import_sqli_detector():
    """SQLi detector must import cleanly after the dependency bump."""
    assert SQLiDetector is not None
    assert isinstance(SQLiDetector, type)


def test_sqli_detector_session_passthrough():
    """The session passed to SQLiDetector must reach both self.session and the base class."""
    # Arrange
    mock_config = MagicMock(name="config")
    mock_session = MagicMock(name="session", spec=HTTPPool)

    # Act
    detector = SQLiDetector(config=mock_config, session=mock_session)

    # Assert: constructor stores the injected session on the instance.
    assert detector.session is mock_session
    # Assert: the session was transmitted to the base class via
    # super().__init__(config, session) — otherwise _active_session stays None.
    assert detector._active_session is mock_session


def test_pyproject_declares_httpx_and_flask():
    """pyproject.toml must declare the httpx and flask dependencies."""
    # Arrange
    pyproject_path = REPO_ROOT / "pyproject.toml"
    assert pyproject_path.exists(), "pyproject.toml not found at repo root"

    # Act
    with pyproject_path.open("rb") as fh:
        data = tomllib.load(fh)
    deps = data["project"]["dependencies"]

    def _package_name(dep: str) -> str:
        # Strip any version specifier / marker to get the bare package name.
        return re.split(r"[<>=!~ ;]", dep.strip())[0].strip().lower()

    dep_names = {_package_name(d) for d in deps}

    # Assert
    assert "httpx" in dep_names, "httpx missing from dependencies"
    assert "flask" in dep_names, "flask missing from dependencies"

    # The httpx pin must stay within the httpx 0.27.x compatible range
    # (proxies= was removed in 0.28, so we must not allow >=0.29).
    httpx_dep = next(d for d in deps if d.lower().startswith("httpx"))
    assert "<0.29" in httpx_dep, "httpx upper bound must stay <0.29"
    assert "flask>=3" in [d.lower() for d in deps], "flask must be >=3"


def test_session_uses_proxy_not_proxies():
    """session.py must use the new httpx `proxy=` param, never the removed `proxies=`."""
    # Arrange
    session_src = (REPO_ROOT / "wvs" / "core" / "session.py").read_text(encoding="utf-8")

    # Assert: the legacy parameter name (removed in httpx 0.28) must never reappear.
    assert "proxies=" not in session_src, "session.py still uses removed httpx 'proxies=' param"

    # Sanity: the corrected `proxy=` usage actually exists in the file.
    assert '"proxy"' in session_src, "session.py does not use the new httpx 'proxy' param"
