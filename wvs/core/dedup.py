"""
Result deduplication and checkpoint management for WAVScanner.

Extracted from scanner.py (P1-1 refactor) to reduce the WAVScanner god class.
Preserves the exact dedup logic including regex-based URL normalization.
"""

import hashlib
import json
import logging
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Vulnerability

logger = logging.getLogger(__name__)


class ResultDeduplicator:
    """Handles vulnerability deduplication and scan checkpoint persistence."""

    def __init__(self):
        self._last_checkpoint_time: float = 0.0

    # -- URL normalization (preserved from scanner.py) --

    @staticmethod
    def normalize_vuln_url(url: str) -> str:
        """Strip query string AND fragment for dedup.

        /get?name=test#x and /get are the same endpoint.
        Also collapses static resource paths and dynamic ID segments.
        """
        u = url.split("?")[0].split("#")[0].rstrip("/")
        u = re.sub(r"/\d+$", "/:id", u)
        # Collapse static resource sub-paths
        u = re.sub(
            r"/(css|js|img|images|themes|theme|static|assets|fonts|locale|lang)/.+",
            r"/\1/*",
            u,
            flags=re.IGNORECASE,
        )
        # Collapse dynamic path segments
        u = re.sub(r"/(\d{2,})/", "/:id/", u)
        # Collapse hash-like segments
        u = re.sub(r"/[/]?[a-f0-9]{16,}", "/:hash", u)
        return u

    # -- Dedup signature --

    def signature(self, v: Vulnerability) -> str:
        """Compute a dedup signature from (type, url, parameter, payload)."""
        parts = [
            v.type.value,
            self.normalize_vuln_url(v.url or ""),
            v.parameter or "",
            v.payload or "",
        ]
        return "|".join(parts).lower()

    def deduplicate(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Deduplicate, keeping highest severity; same severity -> higher confidence."""
        unique: Dict[str, Vulnerability] = {}
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        conf_order = {"certain": 0, "high": 1, "medium": 2, "low": 3}

        for v in vulns:
            sig = self.signature(v)
            if sig not in unique:
                unique[sig] = v
            else:
                existing = unique[sig]
                if severity_order.get(v.severity.value, 5) < severity_order.get(existing.severity.value, 5):
                    unique[sig] = v
                elif severity_order.get(v.severity.value, 5) == severity_order.get(existing.severity.value, 5):
                    if conf_order.get(v.confidence.value, 5) < conf_order.get(existing.confidence.value, 5):
                        unique[sig] = v
        return list(unique.values())

    # -- Checkpoint --

    @staticmethod
    def _checkpoint_path(target_url: str) -> Path:
        url_hash = hashlib.md5(target_url.encode()).hexdigest()[:12]
        return Path(tempfile.gettempdir()) / f"rayscan_checkpoint_{url_hash}.json"

    def save_checkpoint(
        self,
        target_url: str,
        vulns: List[Vulnerability],
        modules_done: List[str],
        endpoints_found: int,
        requests_made: int,
    ) -> None:
        """Save incremental scan results for crash/timeout resilience."""
        try:
            cp = self._checkpoint_path(target_url)
            data = {
                "target": target_url,
                "vulnerabilities": [v.to_dict() for v in vulns],
                "modules_done": modules_done,
                "endpoints_found": endpoints_found,
                "requests_made": requests_made,
                "timestamp": time.time(),
            }
            cp.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
            self._last_checkpoint_time = time.time()
        except Exception as e:
            logger.debug(f"Checkpoint save failed: {e}")

    def load_checkpoint(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Load a previously saved checkpoint for --resume."""
        cp = self._checkpoint_path(target_url)
        if cp.exists():
            try:
                parsed = json.loads(cp.read_text(encoding="utf-8"))
                return parsed if isinstance(parsed, dict) else None
            except Exception as e:
                logger.warning(f"Checkpoint load failed: {e}")
        return None


def prioritize_endpoints(endpoints):
    """Sort endpoints so most promising (dynamic, parameterised) ones are scanned first."""

    def score(ep) -> int:
        s = 0
        if ep.parameters:
            s -= 100
        if ep.method.upper() == "POST":
            s -= 50
        s -= min(len(ep.parameters or {}), 10)
        if any(
            k.lower() in ("id", "page", "file", "path", "url", "cmd", "exec", "query", "search")
            for k in (ep.parameters or {})
        ):
            s -= 30
        return s

    return sorted(endpoints, key=score)
