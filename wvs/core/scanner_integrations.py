"""
Scanner integrations mixin — third-party tool integration methods.

Contains the methods that integrate external tools (Nuclei, sqlmap, ffuf, Wappalyzer,
JSPathfinder) into the scan pipeline. These are extracted from scanner.py for
better separation of concerns.
"""

import asyncio
import json
import logging
import sys
import tempfile
from typing import Dict, List, TYPE_CHECKING

from ..models import Vulnerability, VulnerabilityType, Severity, Confidence
from ..core.result_merger import ResultMerger, merge_and_display

if TYPE_CHECKING:
    from .crawler import DiscoveredEndpoint
    from ..models import ScanTarget, ScanResult

logger = logging.getLogger(__name__)


class ScannerIntegrationsMixin:
    """External tool integration methods for the scanner."""

    async def _run_jspathfinder(
        self: "ScannerIntegrationsMixin",
        target: "ScanTarget",
    ) -> List[Vulnerability]:
        """Run JSPathfinder — JS secrets + endpoint discovery."""
        try:
            from ..modules.jspathfinder import JSPathfinderDetector

            detector = JSPathfinderDetector(config=self.config, session=self.session)  # type: ignore[attr-defined]
            return await detector.scan(target)
        except ImportError:
            logger.warning("[Scanner] JSPathfinder module not available")
            return []
        except Exception as e:
            logger.exception("[Scanner] JSPathfinder error")
            return []

    async def _run_integrations(
        self: "ScannerIntegrationsMixin",
        target: "ScanTarget",
        all_vulns: List[Vulnerability],
        endpoints: List["DiscoveredEndpoint"],
    ) -> List[Vulnerability]:
        """Run all external tool integrations concurrently."""
        integration_vulns: List[Vulnerability] = []
        tasks = []
        base_url = target.url.rstrip("/")

        if self.config.get("integrations.wappalyzer.enabled", True):  # type: ignore[attr-defined]
            if getattr(self, "_wappalyzer", None) is None:
                from ..integrations import WappalyzerIntegration

                self._wappalyzer = WappalyzerIntegration(config=self.config)  # type: ignore[attr-defined]
            tasks.append(("wappalyzer", self._run_wappalyzer_fingerprint(base_url)))

        if self.config.get("integrations.ffuf.enabled", True):  # type: ignore[attr-defined]
            if getattr(self, "_ffuf", None) is None:
                from ..integrations import FfufIntegration

                self._ffuf = FfufIntegration(config=self.config)  # type: ignore[attr-defined]
            if self._ffuf.is_available:  # type: ignore[attr-defined]
                tasks.append(("ffuf", self._run_ffuf_discovery(base_url)))

        sqli_enabled = self.config.get("integrations.sqlmap.enabled", True)  # type: ignore[attr-defined]
        if sqli_enabled:
            if getattr(self, "_sqlmap", None) is None:
                from ..integrations import SqlmapIntegration

                self._sqlmap = SqlmapIntegration(config=self.config)  # type: ignore[attr-defined]
            if self._sqlmap.is_available:  # type: ignore[attr-defined]
                aggressive = self.config.get("integrations.sqlmap.aggressive", False)  # type: ignore[attr-defined]
                sqli_hints = any(v.type.value == "sql_injection" for v in all_vulns)
                if sqli_hints or aggressive:
                    tasks.append(("sqlmap", self._run_sqlmap_scan(base_url, endpoints)))
                else:
                    logger.info("[*] sqlmap: skipping (no SQLi hints, use --aggressive to force)")

        if self.config.get("integrations.nuclei.enabled", True):  # type: ignore[attr-defined]
            tasks.append(("nuclei", self.scan_with_nuclei(base_url)))

        if not tasks:
            return integration_vulns

        names = [n for n, _ in tasks]
        coros = [c for _, c in tasks]
        logger.info(f"[*] Running: {', '.join(names)}")

        results = await asyncio.gather(*coros, return_exceptions=True)
        for name, result in zip(names, results):
            if isinstance(result, Exception):
                logger.warning(f"[Scanner] {name} integration failed: {result}")
            elif isinstance(result, list):
                integration_vulns.extend(result)
                logger.info(f"[+] {name}: found {len(result)} issues")
            else:
                logger.info(f"[-] {name}: no results")

        return integration_vulns

    async def _run_wappalyzer_fingerprint(self: "ScannerIntegrationsMixin", url: str) -> List[Vulnerability]:
        """Run Wappalyzer fingerprint."""
        try:
            fp = await self._wappalyzer.fingerprint(url)  # type: ignore[attr-defined]
            summary = fp.summary()
            logger.info(f"    [Wappalyzer] {summary}")
            recs = self._wappalyzer.get_scan_recommendations(fp)  # type: ignore[attr-defined]
            if recs.get("focus"):
                logger.info(f"    [Wappalyzer] Suggested focus: {', '.join(recs['focus'])}")
            if fp.has_waf:
                logger.info(f"    [Wappalyzer] WAF detected: {fp.waf_name or 'Yes'}")
                modules = getattr(self, "_modules", {})
                if "waf" in modules:
                    waf_mod = modules["waf"]
                    if hasattr(waf_mod, "set_waf_detected"):
                        waf_mod.set_waf_detected(True)
            return []
        except Exception as e:
            logger.warning(f"    [Wappalyzer] failed: {e}")
            return []

    async def _run_ffuf_discovery(self: "ScannerIntegrationsMixin", url: str) -> List[Vulnerability]:
        """Run ffuf directory/file discovery."""
        try:
            ffuf_url = url.rstrip("/") + "/FUZZ"
            return await self._ffuf.discover(  # type: ignore[attr-defined]
                url=ffuf_url,
                match_codes="200,204,301,302,307,401,403",
                rate=30,
            )
        except Exception as e:
            logger.warning(f"    [ffuf] failed: {e}")
            return []

    async def _run_sqlmap_scan(
        self: "ScannerIntegrationsMixin",
        url: str,
        endpoints: List["DiscoveredEndpoint"],
    ) -> List[Vulnerability]:
        """Run sqlmap on the target base URL."""
        try:
            level = self.config.get("integrations.sqlmap.level", 2)  # type: ignore[attr-defined]
            risk = self.config.get("integrations.sqlmap.risk", 1)  # type: ignore[attr-defined]
            param_endpoints = [
                e for e in endpoints
                if e.parameters and any(k.lower() in ("id", "page", "query", "search", "cat", "user", "item") for k in e.parameters)
            ]
            target_url = param_endpoints[0].url if param_endpoints else url

            return await self._sqlmap.scan(  # type: ignore[attr-defined]
                url=target_url, level=level, risk=risk, techniques="BEUST",
            )
        except Exception as e:
            logger.warning(f"    [sqlmap] failed: {e}")
            return []

    async def scan_with_nuclei(self: "ScannerIntegrationsMixin", url: str) -> List[Vulnerability]:
        """Scan the target URL with Nuclei CLI (or built-in fallback templates)."""
        from ..integrations import NucleiIntegration

        nuclei = NucleiIntegration(config=self.config)
        if not nuclei.is_available:
            logger.info("[*] Nuclei CLI not available, using built-in fallback templates (50+ checks)")
        return await nuclei.scan(url)

    async def scan_with_awvs(self, url: str, instance_name: str = "default") -> List[Vulnerability]:
        """Use AWVS to scan the target URL"""
        from ..integrations import AWVSIntegration

        awvs = AWVSIntegration(config=self.config)
        if not awvs.is_available:
            logger.info("[*] AWVS not configured — skipping (configure integrations.awvs.instances)")
            return []
        logger.info("[*] Scanning with AWVS...")
        return await awvs.scan(url, instance_name=instance_name)

    async def scan_with_nessus(self, url: str, instance_name: str = "default") -> List[Vulnerability]:
        """Use Nessus to scan the target URL"""
        from ..integrations import NessusIntegration

        nessus = NessusIntegration(config=self.config)
        if not nessus.is_available:
            logger.info("[*] Nessus not configured — skipping (configure integrations.nessus.instances)")
            return []
        logger.info("[*] Scanning with Nessus...")
        return await nessus.scan(url, instance_name=instance_name)

    async def run_multi_engine_scan(self, url: str) -> List[Vulnerability]:
        """Run multi-engine scan and merge results"""
        logger.info("[*] Running multi-engine scan (RayScan + AWVS + Nessus + Nuclei)...")
        engine_results = {}

        # RayScan built-in modules (already run by scanner)
        # Collect from this scanner instance
        if hasattr(self, "_modules"):
            rayscan_vulns = []
            for mod_name, mod_instance in self._modules.items():
                if hasattr(mod_instance, "_found_vulns"):
                    rayscan_vulns.extend(mod_instance._found_vulns)
            if rayscan_vulns:
                engine_results["rayscan"] = rayscan_vulns

        # Nuclei
        try:
            nuclei_vulns = await self.scan_with_nuclei(url)
            if nuclei_vulns:
                engine_results["nuclei"] = nuclei_vulns
        except Exception as e:
            logger.warning(f"[Scanner] Nuclei scan failed: {e}")

        # AWVS (if configured)
        try:
            awvs_vulns = await self.scan_with_awvs(url)
            if awvs_vulns:
                engine_results["awvs"] = awvs_vulns
        except Exception as e:
            logger.warning(f"[Scanner] AWVS scan failed: {e}")

        # Nessus (if configured)
        try:
            nessus_vulns = await self.scan_with_nessus(url)
            if nessus_vulns:
                engine_results["nessus"] = nessus_vulns
        except Exception as e:
            logger.warning(f"[Scanner] Nessus scan failed: {e}")

        # Merge
        if len(engine_results) >= 2:
            merger = ResultMerger()
            merged = merger.merge(engine_results)
            logger.info(f"[Scanner] Multi-engine merge: {len(merged)} vulns from {len(engine_results)} engines")
            return merged

        # Single engine — return as-is
        for engine, vulns in engine_results.items():
            return vulns
        return []

    # ── Progress helpers ────────────────────────────────────────

    def _print_header(self: "ScannerIntegrationsMixin", target: "ScanTarget") -> None:
        sep = "=" * 60
        print(f"\n{sep}")
        print("  RayScan 1.0 — Web Vulnerability Scanner")
        print(f"  Target : {target.url}")
        profile_tag = f" [{getattr(self, '_lab_profile', None).name}]" if getattr(self, "_lab_profile", None) else ""
        print(f"  Modules: {', '.join(getattr(self, '_modules', {}).keys()) or 'none'}{profile_tag}")
        print(sep)

    def _print_progress(self: "ScannerIntegrationsMixin", done: int, total: int, phase: str) -> None:
        if total == 0:
            pct = 0
        else:
            pct = int(done / total * 100)
        bar_len = 30
        filled = int(bar_len * pct / 100)
        bar = "#" * filled + "-" * (bar_len - filled)
        msg = f"[{bar}] {pct:3d}%  ({done}/{total})  {phase:<15}"
        sys.stdout.write(f"\r  {msg}")
        sys.stdout.flush()
        if hasattr(self, "_progress_callback") and self._progress_callback:
            self._progress_callback(phase, done, total, pct)

    def _print_summary(self: "ScannerIntegrationsMixin", result: "ScanResult") -> None:
        sep = "=" * 60
        print(f"\n{sep}")
        print("  Scan complete")
        print(f"  Target   : {result.target.url}")
        print(f"  Duration : {result.duration:.1f}s")
        print(f"  Requests : {result.requests_made}")
        print(f"  Found    : {len(result.vulnerabilities)} vulnerabilities")
        print()
        if result.vulnerabilities:
            print("  Findings:")
            for v in result.vulnerabilities:
                badge = f"[{v.severity.value.upper():<8}]"
                print(f"    {badge} {v.type.value:<25} {v.url}")
        else:
            print("  No vulnerabilities found (target may still be vulnerable)")
        print(sep)

    def get_stats(self: "ScannerIntegrationsMixin") -> Dict[str, object]:
        stats = getattr(self, "_stats", {})
        return {
            **stats,
            "duration": stats.get("end_time", 0.0) - stats.get("start_time", 0.0) if stats.get("end_time") else 0.0,
        }
