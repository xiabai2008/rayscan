"""
JavaScript Analysis Module (concept from LinkFinder).

Extracts from JavaScript files:
- Hidden endpoints (API paths, REST endpoints)
- Sensitive information (API keys, tokens, secrets)
- Configuration details

Based on: GerbenJavado/LinkFinder regex patterns.
"""

import asyncio
import logging
from typing import Dict, List, Optional

from ..base import DetectionModule, ModuleInfo, register_module
from ...models import Vulnerability, ScanTarget, Severity, Confidence
from ...core.session import HTTPPool
from .analyzer import extract_sensitive_info, extract_endpoints_from_js

logger = logging.getLogger("wvs.module.js_analysis")


@register_module
class JSAnalysisDetector(DetectionModule):
    """JavaScript Analysis Module"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="js_analysis",
            description="Analyze JavaScript files for hidden endpoints and sensitive information (LinkFinder)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["js", "javascript", "sensitive-info", "endpoints", "linkfinder"],
        )

    def __init__(self, config=None, session: Optional[HTTPPool] = None):
        super().__init__(config)
        self.session = session

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """Analyze JS files referenced on the target page."""
        findings: List[Vulnerability] = []

        url = target.url
        params = getattr(target, "params", {}) or {}

        resp = await self._send_request("GET", url, params, "query")
        if resp is None:
            return findings

        body = resp.get("text", "")[:100000]
        if not body:
            return findings

        # ── 1. Extract <script src="..."> references ──
        import re
        from urllib.parse import urljoin

        script_urls = set()
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE):
            src = match.group(1)
            full_url = urljoin(url, src)
            if full_url.startswith("http"):
                script_urls.add(full_url)

        logger.info(f"[JS Analysis] Found {len(script_urls)} JS files to analyze")

        # ── 2. Analyze each JS file ──
        async def analyze_js(js_url: str) -> List[Vulnerability]:
            js_findings = []
            try:
                js_resp = await self._send_request("GET", js_url, {}, "query")
                if not js_resp:
                    return js_findings

                js_text = js_resp.get("text", "")[:500000]
                if not js_text:
                    return js_findings

                # Extract sensitive info
                sensitive = extract_sensitive_info(js_text)
                for item in sensitive[:5]:  # Cap at 5 per file
                    vuln = self._create_vuln(
                        url=js_url,
                        param=item["type"],
                        param_type="js-source",
                        method="GET",
                        payload=item["value"][:50],
                        vuln_type="sensitive_info",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence=(
                            f"Sensitive info in {js_url}: {item['type']} = {item['value'][:60]} "
                            f"(line {item['line']}: {item['context'][:60]})"
                        ),
                    )
                    js_findings.append(vuln)

                # Extract hidden endpoints
                endpoints = extract_endpoints_from_js(js_text)
                if endpoints:
                    logger.debug(f"[JS Analysis] {js_url}: found {len(endpoints)} endpoints")
                    for ep in endpoints[:3]:
                        vuln = self._create_vuln(
                            url=js_url,
                            param="endpoint",
                            param_type="js-source",
                            method="GET",
                            payload=ep,
                            vuln_type="hidden_endpoint",
                            severity=Severity.INFO,
                            confidence=Confidence.LOW,
                            evidence=f"Hidden endpoint in {js_url}: {ep}",
                        )
                        js_findings.append(vuln)

            except Exception as e:
                logger.debug(f"[JS Analysis] Failed to analyze {js_url}: {e}")

            return js_findings

        # Concurrent analysis
        tasks = [analyze_js(js_url) for js_url in list(script_urls)[:10]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        sensitive_count = sum(1 for f in findings if f.vuln_type == "sensitive_info")
        endpoint_count = sum(1 for f in findings if f.vuln_type == "hidden_endpoint")
        logger.info(
            f"[JS Analysis] Done: {sensitive_count} sensitive infos, "
            f"{endpoint_count} hidden endpoints from {len(script_urls)} JS files"
        )

        return findings
