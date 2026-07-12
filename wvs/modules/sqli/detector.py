"""
SQL Injection Detection Module

Orchestrates SQL injection scanning: endpoint extraction, technique dispatching,
and vulnerability reporting. Individual detection techniques live in techniques_mixins.py.
Response analysis lives in analyzer.py.
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urljoin, urlparse

from ...core.session import HTTPPool
from ...models import Confidence, ScanTarget, Severity, Vulnerability, VulnerabilityType
from ..base import DetectionModule, ModuleInfo, register_module
from .analyzer import ResponseAnalyzer
from .payloads import (
    ERROR_BASED_PAYLOADS,
    WAF_BYPASS_PAYLOADS,
)
from .techniques_mixins import SQLiTechniquesMixin

logger = logging.getLogger("wvs.module.sqli")


@register_module
class SQLiDetector(DetectionModule, SQLiTechniquesMixin):
    """SQL Injection Detection Module"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="sqli",
            description="Detect SQL injection vulnerabilities (error-based / union / boolean-blind / time-based)",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            category="core",
            priority=10,
            tags=["sqli", "injection", "sql-injection", "database"],
        )

    def __init__(self, config=None, session: Optional[HTTPPool] = None):
        # Forward both config and session to the parent so DetectionModule
        # initialises self.session AND self._active_session correctly.
        super().__init__(config, session)
        self.session = session
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()

    # ----------------------------------------------------------
    # Core Entry Point
    # ----------------------------------------------------------

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """
        Scan target for SQL injection

        P20: Two-phase execution — fast checks (error/union/boolean) run serially,
        time-based/stacked are collected then executed concurrently. Eliminates time-blind bottleneck.
        """
        self._found_vulns = []
        self._checked_urls = set()
        logger.debug(f"[SQLi] _scan_impl ENTRY: url={target.url}")

        # P24: Global exception guard — ensure scan exits cleanly even on
        # unhandled errors, preventing exit code 1 without report generation.
        try:
            return await self._scan_impl_safe(target)
        except asyncio.CancelledError:
            logger.warning("[SQLi] Scan cancelled")
            return self._found_vulns
        except Exception as e:
            logger.error(f"[SQLi] Scan fatally failed: {e}", exc_info=True)
            return self._found_vulns

    async def _scan_impl_safe(self, target: ScanTarget) -> List[Vulnerability]:
        """Core scan logic (wrapped by _scan_impl for exception safety)."""
        self._found_vulns = []
        self._checked_urls = set()

        time_candidates: list = []
        targets = []

        # ── 1. Use target.params / target.data ──
        target_params = getattr(target, "params", None) or {}
        target_data = getattr(target, "data", None) or {}

        if target_params:
            url_key = target.url.rstrip("/")
            if url_key not in self._checked_urls:
                self._checked_urls.add(url_key)
                targets.append((target.url, target_params.copy(), "GET", "query"))

        if target_data:
            url_key = target.url.rstrip("/")
            if url_key not in self._checked_urls:
                self._checked_urls.add(url_key)
                targets.append((target.url, target_data.copy(), "POST", "body"))

        # ── 2. Supplement: extract more injection points ──
        form_eps = await self._extract_endpoints_async(target)
        for ep in form_eps:
            url = ep["url"].rstrip("/")
            params = ep.get("params", {})
            method = ep.get("method", "GET")
            param_type = ep.get("param_type", "query")

            if url in self._checked_urls:
                continue
            if not params:
                continue

            self._checked_urls.add(url)
            targets.append((url, params, method, param_type))

        # Phase 1: fast checks + collect time-based candidates
        for t_url, t_params, t_method, t_ptype in targets:
            try:
                await self._scan_endpoint(t_url, t_params, t_method, t_ptype, time_candidates=time_candidates)
            except Exception as e:
                logger.debug(f"[SQLi] _scan_endpoint failed {t_url}: {e}")

        # Phase 2: concurrent time-based + stacked query detection
        if time_candidates:
            logger.info(f"[SQLi] Starting concurrent time-based detection: {len(time_candidates)} candidates")
            sem = asyncio.Semaphore(min(5, len(time_candidates)))

            async def _run_time_test(candidate):
                (c_url, c_params, c_pname, c_pval, c_method, c_ptype, c_baseline, c_dbtype) = candidate
                async with sem:
                    try:
                        await self._test_time_based(
                            c_url,
                            c_params,
                            c_pname,
                            c_pval,
                            c_method,
                            c_ptype,
                            c_baseline,
                            c_dbtype,
                        )
                        await self._test_stacked_query(
                            c_url,
                            c_params,
                            c_pname,
                            c_pval,
                            c_method,
                            c_ptype,
                            c_baseline,
                        )
                    except Exception as e:
                        logger.debug(f"[SQLi] time-based detection failed {c_url}: {e}")

            await asyncio.gather(*[_run_time_test(c) for c in time_candidates])

        logger.info(f"[SQLi] Scan complete, found {len(self._found_vulns)} vulnerabilities")
        return self._found_vulns

    async def _scan_endpoint(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
        time_candidates: Optional[List] = None,
    ) -> None:
        """Test a single endpoint for SQL injection."""
        logger.debug(f"[SQLi] _scan_endpoint: url={url} params={list(params.keys())} method={method}")
        if not params:
            return

        baseline = await self._get_cached_baseline(method, url, params, param_type)
        if baseline is None:
            return

        db_type = await self._fingerprint_dbms(url, params, method, param_type, baseline)
        waf_prefix = WAF_BYPASS_PAYLOADS[:6] if self._waf_detected else []

        _sqli_url_kw = {
            "sqli",
            "product",
            "news",
            "item",
            "user",
            "search",
            "login",
            "member",
            "article",
            "cat",
            "id",
            "brute",
        }
        _sqli_param_kw = {
            "id",
            "uid",
            "user",
            "search",
            "q",
            "query",
            "pid",
            "cat",
            "page",
            "username",
            "password",
            "email",
        }
        url_lower = url.lower()
        is_sqli_endpoint = any(kw in url_lower for kw in _sqli_url_kw) or any(
            p.lower() in _sqli_param_kw for p in params
        )

        # P23: On POST form endpoints with many params, only test the most
        # security-relevant ones to avoid form-storm on registration/comment forms.
        param_names = list(params.keys())
        if method == "POST" and len(param_names) > 4:
            prioritized = [
                p for p in param_names if p.lower() in {"username", "password", "pass", "email", "id", "uid", "user"}
            ]
            remaining = [p for p in param_names if p not in prioritized]
            param_names = prioritized + remaining[:1]
            logger.debug(f"[SQLi] Sampled {len(param_names)}/{len(params)} params for POST {url}")

        for param_name in param_names:
            param_value = params[param_name]

            await self._test_error_based(
                url, params, param_name, param_value, method, param_type, baseline, waf_prefix, db_type
            )

            if is_sqli_endpoint:
                await self._test_union_based(url, params, param_name, param_value, method, param_type, baseline)
                await self._test_boolean_blind(url, params, param_name, param_value, method, param_type, baseline)

            # Wide-byte injection (GBK bypass for addslashes)
            await self._test_wide_byte(url, params, param_name, param_value, method, param_type, baseline, waf_prefix)

            # Second-order SQLi (POST endpoints only — data may be stored)
            await self._test_second_order(url, params, param_name, param_value, method, param_type, baseline)

            if time_candidates is not None:
                time_candidates.append(
                    (url, params.copy(), param_name, param_value, method, param_type, baseline, db_type)
                )
            else:
                await self._test_time_based(url, params, param_name, param_value, method, param_type, baseline, db_type)
                await self._test_stacked_query(url, params, param_name, param_value, method, param_type, baseline)

            # OOB exfiltration (DNS/HTTP callback, requires --oob-server)
            await self._test_oob_exfil(url, params, param_name, param_value, method, param_type, baseline)

    # ----------------------------------------------------------
    # DBMS Fingerprinting
    # ----------------------------------------------------------

    async def _fingerprint_dbms(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> str:
        """Quick probe to detect DB type using error-based payloads.

        P24 fix: Previously used list(params.keys())[0] which picks the
        alphabetically first parameter. For params like {a: "text", c: "text",
        id: "5"}, the first key is "a" — a string value that doesn't error
        on quote injection, causing DB fingerprint to always return "unknown".

        Fix: Prioritize numeric-looking parameters first, then try all params
        until one triggers a SQL error.
        """
        # Prioritize common ID/numeric parameters
        PRIORITY_PARAMS = {"id", "uid", "pid", "fid", "cat", "page", "user", "aid", "bid", "cid", "sid", "nid"}
        param_names = list(params.keys())
        prioritized = [p for p in param_names if p.lower() in PRIORITY_PARAMS]
        remaining = [p for p in param_names if p.lower() not in PRIORITY_PARAMS]
        ordered = prioritized + remaining

        for db in ERROR_BASED_PAYLOADS:
            for payload in ERROR_BASED_PAYLOADS[db][:2]:
                for param_name in ordered:
                    test_params = self._inject_param(params, param_name, payload)
                    resp = await self._send_request(method, url, test_params, param_type)
                    if resp is None:
                        continue
                    analyzer = ResponseAnalyzer(baseline)
                    is_error, detected_db = analyzer.is_sql_error(resp)
                    if is_error:
                        return detected_db or db
                    # Don't flood — first param that doesn't error, try next payload
                    break
        return "unknown"

    # ----------------------------------------------------------
    # Endpoint Extraction
    # ----------------------------------------------------------

    def _extract_endpoints(self, target: ScanTarget) -> List[Dict]:
        """Extract endpoints to test from ScanTarget"""
        endpoints = []
        url = target.url.rstrip("/")

        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            flat_params = {k: v[0] if v else "" for k, v in query_params.items()}
            base_url = url.split("?")[0]
            endpoints.append({"url": base_url, "params": flat_params, "method": "GET", "param_type": "query"})

        if target.data:
            endpoints.append({"url": url, "params": target.data, "method": "POST", "param_type": "body"})

        if target.cookies:
            cookie_params = dict.fromkeys(target.cookies.keys(), "1")
            endpoints.append({"url": url, "params": cookie_params, "method": "GET", "param_type": "cookie"})

        form_endpoints = self._extract_form_params(target)
        for ep in form_endpoints:
            dup = any(e["url"] == ep["url"] and e.get("params", {}) == ep.get("params", {}) for e in endpoints)
            if not dup:
                endpoints.append(ep)

        return endpoints

    async def _extract_endpoints_async(self, target: ScanTarget) -> List[Dict]:
        """Async version: proactively fetch target page to get form parameters."""
        endpoints = self._extract_endpoints(target)

        if any(ep["params"] for ep in endpoints):
            return endpoints

        logger.debug(f"[SQLi] No params, attempting to extract form parameters: {target.url}")
        try:
            resp = await self._send_request("GET", target.url, {}, "query")
            if resp and resp.get("text"):
                original_html = getattr(target, "html", None)
                target.html = resp["text"]
                form_eps = self._extract_form_params(target)
                target.html = original_html
                for ep in form_eps:
                    dup = any(e["url"] == ep["url"] and e.get("params", {}) == ep.get("params", {}) for e in endpoints)
                    if not dup:
                        endpoints.append(ep)
        except Exception as e:
            logger.debug(f"[SQLi] Failed to fetch form params {target.url}: {e}")

        return endpoints

    def _extract_form_params(self, target: ScanTarget) -> List[Dict]:
        """Extract form parameters from target HTML response to detect hidden injection points."""
        endpoints = []
        html = getattr(target, "html", "") or ""
        if not html:
            return endpoints

        url = target.url.rstrip("/")

        form_pattern = re.compile(r'<form[^>]*\baction\s*=\s*["\']([^"\']*)["\'][^>]*>', re.IGNORECASE)
        method_pattern = re.compile(r'<form[^>]*\bmethod\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_action = form_match.group(1).strip()
            form_method = method_pattern.search(form_match.group(0))
            method = form_method.group(1).upper() if form_method else "GET"

            parsed = urlparse(url)
            if form_action.startswith("/"):
                form_url = f"{parsed.scheme}://{parsed.netloc}{form_action}"
            elif form_action and not form_action.startswith("http"):
                form_url = urljoin(url, form_action)
            else:
                form_url = form_action or url

            form_url = form_url.rstrip("/")
            if not form_url.startswith(parsed.scheme + "://"):
                continue

            form_start = form_match.start()
            form_end = html.find("</form>", form_start)
            if form_end == -1:
                form_end = form_start + 2000
            form_body = html[form_start:form_end]

            SKIP_TYPES = {"submit", "button", "image", "reset", "file"}
            input_pattern = re.compile(r'<input[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
            type_pattern = re.compile(r'\btype\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
            value_pattern = re.compile(r'\bvalue\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

            params = {}
            for inp_match in input_pattern.finditer(form_body):
                inp_name = inp_match.group(1)
                tag_start = inp_match.start()
                tag_end = form_body.find(">", tag_start) + 1
                full_tag = form_body[tag_start:tag_end]
                inp_value_m = value_pattern.search(full_tag)
                inp_value = inp_value_m.group(1) if inp_value_m else ""
                inp_type_m = type_pattern.search(full_tag)
                inp_type = inp_type_m.group(1).lower() if inp_type_m else "text"

                if inp_type in SKIP_TYPES:
                    continue
                if inp_name in params:
                    continue
                params[inp_name] = inp_value

            select_pattern = re.compile(r'<select[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
            option_pattern = re.compile(r'<option[^>]*\bvalue\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
            for sel_match in select_pattern.finditer(form_body):
                sel_name = sel_match.group(1)
                if sel_name in params:
                    continue
                sel_start = sel_match.start()
                sel_end = form_body.find("</select>", sel_start)
                if sel_end == -1:
                    sel_end = sel_start + 500
                sel_body = form_body[sel_start:sel_end]
                opt_match = option_pattern.search(sel_body)
                params[sel_name] = opt_match.group(1) if opt_match else "1"

            if params:
                endpoints.append(
                    {
                        "url": form_url,
                        "params": params,
                        "method": method,
                        "param_type": "body" if method == "POST" else "query",
                    }
                )

        return endpoints

    def _create_vuln(
        self,
        url: str,
        param: str,
        param_type: str,
        method: str,
        payload: str,
        vuln_type: str,
        confidence: Confidence,
        db_type: str,
        evidence: str,
    ) -> Vulnerability:
        """Create a vulnerability object"""
        return Vulnerability(
            type=VulnerabilityType.SQL_INJECTION,
            title=f"SQL Injection ({vuln_type}) — {db_type}",
            url=url,
            method=method,
            parameter=param,
            parameter_type=param_type,
            payload=payload,
            evidence=evidence,
            severity=Severity.HIGH,
            confidence=confidence,
            description=f"Found {vuln_type} type SQL injection vulnerability, possible database type is {db_type}",
            recommendation="Use parameterized queries (Prepared Statements) or compiled statements, avoid string concatenation in SQL",
            module="sqli",
            tags=["sql-injection", vuln_type, db_type],
            context={"vuln_type": vuln_type, "db_type": db_type},
        )
