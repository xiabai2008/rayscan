"""
SQLi ResponseAnalyzer — HTTP response analysis for SQL injection characteristics.

Detects SQL errors, boolean-blind patterns, union injection markers,
and time-based delays in raw HTTP responses.
"""

import logging
import re
from typing import Any, Dict, Optional, Tuple

from .payloads import DB_ERROR_PATTERNS

logger = logging.getLogger("wvs.module.sqli")


class ResponseAnalyzer:
    """Analyze HTTP responses for SQL injection characteristics"""

    def __init__(self, baseline_response: Dict[str, Any]):
        """
        Args:
            baseline_response: Baseline response (original request), includes status_code, text, headers
        """
        self.baseline = baseline_response
        self.baseline_text = baseline_response.get("text", "")[:10000]  # Truncate to avoid oversized content
        self.baseline_status = baseline_response.get("status_code", 200)
        self.baseline_hash = hash(self.baseline_text)

    def is_sql_error(self, response: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Detect whether the response contains SQL error information

        Returns:
            (is_error, db_type) — Whether it is a SQL error, and the identified database type
        """
        text = response.get("text", "")[:10000]

        # Exact match against database error signatures
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern in text:
                    logger.debug(f"[SQLi] Found DB error signature: {db_type} - {pattern[:50]}")
                    return True, db_type

        # DVWA / PHP specific error patterns
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
                logger.debug(f"[SQLi] Found DVWA/PHP error pattern: {pattern}")
                return True, "mysql"

        # Broader matching: SQL syntax error
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
                logger.debug(f"[SQLi] Found generic error pattern: {pattern}")
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
        import re as _re

        def _strip_sql_noise(t: str) -> str:
            t = _re.sub(r"<[^>]+>", "", t)
            t = _re.sub(r"'[^']*'", "", t)
            t = _re.sub(r'"[^"]*"', "", t)
            t = _re.sub(r"\b(?:AND|OR|NOT|SELECT|UNION|NULL|WHERE|FROM|ORDER|BY|SLEEP|HAVING|LIKE)\b", "", t, flags=_re.IGNORECASE)
            t = _re.sub(r"\b\d+\b", "N", t)
            t = _re.sub(r"[=\<\>\!\+\-\*/%]", " ", t)
            t = _re.sub(r"--|#", " ", t)
            t = _re.sub(r"\b\w\b", "", t)
            t = _re.sub(r"\s+", " ", t).strip()
            return t

        t_clean = _strip_sql_noise(true_text)
        f_clean = _strip_sql_noise(false_text)
        if t_clean == f_clean:
            return False

        def _normalize(t: str) -> str:
            t = _re.sub(r"<[^>]+>", " ", t)
            t = _re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", " ", t)
            t = _re.sub(r"[a-f0-9]{32,}", " ", t)
            t = _re.sub(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", " ", t)
            t = _re.sub(r"\b(?:AND|OR|NOT|NULL|TRUE|FALSE|SELECT|UNION|ORDER|BY|WHERE|FROM)\b", "", t, flags=_re.IGNORECASE)
            t = _re.sub(r"'[^']*'", "''", t)
            t = _re.sub(r"\b\d+\b", "N", t)
            t = _re.sub(r"[+\-*/%]=?", " ", t)
            t = _re.sub(r"--|#", " ", t)
            t = _re.sub(r"\s+", " ", t).strip()
            return t

        t_norm = _normalize(true_text)
        f_norm = _normalize(false_text)
        if t_norm != f_norm:
            return True

        return False

    def is_union_positive(self, response: Dict[str, Any]) -> Tuple[bool, Optional[int]]:
        """
        Detect if UNION injection succeeded
        Returns (is_positive, column_count)
        """
        text = response.get("text", "")
        positive_indicators = [
            " UNION ",
            "SELECT",
            re.search(r"\d+\s+NULL", text),
            re.search(r"^\d+$", text.strip()),
        ]
        if any(positive_indicators):
            return True, None
        return False, None

    def is_time_based_positive(self, response: Dict[str, Any], expected_delay: float, actual_delay: float) -> bool:
        """
        Time-based detection: whether the actual delay exceeds the threshold
        """
        return actual_delay >= expected_delay * 0.7
