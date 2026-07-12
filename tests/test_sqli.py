"""Unit tests for the SQLi detector core analysis logic (ResponseAnalyzer).

These exercise the SQL-injection detection core against mocked session
response dicts ({"status_code", "text", "headers"}) — i.e. exactly the shape
a mocked HTTPPool session would return for a request.
"""

from wvs.modules.sqli.analyzer import ResponseAnalyzer

BASELINE = {"status_code": 200, "text": "<html><body>welcome</body></html>", "headers": {}}


# ── is_sql_error: error-signature detection ────────────────────────────────


def test_is_sql_error_mysql_syntax():
    resp = {"status_code": 500, "text": "You have an error in your SQL syntax near 'x'", "headers": {}}
    ok, db = ResponseAnalyzer(BASELINE).is_sql_error(resp)
    assert ok is True
    assert db == "mysql"


def test_is_sql_error_postgres():
    resp = {"status_code": 500, "text": 'ERROR: column "x" does not exist', "headers": {}}
    ok, db = ResponseAnalyzer(BASELINE).is_sql_error(resp)
    assert ok is True
    assert db == "generic"


def test_is_sql_error_clean_response():
    resp = {"status_code": 200, "text": "<html><body>hello world</body></html>", "headers": {}}
    ok, db = ResponseAnalyzer(BASELINE).is_sql_error(resp)
    assert ok is False
    assert db is None


# ── is_boolean_blind_positive: true/false response comparison ──────────────


def test_is_boolean_blind_positive_differs():
    true_resp = {"status_code": 200, "text": "A" * 1000, "headers": {}}
    false_resp = {"status_code": 200, "text": "B" * 10, "headers": {}}
    assert ResponseAnalyzer(BASELINE).is_boolean_blind_positive(true_resp, false_resp) is True


def test_is_boolean_blind_positive_status_mismatch():
    true_resp = {"status_code": 200, "text": "same", "headers": {}}
    false_resp = {"status_code": 404, "text": "same", "headers": {}}
    assert ResponseAnalyzer(BASELINE).is_boolean_blind_positive(true_resp, false_resp) is True


def test_is_boolean_blind_positive_identical():
    a = {"status_code": 200, "text": "same content here", "headers": {}}
    b = {"status_code": 200, "text": "same content here", "headers": {}}
    assert ResponseAnalyzer(BASELINE).is_boolean_blind_positive(a, b) is False


# ── is_union_positive: UNION injection confirmation ────────────────────────


def test_is_union_positive_detected():
    resp = {"status_code": 200, "text": "1 UNION SELECT username, password FROM users", "headers": {}}
    ok, cols = ResponseAnalyzer(BASELINE).is_union_positive(resp)
    assert ok is True


def test_is_union_positive_absent():
    resp = {"status_code": 200, "text": "<html><body>normal page</body></html>", "headers": {}}
    ok, cols = ResponseAnalyzer(BASELINE).is_union_positive(resp)
    assert ok is False


# ── is_time_based_positive: delay threshold ───────────────────────────────


def test_is_time_based_positive_above_threshold():
    ra = ResponseAnalyzer(BASELINE)
    # 4.0 >= 5.0 * 0.7 (3.5) -> True
    assert ra.is_time_based_positive({}, 5.0, 4.0) is True


def test_is_time_based_positive_below_threshold():
    ra = ResponseAnalyzer(BASELINE)
    # 2.0 < 5.0 * 0.7 (3.5) -> False
    assert ra.is_time_based_positive({}, 5.0, 2.0) is False
