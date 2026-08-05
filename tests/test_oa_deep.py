"""S3 回归测试 — OA 三级链路深化（指纹识别 / 版本识别 / 规则级证据 / 版本过滤）. (2026-08-05)"""

from wvs.modules.oa.detector import OADetector


def _detector() -> OADetector:
    return OADetector()


# =====================================================================
# 第 1 级：指纹识别（内容指纹优先，URL 回退）
# =====================================================================


class TestOAFingerprint:
    def test_html_title_fingerprint(self):
        """<title>Nacos</title> → 识别为 Nacos（纯 URL 无法识别）"""
        det = _detector()
        html = "<html><head><title>Nacos Console</title></head><body></body></html>"
        assert det._detect_oa_type("http://target.com:8848/", html) == "Nacos"

    def test_html_body_fingerprint(self):
        """正文含 Jenkins 特征 → 识别为 Jenkins"""
        det = _detector()
        html = "<html><body>Welcome to Jenkins Dashboard</body></html>"
        assert det._detect_oa_type("http://target.com/", html) == "Jenkins"

    def test_header_fingerprint(self):
        """X-Jenkins 响应头 → 识别为 Jenkins（正文无特征时）"""
        det = _detector()
        assert det._detect_oa_type("http://target.com/", "", {"X-Jenkins": "2.440.1"}) == "Jenkins"

    def test_url_fallback(self):
        """无内容特征时回退 URL 路径匹配"""
        det = _detector()
        assert det._detect_oa_type("http://target.com/seeyon/index.jsp", "") == "致远-Seeyon"

    def test_no_fingerprint_no_url_returns_none(self):
        det = _detector()
        assert det._detect_oa_type("http://target.com/", "<html><body>plain</body></html>") is None

    def test_whitelabel_spring_fingerprint(self):
        """Whitelabel Error Page → Spring"""
        det = _detector()
        html = "<html><body>Whitelabel Error Page This application has no explicit mapping</body></html>"
        assert det._detect_oa_type("http://target.com/", html) == "Spring"

    def test_content_fingerprint_precedes_url(self):
        """内容指纹优先级高于 URL（URL 含 healer 但内容识别为 Nacos）"""
        det = _detector()
        html = "<title>Nacos</title>"
        assert det._detect_oa_type("http://target.com/seeyon/", html) == "Nacos"


# =====================================================================
# 第 2 级：版本识别
# =====================================================================


class TestOAVersion:
    def test_jenkins_header_version(self):
        det = _detector()
        assert det._detect_oa_version("Jenkins", "", {"X-Jenkins": "2.440.1"}) == "2.440.1"

    def test_nacos_page_version(self):
        det = _detector()
        html = '<script>var nacos_version = "1.4.0";</script>'
        assert det._detect_oa_version("Nacos", html, {}) == "1.4.0"

    def test_nacos_dashed_version(self):
        det = _detector()
        html = 'window.nacos-version = "2.2.3"'
        assert det._detect_oa_version("Nacos", html, {}) == "2.2.3"

    def test_unknown_version_returns_none(self):
        det = _detector()
        assert det._detect_oa_version("Nacos", "<html>plain</html>", {}) is None
        assert det._detect_oa_version("Jenkins", "", {}) is None


# =====================================================================
# 版本过滤（检查项 min/max_version，[min, max) 语义）
# =====================================================================


class TestOAVersionFilter:
    def test_no_version_info_does_not_block(self):
        """无版本信息时不阻塞（保守放行）"""
        check = {"min_version": "1.0.0", "max_version": "1.4.1"}
        assert OADetector._version_in_range(check, None) is True

    def test_within_range(self):
        check = {"max_version": "1.4.1"}
        assert OADetector._version_in_range(check, "1.4.0") is True

    def test_above_max_blocked(self):
        """[min, max) 语义：等于 max 也阻断"""
        check = {"max_version": "1.4.1"}
        assert OADetector._version_in_range(check, "1.4.1") is False
        assert OADetector._version_in_range(check, "2.2.3") is False

    def test_below_min_blocked(self):
        check = {"min_version": "2.0.0"}
        assert OADetector._version_in_range(check, "1.9.0") is False
        assert OADetector._version_in_range(check, "2.0.0") is True

    def test_parse_failure_does_not_block(self):
        """版本格式异常时保守放行"""
        check = {"max_version": "1.4.1"}
        assert OADetector._version_in_range(check, "dev-master") is True

    def test_no_constraints_always_pass(self):
        check = {}
        assert OADetector._version_in_range(check, "1.0.0") is True
        assert OADetector._version_in_range(check, None) is True


# =====================================================================
# 规则级证据（evidence 优先于通用类型验证）
# =====================================================================


class TestRuleEvidence:
    def test_rule_evidence_priority(self):
        """规则级 evidence 命中即报（即使通用 JSON 验证不满足）"""
        det = _detector()
        # pageItems 命中 → unauth 报
        assert (
            det._verify_evidence("unauth", '{"pageItems": [{"username": "admin"}]}', "application/json", "pageItems")
            is True
        )

    def test_rule_evidence_miss(self):
        """规则级 evidence 未命中 → 不报（不退回通用验证，宁缺勿滥）"""
        det = _detector()
        assert det._verify_evidence("unauth", '{"success": true}', "application/json", "pageItems") is False

    def test_rule_evidence_case_insensitive(self):
        det = _detector()
        assert det._verify_evidence("rce", "Jenkins Groovy console", "text/html", "groovy") is True
        assert det._verify_evidence("rce", "Groovy console", "text/html", "script console") is False

    def test_no_rule_evidence_falls_back_to_generic(self):
        """无规则级 evidence 时走 S1 通用类型验证"""
        det = _detector()
        # sqli：SQL 报错特征
        assert det._verify_evidence("sqli", "SQL syntax error near '1'", "text/html", None) is True
        # unauth：JSON 数据（非 HTML）
        assert det._verify_evidence("unauth", '{"pageItems": []}', "application/json", None) is True
        # 普通 HTML → 不报
        assert det._verify_evidence("unauth", "<html>login</html>", "text/html", None) is False


# =====================================================================
# Nacos 规则集成：evidence + 版本过滤 在检查项上生效
# =====================================================================


class TestNacosRuleIntegration:
    def test_nacos_users_check_has_evidence_and_version(self):
        """Nacos 用户列表检查项已配置规则级证据与版本约束"""
        from wvs.modules.oa.detector import OA_RULES

        nacos_checks = OA_RULES["Nacos"]["checks"]
        users_check = next(c for c in nacos_checks if "auth/users" in c["path"])
        assert users_check["evidence"] == "pageItems"
        assert users_check["max_version"] == "1.4.1"

    def test_version_filter_blocks_nacos_2x(self):
        """Nacos 2.x 目标：用户列表检查项被版本过滤阻断（漏洞已修复）"""
        from wvs.modules.oa.detector import OA_RULES

        check = next(c for c in OA_RULES["Nacos"]["checks"] if "auth/users" in c["path"])
        assert OADetector._version_in_range(check, "2.2.3") is False
        assert OADetector._version_in_range(check, "1.4.0") is True
