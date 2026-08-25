"""S1 误报治理回归测试 — 2026-08-05.

覆盖：Nuclei 回退"可达即报"、OA 状态码判定、XXE/SSRF baseline 排除、
DOM XSS 假阳性移除。原则：宁可漏报，不可把"路径可达/页面存在"报成漏洞。
"""

from types import SimpleNamespace

from wvs.models import Vulnerability

# =====================================================================
# XXE baseline 排除
# =====================================================================


class TestXXEBaseline:
    def setup_method(self):
        from wvs.modules.xxe.detector import XXEDetector

        self.det = XXEDetector()

    def test_file_content_no_baseline(self):
        """响应含 /etc/passwd 特征且 baseline 无 → 命中（真阳性仍检出）"""
        resp = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin"
        assert self.det._check_xxe_success(resp) is True

    def test_file_content_baseline_contains_same(self):
        """页面本身含 root:x:0:0:（baseline 有）→ 不误报"""
        resp = "<html><pre>root:x:0:0:root:/root:/bin/bash\n</pre></html>"
        baseline = "root:x:0:0:root:/root:/bin/bash"
        assert self.det._check_xxe_success(resp, baseline) is False

    def test_entity_error_baseline_contains(self):
        """baseline 已含完整解析器错误字样（如安全说明页）→ 不误报"""
        assert (
            self.det._check_xxe_success("failed to load external entity", "failed to load external entity doc") is False
        )

    def test_entity_error_no_baseline(self):
        """响应含解析器错误且 baseline 无 → 命中"""
        assert self.det._check_xxe_success("failed to load external entity") is True

    def test_normal_html_no_false_positive(self):
        """普通 HTML 页面 → 不报"""
        assert (
            self.det._check_xxe_success("<html><body>Hello</body></html>", "<html><body>Hello</body></html>") is False
        )


# =====================================================================
# SSRF baseline 排除
# =====================================================================


class TestSSRFBaseline:
    def setup_method(self):
        from wvs.modules.ssrf.detector import SSRFDetector

        self.det = SSRFDetector.__new__(SSRFDetector)

    def test_cloud_metadata_no_baseline(self):
        resp = '{"AccessKeyId": "ASIA123456", "SecretAccessKey": "secret123"}'
        assert self.det._check_ssrf_success(resp, None) is True

    def test_baseline_contains_indicators(self):
        """baseline 已含 /etc/passwd 特征字样 → 不误报"""
        resp = "<html><pre>root:x:0:0:root:/root:/bin/bash\nnobody:x:</pre></html>"
        baseline = "root:x:0:0:root:/root:/bin/bash\nnobody:x:"
        assert self.det._check_ssrf_success(resp, "http://internal:22", baseline) is False

    def test_connection_error_baseline_contains(self):
        """baseline 已含连接错误文案（系统状态页）→ 不误报"""
        assert self.det._check_ssrf_success("Connection refused", "http://internal:22", "Connection refused") is False


# =====================================================================
# OA 检测 — 状态码不再等于漏洞（_run_check）
# =====================================================================


class TestOADetectorEvidence:
    def setup_method(self):
        from wvs.modules.oa.detector import OADetector

        self.det = OADetector()

    def _run_check(self, monkeypatch, status, body, content_type, check):
        from wvs.modules.oa.detector import OADetector

        # 类级 patch 会绑定 self，故 fake_send 需接受 self 参数
        async def fake_send(self, method, url, params, param_type="query"):
            return {"status_code": status, "text": body, "headers": {"content-type": content_type}}

        monkeypatch.setattr(OADetector, "_send_request", fake_send)
        import asyncio

        return asyncio.run(self.det._run_check("http://target.com", check, None))

    # ── 401/403 被正确拦截 ≠ 漏洞 ──
    def test_unauth_401_not_vuln(self, monkeypatch):
        assert (
            self._run_check(
                monkeypatch,
                401,
                "Unauthorized",
                "text/html",
                {"path": "/nacos/v1/auth/users", "type": "unauth", "severity": "critical"},
            )
            is None
        )

    # ── 302/500 重定向/错误页 ≠ 漏洞 ──
    def test_redirect_not_vuln(self, monkeypatch):
        assert (
            self._run_check(
                monkeypatch,
                302,
                "",
                "text/html",
                {"path": "/seeyon/htmlofficeservlet", "type": "rce", "severity": "critical"},
            )
            is None
        )

    def test_server_error_not_vuln(self, monkeypatch):
        assert (
            self._run_check(
                monkeypatch,
                500,
                "Internal Server Error",
                "text/html",
                {"path": "/seeyon/htmlofficeservlet", "type": "rce", "severity": "critical"},
            )
            is None
        )

    # ── 200 但无响应证据 ≠ 漏洞（普通 HTML/登录页）──
    def test_rce_html_page_not_vuln(self, monkeypatch):
        check = {"path": "/seeyon/htmlofficeservlet", "type": "rce", "severity": "critical"}
        assert self._run_check(monkeypatch, 200, "<html><body>Login</body></html>", "text/html", check) is None

    def test_unauth_login_page_not_vuln(self, monkeypatch):
        check = {"path": "/nacos/v1/auth/users", "type": "unauth", "severity": "critical"}
        assert self._run_check(monkeypatch, 200, "<html><body>Nacos Login</body></html>", "text/html", check) is None

    # ── 200 + 真实响应证据 → 命中 ──
    def test_unauth_json_data_is_vuln(self, monkeypatch):
        check = {"path": "/nacos/v1/auth/users", "type": "unauth", "severity": "critical"}
        vuln = self._run_check(monkeypatch, 200, '{"pageItems": [{"username": "admin"}]}', "application/json", check)
        assert vuln is not None
        assert isinstance(vuln, Vulnerability)

    def test_sqli_error_evidence_is_vuln(self, monkeypatch):
        check = {
            "path": "/zentao/api-getModel-api-sql.json",
            "params": {"sql": "select+1"},
            "type": "sqli",
            "severity": "critical",
        }
        vuln = self._run_check(monkeypatch, 200, '{"success": true, "data": []}', "application/json", check)
        assert vuln is not None

    def test_sqli_success_false_not_vuln(self, monkeypatch):
        """S5 续：JSON success 为 false 不是注入成功证据 → 不报"""
        check = {
            "path": "/zentao/api-getModel-api-sql.json",
            "params": {"sql": "select+1"},
            "type": "sqli",
            "severity": "critical",
        }
        assert (
            self._run_check(monkeypatch, 200, '{"success": false, "error": "sql error"}', "application/json", check)
            is None
        )

    def test_rce_octet_stream_is_vuln(self, monkeypatch):
        check = {"path": "/seeyon/htmlofficeservlet", "type": "rce", "severity": "critical"}
        vuln = self._run_check(monkeypatch, 200, "\x1f\x8b\x00binary", "application/octet-stream", check)
        assert vuln is not None

    def test_file_read_source_evidence_is_vuln(self, monkeypatch):
        check = {
            "path": "/sys/ui/extend/varkind/custom_pf.jsp",
            "params": {"var": "1"},
            "type": "file_read",
            "severity": "high",
        }
        vuln = self._run_check(monkeypatch, 200, '<%@ page import="java.io.*" %>', "text/html", check)
        assert vuln is not None

    def test_file_upload_get_never_vuln(self, monkeypatch):
        """file_upload 类 GET 探测无法验证 → 永不报"""
        check = {"path": "/defaultroot/uploadFile.jsp", "type": "file_upload", "severity": "high"}
        assert self._run_check(monkeypatch, 200, "<html>upload page</html>", "text/html", check) is None


# =====================================================================
# Nuclei 内置回退 — 无内容特征不再"可达即报"
# =====================================================================


class TestNucleiFallbackEvidence:
    """通过 fake httpx 客户端驱动 _fallback_scan，验证内容特征匹配。"""

    def _run_fallback(self, monkeypatch, responses):
        """responses: {path: (status, text)}，返回 (vulns, 请求过的路径)

        check_path 内为函数级 `import httpx`，故 patch 全局 httpx 模块对象。
        """
        import httpx

        from wvs.integrations.nuclei_integration import NucleiIntegration

        requested = []

        class FakeAsyncClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, url):
                path = url.split("://", 1)[1]
                path = path[path.index("/") :] if "/" in path else "/"
                requested.append(path)
                status, text = responses.get(path, (200, ""))
                return SimpleNamespace(status_code=status, text=text)

        monkeypatch.setattr(httpx, "AsyncClient", FakeAsyncClient)

        import asyncio

        from wvs.models import Severity

        fallback = NucleiIntegration(use_template_manager=False)
        vulns = asyncio.run(fallback._fallback_scan("http://target.com", [Severity.HIGH]))
        return vulns, requested

    def test_admin_reachable_no_evidence_no_vuln(self, monkeypatch):
        """/admin 返回 200 普通页（SPA/自定义 404）→ 不产生漏洞（原逻辑会报）"""
        vulns, requested = self._run_fallback(
            monkeypatch, {"/admin": (200, "<html><body>Not Found-ish page</body></html>")}
        )
        assert "/admin" in requested
        assert not any("/admin" in v.url for v in vulns)

    def test_robots_disallow_evidence_is_vuln(self, monkeypatch):
        """/robots.txt 含 Disallow 特征 → 命中"""
        vulns, _ = self._run_fallback(monkeypatch, {"/robots.txt": (200, "User-agent: *\nDisallow: /admin")})
        assert any("robots" in v.url for v in vulns)

    def test_graphql_html_without_feature_no_vuln(self, monkeypatch):
        """/graphql 返回 200 但无 graphql 内容特征 → 不报（原逻辑会报）"""
        vulns, _ = self._run_fallback(monkeypatch, {"/graphql": (200, "<html><body>Welcome</body></html>")})
        assert not any("graphql" in v.url for v in vulns)

    def test_graphql_with_feature_is_vuln(self, monkeypatch):
        """/graphql 响应含 GraphQL 特征（introspection 页面）→ 命中"""
        vulns, _ = self._run_fallback(
            monkeypatch, {"/graphql": (200, "<html><title>GraphQL Playground</title></html>")}
        )
        assert any("graphql" in v.url for v in vulns)

    def test_git_config_with_feature_is_vuln(self, monkeypatch):
        """/.git/config 含真实 git 配置特征（`[remote` 段）→ 命中"""
        vulns, _ = self._run_fallback(
            monkeypatch,
            {
                "/.git/config": (
                    200,
                    '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://example.com/repo.git',
                )
            },
        )
        assert any(".git" in v.url for v in vulns)
