"""XSS Content-Type 门禁回归测试。

缺陷背景(黄金矩阵 WARN 暴露):JSON API 把参数原样反射进响应体
(如 Juice Shop 形态 `{"data":[{"name":"result for %s"}]}`)时,检测器仅凭
"payload 原样反射"就报 HIGH XSS —— 但 Content-Type: application/json
下浏览器不会解析为 HTML,反射不构成 XSS(3 条误报)。

门禁内置在 _check_reflection 内(而非各调用点),保证新增调用路径不会绕过。
"""

import pytest

from wvs.modules.xss.detector import XSSDetector, _content_type_allows_xss

HTML_CT = {"Content-Type": "text/html; charset=utf-8"}
JSON_CT = {"Content-Type": "application/json"}
PLAIN_CT = {"Content-Type": "text/plain; charset=utf-8"}
XHTML_CT = {"content-type": "application/xhtml+xml"}


class TestContentTypeGate:
    """_content_type_allows_xss 的判定语义。"""

    @pytest.mark.parametrize(
        "headers",
        [
            HTML_CT,
            {"Content-Type": "text/html"},
            XHTML_CT,  # 大小写不敏感
            {"Content-Type": "text/html;charset=UTF-8"},
            {},  # 无头 → 保守放行(宁多查不漏报)
            None,
            {"Content-Type": "application/unknown+thing"},  # 未知 → 放行
        ],
    )
    def test_allows_html_parsing(self, headers):
        assert _content_type_allows_xss(headers) is True

    @pytest.mark.parametrize(
        "headers",
        [
            JSON_CT,
            {"Content-Type": "application/json; charset=utf-8"},
            {"Content-Type": "text/json"},
            PLAIN_CT,
            {"Content-Type": "application/javascript"},
            {"Content-Type": "application/octet-stream"},
        ],
    )
    def test_blocks_non_html(self, headers):
        assert _content_type_allows_xss(headers) is False


class TestCheckReflectionGate:
    """_check_reflection 的门禁行为:同一条文本,仅 Content-Type 不同则结论不同。"""

    PAYLOAD = "<img src=x onerror=alert(1)>"

    def _body(self):
        # JSON 形态:参数反射进 JSON 字符串值 —— 浏览器不当 HTML 解析
        return '{"data": [{"name": "result for %s"}]}' % self.PAYLOAD

    def _html_body(self):
        # HTML 形态:参数反射进 HTML 文本 —— 可能被执行
        return f"<html><body><div>result for {self.PAYLOAD}</div></body></html>"

    def test_json_response_reflection_not_reported(self):
        """回归:JSON 响应里原样反射载荷 → 不报(曾经的 3 条误报)。"""
        det = XSSDetector.__new__(XSSDetector)
        reflected, evidence = det._check_reflection(self._body(), self.PAYLOAD, "", JSON_CT)
        assert reflected is False
        assert evidence == ""

    def test_plain_text_reflection_not_reported(self):
        det = XSSDetector.__new__(XSSDetector)
        reflected, _ = det._check_reflection(self._body(), self.PAYLOAD, "", PLAIN_CT)
        assert reflected is False

    def test_html_reflection_still_reported(self):
        """防漏报:text/html 下的反射必须仍然检出。"""
        det = XSSDetector.__new__(XSSDetector)
        reflected, evidence = det._check_reflection(self._html_body(), self.PAYLOAD, "", HTML_CT)
        assert reflected is True
        assert evidence  # 证据永不为空

    def test_missing_headers_keeps_legacy_behavior(self):
        """未传 headers(旧调用方式)→ 行为不变,避免影响其他调用路径。"""
        det = XSSDetector.__new__(XSSDetector)
        assert det._check_reflection(self._html_body(), self.PAYLOAD, "")[0] is True

    def test_json_event_handler_pattern_also_blocked(self):
        """'New event handler onload=alert()' 这条结构化判定同样受门禁约束。"""
        payload = "<svg><style></style><img src=x onerror=alert(1)>"
        body = '{"data": [{"name": "result for %s"}]}' % payload
        det = XSSDetector.__new__(XSSDetector)
        assert det._check_reflection(body, payload, "", JSON_CT)[0] is False
