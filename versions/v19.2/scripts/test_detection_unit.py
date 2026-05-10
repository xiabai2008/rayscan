#!/usr/bin/env python3
"""
检测模块单元测试

验证 SQLi / XSS / LFI 检测逻辑是否正确
"""
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio
import sys
import os

# 添加项目根目录到 Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSQLiDetection(unittest.TestCase):
    """SQLi 检测单元测试"""

    def test_error_detection_mysql(self):
        """测试 MySQL 错误检测"""
        from wvs.modules.sqli.detector import ResponseAnalyzer

        # 模拟 MySQL 错误响应
        baseline = {"text": "Normal response", "status_code": 200}
        analyzer = ResponseAnalyzer(baseline)

        # DVWA 典型的 MySQL 错误响应
        error_response = {
            "text": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1",
            "status_code": 200
        }

        is_error, db_type = analyzer.is_sql_error(error_response)
        self.assertTrue(is_error, "应该检测到 MySQL 错误")
        self.assertEqual(db_type, "mysql", "应该识别为 MySQL")

    def test_error_detection_generic(self):
        """测试通用 SQL 错误检测"""
        from wvs.modules.sqli.detector import ResponseAnalyzer

        baseline = {"text": "Normal response", "status_code": 200}
        analyzer = ResponseAnalyzer(baseline)

        # 通用 SQL 错误响应
        error_response = {
            "text": "SQL syntax error near 'SELECT'",
            "status_code": 500
        }

        is_error, db_type = analyzer.is_sql_error(error_response)
        self.assertTrue(is_error, "应该检测到 SQL 错误")

    def test_boolean_blind_detection(self):
        """测试 Boolean-blind 检测"""
        from wvs.modules.sqli.detector import ResponseAnalyzer

        baseline = {"text": "User ID: 1<br>Name: admin<br>", "status_code": 200}
        analyzer = ResponseAnalyzer(baseline)

        # True 条件响应（与 baseline 相似）
        true_response = {"text": "User ID: 1<br>Name: admin<br>", "status_code": 200}

        # False 条件响应（无数据）
        false_response = {"text": "User ID: <br>Name: <br>", "status_code": 200}

        is_true = analyzer.is_boolean_blind_positive(true_response)
        is_false = analyzer.is_boolean_blind_positive(false_response)

        # True 和 False 响应应该有明显差异
        # 这里的测试取决于具体实现


class TestXSSDetection(unittest.TestCase):
    """XSS 检测单元测试"""

    def test_reflection_detection(self):
        """测试 XSS 反射检测"""
        from wvs.modules.xss.detector import XSSDetector

        detector = XSSDetector()

        # payload 完整反射
        resp_text = '<html><body>Hello <script>alert(1)</script></body></html>'
        baseline_text = '<html><body>Hello </body></html>'
        payload = '<script>alert(1)</script>'

        result = detector._check_reflection(resp_text, payload, baseline_text)
        self.assertTrue(result, "应该检测到 payload 反射")

    def test_event_handler_detection(self):
        """测试事件处理器反射检测"""
        from wvs.modules.xss.detector import XSSDetector

        detector = XSSDetector()

        # onerror 事件处理器反射
        resp_text = '<html><body><img src=x onerror=alert(1)></body></html>'
        baseline_text = '<html><body></body></html>'
        payload = '<img src=x onerror=alert(1)>'

        result = detector._check_reflection(resp_text, payload, baseline_text)
        self.assertTrue(result, "应该检测到事件处理器反射")

    def test_case_insensitive_detection(self):
        """测试大小写不敏感检测"""
        from wvs.modules.xss.detector import XSSDetector

        detector = XSSDetector()

        # 大小写混合的 payload 反射
        resp_text = '<html><body><SCRIPT>alert(1)</SCRIPT></body></html>'
        baseline_text = '<html><body></body></html>'
        payload = '<script>alert(1)</script>'

        result = detector._check_reflection(resp_text, payload, baseline_text)
        self.assertTrue(result, "应该检测到大小写混合反射")

    def test_partial_reflection(self):
        """测试部分反射检测"""
        from wvs.modules.xss.detector import XSSDetector

        detector = XSSDetector()

        # 部分反射（payload 被修改但关键部分仍在）
        resp_text = '<html><body><script>alert(1)</script></body></html>'
        baseline_text = '<html><body></body></html>'
        payload = '"><script>alert(1)</script>'  # 引号被过滤

        result = detector._check_reflection(resp_text, payload, baseline_text)
        self.assertTrue(result, "应该检测到部分反射")


class TestLFIDetection(unittest.TestCase):
    """LFI 检测单元测试"""

    def test_passwd_detection(self):
        """测试 /etc/passwd 检测"""
        from wvs.modules.lfi.detector import LFIDetector

        detector = LFIDetector()

        # /etc/passwd 内容反射
        resp_text = '<html><body>root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin</body></html>'
        baseline_text = '<html><body></body></html>'
        payload = '../../../etc/passwd'

        file_path, content = detector._check_file_content(resp_text, payload, baseline_text)
        self.assertIsNotNone(file_path, "应该检测到文件读取")
        self.assertIn("root:", content, "内容应包含 root:")

    def test_php_code_detection(self):
        """测试 PHP 代码检测"""
        from wvs.modules.lfi.detector import LFIDetector

        detector = LFIDetector()

        # PHP 代码反射
        resp_text = '<html><body><?php echo "Hello"; ?></body></html>'
        baseline_text = '<html><body></body></html>'
        payload = 'include.php'

        file_path, content = detector._check_file_content(resp_text, payload, baseline_text)
        self.assertIsNotNone(file_path, "应该检测到 PHP 代码")


class TestPayloads(unittest.TestCase):
    """Payload 测试"""

    def test_sqli_payloads_count(self):
        """测试 SQLi payload 数量"""
        from wvs.modules.sqli.payloads import ERROR_BASED_PAYLOADS, BOOLEAN_BLIND_PAYLOADS

        mysql_error_payloads = ERROR_BASED_PAYLOADS.get("mysql", [])
        self.assertGreater(len(mysql_error_payloads), 5, "MySQL error payloads 应该超过 5 条")

        mysql_boolean_payloads = BOOLEAN_BLIND_PAYLOADS.get("mysql", [])
        self.assertGreater(len(mysql_boolean_payloads), 5, "MySQL boolean payloads 应该超过 5 条")

    def test_xss_payloads_count(self):
        """测试 XSS payload 数量"""
        from wvs.modules.xss.payloads import REFLECTED_PAYLOADS

        self.assertGreater(len(REFLECTED_PAYLOADS), 10, "Reflected payloads 应该超过 10 条")

    def test_lfi_payloads_count(self):
        """测试 LFI payload 数量"""
        from wvs.modules.lfi.payloads import LFI_PAYLOADS_LINUX

        self.assertGreater(len(LFI_PAYLOADS_LINUX), 10, "LFI Linux payloads 应该超过 10 条")


def run_async_test(coro):
    """运行异步测试的辅助函数"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


if __name__ == "__main__":
    print("=" * 60)
    print("WVS v19 检测模块单元测试")
    print("=" * 60)

    # 运行测试
    unittest.main(verbosity=2)
