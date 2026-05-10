"""
靶机实战测试框架

支持：
- DVWA (Damn Vulnerable Web Application)
- Kioptrix
- Mutillidae
- 自定义靶机配置

功能：
- HTTP Basic Auth 和 Form Auth 支持
- 跳过机制（无靶机时自动跳过）
- 测试报告生成
"""
import asyncio
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import pytest

from wvs.config import ConfigManager
from wvs.core.session import HTTPPool
from wvs.models import ScanTarget, Vulnerability
from wvs.modules.sqli import SQLiDetector
from wvs.modules.xss import XSSDetector
from wvs.modules.cmdi import CMDInjectionDetector


# ============================================================
# 靶机配置模板
# ============================================================

@dataclass
class TargetConfig:
    """靶机配置"""
    name: str
    base_url: str
    auth_type: str = "none"  # none, basic, form
    auth_credentials: Dict[str, str] = field(default_factory=dict)
    endpoints: List[Dict[str, str]] = field(default_factory=list)
    expected_vulns: List[str] = field(default_factory=list)
    skip_if_unavailable: bool = True
    timeout: int = 30

    def is_available(self) -> bool:
        """检查靶机是否可用"""
        import httpx
        try:
            with httpx.Client(verify=False, timeout=self.timeout) as client:
                resp = client.get(self.base_url, follow_redirects=True)
                return resp.status_code < 500
        except Exception:
            return False


# 预定义靶机配置
TARGET_TEMPLATES = {
    "dvwa": TargetConfig(
        name="DVWA",
        base_url="http://127.0.0.1:8080/DVWA",
        auth_type="form",
        auth_credentials={
            "login_url": "/login.php",
            "username": "admin",
            "password": "password",
            "username_field": "username",
            "password_field": "password",
        },
        endpoints=[
            {"path": "/vulnerabilities/sqli/?id=1&Submit=Submit", "vuln_type": "sqli"},
            {"path": "/vulnerabilities/xss_r/?name=test", "vuln_type": "xss"},
            {"path": "/vulnerabilities/exec/?ip=127.0.0.1", "vuln_type": "cmdi"},
            {"path": "/vulnerabilities/sqli_blind/?id=1&Submit=Submit", "vuln_type": "sqli-blind"},
        ],
        expected_vulns=["sqli", "xss", "cmdi"],
    ),
    "mutillidae": TargetConfig(
        name="Mutillidae",
        base_url="http://127.0.0.1:8080/mutillidae",
        auth_type="none",
        endpoints=[
            {"path": "/index.php?page=user-info.php&username=admin&password=test&user-info-php-submit-button=View+Account+Details", "vuln_type": "sqli"},
            {"path": "/index.php?page=dns-lookup.php&target-host=127.0.0.1", "vuln_type": "cmdi"},
        ],
        expected_vulns=["sqli", "cmdi"],
    ),
    "bwapp": TargetConfig(
        name="bWAPP",
        base_url="http://127.0.0.1:8080/bwapp",
        auth_type="form",
        auth_credentials={
            "login_url": "/login.php",
            "username": "bee",
            "password": "bug",
            "username_field": "login",
            "password_field": "password",
        },
        endpoints=[
            {"path": "/sqli_1.php?title=1&action=search", "vuln_type": "sqli"},
            {"path": "/xss_get.php?firstname=test&lastname=test&form=submit", "vuln_type": "xss"},
        ],
        expected_vulns=["sqli", "xss"],
    ),
    "kioptrix": TargetConfig(
        name="Kioptrix",
        base_url="http://192.168.1.100",
        auth_type="basic",
        auth_credentials={
            "username": "admin",
            "password": "admin",
        },
        endpoints=[
            {"path": "/index.php?page=1", "vuln_type": "sqli"},
        ],
        expected_vulns=["sqli"],
    ),
}


# ============================================================
# 测试 Fixtures
# ============================================================

def get_target_from_env() -> Optional[TargetConfig]:
    """从环境变量获取靶机配置"""
    target_name = os.environ.get("WVS_TEST_TARGET", "").lower()
    target_url = os.environ.get("WVS_TEST_URL", "")
    target_user = os.environ.get("WVS_TEST_USER", "")
    target_pass = os.environ.get("WVS_TEST_PASS", "")

    if target_url:
        # 使用自定义 URL
        config = TargetConfig(
            name="Custom Target",
            base_url=target_url,
            auth_type="basic" if target_user else "none",
            auth_credentials={"username": target_user, "password": target_pass} if target_user else {},
        )
        return config

    if target_name and target_name in TARGET_TEMPLATES:
        # 使用预定义模板
        return TARGET_TEMPLATES[target_name]

    return None


@pytest.fixture
async def http_session():
    """创建 HTTP 会话"""
    config = ConfigManager()
    async with HTTPPool(config) as session:
        yield session


@pytest.fixture
async def authenticated_session(http_session, request):
    """
    创建已认证的 HTTP 会话

    支持：
    - HTTP Basic Auth
    - Form-based Auth
    """
    target = get_target_from_env()
    if not target:
        pytest.skip("No target configured (set WVS_TEST_TARGET or WVS_TEST_URL)")

    if not target.is_available():
        pytest.skip(f"Target {target.name} is not available at {target.base_url}")

    # HTTP Basic Auth
    if target.auth_type == "basic":
        http_session._client.auth = (
            target.auth_credentials.get("username", ""),
            target.auth_credentials.get("password", ""),
        )

    # Form Auth
    elif target.auth_type == "form":
        creds = target.auth_credentials
        login_url = urljoin(target.base_url, creds.get("login_url", "/login"))

        # 获取登录页面（获取 CSRF token 等）
        login_page = await http_session.get(login_url)
        login_text = login_page.text if hasattr(login_page, "text") else ""

        # 提取可能的 CSRF token
        import re
        csrf_match = re.search(r'name=["\']?(?:csrf|token|user_token)["\']?\s*value=["\']([^"\']+)["\']', login_text, re.IGNORECASE)
        csrf_token = csrf_match.group(1) if csrf_match else None

        # 构造登录数据
        login_data = {
            creds.get("username_field", "username"): creds.get("username", ""),
            creds.get("password_field", "password"): creds.get("password", ""),
        }
        if csrf_token:
            login_data["user_token"] = csrf_token

        # 执行登录
        login_resp = await http_session.post(login_url, data=login_data)

        # 验证登录成功（检查是否重定向或包含成功标志）
        if hasattr(login_resp, "status_code"):
            if login_resp.status_code in (302, 301) or "welcome" in getattr(login_resp, "text", "").lower():
                print(f"[AUTH] Successfully authenticated to {target.name}")

    return http_session, target


# ============================================================
# 测试类
# ============================================================

class TestLiveTarget:
    """靶机实战测试"""

    @pytest.fixture(autouse=True)
    def setup(self, authenticated_session):
        """设置测试环境"""
        self.session, self.target = asyncio.get_event_loop().run_until_complete(authenticated_session)

    @pytest.mark.asyncio
    @pytest.mark.skipif(not os.environ.get("WVS_TEST_TARGET") and not os.environ.get("WVS_TEST_URL"),
                        reason="No target configured")
    async def test_sqli_detection(self):
        """测试 SQL 注入检测"""
        detector = SQLiDetector(session=self.session)

        for endpoint in self.target.endpoints:
            if endpoint.get("vuln_type") not in ["sqli", "sqli-blind"]:
                continue

            url = urljoin(self.target.base_url, endpoint["path"])
            target = ScanTarget(url=url)

            vulns = await detector._scan_impl(target)

            assert len(vulns) > 0, f"Expected SQLi vulnerability at {url}"
            print(f"[PASS] SQLi detected at {url}: {len(vulns)} vulnerabilities")

    @pytest.mark.asyncio
    @pytest.mark.skipif(not os.environ.get("WVS_TEST_TARGET") and not os.environ.get("WVS_TEST_URL"),
                        reason="No target configured")
    async def test_xss_detection(self):
        """测试 XSS 检测"""
        detector = XSSDetector(session=self.session)

        for endpoint in self.target.endpoints:
            if endpoint.get("vuln_type") != "xss":
                continue

            url = urljoin(self.target.base_url, endpoint["path"])
            target = ScanTarget(url=url)

            vulns = await detector._scan_impl(target)

            assert len(vulns) > 0, f"Expected XSS vulnerability at {url}"
            print(f"[PASS] XSS detected at {url}: {len(vulns)} vulnerabilities")

    @pytest.mark.asyncio
    @pytest.mark.skipif(not os.environ.get("WVS_TEST_TARGET") and not os.environ.get("WVS_TEST_URL"),
                        reason="No target configured")
    async def test_cmdi_detection(self):
        """测试命令注入检测"""
        detector = CMDInjectionDetector(session=self.session)

        for endpoint in self.target.endpoints:
            if endpoint.get("vuln_type") != "cmdi":
                continue

            url = urljoin(self.target.base_url, endpoint["path"])
            target = ScanTarget(url=url)

            vulns = await detector._scan_impl(target)

            assert len(vulns) > 0, f"Expected CMDi vulnerability at {url}"
            print(f"[PASS] CMDi detected at {url}: {len(vulns)} vulnerabilities")


class ReportGenerator:
    """测试报告生成器"""

    def __init__(self):
        self.results: List[Dict[str, Any]] = []
        self.start_time: float = 0

    def start(self):
        """开始记录"""
        self.start_time = time.time()
        self.results = []

    def add_result(self, test_name: str, success: bool, details: str = ""):
        """添加测试结果"""
        self.results.append({
            "test": test_name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        })

    def generate_report(self, target_name: str) -> str:
        """生成测试报告"""
        elapsed = time.time() - self.start_time
        passed = sum(1 for r in self.results if r["success"])
        failed = len(self.results) - passed

        report = f"""
{'=' * 60}
WVS 靶机测试报告
{'=' * 60}
目标: {target_name}
时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
耗时: {elapsed:.2f} 秒

{'─' * 60}
测试结果汇总
{'─' * 60}
总计: {len(self.results)} 个测试
通过: {passed}
失败: {failed}

{'─' * 60}
详细结果
{'─' * 60}
"""
        for r in self.results:
            status = "✓ PASS" if r["success"] else "✗ FAIL"
            report += f"\n{status} | {r['test']}"
            if r["details"]:
                report += f"\n      {r['details']}"

        report += f"\n{'=' * 60}\n"
        return report

    def save_report(self, filepath: str):
        """保存报告到文件"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.generate_report("Test Target"))


# ============================================================
# 辅助函数
# ============================================================

def list_available_targets():
    """列出可用的靶机配置"""
    print("可用的靶机配置:")
    print("-" * 40)
    for name, config in TARGET_TEMPLATES.items():
        print(f"  {name}: {config.name}")
        print(f"    URL: {config.base_url}")
        print(f"    认证: {config.auth_type}")
        print(f"    预期漏洞: {', '.join(config.expected_vulns)}")
        print()


def check_target_availability():
    """检查靶机可用性"""
    print("检查靶机可用性:")
    print("-" * 40)
    for name, config in TARGET_TEMPLATES.items():
        available = config.is_available()
        status = "✓ 可用" if available else "✗ 不可用"
        print(f"  {name}: {status}")
    print()


async def run_full_test(target_name: str = None) -> ReportGenerator:
    """
    运行完整测试套件

    用法:
        python -m pytest tests/test_live_target.py -v
        或
        python tests/test_live_target.py --target dvwa
    """
    target = get_target_from_env()
    if not target:
        target = TARGET_TEMPLATES.get(target_name) if target_name else None

    if not target:
        print("错误: 未指定靶机配置")
        list_available_targets()
        return None

    reporter = ReportGenerator()
    reporter.start()

    print(f"\n{'=' * 60}")
    print(f"开始测试: {target.name}")
    print(f"目标 URL: {target.base_url}")
    print(f"{'=' * 60}\n")

    # 检查靶机可用性
    if not target.is_available():
        print(f"错误: 靶机 {target.name} 不可用")
        return reporter

    # 创建 HTTP 会话
    config = ConfigManager()
    async with HTTPPool(config) as session:
        # 测试各模块
        detectors = [
            ("SQLi", SQLiDetector(session=session)),
            ("XSS", XSSDetector(session=session)),
            ("CMDi", CMDInjectionDetector(session=session)),
        ]

        for endpoint in target.endpoints:
            url = urljoin(target.base_url, endpoint["path"])
            vuln_type = endpoint.get("vuln_type", "unknown")
            target_obj = ScanTarget(url=url)

            for detector_name, detector in detectors:
                if vuln_type not in ["sqli", "sqli-blind", "xss", "cmdi"]:
                    continue

                try:
                    vulns = await detector._scan_impl(target_obj)
                    success = len(vulns) > 0
                    reporter.add_result(
                        f"{detector_name} @ {endpoint['path']}",
                        success,
                        f"发现 {len(vulns)} 个漏洞" if success else "未发现漏洞"
                    )
                    status = "✓" if success else "✗"
                    print(f"{status} {detector_name}: {len(vulns)} vulnerabilities at {url}")
                except Exception as e:
                    reporter.add_result(
                        f"{detector_name} @ {endpoint['path']}",
                        False,
                        f"错误: {str(e)}"
                    )
                    print(f"✗ {detector_name}: Error - {e}")

    print(f"\n{reporter.generate_report(target.name)}")
    return reporter


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="WVS 靶机测试")
    parser.add_argument("--target", "-t", help="靶机名称 (dvwa/mutillidae/bwapp/kioptrix)")
    parser.add_argument("--list", "-l", action="store_true", help="列出可用靶机")
    parser.add_argument("--check", "-c", action="store_true", help="检查靶机可用性")
    parser.add_argument("--url", "-u", help="自定义靶机 URL")
    parser.add_argument("--user", help="认证用户名")
    parser.add_argument("--pass", dest="password", help="认证密码")

    args = parser.parse_args()

    if args.list:
        list_available_targets()
    elif args.check:
        check_target_availability()
    elif args.url:
        # 设置环境变量
        os.environ["WVS_TEST_URL"] = args.url
        if args.user:
            os.environ["WVS_TEST_USER"] = args.user
        if args.password:
            os.environ["WVS_TEST_PASS"] = args.password
        asyncio.run(run_full_test())
    elif args.target:
        os.environ["WVS_TEST_TARGET"] = args.target
        asyncio.run(run_full_test(args.target))
    else:
        parser.print_help()
