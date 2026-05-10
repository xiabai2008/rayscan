"""WVS v18 - 认证模块：表单登录 + Cookie 管理"""
import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import aiohttp


@dataclass
class LoginResult:
    """登录结果"""
    success: bool
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session_token: str = ""
    username: str = ""
    error: str = ""
    protected_urls: List[str] = field(default_factory=list)


class FormLoginConfig:
    """表单登录配置"""
    def __init__(
        self,
        login_url: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_data: Dict = None,
        success_pattern: str = None,  # 登录成功页面特征
        fail_pattern: str = None,     # 登录失败页面特征
        check_protected_url: str = None,  # 用于验证登录是否成功的受保护 URL
    ):
        self.login_url = login_url
        self.username_field = username_field
        self.password_field = password_field
        self.extra_data = extra_data or {}
        self.success_pattern = success_pattern
        self.fail_pattern = fail_pattern
        self.check_protected_url = check_protected_url


class AuthHandler:
    """认证处理器 - 支持多种认证场景"""
    
    # 常见默认凭证（按应用分类）
    DEFAULT_CREDS = {
        "dvwa": [("admin", "password"), ("admin", "admin")],
        "mutillidae": [("admin", "admin")],
        "phpmyadmin": [("root", ""), ("root", "root"), ("admin", "admin")],
        "admin": [("admin", "admin"), ("admin", "password"), ("administrator", "administrator")],
        "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("admin", "tomcat")],
        "zabbix": [("Admin", "zabbix")],
        "jenkins": [("admin", "admin"), ("jenkins", "jenkins")],
        "grafana": [("admin", "admin"), ("admin", "password")],
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.timeout = self.config.get("timeout", 15)
        self.session_cookies: Dict[str, str] = {}
        self.session_headers: Dict[str, str] = {}
        self.username: str = ""
        self.logged_in: bool = False
    
    async def login_form(self, login_url: str, username: str, password: str,
                        username_field: str = "username",
                        password_field: str = "password",
                        extra_data: Dict = None,
                        success_pattern: str = None,
                        check_url: str = None) -> LoginResult:
        """
        表单登录
        
        Args:
            login_url: 登录页面 URL
            username/password: 凭证
            username_field/password_field: 表单字段名
            extra_data: 额外表单字段（如 CSRF token）
            success_pattern: 登录成功页面特征（正则）
            check_url: 验证登录是否成功的受保护 URL
        
        Returns:
            LoginResult
        """
        result = LoginResult(success=False, username=username)
        
        async with aiohttp.ClientSession() as session:
            try:
                # 1. 先 GET 登录页面，提取 CSRF token 等隐藏字段
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
                
                async with session.get(login_url, headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                    page_content = await resp.text()
                    
                    # 收集所有 cookies
                    for name, morsel in session.cookie_jar.filter_cookies(login_url).items():
                        self.session_cookies[name] = morsel.value
                    
                    # 提取隐藏字段
                    hidden_fields = self._extract_hidden_fields(page_content)
                    
                    # 尝试从页面提取 CSRF token
                    csrf_token = self._extract_csrf_token(page_content, login_url)
                    if csrf_token:
                        hidden_fields["CSRFToken"] = csrf_token
                        # 也尝试常见字段名
                        for field_name in ["csrf_token", "csrf", "token", "_token"]:
                            if field_name not in hidden_fields:
                                hidden_fields[field_name] = csrf_token
                
                # 2. 构造登录 POST 数据
                post_data = {
                    username_field: username,
                    password_field: password,
                    **hidden_fields,
                    **(extra_data or {})
                }
                
                # 移除空值字段
                post_data = {k: v for k, v in post_data.items() if v}
                
                # 3. 发送登录请求
                async with session.post(login_url, data=post_data, cookies=self.session_cookies,
                                       headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout)) as login_resp:
                    login_content = await login_resp.text()
                    login_url_after = str(login_resp.url)
                    
                    # 更新 cookies
                    for name, morsel in session.cookie_jar.filter_cookies(login_url).items():
                        self.session_cookies[name] = morsel.value
                    
                    result.cookies = dict(self.session_cookies)
                
                # 4. 验证登录是否成功
                success = False
                
                # 方式 A: 通过 success_pattern 判断
                if success_pattern:
                    if re.search(success_pattern, login_content, re.IGNORECASE):
                        success = True
                    elif re.search(success_pattern, login_url_after, re.IGNORECASE):
                        success = True
                
                # 方式 B: 检查受保护 URL 是否可访问
                if not success and check_url:
                    check_headers = {**headers}
                    async with session.get(check_url, cookies=self.session_cookies,
                                          headers=check_headers,
                                          timeout=aiohttp.ClientTimeout(total=self.timeout)) as check_resp:
                        if check_resp.status == 200:
                            check_content = await check_resp.text()
                            # 如果是登录页，说明没登录成功
                            if "login" not in check_resp.url.path.lower() and \
                               "auth" not in check_resp.url.path.lower():
                                success = True
                            # 排除包含 login 关键词的页面
                            if re.search(r"(login|signin|log in)", check_content, re.IGNORECASE):
                                success = False
                            else:
                                success = True
                
                # 方式 C: 检查登录失败特征
                if not success:
                    fail_patterns = [
                        r"(incorrect|invalid|failed|failure|error).*?(login|password|credential)",
                        r"(login|authentication).*?(failed|incorrect|invalid)",
                        r"(wrong|incorrect).*?(username|password|credentials)",
                        r"<title>.*?Login.*?Failed",
                    ]
                    for fp in fail_patterns:
                        if re.search(fp, login_content, re.IGNORECASE):
                            result.error = "Login failed - invalid credentials"
                            return result
                    # 没有失败特征，也没有明确失败，也算成功
                    if login_content and len(login_content) > 500:
                        success = True
                
                if success:
                    result.success = True
                    result.headers = {k: v for k, v in headers.items()}
                    self.logged_in = True
                    self.username = username
                else:
                    result.error = "Could not verify login success"
                
            except asyncio.TimeoutError:
                result.error = "Login request timeout"
            except Exception as e:
                result.error = f"Login error: {str(e)}"
        
        return result
    
    async def try_default_creds(
        self,
        login_url: str,
        app_type: str = None,
        username_field: str = "username",
        password_field: str = "password",
        check_url: str = None
    ) -> LoginResult:
        """
        尝试默认凭证登录
        """
        # 收集要尝试的凭证
        creds_to_try = []
        
        if app_type and app_type.lower() in self.DEFAULT_CREDS:
            creds_to_try.extend(self.DEFAULT_CREDS[app_type.lower()])
        
        # 也尝试通用默认凭证
        if "admin" not in [c[0] for c in creds_to_try]:
            creds_to_try.append(("admin", "admin"))
        if "root" not in [c[0] for c in creds_to_try]:
            creds_to_try.append(("root", "root"))
        
        # 去重
        seen = set()
        unique_creds = []
        for c in creds_to_try:
            key = (c[0], c[1])
            if key not in seen:
                seen.add(key)
                unique_creds.append(c)
        
        # 逐个尝试
        for username, password in unique_creds:
            result = await self.login_form(
                login_url, username, password,
                username_field, password_field,
                check_url=check_url
            )
            if result.success:
                return result
        
        return LoginResult(success=False, error="No valid credentials found")
    
    async def auto_detect_login(self, base_url: str, forms: List[Dict]) -> LoginResult:
        """
        自动检测并登录（根据爬取的表单）
        
        Args:
            base_url: 目标基础 URL
            forms: 爬取的表单列表
        """
        result = LoginResult(success=False)
        
        # 查找可能的登录表单
        login_forms = []
        for form in forms:
            inputs = form.get("inputs", {})
            input_names = [k.lower() for k in inputs.keys()]
            
            # 含有 username/user/email + password 的表单
            has_user = any(k in input_names for k in ["username", "user", "email", "login", "log"])
            has_pass = "password" in input_names
            
            if has_user and has_pass:
                login_forms.append(form)
        
        if not login_forms:
            # 尝试常见登录 URL
                login_urls = [
                    f"{base_url.rstrip('/')}/login.php",
                    f"{base_url.rstrip('/')}/admin/login.php",
                    f"{base_url.rstrip('/')}/admin/",
                    f"{base_url.rstrip('/')}/wp-login.php",
                    f"{base_url.rstrip('/')}/administrator/",
                ]
                
                for login_url in login_urls:
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(login_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                                if resp.status == 200:
                                    content = await resp.text()
                                    if "password" in content.lower() and "login" in content.lower():
                                        # 找到登录页，尝试默认凭证
                                        parsed = urlparse(login_url)
                                        # 推断 app_type
                                        path = parsed.path.lower()
                                        if "admin" in path:
                                            app_type = "admin"
                                        else:
                                            app_type = None
                                        
                                        result = await self.try_default_creds(
                                            login_url, app_type=app_type,
                                            check_url=login_url
                                        )
                                        if result.success:
                                            return result
                    except:
                        continue
        
        return result
    
    def get_auth_cookies(self) -> Dict[str, str]:
        """获取认证 Cookie"""
        return dict(self.session_cookies)
    
    def get_auth_headers(self) -> Dict[str, str]:
        """获取认证 Header"""
        return dict(self.session_headers)
    
    def is_logged_in(self) -> bool:
        """是否已登录"""
        return self.logged_in and bool(self.session_cookies)
    
    def _extract_hidden_fields(self, html: str) -> Dict[str, str]:
        """从 HTML 提取所有隐藏字段"""
        fields = {}
        # 匹配 <input type="hidden" name="xxx" value="yyy">
        pattern = r'<input[^>]+type=["\']?hidden["\']?[^>]+name=["\']?([\w\-\[\]]+)["\']?[^>]+value=["\']?([^"\']*)["\']?'
        for match in re.finditer(pattern, html, re.IGNORECASE):
            fields[match.group(1)] = match.group(2)
        
        # 备选模式
        pattern2 = r'<input[^>]+name=["\']?([\w\-\[\]]+)["\']?[^>]+type=["\']?hidden["\']?[^>]+value=["\']?([^"\']*)["\']?'
        for match in re.finditer(pattern2, html, re.IGNORECASE):
            if match.group(1) not in fields:
                fields[match.group(1)] = match.group(2)
        
        return fields
    
    def _extract_csrf_token(self, html: str, url: str) -> Optional[str]:
        """提取 CSRF token"""
        patterns = [
            r'(?:csrf|token|_token|csrf_token|csrftoken)[^>]*value=["\']([^"\']+)["\']',
            r'(?:csrf|token|_token)[^>]*content=["\']([^"\']+)["\']',
            r'"csrfmiddlewaretoken"[^>]*value=["\']([^"\']+)["\']',
            r"var\s+\w*[tT]oken\w*\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None


# 同步包装
def login_sync(login_url: str, username: str, password: str,
               username_field: str = "username",
               password_field: str = "password",
               **kwargs) -> LoginResult:
    """同步登录入口"""
    return asyncio.run(
        AuthHandler().login_form(
            login_url, username, password,
            username_field, password_field, **kwargs
        )
    )
