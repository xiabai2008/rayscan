"""
Authentication plugin
v18 pain point: authenticated scanning was never implemented, making login-required pages completely unscannable

Supports four authentication methods:
1. Form Login - submit login form to get session cookie (v19: auto-extract CSRF token)
2. Bearer Token - Authorization: Bearer <token>
3. Basic Auth - Authorization: Basic <base64>
4. API Key - custom header (e.g. X-API-Key)
"""

import base64
import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx

from ..config import ConfigManager
from ..models import ScanTarget


logger = logging.getLogger("wvs.auth")


# ─────────────────────────────────────────────────────────────────
# Auth Provider Interface
# ─────────────────────────────────────────────────────────────────


class AuthProvider(ABC):
    """
    Base class for auth providers

    Subclasses must implement:
    - authenticate(): Execute authentication, return cookies/headers
    - is_authenticated(): Check if still valid
    """

    @abstractmethod
    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        """
        Execute authentication

        Args:
            session: httpx client instance

        Returns:
            dict containing:
            - cookies: Dict[str, str]
            - headers: Dict[str, str]
            - authenticated: bool
            - error: Optional[str]
        """
        ...

    async def is_authenticated(
        self,
        session: httpx.AsyncClient,
        check_url: str,
    ) -> bool:
        """
        Check if authentication is still valid (subclass may override)

        Default: check response status code, 2xx = valid
        """
        try:
            resp = await session.get(check_url, timeout=10)
            return resp.status_code < 400
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────
# Form Login Auth
# ─────────────────────────────────────────────────────────────────


class FormLoginAuth(AuthProvider):
    """
    Form login authentication (v19: auto-extract CSRF token)

    Flow:
    1. GET login page -> extract CSRF token
    2. POST login form -> get session cookie

    Configuration parameters:
    - login_url: Login page URL (target for both GET and POST)
    - username_field: Name attribute of username input (default: username)
    - password_field: Name attribute of password input (default: password)
    - extra_fields: Additional form fields
    - csrf_fields: Custom CSRF field name list (default: auto-detect common names)
    - success_check: Login success indicator string
    - fail_check: Login failure indicator string
    """

    # Auto-detected CSRF token field names (ordered by commonality)
    CSRF_FIELD_NAMES = [
        "user_token",  # DVWA
        "csrf_token",  # Generic
        "csrfmiddlewaretoken",  # Django
        "authenticity_token",  # Rails
        "_token",  # Laravel
        "token",  # Generic
        "anti_forgery_token",  # ASP.NET
        "__requestverificationtoken",  # ASP.NET MVC
        "nonce",  # WordPress
        "_wpnonce",  # WordPress
    ]

    # Common login failure indicators
    DEFAULT_FAIL_CHECKS = [
        "login failed",
        "Login failed",
        "Login Failed",
        "incorrect",
        "Invalid username or password",
        "Invalid Username or Password",
        "authentication failed",
        "Authentication failed",
        "wrong password",
        "Wrong password",
    ]

    def __init__(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: Optional[Dict[str, str]] = None,
        csrf_fields: Optional[List[str]] = None,
        success_check: Optional[str] = None,
        fail_check: Optional[str] = None,
        method: str = "POST",
    ):
        self.login_url = login_url
        self.username = username
        self.password = password
        self.username_field = username_field
        self.password_field = password_field
        self.extra_fields = extra_fields or {}
        self.csrf_fields = csrf_fields or self.CSRF_FIELD_NAMES
        self.success_check = success_check
        self.fail_check = fail_check
        self.method = method.upper()

    def _extract_csrf_tokens(self, html: str) -> Dict[str, str]:
        """
        Extract CSRF tokens from login page HTML

        Supported HTML forms:
        - <input type="hidden" name="user_token" value="xxx">
        - <input name="csrf_token" type="hidden" value="xxx">
        - <meta name="csrf-token" content="xxx">

        Returns:
            dict: {field_name: token_value}
        """
        tokens: Dict[str, str] = {}

        # Check user-specified fields first
        field_names = list(self.csrf_fields)

        for field_name in field_names:
            # Pattern 1: <input ... name="field_name" ... value="xxx">
            # Match name before or after value
            patterns = [
                # name="xxx" value="yyy"
                rf'<input[^>]*\bname\s*=\s*["\']?{re.escape(field_name)}["\']?[^>]*\bvalue\s*=\s*["\']([^"\']+)["\']',
                # value="yyy" name="xxx"
                rf'<input[^>]*\bvalue\s*=\s*["\']([^"\']+)["\'][^>]*\bname\s*=\s*["\']?{re.escape(field_name)}["\']?[^>]*',
                # <meta name="xxx" content="yyy">
                rf'<meta[^>]*\bname\s*=\s*["\']?{re.escape(field_name)}["\']?[^>]*\bcontent\s*=\s*["\']([^"\']+)["\']',
            ]
            for pattern in patterns:
                m = re.search(pattern, html, re.IGNORECASE)
                if m:
                    tokens[field_name] = m.group(1)
                    logger.debug(f"[Auth:FormLogin] Extracted CSRF token: {field_name}={m.group(1)[:8]}...")
                    break  # One match is enough

        return tokens

    def _extract_submit_buttons(self, html: str) -> Dict[str, str]:
        """
        Extract submit buttons from login page HTML

        Many login forms require the submit button's name=value to work properly
        (e.g. DVWA requires Login=Login)

        Returns:
            dict: {button_name: button_value}
        """
        buttons: Dict[str, str] = {}

        # <input type="submit" name="Login" value="Login">
        patterns = [
            # <input type="submit" name="xxx" value="yyy">
            r'<input[^>]*type\s*=\s*["\']?submit["\']?[^>]*\bname\s*=\s*["\']([^"\']+)["\']?[^>]*\bvalue\s*=\s*["\']([^"\']*)["\']',
            # <input type="submit" value="yyy" name="xxx">
            r'<input[^>]*type\s*=\s*["\']?submit["\']?[^>]*\bvalue\s*=\s*["\']([^"\']*)["\']?[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
            # <button type="submit" name="xxx" value="yyy">
            r'<button[^>]*type\s*=\s*["\']?submit["\']?[^>]*\bname\s*=\s*["\']([^"\']+)["\']?[^>]*\bvalue\s*=\s*["\']([^"\']*)["\']',
        ]

        for pattern in patterns:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                # Get name and value (position depends on pattern)
                groups = m.groups()
                if len(groups) == 2:
                    # First pattern: name, value
                    name, value = groups[0], groups[1]
                    if name and value:
                        buttons[name] = value
                        logger.debug(f"[Auth:FormLogin] Found submit button: {name}={value}")
                    elif name:
                        buttons[name] = ""
                        logger.debug(f"[Auth:FormLogin] Found submit button: {name}=(empty)")
                break  # Only take the first submit button

        return buttons

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        try:
            # -- Step 1: GET login page, extract CSRF token --
            logger.info(f"[Auth:FormLogin] GET {self.login_url} (extract CSRF token)")
            get_resp = await session.get(self.login_url, timeout=30, follow_redirects=True)

            csrf_tokens = {}
            submit_buttons = {}
            if get_resp.status_code == 200:
                csrf_tokens = self._extract_csrf_tokens(get_resp.text)
                submit_buttons = self._extract_submit_buttons(get_resp.text)
                if csrf_tokens:
                    logger.info(f"[Auth:FormLogin] Found {len(csrf_tokens)} CSRF tokens: {list(csrf_tokens.keys())}")
                else:
                    logger.debug("[Auth:FormLogin] No CSRF token found (may not be required)")
                if submit_buttons:
                    logger.info(f"[Auth:FormLogin] Found {len(submit_buttons)} submit buttons: {list(submit_buttons.keys())}")
            else:
                logger.debug(f"[Auth:FormLogin] GET returned {get_resp.status_code}, skipping CSRF extraction")

            # -- Step 2: Build login POST data --
            data = {
                self.username_field: self.username,
                self.password_field: self.password,
            }
            # Submit button (many forms require it, e.g. DVWA's Login=Login)
            data.update(submit_buttons)
            # CSRF token priority: extra_fields > auto-extracted
            data.update(csrf_tokens)
            data.update(self.extra_fields)

            logger.info(f"[Auth:FormLogin] {self.method} {self.login_url}")
            logger.debug(f"[Auth:FormLogin] Fields: {list(data.keys())}")

            # -- Step 3: POST login form --
            if self.method == "POST":
                resp = await session.post(self.login_url, data=data, timeout=30, follow_redirects=True)
            else:
                resp = await session.request(self.method, self.login_url, data=data, timeout=30, follow_redirects=True)

            # -- Step 4: Check login result --

            # 4a. Strongest signal: POST URL no longer login page -> login success
            login_path = self.login_url.rstrip("/").split("/")[-1]
            current_path = str(resp.url).rstrip("/")
            if login_path not in current_path.split("/")[-1]:
                cookies = dict(session.cookies)
                if cookies:
                    logger.info(f"[Auth:FormLogin] Login successful (redirected to {resp.url}, {len(cookies)} cookies)")
                    return {"cookies": cookies, "headers": {}, "authenticated": True, "error": None}

            # 4b. Check failure indicators
            fail_checks = [self.fail_check] if self.fail_check else self.DEFAULT_FAIL_CHECKS
            for fc in fail_checks:
                if fc and fc in resp.text:
                    return {
                        "cookies": {},
                        "headers": {},
                        "authenticated": False,
                        "error": f"Login failed: response contains failure indicator '{fc}'",
                    }

            # 4b. Check if still on login page (didn't redirect)
            login_form_indicators = [
                f'name="{self.username_field}"',
                f'name="{self.password_field}"',
                f"name='{self.username_field}'",
                f"name='{self.password_field}'",
            ]
            still_on_login = any(ind in resp.text for ind in login_form_indicators)
            # Only consider failed if URL is still the login page
            if still_on_login and self.login_url.rstrip("/") in resp.url.path:
                # Double-check: if page also has success marker, it's not a failure
                if not self.success_check or self.success_check not in resp.text:
                    return {
                        "cookies": {},
                        "headers": {},
                        "authenticated": False,
                        "error": "Still on login page after login, possibly incorrect username/password or invalid CSRF token",
                    }

            # 4c. Check success indicator
            if self.success_check:
                if self.success_check in resp.text:
                    cookies = dict(session.cookies)
                    logger.info(f"[Auth:FormLogin] Login successful, got {len(cookies)} cookies")
                    return {"cookies": cookies, "headers": {}, "authenticated": True, "error": None}
                else:
                    # No success marker, but no failure marker either -- try checking cookies
                    cookies = dict(session.cookies)
                    if cookies:
                        logger.info(f"[Auth:FormLogin] No success marker but {len(cookies)} cookies present, treating as login success")
                        return {"cookies": cookies, "headers": {}, "authenticated": True, "error": None}
                    return {
                        "cookies": {},
                        "headers": {},
                        "authenticated": False,
                        "error": f"Login success indicator '{self.success_check}' not found in response",
                    }

            # 4d. Default: cookies = success
            if resp.status_code in (200, 302, 303):
                cookies = dict(session.cookies)
                if cookies:
                    logger.info(f"[Auth:FormLogin] Login successful ({len(cookies)} cookies)")
                    return {"cookies": cookies, "headers": {}, "authenticated": True, "error": None}
                else:
                    return {
                        "cookies": {},
                        "headers": {},
                        "authenticated": False,
                        "error": "No cookies received",
                    }

            return {
                "cookies": {},
                "headers": {},
                "authenticated": False,
                "error": f"HTTP {resp.status_code}",
            }

        except Exception as e:
            logger.exception("[Auth:FormLogin] Exception")
            return {"cookies": {}, "headers": {}, "authenticated": False, "error": str(e)}


# ─────────────────────────────────────────────────────────────────
# Bearer Token
# ─────────────────────────────────────────────────────────────────


class BearerTokenAuth(AuthProvider):
    """
    Bearer Token authentication

    Used for JWT, OAuth2 access_token, etc.
    """

    def __init__(self, token: str, header_name: str = "Authorization"):
        self.token = token
        self.header_name = header_name

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        header_value = f"Bearer {self.token}" if not self.token.startswith("Bearer ") else self.token
        return {
            "cookies": {},
            "headers": {self.header_name: header_value},
            "authenticated": True,
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# Basic Auth
# ─────────────────────────────────────────────────────────────────


class BasicAuth(AuthProvider):
    """
    HTTP Basic authentication
    """

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        return {
            "cookies": {},
            "headers": {"Authorization": f"Basic {credentials}"},
            "authenticated": True,
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# API Key
# ─────────────────────────────────────────────────────────────────


class APIKeyAuth(AuthProvider):
    """
    API Key authentication (custom Header)
    """

    def __init__(self, key: str, header_name: str = "X-API-Key"):
        self.key = key
        self.header_name = header_name

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        return {
            "cookies": {},
            "headers": {self.header_name: self.key},
            "authenticated": True,
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# Cookie Auth (directly inject existing cookies)
# ─────────────────────────────────────────────────────────────────


class CookieAuth(AuthProvider):
    """
    Directly inject Cookies (manually obtained or copied from browser)
    """

    def __init__(self, cookies: Dict[str, str]):
        if isinstance(cookies, str):
            # Supports "PHPSESSID=abc; user=admin" formatted strings
            self.cookie_dict = {}
            for part in cookies.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.cookie_dict[k.strip()] = v.strip()
        else:
            self.cookie_dict = cookies

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        # Directly set cookies on session
        for name, value in self.cookie_dict.items():
            session.cookies.set(name, value)
        return {
            "cookies": self.cookie_dict,
            "headers": {},
            "authenticated": True,
            "error": None,
        }


# ─────────────────────────────────────────────────────────────────
# Auth Manager
# ─────────────────────────────────────────────────────────────────


class AuthManager:
    """
    Authentication manager

    Unified management of the authentication workflow:
    1. Build AuthProvider
    2. Execute authentication
    3. Inject authentication result into ScanTarget
    4. Verify authentication status
    """

    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self._provider: Optional[AuthProvider] = None
        self._auth_result: Dict[str, Any] = {}

    def configure_form_login(
        self,
        login_url: str,
        username: str,
        password: str,
        **kwargs,
    ) -> "AuthManager":
        """Configure form login"""
        self._provider = FormLoginAuth(
            login_url=login_url,
            username=username,
            password=password,
            **kwargs,
        )
        return self

    def configure_bearer(self, token: str, header_name: str = "Authorization") -> "AuthManager":
        self._provider = BearerTokenAuth(token=token, header_name=header_name)
        return self

    def configure_basic(self, username: str, password: str) -> "AuthManager":
        self._provider = BasicAuth(username=username, password=password)
        return self

    def configure_api_key(self, key: str, header_name: str = "X-API-Key") -> "AuthManager":
        self._provider = APIKeyAuth(key=key, header_name=header_name)
        return self

    def configure_cookies(self, cookies: Dict[str, str]) -> "AuthManager":
        self._provider = CookieAuth(cookies=cookies)
        return self

    async def authenticate(self, session: httpx.AsyncClient) -> Dict[str, Any]:
        """
        Execute authentication and return auth info

        Returns:
            dict, same as AuthProvider.authenticate() return value
        """
        if not self._provider:
            logger.warning("[AuthManager] No authentication method configured")
            return {"cookies": {}, "headers": {}, "authenticated": False, "error": "No auth configured"}

        self._auth_result = await self._provider.authenticate(session)
        return self._auth_result

    def apply_to_target(self, target: ScanTarget) -> ScanTarget:
        """
        Apply authentication result to ScanTarget

        Modifies target.cookies and target.headers
        """
        if not self._auth_result:
            logger.warning("[AuthManager] Authentication has not been performed yet")
            return target

        if self._auth_result.get("cookies"):
            for k, v in self._auth_result["cookies"].items():
                target.cookies[k] = v
                logger.debug(f"[AuthManager] Applied Cookie: {k}=...")

        if self._auth_result.get("headers"):
            target.headers.update(self._auth_result["headers"])
            logger.debug(f"[AuthManager] Applied Header: {list(self._auth_result['headers'].keys())}")

        return target

    @property
    def is_authenticated(self) -> bool:
        return self._auth_result.get("authenticated", False)

    @property
    def auth_error(self) -> Optional[str]:
        return self._auth_result.get("error")

    @property
    def provider_name(self) -> str:
        return self._provider.__class__.__name__ if self._provider else "None"
