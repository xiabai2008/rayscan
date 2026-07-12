"""
Lab target profiles — isolates lab-specific paths/auth from core scanner.

Each profile defines known vulnerable endpoints for a specific lab target.
The scanner loads these ONLY when the target matches the profile's host/URL pattern.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class LabEndpoint:
    path: str
    method: str = "GET"
    params: Dict[str, str] = field(default_factory=dict)
    param_types: Dict[str, str] = field(default_factory=dict)


@dataclass
class LabProfile:
    name: str
    description: str
    host_patterns: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)
    login_path: Optional[str] = None
    login_method: str = "POST"
    login_params: Dict[str, str] = field(default_factory=dict)
    login_success_marker: Optional[str] = None
    endpoints: List[LabEndpoint] = field(default_factory=list)
    default_security_level: Optional[str] = None
    ip_ranges: List[str] = field(default_factory=list)
    fingerprint_paths: List[str] = field(default_factory=list)


# ── Predefined lab profiles ──

DVWA_PROFILE = LabProfile(
    name="dvwa",
    description="Damn Vulnerable Web Application",
    host_patterns=["dvwa", "localhost", "172.17.43.129", "47.95.192.41"],
    url_patterns=["/dvwa/", "/DVWA/"],
    login_path="/login.php",
    login_method="POST",
    login_params={"username": "admin", "password": "password", "Login": "Login"},
    login_success_marker="Welcome",
    default_security_level="low",
    endpoints=[
        LabEndpoint(
            "/vulnerabilities/sqli/",
            params={"id": "1", "Submit": "Submit"},
            param_types={"id": "query", "Submit": "query"},
        ),
        LabEndpoint(
            "/vulnerabilities/sqli_blind/",
            params={"id": "1", "Submit": "Submit"},
            param_types={"id": "query", "Submit": "query"},
        ),
        LabEndpoint("/vulnerabilities/xss_r/", params={"name": "test"}, param_types={"name": "query"}),
        LabEndpoint(
            "/vulnerabilities/xss_s/",
            method="POST",
            params={"txtName": "test", "mtxMessage": "test", "btnSign": "Sign"},
            param_types={"txtName": "body", "mtxMessage": "body", "btnSign": "body"},
        ),
        LabEndpoint("/vulnerabilities/xss_d/", params={"default": "English"}, param_types={"default": "query"}),
        LabEndpoint("/vulnerabilities/fi/", params={"page": "include.php"}, param_types={"page": "query"}),
        LabEndpoint(
            "/vulnerabilities/exec/",
            method="POST",
            params={"ip": "127.0.0.1", "Submit": "Submit"},
            param_types={"ip": "body", "Submit": "body"},
        ),
        LabEndpoint(
            "/vulnerabilities/brute/",
            params={"username": "admin", "password": "password", "Login": "Login"},
            param_types={"username": "query", "password": "query", "Login": "query"},
        ),
        LabEndpoint(
            "/vulnerabilities/csrf/",
            params={"password_new": "test", "password_conf": "test", "Change": "Change"},
            param_types={"password_new": "query", "password_conf": "query", "Change": "query"},
        ),
        LabEndpoint("/vulnerabilities/upload/", method="POST", params={}, param_types={}),
        LabEndpoint(
            "/vulnerabilities/csp/", method="POST", params={"include": "test"}, param_types={"include": "body"}
        ),
        LabEndpoint(
            "/vulnerabilities/javascript/",
            method="POST",
            params={"token": "test", "phrase": "test", "send": "Submit"},
            param_types={"token": "body", "phrase": "body", "send": "body"},
        ),
    ],
)

MUTILLIDAE_PROFILE = LabProfile(
    name="mutillidae",
    description="OWASP Mutillidae II",
    host_patterns=["mutillidae", "localhost"],
    url_patterns=["/mutillidae/"],
    endpoints=[
        LabEndpoint("/index.php?page=text-file-viewer.php", params={"text": "test"}, param_types={"text": "query"}),
        LabEndpoint(
            "/index.php?page=login.php",
            params={"username": "test", "password": "test"},
            param_types={"username": "query", "password": "query"},
        ),
        LabEndpoint("/index.php?page=user-info.php", params={"username": "test"}, param_types={"username": "query"}),
        LabEndpoint(
            "/index.php?page=register.php",
            params={"username": "test", "password": "test"},
            param_types={"username": "query", "password": "query"},
        ),
        LabEndpoint(
            "/index.php?page=dns-lookup.php", params={"target_host": "127.0.0.1"}, param_types={"target_host": "query"}
        ),
        LabEndpoint(
            "/index.php?page=add-to-your-blog.php", params={"blog_entry": "test"}, param_types={"blog_entry": "query"}
        ),
        LabEndpoint(
            "/index.php?page=sqlmap-targets.php", params={"username": "test"}, param_types={"username": "query"}
        ),
        LabEndpoint(
            "/index.php?page=captcha.php",
            params={"username": "test", "password": "test"},
            param_types={"username": "query", "password": "query"},
        ),
    ],
)

METASPLOITABLE2_PROFILE = LabProfile(
    name="metasploitable2",
    description="Metasploitable 2 Linux",
    host_patterns=["metasploitable"],
    ip_ranges=["172.", "192.168.", "10."],
    url_patterns=["/mutillidae/", "/dav/", "/phpMyAdmin/", "/dvwa/", "/twiki/", "/tikiwiki/"],
    fingerprint_paths=["/mutillidae/", "/dvwa/", "/phpMyAdmin/", "/dav/", "/twiki/", "/tikiwiki/"],
    login_path="/login.php",
    login_method="POST",
    login_params={"username": "admin", "password": "password", "Login": "Login"},
    login_success_marker="Welcome",
    default_security_level="low",
    endpoints=[
        # ── Mutillidae ──
        LabEndpoint(
            "/mutillidae/index.php?page=text-file-viewer.php", params={"text": "test"}, param_types={"text": "query"}
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=login.php",
            params={"username": "test", "password": "test"},
            param_types={"username": "query", "password": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=user-info.php", params={"username": "test"}, param_types={"username": "query"}
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=dns-lookup.php",
            params={"target_host": "127.0.0.1"},
            param_types={"target_host": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=add-to-your-blog.php",
            params={"blog_entry": "test"},
            param_types={"blog_entry": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=sqlmap-targets.php",
            params={"username": "test"},
            param_types={"username": "query"},
        ),
        LabEndpoint("/mutillidae/index.php?page=show-log.php", params={}, param_types={}),
        LabEndpoint(
            "/mutillidae/index.php?page=source-viewer.php",
            params={"filename": "test"},
            param_types={"filename": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=poll-questionaire.php",
            params={"choice": "test"},
            param_types={"choice": "query"},
        ),
        # P11: Additional Mutillidae endpoints for CSRF, file upload, etc.
        LabEndpoint(
            "/mutillidae/index.php?page=register.php",
            params={"username": "test", "password": "test", "confirm_password": "test"},
            param_types={"username": "query", "password": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=captcha.php",
            params={"username": "test", "password": "test"},
            param_types={"username": "query", "password": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=pen-test-tool-lookup.php",
            params={"tool": "nmap", "target": "127.0.0.1"},
            param_types={"tool": "query", "target": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=html5-storage.php",
            params={"key": "test", "value": "test"},
            param_types={"key": "query", "value": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=client-side-control-challenge.php",
            params={"price": "100"},
            param_types={"price": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=view-someones-blog.php",
            params={"author": "test"},
            param_types={"author": "query"},
        ),
        LabEndpoint(
            "/mutillidae/index.php?page=arbitrary-file-inclusion.php",
            params={"page": "include.php"},
            param_types={"page": "query"},
        ),
        # ── DVWA (on Metasploitable2 at /dvwa/) ──
        LabEndpoint(
            "/dvwa/vulnerabilities/sqli/",
            params={"id": "1", "Submit": "Submit"},
            param_types={"id": "query", "Submit": "query"},
        ),
        LabEndpoint(
            "/dvwa/vulnerabilities/sqli_blind/",
            params={"id": "1", "Submit": "Submit"},
            param_types={"id": "query", "Submit": "query"},
        ),
        LabEndpoint("/dvwa/vulnerabilities/xss_r/", params={"name": "test"}, param_types={"name": "query"}),
        LabEndpoint(
            "/dvwa/vulnerabilities/xss_s/",
            method="POST",
            params={"txtName": "test", "mtxMessage": "test", "btnSign": "Sign"},
            param_types={"txtName": "body", "mtxMessage": "body", "btnSign": "body"},
        ),
        LabEndpoint("/dvwa/vulnerabilities/xss_d/", params={"default": "English"}, param_types={"default": "query"}),
        LabEndpoint("/dvwa/vulnerabilities/fi/", params={"page": "include.php"}, param_types={"page": "query"}),
        LabEndpoint(
            "/dvwa/vulnerabilities/exec/",
            method="POST",
            params={"ip": "127.0.0.1", "Submit": "Submit"},
            param_types={"ip": "body", "Submit": "body"},
        ),
        LabEndpoint("/dvwa/vulnerabilities/upload/", method="POST", params={}, param_types={}),
        LabEndpoint(
            "/dvwa/vulnerabilities/csrf/",
            params={"password_new": "test", "password_conf": "test", "Change": "Change"},
            param_types={"password_new": "query", "password_conf": "query"},
        ),
        LabEndpoint(
            "/dvwa/vulnerabilities/brute/",
            params={"username": "admin", "password": "password", "Login": "Login"},
            param_types={"username": "query", "password": "query"},
        ),
        LabEndpoint(
            "/dvwa/vulnerabilities/csp/", method="POST", params={"include": "test"}, param_types={"include": "body"}
        ),
        LabEndpoint(
            "/dvwa/vulnerabilities/javascript/",
            method="POST",
            params={"token": "test", "phrase": "test", "send": "Submit"},
            param_types={"token": "body", "phrase": "body", "send": "body"},
        ),
        # ── TWiki ──
        LabEndpoint("/twiki/bin/view/Main/WebHome", params={}, param_types={}),
        LabEndpoint("/twiki/bin/view/TWiki/WebHome", params={}, param_types={}),
        LabEndpoint("/twiki/bin/view", params={}, param_types={}),
        LabEndpoint("/twiki/bin/configure", params={}, param_types={}),
        LabEndpoint("/twiki/bin/edit/Main/WebHome", params={"text": "test"}, param_types={"text": "body"}),
        LabEndpoint("/tikiwiki/tiki-index.php", params={"page": "test"}, param_types={"page": "query"}),
        # ── phpMyAdmin ──
        LabEndpoint("/phpMyAdmin/", method="GET", params={}, param_types={}),
        LabEndpoint(
            "/phpMyAdmin/index.php",
            params={"pma_username": "root", "pma_password": ""},
            param_types={"pma_username": "query", "pma_password": "query"},
        ),
        # P11: phpMyAdmin default credentials check
        LabEndpoint(
            "/phpMyAdmin/index.php",
            method="POST",
            params={"pma_username": "root", "pma_password": "", "server": "1", "target": "index.php"},
            param_types={"pma_username": "body", "pma_password": "body"},
        ),
        LabEndpoint(
            "/phpMyAdmin/index.php",
            params={"pma_username": "root", "pma_password": "root"},
            param_types={"pma_username": "query", "pma_password": "query"},
        ),
        # ── WebDAV ──
        LabEndpoint("/dav/", method="GET", params={}, param_types={}),
        LabEndpoint("/dav/", method="PROPFIND", params={}, param_types={}),
        LabEndpoint("/dav/", method="PUT", params={}, param_types={}),
    ],
)

PIKACHU_PROFILE = LabProfile(
    name="pikachu",
    description="Pikachu vulnerability practice platform",
    host_patterns=["pikachu", "localhost"],
    url_patterns=["/pikachu/"],
    endpoints=[
        LabEndpoint(
            "/pikachu/vul/sqli/sqli_id.php",
            params={"id": "1", "submit": "查询"},
            param_types={"id": "query", "submit": "query"},
        ),
        LabEndpoint(
            "/pikachu/vul/sqli/sqli_search.php",
            params={"name": "test", "submit": "搜索"},
            param_types={"name": "query", "submit": "query"},
        ),
        LabEndpoint(
            "/pikachu/vul/xss/xss_reflected_get.php",
            params={"message": "test", "submit": "submit"},
            param_types={"message": "query", "submit": "query"},
        ),
        LabEndpoint(
            "/pikachu/vul/xss/xss_post.php",
            params={"message": "test", "submit": "submit"},
            param_types={"message": "body", "submit": "body"},
        ),
        LabEndpoint(
            "/pikachu/vul/rce/rce_ping.php",
            params={"ipaddress": "127.0.0.1", "submit": "Ping"},
            param_types={"ipaddress": "query", "submit": "query"},
        ),
        LabEndpoint(
            "/pikachu/vul/rce/rce_eval.php",
            params={"txt": "test", "submit": "提交"},
            param_types={"txt": "body", "submit": "body"},
        ),
        LabEndpoint(
            "/pikachu/vul/fileinclude/fi_local.php",
            params={"filename": "include.php", "submit": "提交"},
            param_types={"filename": "query", "submit": "query"},
        ),
        LabEndpoint(
            "/pikachu/vul/ssrf/ssrf_curl.php",
            params={"url": "http://127.0.0.1", "submit": "提交"},
            param_types={"url": "query", "submit": "query"},
        ),
        LabEndpoint(
            "/pikachu/vul/xxe/xxe_1.php",
            params={"xml": "<test/>", "submit": "提交"},
            param_types={"xml": "body", "submit": "body"},
        ),
    ],
)

# Registry of all known lab profiles
ALL_PROFILES: Dict[str, LabProfile] = {
    "dvwa": DVWA_PROFILE,
    "mutillidae": MUTILLIDAE_PROFILE,
    "metasploitable2": METASPLOITABLE2_PROFILE,
    "pikachu": PIKACHU_PROFILE,
}


def detect_lab_profile(base_url: str) -> Optional[LabProfile]:
    """Auto-detect which lab profile matches the target URL."""
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    host = parsed.netloc.lower()
    path = parsed.path.lower()

    for name, profile in ALL_PROFILES.items():
        host_match = any(p.lower() in host for p in profile.host_patterns)
        url_match = any(p.lower() in path for p in profile.url_patterns)
        ip_match = any(host.startswith(r) for r in profile.ip_ranges) if profile.ip_ranges else False
        if host_match or url_match or ip_match:
            return profile
    return None


def detect_lab_profile_from_paths(base_url: str, discovered_paths: List[str]) -> Optional[LabProfile]:
    """Detect lab profile from discovered URL paths (for IP-based targets)."""
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    host = parsed.netloc.lower()

    for name, profile in ALL_PROFILES.items():
        host_match = any(p.lower() in host for p in profile.host_patterns)
        if host_match:
            return profile
        for dpath in discovered_paths:
            dpath_lower = dpath.lower()
            if any(p.lower() in dpath_lower for p in profile.url_patterns):
                return profile
    return None


def get_lab_endpoints(profile: LabProfile, base_url: str) -> list:
    """Generate endpoint URLs from a lab profile."""
    from urllib.parse import urlparse

    from .crawler import DiscoveredEndpoint

    base = base_url.rstrip("/")
    base_parsed = urlparse(base)
    base_path = base_parsed.path
    endpoints = []
    for ep in profile.endpoints:
        # Avoid double prefix: if base already contains /dvwa/ and ep adds /dvwa/...,
        # strip the duplicate prefix from ep.path
        ep_path = ep.path
        if base_path and base_path != "/":
            # Check if ep.path starts with a segment that's already in base_path
            for seg in [s for s in base_path.strip("/").split("/") if s]:
                if ep_path.startswith(f"/{seg}/") and f"/{seg}/" in base_path:
                    ep_path = ep_path[len(f"/{seg}/") :]
                    break
                elif ep_path.startswith(f"/{seg}"):
                    ep_path = ep_path[len(f"/{seg}") :]
                    break
        full_url = base + ep_path
        endpoints.append(
            DiscoveredEndpoint(
                url=full_url,
                method=ep.method,
                parameters=ep.params.copy() if ep.params else {},
                param_types=ep.param_types.copy() if ep.param_types else {},
                source_url=base_url,
                source_depth=1,
            )
        )
    return endpoints
