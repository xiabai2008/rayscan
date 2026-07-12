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
from typing import Any, Dict, List, Optional

from ..base import DetectionModule, ModuleInfo, register_module
from ...models import Vulnerability, VulnerabilityType, Severity, Confidence, ScanTarget

logger = logging.getLogger("wvs.module.oa")

# ── OA 系统指纹与检测规则 ──────────────────────────────────────
# 每个 OA 系统的识别路径、关键词、检测端点

OA_RULES: Dict[str, dict] = {
    "泛微-Ecology": {
        "paths": ["/weaver/", "/ecology/", "/wui/"],
        "keywords": ["weaver", "ecology", "e-cology", "eoffice"],
        "checks": [
            {"path": "/weaver/weaver.file.FileDownloadForOutDoc", "params": {"isFromOutDoc": "true", "downloadFileId": "../../../../etc/passwd"}, "type": "lfi", "severity": "high"},
            {"path": "/api/portal/weaver/weaver.do", "method": "POST", "type": "rce", "severity": "critical"},
            {"path": "/workflow/WorkflowCenterTreeData.jsp", "params": {"nodeid": "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"}, "type": "sqli", "severity": "high"},
        ],
    },
    "通达OA": {
        "paths": ["/ispirit/", "/mac/", "/general/", "/templates/"],
        "keywords": ["tongda", "通达", "td_", "/general/"],
        "checks": [
            {"path": "/ispirit/remotelogin.php", "params": {"type": "mobile"}, "type": "auth_bypass", "severity": "critical"},
            {"path": "/mac/gateway.php", "params": {"json": "{\"id\":\"1' AND 1=1--\"}"}, "type": "sqli", "severity": "high"},
            {"path": "/general/document/index.php", "type": "sqli", "severity": "medium"},
        ],
    },
    "金蝶-Kingdee": {
        "paths": ["/kingdee/", "/k3cloud/", "/k3/"],
        "keywords": ["kingdee", "金蝶", "k3cloud"],
        "checks": [
            {"path": "/k3cloud/Kingdee.BOS.ServiceFacade.ServicesStub.InstallService.CommonInstallService.commoninstallService.commoninstallServiceHttpFlowService", "type": "rce", "severity": "critical"},
        ],
    },
    "蓝凌-Landray": {
        "paths": ["/landray/", "/sys/", "/km/"],
        "keywords": ["landray", "蓝凌", "ekp"],
        "checks": [
            {"path": "/sys/ui/extend/varkind/custom_pf.jsp", "params": {"var": "1"}, "type": "file_read", "severity": "high"},
        ],
    },
    "致远-Seeyon": {
        "paths": ["/seeyon/", "/yyoa/"],
        "keywords": ["seeyon", "致远", "yyoa"],
        "checks": [
            {"path": "/seeyon/htmlofficeservlet", "type": "rce", "severity": "critical"},
            {"path": "/seeyon/thirdpartyController.do", "type": "rce", "severity": "critical"},
        ],
    },
    "用友-Yonyou": {
        "paths": ["/yonyou/", "/ufida/", "/nc/"],
        "keywords": ["yonyou", "用友", "ufida", "nccloud"],
        "checks": [
            {"path": "/servlet/~uapss/uploadServlet", "type": "rce", "severity": "critical"},
        ],
    },
    "禅道-Zentao": {
        "paths": ["/zentao/", "/chanzhi/"],
        "keywords": ["zentao", "禅道", "zentaopms"],
        "checks": [
            {"path": "/zentao/api-getModel-api-sql.json", "params": {"sql": "select+1"}, "type": "sqli", "severity": "critical"},
        ],
    },
    "万户-Whir": {
        "paths": ["/whir/", "/defaultroot/"],
        "keywords": ["whir", "万户"],
        "checks": [
            {"path": "/defaultroot/uploadFile.jsp", "type": "file_upload", "severity": "high"},
        ],
    },
    "Nacos": {
        "paths": ["/nacos/"],
        "keywords": ["nacos"],
        "checks": [
            {"path": "/nacos/v1/auth/users?pageNo=1&pageSize=10", "type": "unauth", "severity": "critical"},
            {"path": "/nacos/v1/cs/configs?dataId=&group=&appName=&config_tags=&pageNo=1&pageSize=10", "type": "unauth", "severity": "high"},
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

        # Step 1: 识别 OA 类型
        detected_oa = self._detect_oa_type(url)

        if not detected_oa:
            self.logger.info("[OA] 未识别到已知 OA 系统，执行通用 OA 检测")
            # 通用检测: 对所有 OA 的通用路径做轻量检查
            return await self._check_common_oa_paths(url, target)

        self.logger.info(f"[OA] 识别到: {detected_oa}")

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

    def _detect_oa_type(self, url: str) -> Optional[str]:
        """
        从 URL 中识别 OA 系统类型

        优先路径匹配，其次关键词匹配
        """
        url_lower = url.lower()

        for oa_name, rule in OA_RULES.items():
            # 路径匹配
            for path in rule["paths"]:
                if path.rstrip("/") in url_lower:
                    self.logger.debug(f"[OA] 路径匹配 → {oa_name}: {path}")
                    return oa_name
            # 关键词匹配
            for kw in rule["keywords"]:
                if kw.lower() in url_lower:
                    self.logger.debug(f"[OA] 关键词匹配 → {oa_name}: {kw}")
                    return oa_name

        return None

    async def _run_check(self, base_url: str, check: dict, target: ScanTarget) -> Optional[Vulnerability]:
        """执行单条 OA 检测规则"""
        path = check["path"]
        check_url = base_url.rstrip("/") + path
        method = check.get("method", "GET")
        vuln_type_str = check.get("type", "info")
        severity_str = check.get("severity", "info")
        params = check.get("params", {})

        vuln_type = VULN_TYPE_MAP.get(vuln_type_str, VulnerabilityType.OTHER)
        severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

        try:
            resp = await self._send_request(method, check_url, params)

            if resp and resp.get("status_code") and resp["status_code"] not in (404, 400, 0):
                status = resp["status_code"]
                body = resp.get("text", "")

                # 不同类型有不同的判断逻辑
                found = False
                if status == 200:
                    # 对于信息泄露类，检查响应内容是否合理
                    if vuln_type_str == "info_disclosure":
                        if len(body) > 50 and "error" not in body[:200].lower():
                            found = True
                    elif vuln_type_str == "unauth":
                        if status == 200:
                            found = True
                    else:
                        found = True
                elif status in (401, 403):
                    # 需要认证但暴露了路径
                    if vuln_type_str == "unauth":
                        found = True
                elif status in (500, 302):
                    found = True

                if found:
                    return self._create_vuln(
                        url=check_url,
                        param=list(params.keys())[0] if params else None,
                        param_type="query",
                        method=method,
                        payload=check_url,
                        vuln_type=vuln_type_str,
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

    async def _check_common_oa_paths(self, base_url: str, target: ScanTarget) -> List[Vulnerability]:
        """通用 OA 路径检查 — 对所有 OA 都执行的基础检测"""
        vulns = []
        common_paths = [
            # 常见 OA 入口
            "/admin/", "/login/", "/system/", "/api/", "/webservice/",
            # 常见泄露路径
            "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
            "/.git/HEAD", "/.env", "/backup/",
        ]

        for path in common_paths:
            check_url = base_url.rstrip("/") + path
            try:
                resp = await self._send_request("GET", check_url, {})
                if resp and resp.get("status_code") in (200, 401, 403):
                    status = resp["status_code"]
                    severity = Severity.INFO if status in (401, 403) else Severity.LOW
                    vulns.append(self._create_vuln(
                        url=check_url,
                        param=None,
                        param_type="query",
                        method="GET",
                        payload="",
                        vuln_type="info_disclosure",
                        severity=severity,
                        confidence=Confidence.LOW,
                        evidence=f"HTTP {status}",
                        description=f"发现 OA 路径: {check_url}",
                        recommendation="限制敏感路径的外部访问",
                    ))
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
