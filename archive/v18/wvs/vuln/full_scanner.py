"""WVS v18.0 - 完整扫描器 (集成版)

整合:
- 基础漏洞检测 (SQLi, XSS, CMDi)
- SQLMap (高级 SQL 注入)
- Nuclei (CVE 和配置问题)
- Playwright (JS 渲染 + DOM XSS)
"""
import asyncio
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
import aiohttp

# 导入统一数据模型
from .models import Vulnerability, ScanResult
from .scanner_v18 import EnhancedCrawler, VulnerabilityScanner
from .report_v18 import ReportGeneratorV18
from ..integrations import (
    SQLMapIntegration,
    NucleiIntegration,
    PlaywrightIntegration,
    DOMXSSVulnerability
)
from ..modules.cmdi import CommandInjectionScanner
from ..modules.lfi import LFIScanner, PHPLiteAdminScanner
from ..modules.log_poison import LogPoisonScanner
from ..modules.auth import AuthHandler
from ..modules.auth.login_sqli_scanner import LoginSqliScanner
from ..modules.exploit import ExploitEngine
from ..modules.waf import WAFDetector, get_bypass_payloads


class FullScanner:
    """完整扫描器 - 集成多种扫描引擎"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # 各模块配置
        self.max_depth = self.config.get("max_depth", 3)
        self.max_urls = self.config.get("max_urls", 200)
        self.timeout = self.config.get("timeout", 15)
        self.delay = self.config.get("delay", 0.1)
        
        # 启用哪些扫描器
        self.enable_basic = self.config.get("enable_basic", True)  # 基础扫描器
        self.enable_sqlmap = self.config.get("enable_sqlmap", True)  # SQLMap
        self.enable_nuclei = self.config.get("enable_nuclei", True)  # Nuclei
        self.enable_playwright = self.config.get("enable_playwright", True)  # Playwright
        
        # 模块实例
        self.crawler = EnhancedCrawler({
            "max_depth": self.max_depth,
            "max_urls": self.max_urls,
            "timeout": self.timeout,
            "delay": self.delay
        })
        self.scanner = VulnerabilityScanner({"timeout": self.timeout, "delay": self.delay})
        self.sqlmap = SQLMapIntegration({"level": 2, "risk": 1})
        self.nuclei = NucleiIntegration()
        self.playwright = PlaywrightIntegration({"timeout": self.timeout * 1000})
        self.cmdi_scanner = CommandInjectionScanner({"timeout": self.timeout, "delay": self.delay})
        self.log_poison_scanner = LogPoisonScanner({"timeout": self.timeout, "delay": self.delay})
        self.phpliteadmin_scanner = PHPLiteAdminScanner({"timeout": self.timeout, "delay": self.delay})
        self.auth_handler = AuthHandler()
        self.login_sqli_scanner = LoginSqliScanner(timeout=self.timeout, delay=self.delay)
        self.waf_detector = WAFDetector(timeout=self.timeout)
        
        # WAF 状态
        self.waf_detected = False
        self.waf_type = ""
        
        # 认证
        self.session_cookies: Dict = {}
        self.session_headers: Dict = {}
    
    def set_auth(self, cookies: Dict = None, headers: Dict = None):
        """设置认证信息"""
        if cookies:
            self.session_cookies.update(cookies)
        if headers:
            self.session_headers.update(headers)
        
        self.crawler.set_auth(cookies, headers)
        self.scanner.set_auth(cookies, headers)

    def _get_bypass_payloads(self, vuln_type: str) -> list:
        "Get WAF bypass payloads for the detected WAF type."
        from ..modules.waf import get_bypass_payloads
        
        # Get bypass payloads
        bypass_list = get_bypass_payloads(self.waf_type, vuln_type)
        
        if not bypass_list:
            return None
        
        # Convert to the format expected by scanner
        if vuln_type == 'sqli':
            # Format: (payload, check_str, sqli_type)
            return [(p, '', 'union-based') for p in bypass_list]
        elif vuln_type == 'xss':
            # Format: (payload, xss_type)
            return [(p, 'reflected') for p in bypass_list]
        
        return None
    
    
    async def _add_and_exploit_vulnerability(self, result: ScanResult, vuln: Vulnerability):
        """添加漏洞并立即尝试利用"""
        result.vulnerabilities.append(vuln)
        
        # 只对高危漏洞进行利用尝试
        if vuln.severity in ["critical", "high"] and vuln.confidence >= 0.7:
            try:
                print(f"    [!] Attempting to exploit: {vuln.type}")
                exploit_result = await self.exploit_engine.exploit({
                    'type': vuln.type,
                    'url': vuln.url,
                    'parameter': vuln.parameter,
                    'payload': vuln.payload,
                    'evidence': vuln.evidence,
                    'severity': vuln.severity,
                    'attacker_ip': '127.0.0.1',
                    'attacker_port': 4444
                })
                
                if exploit_result['success']:
                    print(f"      [SUCCESS] Exploit successful: {exploit_result['result'][:100]}...")
                    vuln.evidence = f"{vuln.evidence}\n[EXPLOITED] {exploit_result['result']}"
                else:
                    print(f"      [FAILED] Exploit failed: {exploit_result['result'][:100]}")
            except Exception as e:
                print(f"      [ERROR] Exploit error: {e}")
                pass  # 利用失败不影响扫描继续
    async def scan(self, url: str, modules: List[str] = None) -> ScanResult:
        """
        完整扫描
        
        Args:
            url: 目标 URL
            modules: 启用的模块 ["sqli", "xss", "nuclei", "dom-xss"]
                    None 表示全部启用
        """
        modules = modules or ["sqli", "xss", "cmdi", "lfi", "log_poison", "phpliteadmin", "nuclei", "dom-xss"]
        start_time = time.time()
        
        result = ScanResult(target=url)
        
        # 1. 爬取（第一轮，匿名）
        print(f"[*] Crawling: {url}")
        crawl_result = await self.crawler.crawl(url)
        
        result.urls = [u.url for u in crawl_result.urls]
        result.forms = crawl_result.forms
        result.sensitive_paths = crawl_result.sensitive_paths
        
        print(f"    Found: {len(result.urls)} URLs, {len(result.forms)} forms")
        
        # 1.1 WAF 检测
        print(f"[*] Detecting WAF...")
        try:
            waf_result = await self.waf_detector.detect(url)
            if waf_result.detected:
                self.waf_detected = True
                self.waf_type = waf_result.waf_type
                print(f"    [!] WAF Detected: {waf_result.waf_type.upper()} ({waf_result.confidence:.0%})")
                print(f"        Evidence: {waf_result.evidence[:80]}")
                print(f"        Bypass: {waf_result.bypass_method}")
                result.sources.append(f"waf:{waf_result.waf_type}")
            else:
                print(f"    [-] No WAF detected")
        except Exception as e:
            print(f"    [-] WAF detection failed: {e}")
        
        # 1.5 认证检测 - 尝试自动登录
        authed = False
        auth_login_url = self._find_login_url(url, crawl_result.forms)
        if auth_login_url:
            print(f"[*] Attempting authentication at {auth_login_url}")
            # DVWA/Mutillidae 等靶场
            login_result = await self.auth_handler.try_default_creds(
                auth_login_url,
                app_type=self._detect_app_type(auth_login_url),
                check_url=auth_login_url
            )
            if login_result.success:
                print(f"    [+] Auth success: {login_result.username}")
                auth_cookies = login_result.cookies
                authed = True
                # 方案A: 直接复用第一轮爬到的URL列表（已知有效），只加认证header
                # 方案B: 重新爬虫
                # 这里用方案A: 保持已有URL，给爬虫+扫描器设置认证cookie
                self.crawler.set_auth(auth_cookies, None)
                self.scanner.set_auth(auth_cookies, None)
                print(f"    [*] Using {len(result.urls)} pre-discovered URLs with auth")
            else:
                print(f"    [-] Auth failed: {login_result.error}")
        
        # 2. Login Form SQL 注入检测（无错 SQLi — 认证绕过）
        if "sqli" in modules:
            login_sqli_vulns = await self._scan_login_sqli(url, crawl_result)
            result.vulnerabilities.extend(login_sqli_vulns)
            if login_sqli_vulns:
                result.sources.append("login_sqli")

        # 3. 基础漏洞扫描
        if self.enable_basic:
            basic_vulns = await self._scan_basic(url, crawl_result, modules)
            result.vulnerabilities.extend(basic_vulns)
            result.sources.append("basic")
        
        # 3. SQLMap (SQL 注入)
        if self.enable_sqlmap and "sqli" in modules:
            sqlmap_vulns = await self._scan_sqlmap(result.urls)
            result.vulnerabilities.extend(sqlmap_vulns)
            result.sources.append("sqlmap")
        
        # 4. Nuclei (CVE 和配置) — 传入爬取到的 URL
        if self.enable_nuclei and "nuclei" in modules:
            nuclei_vulns = await self._scan_nuclei(url, result.urls)
            result.vulnerabilities.extend(nuclei_vulns)
            result.sources.append("nuclei")
        
        # 5. 命令注入检测 (CMDi)
        if "cmdi" in modules:
            cmdi_vulns = await self._scan_cmdi(crawl_result)
            result.vulnerabilities.extend(cmdi_vulns)
            result.sources.append("cmdi")
        
        # 6. LFI 检测 + Log Poisoning RCE
        if "lfi" in modules:
            lfi_vulns = await self._scan_lfi(crawl_result)
            result.vulnerabilities.extend(lfi_vulns)
            result.sources.append("lfi")
            
            # LFI 成功后尝试 Log Poisoning
            if lfi_vulns and "log_poison" in modules:
                log_poison_vulns = await self._scan_log_poison(url, lfi_vulns)
                result.vulnerabilities.extend(log_poison_vulns)
                result.sources.append("log_poison")
        
        # 7. phpLiteAdmin 专项检测
        if "phpliteadmin" in modules:
            phpliteadmin_vulns = await self._scan_phpliteadmin(url)
            result.vulnerabilities.extend(phpliteadmin_vulns)
            result.sources.append("phpliteadmin")
        
        # 8. Playwright (JS 渲染 + DOM XSS)
        if self.enable_playwright and "dom-xss" in modules:
            dom_vulns = await self._scan_dom_xss(url)
            result.vulnerabilities.extend(dom_vulns)
            result.sources.append("playwright")

        # 9. 认证后扫描 — 登录成功后对会员页进行第二轮扫描
        if authed and self.session_cookies:
            print(f"[*] Running authenticated scan on member pages...")
            authed_vulns = await self._scan_authenticated(url, crawl_result, modules)
            if authed_vulns:
                result.vulnerabilities.extend(authed_vulns)
                result.sources.append("authed")
                print(f"    Authenticated scan found: {len(authed_vulns)} additional vulnerabilities")

        # ── 漏洞去重 ──
        seen: Set[int] = set()
        deduped: List[Vulnerability] = []
        for v in result.vulnerabilities:
            h = hash((v.type, v.url, v.parameter, v.payload))
            if h not in seen:
                seen.add(h)
                deduped.append(v)
        dropped = len(result.vulnerabilities) - len(deduped)
        if dropped > 0:
            print(f"    [DEDUP] Removed {dropped} duplicate vulnerabilities")
        result.vulnerabilities = deduped

        result.duration = time.time() - start_time

        return result
    
    async def _scan_basic(self, url: str, crawl_result, modules: List[str]) -> List[Vulnerability]:
        """基础漏洞扫描"""
        print(f"[*] Running basic vulnerability scan...")
        vulns = []
        
        # WAF bypass payloads
        bypass_sqli = None
        bypass_xss = None
        if self.waf_detected and self.waf_type:
            print(f"    [*] Using WAF bypass payloads for {self.waf_type}")
            bypass_sqli = self._get_bypass_payloads("sqli")
            bypass_xss = self._get_bypass_payloads("xss")
        
        async with aiohttp.ClientSession() as session:
            for url_info in crawl_result.urls:
                # GET 参数
                for param in url_info.params.keys():
                    if "sqli" in modules:
                        sqli_results = await self.scanner.test_sqli(session, url_info.url, param, "GET", custom_payloads=bypass_sqli)
                        for v in sqli_results:
                            vulns.append(Vulnerability(
                                type=v.type,
                                url=v.url,
                                parameter=v.parameter,
                                payload=v.payload,
                                severity=v.severity,
                                confidence=v.confidence,
                                evidence=v.evidence,
                                source="basic"
                            ))
                    
                    if "xss" in modules:
                        xss_results = await self.scanner.test_xss(session, url_info.url, param, "GET", custom_payloads=bypass_xss)
                        for v in xss_results:
                            vulns.append(Vulnerability(
                                type=v.type,
                                url=v.url,
                                parameter=v.parameter,
                                payload=v.payload,
                                severity=v.severity,
                                confidence=v.confidence,
                                source="basic"
                            ))
                
                # 表单
                for form in crawl_result.forms:
                    if form["url"] != url_info.url:
                        continue
                    for input_name in form["inputs"].keys():
                        if "sqli" in modules:
                            sqli_results = await self.scanner.test_sqli(
                                session, form["url"], input_name, form["method"],
                                custom_payloads=bypass_sqli
                            )
                            for v in sqli_results:
                                vulns.append(Vulnerability(
                                    type=v.type,
                                    url=v.url,
                                    parameter=v.parameter,
                                    payload=v.payload,
                                    severity=v.severity,
                                    confidence=v.confidence,
                                    source="basic"
                                ))
                        
                        if "xss" in modules:
                            xss_results = await self.scanner.test_xss(
                                session, form["url"], input_name, form["method"],
                                custom_payloads=bypass_xss
                            )
                            for v in xss_results:
                                vulns.append(Vulnerability(
                                    type=v.type,
                                    url=v.url,
                                    parameter=v.parameter,
                                    payload=v.payload,
                                    severity=v.severity,
                                    confidence=v.confidence,
                                    source="basic"
                                ))
        
        print(f"    Basic scan found: {len(vulns)} vulnerabilities")
        return vulns
    
    async def _scan_sqlmap(self, urls: List[str]) -> List[Vulnerability]:
        """SQLMap SQL 注入扫描 — 在线程池中运行避免阻塞事件循环"""
        print(f"[*] Running SQLMap scan...")
        vulns = []
        
        # 只测试前 5 个 URL（有参数的优先）
        test_urls = [u for u in urls[:20] if "?" in u][:5]
        if not test_urls:
            test_urls = urls[:5]
        
        loop = asyncio.get_event_loop()
        
        for url in test_urls:
            try:
                # 同步 SQLMap 跑在线程池里，不阻塞事件循环
                sqlmap_results = await loop.run_in_executor(
                    None, self.sqlmap.scan, url
                )
                
                for r in sqlmap_results:
                    vulns.append(Vulnerability(
                        type=f"SQL Injection ({r.injection_type})",
                        url=r.url,
                        parameter=r.parameter,
                        payload=r.payload,
                        severity="critical",
                        confidence=r.confidence,
                        evidence=f"DBMS: {r.dbms}, OS: {r.os}",
                        source="sqlmap"
                    ))
                    
            except Exception as e:
                print(f"    SQLMap error: {e}")
                continue
        
        print(f"    SQLMap found: {len(vulns)} vulnerabilities")
        return vulns
    
    async def _scan_nuclei(self, url: str, discovered_urls: List[str] = None) -> List[Vulnerability]:
        """Nuclei CVE 扫描 — 异步版，传入已发现 URL"""
        print(f"[*] Running Nuclei CVE scan...")
        vulns = []
        
        try:
            # 使用异步版本，传入爬取到的 URL（大幅提升检出率）
            nuclei_results = await self.nuclei.scan_async(
                url,
                discovered_urls=discovered_urls,
                cookies=self.session_cookies or None,
                headers=self.session_headers or None,
                severity=["critical", "high", "medium", "info"]
            )
            
            for r in nuclei_results:
                vulns.append(Vulnerability(
                    type=r.name,
                    url=r.matched_at,
                    parameter="",
                    payload="",
                    severity=r.severity,
                    confidence=0.95,
                    evidence=r.description,
                    source="nuclei",
                    cve_id=",".join(r.cve_ids) if r.cve_ids else "",
                    cvss_score=r.cvss_score or 0.0
                ))
                
        except Exception as e:
            print(f"    Nuclei error: {e}")
        
        print(f"    Nuclei found: {len(vulns)} vulnerabilities")
        return vulns
    
    async def _scan_dom_xss(self, url: str) -> List[Vulnerability]:
        """DOM XSS 扫描"""
        print(f"[*] Running DOM XSS scan...")
        vulns = []
        
        try:
            dom_results = await self.playwright.test_dom_xss(url)
            
            for r in dom_results:
                vulns.append(Vulnerability(
                    type="DOM XSS",
                    url=r.url,
                    parameter=r.source,
                    payload=r.payload,
                    severity=r.severity,
                    confidence=0.85,
                    evidence=f"Sink: {r.sink}",
                    source="playwright"
                ))
                
        except Exception as e:
            print(f"    DOM XSS error: {e}")
        
        print(f"    DOM XSS found: {len(vulns)} vulnerabilities")
        return vulns
    
    async def _scan_cmdi(self, crawl_result) -> List[Vulnerability]:
        """命令注入检测 — 带基线对比，避免误报"""
        print(f"[*] Running CMDi scan...")
        vulns = []

        async with aiohttp.ClientSession() as session:
            for url_info in crawl_result.urls:
                for param in url_info.params.keys():
                    try:
                        # 获取基线响应（无注入时的正常响应）
                        _, baseline_content, _ = await self.scanner._send_request(
                            session, url_info.url, "GET", {param: "WVS_BASE"}
                        )
                        # 用基线对比检测，避免误报
                        results = await self.cmdi_scanner.test_reflected(
                            url_info.url, param, "GET", baseline_content=baseline_content
                        )
                        for r in results:
                            vulns.append(Vulnerability(
                                type="Command Injection",
                                url=url_info.url,
                                parameter=param,
                                payload=r.payload,
                                severity="critical",
                                confidence=r.confidence,
                                evidence=r.evidence,
                                source="cmdi"
                            ))
                    except Exception as e:
                        pass

        print(f"    CMDi found: {len(vulns)} vulnerabilities")
        return vulns
    
    async def _scan_lfi(self, crawl_result) -> List[Vulnerability]:
        """LFI 检测"""
        print(f"[*] Running LFI scan...")
        vulns = []
        
        async with aiohttp.ClientSession() as sess:
            for url_info in crawl_result.urls:
                for param in url_info.params.keys():
                    try:
                        results = await self.scanner.test_lfi(sess, url_info.url, param)
                        for r in results:
                            vulns.append(Vulnerability(
                                type=r.type,
                                url=r.url,
                                parameter=r.parameter,
                                payload=r.payload,
                                severity=r.severity,
                                confidence=r.confidence,
                                evidence=r.evidence,
                                source="lfi"
                            ))
                    except Exception as e:
                        pass
        
        print(f"    LFI found: {len(vulns)} vulnerabilities")
        return vulns
    
    async def _scan_log_poison(self, base_url: str, lfi_vulns: List) -> List[Vulnerability]:
        """Log Poisoning RCE 链"""
        print(f"[*] Running Log Poisoning scan...")
        vulns = []
        
        for lfi in lfi_vulns:
            try:
                results = await self.log_poison_scanner.scan(base_url, lfi.parameter)
                for r in results:
                    vulns.append(Vulnerability(
                        type="Log Poisoning RCE",
                        url=base_url,
                        parameter=r.lfi_param,
                        payload=r.payload_type,
                        severity="critical",
                        confidence=r.confidence,
                        evidence=r.response_evidence[:200] if r.response_evidence else r.log_path,
                        source="log_poison"
                    ))
            except Exception as e:
                print(f"    Log Poisoning error: {e}")
        
        print(f"    Log Poisoning found: {len(vulns)} vulnerabilities")
        return vulns
    
    async def _scan_phpliteadmin(self, base_url: str) -> List[Vulnerability]:
        """phpLiteAdmin 专项检测"""
        print(f"[*] Running phpLiteAdmin scan...")
        vulns = []
        
        try:
            results = await self.phpliteadmin_scanner.scan(base_url)
            for r in results:
                vulns.append(Vulnerability(
                    type=r.type,
                    url=r.url,
                    parameter=r.parameter,
                    payload=r.payload,
                    severity=r.severity,
                    confidence=r.confidence,
                    evidence=r.evidence,
                    source="phpliteadmin"
                ))
        except Exception as e:
            print(f"    phpLiteAdmin scan error: {e}")
        
        print(f"    phpLiteAdmin found: {len(vulns)} vulnerabilities")
        return vulns

    async def _scan_authenticated(self, base_url: str, crawl_result, modules: List[str]) -> List[Vulnerability]:
        """认证后会话扫揟 - 用登录后的 cookie 对会员区域进行漏洞检测。场景：DVWA / Mutillidae 等靶机，匿名只能访问登录页，登录后才能摆到 /dvwa/vulnerabilities/sqli/ 等真实漏洞页面。"""
        from urllib.parse import urljoin, urlparse, parse_qs

        vulns = []
        authed_urls = []

        # 策略1：已知会员路径
        known_paths = [
            "/dvwa/vulnerabilities/sqli/",
            "/dvwa/vulnerabilities/sqli/?id=1",
            "/dvwa/vulnerabilities/xss_r/",
            "/dvwa/vulnerabilities/xss_r/?id=1",
            "/dvwa/vulnerabilities/exec/",
            "/dvwa/vulnerabilities/csp/",
            "/dvwa/vulnerabilities/csrf/",
            "/dvwa/vulnerabilities/brute/",
            "/dvwa/vulnerabilities/upload/",
            "/dvwa/vulnerabilities/lfi/",
            "/dvwa/security.php",
            "/mutillidae/index.php?page=user-info.php",
            "/mutillidae/index.php?page=dns-lookup.php",
            "/mutillidae/index.php?page=document-viewer.php",
            "/mutillidae/index.php?page=phpinfo.php",
            "/admin/",
            "/admin/index.php",
            "/account/",
            "/profile.php",
            "/dashboard.php",
        ]
        for path in known_paths:
            authed_urls.append(urljoin(base_url, path))

        # 策略2：追加蜗取到的所有 URL
        for u in crawl_result.urls:
            if u.url not in authed_urls:
                authed_urls.append(u.url)

        print(f"    Scanning {len(authed_urls)} authenticated URLs...")

        async with aiohttp.ClientSession(
            cookies=self.session_cookies,
            headers=self.session_headers
        ) as session:
            for target_url in authed_urls:
                if "login" in target_url.lower() and "page=login" in target_url.lower():
                    continue

                # 验证是否真的进入了会员区（不是被重定向回登录页）
                try:
                    async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                        resp_text = await resp.text()
                        if "password" in resp_text[:300] and "login" in resp_text[:300]:
                            continue
                except Exception:
                    continue

                # 解析参数并检测
                parsed = urlparse(target_url)
                params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

                for param in params.keys():
                    if "sqli" in modules:
                        sqli_results = await self.scanner.test_sqli(session, target_url, param, "GET")
                        for v in sqli_results:
                            vulns.append(Vulnerability(
                                type=v.type, url=target_url, parameter=param,
                                payload=v.payload, severity=v.severity,
                                confidence=v.confidence, evidence=v.evidence,
                                source="authed_sqli"
                            ))

                    if "xss" in modules:
                        xss_results = await self.scanner.test_xss(session, target_url, param, "GET")
                        for v in xss_results:
                            vulns.append(Vulnerability(
                                type=v.type, url=target_url, parameter=param,
                                payload=v.payload, severity=v.severity,
                                confidence=v.confidence, evidence=v.evidence,
                                source="authed_xss"
                            ))

                    if "cmdi" in modules:
                        _, baseline_content, _ = await self.scanner._send_request(
                            session, target_url, "GET", {param: "WVS_BASE"}
                        )
                        cmdi_results = await self.cmdi_scanner.test_reflected(
                            target_url, param, "GET", baseline_content=baseline_content
                        )
                        for r in cmdi_results:
                            vulns.append(Vulnerability(
                                type="Command Injection", url=target_url, parameter=param,
                                payload=r.payload, severity="critical",
                                confidence=r.confidence, evidence=r.evidence,
                                source="authed_cmdi"
                            ))

        return vulns

    def generate_report(self, result: ScanResult, format: str = "html") -> Path:
        """生成报告"""
        report_gen = ReportGeneratorV18()
        
        # 转换漏洞格式
        findings = []
        for v in result.vulnerabilities:
            findings.append({
                "type": v.type,
                "url": v.url,
                "severity": v.severity,
                "parameter": v.parameter,
                "payload": v.payload,
                "confidence": v.confidence,
                "evidence": v.evidence,
                "source": v.source,
                "cve_id": v.cve_id,
                "cvss_score": v.cvss_score
            })
        
        # 添加敏感路径
        for p in result.sensitive_paths:
            findings.append({
                "type": p.get("type", "Sensitive File"),
                "url": p["url"],
                "severity": p.get("severity", "medium"),
                "parameter": "N/A",
                "payload": "N/A",
                "confidence": 0.9
            })
        
        return report_gen.save_report(findings, format=format)

    def _find_login_url(self, base_url: str, forms: list) -> Optional[str]:
        """从爬取的表单中找登录表单 URL"""
        from urllib.parse import urljoin
        for form in forms:
            action = form.get("url", "")
            if not action:
                continue
            inputs = [k.lower() for k in form.get("inputs", {}).keys()]
            has_user = any(k in inputs for k in ["username", "user", "email", "login"])
            has_pass = "password" in inputs
            if has_user and has_pass and "login" in action.lower():
                return action
        # 兜底：常见登录路径
        common = [
            urljoin(base_url, "/dvwa/login.php"),
            urljoin(base_url, "/mutillidae/index.php?page=login.php"),
            urljoin(base_url, "/login.php"),
            urljoin(base_url, "/admin/login.php"),
        ]
        for u in common:
            return u  # 直接返回第一个（靶机几乎都有 dvwa）
        return None

    def _detect_app_type(self, login_url: str) -> str:
        """从登录 URL 推断应用类型"""
        url_lower = login_url.lower()
        if "dvwa" in url_lower:
            return "dvwa"
        if "mutillidae" in url_lower:
            return "mutillidae"
        if "phpmyadmin" in url_lower:
            return "phpmyadmin"
        if "tomcat" in url_lower:
            return "tomcat"
        return "admin"

    async def _scan_login_sqli(self, base_url: str, crawl_result) -> List[Vulnerability]:
        """
        登录表单 SQL 注入检测（认证绕过 / 无错 SQLi）。

        策略：
        1. 从爬取的表单中找 login 表单
        2. 兜底：常见登录路径（dvwa, mutillidae, admin/login.php 等）
        3. 对每个 login URL 调用 LoginSqliScanner
        4. 命中后转换为 Vulnerability 格式
        """
        print(f"[*] Running Login SQLi scan...")
        vulns = []
        login_urls: List[str] = []

        # 策略1：从爬取的表单中找
        for form in crawl_result.forms:
            action = form.get("url", "")
            if not action:
                continue
            inputs = {k.lower(): v for k, v in form.get("inputs", {}).items()}
            has_user = any(k in inputs for k in [
                "username", "user", "user_name", "email", "login", "account"])
            has_pass = "password" in inputs or "pass" in inputs or "pwd" in inputs
            if has_user and has_pass:
                login_urls.append(action)

        # 策略2：常见登录路径
        from urllib.parse import urljoin
        common_login_paths = [
            "/dvwa/login.php",
            "/dvwa/",
            "/mutillidae/index.php?page=login.php",
            "/login.php",
            "/admin/login.php",
            "/admin/index.php",
            "/index.php?page=login",
        ]
        for path in common_login_paths:
            full_url = urljoin(base_url, path)
            if full_url not in login_urls:
                login_urls.append(full_url)

        # 去重
        login_urls = list(dict.fromkeys(login_urls))
        print(f"    Testing {len(login_urls)} login URL(s)")

        for login_url in login_urls:
            try:
                results = await self.login_sqli_scanner.scan(login_url)
                for r in results:
                    # 确认绕过（session validated）
                    sev = "critical" if r.confidence >= 0.9 else \
                          "high" if r.confidence >= 0.7 else \
                          "medium" if r.confidence >= 0.4 else "low"
                    vulns.append(Vulnerability(
                        type=f"SQL Injection (Login Bypass — {r.sqli_type})",
                        url=r.url,
                        parameter=r.field,
                        payload=r.payload,
                        severity=sev,
                        confidence=r.confidence,
                        evidence=r.evidence,
                        source="login_sqli"
                    ))
                    print(f"    [!] Login SQLi found: {r.url}")
                    print(f"        payload: {r.payload[:40]}  confidence: {r.confidence:.0%}")
                    print(f"        evidence: {r.evidence[:80]}")
            except Exception as e:
                print(f"    [-] Login SQLi error on {login_url}: {e}")

        print(f"    Login SQLi found: {len(vulns)} vulnerabilities")
        return vulns


# 异步入口
async def scan_async(url: str, config: Dict = None) -> ScanResult:
    """异步扫描"""
    scanner = FullScanner(config)
    return await scanner.scan(url)


# 同步入口
def scan(url: str, config: Dict = None) -> ScanResult:
    """同步扫描"""
    return asyncio.run(scan_async(url, config))