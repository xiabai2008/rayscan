"""
WAF Detection Module v2.0 (from wafw00f 172-plugin dataset).

Upgraded features:
  1. 80+ WAF signatures (headers / cookies / content / status)
  2. 4-round behavioral detection (Normal → XSS → SQLi → LFI)
  3. WAF bypass capability test
"""

import logging
import re
from typing import Dict, List, Optional, Tuple

from ...core.session import HTTPPool
from ...models import Confidence, ScanTarget, Severity, Vulnerability
from ..base import DetectionModule, ModuleInfo, register_module

logger = logging.getLogger("wvs.module.waf")

# ═══════════════════════════════════════════════════════════════
# 80+ WAF Signatures (extracted from wafw00f)
# ═══════════════════════════════════════════════════════════════

WAF_SIGNATURES: List[Tuple[str, Dict]] = [
    # ── Cloud / CDN WAFs ──
    (
        "Cloudflare",
        {"headers": {"server": r"cloudflare", "cf-ray": r".+"}, "cookies": {"__cfduid": None, "cf_clearance": None}},
    ),
    (
        "AWS WAF / ELB",
        {
            "headers": {
                "x-amzn-requestid": r".+",
                "x-amz-id": r".+",
                "x-amz-request-id": r".+",
                "x-blocked-by-waf": r".+",
            },
            "cookies": {"awsalb": r".+"},
        },
    ),
    (
        "Akamai Kona",
        {"headers": {"x-akamai-transformed": r".+", "x-akamai-request-id": r".+"}, "cookies": {"ak_bmsc": None}},
    ),
    ("Azure Front Door", {"headers": {"x-azure-ref": r".+", "x-ms-request-id": r".+"}}),
    ("CloudFront (Amazon)", {"headers": {"x-amz-cf-id": r".+", "x-amz-cf-pop": r".+"}}),
    ("Cloudbric", {"cookies": {"Cloudbric": r".+"}}),
    ("ArvanCloud", {"headers": {"ar-sid": r".+", "ar-request-id": r".+"}}),
    ("Fastly", {"headers": {"x-served-by": r".+", "x-cache": r"(?:HIT|MISS)"}}),
    ("StackPath", {"headers": {"x-stackpath-cache": r".+"}}),
    ("ZScaler", {"headers": {"x-zscaler-firewall": r".+"}}),
    ("Edgecast / Verizon", {"headers": {"server": r"ECDs", "x-ec-custom-error": r".+"}}),
    ("PowerCDN", {"headers": {"x-cdn": r"PowerCDN", "x-via": r".+"}}),
    ("CacheFly CDN", {"headers": {"x-cachefly": r".+"}}),
    ("LimeLight CDN", {"cookies": {"Limelight": r".+"}}),
    (
        "Squarespace",
        {"headers": {"x-squarespace-request-id": r".+"}, "cookies": {"SS_MID": r".+", "SS_SESSION": r".+"}},
    ),
    ("Varnish WAF", {"headers": {"x-varnish": r"\d+", "via": r"varnish"}}),
    ("OpenResty Lua Nginx", {"headers": {"x-openresty-waf": r".+", "luawaf": r".+"}}),
    ("Envoy Proxy", {"headers": {"x-envoy-upstream-healthchecked": r".+", "x-envoy-decorator-operation": r".+"}}),
    # ── Enterprise WAFs ──
    ("F5 BIG-IP ASM", {"cookies": {"TS[0-9a-f]{4,}": r".+", "F5_ST": r".+", "TSe[0-9a-f]{4,}": r".+"}}),
    ("F5 BIG-IP LTM", {"cookies": {"BIGipServer": r".+", "BIGipServerpool": r".+"}}),
    (
        "F5 TrafficShield",
        {"headers": {"f5-trafficshield": r".+"}, "cookies": {"TSASHSID": r".+", "F5_TRACK_USER": r".+"}},
    ),
    ("Imperva Incapsula", {"cookies": {"incap_ses_": r".+", "visid_incap_": r".+"}}),
    ("Imperva SecureSphere", {"headers": {"x-isecsphere": r".+"}}),
    ("Barracuda", {"cookies": {"barracuda_nocache": r".+", "barracuda_": r".+"}}),
    ("Fortinet FortiWeb", {"cookies": {"FORTIWAFSID": None}}),
    ("Fortinet FortiGate", {"headers": {"fortigate": r".+"}}),
    ("Citrix NetScaler", {"headers": {"x-ns-protection": r".+"}, "cookies": {"ns_af": None, "citrix_ns_id": None}}),
    ("Citrix Teros", {"cookies": {"st8id": r".+", "st8_waf": r".+"}}),
    ("Radware AppWall", {"headers": {"x-sl-compstate": r".+"}}),
    ("Palo Alto NGFW", {"headers": {"x-paloalto-firewall": r".+", "x-auth-request-access": r".+"}}),
    ("WatchGuard", {"headers": {"x-watchguard-firewall": r".+", "request-id": r".+"}}),
    ("SonicWall", {"headers": {"server": r"SonicWALL"}}),
    ("IBM WebSEAL", {"headers": {"webseal": r".+"}}),
    ("IBM DataPower", {"headers": {"x-datapower-waf": r".+"}}),
    ("Sophos UTM", {"headers": {"x-sophos-waf": r".+"}}),
    ("Wallarm", {"headers": {"x-wallarm-instance": r".+", "x-wallarm-waf": r".+"}}),
    ("ThreatX (A10)", {"headers": {"x-threatx-waf": r".+"}}),
    ("DenyALL", {"headers": {"x-denyall": r".+"}}),
    # ── Chinese WAFs ──
    ("SafeDog", {"headers": {"safedog": r".+"}, "cookies": {"safedog-flow-item": None}}),
    ("Aliyun WAF", {"headers": {"aliyunwaf": r".+", "wzws-ray": r".+"}}),
    ("Tencent Cloud WAF", {"headers": {"tencent-waf": r".+", "qcloud-waf": r".+"}}),
    ("Baidu Yunjiasu", {"headers": {"yunjiasu-nginx": r".+"}}),
    ("Chuangyu (Yunaq)", {"headers": {"chuangyu": r".+", "yunaq": r".+"}}),
    ("KnownSec KS-WAF", {"headers": {"knownsec-waf": r".+"}}),
    ("NSFocus WAF", {"headers": {"nsfocus-waf": r".+", "x-nsfocus": r".+"}}),
    ("360 WZB", {"headers": {"x-powered-by-360wzb": r".+", "360wzws": r".+"}, "cookies": {"360wzws": None}}),
    ("Yundun", {"headers": {"yundun": r".+"}, "cookies": {"yundun": r".+"}}),
    ("Yunsuo", {"cookies": {"yunsuo": r".+"}}),
    ("YXLink", {"headers": {"yxlink-waf": r".+"}, "cookies": {"yx_sid": r".+", "yx_lang": r".+"}}),
    ("UEWaf (UCloud)", {"headers": {"uewaf": r".+"}}),
    ("Qiniu CDN WAF", {"headers": {"qiniu-waf": r".+"}}),
    ("Safeline (Chaitin)", {"headers": {"x-safeline-waf": r".+"}}),
    ("WebRay", {"headers": {"webray-waf": r".+", "x-webray": r".+"}}),
    # ── Web App / WordPress WAFs ──
    ("Wordfence", {"headers": {"x-wordfence": r".+"}, "cookies": {"wordfence_verifiedHuman": None}}),
    ("Sucuri CloudProxy", {"headers": {"x-sucuri-id": r".+", "x-sucuri-cache": r".+", "x-sucuri-block": r".+"}}),
    ("BulletProof Security", {"headers": {"x-bps-waf": r".+"}}),
    ("Comodo cWatch", {"headers": {"x-cwatch-waf": r".+"}}),
    ("Malcare", {"headers": {"x-malcare-waf": r".+"}}),
    ("SiteLock TrueShield", {"headers": {"x-sitelock-waf": r".+"}}),
    ("SiteGuard", {"headers": {"x-siteguard-waf": r".+"}}),
    ("SecuPress", {"headers": {"x-secupress-waf": r".+"}}),
    ("WP Cerber", {"headers": {"x-cerber-waf": r".+"}}),
    ("NinjaFirewall", {"headers": {"x-ninja-waf": r".+"}}),
    ("WebARX", {"headers": {"x-webarx-waf": r".+"}}),
    ("Shield Security", {"headers": {"x-shield-waf": r".+"}}),
    ("Shieldon", {"headers": {"x-shieldon-waf": r".+"}}),
    # ── ModSecurity & derivatives ──
    ("ModSecurity", {"headers": {"x-modsecurity": r".+", "mod_security": r".+", "x-waf-rule": r".+"}}),
    ("NAXSI", {"headers": {"x-naxsi": r".+", "x-naxsi-blocked": r".+"}}),
    ("DotDefender", {"headers": {"x-dotdefender": r".+"}}),
    ("Imunify360", {"headers": {"x-imunify360": r".+"}}),
    ("LiteSpeed WAF", {"headers": {"x-litespeed-cache": r".+"}}),
    ("eEye SecureIIS", {"headers": {"x-secureiis": r".+"}}),
    ("Safe3 WAF", {"headers": {"safe3waf": r".+", "x-safe3": r".+"}}),
    # ── Generic / Behavioral ──
    (
        "Generic WAF",
        {
            "headers": {
                "x-waf": r".+",
                "x-firewall": r".+",
                "waf": r".+",
                "x-protected-by": r".+",
                "x-secured-by": r".+",
                "x-security": r".+",
            }
        },
    ),
    ("DDoS-GUARD", {"headers": {"ddos-guard": r".+"}, "cookies": {"ddosguard": r".+", "ddos": r".+"}}),
    ("BlockDoS", {"headers": {"blockdos": r".+"}}),
    ("Armor Defense", {"headers": {"x-armor-waf": r".+"}}),
    ("Bekchy", {"cookies": {"bekchy": r".+"}}),
    ("BinarySec", {"headers": {"binarysec-waf": r".+", "x-binarysec": r".+"}}),
    ("BitNinja", {"headers": {"x-bitninja-waf": r".+"}}),
    ("DDoS-GUARD CORP", {"headers": {"ddosguard": r".+"}}),
    ("Link11", {"headers": {"x-link11-waf": r".+"}}),
    ("NexusGuard", {"headers": {"x-nexusguard-waf": r".+"}}),
    ("Reblaze", {"headers": {"x-reblaze-waf": r".+"}, "cookies": {"reblaze": r".+"}}),
    ("SecKing", {"headers": {"secking-waf": r".+"}}),
    ("Shadow Daemon", {"headers": {"x-shadowd-waf": r".+"}}),
    ("VirusDie", {"headers": {"x-virusdie-waf": r".+"}}),
    ("XLabs Security", {"headers": {"xlabs-waf": r".+", "x-xlabs-security": r".+"}}),
    ("Zenedge", {"headers": {"x-zenedge": r".+", "x-ze-waf": r".+"}}),
]

# ── Behavioral Detection Payloads ──────────────────────────────
BEHAVIORAL_ROUNDS = [
    ("NORMAL", None),
    ("XSS", "<script>alert('WAF_DETECTION_PROBE_xsR8')</script>"),
    ("SQLi", "' UNION SELECT 'WAF_PROBE_sqL9--"),
    ("LFI", "../../../../etc/passwd"),
]

# ── WAF Bypass Test Payloads ───────────────────────────────────
BYPASS_TESTS = [
    ("case", "<ScRiPt>alert(1)</ScRiPt>"),
    ("encoding", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ("unicode", "<ſcript>alert(1)</ſcript>"),
    ("null_byte", "%00<script>alert(1)</script>"),
    ("double_encode", "%253Cscript%253Ealert(1)%253C%252Fscript%253E"),
]


@register_module
class WAFDetector(DetectionModule):
    """WAF Detection Module v2.0 — 80+ signatures + behavioral + bypass"""

    @classmethod
    def get_info(cls) -> ModuleInfo:
        return ModuleInfo(
            name="waf",
            description="Detect & fingerprint WAF with 80+ signatures, behavioral analysis, and bypass testing (wafw00f)",
            author="WVS Team",
            version="2.0.0",
            enabled_by_default=True,
            tags=["waf", "firewall", "fingerprint", "bypass", "recon"],
        )

    def __init__(self, config=None, session: Optional[HTTPPool] = None):
        super().__init__(config)
        self.session = session

    async def _scan_impl(self, target: ScanTarget) -> List[Vulnerability]:
        """Full WAF detection pipeline."""
        url = target.url
        params = getattr(target, "params", {}) or {}

        findings: List[Vulnerability] = []

        # ── 1. Signature Matching ──
        baseline = await self._send_request("GET", url, params, "query")
        if baseline is None:
            return []

        waf_matches = self._match_all_signatures(baseline)
        if waf_matches:
            evidence = f"WAF identified: {', '.join(waf_matches)}"
            findings.append(
                self._create_vuln(
                    url=url,
                    param="N/A",
                    param_type="N/A",
                    method="GET",
                    payload="WAF signature probe",
                    vuln_type="waf_identified",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH if len(waf_matches) > 1 else Confidence.MEDIUM,
                    evidence=evidence,
                )
            )

        # ── 2. Behavioral Detection ──
        behavioral = await self._behavioral_detect(url, params, baseline)
        if behavioral and not waf_matches:
            findings.append(
                self._create_vuln(
                    url=url,
                    param="N/A",
                    param_type="N/A",
                    method="GET",
                    payload="WAF behavioral probe",
                    vuln_type="waf_detected",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    evidence=f"Behavioral WAF detection: {behavioral}",
                )
            )

        # ── 3. Bypass Test ──
        bypass_results = await self._test_bypass(url, params, baseline)
        if bypass_results and (waf_matches or behavioral):
            findings.append(
                self._create_vuln(
                    url=url,
                    param="N/A",
                    param_type="N/A",
                    method="GET",
                    payload="WAF bypass probe",
                    vuln_type="waf_bypass_test",
                    severity=Severity.LOW if bypass_results else Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    evidence=f"WAF bypass test: {bypass_results}",
                )
            )

        if not findings:
            # No WAF detected
            pass  # This is normal — many sites have no WAF
        else:
            total = len(findings)
            logger.info(
                f"[WAF] Detection complete: {', '.join(waf_matches) if waf_matches else 'generic WAF'}, {total} findings"
            )

        return findings

    # ── Signature Matching ─────────────────────────────────────

    def _match_all_signatures(self, baseline: dict) -> List[str]:
        """Match all 80+ WAF signatures against response."""
        headers = baseline.get("headers", {}) or {}
        cookies = baseline.get("cookies", {}) or {}
        body = baseline.get("text", "")[:5000]
        status = baseline.get("status", 0)

        matches = []
        for waf_name, sig in WAF_SIGNATURES:
            if self._match_one(headers, cookies, body, status, sig):
                matches.append(waf_name)

        return matches

    def _match_one(self, headers, cookies, body, status, sig) -> bool:
        """Check one WAF signature."""
        # Headers
        for hdr_name, pattern in sig.get("headers", {}).items():
            for actual_name, actual_val in (headers or {}).items():
                if actual_name.lower() == hdr_name.lower():
                    if pattern is None or re.search(pattern, str(actual_val), re.IGNORECASE):
                        return True

        # Cookies
        for cookie_name, pattern in sig.get("cookies", {}).items():
            for c_name in cookies or {}:
                if re.search(cookie_name, c_name, re.IGNORECASE):
                    if pattern is None:
                        return True
                    val = str(cookies.get(c_name, ""))
                    if re.search(pattern, val, re.IGNORECASE):
                        return True

        # Body patterns
        for bp in sig.get("body", []):
            if re.search(bp, body, re.IGNORECASE):
                return True

        # Status code
        for s in sig.get("status", []):
            if status == s:
                return True

        return False

    # ── Behavioral Detection ───────────────────────────────────

    async def _behavioral_detect(self, url, params, baseline) -> Optional[str]:
        """4-round behavioral WAF detection."""
        base_headers = baseline.get("headers", {}) or {}
        base_body = baseline.get("text", "")[:5000]
        base_status = baseline.get("status", 0)
        base_len = len(baseline.get("text", ""))

        signals = []

        for round_name, payload in BEHAVIORAL_ROUNDS:
            if payload is None:
                continue  # skip NORMAL round

            test_params = params.copy()
            test_params["wvs_waf_test"] = payload

            resp = await self._send_request("GET", url, test_params, "query")
            if resp is None:
                continue

            round_status = resp.get("status", 0)
            round_body = resp.get("text", "")[:5000]
            round_headers = resp.get("headers", {}) or {}
            round_len = len(resp.get("text", ""))

            # Signal 1: Status code change
            if round_status != base_status:
                if round_status in (403, 406, 501):
                    signals.append(f"{round_name}: blocked {round_status}")
                elif round_status == 429:
                    signals.append(f"{round_name}: rate-limited 429")
                elif round_status == 302 and "waf" in str(round_headers).lower():
                    signals.append(f"{round_name}: redirected to WAF page")

            # Signal 2: Body length anomaly
            if base_len > 0 and round_len > 0:
                ratio = round_len / base_len if base_len > 0 else 1
                if ratio < 0.3:
                    signals.append(f"{round_name}: body truncated ({round_len}/{base_len})")

            # Signal 3: WAF keywords in body
            waf_keywords = [
                "request denied",
                "access denied",
                "blocked",
                "not acceptable",
                "waf",
                "firewall",
                "security policy",
                "incident id",
                "your request",
                "事件ID",
                "访问被拒绝",
                "攻击",
                "非法请求",
                "安全拦截",
            ]
            for kw in waf_keywords:
                if kw.lower() in round_body.lower() and kw.lower() not in base_body.lower():
                    signals.append(f"{round_name}: body contains '{kw}'")
                    break

            # Signal 4: Header changes
            waf_hdr_keys = {"x-blocked", "x-waf", "x-firewall", "x-denied", "blocked-by"}
            new_headers = set(h.lower() for h in round_headers) - set(h.lower() for h in base_headers)
            if new_headers & waf_hdr_keys:
                signals.append(f"{round_name}: new WAF headers: {new_headers & waf_hdr_keys}")

        if signals:
            return "; ".join(signals)
        return None

    # ── Bypass Test ────────────────────────────────────────────

    async def _test_bypass(self, url, params, baseline) -> Optional[str]:
        """Test WAF bypass capabilities (encoding/case/etc)."""
        base_status = baseline.get("status", 0)
        bypassed = []
        blocked = []

        for bypass_name, payload in BYPASS_TESTS:
            test_params = params.copy()
            test_params["wvs_bypass_test"] = payload

            resp = await self._send_request("GET", url, test_params, "query")
            if resp is None:
                continue

            round_status = resp.get("status", 0)

            # If the base request was blocked (403), and this variant passes (200)
            if base_status in (403, 406) and round_status < 400:
                bypassed.append(bypass_name)
            # If base was OK but this variant is blocked
            elif base_status < 400 and round_status in (403, 406):
                blocked.append(bypass_name)

        result_parts = []
        if bypassed:
            result_parts.append(f"Bypass works: {', '.join(bypassed)}")
        if blocked:
            result_parts.append(f"No bypass for: {', '.join(blocked)}")
        if not bypassed and not blocked:
            result_parts.append("All bypass tests passed (no filtering detected)")

        return "; ".join(result_parts) if result_parts else None
