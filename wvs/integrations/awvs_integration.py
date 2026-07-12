"""
AWVS Integration Module — Acunetix Web Vulnerability Scanner API 集成

通过 AWVS REST API 远程调度扫描，获取结果并转换为 RayScan Vulnerability 对象。

支持:
  - AWVS v14 ~ v25 (REST API v1)
  - 多 AWVS 实例管理
  - 目标创建 / 扫描启动 / 结果拉取
  - 扫描进度监控
  - WAF 检测结果同步
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from ..config import ConfigManager
from ..models import Vulnerability, VulnerabilityType, Severity, Confidence

logger = logging.getLogger("wvs.integrations.awvs")

# AWVS 默认配置
AWVS_DEFAULT_PORT = 3443
AWVS_DEFAULT_TIMEOUT = 3600  # 1 hour per scan
AWVS_POLL_INTERVAL = 30  # seconds between status checks

# ── AWVS Severity 映射 ─────────────────────────────────────────
AWVS_SEVERITY_MAP = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}

# ── AWVS Vulnerability Type 映射 ───────────────────────────────
AWVS_VULN_TYPE_KEYWORDS: Dict[str, VulnerabilityType] = {
    "sql injection": VulnerabilityType.SQL_INJECTION,
    "xss": VulnerabilityType.XSS,
    "cross site scripting": VulnerabilityType.XSS,
    "command injection": VulnerabilityType.COMMAND_INJECTION,
    "lfi": VulnerabilityType.LFI,
    "file inclusion": VulnerabilityType.LFI,
    "directory traversal": VulnerabilityType.LFI,
    "xxe": VulnerabilityType.XXE,
    "ssrf": VulnerabilityType.SSRF,
    "rce": VulnerabilityType.REMOTE_CODE_EXECUTION,
    "code execution": VulnerabilityType.REMOTE_CODE_EXECUTION,
    "idor": VulnerabilityType.IDOR,
    "information disclosure": VulnerabilityType.INFO_DISCLOSURE,
    "exposed": VulnerabilityType.INFO_DISCLOSURE,
    "authentication": VulnerabilityType.BROKEN_AUTH,
    "broken access": VulnerabilityType.BROKEN_ACCESS,
    "api": VulnerabilityType.API_SECURITY,
}


@dataclass
class AWVSInstance:
    """AWVS 实例配置"""
    name: str
    host: str
    port: int = AWVS_DEFAULT_PORT
    api_key: str = ""
    verify_ssl: bool = False
    max_concurrent: int = 2
    scan_profile_id: str = "11111111-1111-1111-1111-111111111111"  # Full scan
    description: str = ""


@dataclass
class AWVSScanResult:
    """AWVS 扫描结果摘要"""
    scan_id: str
    target_url: str
    status: str  # processing / completed / failed / aborted
    progress: int = 0
    total_vulns: int = 0
    high_count: int = 0
    med_count: int = 0
    low_count: int = 0
    info_count: int = 0
    duration: int = 0
    error: Optional[str] = None


# ── AWVS REST 客户端 ──────────────────────────────────────────

class AWVSClient:
    """AWVS REST API 客户端 (v1)"""

    def __init__(self, instance: AWVSInstance, timeout: int = 60):
        self.instance = instance
        self.base_url = f"https://{instance.host}:{instance.port}/api/v1"
        self.api_key = instance.api_key
        self.timeout = timeout
        self._headers = {
            "X-Auth": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _request(self, method: str, path: str, data: Optional[dict] = None) -> Optional[dict]:
        """发送 HTTP 请求到 AWVS API"""
        import httpx

        url = urljoin(self.base_url, path)
        try:
            async with httpx.AsyncClient(
                verify=self.instance.verify_ssl,
                timeout=self.timeout,
            ) as client:
                if method.upper() == "GET":
                    resp = await client.get(url, headers=self._headers)
                elif method.upper() == "POST":
                    resp = await client.post(url, headers=self._headers, json=data)
                elif method.upper() == "DELETE":
                    resp = await client.delete(url, headers=self._headers)
                else:
                    return None

                if resp.status_code in (200, 201, 204):
                    return resp.json() if resp.text else {}
                elif resp.status_code == 401:
                    logger.error(f"[AWVS] 认证失败: {self.instance.name}")
                    return None
                else:
                    logger.warning(f"[AWVS] API 错误 ({resp.status_code}): {resp.text[:200]}")
                    return None
        except Exception as e:
            logger.error(f"[AWVS] 连接失败 ({self.instance.host}): {e}")
            return None

    async def test_connection(self) -> bool:
        """测试 AWVS 连接"""
        result = await self._request("GET", "/me")
        return result is not None

    async def create_target(self, url: str, description: str = "") -> Optional[str]:
        """在 AWVS 中创建扫描目标"""
        data = {
            "address": url,
            "description": description,
            "criticality": 10,
        }
        # 先检查目标是否已存在
        existing = await self._request("GET", f"/targets?q=address:{url}")
        if existing and existing.get("targets"):
            target_id = existing["targets"][0]["target_id"]
            logger.info(f"[AWVS] 目标已存在: {url} (id={target_id})")
            return target_id

        result = await self._request("POST", "/targets", data)
        if result:
            target_id = result.get("target_id")
            logger.info(f"[AWVS] 目标创建成功: {url} (id={target_id})")
            return target_id
        return None

    async def start_scan(self, target_id: str, profile_id: str = None) -> Optional[str]:
        """启动扫描"""
        profile = profile_id or self.instance.scan_profile_id
        data = {
            "target_id": target_id,
            "profile_id": profile,
            "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
        }
        result = await self._request("POST", "/scans", data)
        if result:
            scan_id = result.get("scan_id")
            logger.info(f"[AWVS] 扫描启动: scan_id={scan_id}")
            return scan_id
        return None

    async def get_scan_status(self, scan_id: str) -> Optional[AWVSScanResult]:
        """获取扫描状态"""
        result = await self._request("GET", f"/scans/{scan_id}")
        if not result:
            return None

        status = result.get("current_session", {}).get("status", "unknown")
        progress = result.get("current_session", {}).get("progress", 0)
        scan_result = AWVSScanResult(
            scan_id=scan_id,
            target_url=result.get("target", {}).get("address", ""),
            status=status,
            progress=progress or 0,
        )
        return scan_result

    async def wait_for_completion(self, scan_id: str, timeout: int = AWVS_DEFAULT_TIMEOUT) -> AWVSScanResult:
        """等待扫描完成（轮询）"""
        start = asyncio.get_event_loop().time()
        while True:
            elapsed = asyncio.get_event_loop().time() - start
            if elapsed > timeout:
                logger.warning(f"[AWVS] 扫描超时 ({timeout}s): {scan_id}")
                return AWVSScanResult(scan_id=scan_id, target_url="", status="timeout")

            status = await self.get_scan_status(scan_id)
            if not status:
                return AWVSScanResult(scan_id=scan_id, target_url="", status="error", error="Connection lost")

            if status.status in ("completed", "failed", "aborted"):
                # 拉取最终漏洞数
                vulns = await self.get_vulnerabilities(scan_id)
                status.total_vulns = len(vulns) if vulns else 0
                status.high_count = sum(1 for v in (vulns or []) if v.get("severity", 0) >= 3)
                status.med_count = sum(1 for v in (vulns or []) if v.get("severity", 0) == 2)
                return status

            await asyncio.sleep(AWVS_POLL_INTERVAL)

    async def get_vulnerabilities(self, scan_id: str) -> Optional[List[dict]]:
        """获取扫描结果中的漏洞列表"""
        result = await self._request("GET", f"/scans/{scan_id}/results")
        if not result or not result.get("results"):
            return None

        results_list = result["results"]
        all_vulns = []

        for res in results_list:
            result_id = res.get("result_id")
            if not result_id:
                continue
            vulns = await self._get_result_vulnerabilities(scan_id, result_id)
            if vulns:
                all_vulns.extend(vulns)

        return all_vulns

    async def _get_result_vulnerabilities(self, scan_id: str, result_id: str) -> Optional[List[dict]]:
        """获取单个扫描结果的漏洞详情"""
        result = await self._request("GET", f"/scans/{scan_id}/results/{result_id}/vulnerabilities")
        if result:
            return result.get("vulnerabilities", [])
        return None

    async def delete_scan(self, scan_id: str) -> bool:
        """删除扫描"""
        result = await self._request("DELETE", f"/scans/{scan_id}")
        return result is not None


# ── AWVS 集成主类 ─────────────────────────────────────────────

class AWVSIntegration:
    """AWVS 扫描器集成"""

    def __init__(self, config: Optional[ConfigManager] = None):
        self.config = config or ConfigManager()
        self.instances: List[AWVSInstance] = []
        self._clients: Dict[str, AWVSClient] = {}
        self._stats = {"scans_started": 0, "scans_completed": 0, "vulns_found": 0, "errors": 0}

        # 从配置加载 AWVS 实例
        self._load_instances()

    def _load_instances(self) -> None:
        """从配置加载 AWVS 实例列表"""
        awvs_config = self.config.get("integrations.awvs", {})
        if not awvs_config:
            return

        instances_config = awvs_config.get("instances", [])
        if isinstance(instances_config, list):
            for cfg in instances_config:
                inst = AWVSInstance(
                    name=cfg.get("name", "default"),
                    host=cfg.get("host", ""),
                    port=cfg.get("port", AWVS_DEFAULT_PORT),
                    api_key=cfg.get("api_key", ""),
                    verify_ssl=cfg.get("verify_ssl", False),
                    max_concurrent=cfg.get("max_concurrent", 2),
                    scan_profile_id=cfg.get("scan_profile_id", "11111111-1111-1111-1111-111111111111"),
                )
                if inst.host and inst.api_key:
                    self.add_instance(inst)

    def add_instance(self, instance: AWVSInstance) -> None:
        """添加 AWVS 实例"""
        self.instances.append(instance)
        self._clients[instance.name] = AWVSClient(instance)

    def get_client(self, name: str = "default") -> Optional[AWVSClient]:
        """获取 AWVS 客户端"""
        if name in self._clients:
            return self._clients[name]
        if self._clients:
            return list(self._clients.values())[0]
        return None

    @property
    def is_available(self) -> bool:
        """是否有可用的 AWVS 实例"""
        return len(self.instances) > 0

    async def scan(
        self,
        url: str,
        instance_name: str = "default",
        wait_for_result: bool = True,
        timeout: int = AWVS_DEFAULT_TIMEOUT,
    ) -> List[Vulnerability]:
        """
        使用 AWVS 扫描目标

        Args:
            url: 目标 URL
            instance_name: AWVS 实例名
            wait_for_result: 是否等待扫描完成
            timeout: 超时时间

        Returns:
            Vulnerability 列表
        """
        client = self.get_client(instance_name)
        if not client:
            logger.error(f"[AWVS] 无可用的 AWVS 实例: {instance_name}")
            return []

        logger.info(f"[AWVS] 开始扫描: {url} (instance={instance_name})")

        # 1. 创建目标
        target_id = await client.create_target(url)
        if not target_id:
            self._stats["errors"] += 1
            return []

        # 2. 启动扫描
        scan_id = await client.start_scan(target_id)
        if not scan_id:
            self._stats["errors"] += 1
            return []

        self._stats["scans_started"] += 1

        if not wait_for_result:
            logger.info(f"[AWVS] 扫描已启动 (异步): scan_id={scan_id}")
            return []

        # 3. 等待完成
        scan_result = await client.wait_for_completion(scan_id, timeout=timeout)
        self._stats["scans_completed"] += 1

        if scan_result.status != "completed":
            logger.warning(f"[AWVS] 扫描未完成: {scan_result.status}")
            return []

        # 4. 获取漏洞详情并转换
        raw_vulns = await client.get_vulnerabilities(scan_id)
        if not raw_vulns:
            return []

        vulns = [self._convert_vulnerability(v, url) for v in raw_vulns]
        vulns = [v for v in vulns if v is not None]

        self._stats["vulns_found"] += len(vulns)
        logger.info(f"[AWVS] 扫描完成: {len(vulns)} 个漏洞 found on {url}")
        return vulns

    def _convert_vulnerability(self, awvs_vuln: dict, base_url: str) -> Optional[Vulnerability]:
        """将 AWVS 漏洞对象转换为 Vulnerability"""
        try:
            vt_name = awvs_vuln.get("vt_name", "") or ""
            severity = AWVS_SEVERITY_MAP.get(awvs_vuln.get("severity", 0), Severity.INFO)
            impact = awvs_vuln.get("impact", "") or ""
            description = awvs_vuln.get("description", "") or ""
            recommendation = awvs_vuln.get("remediation", "") or ""
            affected_url = awvs_vuln.get("affects_url", "") or base_url
            param = awvs_vuln.get("affects_detail", "") or ""
            request = awvs_vuln.get("request", "") or ""
            response_body = awvs_vuln.get("response", "") or ""

            # 漏洞类型推断
            vuln_type = self._infer_type(vt_name, description)

            # CWE ID
            cwe_id = None
            cwe_raw = awvs_vuln.get("cwe", 0) or 0
            if cwe_raw:
                cwe_id = int(cwe_raw)

            # 置信度：AWVS 的 confirmed 级别
            confirmed = awvs_vuln.get("confirmed", False)
            confidence = Confidence.HIGH if confirmed else Confidence.MEDIUM

            return Vulnerability(
                type=vuln_type,
                title=f"[AWVS] {vt_name}",
                url=affected_url,
                parameter=param[:100] if param else None,
                method=awvs_vuln.get("method", "GET"),
                payload=request[:200] if request else None,
                evidence=response_body[:200] if response_body else f"Severity: {severity.value}",
                severity=severity,
                confidence=confidence,
                cwe_id=cwe_id,
                description=description[:500] if description else vt_name,
                impact=impact[:500] if impact else "",
                recommendation=recommendation[:500] if recommendation else "参考 AWVS 提示修复",
                module="awvs",
                tags=["awvs", "acunetix", vuln_type.value],
                context={
                    "source": "awvs",
                    "awvs_vt_name": vt_name,
                    "affected_url": affected_url,
                    "remediation": recommendation,
                },
            )
        except Exception as e:
            logger.debug(f"[AWVS] 漏洞转换失败: {e}")
            return None

    @staticmethod
    def _infer_type(vt_name: str, description: str) -> VulnerabilityType:
        """从 AWVS 漏洞名称推断 VulnerabilityType"""
        combined = (vt_name + " " + description).lower()
        for keyword, vuln_type in AWVS_VULN_TYPE_KEYWORDS.items():
            if keyword in combined:
                return vuln_type
        return VulnerabilityType.OTHER

    def get_stats(self) -> Dict[str, Any]:
        return self._stats.copy()


def create_awvs_instance_config(
    name: str, host: str, api_key: str, port: int = 3443
) -> dict:
    """创建 AWVS 实例配置（供 config.yaml 使用）"""
    return {
        "name": name,
        "host": host,
        "port": port,
        "api_key": api_key,
        "verify_ssl": False,
        "max_concurrent": 2,
        "scan_profile_id": "11111111-1111-1111-1111-111111111111",
    }
